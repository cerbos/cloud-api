// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/minio/sha256-simd"
	"golang.org/x/oauth2"

	"github.com/cerbos/cloud-api/crypto"
	authv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/auth/v1"
)

const (
	ageSecretKeyPrefix = "AGE-SECRET-KEY-1"
	cerbosKeyPrefix    = "CERBOS-1"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidPrivateKey  = errors.New("invalid private key")
)

type Source interface {
	oauth2.TokenSource
	BootstrapKey() ([]byte, error)
}

type Credentials struct {
	identity         *age.X25519Identity
	recipient        string
	WorkspaceID      string
	Source           Source
	ClientID         string
	ClientSecret     string
	SavedCredentials *authv1.SavedCredentials
	BootstrapKey     []byte
}

func New(clientID, clientSecret, privateKey string) (*Credentials, error) {
	if clientID == "" || clientSecret == "" {
		return nil, ErrInvalidCredentials
	}

	bootstrapKey := Hash([]byte(clientID), []byte(clientSecret))
	if privateKey == "" {
		return &Credentials{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			BootstrapKey: bootstrapKey,
		}, nil
	}

	workspaceID, ageKey, ok := strings.Cut(strings.TrimPrefix(privateKey, cerbosKeyPrefix), "-")
	if !ok {
		return nil, ErrInvalidPrivateKey
	}

	identity, err := age.ParseX25519Identity(ageSecretKeyPrefix + ageKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &Credentials{
		identity:     identity,
		recipient:    identity.Recipient().String(),
		WorkspaceID:  workspaceID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		BootstrapKey: bootstrapKey,
	}, nil
}

func NewFromSavedCredentials(credentials *authv1.SavedCredentials) (*Credentials, error) {
	switch c := credentials.GetCredentials().(type) {
	case *authv1.SavedCredentials_ClientCredentials:
		// We don't need to update the refresh token in storage if the saved credentials are just client ID and client secret.
		// Hence why saved client ID and client secret are treated as they were supplied through the environment.
		return New(c.ClientCredentials.GetClientId(), c.ClientCredentials.GetClientSecret(), "")
	case *authv1.SavedCredentials_DeviceToken:
		return &Credentials{SavedCredentials: credentials}, nil
	default:
		return nil, fmt.Errorf("unknown saved credentials type %T", c)
	}
}

func (c *Credentials) Encrypt(dst io.Writer) (io.WriteCloser, error) {
	if c.identity == nil {
		return nil, ErrInvalidPrivateKey
	}

	return age.Encrypt(dst, c.identity.Recipient())
}

func (c *Credentials) Decrypt(input io.Reader) (io.Reader, error) {
	if c.identity == nil {
		return nil, ErrInvalidPrivateKey
	}

	out, err := age.Decrypt(input, c.identity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return out, nil
}

func (c *Credentials) DecryptV2(encrypted io.Reader) ([]byte, error) {
	decrypted := new(bytes.Buffer)
	_, err := crypto.DecryptChaCha20Poly1305Stream(c.BootstrapKey, encrypted, decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return decrypted.Bytes(), nil
}

func (c *Credentials) HashString(value string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%s", c.recipient, value)

	return hex.EncodeToString(h.Sum(nil))
}

func Hash(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}

	return h.Sum(nil)
}
