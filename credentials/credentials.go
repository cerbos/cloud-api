// Copyright 2021-2025 Zenauth Ltd.
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

	"github.com/cerbos/cloud-api/crypto"
)

const (
	ageSecretKeyPrefix = "AGE-SECRET-KEY-1"
	cerbosKeyPrefix    = "CERBOS-1"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidPrivateKey  = errors.New("invalid private key")
)

type Credentials struct {
	identity     *age.X25519Identity
	recipient    string
	WorkspaceID  string
	ClientID     string
	ClientSecret string
	BootstrapKey []byte
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
