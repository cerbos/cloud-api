// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/minio/sha256-simd"

	"github.com/cerbos/cloud-api/crypto"
	authv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/auth/v1"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidPrivateKey  = errors.New("invalid private key")
)

type Credentials struct {
	ClientID         string
	ClientSecret     string
	SavedCredentials *authv1.SavedCredentials
	BootstrapKey     []byte
}

func New(clientID, clientSecret string) (*Credentials, error) {
	if clientID == "" || clientSecret == "" {
		return nil, ErrInvalidCredentials
	}

	return &Credentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		BootstrapKey: Hash([]byte(clientID), []byte(clientSecret)),
	}, nil
}

func NewFromSavedCredentials(credentials *authv1.SavedCredentials) (*Credentials, error) {
	switch c := credentials.GetCredentials().(type) {
	case *authv1.SavedCredentials_ClientCredentials:
		// We don't need to update the refresh token in storage if the saved credentials are just client ID and client secret.
		// Hence why saved client ID and client secret are treated as they were supplied through the environment.
		return New(c.ClientCredentials.GetClientId(), c.ClientCredentials.GetClientSecret())
	case *authv1.SavedCredentials_DeviceToken:
		return &Credentials{SavedCredentials: credentials}, nil
	default:
		return nil, fmt.Errorf("unknown saved credentials type %T", c)
	}
}

func (c *Credentials) Decrypt(encrypted io.Reader) ([]byte, error) {
	decrypted := new(bytes.Buffer)
	_, err := crypto.DecryptChaCha20Poly1305Stream(c.BootstrapKey, encrypted, decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return decrypted.Bytes(), nil
}

func Hash(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}

	return h.Sum(nil)
}
