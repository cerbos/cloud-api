// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	sha256 "github.com/minio/sha256-simd"
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
}

func New(clientID, clientSecret, privateKey string) (*Credentials, error) {
	if clientID == "" || clientSecret == "" || privateKey == "" {
		return nil, ErrInvalidCredentials
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
	}, nil
}

func (c *Credentials) Encrypt(dst io.Writer) (io.WriteCloser, error) {
	return age.Encrypt(dst, c.identity.Recipient())
}

func (c *Credentials) Decrypt(input io.Reader) (io.Reader, error) {
	out, err := age.Decrypt(input, c.identity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return out, nil
}

func (c *Credentials) HashString(value string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%s", c.recipient, value)

	return hex.EncodeToString(h.Sum(nil))
}
