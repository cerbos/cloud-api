// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/minio/sha256-simd"
	"golang.org/x/crypto/chacha20poly1305"
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
	aead         cipher.AEAD
	recipient    string
	WorkspaceID  string
	ClientID     string
	ClientSecret string
	BootstrapKey []byte
	maxSize      int64
}

func New(clientID, clientSecret, privateKey string, maxSize int64) (*Credentials, error) {
	if clientID == "" || clientSecret == "" {
		return nil, ErrInvalidCredentials
	}

	bootstrapKey := HashStrings(clientID, clientSecret)
	c := &Credentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		BootstrapKey: bootstrapKey,
		maxSize:      maxSize,
	}

	var err error
	if c.aead, err = chacha20poly1305.NewX(bootstrapKey); err != nil {
		return nil, fmt.Errorf("failed to initialize cipher: %w", err)
	}

	if privateKey == "" {
		return c, nil
	}

	var ageKey string
	var ok bool
	if c.WorkspaceID, ageKey, ok = strings.Cut(strings.TrimPrefix(privateKey, cerbosKeyPrefix), "-"); !ok {
		return nil, ErrInvalidPrivateKey
	}

	if c.identity, err = age.ParseX25519Identity(ageSecretKeyPrefix + ageKey); err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	c.recipient = c.identity.Recipient().String()
	return c, nil
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

func (c *Credentials) DecryptV2(ciphertext []byte) ([]byte, error) {
	nonce, message := ciphertext[:c.aead.NonceSize()], ciphertext[c.aead.NonceSize():]
	decrypted, err := c.aead.Open(nil, nonce, message, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return decrypted, nil
}

func (c *Credentials) HashString(value string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%s", c.recipient, value)

	return hex.EncodeToString(h.Sum(nil))
}

func HashStrings(data ...string) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write([]byte(d))
	}

	return h.Sum(nil)
}
