// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/minio/sha256-simd"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/cerbos/cloud-api/crypto"
	"github.com/cerbos/cloud-api/crypto/stream"
)

func TestDecryptChaCha20Poly1305Stream(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	input, err := os.ReadFile(filepath.Join("testdata", "input.txt"))
	require.NoError(t, err)

	encrypted := new(bytes.Buffer)
	checksummer := sha256.New()
	teeStream := io.MultiWriter(encrypted, checksummer)
	encryptor, err := stream.NewWriter(key, teeStream)
	require.NoError(t, err)

	_, err = io.Copy(encryptor, bytes.NewReader(input))
	require.NoError(t, err)
	require.NoError(t, encryptor.Close())

	wantChecksum := checksummer.Sum(nil)
	decrypted := new(bytes.Buffer)
	haveChecksum, err := crypto.DecryptChaCha20Poly1305Stream(key, encrypted, decrypted)
	require.NoError(t, err)
	require.Equal(t, wantChecksum, haveChecksum)
	require.Equal(t, input, decrypted.Bytes())
}
