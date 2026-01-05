// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package crypto //nolint:revive

import (
	"fmt"
	"io"

	"github.com/minio/sha256-simd"

	"github.com/cerbos/cloud-api/crypto/stream"
)

func DecryptChaCha20Poly1305Stream(key []byte, in io.Reader, out io.Writer) ([]byte, error) {
	checksummer := sha256.New()
	inStream := io.TeeReader(in, checksummer)

	decryptor, err := stream.NewReader(key, inStream)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryptor: %w", err)
	}

	if _, err := io.Copy(out, decryptor); err != nil {
		return nil, fmt.Errorf("failed to decrypt stream: %w", err)
	}

	checksum := checksummer.Sum(nil)
	return checksum, nil
}
