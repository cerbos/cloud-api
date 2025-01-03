// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package credentials_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cloud-api/credentials"

	_ "embed"
)

//go:embed testdata/encrypted
var encrypted []byte

func TestCredentials(t *testing.T) {
	clientID := "clientid"
	clientSecret := "clientsecret"

	t.Run("with private key", func(t *testing.T) {
		privateKey := "CERBOS-1MKYX97DHPT3B-L05ALANNYUXY7HEMFXUNQRLS47D8G8D9ZYUMEDPE4X2382Q2WMSSXY2G2A"

		c, err := credentials.New(clientID, clientSecret, privateKey)
		require.NoError(t, err, "Failed to create credentials")
		require.Equal(t, clientID, c.ClientID, "Client ID mismatch")
		require.Equal(t, clientSecret, c.ClientSecret, "Client secret mismatch")
		require.Equal(t, "MKYX97DHPT3B", c.WorkspaceID, "Workspace ID mismatch")

		have, err := c.Decrypt(bytes.NewReader(encrypted))
		require.NoError(t, err, "Failed to decrypt")

		haveDecrypted := new(bytes.Buffer)
		_, err = haveDecrypted.ReadFrom(have)
		require.NoError(t, err)
		require.Equal(t, "cerbos", haveDecrypted.String())

		require.Equal(t, "d27f6dfbae5e84c7557e7e013e0bab6e81ada2b4a817689684652548448b6267", c.HashString("cerbos"))
	})

	t.Run("without private key", func(t *testing.T) {
		c, err := credentials.New(clientID, clientSecret, "")
		require.NoError(t, err, "Failed to create credentials")
		require.Equal(t, clientID, c.ClientID, "Client ID mismatch")
		require.Equal(t, clientSecret, c.ClientSecret, "Client secret mismatch")
		require.Empty(t, c.WorkspaceID, "Workspace ID mismatch")

		_, err = c.Decrypt(bytes.NewReader(encrypted))
		require.ErrorIs(t, err, credentials.ErrInvalidPrivateKey)

		_, err = c.Encrypt(new(bytes.Buffer))
		require.ErrorIs(t, err, credentials.ErrInvalidPrivateKey)

		require.Equal(t, "eaf69a17369b5b65a4bc95b0b5803afb64818cb9ad6d98dac67118d691b06bd4", c.HashString("cerbos"))
	})
}
