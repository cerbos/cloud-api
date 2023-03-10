// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package credentials_test

import (
	"bytes"
	"testing"

	"github.com/cerbos/cloud-api/credentials"
	"github.com/stretchr/testify/require"

	_ "embed"
)

//go:embed testdata/encrypted
var encrypted []byte

func TestCredentials(t *testing.T) {
	clientID := "clientid"
	clientSecret := "clientsecret"
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
}
