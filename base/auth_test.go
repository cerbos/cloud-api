// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package base_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cloud-api/base"
	authv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/auth/v1"
)

func TestSaveAndLoadCredentials(t *testing.T) {
	keyring.MockInit()

	t.Run("ClientCredentials", func(t *testing.T) {
		want := &authv1.SavedCredentials{
			ApiEndpoint: "https://api.example.com",
			Credentials: &authv1.SavedCredentials_ClientCredentials{
				ClientCredentials: &authv1.ClientCredentials{
					ClientId:     "client",
					ClientSecret: "secret",
				},
			},
		}

		require.NoError(t, base.SaveCredentials(want))
		have, err := base.GetSavedCredentials("https://api.example.com")
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
	})

	t.Run("DeviceToken", func(t *testing.T) {
		want := &authv1.SavedCredentials{
			ApiEndpoint: "https://device.example.com",
			Credentials: &authv1.SavedCredentials_DeviceToken{
				DeviceToken: &authv1.DeviceToken{
					AccessToken:  "access",
					RefreshToken: "refresh",
					ExpiresAt:    timestamppb.New(time.Now().UTC().Add(30 * time.Minute)),
					TokenType:    "Bearer",
				},
			},
		}

		require.NoError(t, base.SaveCredentials(want))
		have, err := base.GetSavedCredentials("https://device.example.com")
		require.NoError(t, err)
		require.Empty(t, cmp.Diff(want, have, protocmp.Transform()))
	})
}
