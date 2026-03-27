// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/go-logr/logr"
	"github.com/zalando/go-keyring"
	"google.golang.org/protobuf/proto"

	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
	authv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/auth/v1"
)

const (
	AuthTokenHeader = "x-cerbos-auth" //nolint:gosec
	earlyExpiry     = 5 * time.Minute
)

var (
	ErrAuthenticationFailed = errors.New("failed to authenticate: invalid credentials")
	ErrNoSavedCredentials   = errors.New("no saved credentials")
)

type tokenSetter struct {
	expiresAt          time.Time
	apiKeyClient       apikeyv1connect.ApiKeyServiceClient
	logger             logr.Logger
	accessToken        string
	clientID           string
	clientSecret       string
	savedCredentials   *authv1.SavedCredentials
	invalidCredentials bool
	mutex              sync.RWMutex
}

func newTokenSetter(conf ClientConf, httpClient *http.Client, clientOptions ...connect.ClientOption) *tokenSetter {
	return &tokenSetter{
		apiKeyClient:     apikeyv1connect.NewApiKeyServiceClient(httpClient, conf.APIEndpoint, clientOptions...),
		clientID:         conf.Credentials.ClientID,
		clientSecret:     conf.Credentials.ClientSecret,
		savedCredentials: conf.Credentials.SavedCredentials,
		logger:           conf.Logger.WithName("auth"),
	}
}

func (a *tokenSetter) SetHeader(ctx context.Context, headers http.Header) error {
	accessToken, err := a.authenticate(ctx)
	if err != nil {
		a.logger.V(1).Error(err, "Failed to authenticate")
		return err
	}

	headers.Set(AuthTokenHeader, accessToken)
	return nil
}

func (a *tokenSetter) authenticate(ctx context.Context) (string, error) {
	a.mutex.RLock()
	if a.invalidCredentials {
		a.mutex.RUnlock()
		a.logger.V(4).Info("Short-circuiting auth because credentials are invalid")
		return "", ErrAuthenticationFailed
	}
	accessToken, ok := a.currentAccessToken()
	a.mutex.RUnlock()
	if ok {
		a.logger.V(4).Info("Using existing token")
		return accessToken, nil
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.invalidCredentials {
		a.logger.V(4).Info("Short-circuiting auth because credentials are invalid")
		return "", ErrAuthenticationFailed
	}

	accessToken, ok = a.currentAccessToken()
	if ok {
		a.logger.V(4).Info("Using existing token")
		return accessToken, nil
	}

	a.logger.V(4).Info("Obtaining new access token")
	var expiresIn time.Duration
	var err error
	if a.savedCredentials != nil {
		// Saved credentials can only be device tokens. See credentials/credentials.go:86.
		var response *connect.Response[apikeyv1.RefreshDeviceTokenResponse]
		response, err = a.apiKeyClient.RefreshDeviceToken(ctx, connect.NewRequest(&apikeyv1.RefreshDeviceTokenRequest{
			DeviceToken: a.savedCredentials.GetDeviceToken(),
		}))
		if err == nil {
			a.accessToken = response.Msg.GetDeviceToken().GetAccessToken()
			a.savedCredentials = &authv1.SavedCredentials{
				ApiEndpoint: a.savedCredentials.GetApiEndpoint(),
				Credentials: &authv1.SavedCredentials_DeviceToken{
					DeviceToken: response.Msg.GetDeviceToken(),
				},
			}
			expiresIn = a.savedCredentials.GetDeviceToken().GetExpiresIn().AsDuration()
			// Refresh token rotates so we need to save it.
			_ = SaveCredentials(a.savedCredentials)
		}
	} else {
		var response *connect.Response[apikeyv1.IssueAccessTokenResponse]
		response, err = a.apiKeyClient.IssueAccessToken(ctx, connect.NewRequest(&apikeyv1.IssueAccessTokenRequest{
			ClientId:     a.clientID,
			ClientSecret: a.clientSecret,
		}))
		if err == nil {
			a.accessToken = response.Msg.GetAccessToken()
			expiresIn = response.Msg.ExpiresIn.AsDuration()
		}
	}

	if err != nil {
		a.logger.V(1).Error(err, "Failed to authenticate")
		if connect.CodeOf(err) == connect.CodeUnauthenticated {
			a.invalidCredentials = true
			return "", ErrAuthenticationFailed
		}
		return "", fmt.Errorf("failed to authenticate: %w", err)
	}

	if expiresIn > earlyExpiry {
		expiresIn -= earlyExpiry
	}

	a.expiresAt = time.Now().Add(expiresIn)
	a.logger.V(4).Info("Obtained new access token")

	return a.accessToken, nil
}

func (a *tokenSetter) currentAccessToken() (string, bool) {
	return a.accessToken, a.accessToken != "" && a.expiresAt.After(time.Now())
}

func DeviceLogin(ctx context.Context, apiEndpoint string, tlsConf *tls.Config) error {
	credentials, err := startDeviceRegistrationFlow(ctx, apiEndpoint, tlsConf)
	if err != nil {
		return err
	}

	return SaveCredentials(credentials)
}

func startDeviceRegistrationFlow(ctx context.Context, apiEndpoint string, tlsConf *tls.Config) (*authv1.SavedCredentials, error) {
	httpClient := mkHTTPClient(ClientConf{TLS: tlsConf})
	apiClient := apikeyv1connect.NewApiKeyServiceClient(httpClient, apiEndpoint)
	stream, err := apiClient.RegisterDevice(ctx, connect.NewRequest(&apikeyv1.RegisterDeviceRequest{}))
	if err != nil {
		return nil, fmt.Errorf("failed to start device registration: %w", err)
	}

	defer stream.Close()

	for stream.Receive() {
		msg := stream.Msg()
		switch m := msg.GetMessage().(type) {
		case *apikeyv1.RegisterDeviceResponse_VerificationUrl:
			fmt.Printf("Log in and connect this machine to your account by visiting %s\n", m.VerificationUrl) //nolint:forbidigo
		case *apikeyv1.RegisterDeviceResponse_DeviceToken:
			return &authv1.SavedCredentials{
				ApiEndpoint: apiEndpoint,
				Credentials: &authv1.SavedCredentials_DeviceToken{
					DeviceToken: &authv1.DeviceToken{
						AccessToken:  m.DeviceToken.GetAccessToken(),
						RefreshToken: m.DeviceToken.GetRefreshToken(),
						ExpiresIn:    m.DeviceToken.GetExpiresIn(),
						TokenType:    m.DeviceToken.GetTokenType(),
					},
				},
			}, nil
		}
	}

	if err := stream.Err(); err != nil {
		return nil, fmt.Errorf("device registration failed: %w", err)
	}

	return nil, nil
}

func ClientLogin(ctx context.Context, apiEndpoint string, tlsConf *tls.Config, clientID, clientSecret string) error {
	httpClient := mkHTTPClient(ClientConf{TLS: tlsConf})
	apiClient := apikeyv1connect.NewApiKeyServiceClient(httpClient, apiEndpoint)
	if _, err := apiClient.IssueAccessToken(ctx, connect.NewRequest(&apikeyv1.IssueAccessTokenRequest{
		ClientId:     clientID,
		ClientSecret: clientSecret,
	})); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	return SaveCredentials(&authv1.SavedCredentials{
		ApiEndpoint: apiEndpoint,
		Credentials: &authv1.SavedCredentials_ClientCredentials{
			ClientCredentials: &authv1.ClientCredentials{
				ClientId:     clientID,
				ClientSecret: clientSecret,
			},
		},
	})
}

func SaveCredentials(creds *authv1.SavedCredentials) error {
	credBytes, err := proto.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	credEncoded := base64.StdEncoding.EncodeToString(credBytes)
	if err := keyring.Set(creds.GetApiEndpoint(), "cerbos", credEncoded); err != nil {
		return fmt.Errorf("failed to save credentials to key ring: %w", err)
	}

	return nil
}

func GetSavedCredentials(apiEndpoint string) (*authv1.SavedCredentials, error) {
	credEncoded, err := keyring.Get(apiEndpoint, "cerbos")
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials from key ring: %w", err)
	}

	credBytes, err := base64.StdEncoding.DecodeString(credEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode credentials: %w", err)
	}

	creds := &authv1.SavedCredentials{}
	if err := proto.Unmarshal(credBytes, creds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	return creds, nil
}
