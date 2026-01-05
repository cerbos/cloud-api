// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/go-logr/logr"

	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
)

const (
	AuthTokenHeader = "x-cerbos-auth" //nolint:gosec
	earlyExpiry     = 5 * time.Minute
)

var ErrAuthenticationFailed = errors.New("failed to authenticate: invalid credentials")

type authClient struct {
	expiresAt          time.Time
	apiKeyClient       apikeyv1connect.ApiKeyServiceClient
	logger             logr.Logger
	accessToken        string
	clientID           string
	clientSecret       string
	invalidCredentials bool
	mutex              sync.RWMutex
}

func newAuthClient(conf ClientConf, httpClient *http.Client, clientOptions ...connect.ClientOption) *authClient {
	return &authClient{
		apiKeyClient: apikeyv1connect.NewApiKeyServiceClient(httpClient, conf.APIEndpoint, clientOptions...),
		clientID:     conf.Credentials.ClientID,
		clientSecret: conf.Credentials.ClientSecret,
		logger:       conf.Logger.WithName("auth"),
	}
}

func (a *authClient) SetAuthTokenHeader(ctx context.Context, headers http.Header) error {
	accessToken, err := a.authenticate(ctx)
	if err != nil {
		a.logger.V(1).Error(err, "Failed to authenticate")
		return err
	}

	headers.Set(AuthTokenHeader, accessToken)
	return nil
}

func (a *authClient) authenticate(ctx context.Context) (string, error) {
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
	response, err := a.apiKeyClient.IssueAccessToken(ctx, connect.NewRequest(&apikeyv1.IssueAccessTokenRequest{
		ClientId:     a.clientID,
		ClientSecret: a.clientSecret,
	}))
	if err != nil {
		a.logger.V(1).Error(err, "Failed to authenticate")
		if connect.CodeOf(err) == connect.CodeUnauthenticated {
			a.invalidCredentials = true
			return "", ErrAuthenticationFailed
		}
		return "", fmt.Errorf("failed to authenticate: %w", err)
	}

	expiresIn := response.Msg.ExpiresIn.AsDuration()
	if expiresIn > earlyExpiry {
		expiresIn -= earlyExpiry
	}

	a.accessToken = response.Msg.AccessToken
	a.expiresAt = time.Now().Add(expiresIn)
	a.logger.V(4).Info("Obtained new access token")

	return a.accessToken, nil
}

func (a *authClient) currentAccessToken() (string, bool) {
	return a.accessToken, a.accessToken != "" && a.expiresAt.After(time.Now())
}
