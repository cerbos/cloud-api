// Copyright 2021-2022 Zenauth Ltd.

package bundle

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/bufbuild/connect-go"
	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
)

const (
	AuthTokenHeader = "x-cerbos-auth" //nolint:gosec
	earlyExpiry     = 5 * time.Minute
)

type authClient struct {
	accessToken  string
	expiresAt    time.Time
	apiKeyClient apikeyv1connect.ApiKeyServiceClient
	clientID     string
	clientSecret string
	mutex        sync.RWMutex
}

func newAuthClient(conf ClientConf, httpClient *http.Client, clientOptions ...connect.ClientOption) *authClient {
	return &authClient{
		apiKeyClient: apikeyv1connect.NewApiKeyServiceClient(httpClient, conf.ServerURL, clientOptions...),
		clientID:     conf.ClientID,
		clientSecret: conf.ClientSecret,
	}
}

func (a *authClient) SetAuthTokenHeader(ctx context.Context, headers http.Header) error {
	accessToken, err := a.authenticate(ctx)
	if err != nil {
		return err
	}

	headers.Set(AuthTokenHeader, accessToken)
	return nil
}

func (a *authClient) authenticate(ctx context.Context) (string, error) {
	a.mutex.RLock()
	accessToken, ok := a.currentAccessToken()
	a.mutex.RUnlock()
	if ok {
		return accessToken, nil
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	accessToken, ok = a.currentAccessToken()
	if ok {
		return accessToken, nil
	}

	response, err := a.apiKeyClient.IssueAccessToken(ctx, connect.NewRequest(&apikeyv1.IssueAccessTokenRequest{
		ClientId:     a.clientID,
		ClientSecret: a.clientSecret,
	}))
	if err != nil {
		return "", fmt.Errorf("failed to authenticate: %w", err)
	}

	expiresIn := response.Msg.ExpiresIn.AsDuration()
	if expiresIn > earlyExpiry {
		expiresIn -= earlyExpiry
	}

	a.accessToken = response.Msg.AccessToken
	a.expiresAt = time.Now().Add(expiresIn)

	return a.accessToken, nil
}

func (a *authClient) currentAccessToken() (string, bool) {
	return a.accessToken, a.accessToken != "" && a.expiresAt.After(time.Now())
}
