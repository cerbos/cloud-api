// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/go-logr/logr"
	"github.com/jdx/go-netrc"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

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

var (
	_ tokenSetter = (*apiKeyTokenSetter)(nil)
	_ tokenSetter = (*deviceTokenSetter)(nil)
)

type tokenSetter interface {
	SetHeader(context.Context, http.Header) error
}

func newTokenSetter(conf ClientConf, httpClient *http.Client, clientOptions ...connect.ClientOption) tokenSetter {
	if conf.Credentials.TokenSource != nil {
		return newDeviceTokenSetter(conf.Credentials.TokenSource)
	}

	return newAPIKeySetter(conf, httpClient, clientOptions...)
}

type apiKeyTokenSetter struct {
	expiresAt          time.Time
	apiKeyClient       apikeyv1connect.ApiKeyServiceClient
	logger             logr.Logger
	accessToken        string
	clientID           string
	clientSecret       string
	invalidCredentials bool
	mutex              sync.RWMutex
}

func newAPIKeySetter(conf ClientConf, httpClient *http.Client, clientOptions ...connect.ClientOption) *apiKeyTokenSetter {
	return &apiKeyTokenSetter{
		apiKeyClient: apikeyv1connect.NewApiKeyServiceClient(httpClient, conf.APIEndpoint, clientOptions...),
		clientID:     conf.Credentials.ClientID,
		clientSecret: conf.Credentials.ClientSecret,
		logger:       conf.Logger.WithName("auth"),
	}
}

func (a *apiKeyTokenSetter) SetHeader(ctx context.Context, headers http.Header) error {
	accessToken, err := a.authenticate(ctx)
	if err != nil {
		a.logger.V(1).Error(err, "Failed to authenticate")
		return err
	}

	headers.Set(AuthTokenHeader, accessToken)
	return nil
}

func (a *apiKeyTokenSetter) authenticate(ctx context.Context) (string, error) {
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

func (a *apiKeyTokenSetter) currentAccessToken() (string, bool) {
	return a.accessToken, a.accessToken != "" && a.expiresAt.After(time.Now())
}

func newDeviceTokenSetter(tokenSource oauth2.TokenSource) *deviceTokenSetter {
	return &deviceTokenSetter{
		tokenSource: tokenSource,
	}
}

type deviceTokenSetter struct {
	tokenSource oauth2.TokenSource
}

func (d *deviceTokenSetter) SetHeader(_ context.Context, headers http.Header) error {
	token, err := d.tokenSource.Token()
	if err != nil {
		return err
	}
	headers.Set(AuthTokenHeader, token.AccessToken)
	return nil
}

func DeviceTokenSource(ctx context.Context, authURL, tokenURL, clientID string, deviceToken *authv1.DeviceToken) oauth2.TokenSource {
	config := makeOauthConfig(authURL, tokenURL, clientID)
	return config.TokenSource(ctx, &oauth2.Token{
		AccessToken:  deviceToken.GetAccessToken(),
		RefreshToken: deviceToken.GetRefreshToken(),
		Expiry:       deviceToken.GetExpiry().AsTime(),
		TokenType:    deviceToken.GetTokenType(),
	})
}

func GetSavedCredentials(apiEndpoint string) (*authv1.SavedCredentials, error) {
	path, err := netrcPath()
	if err != nil {
		return nil, err
	}

	netrcContents, err := netrc.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse netrc from %s: %w", path, err)
	}

	m := netrcContents.Machine(apiEndpoint)
	if m == nil {
		return nil, ErrNoSavedCredentials
	}

	login := m.Get("login")
	password := m.Get("password")
	if login == "device" {
		deviceTokenBytes, err := base64.StdEncoding.DecodeString(password)
		if err != nil {
			return nil, fmt.Errorf("failed to decode token: %w", err)
		}

		deviceToken := &authv1.DeviceToken{}
		if err := proto.Unmarshal(deviceTokenBytes, deviceToken); err != nil {
			return nil, fmt.Errorf("failed to unmarshal device token: %w", err)
		}

		return &authv1.SavedCredentials{
			ApiEndpoint: apiEndpoint,
			Credentials: &authv1.SavedCredentials_DeviceToken{
				DeviceToken: deviceToken,
			},
		}, nil
	}

	return &authv1.SavedCredentials{
		ApiEndpoint: apiEndpoint,
		Credentials: &authv1.SavedCredentials_ClientCredentials{
			ClientCredentials: &authv1.ClientCredentials{
				ClientId:     login,
				ClientSecret: password,
			},
		},
	}, nil
}

func DeviceLogin(ctx context.Context, apiEndpoint, authURL, tokenURL, clientID, audience string) error {
	config := makeOauthConfig(authURL, tokenURL, clientID)
	verifier := oauth2.GenerateVerifier()
	response, err := config.DeviceAuth(ctx, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("audience", audience))
	if err != nil {
		return fmt.Errorf("failed to start auth flow: %w", err)
	}

	fmt.Printf("Log in and connect this machine to your account by visiting %s\n", response.VerificationURIComplete) //nolint:forbidigo
	token, err := config.DeviceAccessToken(ctx, response)
	if err != nil {
		return fmt.Errorf("failed to obtain token: %w", err)
	}

	return SaveCredentials(&authv1.SavedCredentials{
		ApiEndpoint: apiEndpoint,
		Credentials: &authv1.SavedCredentials_DeviceToken{
			DeviceToken: &authv1.DeviceToken{
				AccessToken:  token.AccessToken,
				RefreshToken: token.RefreshToken,
				Expiry:       timestamppb.New(token.Expiry),
				TokenType:    token.Type(),
			},
		},
	})
}

func makeOauthConfig(authURL, tokenURL, clientID string) *oauth2.Config {
	return &oauth2.Config{
		ClientID: clientID,
		Scopes:   []string{"offline_access"},
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: authURL,
			TokenURL:      tokenURL,
		},
	}
}

func ClientLogin(ctx context.Context, apiEndpoint, clientID, clientSecret string) error {
	apiClient := apikeyv1connect.NewApiKeyServiceClient(http.DefaultClient, apiEndpoint)
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
	switch c := creds.Credentials.(type) {
	case *authv1.SavedCredentials_ClientCredentials:
		return writeNetrc(creds.GetApiEndpoint(), c.ClientCredentials.GetClientId(), c.ClientCredentials.GetClientSecret())
	case *authv1.SavedCredentials_DeviceToken:
		deviceTokenBytes, err := proto.Marshal(c.DeviceToken)
		if err != nil {
			return fmt.Errorf("failed to marshal device token: %w", err)
		}
		deviceTokenEncoded := base64.StdEncoding.EncodeToString(deviceTokenBytes)
		return writeNetrc(creds.GetApiEndpoint(), "device", deviceTokenEncoded)
	default:
		return fmt.Errorf("unknown credential type %T", c)
	}
}

func writeNetrc(apiEndpoint, user, password string, kvPairs ...string) error {
	path, err := netrcPath()
	if err != nil {
		return err
	}

	var netrcContents *netrc.Netrc
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			netrcContents = netrc.New(path)
		} else {
			return fmt.Errorf("failed to stat %s: %w", path, err)
		}
	} else {
		netrcContents, err = netrc.Parse(path)
		if err != nil {
			return fmt.Errorf("failed to parse netrc at %s: %w", path, err)
		}
	}

	if m := netrcContents.Machine(apiEndpoint); m != nil {
		netrcContents.RemoveMachine(apiEndpoint)
	}

	netrcContents.AddMachine(apiEndpoint, user, password)
	if len(kvPairs) > 0 {
		m := netrcContents.Machine(apiEndpoint)
		for kv := range slices.Chunk(kvPairs, 2) {
			if len(kv) == 2 {
				m.Set(kv[0], kv[1])
			}
		}
	}
	if err := netrcContents.Save(); err != nil {
		return fmt.Errorf("failed to save netrc file: %w", err)
	}

	return nil
}

func netrcPath() (string, error) {
	if path := os.Getenv("NETRC"); path != "" {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine home directory: %w", err)
	}

	return filepath.Join(home, ".netrc"), nil
}
