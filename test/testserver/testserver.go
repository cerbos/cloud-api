// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package testserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/credentials"
	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	"github.com/cerbos/cloud-api/hub"
	mockapikeyv1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
)

func ConnectOptions() []connect.Option {
	compress1KB := connect.WithCompressMinBytes(1024)
	authInterceptor := connect.WithInterceptors(authCheck{})
	return []connect.Option{authInterceptor, compress1KB}
}

func LogRequests(t *testing.T, h http.Handler) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("REQUEST: %s", r.URL)
		h.ServeHTTP(w, r)
	})
}

func Start(t *testing.T, handlers map[string]http.Handler, creds *credentials.Credentials) (*mockapikeyv1connect.ApiKeyServiceHandler, *hub.Hub) {
	t.Helper()

	mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
	apiKeyPath, apiKeySvcHandler := apikeyv1connect.NewApiKeyServiceHandler(mockAPIKeySvc)

	mux := http.NewServeMux()
	mux.Handle(apiKeyPath, LogRequests(t, apiKeySvcHandler))
	for path, handler := range handlers {
		mux.Handle(path, handler)
	}

	s := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	s.EnableHTTP2 = true
	s.StartTLS()

	t.Cleanup(s.Close)

	h := newHub(t, s, creds)
	return mockAPIKeySvc, h
}

func newHub(t *testing.T, server *httptest.Server, creds *credentials.Credentials) *hub.Hub {
	t.Helper()

	cert := server.Certificate()
	var tlsConf *tls.Config
	if cert != nil {
		certPool := x509.NewCertPool()
		certPool.AddCert(cert)
		tlsConf = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			NextProtos: []string{"h2"},
			RootCAs:    certPool,
		}
	}

	url := server.URL
	pdpIdentifer := &pdpv1.Identifier{
		Instance: "instance",
		Version:  "0.34.0",
	}
	h, err := hub.New(base.ClientConf{
		Credentials:       creds,
		BootstrapEndpoint: url,
		APIEndpoint:       url,
		PDPIdentifier:     pdpIdentifer,
		RetryWaitMin:      10 * time.Millisecond,
		RetryWaitMax:      30 * time.Millisecond,
		RetryMaxAttempts:  2,
		Logger:            testr.NewWithOptions(t, testr.Options{Verbosity: 4}),
		TLS:               tlsConf,
	})
	require.NoError(t, err, "Failed to create hub instance")

	return h
}

type authCheck struct{}

func (ac authCheck) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Header().Get(base.AuthTokenHeader) != "access-token" {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or missing access token"))
		}
		return next(ctx, req)
	})
}

func (ac authCheck) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (ac authCheck) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if conn.RequestHeader().Get(base.AuthTokenHeader) != "access-token" {
			return connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or missing access token"))
		}

		return next(ctx, conn)
	})
}

func ExpectAPIKeySuccess(t *testing.T, mockAPIKeySvc *mockapikeyv1connect.ApiKeyServiceHandler) {
	t.Helper()

	mockAPIKeySvc.EXPECT().
		IssueAccessToken(mock.Anything, mock.MatchedBy(issueAccessTokenRequest())).
		Return(connect.NewResponse(&apikeyv1.IssueAccessTokenResponse{
			AccessToken: "access-token",
			ExpiresIn:   durationpb.New(1 * time.Minute),
		}), nil)
}

func ExpectAPIKeyFailure(t *testing.T, mockAPIKeySvc *mockapikeyv1connect.ApiKeyServiceHandler) {
	t.Helper()

	mockAPIKeySvc.EXPECT().
		IssueAccessToken(mock.Anything, mock.MatchedBy(issueAccessTokenRequest())).
		Return(nil, connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))).
		Once()
}

func issueAccessTokenRequest() func(*connect.Request[apikeyv1.IssueAccessTokenRequest]) bool {
	return func(req *connect.Request[apikeyv1.IssueAccessTokenRequest]) bool {
		return req.Msg.ClientId == "client-id" && req.Msg.ClientSecret == "client-secret"
	}
}
