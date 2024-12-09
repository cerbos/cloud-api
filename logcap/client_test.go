// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package logcap_test

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
	"connectrpc.com/grpcreflect"
	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/go-logr/logr/testr"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/credentials"
	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1/logsv1connect"
	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	"github.com/cerbos/cloud-api/hub"
	"github.com/cerbos/cloud-api/logcap"
	mockapikeyv1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
	mocklogsv1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/logs/v1/logsv1connect"
)

const testPrivateKey = "CERBOS-1MKYX97DHPT3B-L05ALANNYUXY7HEMFXUNQRLS47D8G8D9ZYUMEDPE4X2382Q2WMSSXY2G2A"

var pdpIdentifer = &pdpv1.Identifier{
	Instance: "instance",
	Version:  "0.34.0",
}

func TestIngest(t *testing.T) {
	mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
	mockLogsSvc := mocklogsv1connect.NewCerbosLogsServiceHandler(t)
	server := startTestServer(t, mockAPIKeySvc, mockLogsSvc)
	t.Cleanup(server.Close)

	client := mkClient(t, server.URL, server.Certificate())

	t.Run("Success", func(t *testing.T) {
		mockAPIKeySvc.EXPECT().
			IssueAccessToken(mock.Anything, mock.MatchedBy(issueAccessTokenRequest())).
			Return(connect.NewResponse(&apikeyv1.IssueAccessTokenResponse{
				AccessToken: "access-token",
				ExpiresIn:   durationpb.New(1 * time.Minute),
			}), nil)

		now := time.Now()

		batch := &logsv1.IngestBatch{
			Id: "foo",
			Entries: []*logsv1.IngestBatch_Entry{
				{
					Kind:      logsv1.IngestBatch_ENTRY_KIND_ACCESS_LOG,
					Timestamp: &timestamppb.Timestamp{},
					Entry: &logsv1.IngestBatch_Entry_AccessLogEntry{
						AccessLogEntry: &auditv1.AccessLogEntry{
							CallId:    "1",
							Timestamp: timestamppb.New(now.Add(time.Duration(1) * time.Second)),
							Peer: &auditv1.Peer{
								Address: "1.1.1.1",
							},
							Metadata: map[string]*auditv1.MetaValues{},
							Method:   "/cerbos.svc.v1.CerbosService/Check",
						},
					},
				},
				{
					Kind:      logsv1.IngestBatch_ENTRY_KIND_DECISION_LOG,
					Timestamp: &timestamppb.Timestamp{},
					Entry: &logsv1.IngestBatch_Entry_DecisionLogEntry{
						DecisionLogEntry: &auditv1.DecisionLogEntry{
							CallId:    "2",
							Timestamp: timestamppb.New(now.Add(time.Duration(2) * time.Second)),
							Inputs: []*enginev1.CheckInput{
								{
									RequestId: "2",
									Resource: &enginev1.Resource{
										Kind: "test:kind",
										Id:   "test",
									},
									Principal: &enginev1.Principal{
										Id:    "test",
										Roles: []string{"a", "b"},
									},
									Actions: []string{"a1", "a2"},
								},
							},
							Outputs: []*enginev1.CheckOutput{
								{
									RequestId:  "2",
									ResourceId: "test",
									Actions: map[string]*enginev1.CheckOutput_ActionEffect{
										"a1": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
										"a2": {Effect: effectv1.Effect_EFFECT_ALLOW, Policy: "resource.test.v1"},
									},
								},
							},
						},
					},
				},
			},
		}

		want := &logsv1.IngestRequest{
			PdpId: pdpIdentifer,
			Batch: batch,
		}

		mockLogsSvc.EXPECT().
			Ingest(mock.Anything, mock.MatchedBy(func(c *connect.Request[logsv1.IngestRequest]) bool {
				return cmp.Diff(c.Msg, want, protocmp.Transform()) == ""
			})).
			Return(connect.NewResponse(&logsv1.IngestResponse{
				Status: &logsv1.IngestResponse_Success{},
			}), nil).Once()

		err := client.Ingest(context.Background(), batch)
		require.NoError(t, err)
	})

	t.Run("AuthenticationFailure", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockLogsSvc := mocklogsv1connect.NewCerbosLogsServiceHandler(t)
		server := startTestServer(t, mockAPIKeySvc, mockLogsSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL, server.Certificate())

		mockAPIKeySvc.EXPECT().
			IssueAccessToken(mock.Anything, mock.MatchedBy(issueAccessTokenRequest())).
			Return(nil, connect.NewError(connect.CodeUnauthenticated, errors.New("🙅")))

		err := client.Ingest(context.Background(), &logsv1.IngestBatch{})
		require.Error(t, err)
		require.ErrorIs(t, err, base.ErrAuthenticationFailed)
	})
}

func startTestServer(t *testing.T, mockAPIKeySvc apikeyv1connect.ApiKeyServiceHandler, mockLogsSvc logsv1connect.CerbosLogsServiceHandler) *httptest.Server {
	t.Helper()

	compress1KB := connect.WithCompressMinBytes(1024)
	apiKeyPath, apiKeySvcHandler := apikeyv1connect.NewApiKeyServiceHandler(mockAPIKeySvc, compress1KB)
	logsPath, logsSvcHandler := logsv1connect.NewCerbosLogsServiceHandler(mockLogsSvc, connect.WithInterceptors(authCheck{}), compress1KB)

	logRequests := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("REQUEST: %s", r.URL)
			h.ServeHTTP(w, r)
		})
	}
	mux := http.NewServeMux()
	mux.Handle(apiKeyPath, logRequests(apiKeySvcHandler))
	mux.Handle(logsPath, logRequests(logsSvcHandler))
	mux.Handle(grpcreflect.NewHandlerV1(
		grpcreflect.NewStaticReflector(logsv1connect.CerbosLogsServiceName),
		compress1KB,
	))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(
		grpcreflect.NewStaticReflector(logsv1connect.CerbosLogsServiceName),
		compress1KB,
	))

	s := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	s.EnableHTTP2 = true
	s.StartTLS()

	return s
}

func mkClient(t *testing.T, url string, cert *x509.Certificate) *logcap.Client {
	t.Helper()

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

	creds, err := credentials.New("client-id", "client-secret", testPrivateKey)
	require.NoError(t, err, "Failed to create credentials")

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

	client, err := h.LogCapClient()
	require.NoError(t, err, "Failed to create client")

	return client
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

func issueAccessTokenRequest() func(*connect.Request[apikeyv1.IssueAccessTokenRequest]) bool {
	return func(req *connect.Request[apikeyv1.IssueAccessTokenRequest]) bool {
		return req.Msg.ClientId == "client-id" && req.Msg.ClientSecret == "client-secret"
	}
}
