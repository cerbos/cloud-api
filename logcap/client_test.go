// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package logcap_test

import (
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/credentials"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1/logsv1connect"
	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	"github.com/cerbos/cloud-api/test"
	mocklogsv1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/logs/v1/logsv1connect"
	"github.com/cerbos/cloud-api/test/testserver"
)

const testPrivateKey = "CERBOS-1MKYX97DHPT3B-L05ALANNYUXY7HEMFXUNQRLS47D8G8D9ZYUMEDPE4X2382Q2WMSSXY2G2A"

var pdpIdentifer = &pdpv1.Identifier{
	Instance: "instance",
	Version:  "0.34.0",
}

func TestIngest(t *testing.T) {
	creds, err := credentials.New("client-id", "client-secret", testPrivateKey)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		mockLogsSvc := mocklogsv1connect.NewCerbosLogsServiceHandler(t)
		logsPath, logsHandler := logsv1connect.NewCerbosLogsServiceHandler(mockLogsSvc)
		mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{logsPath: testserver.LogRequests(t, logsHandler)}, creds)

		testserver.ExpectAPIKeySuccess(t, mockAPIKeySvc)
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

		client, err := hub.LogCapClient()
		require.NoError(t, err)

		_, err = client.Ingest(test.Context(t), batch)
		require.NoError(t, err)
	})

	t.Run("AuthenticationFailure", func(t *testing.T) {
		mockLogsSvc := mocklogsv1connect.NewCerbosLogsServiceHandler(t)
		logsPath, logsHandler := logsv1connect.NewCerbosLogsServiceHandler(mockLogsSvc)
		mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{logsPath: testserver.LogRequests(t, logsHandler)}, creds)
		testserver.ExpectAPIKeyFailure(t, mockAPIKeySvc)

		client, err := hub.LogCapClient()
		require.NoError(t, err)

		_, err = client.Ingest(test.Context(t), &logsv1.IngestBatch{})
		require.Error(t, err)
		require.ErrorIs(t, err, base.ErrAuthenticationFailed)
	})
}
