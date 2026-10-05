// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/credentials"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1/logsv1connect"
	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	"github.com/cerbos/cloud-api/logcap"
	mocklogsv1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/logs/v1/logsv1connect"
	"github.com/cerbos/cloud-api/test/testserver"
)

var pdpIdentifer = &pdpv1.Identifier{
	Instance: "instance",
	Version:  "0.34.0",
}

func mkIngestBatch(now time.Time) *logsv1.IngestBatch {
	return &logsv1.IngestBatch{
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
						//nolint:staticcheck
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
						//nolint:staticcheck
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
}

func TestIngest(t *testing.T) {
	creds, err := credentials.New("client-id", "client-secret")
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		testCases := []struct {
			name       string
			target     logcap.Target
			wantTarget *logsv1.IngestTarget
		}{
			{
				name:       "target unspecified",
				target:     nil,
				wantTarget: nil,
			},
			{
				name:       "workspace",
				target:     logcap.WorkspaceID("LFFQFJRJU11P"),
				wantTarget: &logsv1.IngestTarget{Target: &logsv1.IngestTarget_WorkspaceId{WorkspaceId: "LFFQFJRJU11P"}},
			},
			{
				name:       "deployment",
				target:     logcap.DeploymentID("LFFQFJRJU11P"),
				wantTarget: &logsv1.IngestTarget{Target: &logsv1.IngestTarget_DeploymentId{DeploymentId: "LFFQFJRJU11P"}},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				mockLogsSvc := mocklogsv1connect.NewCerbosLogsServiceHandler(t)
				logsPath, logsHandler := logsv1connect.NewCerbosLogsServiceHandler(mockLogsSvc)
				mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{logsPath: testserver.LogRequests(t, logsHandler)}, creds)

				testserver.ExpectAPIKeySuccess(t, mockAPIKeySvc)

				batch := mkIngestBatch(time.Now())

				want := &logsv1.IngestRequest{
					PdpId:  pdpIdentifer,
					Batch:  batch,
					Target: tc.wantTarget,
				}

				mockLogsSvc.EXPECT().
					Ingest(mock.Anything, mock.MatchedBy(func(c *connect.Request[logsv1.IngestRequest]) bool {
						return cmp.Equal(c.Msg, want, protocmp.Transform())
					})).
					Return(connect.NewResponse(&logsv1.IngestResponse{
						Status: &logsv1.IngestResponse_Success{},
					}), nil).Once()

				client, err := hub.LogCapClient()
				require.NoError(t, err)

				_, err = client.Ingest(t.Context(), tc.target, batch)
				require.NoError(t, err)
			})
		}
	})

	t.Run("AuthenticationFailure", func(t *testing.T) {
		mockLogsSvc := mocklogsv1connect.NewCerbosLogsServiceHandler(t)
		logsPath, logsHandler := logsv1connect.NewCerbosLogsServiceHandler(mockLogsSvc)
		mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{logsPath: testserver.LogRequests(t, logsHandler)}, creds)
		testserver.ExpectAPIKeyFailure(t, mockAPIKeySvc)

		client, err := hub.LogCapClient()
		require.NoError(t, err)
		client.BypassCircuitBreaker()

		_, err = client.Ingest(t.Context(), nil, &logsv1.IngestBatch{})
		require.Error(t, err)
		require.ErrorIs(t, err, base.ErrAuthenticationFailed)
	})
}

func TestIngestRaw(t *testing.T) {
	creds, err := credentials.New("client-id", "client-secret")
	require.NoError(t, err)

	testCases := []struct {
		name       string
		target     logcap.Target
		wantTarget *logsv1.IngestTarget
	}{
		{
			name:       "target unspecified",
			target:     nil,
			wantTarget: nil,
		},
		{
			name:       "workspace",
			target:     logcap.WorkspaceID("LFFQFJRJU11P"),
			wantTarget: &logsv1.IngestTarget{Target: &logsv1.IngestTarget_WorkspaceId{WorkspaceId: "LFFQFJRJU11P"}},
		},
		{
			name:       "deployment",
			target:     logcap.DeploymentID("LFFQFJRJU11P"),
			wantTarget: &logsv1.IngestTarget{Target: &logsv1.IngestTarget_DeploymentId{DeploymentId: "LFFQFJRJU11P"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockLogsSvc := mocklogsv1connect.NewCerbosLogsServiceHandler(t)
			logsPath, logsHandler := logsv1connect.NewCerbosLogsServiceHandler(mockLogsSvc)
			mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{logsPath: testserver.LogRequests(t, logsHandler)}, creds)

			testserver.ExpectAPIKeySuccess(t, mockAPIKeySvc)

			batch := mkIngestBatch(time.Now())
			rawBatch, err := batch.MarshalVT()
			require.NoError(t, err)

			want := &logsv1.IngestRequest{
				PdpId:  pdpIdentifer,
				Batch:  batch,
				Target: tc.wantTarget,
			}

			mockLogsSvc.EXPECT().
				Ingest(mock.Anything, mock.MatchedBy(func(c *connect.Request[logsv1.IngestRequest]) bool {
					return cmp.Equal(c.Msg, want, protocmp.Transform())
				})).
				Return(connect.NewResponse(&logsv1.IngestResponse{
					Status: &logsv1.IngestResponse_Success{},
				}), nil).Once()

			client, err := hub.LogCapClient()
			require.NoError(t, err)

			_, err = client.IngestRaw(t.Context(), tc.target, rawBatch)
			require.NoError(t, err)
		})
	}
}

func TestRawIngestRequestWireEquivalence(t *testing.T) {
	batch := mkIngestBatch(time.Now())
	det := proto.MarshalOptions{Deterministic: true}
	rawBatch, err := det.Marshal(batch)
	require.NoError(t, err)

	testCases := []struct {
		name   string
		target *logsv1.IngestTarget
	}{
		{
			name: "target unspecified",
		},
		{
			name:   "workspace",
			target: &logsv1.IngestTarget{Target: &logsv1.IngestTarget_WorkspaceId{WorkspaceId: "LFFQFJRJU11P"}},
		},
		{
			name:   "deployment",
			target: &logsv1.IngestTarget{Target: &logsv1.IngestTarget_DeploymentId{DeploymentId: "6CXEQL80M0H0"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			typed := &logsv1.IngestRequest{PdpId: pdpIdentifer, Batch: batch, Target: tc.target}
			raw := &logsv1.RawIngestRequest{PdpId: pdpIdentifer, Batch: rawBatch, Target: tc.target}

			typedWire, err := det.Marshal(typed)
			require.NoError(t, err)
			rawWire, err := raw.MarshalVT()
			require.NoError(t, err)
			require.Equal(t, typedWire, rawWire, "RawIngestRequest wire encoding diverged from IngestRequest")

			decoded := &logsv1.IngestRequest{}
			require.NoError(t, proto.Unmarshal(rawWire, decoded))
			require.Empty(t, cmp.Diff(decoded, typed, protocmp.Transform()))
		})
	}
}
