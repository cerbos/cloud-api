// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/credentials"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1/storev1connect"
	"github.com/cerbos/cloud-api/store"
	mockstorev1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/store/v1/storev1connect"
	"github.com/cerbos/cloud-api/test/testserver"
)

func TestStoreClient(t *testing.T) {
	creds, err := credentials.New("client-id", "client-secret", "")
	require.NoError(t, err)

	t.Run("ListFiles", testListFiles(creds))
	t.Run("GetFiles", testGetFiles(creds))
	t.Run("ModifyFiles", testModifyFiles(creds))
	t.Run("ReplaceFiles", testReplaceFiles(creds))
}

func testListFiles(creds *credentials.Credentials) func(*testing.T) {
	return func(t *testing.T) {
		wantReq := &storev1.ListFilesRequest{
			StoreId: "B6C0NNZO5VO6",
			Filter: &storev1.FileFilter{
				Path: &storev1.StringMatch{
					Match: &storev1.StringMatch_Equals{
						Equals: "foo.yaml",
					},
				},
			},
		}

		t.Run("Success", func(t *testing.T) {
			mockStoreSvc := mockstorev1connect.NewCerbosStoreServiceHandler(t)
			storePath, storeHandler := storev1connect.NewCerbosStoreServiceHandler(mockStoreSvc)
			mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{storePath: testserver.LogRequests(t, storeHandler)}, creds)
			testserver.ExpectAPIKeySuccess(t, mockAPIKeySvc)

			wantResp := &storev1.ListFilesResponse{
				StoreVersion: 2,
				Files:        []string{"foo.yaml"},
			}

			mockStoreSvc.EXPECT().ListFiles(mock.Anything, mock.MatchedBy(func(c *connect.Request[storev1.ListFilesRequest]) bool {
				return cmp.Equal(c.Msg, wantReq, protocmp.Transform())
			})).Return(connect.NewResponse(wantResp), nil)

			client, err := hub.StoreClient()
			require.NoError(t, err)

			haveResp, err := client.ListFiles(t.Context(), wantReq)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(wantResp, haveResp, protocmp.Transform()))
		})

		t.Run("ErrorHandling", testErrorHandling(creds, func(mockStoreSvc *mockstorev1connect.CerbosStoreServiceHandler, client *store.Client, wantErr error) error {
			mockStoreSvc.EXPECT().ListFiles(mock.Anything, mock.MatchedBy(func(c *connect.Request[storev1.ListFilesRequest]) bool {
				return cmp.Equal(c.Msg, wantReq, protocmp.Transform())
			})).Return(nil, wantErr)

			_, err := client.ListFiles(t.Context(), wantReq)
			return err
		}))

		t.Run("AuthenticationFailure", testAuthenticationFailure(creds, func(c *store.Client) error {
			_, err := c.ListFiles(t.Context(), wantReq)
			return err
		}))
	}
}

func testAuthenticationFailure(creds *credentials.Credentials, fn func(*store.Client) error) func(*testing.T) {
	return func(t *testing.T) {
		mockStoreSvc := mockstorev1connect.NewCerbosStoreServiceHandler(t)
		storePath, storeHandler := storev1connect.NewCerbosStoreServiceHandler(mockStoreSvc)
		mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{storePath: testserver.LogRequests(t, storeHandler)}, creds)
		testserver.ExpectAPIKeyFailure(t, mockAPIKeySvc)

		client, err := hub.StoreClient()
		require.NoError(t, err)

		err = fn(client)
		require.ErrorIs(t, err, base.ErrAuthenticationFailed)
		haveErr := new(store.RPCError)
		require.ErrorAs(t, err, haveErr)
		require.Equal(t, store.RPCErrorAuthenticationFailed, haveErr.Kind)
	}
}

func testErrorHandling(creds *credentials.Credentials, fn func(*mockstorev1connect.CerbosStoreServiceHandler, *store.Client, error) error) func(*testing.T) {
	return func(t *testing.T) {
		testCases := []struct {
			name                    string
			err                     *connect.Error
			details                 proto.Message
			wantKind                store.RPCErrorKind
			wantIgnored             []string
			wantValidationErr       []*storev1.FileError
			wantCurrentStoreVersion int64
		}{
			{
				name:     "StoreNotFound",
				err:      connect.NewError(connect.CodeNotFound, errors.New("store not found")),
				wantKind: store.RPCErrorStoreNotFound,
			},
			{
				name:     "PermissionDenied",
				err:      connect.NewError(connect.CodePermissionDenied, errors.New("permission denied")),
				wantKind: store.RPCErrorPermissionDenied,
			},
			{
				name:                    "ConditionUnsatisfied",
				err:                     connect.NewError(connect.CodeFailedPrecondition, errors.New("condition unsatisfied")),
				details:                 &storev1.ErrDetailConditionUnsatisfied{CurrentStoreVersion: 5},
				wantKind:                store.RPCErrorConditionUnsatisfied,
				wantCurrentStoreVersion: 5,
			},
			{
				name:        "NoUsableFiles",
				err:         connect.NewError(connect.CodeInvalidArgument, errors.New("no usable files")),
				details:     &storev1.ErrDetailNoUsableFiles{IgnoredFiles: []string{"foo"}},
				wantKind:    store.RPCErrorNoUsableFiles,
				wantIgnored: []string{"foo"},
			},
			{
				name:                    "OperationDiscarded",
				err:                     connect.NewError(connect.CodeAlreadyExists, errors.New("operation discarded")),
				details:                 &storev1.ErrDetailOperationDiscarded{CurrentStoreVersion: 5},
				wantKind:                store.RPCErrorOperationDiscarded,
				wantCurrentStoreVersion: 5,
			},
			{
				name: "ValidationFailure",
				err:  connect.NewError(connect.CodeInvalidArgument, errors.New("validation failure")),
				details: &storev1.ErrDetailValidationFailure{
					Errors: []*storev1.FileError{
						{
							File:    "foo.yaml",
							Cause:   storev1.FileError_CAUSE_DUPLICATE_FILE_PATH,
							Details: "duplicate file",
						},
					},
				},
				wantKind: store.RPCErrorValidationFailure,
				wantValidationErr: []*storev1.FileError{
					{
						File:    "foo.yaml",
						Cause:   storev1.FileError_CAUSE_DUPLICATE_FILE_PATH,
						Details: "duplicate file",
					},
				},
			},
			{
				name:     "Unknown",
				err:      connect.NewError(connect.CodeInternal, errors.New("internal error")),
				wantKind: store.RPCErrorUnknown,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				mockStoreSvc := mockstorev1connect.NewCerbosStoreServiceHandler(t)
				storePath, storeHandler := storev1connect.NewCerbosStoreServiceHandler(mockStoreSvc)
				mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{storePath: testserver.LogRequests(t, storeHandler)}, creds)
				testserver.ExpectAPIKeySuccess(t, mockAPIKeySvc)

				if tc.details != nil {
					details, err := connect.NewErrorDetail(tc.details)
					require.NoError(t, err)
					tc.err.AddDetail(details)
				}

				client, err := hub.StoreClient()
				require.NoError(t, err)

				err = fn(mockStoreSvc, client, tc.err)
				haveErr := new(store.RPCError)
				require.ErrorAs(t, err, haveErr)
				require.Equal(t, tc.wantKind, haveErr.Kind)
				require.Equal(t, tc.wantIgnored, haveErr.IgnoredFiles)
				require.Equal(t, tc.wantValidationErr, haveErr.ValidationErrors)
				require.Equal(t, tc.wantCurrentStoreVersion, haveErr.CurrentStoreVersion)
			})
		}
	}
}

func testGetFiles(creds *credentials.Credentials) func(*testing.T) {
	return func(t *testing.T) {
		wantReq := &storev1.GetFilesRequest{
			StoreId: "B6C0NNZO5VO6",
			Files:   []string{"f1.yaml", "f2.yaml", "f3.yaml"},
		}

		t.Run("Success", func(t *testing.T) {
			mockStoreSvc := mockstorev1connect.NewCerbosStoreServiceHandler(t)
			storePath, storeHandler := storev1connect.NewCerbosStoreServiceHandler(mockStoreSvc)
			mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{storePath: testserver.LogRequests(t, storeHandler)}, creds)
			testserver.ExpectAPIKeySuccess(t, mockAPIKeySvc)

			wantResp := &storev1.GetFilesResponse{
				StoreVersion: 2,
				Files: []*storev1.File{
					{
						Path:     "f1.yaml",
						Contents: []byte("f1"),
					},
					{
						Path:     "f2.yaml",
						Contents: []byte("f2"),
					},
					{
						Path:     "f3.yaml",
						Contents: []byte("f3"),
					},
				},
			}

			mockStoreSvc.EXPECT().GetFiles(mock.Anything, mock.MatchedBy(func(c *connect.Request[storev1.GetFilesRequest]) bool {
				return cmp.Equal(c.Msg, wantReq, protocmp.Transform())
			})).Return(connect.NewResponse(wantResp), nil)

			client, err := hub.StoreClient()
			require.NoError(t, err)

			haveResp, err := client.GetFiles(t.Context(), wantReq)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(wantResp, haveResp, protocmp.Transform()))
		})

		t.Run("ErrorHandling", testErrorHandling(creds, func(mockStoreSvc *mockstorev1connect.CerbosStoreServiceHandler, client *store.Client, wantErr error) error {
			mockStoreSvc.EXPECT().GetFiles(mock.Anything, mock.MatchedBy(func(c *connect.Request[storev1.GetFilesRequest]) bool {
				return cmp.Equal(c.Msg, wantReq, protocmp.Transform())
			})).Return(nil, wantErr)

			_, err := client.GetFiles(t.Context(), wantReq)
			return err
		}))

		t.Run("AuthenticationFailure", testAuthenticationFailure(creds, func(c *store.Client) error {
			_, err := c.GetFiles(t.Context(), wantReq)
			return err
		}))
	}
}

func testModifyFiles(creds *credentials.Credentials) func(*testing.T) {
	return func(t *testing.T) {
		wantReq := &storev1.ModifyFilesRequest{
			StoreId: "B6C0NNZO5VO6",
			Operations: []*storev1.FileOp{
				{
					Op: &storev1.FileOp_AddOrUpdate{
						AddOrUpdate: &storev1.File{
							Path:     "foo.yaml",
							Contents: []byte("foo"),
						},
					},
				},
			},
		}

		t.Run("Success", func(t *testing.T) {
			mockStoreSvc := mockstorev1connect.NewCerbosStoreServiceHandler(t)
			storePath, storeHandler := storev1connect.NewCerbosStoreServiceHandler(mockStoreSvc)
			mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{storePath: testserver.LogRequests(t, storeHandler)}, creds)
			testserver.ExpectAPIKeySuccess(t, mockAPIKeySvc)

			wantResp := &storev1.ModifyFilesResponse{
				NewStoreVersion: 3,
			}

			mockStoreSvc.EXPECT().ModifyFiles(mock.Anything, mock.MatchedBy(func(c *connect.Request[storev1.ModifyFilesRequest]) bool {
				return cmp.Equal(c.Msg, wantReq, protocmp.Transform())
			})).Return(connect.NewResponse(wantResp), nil)

			client, err := hub.StoreClient()
			require.NoError(t, err)

			haveResp, err := client.ModifyFiles(t.Context(), wantReq)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(wantResp, haveResp, protocmp.Transform()))
		})

		t.Run("ErrorHandling", testErrorHandling(creds, func(mockStoreSvc *mockstorev1connect.CerbosStoreServiceHandler, client *store.Client, wantErr error) error {
			mockStoreSvc.EXPECT().ModifyFiles(mock.Anything, mock.MatchedBy(func(c *connect.Request[storev1.ModifyFilesRequest]) bool {
				return cmp.Equal(c.Msg, wantReq, protocmp.Transform())
			})).Return(nil, wantErr)

			_, err := client.ModifyFiles(t.Context(), wantReq)
			return err
		}))

		t.Run("AuthenticationFailure", testAuthenticationFailure(creds, func(c *store.Client) error {
			_, err := c.ModifyFiles(t.Context(), wantReq)
			return err
		}))
	}
}

func testReplaceFiles(creds *credentials.Credentials) func(*testing.T) {
	return func(t *testing.T) {
		wantReq := &storev1.ReplaceFilesRequest{
			StoreId:        "B6C0NNZO5VO6",
			ZippedContents: []byte("this is a zip file"),
		}

		t.Run("Success", func(t *testing.T) {
			mockStoreSvc := mockstorev1connect.NewCerbosStoreServiceHandler(t)
			storePath, storeHandler := storev1connect.NewCerbosStoreServiceHandler(mockStoreSvc)
			mockAPIKeySvc, hub := testserver.Start(t, map[string]http.Handler{storePath: testserver.LogRequests(t, storeHandler)}, creds)
			testserver.ExpectAPIKeySuccess(t, mockAPIKeySvc)

			wantResp := &storev1.ReplaceFilesResponse{
				NewStoreVersion: 3,
				IgnoredFiles:    []string{"foo"},
			}

			mockStoreSvc.EXPECT().ReplaceFiles(mock.Anything, mock.MatchedBy(func(c *connect.Request[storev1.ReplaceFilesRequest]) bool {
				return cmp.Equal(c.Msg, wantReq, protocmp.Transform())
			})).Return(connect.NewResponse(wantResp), nil)

			client, err := hub.StoreClient()
			require.NoError(t, err)

			haveResp, err := client.ReplaceFiles(t.Context(), wantReq)
			require.NoError(t, err)
			require.Empty(t, cmp.Diff(wantResp, haveResp, protocmp.Transform()))
		})

		t.Run("ErrorHandling", testErrorHandling(creds, func(mockStoreSvc *mockstorev1connect.CerbosStoreServiceHandler, client *store.Client, wantErr error) error {
			mockStoreSvc.EXPECT().ReplaceFiles(mock.Anything, mock.MatchedBy(func(c *connect.Request[storev1.ReplaceFilesRequest]) bool {
				return cmp.Equal(c.Msg, wantReq, protocmp.Transform())
			})).Return(nil, wantErr)

			_, err := client.ReplaceFiles(t.Context(), wantReq)
			return err
		}))

		t.Run("AuthenticationFailure", testAuthenticationFailure(creds, func(c *store.Client) error {
			_, err := c.ReplaceFiles(t.Context(), wantReq)
			return err
		}))
	}
}
