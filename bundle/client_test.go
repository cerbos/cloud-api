// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests
// +build tests

package bundle_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"github.com/Shopify/toxiproxy/v2"
	toxiclient "github.com/Shopify/toxiproxy/v2/client"
	"github.com/go-logr/logr/testr"
	"github.com/google/go-cmp/cmp"
	"github.com/minio/sha256-simd"
	"github.com/rs/zerolog/log"
	"github.com/sourcegraph/conc/pool"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/credentials"
	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
	bootstrapv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bootstrap/v1"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1/bundlev1connect"
	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	mockapikeyv1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/apikey/v1/apikeyv1connect"
	mockbundlev1connect "github.com/cerbos/cloud-api/test/mocks/genpb/cerbos/cloud/bundle/v1/bundlev1connect"
)

const testPrivateKey = "CERBOS-1MKYX97DHPT3B-L05ALANNYUXY7HEMFXUNQRLS47D8G8D9ZYUMEDPE4X2382Q2WMSSXY2G2A"

var pdpIdentifer = &pdpv1.Identifier{
	Instance: "instance",
	Version:  "0.19.0",
}

func TestBootstrapBundle(t *testing.T) {
	mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
	mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
	server, _ := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
	t.Cleanup(server.Close)

	client, creds := mkClient(t, server.URL, server.Certificate())

	rootDir := filepath.Join("testdata", "bootstrap")
	require.NoError(t, os.RemoveAll(rootDir), "Failed to remove bootstrap dir")

	dataDir := filepath.Join(rootDir, "v1", creds.HashString(creds.WorkspaceID))
	require.NoError(t, os.MkdirAll(dataDir, 0o774), "Failed to create data dir")

	writeConf := func(t *testing.T, label string, data []byte) {
		t.Helper()

		confFile, err := os.Create(filepath.Join(dataDir, creds.HashString(label)))
		require.NoError(t, err, "Failed to create bootstrap file")
		t.Cleanup(func() { _ = confFile.Close() })

		confWriter, err := creds.Encrypt(confFile)
		require.NoError(t, err, "Failed to create encryption stream")
		t.Cleanup(func() { _ = confWriter.Close() })

		_, err = bytes.NewReader(data).WriteTo(confWriter)
		require.NoError(t, err, "Failed to encrypt conf")

		require.NoError(t, confWriter.Close(), "Failed to close encryption stream")
		require.NoError(t, confFile.Close(), "Failed to close conf file")
	}

	t.Run("success", func(t *testing.T) {
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))
		label := "label1"
		conf := &bootstrapv1.PDPConfig{
			Meta: &bootstrapv1.PDPConfig_Meta{
				CommitHash: "1ebe782f7b0cd6b78bec8e764f916afd285401db",
				CreatedAt:  timestamppb.Now(),
			},
			BundleInfo: &bundlev1.BundleInfo{
				Label:      label,
				BundleHash: wantChecksum,
				Segments: []*bundlev1.BundleInfo_Segment{
					{
						SegmentId: 1,
						Checksum:  wantChecksum,
						DownloadUrls: []string{
							fmt.Sprintf("%s/files/bundle1.crbp", server.URL),
							fmt.Sprintf("%s/files/bundle1_copy.crbp", server.URL),
						},
					},
				},
			},
		}

		confJSON, err := protojson.Marshal(conf)
		require.NoError(t, err, "Failed to marshal JSON")
		writeConf(t, label, confJSON)

		file, err := client.BootstrapBundle(context.Background(), label)
		require.NoError(t, err)

		haveChecksum := checksum(t, file)
		require.Equal(t, wantChecksum, haveChecksum, "Checksum does not match")
	})

	t.Run("failure", func(t *testing.T) {
		_, err := client.BootstrapBundle(context.Background(), "blah")
		require.Error(t, err)
	})
}

func TestGetBundle(t *testing.T) {
	t.Run("SingleSegment", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		expectIssueAccessToken(mockAPIKeySvc)

		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: wantChecksum,
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId:    1,
							Checksum:     wantChecksum,
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
						},
					},
				},
			}), nil).Times(3)

		for i := 0; i < 3; i++ {
			file, err := client.GetBundle(context.Background(), "label")
			require.NoError(t, err)

			haveChecksum := checksum(t, file)
			require.Equal(t, wantChecksum, haveChecksum, "Checksum does not match")
		}

		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1.crbp"), "Path hit count does not match")

		cached, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum, checksum(t, cached), "Checksum does not match for cached bundle")
	})

	t.Run("MultipleDownloadURLs", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		expectIssueAccessToken(mockAPIKeySvc)

		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: wantChecksum,
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId: 1,
							Checksum:  wantChecksum,
							DownloadUrls: []string{
								fmt.Sprintf("%s/files/bundle1.crbp", server.URL),
								fmt.Sprintf("%s/files/bundle1_copy.crbp", server.URL),
							},
						},
					},
				},
			}), nil)

		file, err := client.GetBundle(context.Background(), "label")
		require.NoError(t, err)

		haveChecksum := checksum(t, file)
		require.Equal(t, wantChecksum, haveChecksum, "Checksum does not match")

		cached, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum, checksum(t, cached), "Checksum does not match for cached bundle")
	})

	t.Run("MultipleSegments", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		expectIssueAccessToken(mockAPIKeySvc)

		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: wantChecksum,
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId:    1,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_00")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_00", server.URL)},
						},
						{
							SegmentId:    2,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_01")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_01", server.URL)},
						},
						{
							SegmentId:    3,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_02")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_02", server.URL)},
						},
					},
				},
			}), nil).Times(3)

		for i := 0; i < 3; i++ {
			file, err := client.GetBundle(context.Background(), "label")
			require.NoError(t, err)

			haveChecksum := checksum(t, file)
			require.Equal(t, wantChecksum, haveChecksum, "Checksum does not match")
		}

		require.Equal(t, 3, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_00"), "Path hit count does not match for segment 00")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_01"), "Path hit count does not match for segment 01")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_02"), "Path hit count does not match for segment 02")

		cached, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum, checksum(t, cached), "Checksum does not match for cached bundle")
	})

	t.Run("BundleChangesWithCommonSegments", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())

		expectIssueAccessToken(mockAPIKeySvc)

		// first call returns bundle1
		wantChecksum1 := checksum(t, filepath.Join("testdata", "bundle1.crbp"))
		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: wantChecksum1,
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId:    1,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_00")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_00", server.URL)},
						},
						{
							SegmentId:    2,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_01")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_01", server.URL)},
						},
						{
							SegmentId:    3,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_02")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_02", server.URL)},
						},
					},
				},
			}), nil).Times(3)

		for i := 0; i < 3; i++ {
			file1, err := client.GetBundle(context.Background(), "label")
			require.NoError(t, err)

			haveChecksum1 := checksum(t, file1)
			require.Equal(t, wantChecksum1, haveChecksum1, "Checksum1 does not match")
		}

		cached1, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum1, checksum(t, cached1), "Checksum does not match for cached bundle")

		// second call returns bundle2. segment_00 and segment_01 are identical for both bundle1 and bundle2.
		wantChecksum2 := checksum(t, filepath.Join("testdata", "bundle2.crbp"))
		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: wantChecksum2,
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId:    1,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle2_segment_00")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle2_segment_00", server.URL)},
						},
						{
							SegmentId:    2,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle2_segment_01")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle2_segment_01", server.URL)},
						},
						{
							SegmentId:    3,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle2_segment_02")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle2_segment_02", server.URL)},
						},
						{
							SegmentId:    4,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle2_segment_03")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle2_segment_03", server.URL)},
						},
						{
							SegmentId:    5,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle2_segment_04")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle2_segment_04", server.URL)},
						},
					},
				},
			}), nil).Times(3)

		for i := 0; i < 3; i++ {
			file2, err := client.GetBundle(context.Background(), "label")
			require.NoError(t, err)

			haveChecksum2 := checksum(t, file2)
			require.Equal(t, wantChecksum2, haveChecksum2, "Checksum2 does not match")
		}

		cached2, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum2, checksum(t, cached2), "Checksum does not match for cached bundle")

		require.Equal(t, 6, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_00"), "Path hit count does not match for bundle1 segment 00")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_01"), "Path hit count does not match for bundle1 segment 01")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_02"), "Path hit count does not match for bundle1 segment 02")
		require.Equal(t, 0, counter.pathHits("bundle2_segment_00"), "Path hit count does not match for bundle2 segment 00")
		require.Equal(t, 0, counter.pathHits("bundle2_segment_01"), "Path hit count does not match for bundle2 segment 01")
		require.Equal(t, 1, counter.pathHits("bundle2_segment_02"), "Path hit count does not match for bundle2 segment 02")
		require.Equal(t, 1, counter.pathHits("bundle2_segment_03"), "Path hit count does not match for bundle2 segment 03")
		require.Equal(t, 1, counter.pathHits("bundle2_segment_04"), "Path hit count does not match for bundle2 segment 04")
	})

	t.Run("BundleNotAvailableForDownload", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		expectIssueAccessToken(mockAPIKeySvc)

		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: wantChecksum,
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId: 1,
							Checksum:  wantChecksum,
							DownloadUrls: []string{
								fmt.Sprintf("%s/files/bundle1_BLAH1.crbp", server.URL),
								fmt.Sprintf("%s/files/bundle1_BLAH2.crbp", server.URL),
								fmt.Sprintf("%s/files/bundle1_BLAH3.crbp", server.URL),
							},
						},
					},
				},
			}), nil).Once()

		_, err := client.GetBundle(context.Background(), "label")
		require.Error(t, err)

		require.Equal(t, 3, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_BLAH1.crbp"), "Path hit count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_BLAH2.crbp"), "Path hit count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_BLAH3.crbp"), "Path hit count does not match")
	})

	t.Run("SegmentNotAvailableForDownload", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		expectIssueAccessToken(mockAPIKeySvc)

		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: wantChecksum,
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId:    1,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_00")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_00", server.URL)},
						},
						{
							SegmentId:    2,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_01")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_01", server.URL)},
						},
						{
							SegmentId:    3,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle1_segment_02")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_segment_02_BLAH", server.URL)},
						},
					},
				},
			}), nil).Once()

		_, err := client.GetBundle(context.Background(), "label")
		require.Error(t, err)

		require.Equal(t, 3, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_00"), "Path hit count does not match for segment 00")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_01"), "Path hit count does not match for segment 01")
		require.Equal(t, 1, counter.pathHits("bundle1_segment_02_BLAH"), "Path hit count does not match for segment 02")
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())

		expectIssueAccessToken(mockAPIKeySvc)

		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: checksum(t, filepath.Join("testdata", "bundle1.crbp")),
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId:    1,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle2.crbp")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
						},
					},
				},
			}), nil).Once()

		_, err := client.GetBundle(context.Background(), "label")
		require.Error(t, err)

		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1.crbp"), "Path hit count does not match")
	})

	t.Run("InvalidBundleHash", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())

		expectIssueAccessToken(mockAPIKeySvc)

		mockBundleSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: []byte{0xba, 0xd1},
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId:    1,
							Checksum:     checksum(t, filepath.Join("testdata", "bundle2.crbp")),
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
						},
					},
				},
			}), nil).Once()

		_, err := client.GetBundle(context.Background(), "label")
		require.Error(t, err)
	})

	t.Run("AuthenticationFailure", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())

		mockAPIKeySvc.EXPECT().
			IssueAccessToken(mock.Anything, mock.MatchedBy(issueAccessTokenRequest())).
			Return(nil, connect.NewError(connect.CodeUnauthenticated, errors.New("🙅")))

		_, err := client.GetBundle(context.Background(), "label")
		require.Error(t, err)
		require.ErrorIs(t, err, bundle.ErrAuthenticationFailed)
	})
}

func getBundleReq(wantLabel string) func(*connect.Request[bundlev1.GetBundleRequest]) bool {
	return func(c *connect.Request[bundlev1.GetBundleRequest]) bool {
		return c.Msg.GetBundleLabel() == wantLabel && c.Msg.GetPdpId().Instance == "instance"
	}
}

func TestWatchBundle(t *testing.T) {
	t.Run("NormalStream", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockWatchSvc := newMockBundleWatchService()

		server, counter := startTestServer(t, mockAPIKeySvc, mockWatchSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		bundleID1 := randomCommit()
		bundleID2 := randomCommit()
		wantChecksum1 := checksum(t, filepath.Join("testdata", "bundle1.crbp"))
		wantChecksum2 := checksum(t, filepath.Join("testdata", "bundle2.crbp"))

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)
		expectIssueAccessToken(mockAPIKeySvc)

		handle, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")
		eventStream := handle.ServerEvents()

		mockWatchSvc.requireRequestReceived(t, mkWBWatchLabelReq("label"))
		mockWatchSvc.respondWithBundleUpdate(&bundlev1.BundleInfo{
			Label:      "label",
			BundleHash: wantChecksum1,
			Segments: []*bundlev1.BundleInfo_Segment{
				{
					SegmentId:    1,
					Checksum:     wantChecksum1,
					DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
				},
			},
		})
		haveEvent1 := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventNewBundle, haveEvent1.Kind, "Unexpected event kind")
		require.NotEmpty(t, haveEvent1.NewBundlePath, "BundlePath is empty")
		haveChecksum1 := checksum(t, haveEvent1.NewBundlePath)
		require.Equal(t, wantChecksum1, haveChecksum1, "Checksum does not match")
		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1.crbp"), "Path hit count does not match")
		cached1, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum1, checksum(t, cached1), "Checksum does not match for cached bundle")

		require.NoError(t, handle.ActiveBundleChanged(bundleID1), "Failed to acknowledge bundle swap")
		mockWatchSvc.requireRequestReceived(t, mkWBHeartbeatReq(bundleID1))

		mockWatchSvc.respondWithBundleUpdate(&bundlev1.BundleInfo{
			Label:      "label",
			BundleHash: wantChecksum2,
			Segments: []*bundlev1.BundleInfo_Segment{
				{
					SegmentId:    1,
					Checksum:     wantChecksum2,
					DownloadUrls: []string{fmt.Sprintf("%s/files/bundle2.crbp", server.URL)},
				},
			},
		})
		haveEvent2 := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventNewBundle, haveEvent2.Kind, "Unexpected event kind")
		require.NotEmpty(t, haveEvent2.NewBundlePath, "BundlePath is empty")
		haveChecksum2 := checksum(t, haveEvent2.NewBundlePath)
		require.Equal(t, wantChecksum2, haveChecksum2, "Checksum does not match")
		require.Equal(t, 2, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle2.crbp"), "Path hit count does not match")
		cached2, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum2, checksum(t, cached2), "Checksum does not match for cached bundle")

		require.NoError(t, handle.ActiveBundleChanged(bundleID2), "Failed to acknowledge bundle swap")
		mockWatchSvc.requireRequestReceived(t, mkWBHeartbeatReq(bundleID2))
	})

	t.Run("BadDownloadURL", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockWatchSvc := newMockBundleWatchService()
		server, counter := startTestServer(t, mockAPIKeySvc, mockWatchSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)
		expectIssueAccessToken(mockAPIKeySvc)

		handle, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")
		eventStream := handle.ServerEvents()

		mockWatchSvc.requireRequestReceived(t, mkWBWatchLabelReq("label"))
		mockWatchSvc.respondWithBundleUpdate(&bundlev1.BundleInfo{
			Label:      "label",
			BundleHash: wantChecksum,
			Segments: []*bundlev1.BundleInfo_Segment{
				{
					SegmentId:    1,
					Checksum:     wantChecksum,
					DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_BLAH.crbp", server.URL)},
				},
			},
		})

		haveEvent := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventError, haveEvent.Kind, "Unexpected event kind")
		require.Error(t, haveEvent.Error, "Expected error in event")
		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_BLAH.crbp"), "Path hit count does not match")
	})

	t.Run("BundleNotFound", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockWatchSvc := newMockBundleWatchService()

		server, _ := startTestServer(t, mockAPIKeySvc, mockWatchSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)
		expectIssueAccessToken(mockAPIKeySvc)

		handle, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")
		eventStream := handle.ServerEvents()

		mockWatchSvc.requireRequestReceived(t, mkWBWatchLabelReq("label"))
		mockWatchSvc.respondWithError(connect.NewError(connect.CodeNotFound, errors.New(" bundle not found")))

		haveEvent := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventError, haveEvent.Kind, "Unexpected event kind")
		require.Error(t, haveEvent.Error, "Error expected")
		require.ErrorIs(t, haveEvent.Error, bundle.ErrBundleNotFound, "Unexpected error kind")
	})

	t.Run("Reconnect", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockWatchSvc := newMockBundleWatchService()

		server, counter := startTestServer(t, mockAPIKeySvc, mockWatchSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		wantChecksum1 := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)
		expectIssueAccessToken(mockAPIKeySvc)

		handle, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")
		eventStream := handle.ServerEvents()

		mockWatchSvc.requireRequestReceived(t, mkWBWatchLabelReq("label"))
		mockWatchSvc.respondWithBundleUpdate(&bundlev1.BundleInfo{
			Label:      "label",
			BundleHash: wantChecksum1,
			Segments: []*bundlev1.BundleInfo_Segment{
				{
					SegmentId:    1,
					Checksum:     wantChecksum1,
					DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
				},
			},
		})

		haveEvent1 := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventNewBundle, haveEvent1.Kind, "Unexpected event kind")
		require.NotEmpty(t, haveEvent1.NewBundlePath, "BundlePath is empty")
		haveChecksum1 := checksum(t, haveEvent1.NewBundlePath)
		require.Equal(t, wantChecksum1, haveChecksum1, "Checksum does not match")
		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1.crbp"), "Path hit count does not match")

		mockWatchSvc.respondWithReconnect(1 * time.Minute)
		haveEvent2 := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventReconnect, haveEvent2.Kind, "Unexpected event kind")
		require.Equal(t, 1*time.Minute, haveEvent2.ReconnectBackoff)
	})

	t.Run("BundleRemoved", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockWatchSvc := newMockBundleWatchService()

		server, counter := startTestServer(t, mockAPIKeySvc, mockWatchSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())
		wantChecksum1 := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)
		expectIssueAccessToken(mockAPIKeySvc)

		handle, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")
		eventStream := handle.ServerEvents()

		mockWatchSvc.requireRequestReceived(t, mkWBWatchLabelReq("label"))
		mockWatchSvc.respondWithBundleUpdate(&bundlev1.BundleInfo{
			Label:      "label",
			BundleHash: wantChecksum1,
			Segments: []*bundlev1.BundleInfo_Segment{
				{
					SegmentId:    1,
					Checksum:     wantChecksum1,
					DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
				},
			},
		})

		haveEvent1 := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventNewBundle, haveEvent1.Kind, "Unexpected event kind")
		require.NotEmpty(t, haveEvent1.NewBundlePath, "BundlePath is empty")
		haveChecksum1 := checksum(t, haveEvent1.NewBundlePath)
		require.Equal(t, wantChecksum1, haveChecksum1, "Checksum does not match")
		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1.crbp"), "Path hit count does not match")

		mockWatchSvc.respondWithBundleRemoved()

		haveEvent2 := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventBundleRemoved, haveEvent2.Kind, "Unexpected event kind")
	})

	t.Run("AuthenticationFailure", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockBundleSvc := mockbundlev1connect.NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockAPIKeySvc, mockBundleSvc)
		t.Cleanup(server.Close)

		client, _ := mkClient(t, server.URL, server.Certificate())

		mockAPIKeySvc.EXPECT().
			IssueAccessToken(mock.Anything, mock.MatchedBy(issueAccessTokenRequest())).
			Return(nil, connect.NewError(connect.CodeUnauthenticated, errors.New("🙅")))

		_, err := client.WatchBundle(context.Background(), "label")
		require.Error(t, err)
		require.ErrorIs(t, err, bundle.ErrAuthenticationFailed)
	})
}

func mustPopFromChan[A any](t *testing.T, c <-chan A) (out A) {
	t.Helper()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case out = <-c:
		return out
	case <-timer.C:
		t.Fatal("Timed out waiting for channel")
		return out
	}
}

func mkWBWatchLabelReq(label string) *bundlev1.WatchBundleRequest {
	return &bundlev1.WatchBundleRequest{
		PdpId: pdpIdentifer,
		Msg: &bundlev1.WatchBundleRequest_WatchLabel_{
			WatchLabel: &bundlev1.WatchBundleRequest_WatchLabel{
				BundleLabel: label,
			},
		},
	}
}

func mkWBHeartbeatReq(bundleID string) *bundlev1.WatchBundleRequest {
	return &bundlev1.WatchBundleRequest{
		PdpId: pdpIdentifer,
		Msg: &bundlev1.WatchBundleRequest_Heartbeat_{
			Heartbeat: &bundlev1.WatchBundleRequest_Heartbeat{
				Timestamp:      timestamppb.Now(),
				ActiveBundleId: bundleID,
			},
		},
	}
}

func TestGetCachedBundle(t *testing.T) {
	t.Run("NonExistentLabel", func(t *testing.T) {
		client, _ := mkClient(t, "https://localhost", nil)
		_, err := client.GetCachedBundle("blah")
		require.Error(t, err)
	})
}

func TestNetworkIssues(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	toxic := startToxiProxy(t)

	t.Run("ServerDown", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockWatchSvc := newMockBundleWatchService()
		server, _ := startTestServer(t, mockAPIKeySvc, mockWatchSvc)
		t.Cleanup(server.Close)

		proxy := mkProxy(t, toxic, server.Listener.Addr().String())
		t.Cleanup(func() { _ = proxy.Delete() })

		client, _ := mkClient(t, "https://"+proxy.Listen, server.Certificate())
		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)

		require.NoError(t, proxy.Disable(), " Failed to apply toxic")

		_, err := client.WatchBundle(ctx, "label")
		require.Error(t, err, "Expected RPC to fail")
		require.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
	})

	t.Run("ServerReset", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockWatchSvc := newMockBundleWatchService()
		server, _ := startTestServer(t, mockAPIKeySvc, mockWatchSvc)
		t.Cleanup(server.Close)

		proxy := mkProxy(t, toxic, server.Listener.Addr().String())
		t.Cleanup(func() { _ = proxy.Delete() })

		client, _ := mkClient(t, "https://"+proxy.Listen, server.Certificate())

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)
		expectIssueAccessToken(mockAPIKeySvc)

		handle, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")
		eventStream := handle.ServerEvents()

		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		mockWatchSvc.requireRequestReceived(t, mkWBWatchLabelReq("label"))
		mockWatchSvc.respondWithBundleUpdate(&bundlev1.BundleInfo{
			Label:      "label",
			BundleHash: wantChecksum,
			Segments: []*bundlev1.BundleInfo_Segment{
				{
					SegmentId:    1,
					Checksum:     wantChecksum,
					DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
				},
			},
		})
		haveEvent1 := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventNewBundle, haveEvent1.Kind, "Unexpected event kind")
		require.NotEmpty(t, haveEvent1.NewBundlePath, "BundlePath is empty")

		_, err = proxy.AddToxic("", "reset_peer", "", 1, toxiclient.Attributes{"timeout": 10})
		require.NoError(t, err, "Failed to add toxic")

		require.NoError(t, handle.ActiveBundleChanged(randomCommit()), "Failed to notify bundle change")

		haveErr := mustPopFromChan(t, handle.Errors())
		require.Error(t, haveErr, "Expected error ")
		require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(haveErr))
	})

	t.Run("Timeout", func(t *testing.T) {
		mockAPIKeySvc := mockapikeyv1connect.NewApiKeyServiceHandler(t)
		mockWatchSvc := newMockBundleWatchService()
		server, _ := startTestServer(t, mockAPIKeySvc, mockWatchSvc)
		t.Cleanup(server.Close)

		proxy := mkProxy(t, toxic, server.Listener.Addr().String())
		t.Cleanup(func() { _ = proxy.Delete() })

		client, _ := mkClient(t, "https://"+proxy.Listen, server.Certificate())

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)
		expectIssueAccessToken(mockAPIKeySvc)

		handle, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")
		eventStream := handle.ServerEvents()

		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		mockWatchSvc.requireRequestReceived(t, mkWBWatchLabelReq("label"))
		mockWatchSvc.respondWithBundleUpdate(&bundlev1.BundleInfo{
			Label:      "label",
			BundleHash: wantChecksum,
			Segments: []*bundlev1.BundleInfo_Segment{
				{
					SegmentId:    1,
					Checksum:     wantChecksum,
					DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
				},
			},
		})
		haveEvent1 := mustPopFromChan(t, eventStream)
		require.Equal(t, bundle.ServerEventNewBundle, haveEvent1.Kind, "Unexpected event kind")
		require.NotEmpty(t, haveEvent1.NewBundlePath, "BundlePath is empty")

		_, err = proxy.AddToxic("", "timeout", "", 1, toxiclient.Attributes{"timeout": 50})
		require.NoError(t, err, "Failed to add toxic")

		require.NoError(t, handle.ActiveBundleChanged(randomCommit()), "Failed to notify bundle change")

		haveErr := mustPopFromChan(t, handle.Errors())
		require.Error(t, haveErr, "Expected error ")
		require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(haveErr))
	})
}

func startTestServer(t *testing.T, mockAPIKeySvc apikeyv1connect.ApiKeyServiceHandler, mockBundleSvc bundlev1connect.CerbosBundleServiceHandler) (*httptest.Server, *downloadCounter) {
	t.Helper()

	compress1KB := connect.WithCompressMinBytes(1024)
	fileHandler := http.FileServer(http.Dir("testdata"))
	apiKeyPath, apiKeySvcHandler := apikeyv1connect.NewApiKeyServiceHandler(mockAPIKeySvc, compress1KB)
	bundlePath, bundleSvcHandler := bundlev1connect.NewCerbosBundleServiceHandler(mockBundleSvc, connect.WithInterceptors(authCheck{}), compress1KB)

	counter := newDownloadCounter()

	logRequests := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("REQUEST: %s", r.URL)
			h.ServeHTTP(w, r)
		})
	}
	mux := http.NewServeMux()
	mux.Handle(apiKeyPath, logRequests(apiKeySvcHandler))
	mux.Handle(bundlePath, logRequests(bundleSvcHandler))
	mux.Handle("/files/", http.StripPrefix("/files/", counter.wrap(fileHandler)))
	mux.Handle("/bootstrap/", counter.wrap(fileHandler))
	mux.Handle(grpcreflect.NewHandlerV1(
		grpcreflect.NewStaticReflector(bundlev1connect.CerbosBundleServiceName),
		compress1KB,
	))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(
		grpcreflect.NewStaticReflector(bundlev1connect.CerbosBundleServiceName),
		compress1KB,
	))

	s := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	s.EnableHTTP2 = true
	s.StartTLS()

	return s, counter
}

func startToxiProxy(t *testing.T) *toxiclient.Client {
	t.Helper()

	host, port, err := getFreeListenAddr()
	require.NoError(t, err, "Failed to get free listen address")

	server := toxiproxy.NewServer(toxiproxy.NewMetricsContainer(nil), log.Logger)
	go server.Listen(host, port)
	runtime.Gosched()

	require.Eventually(t, func() bool {
		hc := &http.Client{}
		url := fmt.Sprintf("http://%s:%s/version", host, port)

		ctx, cancelFn := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancelFn()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return false
		}

		resp, err := hc.Do(req)
		if err != nil {
			return false
		}

		ok := resp.StatusCode == http.StatusOK
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		return ok
	}, 5*time.Second, 200*time.Millisecond)

	return toxiclient.NewClient(net.JoinHostPort(host, port))
}

func mkProxy(t *testing.T, client *toxiclient.Client, dest string) *toxiclient.Proxy {
	t.Helper()

	proxyHost, proxyPort, err := getFreeListenAddr()
	require.NoError(t, err, "Failed to get free listen address")

	proxyAddr := net.JoinHostPort(proxyHost, proxyPort)
	proxy, err := client.CreateProxy("cerbos", proxyAddr, dest)
	require.NoError(t, err, "Failed to create proxy")

	return proxy
}

func getFreeListenAddr() (string, string, error) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", "", err
	}
	defer lis.Close()

	addr := lis.Addr().String()
	return net.SplitHostPort(addr)
}

func checksum(t *testing.T, file string) []byte {
	t.Helper()

	f, err := os.Open(file)
	require.NoError(t, err, "Failed to open %s", file)
	t.Cleanup(func() { _ = f.Close() })

	sum := sha256.New()
	_, err = io.Copy(sum, f)
	require.NoError(t, err, "Failed to hash %s", file)

	return sum.Sum(nil)
}

func mkClient(t *testing.T, url string, cert *x509.Certificate) (*bundle.Client, *credentials.Credentials) {
	t.Helper()

	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o774), "Failed to create %s", cacheDir)

	tempDir := filepath.Join(tmp, "temp")
	require.NoError(t, os.MkdirAll(tempDir, 0o774), "Failed to create %s", tempDir)

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

	conf := bundle.ClientConf{
		Credentials:       creds,
		BootstrapEndpoint: url,
		APIEndpoint:       url,
		PDPIdentifier:     pdpIdentifer,
		RetryWaitMin:      10 * time.Millisecond,
		RetryWaitMax:      30 * time.Millisecond,
		RetryMaxAttempts:  2,
		CacheDir:          cacheDir,
		TempDir:           tempDir,
		Logger:            testr.NewWithOptions(t, testr.Options{Verbosity: 4}),
		TLS:               tlsConf,
	}

	client, err := bundle.NewClient(conf)
	require.NoError(t, err, "Failed to create client")

	return client, creds
}

type haveWatchReq struct {
	msg *bundlev1.WatchBundleRequest
	err error
}

type wantWatchResp struct {
	msg *bundlev1.WatchBundleResponse
	err error
}

type mockBundleWatchService struct {
	requests  chan haveWatchReq
	responses chan wantWatchResp
}

func newMockBundleWatchService() *mockBundleWatchService {
	return &mockBundleWatchService{
		requests:  make(chan haveWatchReq, 10),
		responses: make(chan wantWatchResp, 10),
	}
}

func (m *mockBundleWatchService) WatchBundle(ctx context.Context, stream *connect.BidiStream[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse]) error {
	// Wait for first message from client (start watch)
	msg, err := stream.Receive()
	m.requests <- haveWatchReq{msg: msg, err: err}
	if err != nil {
		return err
	}

	// Respond
	resp := <-m.responses
	if resp.err != nil {
		return resp.err
	}
	if err := stream.Send(resp.msg); err != nil {
		return err
	}

	// Now start bidi comms
	p := pool.New().WithContext(ctx).WithCancelOnError().WithFirstError()
	p.Go(func(ctx context.Context) (outErr error) {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}

			msg, err := stream.Receive()
			m.requests <- haveWatchReq{msg: msg, err: err}
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return fmt.Errorf("failed to receive message: %w", err)
			}
		}
	})

	p.Go(func(ctx context.Context) error {
		for {
			select {
			case resp := <-m.responses:
				if resp.err != nil {
					return resp.err
				}

				if err := stream.Send(resp.msg); err != nil {
					return fmt.Errorf("failed to send message: %w", err)
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})

	return p.Wait()
}

func (m *mockBundleWatchService) respondWithBundleUpdate(binfo *bundlev1.BundleInfo) {
	m.responses <- wantWatchResp{
		msg: &bundlev1.WatchBundleResponse{
			Msg: &bundlev1.WatchBundleResponse_BundleUpdate{
				BundleUpdate: binfo,
			},
		},
	}
}

func (m *mockBundleWatchService) respondWithReconnect(backoff time.Duration) {
	m.responses <- wantWatchResp{
		msg: &bundlev1.WatchBundleResponse{
			Msg: &bundlev1.WatchBundleResponse_Reconnect_{
				Reconnect: &bundlev1.WatchBundleResponse_Reconnect{
					Backoff: durationpb.New(backoff),
				},
			},
		},
	}
}

func (m *mockBundleWatchService) respondWithBundleRemoved() {
	m.responses <- wantWatchResp{
		msg: &bundlev1.WatchBundleResponse{
			Msg: &bundlev1.WatchBundleResponse_BundleRemoved_{
				BundleRemoved: &bundlev1.WatchBundleResponse_BundleRemoved{},
			},
		},
	}
}

func (m *mockBundleWatchService) respondWithError(err error) {
	m.responses <- wantWatchResp{err: err}
}

func (m *mockBundleWatchService) requireRequestReceived(t *testing.T, wantReq *bundlev1.WatchBundleRequest) {
	t.Helper()
	haveReq := mustPopFromChan(t, m.requests)
	require.NoError(t, haveReq.err, "Server error during receive")
	require.Empty(t,
		cmp.Diff(wantReq, haveReq.msg, protocmp.Transform(), protocmp.IgnoreFields(&bundlev1.WatchBundleRequest_Heartbeat{}, "timestamp")))
}

func (m *mockBundleWatchService) GetBundle(_ context.Context, _ *connect.Request[bundlev1.GetBundleRequest]) (*connect.Response[bundlev1.GetBundleResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("unimplemented"))
}

type authCheck struct{}

func (ac authCheck) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Header().Get(bundle.AuthTokenHeader) != "access-token" {
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
		if conn.RequestHeader().Get(bundle.AuthTokenHeader) != "access-token" {
			return connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or missing access token"))
		}

		return next(ctx, conn)
	})
}

type downloadCounter struct {
	paths map[string]int
	total int
	mu    sync.RWMutex
}

func newDownloadCounter() *downloadCounter {
	return &downloadCounter{paths: make(map[string]int)}
}

func (dc *downloadCounter) wrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dc.mu.Lock()
		dc.total++
		dc.paths[r.URL.Path]++
		dc.mu.Unlock()

		handler.ServeHTTP(w, r)
	})
}

func (dc *downloadCounter) getTotal() int {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	return dc.total
}

func (dc *downloadCounter) pathHits(path string) int {
	dc.mu.RLock()
	defer dc.mu.RUnlock()

	return dc.paths[path]
}

func expectIssueAccessToken(mockAPIKeySvc *mockapikeyv1connect.ApiKeyServiceHandler) {
	mockAPIKeySvc.EXPECT().
		IssueAccessToken(mock.Anything, mock.MatchedBy(issueAccessTokenRequest())).
		Return(connect.NewResponse(&apikeyv1.IssueAccessTokenResponse{
			AccessToken: "access-token",
			ExpiresIn:   durationpb.New(1 * time.Minute),
		}), nil)
}

func issueAccessTokenRequest() func(*connect.Request[apikeyv1.IssueAccessTokenRequest]) bool {
	return func(req *connect.Request[apikeyv1.IssueAccessTokenRequest]) bool {
		return req.Msg.ClientId == "client-id" && req.Msg.ClientSecret == "client-secret"
	}
}

func randomCommit() string {
	b := make([]byte, sha1.Size)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
