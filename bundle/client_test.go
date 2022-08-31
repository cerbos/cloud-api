// Copyright 2021-2022 Zenauth Ltd.

//go:build tests
// +build tests

package bundle_test

import (
	"context"
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

	toxiproxy "github.com/Shopify/toxiproxy/v2"
	toxiclient "github.com/Shopify/toxiproxy/v2/client"
	"github.com/bufbuild/connect-go"
	"github.com/cerbos/cloud-api/bundle"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1/bundlev1connect"
	pdpv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1"
	"github.com/go-logr/logr/testr"
	"github.com/minio/sha256-simd"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestGetBundle(t *testing.T) {
	t.Run("SingleSegment", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		mockSvc.EXPECT().
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
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		mockSvc.EXPECT().
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
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		mockSvc.EXPECT().
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
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)

		// first call returns bundle1
		wantChecksum1 := checksum(t, filepath.Join("testdata", "bundle1.crbp"))
		mockSvc.EXPECT().
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
		mockSvc.EXPECT().
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
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		mockSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(connect.NewResponse(&bundlev1.GetBundleResponse{
				BundleInfo: &bundlev1.BundleInfo{
					Label:      "label",
					BundleHash: wantChecksum,
					Segments: []*bundlev1.BundleInfo_Segment{
						{
							SegmentId:    1,
							Checksum:     wantChecksum,
							DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_BLAH.crbp", server.URL)},
						},
					},
				},
			}), nil).Once()

		_, err := client.GetBundle(context.Background(), "label")
		require.Error(t, err)

		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_BLAH.crbp"), "Path hit count does not match")
	})

	t.Run("SegmentNotAvailableForDownload", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		mockSvc.EXPECT().
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
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)

		mockSvc.EXPECT().
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
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)

		mockSvc.EXPECT().
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

	t.Run("RPCErrorRetries", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)

		mockSvc.EXPECT().
			GetBundle(mock.Anything, mock.MatchedBy(getBundleReq("label"))).
			Return(nil, connect.NewError(connect.CodeInternal, errors.New("internal error"))).
			Times(3)

		_, err := client.GetBundle(context.Background(), "label")
		require.Error(t, err)
		require.Equal(t, 0, counter.getTotal(), "Total download count does not match")
	})
}

func getBundleReq(wantLabel string) func(*connect.Request[bundlev1.GetBundleRequest]) bool {
	return func(c *connect.Request[bundlev1.GetBundleRequest]) bool {
		return c.Msg.GetBundleLabel() == wantLabel && c.Msg.GetPdpId().Instance == "instance"
	}
}

func TestWatchBundle(t *testing.T) {
	t.Run("NormalStream", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)
		wantChecksum1 := checksum(t, filepath.Join("testdata", "bundle1.crbp"))
		wantChecksum2 := checksum(t, filepath.Join("testdata", "bundle2.crbp"))

		wantResponses := []*bundlev1.WatchBundleResponse{
			{
				Msg: &bundlev1.WatchBundleResponse_BundleUpdate{
					BundleUpdate: &bundlev1.BundleInfo{
						Label:      "label",
						BundleHash: wantChecksum1,
						Segments: []*bundlev1.BundleInfo_Segment{
							{
								SegmentId:    1,
								Checksum:     wantChecksum1,
								DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
							},
						},
					},
				},
			},
			{
				Msg: &bundlev1.WatchBundleResponse_BundleUpdate{
					BundleUpdate: &bundlev1.BundleInfo{
						Label:      "label",
						BundleHash: wantChecksum2,
						Segments: []*bundlev1.BundleInfo_Segment{
							{
								SegmentId:    1,
								Checksum:     wantChecksum2,
								DownloadUrls: []string{fmt.Sprintf("%s/files/bundle2.crbp", server.URL)},
							},
						},
					},
				},
			},
		}

		mockSvc.EXPECT().
			WatchBundle(mock.Anything, mock.MatchedBy(watchBundleReq("label")), mock.Anything).
			Run(setServerStream(wantResponses, 10*time.Millisecond)).
			Return(nil)

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)

		eventStream, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")

		haveEvent1, ok := <-eventStream
		require.True(t, ok, "Event stream closed")
		require.NoError(t, haveEvent1.Error, "Unexpected error in event")
		require.NotEmpty(t, haveEvent1.BundlePath, "BundlePath is empty")
		haveChecksum1 := checksum(t, haveEvent1.BundlePath)
		require.Equal(t, wantChecksum1, haveChecksum1, "Checksum does not match")
		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1.crbp"), "Path hit count does not match")
		cached1, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum1, checksum(t, cached1), "Checksum does not match for cached bundle")

		haveEvent2, ok := <-eventStream
		require.True(t, ok, "Event stream closed")
		require.NoError(t, haveEvent2.Error, "Unexpected error in event")
		require.NotEmpty(t, haveEvent2.BundlePath, "BundlePath is empty")
		haveChecksum2 := checksum(t, haveEvent2.BundlePath)
		require.Equal(t, wantChecksum2, haveChecksum2, "Checksum does not match")
		require.Equal(t, 2, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle2.crbp"), "Path hit count does not match")
		cached2, err := client.GetCachedBundle("label")
		require.NoError(t, err, "Failed to get cached bundle")
		require.Equal(t, wantChecksum2, checksum(t, cached2), "Checksum does not match for cached bundle")

		_, ok = <-eventStream
		require.False(t, ok, "Event stream not closed")
	})

	t.Run("BadDownloadURL", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)
		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		wantResponses := []*bundlev1.WatchBundleResponse{
			{
				Msg: &bundlev1.WatchBundleResponse_BundleUpdate{
					BundleUpdate: &bundlev1.BundleInfo{
						Label:      "label",
						BundleHash: wantChecksum,
						Segments: []*bundlev1.BundleInfo_Segment{
							{
								SegmentId:    1,
								Checksum:     wantChecksum,
								DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1_BLAH.crbp", server.URL)},
							},
						},
					},
				},
			},
		}

		mockSvc.EXPECT().
			WatchBundle(mock.Anything, mock.MatchedBy(watchBundleReq("label")), mock.Anything).
			Run(setServerStream(wantResponses, 10*time.Millisecond)).
			Return(nil)

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)

		eventStream, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")

		haveEvent, ok := <-eventStream
		require.True(t, ok, "Event stream closed")
		require.Error(t, haveEvent.Error, "Expected error in event")
		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1_BLAH.crbp"), "Path hit count does not match")

		_, ok = <-eventStream
		require.False(t, ok, "Event stream not closed")
	})

	t.Run("BundleNotFound", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)

		mockSvc.EXPECT().
			WatchBundle(mock.Anything, mock.MatchedBy(watchBundleReq("label")), mock.Anything).
			Return(connect.NewError(connect.CodeNotFound, errors.New(" bundle not found")))

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)

		eventStream, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")

		haveEvent, ok := <-eventStream
		require.True(t, ok, "Event stream closed")
		require.Error(t, haveEvent.Error, "Error expected")
		require.Equal(t, connect.CodeNotFound, connect.CodeOf(haveEvent.Error), "Error code mismatch")

		_, ok = <-eventStream
		require.False(t, ok, "Event stream not closed")
	})

	t.Run("Reconnect", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, counter := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		client := mkClient(t, server.URL)
		wantChecksum1 := checksum(t, filepath.Join("testdata", "bundle1.crbp"))

		wantResponses := []*bundlev1.WatchBundleResponse{
			{
				Msg: &bundlev1.WatchBundleResponse_BundleUpdate{
					BundleUpdate: &bundlev1.BundleInfo{
						Label:      "label",
						BundleHash: wantChecksum1,
						Segments: []*bundlev1.BundleInfo_Segment{
							{
								SegmentId:    1,
								Checksum:     wantChecksum1,
								DownloadUrls: []string{fmt.Sprintf("%s/files/bundle1.crbp", server.URL)},
							},
						},
					},
				},
			},
			{
				Msg: &bundlev1.WatchBundleResponse_Reconnect_{
					Reconnect: &bundlev1.WatchBundleResponse_Reconnect{
						Backoff: durationpb.New(1 * time.Minute),
					},
				},
			},
		}

		mockSvc.EXPECT().
			WatchBundle(mock.Anything, mock.MatchedBy(watchBundleReq("label")), mock.Anything).
			Run(setServerStream(wantResponses, 10*time.Millisecond)).
			Return(nil)

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)

		eventStream, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")

		haveEvent1, ok := <-eventStream
		require.True(t, ok, "Event stream closed")
		require.NoError(t, haveEvent1.Error, "Unexpected error in event")
		require.NotEmpty(t, haveEvent1.BundlePath, "BundlePath is empty")
		haveChecksum1 := checksum(t, haveEvent1.BundlePath)
		require.Equal(t, wantChecksum1, haveChecksum1, "Checksum does not match")
		require.Equal(t, 1, counter.getTotal(), "Total download count does not match")
		require.Equal(t, 1, counter.pathHits("bundle1.crbp"), "Path hit count does not match")

		haveEvent2, ok := <-eventStream
		require.True(t, ok, "Event stream closed")
		require.Error(t, haveEvent2.Error, "Expected error in event")

		wantErr := new(bundle.ErrReconnect)
		require.ErrorAs(t, haveEvent2.Error, wantErr, "Error is not a reconnect error")
		require.Equal(t, 1*time.Minute, wantErr.Backoff, "Backoff duration mismatch")

		_, ok = <-eventStream
		require.False(t, ok, "Event stream not closed")
	})
}

func TestGetCachedBundle(t *testing.T) {
	t.Run("NonExistentLabel", func(t *testing.T) {
		client := mkClient(t, "https://localhost")
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
		client := mkClient(t, "http://127.0.0.10:6666")

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)

		eventStream, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")

		haveEvent, ok := <-eventStream
		require.True(t, ok, "Event stream closed")
		require.Error(t, haveEvent.Error, "Expected error in event")
		require.Equal(t, connect.CodeUnavailable, connect.CodeOf(haveEvent.Error))

		_, ok = <-eventStream
		require.False(t, ok, "Event stream not closed")
	})

	t.Run("ServerReset", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))
		wantResponses := []*bundlev1.WatchBundleResponse{
			{
				Msg: &bundlev1.WatchBundleResponse_BundleUpdate{
					BundleUpdate: &bundlev1.BundleInfo{
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
				},
			},
		}

		mockSvc.EXPECT().
			WatchBundle(mock.Anything, mock.MatchedBy(watchBundleReq("label")), mock.Anything).
			Run(setServerStream(wantResponses, 30*time.Millisecond)).
			Return(nil)

		proxy := mkProxy(t, toxic, server.Listener.Addr().String())
		t.Cleanup(func() { _ = proxy.Delete() })

		client := mkClient(t, "http://"+proxy.Listen)

		_, err := proxy.AddToxic("", "reset_peer", "", 1, toxiclient.Attributes{"timeout": 10})
		require.NoError(t, err, "Failed to add toxic")

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)

		eventStream, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")

		haveEvent, ok := <-eventStream
		require.True(t, ok, "Event stream closed")
		require.Error(t, haveEvent.Error, "Expected error in event")
		require.Equal(t, connect.CodeUnavailable, connect.CodeOf(haveEvent.Error))

		_, ok = <-eventStream
		require.False(t, ok, "Event stream not closed")
	})

	t.Run("Timeout", func(t *testing.T) {
		mockSvc := NewCerbosBundleServiceHandler(t)
		server, _ := startTestServer(t, mockSvc)
		t.Cleanup(server.Close)

		wantChecksum := checksum(t, filepath.Join("testdata", "bundle1.crbp"))
		wantResponses := []*bundlev1.WatchBundleResponse{
			{
				Msg: &bundlev1.WatchBundleResponse_BundleUpdate{
					BundleUpdate: &bundlev1.BundleInfo{
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
				},
			},
		}

		mockSvc.EXPECT().
			WatchBundle(mock.Anything, mock.MatchedBy(watchBundleReq("label")), mock.Anything).
			Run(setServerStream(wantResponses, 30*time.Millisecond)).
			Return(nil)

		proxy := mkProxy(t, toxic, server.Listener.Addr().String())
		t.Cleanup(func() { _ = proxy.Delete() })

		client := mkClient(t, "http://"+proxy.Listen)

		_, err := proxy.AddToxic("", "timeout", "", 1, toxiclient.Attributes{"timeout": 50})
		require.NoError(t, err, "Failed to add toxic")

		ctx, cancelFn := context.WithCancel(context.Background())
		t.Cleanup(cancelFn)

		eventStream, err := client.WatchBundle(ctx, "label")
		require.NoError(t, err, "Failed to call RPC")

		// TODO(cell): How to send back an error to the client in this case?
		_, ok := <-eventStream
		require.False(t, ok, "Event stream not closed")
	})
}

func watchBundleReq(wantLabel string) func(*connect.Request[bundlev1.WatchBundleRequest]) bool {
	return func(c *connect.Request[bundlev1.WatchBundleRequest]) bool {
		return c.Msg.GetBundleLabel() == wantLabel && c.Msg.GetPdpId().Instance == "instance"
	}
}

func setServerStream(responses []*bundlev1.WatchBundleResponse, delay time.Duration) func(context.Context, *connect.Request[bundlev1.WatchBundleRequest], *connect.ServerStream[bundlev1.WatchBundleResponse]) {
	return func(_ context.Context, _ *connect.Request[bundlev1.WatchBundleRequest], stream *connect.ServerStream[bundlev1.WatchBundleResponse]) {
		for _, r := range responses {
			time.Sleep(delay)
			if err := stream.Send(r); err != nil {
				panic(err)
			}
		}
	}
}

func startTestServer(t *testing.T, mockSvc bundlev1connect.CerbosBundleServiceHandler) (*httptest.Server, *downloadCounter) {
	t.Helper()

	fileHandler := http.FileServer(http.Dir("testdata"))
	path, svcHandler := bundlev1connect.NewCerbosBundleServiceHandler(mockSvc, connect.WithInterceptors(authCheck{}))

	counter := newDownloadCounter()

	mux := http.NewServeMux()
	mux.Handle(path, svcHandler)
	mux.Handle("/files/", http.StripPrefix("/files/", counter.wrap(fileHandler)))

	s := httptest.NewUnstartedServer(h2c.NewHandler(mux, &http2.Server{}))
	s.EnableHTTP2 = true
	s.Start()

	return s, counter
}

func startToxiProxy(t *testing.T) *toxiclient.Client {
	t.Helper()

	host, port, err := getFreeListenAddr()
	require.NoError(t, err, "Failed to get free listen address")

	server := toxiproxy.NewServer(toxiproxy.NewMetricsContainer(nil))
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

func mkClient(t *testing.T, url string) *bundle.Client {
	t.Helper()

	tmp := t.TempDir()
	cacheDir := filepath.Join(tmp, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o774), "Failed to create %s", cacheDir)

	tempDir := filepath.Join(tmp, "temp")
	require.NoError(t, os.MkdirAll(tempDir, 0o774), "Failed to create %s", tempDir)

	conf := bundle.ClientConf{
		APIKey:           "apikey",
		ServerURL:        url,
		PDPIdentifier:    &pdpv1.Identifier{Instance: "instance", Version: "0.19.0"},
		RetryWaitMin:     10 * time.Millisecond,
		RetryWaitMax:     30 * time.Millisecond,
		RetryMaxAttempts: 2,
		CacheDir:         cacheDir,
		TempDir:          tempDir,
		Logger:           testr.NewWithOptions(t, testr.Options{Verbosity: 2}),
	}

	client, err := bundle.NewClient(conf)
	require.NoError(t, err, "Failed to create client")

	return client
}

type authCheck struct{}

func (ac authCheck) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Header().Get(bundle.APIKeyHeader) != "apikey" {
			return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or missing API key"))
		}
		return next(ctx, req)
	})
}

func (ac authCheck) WrapStreamingClient(c connect.StreamingClientFunc) connect.StreamingClientFunc {
	return c
}

func (ac authCheck) WrapStreamingHandler(h connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if conn.RequestHeader().Get(bundle.APIKeyHeader) != "apikey" {
			return connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or missing API key"))
		}

		return h(ctx, conn)
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
