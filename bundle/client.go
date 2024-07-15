// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unicode"

	"connectrpc.com/connect"
	"github.com/go-logr/logr"
	"github.com/minio/sha256-simd"
	"github.com/rogpeppe/go-internal/cache"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cloud-api/base"
	bootstrapv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bootstrap/v1"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1/bundlev1connect"
)

const (
	bootstrapPathPrefix = "bootstrap/v1"
	defaultBackoff      = 5 * time.Minute
	maxDownloadAttempts = 3

	bufPeekSize      = 256
	bufSize          = 10 * 1024   // 10 KiB
	maxBootstrapSize = 1024 * 1024 // 1MiB
)

var jsonStart = []byte("{")

const (
	BundleIDUnknown  = "__unknown__"
	BundleIDOrphaned = "__orphaned__"
)

var (
	ErrBootstrapBundleNotFound = errors.New("bootstrap bundle not found")
	ErrBundleNotFound          = errors.New("bundle not found")
	errChecksumMismatch        = errors.New("checksum mismatch")
	errDownloadFailed          = errors.New("download failed")
	errInvalidResponse         = errors.New("invalid response from server")
	errNoSegmentDownloadURL    = errors.New("no download URLs")
	errStreamEnded             = errors.New("stream ended")
)

// ReconnectError is the error returned when the server requests a reconnect.
type ReconnectError struct {
	Backoff time.Duration
}

func (er ReconnectError) Error() string {
	return fmt.Sprintf("reconnect in %s", er.Backoff)
}

// ServerEventKind represents events sent by the server through the watch stream.
type ServerEventKind uint8

const (
	ServerEventUndefined ServerEventKind = iota
	ServerEventError
	ServerEventNewBundle
	ServerEventBundleRemoved
	ServerEventReconnect
)

type ServerEvent struct {
	Error            error
	NewBundlePath    string
	ReconnectBackoff time.Duration
	Kind             ServerEventKind
}

// ClientEventKind represents events sent by the client through the watch stream.
type ClientEventKind uint8

const (
	ClientEventUndefined ClientEventKind = iota
	ClientEventBundleSwap
)

type ClientEvent struct {
	ActiveBundleID string
	Kind           ClientEventKind
}

type Client struct {
	rpcClient   bundlev1connect.CerbosBundleServiceClient
	bundleCache *cache.Cache
	conf        ClientConf
	base.Client
}

func NewClient(conf ClientConf, baseClient base.Client, options []connect.ClientOption) (*Client, error) {
	if err := conf.Validate(); err != nil {
		return nil, err
	}

	bcache, err := mkBundleCache(conf.CacheDir)
	if err != nil {
		return nil, err
	}

	httpClient := baseClient.StdHTTPClient() // Bidi streams don't work with retryable HTTP client.
	rpcClient := bundlev1connect.NewCerbosBundleServiceClient(httpClient, baseClient.APIEndpoint, options...)

	return &Client{
		Client:      baseClient,
		bundleCache: bcache,
		conf:        conf,
		rpcClient:   rpcClient,
	}, nil
}

func mkBundleCache(path string) (*cache.Cache, error) {
	cacheDir := path
	if cacheDir == "" {
		userCacheDir, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("failed to determine user cache directory: %w", err)
		}

		cacheDir = filepath.Join(userCacheDir, "cerbos", "cloud", "bundles")
		//nolint:gomnd
		if err := os.MkdirAll(cacheDir, 0o774); err != nil {
			return nil, fmt.Errorf("failed to create cache directory %q: %w", cacheDir, err)
		}
	}

	c, err := cache.Open(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache at %q: %w", cacheDir, err)
	}

	return c, nil
}

func (c *Client) BootstrapBundle(ctx context.Context, bundleLabel string) (string, error) {
	log := c.Logger.WithValues("bundle", bundleLabel)
	log.V(1).Info("Getting bootstrap configuration")

	wsID := c.Credentials.HashString(c.Credentials.WorkspaceID)
	labelHash := c.Credentials.HashString(bundleLabel)
	bootstrapURL, err := url.JoinPath(c.BootstrapEndpoint, bootstrapPathPrefix, wsID, labelHash)
	if err != nil {
		return "", fmt.Errorf("failed to construct bootstrap URL: %w", err)
	}

	bootstrapConf, err := c.downloadBootstrapConf(ctx, bootstrapURL)
	if err != nil {
		log.Error(err, "Failed to download bootstrap configuration")
		return "", err
	}

	if meta := bootstrapConf.Meta; meta != nil {
		log.Info("Bootstrap configuration downloaded", "created_at", meta.CreatedAt.AsTime(), "commit_hash", meta.CommitHash)
	}

	base.LogResponsePayload(log, bootstrapConf)
	return c.getBundleFile(logr.NewContext(ctx, log), bootstrapConf.BundleInfo)
}

func (c *Client) downloadBootstrapConf(ctx context.Context, url string) (*bootstrapv1.PDPConfig, error) {
	log := logr.FromContextOrDiscard(ctx).WithValues("url", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		log.V(1).Error(err, "Failed to construct download request")
		return nil, fmt.Errorf("failed to construct download request: %w", err)
	}

	log.V(1).Info("Sending download request")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.V(1).Error(err, "Failed to send download request")
		return nil, fmt.Errorf("failed to send download request: %w", err)
	}

	log.V(1).Info(fmt.Sprintf("Download request status: %s", resp.Status))
	defer func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			log.V(1).Info("Bootstrap bundle not found")
			return nil, ErrBootstrapBundleNotFound
		}

		log.V(1).Info("Failed to download bootstrap bundle")
		return nil, errDownloadFailed
	}

	confData, err := c.Credentials.Decrypt(io.LimitReader(resp.Body, maxBootstrapSize))
	if err != nil {
		return nil, err
	}

	return c.parseBootstrapConf(confData)
}

func (c *Client) parseBootstrapConf(input io.Reader) (*bootstrapv1.PDPConfig, error) {
	confBytes, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted bootstrap configuration: %w", err)
	}

	trimmed := bytes.TrimLeftFunc(confBytes, unicode.IsSpace)
	out := &bootstrapv1.PDPConfig{}
	if bytes.HasPrefix(trimmed, jsonStart) {
		unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
		if err := unmarshaler.Unmarshal(trimmed, out); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bootstrap JSON: %w", err)
		}
	} else if err := out.UnmarshalVT(trimmed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bootstrap proto: %w", err)
	}

	if err := Validate(out); err != nil {
		return out, fmt.Errorf("invalid bootstrap configuration: %w", err)
	}

	return out, nil
}

// GetBundle returns the path to the bundle with the given label.
func (c *Client) GetBundle(ctx context.Context, bundleLabel string) (string, error) {
	log := c.Logger.WithValues("bundle", bundleLabel)
	log.V(1).Info("Calling GetBundle RPC")

	resp, err := c.rpcClient.GetBundle(ctx, connect.NewRequest(&bundlev1.GetBundleRequest{
		PdpId:       c.PDPIdentifier,
		BundleLabel: bundleLabel,
	}))
	if err != nil {
		log.Error(err, "GetBundle RPC failed")
		return "", err
	}

	base.LogResponsePayload(log, resp.Msg)

	return c.getBundleFile(logr.NewContext(ctx, log), resp.Msg.BundleInfo)
}

func (c *Client) WatchBundle(ctx context.Context, bundleLabel string) (WatchHandle, error) {
	log := c.Logger.WithValues("bundle", bundleLabel)
	log.V(1).Info("Calling WatchBundle RPC")

	stream := c.rpcClient.WatchBundle(ctx)
	if err := stream.Send(nil); err != nil {
		log.V(1).Error(err, "Failed to send request headers")
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
		return nil, fmt.Errorf("failed to send request headers: %w", err)
	}

	wh := &watchHandleImpl{
		serverEvents: make(chan ServerEvent, 1),
		clientEvents: make(chan ClientEvent, 1),
		errors:       make(chan error, 1),
		bundleLabel:  bundleLabel,
		p:            pool.New().WithContext(ctx).WithCancelOnError().WithFirstError(),
	}

	wh.p.Go(c.watchStreamRecv(stream, wh, log))
	wh.p.Go(c.watchStreamSend(stream, wh, log))
	go func() {
		if err := wh.wait(); err != nil {
			switch {
			case errors.Is(err, context.Canceled):
				log.V(2).Info("Watch stream terminated: context cancelled")
			case errors.Is(err, ErrBundleNotFound):
				log.V(2).Info("Watch stream terminated: bundle not found")
			case errors.As(err, &ReconnectError{}):
				log.V(2).Info("Watch stream terminated: server requests reconnect")
			default:
				log.V(2).Error(err, "Watch stream terminated")
			}
			return
		}
		log.V(2).Info("Watch stream terminated")
	}()

	return wh, nil
}

type recvMsg struct {
	msg *bundlev1.WatchBundleResponse
	err error
}

func (c *Client) watchStreamRecv(stream *connect.BidiStreamForClient[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse], wh *watchHandleImpl, logger logr.Logger) func(context.Context) error {
	return func(ctx context.Context) (outErr error) {
		log := logger.WithName("recv")
		log.V(1).Info("Starting response handler")

		recvChan := make(chan recvMsg, 1)
		go func() {
			defer func() {
				close(recvChan)
				if err := stream.CloseResponse(); err != nil && !errors.Is(err, context.Canceled) {
					log.V(2).Error(err, "Error while closing response stream")
				}
			}()

			for {
				if err := ctx.Err(); err != nil {
					return
				}

				log.V(3).Info("Waiting to receive message")
				msg, err := stream.Receive()
				log.V(3).Info("Received message")

				recvChan <- recvMsg{msg: msg, err: err}
				if err != nil {
					if errors.Is(err, context.Canceled) {
						log.V(3).Info("Exiting receive loop")
					} else {
						log.V(3).Error(err, "Exiting receive loop due to error")
					}
					return
				}
			}
		}()

		publishWatchEvent := func(we ServerEvent) error {
			log.V(3).Info("Publishing watch event")
			select {
			case wh.serverEvents <- we:
				log.V(3).Info("Published watch event")
				return nil
			case <-ctx.Done():
				log.V(3).Info("Failed to publish watch event due to context cancellation")
				return ctx.Err()
			}
		}

		processMsg := func(msg *bundlev1.WatchBundleResponse) error {
			base.LogResponsePayload(log, msg)

			switch m := msg.Msg.(type) {
			case *bundlev1.WatchBundleResponse_BundleUpdate:
				log.V(2).Info("Received bundle update")
				bundlePath, err := c.getBundleFile(ctx, m.BundleUpdate)
				if err != nil {
					log.V(1).Error(err, "Failed to get bundle")
					if err := publishWatchEvent(ServerEvent{Kind: ServerEventError, Error: err}); err != nil {
						log.V(2).Error(err, "Failed to send error")
					}

					return err
				}

				if err := publishWatchEvent(ServerEvent{Kind: ServerEventNewBundle, NewBundlePath: bundlePath}); err != nil {
					return err
				}

			case *bundlev1.WatchBundleResponse_BundleRemoved_:
				log.V(1).Info("Bundle label removed")
				if err := publishWatchEvent(ServerEvent{Kind: ServerEventBundleRemoved}); err != nil {
					log.V(2).Error(err, "Failed to send bundle removed")
				}

			case *bundlev1.WatchBundleResponse_Reconnect_:
				log.V(1).Info("Server requests reconnect")
				backoff := defaultBackoff
				if m.Reconnect != nil && m.Reconnect.Backoff != nil {
					backoff = m.Reconnect.Backoff.AsDuration()
				}

				if err := publishWatchEvent(ServerEvent{Kind: ServerEventReconnect, ReconnectBackoff: backoff}); err != nil {
					log.V(2).Error(err, "Failed to send reconnect")
				}

				return ReconnectError{Backoff: backoff}

			default:
				log.V(2).Info("Ignoring unknown message", "msg", base.NewProtoWrapper(msg))
			}

			return nil
		}

		for {
			select {
			case r, ok := <-recvChan:
				if r.err != nil {
					if errors.Is(r.err, io.EOF) {
						log.V(2).Info("Response stream terminated by server")
						return r.err
					}

					if connect.CodeOf(r.err) == connect.CodeNotFound {
						log.V(1).Error(r.err, "Label does not exist")
						_ = publishWatchEvent(ServerEvent{Kind: ServerEventError, Error: ErrBundleNotFound})
						return ErrBundleNotFound
					}

					log.V(1).Error(r.err, "Error receiving message")
					_ = publishWatchEvent(ServerEvent{Kind: ServerEventError, Error: r.err})
					return r.err
				}

				if r.msg != nil {
					if err := processMsg(r.msg); err != nil {
						return err
					}
				}

				if !ok {
					log.V(2).Info("Receive loop ended")
					return errStreamEnded
				}
			case <-ctx.Done():
				log.V(2).Info("Exiting response handler due to context cancellation")
				return ctx.Err()
			}
		}
	}
}

func (c *Client) watchStreamSend(stream *connect.BidiStreamForClient[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse], wh *watchHandleImpl, logger logr.Logger) func(context.Context) error {
	return func(ctx context.Context) (outErr error) {
		log := logger.WithName("send")
		log.V(1).Info("Starting request handler")

		var ticker *time.Ticker
		var tickerChan <-chan time.Time

		if c.HeartbeatInterval > 0 {
			ticker = time.NewTicker(c.HeartbeatInterval)
			tickerChan = ticker.C
		} else {
			log.V(1).Info("Regular heartbeats disabled")
			tickerChan = make(chan time.Time)
		}

		defer func() {
			log.V(1).Info("Exiting request handler")
			if ticker != nil {
				ticker.Stop()
			}

			if err := stream.CloseRequest(); err != nil {
				if !errors.Is(err, context.Canceled) {
					log.V(1).Error(err, "Failed to close request stream")
					outErr = multierr.Append(outErr, err)
				}
			}
		}()

		log.V(2).Info("Initiating bundle watch")
		if err := stream.Send(&bundlev1.WatchBundleRequest{
			PdpId: c.PDPIdentifier,
			Msg: &bundlev1.WatchBundleRequest_WatchLabel_{
				WatchLabel: &bundlev1.WatchBundleRequest_WatchLabel{BundleLabel: wh.bundleLabel},
			},
		}); err != nil {
			log.Error(err, "WatchBundle RPC failed")
			return err
		}

		sendHeartbeat := func(activeBundleID string) error {
			log.V(3).Info("Sending heartbeat", "active_bundle_id", activeBundleID)
			if err := stream.Send(&bundlev1.WatchBundleRequest{
				PdpId: c.PDPIdentifier,
				Msg: &bundlev1.WatchBundleRequest_Heartbeat_{
					Heartbeat: &bundlev1.WatchBundleRequest_Heartbeat{
						Timestamp:      timestamppb.Now(),
						ActiveBundleId: activeBundleID,
					},
				},
			}); err != nil {
				log.V(1).Error(err, "Failed to send heartbeat")
				return err
			}

			return nil
		}

		log.V(2).Info("Starting heartbeat loop")
		activeBundleID := BundleIDUnknown
		for {
			select {
			case <-ctx.Done():
				log.V(2).Info("Terminating request handler due to context cancellation")
				return ctx.Err()
			case evt := <-wh.clientEvents:
				switch evt.Kind {
				case ClientEventBundleSwap:
					if activeBundleID != evt.ActiveBundleID {
						log.V(3).Info("Sending bundle change event")
						activeBundleID = evt.ActiveBundleID
						if err := sendHeartbeat(activeBundleID); err != nil {
							return err
						}
					}
				default:
					log.V(2).Info("Ignoring unknown client event", "event", evt)
				}
			case <-tickerChan:
				if err := sendHeartbeat(activeBundleID); err != nil {
					return err
				}
			}
		}
	}
}

func (c *Client) getBundleFile(ctx context.Context, binfo *bundlev1.BundleInfo) (outPath string, outErr error) {
	log := logr.FromContextOrDiscard(ctx)

	if len(binfo.BundleHash) != cache.HashSize {
		err := fmt.Errorf("length of bundle hash %x does not match expected hash size", binfo.BundleHash)
		log.Error(err, "Invalid bundle hash")
		return "", err
	}

	bdlCacheKey := *((*cache.ActionID)(binfo.BundleHash))
	defer func() {
		if outErr == nil && outPath != "" {
			if err := c.updateLabelCache(binfo.Label, bdlCacheKey); err != nil {
				log.V(1).Error(err, "Failed to update label mapping")
			}
		}
	}()

	entry, err := c.bundleCache.Get(bdlCacheKey)
	if err == nil {
		log.V(1).Info("Bundle exists in cache")
		return c.bundleCache.OutputFile(entry.OutputID), nil
	}

	log.V(1).Info("Downloading bundle segments")
	segments := binfo.Segments

	switch len(segments) {
	case 0:
		log.V(1).Info("No segments provided")
		return "", errInvalidResponse
	case 1:
		return c.downloadSegment(logr.NewContext(ctx, log), bdlCacheKey, segments[0])
	default:
		sort.Slice(segments, func(i, j int) bool { return segments[i].SegmentId < segments[j].SegmentId })
		// TODO(cell): Check segment IDs are sequential (not missing any IDs)
		// TODO(cell): Download in parallel if there are many segments

		joiner := newSegmentJoiner(len(segments))
		for _, s := range segments {
			logger := log.WithValues("segment", s.SegmentId)
			logger.V(1).Info("Getting segment")

			segFile, err := c.getSegmentFile(logr.NewContext(ctx, logger), s)
			if err != nil {
				_ = joiner.Close()
				logger.Error(err, "Failed to get bundle segment")
				return "", err
			}

			if err := joiner.add(segFile); err != nil {
				_ = joiner.Close()
				logger.Error(err, "Failed to open bundle segment")
				return "", err
			}
		}

		file, _, err := c.addToCache(bdlCacheKey, joiner.join())
		return file, err
	}
}

func (c *Client) getSegmentFile(ctx context.Context, segment *bundlev1.BundleInfo_Segment) (string, error) {
	log := logr.FromContextOrDiscard(ctx)

	cacheKey := segmentCacheKey(segment.Checksum)
	entry, err := c.bundleCache.Get(cacheKey)
	if err == nil {
		log.V(1).Info("Cache hit for segment")
		return c.bundleCache.OutputFile(entry.OutputID), nil
	}

	log.V(1).Info("Cache miss: downloading segment")
	return c.downloadSegment(ctx, cacheKey, segment)
}

func (c *Client) downloadSegment(ctx context.Context, cacheKey cache.ActionID, segment *bundlev1.BundleInfo_Segment) (string, error) {
	if len(segment.DownloadUrls) == 0 {
		return "", errNoSegmentDownloadURL
	}

	r := newRing(segment.DownloadUrls)
	return c.doDownloadSegment(ctx, cacheKey, segment, r, 1)
}

func (c *Client) doDownloadSegment(ctx context.Context, cacheKey cache.ActionID, segment *bundlev1.BundleInfo_Segment, r *ring, attempt int) (string, error) {
	downloadURL := r.next()
	log := logr.FromContextOrDiscard(ctx).WithValues("url", downloadURL, "attempt", attempt)
	log.V(1).Info("Constructing download request")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, http.NoBody)
	if err != nil {
		log.V(1).Error(err, "Failed to construct download request")
		return "", fmt.Errorf("failed to construct download request: %w", err)
	}

	log.V(1).Info("Sending download request")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.V(1).Error(err, "Failed to send download request")
		if r.size() > 1 && attempt < maxDownloadAttempts {
			return c.doDownloadSegment(ctx, cacheKey, segment, r, attempt+1)
		}

		return "", fmt.Errorf("failed to send download request: %w", err)
	}

	log.V(1).Info(fmt.Sprintf("Download request status: %s", resp.Status))
	defer func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	switch {
	case resp.StatusCode == http.StatusOK:
		return c.addSegmentToCache(ctx, cacheKey, segment.Checksum, resp)
	case resp.StatusCode >= 404 && r.size() > 1 && attempt < maxDownloadAttempts:
		log.V(1).Info("Retrying download")
		return c.doDownloadSegment(ctx, cacheKey, segment, r, attempt+1)
	default:
		log.V(1).Info("Download failed")
		return "", errDownloadFailed
	}
}

func (c *Client) addSegmentToCache(_ context.Context, cacheKey cache.ActionID, checksum []byte, resp *http.Response) (string, error) {
	file, cs, err := c.addToCache(cacheKey, resp.Body)
	if err != nil {
		return "", err
	}

	if !bytes.Equal(checksum, cs) {
		return "", errChecksumMismatch
	}

	return file, nil
}

func (c *Client) addToCache(cacheKey cache.ActionID, in io.Reader) (string, []byte, error) {
	outFile, err := os.CreateTemp(c.conf.TempDir, "cerbos-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		_ = outFile.Close()
		_ = os.Remove(outFile.Name())
	}()

	sum := sha256.New()
	mw := io.MultiWriter(outFile, sum)
	if _, err := io.Copy(mw, in); err != nil {
		return "", nil, fmt.Errorf("failed to write data to disk: %w", err)
	}

	out, _, err := c.bundleCache.Put(cacheKey, outFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to add data to cache: %w", err)
	}

	return c.bundleCache.OutputFile(out), sum.Sum(nil), nil
}

func (c *Client) updateLabelCache(bundleLabel string, bundleCacheKey cache.ActionID) error {
	lblCacheKey := labelCacheKey(bundleLabel)
	return c.bundleCache.PutBytes(lblCacheKey, bundleCacheKey[:])
}

// GetCachedBundle returns the last cached entry for the given label if it exists.
func (c *Client) GetCachedBundle(bundleLabel string) (string, error) {
	lblCacheKey := labelCacheKey(bundleLabel)
	entry, _, err := c.bundleCache.GetBytes(lblCacheKey)
	if err != nil {
		return "", fmt.Errorf("no cache entry for %s: %w", bundleLabel, err)
	}

	if len(entry) != cache.HashSize {
		return "", errors.New("invalid cache entry for label")
	}

	bdlCacheKey := *((*cache.ActionID)(entry))
	bdlEntry, err := c.bundleCache.Get(bdlCacheKey)
	if err != nil {
		return "", fmt.Errorf("failed to find bundle in cache: %w", err)
	}

	return c.bundleCache.OutputFile(bdlEntry.OutputID), nil
}

func segmentCacheKey(checksum []byte) cache.ActionID {
	s := sha256.New()
	_, _ = fmt.Fprint(s, "segment:")
	_, _ = s.Write(checksum)
	return *((*cache.ActionID)(s.Sum(nil)))
}

func labelCacheKey(label string) cache.ActionID {
	s := sha256.New()
	_, _ = fmt.Fprintf(s, "cerbos:cloud:bundle:label=%s", label)
	return *((*cache.ActionID)(s.Sum(nil)))
}

type segmentJoiner struct {
	readers []io.ReadCloser
}

func newSegmentJoiner(numSegments int) *segmentJoiner {
	return &segmentJoiner{readers: make([]io.ReadCloser, 0, numSegments)}
}

func (sj *segmentJoiner) add(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open %q: %w", file, err)
	}

	sj.readers = append(sj.readers, f)
	return nil
}

func (sj *segmentJoiner) Close() (outErr error) {
	for _, r := range sj.readers {
		if err := r.Close(); err != nil {
			outErr = multierr.Append(outErr, err)
		}
	}

	return outErr
}

func (sj *segmentJoiner) join() io.ReadCloser {
	readers := make([]io.Reader, len(sj.readers))
	for i, r := range sj.readers {
		readers[i] = r
	}

	mr := io.MultiReader(readers...)
	return struct {
		io.Reader
		*segmentJoiner
	}{
		Reader:        mr,
		segmentJoiner: sj,
	}
}

type ring struct {
	elements []string
	idx      int
}

func newRing(elements []string) *ring {
	return &ring{
		elements: elements,
		idx:      rand.Intn(len(elements)), //nolint:gosec
	}
}

func (r *ring) next() string {
	el := r.elements[r.idx]
	r.idx = (r.idx + 1) % len(r.elements)
	return el
}

func (r *ring) size() int {
	return len(r.elements)
}
