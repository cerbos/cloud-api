// Copyright 2021-2023 Zenauth Ltd.

package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/bufbuild/connect-go"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1/bundlev1connect"
	"github.com/go-logr/logr"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/minio/sha256-simd"
	"github.com/rogpeppe/go-internal/cache"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/multierr"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	defaultBackoff      = 5 * time.Minute
	maxDownloadAttempts = 3
)

var (
	ErrBundleNotFound       = errors.New("bundle not found")
	ErrBundleRemoved        = errors.New("bundle removed")
	errChecksumMismatch     = errors.New("checksum mismatch")
	errDownloadFailed       = errors.New("download failed")
	errInvalidResponse      = errors.New("invalid response from server")
	errNoSegmentDownloadURL = errors.New("no download URLs")
)

// ErrReconnect is the error returned when the server requests a reconnect.
type ErrReconnect struct {
	Backoff time.Duration
}

func (er ErrReconnect) Error() string {
	return fmt.Sprintf("reconnect in %s", er.Backoff)
}

// ServerEventKind represents events sent by the server through the watch stream.
type ServerEventKind uint8

const (
	ServerEventError ServerEventKind = iota
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
	ClientEventError ClientEventKind = iota
	ClientEventBundleSwap
)

type ClientEvent struct {
	ActiveBundleID string
	Kind           ClientEventKind
}

type Client struct {
	authClient  *authClient
	rpcClient   bundlev1connect.CerbosBundleServiceClient
	httpClient  *http.Client
	bundleCache *cache.Cache
	conf        ClientConf
}

func NewClient(conf ClientConf) (*Client, error) {
	if err := conf.Validate(); err != nil {
		return nil, err
	}

	bcache, err := mkBundleCache(conf.CacheDir)
	if err != nil {
		return nil, err
	}

	httpClient := mkHTTPClient(conf) // Bidi streams don't work with retryable HTTP client.
	retryableHTTPClient := mkRetryableHTTPClient(conf, httpClient)
	options := []connect.ClientOption{
		connect.WithInterceptors(
			newTracingInterceptor(),
			newUserAgentInterceptor(),
		),
	}

	authClient := newAuthClient(conf, retryableHTTPClient, options...)
	options = append(options, connect.WithInterceptors(newAuthInterceptor(authClient)))
	rpcClient := bundlev1connect.NewCerbosBundleServiceClient(httpClient, conf.ServerURL, options...)

	return &Client{
		bundleCache: bcache,
		conf:        conf,
		authClient:  authClient,
		rpcClient:   rpcClient,
		httpClient:  retryableHTTPClient,
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

func mkHTTPClient(conf ClientConf) *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: conf.TLS.Clone(),
		},
	}
}

func mkRetryableHTTPClient(conf ClientConf, client *http.Client) *http.Client {
	httpClient := retryablehttp.NewClient()
	httpClient.HTTPClient = client
	httpClient.RetryMax = conf.RetryMaxAttempts
	httpClient.RetryWaitMin = conf.RetryWaitMin
	httpClient.RetryWaitMax = conf.RetryWaitMax
	httpClient.Logger = logWrapper{Logger: conf.Logger.WithName("transport")}

	return httpClient.StandardClient()
}

// GetBundle returns the path to the bundle with the given label.
func (c *Client) GetBundle(ctx context.Context, bundleLabel string) (string, error) {
	log := c.conf.Logger.WithValues("bundle", bundleLabel)
	log.V(1).Info("Calling GetBundle RPC")

	resp, err := c.rpcClient.GetBundle(ctx, connect.NewRequest(&bundlev1.GetBundleRequest{
		PdpId:       c.conf.PDPIdentifier,
		BundleLabel: bundleLabel,
	}))
	if err != nil {
		log.Error(err, "GetBundle RPC failed")
		return "", fmt.Errorf("rpc failed: %w", err)
	}

	logResponsePayload(log, resp.Msg)

	return c.getBundleFile(logr.NewContext(ctx, log), resp.Msg.BundleInfo)
}

func (c *Client) WatchBundle(ctx context.Context, bundleLabel string) (WatchHandle, error) {
	log := c.conf.Logger.WithValues("bundle", bundleLabel)
	log.V(1).Info("Calling WatchBundle RPC")

	stream := c.rpcClient.WatchBundle(ctx)
	if err := stream.Send(nil); err != nil {
		log.V(1).Error(err, "Failed to send request headers")
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
		err := wh.wait()
		log.V(2).Error(err, "Watch streams terminated")
	}()

	return wh, nil
}

func (c *Client) watchStreamRecv(stream *connect.BidiStreamForClient[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse], wh *watchHandleImpl, logger logr.Logger) func(context.Context) error {
	return func(ctx context.Context) (outErr error) {
		log := logger.WithName("recv")
		log.V(1).Info("Starting receive stream")

		defer func() {
			log.V(1).Info("Closing receive stream")
			if err := stream.CloseResponse(); err != nil {
				if !errors.Is(err, context.Canceled) {
					log.V(1).Error(err, "Failed to close receive stream")
					outErr = multierr.Append(outErr, err)
				}
			}
		}()

		sendWatchEvent := func(we ServerEvent) error {
			log.V(3).Info("Sending watch event")
			select {
			case wh.serverEvents <- we:
				log.V(3).Info("Sent watch event")
				return nil
			case <-ctx.Done():
				log.V(3).Info("Failed to send watch event due to context cancellation")
				return ctx.Err()
			}
		}

		for {
			if err := ctx.Err(); err != nil {
				log.V(2).Error(err, "Exiting receive loop due to context cancellation")
				return err
			}

			log.V(3).Info("Waiting for message")
			msg, err := stream.Receive()
			if err != nil {
				if errors.Is(err, io.EOF) {
					log.V(2).Info("Stream terminated by server")
					return nil
				}

				if connect.CodeOf(err) == connect.CodeNotFound {
					log.V(1).Error(err, "Label does not exist")
					_ = sendWatchEvent(ServerEvent{Error: ErrBundleNotFound})
					return ErrBundleNotFound
				}

				log.V(1).Error(err, "Error receiving message")
				_ = sendWatchEvent(ServerEvent{Error: err})
				return err
			}

			logResponsePayload(log, msg)

			switch m := msg.Msg.(type) {
			case *bundlev1.WatchBundleResponse_BundleUpdate:
				log.V(2).Info("Received bundle update")
				bundlePath, err := c.getBundleFile(ctx, m.BundleUpdate)
				if err != nil {
					log.V(1).Error(err, "Failed to get bundle")
					if err := sendWatchEvent(ServerEvent{Kind: ServerEventError, Error: err}); err != nil {
						log.V(2).Error(err, "Failed to send error")
					}

					return err
				}

				if err := sendWatchEvent(ServerEvent{Kind: ServerEventNewBundle, NewBundlePath: bundlePath}); err != nil {
					return err
				}

			case *bundlev1.WatchBundleResponse_BundleRemoved_:
				log.V(1).Info("Bundle label removed")
				if err := sendWatchEvent(ServerEvent{Kind: ServerEventBundleRemoved}); err != nil {
					log.V(2).Error(err, "Failed to send bundle removed")
				}

				return ErrBundleRemoved
			case *bundlev1.WatchBundleResponse_Reconnect_:
				log.V(1).Info("Server requests reconnect")
				backoff := defaultBackoff
				if m.Reconnect != nil && m.Reconnect.Backoff != nil {
					backoff = m.Reconnect.Backoff.AsDuration()
				}

				if err := sendWatchEvent(ServerEvent{Kind: ServerEventReconnect, ReconnectBackoff: backoff}); err != nil {
					log.V(2).Error(err, "Failed to send reconnect")
				}

				return ErrReconnect{Backoff: backoff}
			}
		}
	}
}

func (c *Client) watchStreamSend(stream *connect.BidiStreamForClient[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse], wh *watchHandleImpl, logger logr.Logger) func(context.Context) error {
	return func(ctx context.Context) (outErr error) {
		log := logger.WithName("send")
		log.V(1).Info("Starting send stream")

		var ticker *time.Ticker
		var tickerChan <-chan time.Time

		if c.conf.HeartbeatInterval > 0 {
			ticker = time.NewTicker(c.conf.HeartbeatInterval)
			tickerChan = ticker.C
		} else {
			log.V(1).Info("Regular heartbeats disabled")
			tickerChan = make(chan time.Time)
		}

		defer func() {
			log.V(1).Info("Closing send stream")
			if ticker != nil {
				ticker.Stop()
			}

			if err := stream.CloseRequest(); err != nil {
				if !errors.Is(err, context.Canceled) {
					log.V(1).Error(err, "Failed to close send stream")
					outErr = multierr.Append(outErr, err)
				}
			}
		}()

		log.V(2).Info("Initiating bundle watch")
		if err := stream.Send(&bundlev1.WatchBundleRequest{
			PdpId: c.conf.PDPIdentifier,
			Msg: &bundlev1.WatchBundleRequest_WatchLabel_{
				WatchLabel: &bundlev1.WatchBundleRequest_WatchLabel{BundleLabel: wh.bundleLabel},
			},
		}); err != nil {
			log.Error(err, "WatchBundle RPC failed")
			return err
		}

		sendHeartbeat := func(activeBundleID string) error {
			if err := stream.Send(&bundlev1.WatchBundleRequest{
				PdpId: c.conf.PDPIdentifier,
				Msg: &bundlev1.WatchBundleRequest_Heartbeat_{
					Heartbeat: &bundlev1.WatchBundleRequest_Heartbeat{ActiveBundleId: activeBundleID},
				},
			}); err != nil {
				log.V(1).Error(err, "Failed to send message")
				return err
			}

			return nil
		}

		log.V(2).Info("Starting heartbeat loop")
		activeBundleID := "unknown"
		for {
			select {
			case <-ctx.Done():
				log.V(2).Info("Terminating send stream due to context cancellation")
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
				log.V(3).Info("Sending heartbeat")
				if err := sendHeartbeat(activeBundleID); err != nil {
					return err
				}
			}
		}
	}
}

func logResponsePayload(log logr.Logger, payload proto.Message) {
	if lg := log.V(3); lg.Enabled() {
		lg.Info("RPC response", "payload", protoWrapper{p: payload})
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

	if err := c.authClient.SetAuthTokenHeader(ctx, req.Header); err != nil {
		log.V(1).Error(err, "Failed to authenticate")
		return "", err
	}

	log.V(1).Info("Sending download request")
	resp, err := c.httpClient.Do(req)
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

type protoWrapper struct {
	p proto.Message
}

func (pw protoWrapper) MarshalLog() any {
	bytes, err := protojson.Marshal(pw.p)
	if err != nil {
		return fmt.Sprintf("error marshaling response: %v", err)
	}

	return json.RawMessage(bytes)
}
