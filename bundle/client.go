// Copyright 2021-2022 Zenauth Ltd.

package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime/trace"
	"sort"
	"time"

	"github.com/bufbuild/connect-go"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1/bundlev1connect"
	"github.com/go-logr/logr"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/minio/sha256-simd"
	"github.com/rogpeppe/go-internal/cache"
	"go.uber.org/multierr"
)

const (
	defaultBackoff      = 5 * time.Minute
	maxDownloadAttempts = 3
)

var (
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

type WatchEvent struct {
	Error      error
	BundlePath string
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

	httpClient := mkHTTPClient(conf)

	interceptors := connect.WithInterceptors(
		newTracingInterceptor(),
		newUserAgentInterceptor(),
	)

	authClient := newAuthClient(conf, httpClient, interceptors)
	rpcClient := mkRPCClient(conf, httpClient, authClient, interceptors)

	return &Client{
		bundleCache: bcache,
		conf:        conf,
		authClient:  authClient,
		rpcClient:   rpcClient,
		httpClient:  httpClient,
	}, nil
}

func mkHTTPClient(conf ClientConf) *http.Client {
	httpClient := retryablehttp.NewClient()
	httpClient.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   conf.TLS.Clone(),
			ForceAttemptHTTP2: true,
		},
	}
	httpClient.RetryMax = conf.RetryMaxAttempts
	httpClient.RetryWaitMin = conf.RetryWaitMin
	httpClient.RetryWaitMax = conf.RetryWaitMax
	httpClient.Logger = logWrapper{Logger: conf.Logger.WithName("transport")}

	return httpClient.StandardClient()
}

func mkRPCClient(conf ClientConf, httpClient *http.Client, authClient *authClient, options ...connect.ClientOption) bundlev1connect.CerbosBundleServiceClient {
	return bundlev1connect.NewCerbosBundleServiceClient(httpClient, conf.ServerURL,
		append(options, connect.WithInterceptors(newAuthInterceptor(authClient)))...)
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

	return c.getBundleFile(logr.NewContext(ctx, log), resp.Msg.BundleInfo)
}

func (c *Client) WatchBundle(ctx context.Context, bundleLabel string) (<-chan WatchEvent, error) {
	log := c.conf.Logger.WithValues("bundle", bundleLabel)
	log.V(1).Info("Calling WatchBundle RPC")

	stream, err := c.rpcClient.WatchBundle(ctx, connect.NewRequest(&bundlev1.WatchBundleRequest{
		PdpId:       c.conf.PDPIdentifier,
		BundleLabel: bundleLabel,
	}))
	if err != nil {
		log.Error(err, "WatchBundle RPC failed")
		return nil, fmt.Errorf("rpc failed: %w", err)
	}

	outChan := make(chan WatchEvent, 1)
	go c.doWatchBundle(ctx, bundleLabel, stream, outChan)

	return outChan, nil
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
		return c.downloadSegment(logr.NewContext(ctx, log), bdlCacheKey, segments[0], 1)
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
	return c.downloadSegment(ctx, cacheKey, segment, 1)
}

func (c *Client) downloadSegment(ctx context.Context, cacheKey cache.ActionID, segment *bundlev1.BundleInfo_Segment, attempt int) (string, error) {
	numDownloadURLS := len(segment.DownloadUrls)

	var downloadURL string
	switch numDownloadURLS {
	case 0:
		return "", errNoSegmentDownloadURL
	case 1:
		downloadURL = segment.DownloadUrls[0]
	default:
		//nolint:gosec
		downloadURL = segment.DownloadUrls[rand.Intn(numDownloadURLS)]
	}

	log := logr.FromContextOrDiscard(ctx).WithValues("url", downloadURL, "attempt", attempt)
	log.V(1).Info("Constructing download request")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, http.NoBody)
	if err != nil {
		log.V(1).Error(err, "Failed to construct download request")
		return "", fmt.Errorf("failed to construct download request: %w", err)
	}

	err = c.authClient.SetAuthTokenHeader(ctx, req.Header)
	if err != nil {
		log.V(1).Error(err, "Failed to authenticate")
		return "", err
	}

	log.V(1).Info("Sending download request")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.V(1).Error(err, "Failed to send download request")
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
	case resp.StatusCode >= 404 && numDownloadURLS > 1 && attempt < maxDownloadAttempts:
		log.V(1).Info("Retrying download")
		return c.downloadSegment(ctx, cacheKey, segment, attempt+1)
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

func (c *Client) doWatchBundle(ctx context.Context, bundleLabel string, stream *connect.ServerStreamForClient[bundlev1.WatchBundleResponse], outChan chan WatchEvent) {
	ctx, task := trace.NewTask(ctx, "doWatchBundle")
	defer task.End()

	trace.Logf(ctx, "", "label=%s", bundleLabel)

	log := c.conf.Logger.WithValues("bundle", bundleLabel)
	log.V(1).Info("Starting watch")

	defer func() {
		close(outChan)
		if err := stream.Close(); err != nil {
			log.V(2).Error(err, "Failed to close stream")
		}
	}()

	sendWatchEvent := func(we WatchEvent) error {
		log.V(2).Info("Sending watch event")
		select {
		case outChan <- we:
			log.V(2).Info("Sent watch event")
			return nil
		case <-ctx.Done():
			log.V(2).Info("Failed to send watch event due to context cancellation")
			return ctx.Err()
		}
	}

	for stream.Receive() {
		msg := stream.Msg()
		switch m := msg.Msg.(type) {
		case *bundlev1.WatchBundleResponse_BundleUpdate:
			log.V(2).Info("Received bundle update")
			bundlePath, err := c.getBundleFile(ctx, m.BundleUpdate)
			if err != nil {
				log.V(1).Error(err, "Failed to get bundle")
				if err := sendWatchEvent(WatchEvent{Error: err}); err != nil {
					log.V(1).Error(err, "Failed to send error")
				}

				log.V(1).Info("Terminating watch")
				return
			}

			if err := sendWatchEvent(WatchEvent{BundlePath: bundlePath}); err != nil {
				log.V(1).Error(err, "Terminating watch")
				return
			}

		case *bundlev1.WatchBundleResponse_BundleRemoved_:
			log.V(2).Info("Received bundle removed")
			if err := sendWatchEvent(WatchEvent{}); err != nil {
				log.V(1).Error(err, "Terminating watch")
				return
			}
		case *bundlev1.WatchBundleResponse_Reconnect_:
			log.V(1).Info("Server requests reconnect")
			backoff := defaultBackoff
			if m.Reconnect != nil && m.Reconnect.Backoff != nil {
				backoff = m.Reconnect.Backoff.AsDuration()
			}

			if err := sendWatchEvent(WatchEvent{Error: ErrReconnect{Backoff: backoff}}); err != nil {
				log.V(1).Error(err, "Failed to send reconnect")
			}

			log.V(1).Info("Terminating watch")
			return
		}
	}

	if err := stream.Err(); err != nil {
		log.V(1).Error(err, "Watch terminated due to error")
		_ = sendWatchEvent(WatchEvent{Error: err})
	} else {
		log.V(1).Info("Watch terminated")
	}
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
