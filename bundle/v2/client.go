// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"

	"connectrpc.com/connect"
	"github.com/bufbuild/protovalidate-go"
	"github.com/go-logr/logr"
	"github.com/rogpeppe/go-internal/cache"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/bundle/clientcache"
	bundlev2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v2/bundlev2connect"
)

type Client struct {
	rpcClient bundlev2connect.CerbosBundleServiceClient
	cache     *clientcache.ClientCache
	base.Client
}

func NewClient(conf bundle.ClientConf, baseClient base.Client, options []connect.ClientOption) (*Client, error) {
	if err := conf.Validate(); err != nil {
		return nil, err
	}

	c, err := clientcache.New(conf.CacheDir, conf.TempDir)
	if err != nil {
		return nil, err
	}

	httpClient := baseClient.StdHTTPClient() // Bidi streams don't work with retryable HTTP client.
	return &Client{
		Client:    baseClient,
		rpcClient: bundlev2connect.NewCerbosBundleServiceClient(httpClient, baseClient.APIEndpoint, options...),
		cache:     c,
	}, nil
}

func (c *Client) BootstrapBundle(ctx context.Context, source Source) (string, []byte, error) {
	log := c.Logger.WithValues("source", source.String())

	log.V(1).Info("Getting bootstrap bundle response")

	urlPath, err := source.bootstrapBundleURLPath(c.Credentials)
	if err != nil {
		return "", nil, err
	}

	bundleResponseURL, err := url.JoinPath(c.BootstrapEndpoint, urlPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to construct bootstrap bundle response URL: %w", err)
	}

	bundleResponse, err := c.getBundleResponseViaCDN(ctx, bundleResponseURL)
	if err != nil {
		log.Error(err, "Failed to download bootstrap bundle response")
		return "", nil, err
	}

	log.Info("Bootstrap bundle response downloaded")
	base.LogResponsePayload(log, bundleResponse)

	path, err := c.getBundleFile(logr.NewContext(ctx, log), bundleResponse.BundleInfo)
	if err != nil {
		return "", nil, err
	}

	return path, bundleResponse.BundleInfo.EncryptionKey, nil
}

func (c *Client) getBundleResponseViaCDN(ctx context.Context, url string) (*bundlev2.GetBundleResponse, error) {
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
			log.V(1).Info("Bootstrap bundle response not found")
			return nil, bundle.ErrBootstrapBundleResponseNotFound
		}

		log.V(1).Info("Failed to download bootstrap bundle response")
		return nil, bundle.ErrDownloadFailed
	}

	bundleResponseBytes, err := c.Credentials.DecryptV2(io.LimitReader(resp.Body, bundle.MaxBootstrapSize))
	if err != nil {
		log.V(1).Error(err, "Failed to decrypt bootstrap bundle response")
		return nil, fmt.Errorf("failed to decrypt bootstrap bundle response: %w", err)
	}

	return c.parseBundleResponse(bundleResponseBytes)
}

func (c *Client) parseBundleResponse(bundleResponseBytes []byte) (*bundlev2.GetBundleResponse, error) {
	out := &bundlev2.GetBundleResponse{}
	if err := out.UnmarshalVT(bundleResponseBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bootstrap bundle response proto: %w", err)
	}

	if err := protovalidate.Validate(out); err != nil {
		return nil, fmt.Errorf("invalid bootstrap bundle response: %w", err)
	}

	return out, nil
}

// GetBundle returns the path to the bundle with the given label.
func (c *Client) GetBundle(ctx context.Context, source Source) (string, []byte, error) {
	log := c.Logger.WithValues("source", source.String())
	log.V(1).Info("Calling GetBundle RPC")

	resp, err := c.rpcClient.GetBundle(ctx, connect.NewRequest(&bundlev2.GetBundleRequest{PdpId: c.PDPIdentifier, Source: source.ToProto()}))
	if err != nil {
		log.Error(err, "GetBundle RPC failed")
		return "", nil, err
	}

	base.LogResponsePayload(log, resp.Msg)

	path, err := c.getBundleFile(logr.NewContext(ctx, log), resp.Msg.BundleInfo)
	if err != nil {
		return "", nil, err
	}

	return path, resp.Msg.BundleInfo.EncryptionKey, nil
}

func (c *Client) WatchBundle(ctx context.Context, source Source) (bundle.WatchHandle, error) {
	log := c.Logger.WithValues("source", source.String())
	log.V(1).Info("Calling WatchBundle RPC")

	stream := c.rpcClient.WatchBundle(ctx)
	if err := stream.Send(nil); err != nil {
		log.V(1).Error(err, "Failed to send request headers")
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
		return nil, fmt.Errorf("failed to send request headers: %w", err)
	}

	wh := &bundle.WatchHandleImpl[Source]{
		ServerEventsCh: make(chan bundle.ServerEvent, 1),
		ClientEventsCh: make(chan bundle.ClientEvent, 1),
		ErrorsCh:       make(chan error, 1),
		Source:         source,
		Pool:           pool.New().WithContext(ctx).WithCancelOnError().WithFirstError(),
	}

	wh.Pool.Go(c.watchStreamRecv(stream, wh, log))
	wh.Pool.Go(c.watchStreamSend(stream, wh, log))
	go func() {
		if err := wh.Wait(); err != nil {
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				log.V(2).Info("Watch stream terminated: context timed out")
			case errors.Is(err, context.Canceled):
				log.V(2).Info("Watch stream terminated: context cancelled")
			case errors.Is(err, bundle.ErrBundleNotFound):
				log.V(2).Info("Watch stream terminated: bundle not found")
			case errors.As(err, &bundle.ReconnectError{}):
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
	msg *bundlev2.WatchBundleResponse
	err error
}

func (c *Client) watchStreamRecv(stream *connect.BidiStreamForClient[bundlev2.WatchBundleRequest, bundlev2.WatchBundleResponse], wh *bundle.WatchHandleImpl[Source], logger logr.Logger) func(context.Context) error {
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
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						log.V(3).Info("Exiting receive loop")
					} else {
						log.V(3).Error(err, "Exiting receive loop due to error")
					}
					return
				}
			}
		}()

		publishWatchEvent := func(we bundle.ServerEvent) error {
			log.V(3).Info("Publishing watch event")
			select {
			case wh.ServerEventsCh <- we:
				log.V(3).Info("Published watch event")
				return nil
			case <-ctx.Done():
				log.V(3).Info("Failed to publish watch event due to context cancellation")
				return ctx.Err()
			}
		}

		processMsg := func(msg *bundlev2.WatchBundleResponse) error {
			base.LogResponsePayload(log, msg)

			switch m := msg.Msg.(type) {
			case *bundlev2.WatchBundleResponse_BundleUpdate:
				log.V(2).Info("Received bundle update")
				bundlePath, err := c.getBundleFile(ctx, m.BundleUpdate)
				if err != nil {
					log.V(1).Error(err, "Failed to get bundle")
					if err := publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventError, Error: err}); err != nil {
						log.V(2).Error(err, "Failed to send error")
					}

					return err
				}

				if err := publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventNewBundle, NewBundlePath: bundlePath, EncryptionKey: m.BundleUpdate.EncryptionKey}); err != nil {
					return err
				}

			case *bundlev2.WatchBundleResponse_BundleRemoved_:
				log.V(1).Info("Bundle label removed")
				if err := publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventBundleRemoved}); err != nil {
					log.V(2).Error(err, "Failed to send bundle removed")
				}

			case *bundlev2.WatchBundleResponse_Reconnect_:
				log.V(1).Info("Server requests reconnect")
				backoff := bundle.DefaultBackoff
				if m.Reconnect != nil && m.Reconnect.Backoff != nil {
					backoff = m.Reconnect.Backoff.AsDuration()
				}

				if err := publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventReconnect, ReconnectBackoff: backoff}); err != nil {
					log.V(2).Error(err, "Failed to send reconnect")
				}

				return bundle.ReconnectError{Backoff: backoff}

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
						_ = publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventError, Error: bundle.ErrBundleNotFound})
						return bundle.ErrBundleNotFound
					}

					log.V(1).Error(r.err, "Error receiving message")
					_ = publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventError, Error: r.err})
					return r.err
				}

				if r.msg != nil {
					if err := processMsg(r.msg); err != nil {
						return err
					}
				}

				if !ok {
					log.V(2).Info("Receive loop ended")
					return bundle.ErrStreamEnded
				}
			case <-ctx.Done():
				log.V(2).Info("Exiting response handler due to context cancellation")
				return ctx.Err()
			}
		}
	}
}

func (c *Client) watchStreamSend(stream *connect.BidiStreamForClient[bundlev2.WatchBundleRequest, bundlev2.WatchBundleResponse], wh *bundle.WatchHandleImpl[Source], logger logr.Logger) func(context.Context) error {
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
		if err := stream.Send(&bundlev2.WatchBundleRequest{
			PdpId: c.PDPIdentifier,
			Msg: &bundlev2.WatchBundleRequest_Start_{
				Start: &bundlev2.WatchBundleRequest_Start{
					Source: wh.Source.ToProto(),
				},
			},
		}); err != nil {
			log.Error(err, "WatchBundle RPC failed")
			return err
		}

		sendHeartbeat := func(activeBundleID string) error {
			log.V(3).Info("Sending heartbeat", "active_bundle_id", activeBundleID)
			if err := stream.Send(&bundlev2.WatchBundleRequest{
				PdpId: c.PDPIdentifier,
				Msg: &bundlev2.WatchBundleRequest_Heartbeat_{
					Heartbeat: &bundlev2.WatchBundleRequest_Heartbeat{
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
		activeBundleID := bundle.BundleIDUnknown
		for {
			select {
			case <-ctx.Done():
				log.V(2).Info("Terminating request handler due to context cancellation")
				return ctx.Err()
			case evt := <-wh.ClientEventsCh:
				switch evt.Kind {
				case bundle.ClientEventBundleSwap:
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

func (c *Client) getBundleFile(ctx context.Context, binfo *bundlev2.BundleInfo) (outPath string, outErr error) {
	log := logr.FromContextOrDiscard(ctx)

	if len(binfo.OutputHash) != cache.HashSize {
		err := fmt.Errorf("length of output hash %x does not match expected hash size", binfo.OutputHash)
		log.Error(err, "Invalid output hash")
		return "", err
	}

	bdlCacheKey := *((*cache.ActionID)(binfo.OutputHash))
	defer func() {
		if outErr == nil && outPath != "" {
			source, err := sourceFromProto(binfo.GetSource())
			if err != nil {
				log.V(1).Error(err, "Failed to get bundle source")
				return
			}

			if err := c.cache.UpdateSourceCache(source.String(), bdlCacheKey); err != nil {
				log.V(1).Error(err, "Failed to update source mapping")
			}
		}
	}()

	entry, err := c.cache.Get(bdlCacheKey)
	if err == nil {
		log.V(1).Info("Bundle exists in cache")
		return entry, nil
	}

	log.V(1).Info("Downloading bundle segments")
	segments := binfo.Segments

	switch len(segments) {
	case 0:
		log.V(1).Info("No segments provided")
		return "", bundle.ErrInvalidResponse
	case 1:
		return c.downloadSegment(logr.NewContext(ctx, log), bdlCacheKey, segments[0])
	default:
		sort.Slice(segments, func(i, j int) bool { return segments[i].SegmentId < segments[j].SegmentId })
		// TODO(cell): Check segment IDs are sequential (not missing any IDs)
		// TODO(cell): Download in parallel if there are many segments

		joiner := bundle.NewSegmentJoiner(len(segments))
		for _, s := range segments {
			logger := log.WithValues("segment", s.SegmentId)
			logger.V(1).Info("Getting segment")

			segFile, err := c.getSegmentFile(logr.NewContext(ctx, logger), s)
			if err != nil {
				_ = joiner.Close()
				logger.Error(err, "Failed to get bundle segment")
				return "", err
			}

			if err := joiner.Add(segFile); err != nil {
				_ = joiner.Close()
				logger.Error(err, "Failed to open bundle segment")
				return "", err
			}
		}

		file, _, err := c.cache.Add(bdlCacheKey, joiner.Join())
		return file, err
	}
}

func (c *Client) getSegmentFile(ctx context.Context, segment *bundlev2.BundleInfo_Segment) (string, error) {
	log := logr.FromContextOrDiscard(ctx)

	cacheKey := clientcache.SegmentCacheKey(segment.Checksum)
	entry, err := c.cache.Get(cacheKey)
	if err == nil {
		log.V(1).Info("Cache hit for segment")
		return entry, nil
	}

	log.V(1).Info("Cache miss: downloading segment")
	return c.downloadSegment(ctx, cacheKey, segment)
}

func (c *Client) downloadSegment(ctx context.Context, cacheKey cache.ActionID, segment *bundlev2.BundleInfo_Segment) (string, error) {
	if len(segment.DownloadUrls) == 0 {
		return "", bundle.ErrNoSegmentDownloadURL
	}

	r := bundle.NewRing(segment.DownloadUrls)
	return c.doDownloadSegment(ctx, cacheKey, segment, r, 1)
}

func (c *Client) doDownloadSegment(ctx context.Context, cacheKey cache.ActionID, segment *bundlev2.BundleInfo_Segment, r *bundle.Ring, attempt int) (string, error) {
	downloadURL := r.Next()
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
		if r.Size() > 1 && attempt < bundle.MaxDownloadAttempts {
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
		return c.cache.AddSegment(ctx, cacheKey, segment.Checksum, resp)
	case resp.StatusCode >= 404 && r.Size() > 1 && attempt < bundle.MaxDownloadAttempts:
		log.V(1).Info("Retrying download")
		return c.doDownloadSegment(ctx, cacheKey, segment, r, attempt+1)
	default:
		log.V(1).Info("Download failed")
		return "", bundle.ErrDownloadFailed
	}
}

// GetCachedBundle returns the last cached entry for the given source if it exists.
func (c *Client) GetCachedBundle(source Source) (string, error) {
	lblCacheKey := clientcache.SourceCacheKey(source.String())
	entry, err := c.cache.GetBytes(lblCacheKey)
	if err != nil {
		return "", fmt.Errorf("no cache entry for %s: %w", source, err)
	}

	bdlCacheKey := *((*cache.ActionID)(entry))
	bdlEntry, err := c.cache.Get(bdlCacheKey)
	if err != nil {
		return "", fmt.Errorf("failed to find bundle in cache: %w", err)
	}

	return bdlEntry, nil
}
