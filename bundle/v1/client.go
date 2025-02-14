// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"
	"unicode"

	"connectrpc.com/connect"
	"github.com/bufbuild/protovalidate-go"
	"github.com/go-logr/logr"
	"github.com/rogpeppe/go-internal/cache"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cerbos/cloud-api/base"
	"github.com/cerbos/cloud-api/bundle"
	"github.com/cerbos/cloud-api/bundle/clientcache"
	bootstrapv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bootstrap/v1"
	bundlev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/bundle/v1/bundlev1connect"
)

const (
	bootstrapPathPrefix = "bootstrap/v1"
)

type Client struct {
	rpcClient bundlev1connect.CerbosBundleServiceClient
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
		cache:     c,
		Client:    baseClient,
		rpcClient: bundlev1connect.NewCerbosBundleServiceClient(httpClient, baseClient.APIEndpoint, options...),
	}, nil
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
			return nil, bundle.ErrBootstrapBundleNotFound
		}

		log.V(1).Info("Failed to download bootstrap bundle")
		return nil, bundle.ErrDownloadFailed
	}

	confData, err := c.Credentials.Decrypt(io.LimitReader(resp.Body, bundle.MaxBootstrapSize))
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
	if bytes.HasPrefix(trimmed, bundle.JSONStart) {
		unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
		if err := unmarshaler.Unmarshal(trimmed, out); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bootstrap JSON: %w", err)
		}
	} else if err := out.UnmarshalVT(trimmed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bootstrap proto: %w", err)
	}

	if err := protovalidate.Validate(out); err != nil {
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

func (c *Client) WatchBundle(ctx context.Context, bundleLabel string) (bundle.WatchHandle, error) {
	log := c.Logger.WithValues("bundle", bundleLabel)
	log.V(1).Info("Calling WatchBundle RPC")

	stream := c.rpcClient.WatchBundle(ctx)
	if err := stream.Send(nil); err != nil {
		log.V(1).Error(err, "Failed to send request headers")
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
		return nil, fmt.Errorf("failed to send request headers: %w", err)
	}

	wh := &bundle.WatchHandleImpl[string]{
		ServerEventsCh: make(chan bundle.ServerEvent, 1),
		ClientEventsCh: make(chan bundle.ClientEvent, 1),
		ErrorsCh:       make(chan error, 1),
		Source:         bundleLabel,
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
	msg *bundlev1.WatchBundleResponse
	err error
}

func (c *Client) watchStreamRecv(stream *connect.BidiStreamForClient[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse], wh *bundle.WatchHandleImpl[string], logger logr.Logger) func(context.Context) error {
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

		processMsg := func(msg *bundlev1.WatchBundleResponse) error {
			base.LogResponsePayload(log, msg)

			switch m := msg.Msg.(type) {
			case *bundlev1.WatchBundleResponse_BundleUpdate:
				log.V(2).Info("Received bundle update")
				bundlePath, err := c.getBundleFile(ctx, m.BundleUpdate)
				if err != nil {
					log.V(1).Error(err, "Failed to get bundle")
					if err := publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventError, Error: err}); err != nil {
						log.V(2).Error(err, "Failed to send error")
					}

					return err
				}

				if err := publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventNewBundle, NewBundlePath: bundlePath}); err != nil {
					return err
				}

			case *bundlev1.WatchBundleResponse_BundleRemoved_:
				log.V(1).Info("Bundle label removed")
				if err := publishWatchEvent(bundle.ServerEvent{Kind: bundle.ServerEventBundleRemoved}); err != nil {
					log.V(2).Error(err, "Failed to send bundle removed")
				}

			case *bundlev1.WatchBundleResponse_Reconnect_:
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

func (c *Client) watchStreamSend(stream *connect.BidiStreamForClient[bundlev1.WatchBundleRequest, bundlev1.WatchBundleResponse], wh *bundle.WatchHandleImpl[string], logger logr.Logger) func(context.Context) error {
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
				WatchLabel: &bundlev1.WatchBundleRequest_WatchLabel{BundleLabel: wh.Source},
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

func (c *Client) getBundleFile(ctx context.Context, binfo *bundlev1.BundleInfo) (outPath string, outErr error) {
	log := logr.FromContextOrDiscard(ctx)

	if len(binfo.BundleHash) != clientcache.HashSize {
		err := fmt.Errorf("length of bundle hash %x does not match expected hash size", binfo.BundleHash)
		log.Error(err, "Invalid bundle hash")
		return "", err
	}

	bdlCacheKey := *((*cache.ActionID)(binfo.BundleHash))
	defer func() {
		if outErr == nil && outPath != "" {
			if err := c.cache.UpdateSourceCache(binfo.Label, bdlCacheKey); err != nil {
				log.V(1).Error(err, "Failed to update label mapping")
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

func (c *Client) getSegmentFile(ctx context.Context, segment *bundlev1.BundleInfo_Segment) (string, error) {
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

func (c *Client) downloadSegment(ctx context.Context, cacheKey cache.ActionID, segment *bundlev1.BundleInfo_Segment) (string, error) {
	if len(segment.DownloadUrls) == 0 {
		return "", bundle.ErrNoSegmentDownloadURL
	}

	r := bundle.NewRing(segment.DownloadUrls)
	return c.doDownloadSegment(ctx, cacheKey, segment, r, 1)
}

func (c *Client) doDownloadSegment(ctx context.Context, cacheKey cache.ActionID, segment *bundlev1.BundleInfo_Segment, r *bundle.Ring, attempt int) (string, error) {
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

// GetCachedBundle returns the last cached entry for the given label if it exists.
func (c *Client) GetCachedBundle(bundleLabel string) (string, error) {
	lblCacheKey := clientcache.SourceCacheKey(bundleLabel)
	entry, err := c.cache.GetBytes(lblCacheKey)
	if err != nil {
		return "", fmt.Errorf("no cache entry for %s: %w", bundleLabel, err)
	}

	bdlCacheKey := *((*cache.ActionID)(entry))
	bdlEntry, err := c.cache.Get(bdlCacheKey)
	if err != nil {
		return "", fmt.Errorf("failed to find bundle in cache: %w", err)
	}

	return bdlEntry, nil
}
