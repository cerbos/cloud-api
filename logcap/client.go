// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package logcap

import (
	"context"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/cerbos/cloud-api/base"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1/logsv1connect"
)

type Client struct {
	rpcClient    logsv1connect.CerbosLogsServiceClient
	rawRPCClient *connect.Client[logsv1.RawIngestRequest, logsv1.IngestResponse]
	base.Client
}

func NewClient(baseClient base.Client, options []connect.ClientOption) (*Client, error) {
	httpClient := baseClient.StdHTTPClient() // Bidi streams don't work with retryable HTTP client.
	rpcClient := logsv1connect.NewCerbosLogsServiceClient(httpClient, baseClient.APIEndpoint, options...)

	ingestSchema := logsv1.File_cerbos_cloud_logs_v1_logs_proto.Services().ByName("CerbosLogsService").Methods().ByName("Ingest")
	rawRPCClient := connect.NewClient[logsv1.RawIngestRequest, logsv1.IngestResponse](
		httpClient,
		strings.TrimRight(baseClient.APIEndpoint, "/")+logsv1connect.CerbosLogsServiceIngestProcedure,
		connect.WithSchema(ingestSchema),
		connect.WithClientOptions(options...),
	)

	return &Client{
		Client:       baseClient,
		rpcClient:    rpcClient,
		rawRPCClient: rawRPCClient,
	}, nil
}

func (c *Client) Ingest(ctx context.Context, batch *logsv1.IngestBatch) (time.Duration, error) {
	log := c.Logger
	log.V(1).Info("Calling Ingest RPC")

	resp, err := c.rpcClient.Ingest(ctx, connect.NewRequest(&logsv1.IngestRequest{
		PdpId: c.PDPIdentifier,
		Batch: batch,
	}))
	if err != nil {
		log.Error(err, "Ingest RPC failed")
		return 0, err
	}

	base.LogResponsePayload(log, resp.Msg)

	return resp.Msg.GetBackoff().GetDuration().AsDuration(), nil
}

// IngestRaw is Ingest for callers that already hold the batch in serialized
// form. batch must be a serialized logsv1.IngestBatch.
func (c *Client) IngestRaw(ctx context.Context, batch []byte) (time.Duration, error) {
	log := c.Logger
	log.V(1).Info("Calling Ingest RPC (raw)")

	resp, err := c.rawRPCClient.CallUnary(ctx, connect.NewRequest(&logsv1.RawIngestRequest{
		PdpId: c.PDPIdentifier,
		Batch: batch,
	}))
	if err != nil {
		log.Error(err, "Ingest RPC failed")
		return 0, err
	}

	base.LogResponsePayload(log, resp.Msg)

	return resp.Msg.GetBackoff().GetDuration().AsDuration(), nil
}
