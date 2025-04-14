// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package logcap

import (
	"context"
	"time"

	"connectrpc.com/connect"

	"github.com/cerbos/cloud-api/base"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1/logsv1connect"
)

type Client struct {
	rpcClient logsv1connect.CerbosLogsServiceClient
	base.Client
}

func NewClient(baseClient base.Client, options []connect.ClientOption) (*Client, error) {
	httpClient := baseClient.StdHTTPClient() // Bidi streams don't work with retryable HTTP client.
	rpcClient := logsv1connect.NewCerbosLogsServiceClient(httpClient, baseClient.APIEndpoint, options...)

	return &Client{
		Client:    baseClient,
		rpcClient: rpcClient,
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
