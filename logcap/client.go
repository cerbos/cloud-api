// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package logcap

import (
	"context"

	"connectrpc.com/connect"

	"github.com/cerbos/cloud-api/base"
	logsv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/logs/v1/logsv1connect"
)

type Client struct {
	base.Client
	rpcClient logsv1connect.CerbosLogsServiceClient
	conf      ClientConf
}

func NewClient(conf ClientConf) (*Client, error) {
	if err := conf.Validate(); err != nil {
		return nil, err
	}

	baseClient, options, err := base.NewClient(conf.ClientConf)
	if err != nil {
		return nil, err
	}

	httpClient := base.MkHTTPClient(conf.ClientConf) // Bidi streams don't work with retryable HTTP client.
	rpcClient := logsv1connect.NewCerbosLogsServiceClient(httpClient, conf.APIEndpoint, options...)

	return &Client{
		Client:    baseClient,
		conf:      conf,
		rpcClient: rpcClient,
	}, nil
}

func (c *Client) Ingest(ctx context.Context, batch *logsv1.IngestBatch) error {
	log := c.conf.Logger
	log.V(1).Info("Calling Ingest RPC")

	resp, err := c.rpcClient.Ingest(ctx, connect.NewRequest(&logsv1.IngestRequest{
		PdpId: c.conf.PDPIdentifier,
		Batch: batch,
	}))
	if err != nil {
		log.Error(err, "Ingest RPC failed")
		return err
	}

	base.LogResponsePayload(log, resp.Msg)

	return nil
}
