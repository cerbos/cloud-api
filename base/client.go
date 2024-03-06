// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0
package base

import (
	"encoding/json"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/go-logr/logr"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type Client struct {
	HTTPClient *http.Client
	conf       ClientConf
}

func NewClient(conf ClientConf) (c Client, opts []connect.ClientOption, _ error) {
	otelConnect, err := otelconnect.NewInterceptor()
	if err != nil {
		return c, opts, fmt.Errorf("failed to create otel interceptor: %w", err)
	}

	opts = []connect.ClientOption{
		connect.WithCompressMinBytes(1024),
		connect.WithInterceptors(
			otelConnect,
			newUserAgentInterceptor(),
		),
	}

	retryableHTTPClient := mkRetryableHTTPClient(conf)
	authClient := newAuthClient(conf, retryableHTTPClient, opts...)

	opts = append(opts, connect.WithInterceptors(newAuthInterceptor(authClient)))

	return Client{
		conf:       conf,
		HTTPClient: retryableHTTPClient,
	}, opts, nil
}

func MkHTTPClient(conf ClientConf) *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: conf.TLS.Clone(),
		},
	}
}

func mkRetryableHTTPClient(conf ClientConf) *http.Client {
	httpClient := retryablehttp.NewClient()
	httpClient.HTTPClient = MkHTTPClient(conf)
	httpClient.RetryMax = conf.RetryMaxAttempts
	httpClient.RetryWaitMin = conf.RetryWaitMin
	httpClient.RetryWaitMax = conf.RetryWaitMax
	httpClient.Logger = logWrapper{Logger: conf.Logger.WithName("transport")}

	return httpClient.StandardClient()
}

func LogResponsePayload(log logr.Logger, payload proto.Message) {
	if lg := log.V(3); lg.Enabled() {
		lg.Info("RPC response", "payload", ProtoWrapper{p: payload})
	}
}

type ProtoWrapper struct {
	p proto.Message
}

func NewProtoWrapper(msg proto.Message) ProtoWrapper {
	return ProtoWrapper{p: msg}
}

func (pw ProtoWrapper) MarshalLog() any {
	bytes, err := protojson.Marshal(pw.p)
	if err != nil {
		return fmt.Sprintf("error marshaling response: %v", err)
	}

	return json.RawMessage(bytes)
}
