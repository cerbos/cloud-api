// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: cerbos/cloud/apikey/v1/apikey.proto

package apikeyv1connect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	v1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// ApiKeyServiceName is the fully-qualified name of the ApiKeyService service.
	ApiKeyServiceName = "cerbos.cloud.apikey.v1.ApiKeyService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// ApiKeyServiceIssueAccessTokenProcedure is the fully-qualified name of the ApiKeyService's
	// IssueAccessToken RPC.
	ApiKeyServiceIssueAccessTokenProcedure = "/cerbos.cloud.apikey.v1.ApiKeyService/IssueAccessToken"
)

// ApiKeyServiceClient is a client for the cerbos.cloud.apikey.v1.ApiKeyService service.
type ApiKeyServiceClient interface {
	IssueAccessToken(context.Context, *connect.Request[v1.IssueAccessTokenRequest]) (*connect.Response[v1.IssueAccessTokenResponse], error)
}

// NewApiKeyServiceClient constructs a client for the cerbos.cloud.apikey.v1.ApiKeyService service.
// By default, it uses the Connect protocol with the binary Protobuf Codec, asks for gzipped
// responses, and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply the
// connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewApiKeyServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) ApiKeyServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	apiKeyServiceMethods := v1.File_cerbos_cloud_apikey_v1_apikey_proto.Services().ByName("ApiKeyService").Methods()
	return &apiKeyServiceClient{
		issueAccessToken: connect.NewClient[v1.IssueAccessTokenRequest, v1.IssueAccessTokenResponse](
			httpClient,
			baseURL+ApiKeyServiceIssueAccessTokenProcedure,
			connect.WithSchema(apiKeyServiceMethods.ByName("IssueAccessToken")),
			connect.WithClientOptions(opts...),
		),
	}
}

// apiKeyServiceClient implements ApiKeyServiceClient.
type apiKeyServiceClient struct {
	issueAccessToken *connect.Client[v1.IssueAccessTokenRequest, v1.IssueAccessTokenResponse]
}

// IssueAccessToken calls cerbos.cloud.apikey.v1.ApiKeyService.IssueAccessToken.
func (c *apiKeyServiceClient) IssueAccessToken(ctx context.Context, req *connect.Request[v1.IssueAccessTokenRequest]) (*connect.Response[v1.IssueAccessTokenResponse], error) {
	return c.issueAccessToken.CallUnary(ctx, req)
}

// ApiKeyServiceHandler is an implementation of the cerbos.cloud.apikey.v1.ApiKeyService service.
type ApiKeyServiceHandler interface {
	IssueAccessToken(context.Context, *connect.Request[v1.IssueAccessTokenRequest]) (*connect.Response[v1.IssueAccessTokenResponse], error)
}

// NewApiKeyServiceHandler builds an HTTP handler from the service implementation. It returns the
// path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewApiKeyServiceHandler(svc ApiKeyServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	apiKeyServiceMethods := v1.File_cerbos_cloud_apikey_v1_apikey_proto.Services().ByName("ApiKeyService").Methods()
	apiKeyServiceIssueAccessTokenHandler := connect.NewUnaryHandler(
		ApiKeyServiceIssueAccessTokenProcedure,
		svc.IssueAccessToken,
		connect.WithSchema(apiKeyServiceMethods.ByName("IssueAccessToken")),
		connect.WithHandlerOptions(opts...),
	)
	return "/cerbos.cloud.apikey.v1.ApiKeyService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case ApiKeyServiceIssueAccessTokenProcedure:
			apiKeyServiceIssueAccessTokenHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedApiKeyServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedApiKeyServiceHandler struct{}

func (UnimplementedApiKeyServiceHandler) IssueAccessToken(context.Context, *connect.Request[v1.IssueAccessTokenRequest]) (*connect.Response[v1.IssueAccessTokenResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("cerbos.cloud.apikey.v1.ApiKeyService.IssueAccessToken is not implemented"))
}
