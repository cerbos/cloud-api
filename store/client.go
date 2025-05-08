// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/cerbos/cloud-api/base"
	storev1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/store/v1/storev1connect"
)

type RPCErrorKind int

const (
	RPCErrorAuthenticationFailed RPCErrorKind = iota
	RPCErrorConditionUnsatisfied
	RPCErrorInvalidRequest
	RPCErrorNoUsableFiles
	RPCErrorOperationDiscarded
	RPCErrorPermissionDenied
	RPCErrorStoreNotFound
	RPCErrorUnknown
	RPCErrorValidationFailure
)

type RPCError struct {
	Underlying       error
	IgnoredFiles     []string
	ValidationErrors []*storev1.FileError
	Kind             RPCErrorKind
}

func (r RPCError) Error() string {
	return r.Underlying.Error()
}

func (r RPCError) Unwrap() error {
	return r.Underlying
}

func newRPCError(err error) RPCError {
	if errors.Is(err, base.ErrAuthenticationFailed) {
		return RPCError{Kind: RPCErrorAuthenticationFailed, Underlying: err}
	}

	connectErr := new(connect.Error)
	if !errors.As(err, &connectErr) {
		return RPCError{Kind: RPCErrorUnknown, Underlying: err}
	}

	switch connectErr.Code() {
	case connect.CodePermissionDenied:
		return RPCError{Kind: RPCErrorPermissionDenied, Underlying: connectErr}
	case connect.CodeNotFound:
		return RPCError{Kind: RPCErrorStoreNotFound, Underlying: connectErr}
	case connect.CodeFailedPrecondition:
		return RPCError{Kind: RPCErrorConditionUnsatisfied, Underlying: connectErr}
	case connect.CodeInvalidArgument:
		details := connectErr.Details()
		for _, d := range details {
			msg, err := d.Value()
			if err != nil {
				continue
			}

			switch t := msg.(type) {
			case *storev1.ErrDetailNoUsableFiles:
				return RPCError{Kind: RPCErrorNoUsableFiles, Underlying: connectErr, IgnoredFiles: t.GetIgnoredFiles()}
			case *storev1.ErrDetailValidationFailure:
				return RPCError{Kind: RPCErrorValidationFailure, Underlying: connectErr, ValidationErrors: t.GetErrors()}
			}
		}

		return RPCError{Kind: RPCErrorInvalidRequest, Underlying: connectErr}
	case connect.CodeAlreadyExists:
		return RPCError{Kind: RPCErrorOperationDiscarded, Underlying: connectErr}
	default:
		return RPCError{Kind: RPCErrorUnknown, Underlying: connectErr}
	}
}

type Client struct {
	rpcClient storev1connect.CerbosStoreServiceClient
	base.Client
}

func NewClient(baseClient base.Client, options []connect.ClientOption) (*Client, error) {
	httpClient := baseClient.StdHTTPClient()
	rpcClient := storev1connect.NewCerbosStoreServiceClient(httpClient, baseClient.APIEndpoint, options...)

	return &Client{
		Client:    baseClient,
		rpcClient: rpcClient,
	}, nil
}

func (c *Client) ListFiles(ctx context.Context, req *storev1.ListFilesRequest) (*storev1.ListFilesResponse, error) {
	resp, err := c.rpcClient.ListFiles(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, newRPCError(err)
	}

	return resp.Msg, nil
}

func (c *Client) GetFiles(ctx context.Context, req *storev1.GetFilesRequest) (*storev1.GetFilesResponse, error) {
	resp, err := c.rpcClient.GetFiles(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, newRPCError(err)
	}

	return resp.Msg, nil
}

func (c *Client) ModifyFiles(ctx context.Context, req *storev1.ModifyFilesRequest) (*storev1.ModifyFilesResponse, error) {
	resp, err := c.rpcClient.ModifyFiles(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, newRPCError(err)
	}

	return resp.Msg, nil
}

func (c *Client) ReplaceFiles(ctx context.Context, req *storev1.ReplaceFilesRequest) (*storev1.ReplaceFilesResponse, error) {
	resp, err := c.rpcClient.ReplaceFiles(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, newRPCError(err)
	}

	return resp.Msg, nil
}
