// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package provision

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/cerbos/cloud-api/base"
	provisionv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/provision/v1"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/provision/v1/provisionv1connect"
)

var _ Client = (*ClientImpl)(nil)

type Client interface {
	CreateOrganization(context.Context, string) (*provisionv1.Organization, error)
	ReadOrganization(context.Context, *provisionv1.Resource_Organization) (*provisionv1.Organization, error)
	UpdateOrganization(context.Context, *provisionv1.Resource_Organization, string) (*provisionv1.Organization, error)
	DeleteOrganization(context.Context, *provisionv1.Resource_Organization) error
	CreateWorkspace(context.Context, *provisionv1.Resource_Organization, string) (*provisionv1.Workspace, error)
	ReadWorkspace(context.Context, *provisionv1.Resource_Workspace) (*provisionv1.Workspace, error)
	UpdateWorkspace(context.Context, *provisionv1.Resource_Workspace, string) (*provisionv1.Workspace, error)
	DeleteWorkspace(context.Context, *provisionv1.Resource_Workspace) error
	CreateStore(context.Context, *provisionv1.CreateStoreRequest) (*provisionv1.Store, error)
	ReadStore(context.Context, *provisionv1.Resource_Store) (*provisionv1.Store, error)
	UpdateStore(context.Context, *provisionv1.Resource_Store, string) (*provisionv1.Store, error)
	DeleteStore(context.Context, *provisionv1.Resource_Store) error
}

type ClientImpl struct {
	rpcClient  provisionv1connect.CerbosHubProvisioningServiceClient
	baseClient base.Client
}

func NewClient(baseClient base.Client, options []connect.ClientOption) (*ClientImpl, error) {
	httpClient := baseClient.StdHTTPClient()
	rpcClient := provisionv1connect.NewCerbosHubProvisioningServiceClient(httpClient, baseClient.APIEndpoint, options...)

	return &ClientImpl{
		baseClient: baseClient,
		rpcClient:  rpcClient,
	}, nil
}

func (c *ClientImpl) CreateOrganization(ctx context.Context, name string) (*provisionv1.Organization, error) {
	resp, err := c.rpcClient.CreateOrganization(ctx, connect.NewRequest(&provisionv1.CreateOrganizationRequest{Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetOrganization(), nil
}

func (c *ClientImpl) ReadOrganization(ctx context.Context, org *provisionv1.Resource_Organization) (*provisionv1.Organization, error) {
	resp, err := c.rpcClient.ReadOrganization(ctx, connect.NewRequest(&provisionv1.ReadOrganizationRequest{ResourceId: org}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetOrganization(), nil
}

func (c *ClientImpl) UpdateOrganization(ctx context.Context, org *provisionv1.Resource_Organization, name string) (*provisionv1.Organization, error) {
	resp, err := c.rpcClient.UpdateOrganization(ctx, connect.NewRequest(&provisionv1.UpdateOrganizationRequest{ResourceId: org, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetOrganization(), nil
}

func (c *ClientImpl) DeleteOrganization(ctx context.Context, org *provisionv1.Resource_Organization) error {
	if _, err := c.rpcClient.DeleteOrganization(ctx, connect.NewRequest(&provisionv1.DeleteOrganizationRequest{ResourceId: org})); err != nil {
		return handleError(err)
	}

	return nil
}

func (c *ClientImpl) CreateWorkspace(ctx context.Context, org *provisionv1.Resource_Organization, name string) (*provisionv1.Workspace, error) {
	resp, err := c.rpcClient.CreateWorkspace(ctx, connect.NewRequest(&provisionv1.CreateWorkspaceRequest{Organization: org, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetWorkspace(), nil
}

func (c *ClientImpl) ReadWorkspace(ctx context.Context, workspace *provisionv1.Resource_Workspace) (*provisionv1.Workspace, error) {
	resp, err := c.rpcClient.ReadWorkspace(ctx, connect.NewRequest(&provisionv1.ReadWorkspaceRequest{ResourceId: workspace}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetWorkspace(), nil
}

func (c *ClientImpl) UpdateWorkspace(ctx context.Context, workspace *provisionv1.Resource_Workspace, name string) (*provisionv1.Workspace, error) {
	resp, err := c.rpcClient.UpdateWorkspace(ctx, connect.NewRequest(&provisionv1.UpdateWorkspaceRequest{ResourceId: workspace, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetWorkspace(), nil
}

func (c *ClientImpl) DeleteWorkspace(ctx context.Context, workspace *provisionv1.Resource_Workspace) error {
	if _, err := c.rpcClient.DeleteWorkspace(ctx, connect.NewRequest(&provisionv1.DeleteWorkspaceRequest{ResourceId: workspace})); err != nil {
		return handleError(err)
	}

	return nil
}

func (c *ClientImpl) CreateStore(ctx context.Context, req *provisionv1.CreateStoreRequest) (*provisionv1.Store, error) {
	resp, err := c.rpcClient.CreateStore(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetStore(), nil
}

func (c *ClientImpl) ReadStore(ctx context.Context, workspace *provisionv1.Resource_Store) (*provisionv1.Store, error) {
	resp, err := c.rpcClient.ReadStore(ctx, connect.NewRequest(&provisionv1.ReadStoreRequest{ResourceId: workspace}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetStore(), nil
}

func (c *ClientImpl) UpdateStore(ctx context.Context, workspace *provisionv1.Resource_Store, name string) (*provisionv1.Store, error) {
	resp, err := c.rpcClient.UpdateStore(ctx, connect.NewRequest(&provisionv1.UpdateStoreRequest{ResourceId: workspace, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetStore(), nil
}

func (c *ClientImpl) DeleteStore(ctx context.Context, workspace *provisionv1.Resource_Store) error {
	if _, err := c.rpcClient.DeleteStore(ctx, connect.NewRequest(&provisionv1.DeleteStoreRequest{ResourceId: workspace})); err != nil {
		return handleError(err)
	}

	return nil
}

type ErrorCause int

const (
	CauseAborted ErrorCause = iota
	CauseAlreadyExists
	CauseAuthenticationFailed
	CauseFailedPrecondition
	CauseInvalidRequest
	CauseNotFound
	CausePermissionDenied
	CauseTooManyFailures
	CauseUnknown
)

func (ec ErrorCause) String() string {
	switch ec {
	case CauseAborted:
		return "request aborted by server"
	case CauseAlreadyExists:
		return "resource already exists"
	case CauseAuthenticationFailed:
		return "authentication failed"
	case CauseFailedPrecondition:
		return "failed precondition"
	case CauseInvalidRequest:
		return "invalid request"
	case CauseNotFound:
		return "resource not found"
	case CausePermissionDenied:
		return "permission denied"
	case CauseTooManyFailures:
		return "too many failures"
	default:
		return "unknown"
	}
}

type Error struct {
	Underlying error
	Cause      ErrorCause
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %v", e.Cause, e.Underlying)
}

func (e Error) Unwrap() error {
	return e.Underlying
}

func handleError(err error) Error {
	if errors.Is(err, base.ErrAuthenticationFailed) {
		return Error{Cause: CauseAuthenticationFailed, Underlying: err}
	}

	if errors.Is(err, base.ErrTooManyFailures) {
		return Error{Cause: CauseTooManyFailures, Underlying: err}
	}

	connectErr := new(connect.Error)
	if !errors.As(err, &connectErr) {
		return Error{Cause: CauseUnknown, Underlying: err}
	}

	switch connectErr.Code() {
	case connect.CodePermissionDenied:
		return Error{Cause: CausePermissionDenied, Underlying: connectErr}
	case connect.CodeNotFound:
		return Error{Cause: CauseNotFound, Underlying: connectErr}
	case connect.CodeFailedPrecondition:
		return Error{Cause: CauseFailedPrecondition, Underlying: connectErr}
	case connect.CodeInvalidArgument:
		return Error{Cause: CauseInvalidRequest, Underlying: connectErr}
	case connect.CodeAlreadyExists:
		return Error{Cause: CauseAlreadyExists, Underlying: connectErr}
	case connect.CodeAborted, connect.CodeCanceled, connect.CodeDeadlineExceeded:
		return Error{Cause: CauseAborted, Underlying: connectErr}
	default:
		return Error{Cause: CauseUnknown, Underlying: connectErr}
	}
}
