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

var _ Client = (*clientImpl)(nil)

type Client interface {
	ListOrganizations(context.Context) ([]*provisionv1.Organization, error)
	ReadOrganization(context.Context, *provisionv1.Resource_Organization) (*provisionv1.Organization, error)
	UpdateOrganization(context.Context, *provisionv1.Resource_Organization, string) (*provisionv1.Organization, error)
	ListWorkspaces(context.Context, *provisionv1.Resource_Organization) ([]*provisionv1.Workspace, error)
	CreateWorkspace(context.Context, *provisionv1.Resource_Organization, string) (*provisionv1.Workspace, error)
	ReadWorkspace(context.Context, *provisionv1.Resource_Workspace) (*provisionv1.Workspace, error)
	UpdateWorkspace(context.Context, *provisionv1.Resource_Workspace, string) (*provisionv1.Workspace, error)
	DeleteWorkspace(context.Context, *provisionv1.Resource_Workspace) error
	ListStores(context.Context, *provisionv1.Resource_Workspace) ([]*provisionv1.Store, error)
	CreateStore(context.Context, *provisionv1.Resource_Workspace, string) (*provisionv1.Store, error)
	ReadStore(context.Context, *provisionv1.Resource_Store) (*provisionv1.Store, error)
	UpdateStore(context.Context, *provisionv1.Resource_Store, string) (*provisionv1.Store, error)
	DeleteStore(context.Context, *provisionv1.Resource_Store) error
	ListDeployments(context.Context, *provisionv1.Resource_Workspace) ([]*provisionv1.Deployment, error)
	CreateDeployment(context.Context, *provisionv1.Resource_Workspace, string, []string) (*provisionv1.Deployment, error)
	ReadDeployment(context.Context, *provisionv1.Resource_Deployment) (*provisionv1.Deployment, error)
	UpdateDeployment(context.Context, *provisionv1.Resource_Deployment, string) (*provisionv1.Deployment, error)
	DeleteDeployment(context.Context, *provisionv1.Resource_Deployment) error
}

type clientImpl struct {
	rpcClient  provisionv1connect.CerbosHubProvisioningServiceClient
	baseClient base.Client
}

func NewClient(baseClient base.Client, options []connect.ClientOption) (Client, error) {
	httpClient := baseClient.StdHTTPClient()
	rpcClient := provisionv1connect.NewCerbosHubProvisioningServiceClient(httpClient, baseClient.APIEndpoint, options...)

	return &clientImpl{
		baseClient: baseClient,
		rpcClient:  rpcClient,
	}, nil
}

func (c *clientImpl) ListOrganizations(ctx context.Context) ([]*provisionv1.Organization, error) {
	resp, err := c.rpcClient.ListOrganizations(ctx, connect.NewRequest(&provisionv1.ListOrganizationsRequest{}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetOrganizations(), nil
}

func (c *clientImpl) ReadOrganization(ctx context.Context, org *provisionv1.Resource_Organization) (*provisionv1.Organization, error) {
	resp, err := c.rpcClient.ReadOrganization(ctx, connect.NewRequest(&provisionv1.ReadOrganizationRequest{ResourceId: org}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetOrganization(), nil
}

func (c *clientImpl) UpdateOrganization(ctx context.Context, org *provisionv1.Resource_Organization, name string) (*provisionv1.Organization, error) {
	resp, err := c.rpcClient.UpdateOrganization(ctx, connect.NewRequest(&provisionv1.UpdateOrganizationRequest{ResourceId: org, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetOrganization(), nil
}

func (c *clientImpl) ListWorkspaces(ctx context.Context, org *provisionv1.Resource_Organization) ([]*provisionv1.Workspace, error) {
	resp, err := c.rpcClient.ListWorkspaces(ctx, connect.NewRequest(&provisionv1.ListWorkspacesRequest{Organization: org}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetWorkspaces(), nil
}

func (c *clientImpl) CreateWorkspace(ctx context.Context, org *provisionv1.Resource_Organization, name string) (*provisionv1.Workspace, error) {
	resp, err := c.rpcClient.CreateWorkspace(ctx, connect.NewRequest(&provisionv1.CreateWorkspaceRequest{Organization: org, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetWorkspace(), nil
}

func (c *clientImpl) ReadWorkspace(ctx context.Context, workspace *provisionv1.Resource_Workspace) (*provisionv1.Workspace, error) {
	resp, err := c.rpcClient.ReadWorkspace(ctx, connect.NewRequest(&provisionv1.ReadWorkspaceRequest{ResourceId: workspace}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetWorkspace(), nil
}

func (c *clientImpl) UpdateWorkspace(ctx context.Context, workspace *provisionv1.Resource_Workspace, name string) (*provisionv1.Workspace, error) {
	resp, err := c.rpcClient.UpdateWorkspace(ctx, connect.NewRequest(&provisionv1.UpdateWorkspaceRequest{ResourceId: workspace, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetWorkspace(), nil
}

func (c *clientImpl) DeleteWorkspace(ctx context.Context, workspace *provisionv1.Resource_Workspace) error {
	if _, err := c.rpcClient.DeleteWorkspace(ctx, connect.NewRequest(&provisionv1.DeleteWorkspaceRequest{ResourceId: workspace})); err != nil {
		return handleError(err)
	}

	return nil
}

func (c *clientImpl) ListStores(ctx context.Context, workspace *provisionv1.Resource_Workspace) ([]*provisionv1.Store, error) {
	resp, err := c.rpcClient.ListStores(ctx, connect.NewRequest(&provisionv1.ListStoresRequest{Workspace: workspace}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetStores(), nil
}

func (c *clientImpl) CreateStore(ctx context.Context, workspace *provisionv1.Resource_Workspace, name string) (*provisionv1.Store, error) {
	resp, err := c.rpcClient.CreateStore(ctx, connect.NewRequest(&provisionv1.CreateStoreRequest{Workspace: workspace, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetStore(), nil
}

func (c *clientImpl) ReadStore(ctx context.Context, store *provisionv1.Resource_Store) (*provisionv1.Store, error) {
	resp, err := c.rpcClient.ReadStore(ctx, connect.NewRequest(&provisionv1.ReadStoreRequest{ResourceId: store}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetStore(), nil
}

func (c *clientImpl) UpdateStore(ctx context.Context, store *provisionv1.Resource_Store, name string) (*provisionv1.Store, error) {
	resp, err := c.rpcClient.UpdateStore(ctx, connect.NewRequest(&provisionv1.UpdateStoreRequest{ResourceId: store, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetStore(), nil
}

func (c *clientImpl) DeleteStore(ctx context.Context, store *provisionv1.Resource_Store) error {
	if _, err := c.rpcClient.DeleteStore(ctx, connect.NewRequest(&provisionv1.DeleteStoreRequest{ResourceId: store})); err != nil {
		return handleError(err)
	}

	return nil
}

func (c *clientImpl) ListDeployments(ctx context.Context, workspace *provisionv1.Resource_Workspace) ([]*provisionv1.Deployment, error) {
	resp, err := c.rpcClient.ListDeployments(ctx, connect.NewRequest(&provisionv1.ListDeploymentsRequest{Workspace: workspace}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetDeployments(), nil
}

func (c *clientImpl) CreateDeployment(ctx context.Context, workspace *provisionv1.Resource_Workspace, name string, stores []string) (*provisionv1.Deployment, error) {
	resp, err := c.rpcClient.CreateDeployment(ctx, connect.NewRequest(&provisionv1.CreateDeploymentRequest{
		Workspace: workspace,
		Name:      name,
		Stores:    stores,
	}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetDeployment(), nil
}

func (c *clientImpl) ReadDeployment(ctx context.Context, deployment *provisionv1.Resource_Deployment) (*provisionv1.Deployment, error) {
	resp, err := c.rpcClient.ReadDeployment(ctx, connect.NewRequest(&provisionv1.ReadDeploymentRequest{ResourceId: deployment}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetDeployment(), nil
}

func (c *clientImpl) UpdateDeployment(ctx context.Context, deployment *provisionv1.Resource_Deployment, name string) (*provisionv1.Deployment, error) {
	resp, err := c.rpcClient.UpdateDeployment(ctx, connect.NewRequest(&provisionv1.UpdateDeploymentRequest{ResourceId: deployment, Name: name}))
	if err != nil {
		return nil, handleError(err)
	}

	return resp.Msg.GetDeployment(), nil
}

func (c *clientImpl) DeleteDeployment(ctx context.Context, deployment *provisionv1.Resource_Deployment) error {
	if _, err := c.rpcClient.DeleteDeployment(ctx, connect.NewRequest(&provisionv1.DeleteDeploymentRequest{ResourceId: deployment})); err != nil {
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
