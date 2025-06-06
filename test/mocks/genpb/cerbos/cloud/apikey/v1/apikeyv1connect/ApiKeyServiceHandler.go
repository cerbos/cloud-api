// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify
// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package mockapikeyv1connect

import (
	"context"

	"connectrpc.com/connect"
	"github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"
	mock "github.com/stretchr/testify/mock"
)

// NewApiKeyServiceHandler creates a new instance of ApiKeyServiceHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewApiKeyServiceHandler(t interface {
	mock.TestingT
	Cleanup(func())
}) *ApiKeyServiceHandler {
	mock := &ApiKeyServiceHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// ApiKeyServiceHandler is an autogenerated mock type for the ApiKeyServiceHandler type
type ApiKeyServiceHandler struct {
	mock.Mock
}

type ApiKeyServiceHandler_Expecter struct {
	mock *mock.Mock
}

func (_m *ApiKeyServiceHandler) EXPECT() *ApiKeyServiceHandler_Expecter {
	return &ApiKeyServiceHandler_Expecter{mock: &_m.Mock}
}

// IssueAccessToken provides a mock function for the type ApiKeyServiceHandler
func (_mock *ApiKeyServiceHandler) IssueAccessToken(context1 context.Context, request *connect.Request[apikeyv1.IssueAccessTokenRequest]) (*connect.Response[apikeyv1.IssueAccessTokenResponse], error) {
	ret := _mock.Called(context1, request)

	if len(ret) == 0 {
		panic("no return value specified for IssueAccessToken")
	}

	var r0 *connect.Response[apikeyv1.IssueAccessTokenResponse]
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, *connect.Request[apikeyv1.IssueAccessTokenRequest]) (*connect.Response[apikeyv1.IssueAccessTokenResponse], error)); ok {
		return returnFunc(context1, request)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, *connect.Request[apikeyv1.IssueAccessTokenRequest]) *connect.Response[apikeyv1.IssueAccessTokenResponse]); ok {
		r0 = returnFunc(context1, request)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*connect.Response[apikeyv1.IssueAccessTokenResponse])
		}
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, *connect.Request[apikeyv1.IssueAccessTokenRequest]) error); ok {
		r1 = returnFunc(context1, request)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// ApiKeyServiceHandler_IssueAccessToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IssueAccessToken'
type ApiKeyServiceHandler_IssueAccessToken_Call struct {
	*mock.Call
}

// IssueAccessToken is a helper method to define mock.On call
//   - context1 context.Context
//   - request *connect.Request[apikeyv1.IssueAccessTokenRequest]
func (_e *ApiKeyServiceHandler_Expecter) IssueAccessToken(context1 interface{}, request interface{}) *ApiKeyServiceHandler_IssueAccessToken_Call {
	return &ApiKeyServiceHandler_IssueAccessToken_Call{Call: _e.mock.On("IssueAccessToken", context1, request)}
}

func (_c *ApiKeyServiceHandler_IssueAccessToken_Call) Run(run func(context1 context.Context, request *connect.Request[apikeyv1.IssueAccessTokenRequest])) *ApiKeyServiceHandler_IssueAccessToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 context.Context
		if args[0] != nil {
			arg0 = args[0].(context.Context)
		}
		var arg1 *connect.Request[apikeyv1.IssueAccessTokenRequest]
		if args[1] != nil {
			arg1 = args[1].(*connect.Request[apikeyv1.IssueAccessTokenRequest])
		}
		run(
			arg0,
			arg1,
		)
	})
	return _c
}

func (_c *ApiKeyServiceHandler_IssueAccessToken_Call) Return(response *connect.Response[apikeyv1.IssueAccessTokenResponse], err error) *ApiKeyServiceHandler_IssueAccessToken_Call {
	_c.Call.Return(response, err)
	return _c
}

func (_c *ApiKeyServiceHandler_IssueAccessToken_Call) RunAndReturn(run func(context1 context.Context, request *connect.Request[apikeyv1.IssueAccessTokenRequest]) (*connect.Response[apikeyv1.IssueAccessTokenResponse], error)) *ApiKeyServiceHandler_IssueAccessToken_Call {
	_c.Call.Return(run)
	return _c
}
