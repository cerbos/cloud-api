// Code generated by mockery v2.14.1. DO NOT EDIT.

package mockapikeyv1connect

import (
	apikeyv1 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/apikey/v1"

	connect "github.com/bufbuild/connect-go"

	context "context"

	mock "github.com/stretchr/testify/mock"
)

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

// IssueAccessToken provides a mock function with given fields: _a0, _a1
func (_m *ApiKeyServiceHandler) IssueAccessToken(_a0 context.Context, _a1 *connect.Request[apikeyv1.IssueAccessTokenRequest]) (*connect.Response[apikeyv1.IssueAccessTokenResponse], error) {
	ret := _m.Called(_a0, _a1)

	var r0 *connect.Response[apikeyv1.IssueAccessTokenResponse]
	if rf, ok := ret.Get(0).(func(context.Context, *connect.Request[apikeyv1.IssueAccessTokenRequest]) *connect.Response[apikeyv1.IssueAccessTokenResponse]); ok {
		r0 = rf(_a0, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*connect.Response[apikeyv1.IssueAccessTokenResponse])
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *connect.Request[apikeyv1.IssueAccessTokenRequest]) error); ok {
		r1 = rf(_a0, _a1)
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
//   - _a0 context.Context
//   - _a1 *connect.Request[apikeyv1.IssueAccessTokenRequest]
func (_e *ApiKeyServiceHandler_Expecter) IssueAccessToken(_a0 interface{}, _a1 interface{}) *ApiKeyServiceHandler_IssueAccessToken_Call {
	return &ApiKeyServiceHandler_IssueAccessToken_Call{Call: _e.mock.On("IssueAccessToken", _a0, _a1)}
}

func (_c *ApiKeyServiceHandler_IssueAccessToken_Call) Run(run func(_a0 context.Context, _a1 *connect.Request[apikeyv1.IssueAccessTokenRequest])) *ApiKeyServiceHandler_IssueAccessToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*connect.Request[apikeyv1.IssueAccessTokenRequest]))
	})
	return _c
}

func (_c *ApiKeyServiceHandler_IssueAccessToken_Call) Return(_a0 *connect.Response[apikeyv1.IssueAccessTokenResponse], _a1 error) *ApiKeyServiceHandler_IssueAccessToken_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

type mockConstructorTestingTNewApiKeyServiceHandler interface {
	mock.TestingT
	Cleanup(func())
}

// NewApiKeyServiceHandler creates a new instance of ApiKeyServiceHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewApiKeyServiceHandler(t mockConstructorTestingTNewApiKeyServiceHandler) *ApiKeyServiceHandler {
	mock := &ApiKeyServiceHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}