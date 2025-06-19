// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"

	"connectrpc.com/connect"
	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"
)

var circuitBreaker failsafe.Executor[connect.AnyResponse]

func init() {
	circuitBreaker = failsafe.NewExecutor(
		circuitbreaker.Builder[connect.AnyResponse]().
			WithFailureThresholdRatio(6, 10).
			HandleIf(func(_ connect.AnyResponse, err error) bool {
				if err == nil {
					return false
				}

				code := connect.CodeOf(err)
				switch code {
				case connect.CodeAborted, connect.CodeCanceled, connect.CodeDeadlineExceeded, connect.CodeFailedPrecondition:
					return false
				default:
					return true
				}
			}).
			Build(),
	)
}

type userAgentInterceptor struct {
	userAgent string
}

func newUserAgentInterceptor() userAgentInterceptor {
	version := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Sum != "" {
			version = info.Main.Version
		} else {
			for _, bs := range info.Settings {
				if bs.Key == "vcs.revision" {
					version = bs.Value
				}
			}
		}
	}

	return userAgentInterceptor{userAgent: fmt.Sprintf("cerbos-cloud-client/%s (%s; %s)", version, runtime.GOOS, runtime.GOARCH)}
}

func (uai userAgentInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("User-Agent", uai.userAgent)
		return next(ctx, req)
	})
}

func (uai userAgentInterceptor) WrapStreamingClient(c connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return uaStreamingClientConn{StreamingClientConn: c(ctx, spec), userAgent: uai.userAgent}
	}
}

func (uai userAgentInterceptor) WrapStreamingHandler(h connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return h
}

type uaStreamingClientConn struct {
	connect.StreamingClientConn
	userAgent string
}

func (uas uaStreamingClientConn) RequestHeader() http.Header {
	h := uas.StreamingClientConn.RequestHeader()
	h.Set("User-Agent", uas.userAgent)
	return h
}

type authInterceptor struct {
	authClient *authClient
}

func newAuthInterceptor(authClient *authClient) authInterceptor {
	return authInterceptor{authClient: authClient}
}

func (ai authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		err := ai.authClient.SetAuthTokenHeader(ctx, req.Header())
		if err != nil {
			return nil, err
		}

		return next(ctx, req)
	})
}

func (ai authInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		err := ai.authClient.SetAuthTokenHeader(ctx, conn.RequestHeader())

		return authStreamingClientConn{
			StreamingClientConn: conn,
			err:                 err,
		}
	}
}

func (ai authInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

type authStreamingClientConn struct {
	connect.StreamingClientConn
	err error
}

func (as authStreamingClientConn) Send(req any) error {
	if as.err != nil {
		return as.err
	}

	return as.StreamingClientConn.Send(req)
}

func (as authStreamingClientConn) Receive(req any) error {
	if as.err != nil {
		return as.err
	}

	return as.StreamingClientConn.Receive(req)
}

type circuitBreakerInterceptor struct {
	enabled bool
}

func newCircuitBreakerInterceptor() *circuitBreakerInterceptor {
	return &circuitBreakerInterceptor{enabled: true}
}

func (cbi *circuitBreakerInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if !cbi.enabled {
			return next(ctx, req)
		}

		resp, err := circuitBreaker.Get(func() (connect.AnyResponse, error) {
			return next(ctx, req)
		})

		if errors.Is(err, circuitbreaker.ErrOpen) {
			return resp, ErrTooManyFailures
		}

		return resp, err
	})
}

func (cbi *circuitBreakerInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	}
}

func (cbi *circuitBreakerInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}
