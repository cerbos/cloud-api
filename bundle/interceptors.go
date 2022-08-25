// Copyright 2021-2022 Zenauth Ltd.

package bundle

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"

	"github.com/bufbuild/connect-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
)

func newTracingInterceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, ar connect.AnyRequest) (connect.AnyResponse, error) {
			newCtx, span := otel.Tracer("cerbos.dev/cloud-api").Start(ctx, ar.Spec().Procedure)
			defer span.End()

			resp, err := next(newCtx, ar)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, connect.CodeOf(err).String())
			}

			return resp, err
		})
	})
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

//nolint:gosec
const APIKeyHeader = "x-cerbos-cloud-api-key"

type authInterceptor struct {
	apiKey string
}

func newAuthInterceptor(apiKey string) authInterceptor {
	return authInterceptor{apiKey: apiKey}
}

func (ai authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set(APIKeyHeader, ai.apiKey)
		return next(ctx, req)
	})
}

func (ai authInterceptor) WrapStreamingClient(c connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return authStreamingClientConn{StreamingClientConn: c(ctx, spec), apiKey: ai.apiKey}
	}
}

func (ai authInterceptor) WrapStreamingHandler(h connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return h
}

type authStreamingClientConn struct {
	connect.StreamingClientConn
	apiKey string
}

func (as authStreamingClientConn) RequestHeader() http.Header {
	h := as.StreamingClientConn.RequestHeader()
	h.Set(APIKeyHeader, as.apiKey)
	return h
}
