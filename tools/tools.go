// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build toolsx
// +build toolsx

package tools

import (
	_ "connectrpc.com/connect/cmd/protoc-gen-connect-go"
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "github.com/cerbos/protoc-gen-go-hashpb"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto"
	_ "github.com/vektra/mockery/v2"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
	_ "gotest.tools/gotestsum"
)
