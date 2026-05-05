// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build toolsx
// +build toolsx

package tools

import (
	_ "connectrpc.com/connect/cmd/protoc-gen-connect-go"
	_ "github.com/cerbos/actions/cmd/install-tools"
	_ "github.com/cerbos/protoc-gen-go-hashpb"
	_ "github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto"
	_ "github.com/vektra/mockery/v3"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
	_ "golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize"
	_ "gotest.tools/gotestsum"
	_ "nikand.dev/go/cover"
)
