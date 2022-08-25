XDG_CACHE_HOME ?= $(HOME)/.cache
TOOLS_BIN_DIR := $(abspath $(XDG_CACHE_HOME)/cerbos-cloud-api/bin)
TOOLS_MOD := tools/go.mod

BUF := $(TOOLS_BIN_DIR)/buf
GOLANGCI_LINT := $(TOOLS_BIN_DIR)/golangci-lint
GOTESTSUM := $(TOOLS_BIN_DIR)/gotestsum

MOCKERY := $(TOOLS_BIN_DIR)/mockery
PROTOC_GEN_CONNECT_GO := $(TOOLS_BIN_DIR)/protoc-gen-connect-go
PROTOC_GEN_GO := $(TOOLS_BIN_DIR)/protoc-gen-go
PROTOC_GEN_GO_GRPC := $(TOOLS_BIN_DIR)/protoc-gen-go-grpc
PROTOC_GEN_GO_HASHPB := $(TOOLS_BIN_DIR)/protoc-gen-go-hashpb
PROTOC_GEN_GO_VTPROTO := $(TOOLS_BIN_DIR)/protoc-gen-go-vtproto
PROTOC_GEN_VALIDATE := $(TOOLS_BIN_DIR)/protoc-gen-validate

GENPB_DIR := genpb
PROTOS_DIR := protos

define BUF_GEN_TEMPLATE
{\
  "version": "v1",\
  "plugins": [\
    {\
      "name": "go",\
      "out": "$(GENPB_DIR)",\
      "opt": "paths=source_relative",\
      "path": "$(PROTOC_GEN_GO)"\
    },\
    {\
      "name": "vtproto",\
      "out": "$(GENPB_DIR)",\
      "opt": [\
	    "paths=source_relative",\
	  	"features=marshal+unmarshal+size"\
	  ],\
      "path": "$(PROTOC_GEN_GO_VTPROTO)"\
    },\
    {\
      "name": "validate",\
      "opt": [\
        "paths=source_relative",\
        "lang=go"\
      ],\
      "out": "$(GENPB_DIR)",\
      "path": "$(PROTOC_GEN_VALIDATE)"\
    },\
    {\
      "name": "connect-go",\
      "opt": "paths=source_relative",\
      "out": "$(GENPB_DIR)",\
      "path": "$(PROTOC_GEN_CONNECT_GO)"\
    },\
    {\
      "name": "go-hashpb",\
      "opt": "paths=source_relative",\
      "out": "$(GENPB_DIR)",\
      "path": "$(PROTOC_GEN_GO_HASHPB)"\
    }\
  ]\
}
endef

$(TOOLS_BIN_DIR):
	@ mkdir -p $(TOOLS_BIN_DIR)

$(BUF): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/bufbuild/buf/cmd/buf

$(GOLANGCI_LINT): $(TOOLS_BIN_DIR)
	@ curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLS_BIN_DIR)

$(GOTESTSUM): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) gotest.tools/gotestsum

$(MOCKERY): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/vektra/mockery/v2

$(PROTOC_GEN_CONNECT_GO): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/bufbuild/connect-go/cmd/protoc-gen-connect-go

$(PROTOC_GEN_GO): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) google.golang.org/protobuf/cmd/protoc-gen-go

$(PROTOC_GEN_GO_HASHPB): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/cerbos/protoc-gen-go-hashpb

$(PROTOC_GEN_GO_VTPROTO): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto

$(PROTOC_GEN_VALIDATE): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/envoyproxy/protoc-gen-validate

$(SQLC): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/kyleconroy/sqlc/cmd/sqlc

.PHONY: proto-gen-deps
proto-gen-deps: $(BUF) $(PROTOC_GEN_GO) $(PROTOC_GEN_GO_VTPROTO) $(PROTOC_GEN_VALIDATE) $(PROTOC_GEN_GO_HASHPB) $(PROTOC_GEN_CONNECT_GO)
