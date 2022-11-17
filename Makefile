include tools/tools.mk

.PHONY: all
all: generate deps lint test

.PHONY: clean
clean:
	@go clean

.PHONY: clean-tools
clean-tools:
	@-rm -rf $(TOOLS_BIN_DIR)

.PHONY: lint
lint: $(GOLANGCI_LINT)
	@ $(GOLANGCI_LINT) run --config=.golangci.yaml --fix
	@ $(BUF) lint
	@ $(BUF) format --diff --exit-code

.PHONY: deps
deps:
	@ go mod tidy -e -compat=1.18

.PHONY: generate
generate: clean generate-proto-code generate-mocks

.PHONY: generate-proto-code
generate-proto-code: proto-gen-deps
	@ $(BUF) format -w

	@-rm -rf $(GENPB_DIR)
	@ $(BUF) generate --template '$(BUF_GEN_TEMPLATE)' $(PROTOS_DIR)

.PHONY: generate-mocks
generate-mocks: $(MOCKERY)
	@ $(MOCKERY) --quiet --srcpkg=./genpb/cerbos/cloud/apikey/v1/apikeyv1connect --name=ApiKeyServiceHandler \
		--packageprefix=mock --output=test/mocks --with-expecter --keeptree
	@ $(MOCKERY) --quiet --srcpkg=./genpb/cerbos/cloud/bundle/v1/bundlev1connect --name=CerbosBundleServiceHandler \
		--packageprefix=mock --output=test/mocks --with-expecter --keeptree

.PHONY: compile
compile:
	@ go build ./... && go test -tags="tests integration" -run=ignore  ./... > /dev/null

.PHONY: test
test: $(GOTESTSUM) test-integration

.PHONY: test-unit
test-unit: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests $(COVERPROFILE) -cover ./...

.PHONY: test-integration
test-integration: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests,integration $(COVERPROFILE) -cover ./...
