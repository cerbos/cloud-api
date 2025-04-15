set dotenv-load := true

dev_dir := join(justfile_directory(), "hack", "dev")
genmocks_dir := join(justfile_directory(), "test", "mocks")
genpb_dir := join(justfile_directory(), "genpb")
tools_mod_dir := join(justfile_directory(), "tools")

export TOOLS_BIN_DIR := join(env_var_or_default("XDG_CACHE_HOME", join(env_var("HOME"), ".cache")), "cerbos-cloud-api/bin")

default:
    @ just --list

compile:
    @ go build ./... && go test -tags=tests,integration -run=ignore  ./... > /dev/null

cover PKG='./...' TEST='.*': _cover
    #!/usr/bin/env bash
    set -euo pipefail

    COVERFILE="$(mktemp -t cloud-api-XXXXX)"
    trap 'rm -rf "$COVERFILE"' EXIT
    go test -tags=tests,integration -coverprofile="$COVERFILE" -count=1 -run='{{ TEST }}' '{{ PKG }}'
    "${TOOLS_BIN_DIR}/cover" -p "$COVERFILE"

generate: generate-proto-code generate-mocks

generate-mocks QUIET='--log-level=""': _mockery
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    rm -rf {{ genmocks_dir }}
    "${TOOLS_BIN_DIR}/mockery" {{ QUIET }}

generate-proto-code: _buf
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    "${TOOLS_BIN_DIR}/buf" format -w
    rm -rf {{ genpb_dir }}
    (
        cd {{ tools_mod_dir }}
        "${TOOLS_BIN_DIR}/buf" generate --template=buf.gen.yaml --output=..
    )

lint: lint-modernize _golangcilint _buf
    @ "${TOOLS_BIN_DIR}/golangci-lint" run --config=.golangci.yaml --fix
    @ "${TOOLS_BIN_DIR}/buf" lint
    @ "${TOOLS_BIN_DIR}/buf" format --diff --exit-code

lint-modernize: _modernize
    @ GOFLAGS=-tags=tests,integration "${TOOLS_BIN_DIR}/modernize" -fix -test ./...

pre-commit: generate lint tests

test PKG='./...' TEST='.*':
    @ go test -v -tags=tests,integration -failfast -cover -count=1 -run='{{ TEST }}' '{{ PKG }}'

tests PKG='./...' TEST='.*': _gotestsum
    @ "${TOOLS_BIN_DIR}/gotestsum" --format=dots-v2 --format-hide-empty-pkg -- -tags=tests,integration -failfast -count=1 -run='{{ TEST }}' '{{ PKG }}'

# Executables

_buf: (_install "buf" "github.com/bufbuild/buf" "cmd/buf")

_cover: (_install "cover" "nikand.dev/go/cover@master" )

_golangcilint: (_install "golangci-lint" "github.com/golangci/golangci-lint/v2" "cmd/golangci-lint")

_gotestsum: (_install "gotestsum" "gotest.tools/gotestsum")

_modernize: (_install "modernize" "golang.org/x/tools/gopls" "internal/analysis/modernize/cmd/modernize")

_mockery: (_install "mockery" "github.com/vektra/mockery/v2")

_install EXECUTABLE MODULE CMD_PKG="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ tools_mod_dir }}
    TMP_VERSION=$(GOWORK=off go list -m -f "{{{{.Version}}" "{{ MODULE }}")
    VERSION="${TMP_VERSION#v}"
    BINARY="${TOOLS_BIN_DIR}/{{ EXECUTABLE }}"
    SYMLINK="${BINARY}-${VERSION}"
    if [[ ! -e "$SYMLINK" ]]; then
      echo "Installing $SYMLINK" 1>&2
      mkdir -p "$TOOLS_BIN_DIR"
      find "${TOOLS_BIN_DIR}" -lname "$BINARY" -delete
      if [[ "{{ EXECUTABLE }}" == "golangci-lint" ]]; then
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$TOOLS_BIN_DIR"
      else
        export CGO_ENABLED={{ if EXECUTABLE =~ "(^sql|^tbls)" { "1" } else { "0" } }}
        GOWORK=off GOBIN="$TOOLS_BIN_DIR" go install {{ if CMD_PKG != "" { MODULE + "/" + CMD_PKG } else { MODULE } }}
      fi
      ln -s "$BINARY" "$SYMLINK"
    fi
