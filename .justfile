set dotenv-load := true

dev_dir := join(justfile_directory(), "hack", "dev")
genmocks_dir := join(justfile_directory(), "test", "mocks")
genpb_dir := join(justfile_directory(), "genpb")
tools_mod_dir := join(justfile_directory(), "tools")

export TOOLS_BIN_DIR := join(env_var_or_default("XDG_CACHE_HOME", join(env_var("HOME"), ".cache")), "cerbos-cloud-api/bin")
export PATH := TOOLS_BIN_DIR + ":" + env_var("PATH")

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
    cover -p "$COVERFILE"

generate: generate-proto-code generate-mocks

generate-mocks QUIET='--log-level=""': _mockery
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    rm -rf {{ genmocks_dir }}
    mockery {{ QUIET }}

generate-proto-code: _buf
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    buf format -w
    rm -rf {{ genpb_dir }}
    (
        cd {{ tools_mod_dir }}
        buf generate --template=buf.gen.yaml --output=..
    )
    hack/scripts/remove-unused-protobuf-imports.sh
    go mod tidy

lint: lint-modernize _golangcilint _buf
    @ golangci-lint run --config=.golangci.yaml --fix
    @ buf lint
    @ buf format --diff --exit-code

lint-modernize: _modernize
    @ GOFLAGS=-tags=tests,integration modernize -fix -test ./...

pre-commit: generate lint tests

test PKG='./...' TEST='.*':
    @ go test -v -tags=tests,integration -failfast -cover -count=1 -run='{{ TEST }}' '{{ PKG }}'

tests PKG='./...' TEST='.*': _gotestsum
    @ gotestsum --format=dots-v2 --format-hide-empty-pkg -- -tags=tests,integration -failfast -count=1 -run='{{ TEST }}' '{{ PKG }}'

# Executables

_buf: (_install "buf")

_cover: (_go-install "cover" "nikand.dev/go/cover")

_golangcilint: (_install "golangci-lint")

_gotestsum: (_go-install "gotestsum" "gotest.tools/gotestsum")

_install-tools: (_go-install "install-tools" "github.com/cerbos/actions" "cmd/install-tools")

_mockery: (_go-install "mockery" "github.com/vektra/mockery/v3")

_modernize: (_go-install "modernize" "golang.org/x/tools" "go/analysis/passes/modernize/cmd/modernize")

_go-install EXECUTABLE MODULE CMD_PKG="":
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
      export CGO_ENABLED={{ if EXECUTABLE =~ "(^sql|^tbls)" { "1" } else { "0" } }}
      GOWORK=off GOBIN="$TOOLS_BIN_DIR" go install {{ if CMD_PKG != "" { MODULE + "/" + CMD_PKG } else { MODULE } }}
      ln -s "$BINARY" "$SYMLINK"
    fi

[positional-arguments]
_install *EXECUTABLES:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ "${CI:-}" = "true" ]]; then
    for executable in "$@"; do
      if ! hash "${executable}" 2>/dev/null; then
        printf "\e[31m%s not found\e[0m\nUse cerbos/actions/install-tools to install it\n" "${executable}"
      fi
    done
  else
    just _install-tools
    cd "${TOOLS_BIN_DIR}"
    install-tools "$@"
  fi
