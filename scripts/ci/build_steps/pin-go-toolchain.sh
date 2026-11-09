#!/usr/bin/env bash
set -euo pipefail
echo "GO_BIN=$(command -v go)" >> "$GITHUB_ENV"
echo "GOTOOLCHAIN=auto" >> "$GITHUB_ENV"
go version
go env GOTOOLCHAIN
cat core/psiphon/go.mod | grep -E "^go |^toolchain" || true
cat core/fcae-ffi/bridges/psiphon/go/go.mod | grep -E "^go |^toolchain" || true
cat core/fcae-ffi/bridges/tun2socks/go/go.mod | grep -E "^go |^toolchain" || true
