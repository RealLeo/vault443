#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/qt-env.sh
export GOMODCACHE="$PWD/.cache/go-mod" GOCACHE="$PWD/.cache/go-build"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_SKIP_RPATH=ON
cmake --build build --parallel "${JOBS:-4}"
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o build/vault443d ./cmd/vault443d
