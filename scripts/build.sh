#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/qt-env.sh
export GOMODCACHE="$PWD/.cache/go-mod" GOCACHE="$PWD/.cache/go-build"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_SKIP_RPATH=ON
cmake --build build --parallel "${JOBS:-4}"
python3 scripts/build-service.py "$(dpkg --print-architecture)" build
python3 scripts/build-amneziawg.py "$(dpkg --print-architecture)" --offline
python3 scripts/build-outline.py "$(dpkg --print-architecture)" --offline
