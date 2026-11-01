#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${VAULT443_ARM64_OUTPUT:-$project_dir/build-arm64}"
image="${VAULT443_ARM64_BUILDER:-vault443-cross:24.04-arm64}"
base_image="${VAULT443_ARM64_BASE:-ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55}"
build_network="${VAULT443_BUILD_NETWORK:-default}"
mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"

# Host networking is optional and applies only to downloading build packages.
# Compilation itself always runs in a network-isolated container.
docker build --network="$build_network" --build-arg "BASE_IMAGE=$base_image" \
  --tag "$image" --file "$project_dir/scripts/Dockerfile.arm64-cross" \
  "$project_dir/scripts"
docker image inspect "$image" --format '{{.Id}}' > "$output_dir/builder-image-id.txt"
docker run --rm --network=none --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$project_dir,dst=/src,readonly" \
  --mount "type=bind,src=$output_dir,dst=/out" \
  "$image" sh -ec '
    cmake -S /src -B /out -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=/opt/arm64-toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_SKIP_RPATH=ON -DVAULT443_BUILD_UI_TESTS=OFF
    cmake --build /out --parallel 4
    cp /opt/arm64-sysroot/package-versions.txt /out/qt-sysroot-package-versions.txt
    file /out/vault443
    aarch64-linux-gnu-readelf -h /out/vault443 | grep -q "Machine:.*AArch64"
  '

cd "$project_dir"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOPROXY=off \
  GOMODCACHE="${GOMODCACHE:-$project_dir/.cache/go-mod}" \
  GOCACHE="${GOCACHE:-$project_dir/.cache/go-build}" \
  go build -buildvcs=false -trimpath -ldflags='-s -w' -o "$output_dir/vault443d" ./cmd/vault443d
readelf -h "$output_dir/vault443d" | grep -q 'Machine:.*AArch64'
file "$output_dir/vault443" "$output_dir/vault443d"
python3 scripts/build-amneziawg.py arm64 --offline
sha256sum "$output_dir/vault443" "$output_dir/vault443d"
