#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOMODCACHE="$PWD/.cache/go-mod" GOCACHE="$PWD/.cache/go-build"
CGO_ENABLED=0 python3 scripts/go.py test -c -o build-network.test ./internal/network
docker build --network="${VAULT443_BUILD_NETWORK:-default}" \
  -t vault443-test:24.04 -f tests/integration.Dockerfile tests
docker run --rm --network none --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 -e VAULT443_KERNEL_TEST=1 \
  --mount "type=bind,src=$PWD/build-network.test,dst=/test/network.test,readonly" \
  vault443-test:24.04 /test/network.test -test.run TestKernelIsolatedPolicy -test.v
docker run --rm --network none --cap-add NET_ADMIN --cap-add SYS_PTRACE \
  --device /dev/net/tun -e VAULT443_KERNEL_TEST=1 -e VAULT443_PACKAGE_SOURCE=/src \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  vault443-test:24.04 /src/build-network.test -test.run '^TestDiscoveryServiceCapabilities$' -test.v

docker run --pull never --rm --network none --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  -e VAULT443_KERNEL_TEST=1 \
  --mount "type=bind,src=$PWD/build-network.test,dst=/test/network.test,readonly" \
  vault443-test:24.04 /test/network.test -test.run '^TestKernelBootstrapScopes$' -test.v
