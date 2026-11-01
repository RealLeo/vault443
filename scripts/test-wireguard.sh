#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
release=${1:-24.04}
case "$release" in 24.04|26.04) ;; *) echo 'Expected Ubuntu 24.04 or 26.04' >&2; exit 2;; esac
test "$(uname -m)" = x86_64
test -x .cache/amneziawg/amd64/amneziawg-go
test -x .cache/xray/amd64/xray
export GOMODCACHE="$PWD/.cache/go-mod" GOCACHE="$PWD/.cache/go-build"
mkdir -p .cache/wireguard-e2e
CGO_ENABLED=0 go build -buildvcs=false -o .cache/wireguard-e2e/vault443d ./cmd/vault443d
CGO_ENABLED=0 go build -buildvcs=false -o .cache/wireguard-e2e/fixture ./tests/e2e/fixture
CGO_ENABLED=0 go test -c -o .cache/wireguard-e2e/tests ./tests/e2e
results="${VAULT443_E2E_RESULTS:-$PWD/test-results/$(cat VERSION)/wireguard-$release}"
mkdir -p "$results"
results=$(cd "$results" && pwd)
docker run --rm --network none \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --device /dev/net/tun \
  --security-opt apparmor=unconfined \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  --env VAULT443_E2E_ISOLATED=1 --env VAULT443_WORKVPN_E2E=1 \
  --env VAULT443_WIREGUARD_E2E=1 --env VAULT443_SANDBOX_FILTER_ONLY=1 \
  --env VAULT443_WORKVPN_EVENT_HELPER=/src/.cache/wireguard-e2e/vault443d \
  --env VAULT443_E2E_TEST_BINARY=/src/.cache/wireguard-e2e/tests \
  --env VAULT443_E2E_FIXTURE_BINARY=/src/.cache/wireguard-e2e/fixture \
  --env "VAULT443_E2E_TEST_PATTERN=${VAULT443_E2E_TEST_PATTERN:-^TestRealWireGuard}" \
  --env VAULT443_E2E_TIMEOUT=600s \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  --mount "type=bind,src=$results,dst=/results" \
  "${VAULT443_E2E_IMAGE:-vault443-e2e:$release}" \
  /usr/bin/python3 /src/tests/service-sandbox-probe.py \
  /src/packaging/vault443.service /bin/bash /src/tests/e2e/entrypoint.sh
