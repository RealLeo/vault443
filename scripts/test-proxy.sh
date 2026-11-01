#!/bin/bash
# Real proxy protocols in a disposable namespace; no host network mutations.
set -euo pipefail
cd "$(dirname "$0")/.."
release=${1:-24.04}
case "$release" in 24.04|26.04) ;; *) exit 2;; esac
export GOMODCACHE="$PWD/.cache/go-mod" GOCACHE="$PWD/.cache/go-build"
python3 scripts/build-outline.py amd64 --offline
python3 scripts/go.py build -o .cache/e2e-fixture ./tests/e2e/fixture
python3 scripts/go.py test -c -o .cache/proxy-e2e.test ./tests/e2e
outline_go="$(python3 scripts/go.py --path)"
GOTOOLCHAIN=local GOMODCACHE="$PWD/.cache/outline/modules" GOCACHE="$PWD/.cache/outline/build-cache" \
 "$outline_go" -C helpers/outline build -mod=readonly -o ../../.cache/outline/testserver ./testserver
GOTOOLCHAIN=local CGO_ENABLED=0 GOMODCACHE="$PWD/.cache/quic-mod" GOCACHE="$PWD/.cache/quic-build" \
 "$outline_go" -C tests/quic build -mod=readonly -o ../../.cache/quic-fixture .
results="$PWD/test-results/$(cat VERSION)/proxy-$release"
mkdir -p "$results"
docker run --rm --pull never --network none --cap-add NET_ADMIN --cap-add SYS_ADMIN \
 --security-opt apparmor=unconfined --device /dev/net/tun \
 -e VAULT443_E2E_ISOLATED=1 -e VAULT443_SANDBOX_FILTER_ONLY=1 \
 -e VAULT443_PROXY_E2E=1 -e VAULT443_QUIC_E2E=1 \
 -e VAULT443_E2E_TEST_BINARY=/src/.cache/proxy-e2e.test \
 -e 'VAULT443_E2E_TEST_PATTERN=TestRealProxyProtocols|TestRealProtectedSourceDownload|TestRealTransactionalProfileSwitch' \
 -e VAULT443_E2E_TIMEOUT=480s \
 --mount "type=bind,src=$PWD,dst=/src,readonly" --mount "type=bind,src=$results,dst=/results" \
 "vault443-nm:$release" /usr/bin/python3 /src/tests/service-sandbox-probe.py \
 /src/packaging/vault443.service /bin/bash /src/tests/e2e/entrypoint.sh
