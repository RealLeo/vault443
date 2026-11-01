#!/bin/bash
set -euo pipefail
# Host-side runner: all privileged package/network operations happen inside a
# disposable network-none container, with its own PID1 and private cgroup mount.
# Never bind the host /etc, /run, /var/lib or /sys/fs/cgroup into this test.
cd "$(dirname "$0")/.."
release=${1:-24.04}
case "$release" in 24.04|26.04) ;; *) echo 'Expected Ubuntu 24.04 or 26.04' >&2; exit 2;; esac
image="vault443-package-systemd:$release"
name="vault443-package-systemd-${release//./-}-$$"
version=$(cat VERSION)
results="$PWD/test-results/$version/package-systemd-$release"
mkdir -p "$results"
cleanup() {
  docker logs "$name" >"$results/pid1-console.log" 2>&1 || true
  docker exec "$name" journalctl --no-pager -b >"$results/systemd-journal.log" 2>&1 || true
  docker rm --force "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker run --detach --pull never --name "$name" --network none --cgroupns private \
  --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add SYS_PTRACE \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  --device /dev/net/tun --security-opt apparmor=unconfined \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  --mount "type=bind,src=$PWD,dst=/src,readonly" \
  --mount "type=bind,src=$results,dst=/results" \
  -e container=docker -e VAULT443_PACKAGE_TEST=1 -e VAULT443_REAL_SYSTEMD=1 \
  -e VAULT443_E2E_ISOLATED=1 -e VAULT443_PROXY_E2E=1 -e VAULT443_PACKAGE_NETWORK=1 \
  "$image" /bin/sh -ec 'mount -o remount,rw /sys/fs/cgroup; exec /usr/lib/systemd/systemd' >/dev/null
ready=0
for _ in $(seq 1 100); do
  if docker exec "$name" /bin/sh -ec 'systemctl is-active --quiet dbus.service systemd-resolved.service NetworkManager.service; state=$(systemctl is-system-running || true); test "$state" = running -o "$state" = degraded' 2>/dev/null; then ready=1; break; fi
  sleep .1
done
test "$ready" = 1
docker exec "$name" /bin/sh -ec '
  test "$(cat /proc/1/comm)" = systemd
  test "$(cat /proc/1/cgroup)" = "0::/init.scope"
  test "$(ip -j link show | jq -r length)" = 1
  test "$(ip -j route show default)" = "[]"
  systemctl is-system-running || true
  systemctl is-active NetworkManager.service systemd-resolved.service dbus.service
' | tee "$results/pid1-before.log"
docker exec "$name" /bin/bash /src/tests/e2e/entrypoint.sh
docker exec "$name" /bin/sh -ec '
  test "$(cat /proc/1/comm)" = systemd
  systemctl is-active NetworkManager.service systemd-resolved.service dbus.service
  systemctl --failed --no-pager
' | tee "$results/pid1-after.log"
echo "PASS: real systemd PID1 installation/upgrade on Ubuntu $release; private cgroups and isolated VLESS network"
