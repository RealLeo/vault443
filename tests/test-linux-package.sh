#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
target=${1:?Expected debian13, fedora44, arch or ubuntu24}
version=$(cat VERSION)
case "$target" in
  debian13) package="dist/linux/debian13/vault443_${version}-1debian13_amd64.deb";;
  fedora44) package="dist/linux/fedora44/vault443-${version}-1.fc44.x86_64.rpm";;
  arch) package="dist/linux/arch/vault443-${version}-1-x86_64.pkg.tar.zst";;
  ubuntu24|ubuntu26) package="dist/linux/ubuntu24/vault443_${version}-1ubuntu24.04_amd64.deb";;
  *) exit 2;;
esac
test -s "$package"
results="$PWD/test-results/linux-$version/$target"
mkdir -p "$results"
name="vault443-linux-test-$target-$$"
image="vault443-linux-build:$target"
if [ "$target" = ubuntu24 ]; then image=vault443-package-systemd:24.04; fi
if [ "$target" = ubuntu26 ]; then image=vault443-package-systemd:26.04; fi
cleanup() {
  docker logs "$name" >"$results/pid1.log" 2>&1 || true
  docker exec "$name" journalctl --no-pager -b >"$results/journal.log" 2>&1 || true
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
  -e VAULT443_PACKAGE_LIFECYCLE=/src/tests/linux-package-lifecycle.sh \
  -e "VAULT443_DISTRO=$target" -e "VAULT443_DISTRO_PACKAGE=/src/$package" \
  "$image" /bin/sh -ec 'mount -o remount,rw /sys/fs/cgroup; exec /usr/lib/systemd/systemd' >/dev/null
for _ in $(seq 1 100); do
  if docker exec "$name" systemctl show-environment >/dev/null 2>&1; then break; fi
  sleep .1
done
docker exec "$name" bash -euc '
  test "$(cat /proc/1/comm)" = systemd
  test "$(cat /proc/1/cgroup)" = "0::/init.scope"
  systemctl start dbus.service systemd-resolved.service NetworkManager.service
  systemctl is-active --quiet dbus.service systemd-resolved.service NetworkManager.service
  test "$(ip -j link show | jq length)" = 1
  test "$(ip -j route show default)" = "[]"
'
docker exec "$name" bash /src/tests/e2e/entrypoint.sh
echo "PASS: isolated $target package lifecycle, results: $results"
