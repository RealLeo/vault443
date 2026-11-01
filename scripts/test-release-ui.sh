#!/usr/bin/env bash
# Real X11/Wayland surfaces in a disposable, network-isolated desktop fixture.
set -euo pipefail
if [ "${1:-}" != --inside ]; then
  cd "$(dirname "$0")/.."
  artifacts="${VAULT443_UI_ARTIFACTS:-$PWD/test-results/ui-$(cat VERSION)}"
  build_dir="${VAULT443_UI_BUILD_DIR:-$PWD/build}"
  mkdir -p "$artifacts"
  docker run --rm --pull never --network none --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$build_dir,dst=/app,readonly" \
    --mount "type=bind,src=$PWD/scripts/test-release-ui.sh,dst=/runner,readonly" \
    --mount "type=bind,src=$artifacts,dst=/artifacts" --tmpfs /tmp:rw,mode=1777 \
    "${VAULT443_UI_IMAGE:-vault443-platform-smoke:24.04}" bash /runner --inside
  exit
fi
test -f /.dockerenv
export XDG_RUNTIME_DIR=/tmp/vault443-runtime XDG_CONFIG_HOME=/tmp/vault443-config
mkdir -m700 "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME"
export QT_QUICK_BACKEND=software LIBGL_ALWAYS_SOFTWARE=1 LANG=C.UTF-8
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/tmp/no-system-bus
Xvfb :99 -screen 0 1920x1920x24 -nolisten tcp >/artifacts/xvfb.log 2>&1 &
xpid=$!
wpid=
trap 'test -z "$wpid" || kill "$wpid" 2>/dev/null || true; kill "$xpid" 2>/dev/null || true' EXIT
export DISPLAY=:99
for i in $(seq 1 50); do test -S /tmp/.X11-unix/X99 && break; sleep .1; done
weston --backend=x11 --renderer=pixman --socket=wayland-vault443 --idle-time=0 --width=1920 --height=1920 >/artifacts/weston.log 2>&1 &
wpid=$!
export WAYLAND_DISPLAY=wayland-vault443
for i in $(seq 1 50); do test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" && break; sleep .1; done
test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"
for platform in xcb wayland; do
  for language in en ru; do
    for dpi in 1 1.25 1.5 2; do
      tag="$platform-$language-$dpi"
      LANGUAGE="$language" QT_QPA_PLATFORM="$platform" QT_SCALE_FACTOR="$dpi" \
        /app/vault443 --demo --screenshot "/artifacts/$tag.png" >"/artifacts/$tag.log" 2>&1
      LANGUAGE="$language" QT_QPA_PLATFORM="$platform" QT_SCALE_FACTOR="$dpi" \
        /app/vault443-ui-tests compactImportAndTrafficFitInBothLanguagesAndScales \
        trafficStaysAfterDisconnectAndHidesWhenUnavailableOrForeign \
        workButtonLabelsFitBothLanguages workRoutesAndDNSCanReturnToAutomatic >>"/artifacts/$tag.log" 2>&1
      echo "PASS: $tag screenshot and traffic/import layout"
    done
    LANGUAGE="$language" QT_QPA_PLATFORM="$platform" /app/vault443-ui-tests \
      >"/artifacts/$platform-$language-tests.log" 2>&1
    echo "PASS: $platform $language full GUI suite"
  done
  for state in large-traffic traffic-unavailable; do
    LANGUAGE=en QT_QPA_PLATFORM="$platform" /app/vault443 --demo --demo-state "$state" \
      --screenshot "/artifacts/$platform-$state.png" >"/artifacts/$platform-$state.log" 2>&1
  done
done
cat /etc/os-release > /artifacts/runtime.txt
if command -v dpkg-query >/dev/null; then
  dpkg-query -W 'libqt6core6*' weston xvfb >> /artifacts/runtime.txt
elif command -v rpm >/dev/null; then
  rpm -q qt6-qtbase weston xorg-x11-server-Xvfb >> /artifacts/runtime.txt
else
  pacman -Q qt6-base weston xorg-server-xvfb >> /artifacts/runtime.txt
fi
