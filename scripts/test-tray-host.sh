#!/usr/bin/env bash
# Native Qt tray transport tests, isolated from the desktop's buses and network.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
. scripts/qt-env.sh
build_dir="$project_dir/.cache/tray-host-build"
artifacts="${VAULT443_TRAY_ARTIFACTS:-$project_dir/test-results/tray-host}"
mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
cmake -S tests/tray -B "$build_dir" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_SKIP_RPATH=ON
cmake --build "$build_dir" --parallel 4
docker run --rm --network=none --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$build_dir,dst=/app,readonly" \
    --mount "type=bind,src=$artifacts,dst=/artifacts" \
    --tmpfs /tmp:rw,mode=1777 \
    "${VAULT443_TRAY_IMAGE:-vault443-platform-smoke:24.04}" sh -ec '
    export XDG_RUNTIME_DIR=/tmp/tray-runtime
    mkdir -m700 "$XDG_RUNTIME_DIR"
    export LANG=C.UTF-8 QT_QUICK_BACKEND=software LIBGL_ALWAYS_SOFTWARE=1
    export VAULT443_PRIVATE_TRAY_TEST=1 DBUS_SYSTEM_BUS_ADDRESS=unix:path=/tmp/no-system-bus
    Xvfb :99 -screen 0 1024x768x24 -nolisten tcp > /artifacts/xvfb.log 2>&1 &
    xpid=$!
    trap "kill $xpid 2>/dev/null || true" EXIT
    export DISPLAY=:99
    for i in $(seq 1 50); do test -S /tmp/.X11-unix/X99 && break; sleep .1; done
    export QT_QPA_PLATFORMTHEME=generic
    QT_QPA_PLATFORM=xcb dbus-run-session -- /app/vault443-tray-host-tests > /artifacts/x11.log 2>&1 || { cat /artifacts/x11.log; exit 1; }
    weston --backend=x11 --renderer=pixman --socket=wayland-tray --idle-time=0 > /artifacts/weston.log 2>&1 &
    wpid=$!
    trap "kill $wpid $xpid 2>/dev/null || true" EXIT
    export WAYLAND_DISPLAY=wayland-tray
    for i in $(seq 1 50); do test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" && break; sleep .1; done
    test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"
    QT_QPA_PLATFORM=wayland dbus-run-session -- /app/vault443-tray-host-tests > /artifacts/wayland.log 2>&1 || { cat /artifacts/wayland.log; exit 1; }
    QT_QPA_PLATFORM=xcb QT_SCALE_FACTOR=2 dbus-run-session -- /app/vault443-tray-host-tests > /artifacts/x11-hidpi.log 2>&1 || { cat /artifacts/x11-hidpi.log; exit 1; }
    QT_QPA_PLATFORM=wayland QT_SCALE_FACTOR=2 dbus-run-session -- /app/vault443-tray-host-tests > /artifacts/wayland-hidpi.log 2>&1 || { cat /artifacts/wayland-hidpi.log; exit 1; }
    cat /artifacts/x11.log /artifacts/wayland.log /artifacts/x11-hidpi.log /artifacts/wayland-hidpi.log
    '
