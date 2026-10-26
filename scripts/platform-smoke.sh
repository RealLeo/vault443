#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${VAULT443_PLATFORM_BUILD_DIR:-$project_dir/build}"
run_tests="${VAULT443_PLATFORM_RUN_TESTS:-1}"
test -x "$build_dir/vault443"
if [ "$run_tests" = 1 ]; then test -x "$build_dir/vault443-ui-tests"; fi
image="${VAULT443_PLATFORM_IMAGE:-vault443-platform-smoke:24.04}"
base="${VAULT443_PLATFORM_BASE:-ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55}"
artifacts="${VAULT443_PLATFORM_ARTIFACTS:-$project_dir/test-results/platform-24.04}"
mkdir -p "$artifacts"
artifacts="$(cd -- "$artifacts" && pwd)"
build_dir="$(cd -- "$build_dir" && pwd)"
if [ "${VAULT443_PLATFORM_SKIP_BUILD:-0}" != 1 ]; then
    docker build --network="${VAULT443_BUILD_NETWORK:-default}" --build-arg "BASE_IMAGE=$base" \
        -f "$project_dir/scripts/Dockerfile.platform-smoke" -t "$image" "$project_dir/scripts"
fi
docker run --rm --network=none --user "$(id -u):$(id -g)" \
    --env "VAULT443_PLATFORM_RUN_TESTS=$run_tests" \
    --mount "type=bind,src=$build_dir,dst=/app,readonly" \
    --mount "type=bind,src=$artifacts,dst=/artifacts" \
    --tmpfs /tmp:rw,mode=1777 "$image" sh -ec '
    export XDG_RUNTIME_DIR=/tmp/vault443-runtime
    mkdir -m700 "$XDG_RUNTIME_DIR"
    export QT_QUICK_BACKEND=software
    export LIBGL_ALWAYS_SOFTWARE=1
    export LANG=C.UTF-8
    Xvfb :99 -screen 0 1920x1920x24 -nolisten tcp > /artifacts/xvfb.log 2>&1 &
    xpid=$!
    trap "kill $xpid 2>/dev/null || true" EXIT
    export DISPLAY=:99
    for i in $(seq 1 50); do test -S /tmp/.X11-unix/X99 && break; sleep .1; done
    QT_QPA_PLATFORM=xcb /app/vault443 --demo --scale 1 --screenshot /artifacts/x11.png > /artifacts/x11-gui.log 2>&1
    QT_QPA_PLATFORM=xcb /app/vault443 --demo --demo-screen vpn --screenshot /artifacts/x11-vpn.png >> /artifacts/x11-gui.log 2>&1
    QT_QPA_PLATFORM=xcb /app/vault443 --demo --demo-state stage-resolving_endpoint --screenshot /artifacts/x11-connecting.png >> /artifacts/x11-gui.log 2>&1
    QT_QPA_PLATFORM=xcb /app/vault443 --demo --demo-state retry-wait --screenshot /artifacts/x11-retry.png >> /artifacts/x11-gui.log 2>&1
    QT_QPA_PLATFORM=xcb /app/vault443 --demo --demo-state retry-wait --demo-screen diagnostics --screenshot /artifacts/x11-diagnostics.png >> /artifacts/x11-gui.log 2>&1
    if [ "$VAULT443_PLATFORM_RUN_TESTS" = 1 ]; then
        QT_QPA_PLATFORM=xcb /app/vault443-ui-tests > /artifacts/x11-tests.log 2>&1
        QT_SCALE_FACTOR=2 QT_QPA_PLATFORM=xcb /app/vault443-ui-tests settingsVersionAndAutomaticVPNTab trayIconSizesAndStateColors trayStateOwnershipAndHiddenWindow connectionStagesCancellationAndRetry diagnosticsShowsFailureCacheAndProfileLogs pointerCursorsDoNotConsumeActionsOrTextInput >> /artifacts/x11-tests.log 2>&1
    else
        echo "Not requested: GUI runtime screenshot smoke only" > /artifacts/x11-tests.log
    fi
    # Weston receives a virtual input seat from our private Xvfb. Its clients
    # use native Wayland. A seatless headless backend crashes the Qt 6.4 native
    # text-input context, and would not represent a desktop compositor.
    weston --backend=x11 --renderer=pixman --socket=wayland-vault443 --idle-time=0 --width=1920 --height=1920 > /artifacts/weston.log 2>&1 &
    wpid=$!
    trap "kill $wpid $xpid 2>/dev/null || true" EXIT
    export WAYLAND_DISPLAY=wayland-vault443
    for i in $(seq 1 50); do test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" && break; sleep .1; done
    test -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY"
    QT_QPA_PLATFORM=wayland /app/vault443 --demo --scale 1 --screenshot /artifacts/wayland.png > /artifacts/wayland-gui.log 2>&1
    QT_QPA_PLATFORM=wayland /app/vault443 --demo --demo-screen vpn --screenshot /artifacts/wayland-vpn.png >> /artifacts/wayland-gui.log 2>&1
    QT_QPA_PLATFORM=wayland /app/vault443 --demo --demo-state stage-resolving_endpoint --screenshot /artifacts/wayland-connecting.png >> /artifacts/wayland-gui.log 2>&1
    QT_QPA_PLATFORM=wayland /app/vault443 --demo --demo-state retry-wait --screenshot /artifacts/wayland-retry.png >> /artifacts/wayland-gui.log 2>&1
    QT_QPA_PLATFORM=wayland /app/vault443 --demo --demo-state retry-wait --demo-screen diagnostics --screenshot /artifacts/wayland-diagnostics.png >> /artifacts/wayland-gui.log 2>&1
    if [ "$VAULT443_PLATFORM_RUN_TESTS" = 1 ]; then
        QT_QPA_PLATFORM=wayland /app/vault443-ui-tests > /artifacts/wayland-tests.log 2>&1
        QT_SCALE_FACTOR=2 QT_QPA_PLATFORM=wayland /app/vault443-ui-tests settingsVersionAndAutomaticVPNTab trayIconSizesAndStateColors trayStateOwnershipAndHiddenWindow connectionStagesCancellationAndRetry diagnosticsShowsFailureCacheAndProfileLogs pointerCursorsDoNotConsumeActionsOrTextInput >> /artifacts/wayland-tests.log 2>&1
    else
        echo "Not requested: GUI runtime screenshot smoke only" > /artifacts/wayland-tests.log
    fi
    kill "$wpid"
    wait "$wpid" 2>/dev/null || true
    kill "$xpid"
    wait "$xpid" 2>/dev/null || true
    cat /etc/os-release > /artifacts/runtime.txt
    dpkg-query -W "libqt6core6*" weston xvfb >> /artifacts/runtime.txt
    cat /artifacts/x11-tests.log /artifacts/wayland-tests.log
    '
