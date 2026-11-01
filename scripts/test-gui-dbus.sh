#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${VAULT443_SYSTEM_QT:-0}" != 1 ]; then source scripts/qt-env.sh; fi
export GOMODCACHE="$PWD/.cache/go-mod" GOCACHE="$PWD/.cache/go-build"
fixture_binary=${VAULT443_GUI_FIXTURE_BINARY:-.cache/gui-ipc.test}
if [ -z "${VAULT443_GUI_FIXTURE_BINARY:-}" ]; then
    python3 scripts/go.py test -c -o "$fixture_binary" ./internal/ipc
fi
fixture_dir=$(mktemp -d)
fixture_pid=
cleanup() {
    rm -f "$fixture_dir/address"
    if [ -n "$fixture_pid" ]; then wait "$fixture_pid" || true; fi
    rm -rf "$fixture_dir"
}
trap cleanup EXIT
VAULT443_GUI_DBUS_ADDRESS_FILE="$fixture_dir/address" "$fixture_binary" \
    -test.run '^TestPrivateDBusGUIFixture$' -test.v > "$fixture_dir/fixture.log" 2>&1 &
fixture_pid=$!
for ((i=0; i<100; i++)); do
    test ! -s "$fixture_dir/address" || break
    if ! kill -0 "$fixture_pid" 2>/dev/null; then cat "$fixture_dir/fixture.log"; exit 1; fi
    sleep .1
done
test -s "$fixture_dir/address"
export DBUS_SYSTEM_BUS_ADDRESS="$(cat "$fixture_dir/address")"
export VAULT443_UI_PRIVATE_BUS_TEST=1 QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software
export VAULT443_UI_OPENVPN_FILE="$fixture_dir/address.ovpn"
export VAULT443_UI_OPENVPN_BLOCKED_FILE="$fixture_dir/address.blocked.ovpn"
if [ "$#" = 0 ]; then
    set -- realDBusSwitchCancellationPreservesActiveProfile realDBusProxyImportsAndOutlineRefresh realDBusPollingDoesNotBlinkOrClosePopup realDBusJournalActionsSupersedePolling realDBusScopedRequestsResetAndIgnoreOldReplies realDBusImportDialogWhenFixtureAvailable realDBusRoundTripWhenFixtureAvailable realDBusCompatibilityWhenFixtureAvailable realDBusResponsiveConnectionWhenFixtureAvailable realDBusDiagnosticsDeadlineWhenFixtureAvailable realDBusLanguageSwitchPreservesDraftWithoutMutations realDBusOpenVPNImportControlAndRoutesWhenFixtureAvailable realDBusWireGuardAndAmneziaImportWhenFixtureAvailable
fi
"${VAULT443_UI_TEST_BINARY:-build/vault443-ui-tests}" "$@"
rm "$fixture_dir/address"
wait "$fixture_pid"
fixture_pid=
cat "$fixture_dir/fixture.log"
