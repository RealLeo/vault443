#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
target=${1:?Expected debian13, fedora44 or arch}
case "$target" in debian13|fedora44|arch) ;; *) exit 2;; esac
mkdir -p .cache/distro
python3 scripts/go.py test -c -o .cache/distro/gui-ipc.test ./internal/ipc
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --user 65534:65534 --mount "type=bind,src=$PWD,dst=/src,readonly" \
  -e HOME=/tmp -e LANG=C.UTF-8 -e VAULT443_SYSTEM_QT=1 \
  -e VAULT443_GUI_FIXTURE_BINARY=/src/.cache/distro/gui-ipc.test \
  -e "VAULT443_UI_TEST_BINARY=/src/.cache/distro/$target/build/vault443-ui-tests" \
  "vault443-linux-build:$target" bash -euc '
    for language in en ru; do
      LANGUAGE=$language bash scripts/test-gui-dbus.sh \
        realDBusPollingDoesNotBlinkOrClosePopup realDBusJournalActionsSupersedePolling \
        realDBusSwitchCancellationPreservesActiveProfile realDBusImportDialogWhenFixtureAvailable
    done
  '
