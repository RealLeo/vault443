# Native tray transport checks

Run from the repository root:

```sh
bash scripts/test-tray-host.sh
```

The script builds the production `TrayController` and `Bridge` into a standalone
QtTest executable. It uses the already cached
`vault443-platform-smoke:24.04` Docker image, Xvfb and a nested Weston
compositor. Each run receives a fresh private session D-Bus. The container has no
network, no host bus mounts and no system service access. The bridge uses its
in-memory demo data; these tests never start or alter a VPN.

The host fixture is a separate process implementing the public
`org.kde.StatusNotifierWatcher` contract. The tray itself is Qt's native
`QSystemTrayIcon`, not a mocked presentation object. Tests read its exported
`org.kde.StatusNotifierItem` and `com.canonical.dbusmenu` objects and check:

- delayed appearance of the watcher and a registered host becoming ready later;
- all connection statuses and service/foreign-user states while no window exists;
- tooltip and icon change signals, actual badge pixels and 16/32/HiDPI pixmaps;
- the disabled status row and permission-sensitive Disconnect menu item;
- host disappearance, re-registration after restart and current state recovery;
- the host's D-Bus `Activate` action reaching the window-open signal.

The delayed-host case protects against Qt 6.4 caching a negative availability
result on its first tray query, as implemented in
[`isDBusTrayAvailable()`](https://github.com/qt/qtbase/blob/v6.4.2/src/gui/platform/unix/qgenericunixthemes.cpp#L68-L79).

The suite runs on X11 and native Wayland, with scale factors 1 and 2. Logs are
written under `test-results/tray-host/` (or `VAULT443_TRAY_ARTIFACTS`).

This validates the native Qt transport and host protocol. It does **not** run
GNOME Shell or its AppIndicator extension, and therefore does not replace a
manual GNOME panel appearance check. Ubuntu 26.04 needs a matching QtTest build;
the cached Ubuntu 24.04 test executable links against QtTest 6.4's private ABI.
