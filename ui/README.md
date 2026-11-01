# Qt frontend

Vault 443 uses Qt 6.4+ Quick/QML, C++20 and embedded raster assets. The default
scale is 0.5: **472 × 480** logical pixels from the 944 × 960 artwork. Fonts,
colors, hit areas and textures scale together. The production GUI uses the
system D-Bus service; `--demo` uses fictional in-memory data and never calls it.

## Build and preview

```sh
bash scripts/build.sh
./build/vault443 --demo
./build/vault443 --demo --demo-screen settings
./build/vault443 --demo --demo-state large-traffic
./build/vault443 --demo --scale 1 --screenshot test-results/reference.png
python3 scripts/verify-skin.py test-results/reference.png
ctest --test-dir build --output-on-failure
bash scripts/test-gui-dbus.sh
```

Use `python3 scripts/capture-readme.py` to regenerate the English demo gallery and its checksum manifest. Create the screenshot output directory first. If using downloaded local Qt
libraries, source `scripts/qt-env.sh` before running binaries. Useful demo
screens: `main`, `import-preview`, `settings`, `subscriptions`, `vpn`, `profile`,
`logs`, `icons`, `combo`, `diagnostics`, `outline`. Use `--demo-state proxy` for the mixed main-profile gallery. States include `connecting`,
`reconnecting`, `paused_external`, `retry-wait`, `disconnecting`, `offline`,
`foreign`, `traffic-unavailable`, `large-traffic`, `empty`, `single`, and `many`.

## UI behavior

The lower CRT has three fixed-width groups on one line: elapsed session time,
current download/upload speed, and session download/upload totals. Values come
from the service's `traffic` snapshot. Unknown/foreign statistics show dashes;
closing the GUI does not reset accounting. Hovering a value shows its meaning
and unabridged byte amount. Very large values beyond JavaScript's exact integer
range are marked approximate in the tooltip.

Profile imports use PrepareImport → CommitImport, with per-profile icon choices.
Logs, diagnostics and connection requests have independent asynchronous state.
Connect/cancel/disconnect updates the profile's status immediately. Pointer
cursors do not intercept clicks or scrolling; keyboard focus remains visible.

The tray uses the embedded transparent vault-door emblem with a status badge.
Its tooltip/menu respects session ownership and service availability. Closing
the window leaves the service running; reopening the app raises its window.

## Language and user preferences

English source strings use `qsTr()`/`tr()` and the Russian TS/QM catalog is
embedded in the executable. `QQmlEngine::retranslate()` switches the open UI
without losing input or reconnecting. `QSettings` uses organization `Vault443`,
application `vault443`, key `ui/language` (`system`, `en`, `ru`). System language
uses the first supported `QLocale::system().uiLanguages()` entry, then English.
User profile names, addresses, logs and diagnostic JSON remain unchanged.

GUI autostart is `~/.config/autostart/vault443.desktop` (or XDG_CONFIG_HOME).
It is independent of the privileged system boot profile. No legacy preference
migration runs in this version. Tests and demo use temporary/nonpersistent
preferences.

## Assets and reproducibility

CMake lists runtime QML, PNG and font files explicitly. The resource set includes
Roboto Condensed Regular and Iosevka Term Medium. Font licenses/manifests remain
in `assets/fonts/`; licenses are installed with the package.

Source artwork, prompts and provenance live in `design/`. `scripts/extract-skin.py`
rebuilds the used skin slices; `scripts/prepare-profile-icons.py` rebuilds profile
emblems. The original concept is unchanged. Generated contact sheets go under
`test-results/artwork/`; `verify-skin.py` requires a fresh 1:1 screenshot rather
than an old saved UI image. Intentional English README screenshots live in
`docs/images/readme/`.

## Desktop and tray tests

```sh
bash scripts/test-release-ui.sh
bash scripts/test-tray-host.sh
```

The first runner uses an existing `vault443-platform-smoke:24.04` image, isolated
Xvfb/Weston and both languages at 100/125/150/200%. Configure the image, build
folder and artifacts with `VAULT443_UI_IMAGE`, `VAULT443_UI_BUILD_DIR` and
`VAULT443_UI_ARTIFACTS`. Build images with `scripts/Dockerfile.platform-smoke`.
QtTest binaries must match the runtime Qt version; the production Qt 6.4 binary
can be exercised separately on the newer runtime. Tray tests use a private
StatusNotifier host and D-Bus menu, including host restart and hidden windows.
All generated output belongs in ignored build/cache/test-results directories.

## Background refresh and request state

Snapshot polling and automatic journal reads never set the foreground busy flag.
Import preparation/commit, boot settings and manual journal actions each have a
separate pending state. The boot-profile list compares only IDs, names and order;
runtime and traffic changes do not replace the model. User selection stays local
until Apply succeeds, and a removed selection cannot be applied silently.

Journal reads use generation checks for both success and failure. Manual paging,
clearing and profile switches supersede earlier background replies; empty pages
produce no list update. Local journal errors preserve the last data and do not
open repeating modal dialogs. The private D-Bus GUI suite includes one-second
state signals, delayed replies, a 15-second popup check and read/clear races.
