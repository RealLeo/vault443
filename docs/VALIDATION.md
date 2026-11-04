# Validation

Current release: **Vault 443 1.3.4**. Credentials and certificates are synthetic;
network tests run in disposable containers with no external network. Development
does not change the installed application or workstation VPNs. This release ships
x86-64 packages only.

## 1.3.4 — compact left-side drag handles

- Three vertical brass dots fit the existing strip left of each emblem. Qt tests
  verify all three card variants, the 14×32 logical-pixel hit area, nonoverlapping
  emblem controls, three centered dots, and unchanged rendering on hover/press.
- Handle clicks retain the current focus; handles are excluded from Tab, have no
  tooltip, and Ctrl+arrow keys leave profile order unchanged. Emblems retain
  their properties action. Accessible names remain translated in EN/RU.
- Drag threshold, preview, insertion marker, cancellation, edge scrolling,
  persistent ordering, write errors and the permanent scrollbar retain the
  existing regression checks. The retained artwork matches a fresh scale-1
  screenshot; English demo screenshots and checksums are regenerated.

- X11/Xvfb and Wayland/Weston pass EN/RU at 100/125/150/200%. The full desktop
  suites pass **54 tests per language/platform**; native Debian/Fedora/Arch Qt
  EN/RU suites also pass. Private D-Bus suites pass **17 tests per language**,
  including polling during a drag, daemon/GUI restart, the 15-second open
  dropdown and nonblinking journal controls.
- Ubuntu 24.04/26.04, Debian 13, Fedora 44 and Arch containers pass
  **1.3.3 → 1.3.4**, connected reinstall, preserved profiles/preferences/permissions,
  guard continuity, packaged engine recovery and removal. Locked vulnerability
  checks pass for the service, Outline and standalone AmneziaWG.

Final documentation repacks retain the tested GUI and network-engine binaries.
Raw outputs belong in ignored `test-results/ui-1.3.4/`,
`test-results/linux-1.3.4/` and `.cache/ui134-*`.

## 1.3.3 — local profile ordering and permanent scrollbar

- The stable Qt model is checked with `QAbstractItemModelTester` and persistent
  indexes: mixed protocol order, row moves without resets, per-row rename,
  insertion/removal (including an empty library after restart), persistence, corrupt settings, isolated preferences,
  unwritable settings and nonpersistent demo mode.
- Qt mouse/keyboard tests cover a stationary click, drag threshold, drop-only
  commit, translucent preview, mixed work/main profiles, Ctrl+Up/Down focus,
  Escape, outside release, hidden window, lost grab and library deletion.
  Empty/single/three/twenty/hundred-profile lists, page clicks, thumb dragging,
  minimum hit/thumb dimensions and edge scrolling retain their controls.
- The private D-Bus test holds a drag across one-second runtime updates, checks
  that only read calls occur, restarts the test service and GUI, and confirms
  saved order and unchanged service-side order. EN/RU full private suites pass
  **17 tests each**, including the 15-second open dropdown and nonblinking logs.
- The retained artwork around the live scrollbar matches the fresh scale-1
  screenshot exactly. Tooltips handle overlay destruction during card recycling. README demo images and their checksum manifest are updated;
  no real user data is included. Vulnerability gates pass with locked Go 1.27.3.

- Xvfb X11 and Weston Wayland pass EN/RU at 100/125/150/200%, including
  gesture cancellation and scrollbar geometry. Both full desktop suites pass
  **53 tests each** (private D-Bus cases run separately). The Wayland test waits
  for the compositor to expose a reopened window before injecting a new drag.
- Ubuntu 24.04/26.04, Debian 13, Fedora 44 and Arch containers pass **1.3.2 → 1.3.3**,
  connected reinstall, preserved per-user preferences/data/permissions, guard
  continuity and removal. Packaged engines retain their isolated network/crash
  regressions. Debian/Fedora/Arch runtime-only installations and native Qt EN/RU
  suites pass; private D-Bus subsets pass **8 tests per language**.

Raw outputs belong in ignored `test-results/ui-1.3.3/`,
`test-results/linux-1.3.3/` and `.cache/ui133-*`.

## 1.3.2 — managed OpenVPN and NetworkManager

- Real OpenVPN + NetworkManager fixtures reproduce `LIMITED` without a main-table
  TUN default, then obtain `FULL` from an actual HTTP response over OpenVPN.
  Physical-interface HTTP remains blocked. The test does not set connectivity
  state or disable checks.
- Ubuntu 24.04/26.04, Debian 13, Fedora 44 and Arch: full/partial tunnels, competing
  full-route owners, selected gateway and DNS, unchanged-settings idempotence,
  NetworkManager restart, persistent-TUN outage, no false FULL/direct escape,
  same-boot supervisor reconstruction, changed address lease and reconnection,
  manual disconnect, both startup orders with the main VPN and its resume pass.
- Main VLESS NetworkManager regression passes on Ubuntu 24.04/26.04: HTTP/DNS,
  preserved physical profile, idempotence, NM restart, Xray SIGKILL, reconnection
  and manual cleanup.
- `go test -race ./...` passes, including private D-Bus, stale-result cancellation,
  serialized cleanup, selected-tunnel ownership and safe settings construction.
  Locked `govulncheck` passes for service, Outline and standalone AmneziaWG.
- Qt EN/RU suites pass in the Ubuntu, Debian, Fedora and Arch builds. Ubuntu's
  private D-Bus GUI suite passes in both languages (16 passed each), retaining
  the 15-second open-dropdown, polling, cancellation and journal checks.
- All five distro lifecycle containers pass **1.3.1 → 1.3.2**, connected reinstall,
  private data and permissions, guard continuity, packaged Outline/OpenVPN/WG/AWG
  crash recovery and removal. Runtime-only Debian/Fedora/Arch containers check
  fresh installation, installed EN/RU GUI and complete package contents.

Raw logs live in ignored `test-results/1.3.2/`, `test-results/linux-1.3.2/` and
`.cache/nm132-*`; packages and checksums are in `dist/linux/`. The Arch base image's
`NoExtract` documentation filter is disabled only inside its integrity-test
container so bundled documentation and licenses are checked. Network fixtures
replace Docker-inherited resolv.conf with the fixture DNS, avoiding host search
suffixes and external resolvers. The standalone resolved fixture uses its normal
service user/capabilities; HTTP fixture startup avoids reverse DNS, and DNS
listeners signal readiness before testing. None of this changes workstation settings.

These are isolated container results sharing the host kernel, not bare-metal
GNOME, Wi-Fi, boot/suspend, Fedora enforcing SELinux or firewalld certification.
The interface has no layout changes in 1.3.2; the broader desktop matrix below is
retained as **historical 1.3.1 evidence**, not represented as a new run.

## Historical 1.3.1 native x86-64 distribution packages

Packaging revision 1 of 1.3.1 adds Debian 13, Fedora 44 and Arch Linux alongside
the Ubuntu 24.04-baseline package (also exercised on 26.04). No engine pin,
profile schema or D-Bus method changes are involved. The only service behavior
change is recognition of `wheel` as an administrator group; enrollment and
active-local-session checks remain mandatory and pass Go race tests.

- Native Qt builds: Debian 13 **6.8.2**, Fedora 44 **6.11.2**, Arch **6.12.0**.
  Runtime-only containers install each native package and launch the installed
  EN/RU GUI without development packages. Native GUI suites pass in all three.
- Xvfb X11 and Weston Wayland: EN/RU, scale factors 1 / 1.25 / 1.5 / 2, compact
  layout and screenshots on each new distribution; all 48 combinations pass.
  Each platform/language full demo suite reports 49 passed and 14 intentionally
  skipped private-bus cases. The focused private D-Bus EN/RU suite separately
  checks a dropdown kept open for 15 seconds, non-blinking polling, journal
  actions, import and switch cancellation (7 cases per language).
- Real systemd PID1, private cgroups and network-none containers: Ubuntu 24.04,
  Ubuntu 26.04, Debian 13, Fedora 44 and Arch all pass initial install, reinstall
  while connected, profile/permission preservation and removal. Continuous
  physical-bypass monitoring remains blocked while the supervisor restarts.
- Each lifecycle run establishes a synthetic VLESS connection, exercises the
  packaged Outline adapter and protected source refresh, two OpenVPN work
  tunnels with a Docker-subnet overlap, and WireGuard/AmneziaWG. Process crashes
  preserve guards and reconnect. Removal releases application-owned firewall
  resources, retains unrelated rules/private data and leaves NetworkManager
  and systemd-resolved active.
- Fresh `govulncheck` reports pass for the service, Outline and standalone AWG;
  every format uses the shared compiler/manifest/architecture/RPATH gate.

These results do not establish physical boot/suspend behavior, GNOME tray-host
recovery, Fedora enforcing SELinux or firewalld policy compatibility. The host
kernel is Ubuntu's; distro kernels and bare-metal environments remain acceptance
work. The new ports are initial packages, not official distro repository builds.
An active reinstall exercises each native package manager's replacement hooks;
it is not a claim of upgrading from a previously released Fedora/Arch version.
No new ARM64 distro builds were requested. Logs and screenshots are ignored under
`test-results/linux-1.3.1/`; package provenance is alongside artifacts in
`dist/linux/`. See [package commands and prerequisites](linux-packages.md).

## Audit regressions

- Go race tests cover preparation failure, provider denial, post-cutover failure,
  save failure, successful commit, restoration failure/retry, same-boot recovery,
  stale/foreign cancellation, and the distinction between Cancel and Disconnect.
  The confirmed profile, desired intent, candidate failure and logical traffic
  session are checked independently. Periodic reconciliation cannot overwrite a
  completed candidate error with A's status.
- A real TUN fixture on Ubuntu 24.04/26.04 exercises source denial, bad TLS,
  failure after B passes health checks, cancellation before/after cutover,
  explicit disconnect and successful VLESS → Trojan switching. Preparation
  refusal preserves the actual TUN; rollback preserves the logical session.
  Fresh HTTP requests verify a proxy exit and reject a physical-interface bypass.
- Outline tests compare wrapped/unwrapped half-close, preserve both send/read
  directions through real TCP, deliver replies before EOF, exercise cancellation
  and deadlines, and reuse slots across 300 sequential connections.
- Parser tests cover direct and alternative SS2022, nested alternatives, TCP-first
  ordering, combinations requiring the SDK, unsupported extended SS2022, early
  success and the 256-complete-configuration bound.

## Compiler and vulnerability gate

Go **1.27.3** builds the supervisor, Outline adapter and AmneziaWG. Native and
ARM64 artifacts are checked with `go version -m` against the common lock; package
manifests record hashes and compiler provenance. System Go is unchanged; automatic
toolchain selection is disabled. Xray 26.9.30 remains the unchanged upstream
prerelease binary, with its independent compiler provenance and source pin.

`govulncheck v1.9.0` reports no reachable vulnerabilities in the supervisor,
Outline helper, or the standalone AmneziaWG executable with this compiler. AWG's
unshipped HTTP examples/SDK libraries produce findings under an upstream-wide
`./...` scan; they are absent from the standalone executable's dependency graph.
The release gate scans its actual `.` entry point. Required-but-unreachable module
findings are not presented as reachable executable vulnerabilities. Packaging
requires a passing report tied to the current source digest, at most 24 hours old.
Logs and reports remain in ignored `.cache/security`, never bundled as credentials
or private runtime data.

## Interface

Qt EN/RU suites and private D-Bus checks cover active A/candidate B cards, Retry,
CancelSwitch, tray identity, state/diagnostic responsiveness and preserved traffic.
Private tests also hold the boot-profile popup open for at least 15 seconds during
state polling, observe button enabled signals, and verify import and log actions
against delayed replies and service restarts. X11/Wayland checks use scales
100/125/150/200% on isolated Ubuntu 24.04 and 26.04 desktops. Ubuntu 26.04 QtTest
uses its native Qt 6.10 build; distributed packages retain the Qt 6.4 baseline.
English README screenshots use demo mode and temporary settings; capture commands
and checksums are recorded in `images/readme/manifest.json`.

## Protocol and package regressions

The network fixtures exercise VLESS TLS/REALITY, Trojan TCP/WebSocket/gRPC/XHTTP,
all supported Shadowsocks AEAD/2022 ciphers and AES-2022 key chains, plus Outline
split TCP/UDP, prefixes, WebSocket, encrypted chains and a TCP-only configuration.
They test DNS, TCP/UDP, IPv4/IPv6, HTTPS/HTTP2, unprivileged HTTP/3, helper/process
failure, physical bypass blocking and private adapter access restrictions.

Work fixtures cover OpenVPN, kernel WireGuard and AmneziaWG generations, both
startup orders with a main VPN, overlapping Docker networks, route/DNS conflicts,
manual direction, partial/full tunnels, cancellation, idle peers, failures and
same-boot recovery. Host and forwarded traffic use real kernel routing/firewall
rules inside the container. Real external Pritunl deployments remain a separate
acceptance task.

Package tests run real systemd PID1 with private cgroups on Ubuntu 24.04/26.04:
**1.3.0 → 1.3.1**, active main/work VPNs, boot intent, users/group membership,
unchanged main v3/work v2 stores, existing API signatures, reinstall, purge and
clean APT install. A concurrent direct-traffic probe checks the guard during
upgrade. Installed-package protocol and crash/recovery checks use synthetic keys.
The new `CancelSwitch` method is additive. The Ubuntu 26.04 PID1 container
already reports a failed `netplan-configure` unit before package installation;
NetworkManager, resolved and D-Bus remain active throughout. This is not a
physical-system boot acceptance test.

## Reproduce

Build as described in the README. Use cached isolated images prepared by the
E2E/platform scripts; do not run privileged fixtures on the host network.

```sh
python3 scripts/go.py test -race ./...
GOMODCACHE="$PWD/.cache/outline/modules" python3 scripts/go.py -C helpers/outline test -race ./...
python3 scripts/check-vulnerabilities.py
bash scripts/test-gui-dbus.sh
LANGUAGE=ru bash scripts/test-gui-dbus.sh
bash scripts/test-release-ui.sh
bash scripts/test-proxy.sh 24.04
bash scripts/test-proxy.sh 26.04
bash scripts/test-wireguard.sh 24.04
bash scripts/test-wireguard.sh 26.04
bash tests/package-systemd.sh 24.04
bash tests/package-systemd.sh 26.04
```

Detailed raw outputs live in ignored `test-results/1.3.1` and `.cache/v131`.
Containers share the host kernel. These tests do not certify physical GNOME tray
integration, Wi-Fi roaming, suspend/resume, power loss during boot, provider
availability, corporate server permissions or ARM64 hardware. They also do not
claim that unshipped upstream packages or the separately pinned Xray binary were
rebuilt or made vulnerability-free by upgrading the application's Go compiler.
