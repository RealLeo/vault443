# Validation

Current release: **Vault 443 1.3.1**. Credentials and certificates are synthetic;
network tests run in disposable containers with no external network. Development
does not change the installed application or workstation VPNs. ARM64 is a
cross-build, pending physical-device acceptance.

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
