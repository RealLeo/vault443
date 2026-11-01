# Validation

Current release: **Vault 443 1.2.1**. Tests use generated credentials in disposable,
network-isolated containers. The workstation's installed service, VPNs and network
are unchanged. Real client configurations are not used as fixtures or copied into
the repository. ARM64 is a cross-build, pending hardware acceptance.

## 1.2.1 GUI regression checks

A private D-Bus fixture emits state changes once a second and delays status,
import, journal and boot-setting replies. Tests hold the boot-profile popup open
for at least 15 seconds and observe control signals, not just final screenshots.
They check stable buttons and import labels, retained text/emblems/selection,
manual journal paging/clearing during polling, preserved scroll position, stale
errors and responses, and service disappearance/reappearance.

The update fixture exercises **1.2.0 → 1.2.1**, preserving VLESS and work schema v2,
profiles, requested connections and access rights. No protocol/network code or
public service API changed in this patch. The broader network matrix below
records the 1.2.0 baseline; the patch repeats the installed-package lifecycle in
isolated containers. Demo README image provenance remains explicitly 1.2.0.

## Desktop and service

- English/Russian GUI suites on Ubuntu 24.04 / Qt 6.4 and Ubuntu 26.04 / Qt 6.10,
  X11 and Wayland: 47 passing cases per full suite; twelve private-bus cases are
  skipped there and exercised separately. Focused layout checks cover
  100/125/150/200%, plus HiDPI captures.
- Private D-Bus GUI suites: 14 passing cases in each language, including native
  WireGuard and compressed autonomous Amnezia import, cancellation, duplicate
  review, peer details, independent controls, routes, diagnostics and logs.
- The Qt 6.4 production executable is smoke-tested on both distributions.
  Ubuntu 26.04's full QtTest suite uses a native Qt 6.10 test build because the
  private QtTest ABI is not portable between those versions.
- Go race/vet cover parser limits, duplicate/unknown fields, key validation,
  transport/version metadata, decompression limits, private stores and UID
  isolation, independent retries, same-boot recovery and journal sanitization.
- Work schema v1 migration creates a durable private backup, retains OpenVPN IDs
  and user metadata, and rejects incompatible or unsafe storage. Existing public
  D-Bus methods retain their signatures and OpenVPN-specific behavior.
- Ten English demo images have capture commands and SHA-256 provenance in
  `docs/images/readme/manifest.json`. Demo mode makes no network/service calls.

## WireGuard and AmneziaWG fixtures

Private servers exercise kernel WireGuard plus AmneziaWG legacy, 2.0/CPS and 3.1.
Each run generates fresh private keys and PSKs inside the container. The client
uses production runtime, routing, DNS and firewall code, with the pinned AWG
binary and actual Linux interfaces. Both Ubuntu 24.04 and 26.04 are exercised.

Coverage includes both VLESS startup orders, simultaneous protocols, working
without VLESS, IPv4/IPv6 endpoints and payloads, Docker-forwarded traffic, split
DNS, full-tunnel pause/resume, partial peer availability, and rejection of manual
routes outside AllowedIPs without damaging active traffic. A healthy specific
peer remains usable when a broader peer is offline. Tests also cover unavailable
endpoints, an incorrect PSK, cancellation, idle key renewal, established-peer
outage, AmneziaWG process death and retry. No connection is accepted solely
because its interface exists; a completed handshake is required.

The idle/outage test shortens only the synthetic AWG profile's rekey timers to
exercise renewal and recovery within a bounded test. Unit tests cover packet
checksums, longest-prefix peer selection, ownership validation, safe control
channels, MTU/transport limits, recovery metadata and secret-free status output.

## VLESS and OpenVPN regressions

The generated OpenVPN fixture advertises `192.168.0.0/16` while a Docker-like
bridge owns `192.168.96.0/20`; a private HTTP server uses `192.168.100.15`.
Checks cover both startup orders, independent destinations and DNS, manual
work/local choices, equal routes and two profiles sharing one transport endpoint,
server-pushed/configured full tunnels, fail-closed cancellation, IPv6 and
forwarded traffic, and retention of only still-requested connections on recovery.

Existing VLESS checks cover TLS and REALITY/Vision, browser HTTPS/HTTP2, IPv4/IPv6
fallback, DNS/DoH bootstrap and cancellation, process failure, DNS/traffic
protection, NetworkManager reporting and real session traffic accounting.
Kernel reverse-path filtering is not weakened by the fixtures.

## Packages

Real systemd PID1 fixtures use Ubuntu 24.04 and 26.04 with private cgroups,
NetworkManager and resolved. They check clean installation, an active
**1.2.0 → 1.2.1** upgrade, unchanged work schema v2, physical bypass protection,
reinstallation and purge. Multiuser profiles, subscriptions, boot selection,
operator GID and unrelated firewall state are retained.

The installed hardened unit runs OpenVPN, then WireGuard/AmneziaWG alongside
VLESS. It recovers after SIGKILL and orderly restart, including a kernel
WireGuard interface left by a dead daemon. Work destinations remain protected
while processes restart, and profile data is unchanged. Purge removes only
owned interfaces, routes and firewall state and retains private user data.

amd64 and ARM64 packages include checksums, the unchanged pinned Xray, the AWG
source/toolchain lock, build manifest and linked dependency licenses. Packaging
checks binary architecture, AWG provenance and absence of development RPATHs.
The separate Go 1.25.14 AWG toolchain does not replace the main service's Go build.

## Limits

Containers share the host kernel. These checks do not certify a physical GNOME
tray session, Wi-Fi roaming, suspend/resume, power loss during boot, a real
Pritunl deployment or ARM64 hardware. Corporate server permissions and provider
reachability require separate acceptance after installation. Password/MFA/SSO,
external OpenVPN credentials, TAP, Amnezia Premium/Free APIs, SSH administration,
QR scanning and server creation are outside the supported client scope.

Ubuntu 26.04's container can report a netplan-configure failure without udev;
NetworkManager, resolved and D-Bus are checked explicitly. Xray remains
**26.9.30 (prerelease)**. Raw reports, generated test keys, builds and captures
stay ignored under `.cache/`, `build*/` and `test-results/`. Nothing is staged,
committed, pushed, published or installed on the workstation by this task.
