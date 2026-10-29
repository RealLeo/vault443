# Validation

Current release: **Vault 443 1.1.0**. Tests use generated credentials and disposable,
network-isolated containers. The workstation's installed service, VPNs and network
were not switched. The user's real work profile was parsed read-only; its keys
were not copied into the source tree or test fixtures.

## Desktop and service

- English and Russian GUI suites on Ubuntu 24.04 / Qt 6.4.2 and Ubuntu 26.04 /
  Qt 6.10.2, X11 and Wayland, at 100/125/150/200%. Each full platform/language suite
  passes 43 cases; eight private-bus cases are deliberately skipped there and run
  separately. The same Qt 6.4 production executable is used on both distributions.
- Private D-Bus GUI suites: 10 passed in each language, including real work-import
  preparation/cancellation/confirmation, independent connect/cancel, route and DNS
  edits, diagnostics/logs and unchanged VLESS intent. Fixtures generate temporary
  certificate material and do not start network processes.
- Go race/vet, bounded concurrent import validation, private stores and UID
  ownership, independent retries/cancellation, same-boot intent, journal redaction
  and retained 1.0 D-Bus method signatures.
- Eight English demo README images regenerated with version, commands and SHA-256
  provenance in `docs/images/readme/manifest.json`.

## Network fixtures

The generated work fixture runs multiple certificate-authenticated OpenVPN servers
and the pinned real Xray core. A Docker-like bridge owns `192.168.96.0/20`, while
an OpenVPN server advertises `192.168.0.0/16` and serves `192.168.100.15`.

Coverage includes both startup orders, two independent work destinations,
work-without-VLESS, split DNS, explicit work/local route choices and conflicting
providers, configured and server-pushed full tunnels, VLESS pause/resume,
fail-closed cancellation, and recovery retaining only still-desired connections.
A client namespace exercises forwarded/masqueraded traffic and overlapping return
routes. IPv6 has an actually reachable physical control path; failed connections
must not escape through it. Kernel reverse-path filtering is not disabled.

Existing VLESS regressions pass on Ubuntu 24.04 and 26.04: TLS and REALITY/Vision,
browser HTTPS/HTTP2, IPv4/IPv6 fallback, DNS/DoH bootstrap and cancellation, process
failure, DNS and traffic protection, NetworkManager reporting and real session
traffic accounting. Kernel tests cover forwarded bootstrap isolation and the
packaged discovery capability/seccomp policy.

## Packages

Real systemd PID1 fixtures on Ubuntu 24.04 and 26.04 check clean installation,
1.0.1 → 1.1.0 upgrade during an active VLESS connection, continuous physical bypass
protection, reinstallation and purge. Existing multiuser profiles, subscriptions,
boot selection, GID and unrelated firewall state are retained. All prior public
D-Bus methods keep their signatures; OpenVPN methods are additive.

The installed hardened unit starts two work tunnels alongside VLESS using its
packaged event helper. Both recover after daemon SIGKILL and an orderly restart;
work destinations remain protected during the interruption. Private work profiles
and desired sessions survive unchanged. Removal clears only owned work/VLESS
network resources and retains private user data.

amd64 and ARM64 packages include checksums, the OpenVPN 2.6+ dependency and the
unchanged pinned Xray. ARM64 is cross-compiled; executable architecture and absence
of development-library RPATHs are checked.

## Limits

Container fixtures share the host kernel. They do not certify a physical GNOME
tray session, suspend/resume, power loss during boot, a real Pritunl deployment or
an ARM64 device. The real corporate server still needs a separate acceptance check
after installation; synthetic success does not verify its permissions or pushed
routes. Password/MFA/SSO, external key files and TAP are unsupported.

The Ubuntu 26.04 systemd fixture can report an unrelated netplan-configure failure
without udev; NetworkManager, resolved and D-Bus are checked explicitly. Xray is
still **26.9.30 (prerelease)**. Raw logs, generated keys, builds and test captures
remain ignored under `.cache/`, `build*/` and `test-results/`. Git index is preserved;
no commit, push or release publication is part of this work.
