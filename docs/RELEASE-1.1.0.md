# Vault 443 1.1.0

Managed certificate-based OpenVPN work connections can now run alongside VLESS.
Import `.ovpn` files, select emblems, connect or cancel each profile independently,
and inspect per-profile stages, diagnostics and journals without routine sudo.

Work routes receive priority over overlapping Docker networks. A dedicated
Routes window provides explicit IP/CIDR and DNS-provider choices, including
conflicts between multiple work profiles. Full-tunnel work VPNs retain priority
and pause VLESS until those routes are released.

Work connections start manually, recover after interruptions, survive GUI closure,
and resume after a daemon restart in the same OS boot. Reboot does not autostart
them. Known destinations remain protected during recovery. Existing VLESS boot
settings, profile IDs, subscriptions, traffic counters and public D-Bus methods
are retained.

The runtime uses the distribution's OpenVPN 2.6+ package. Self-contained TUN
certificate profiles are supported; password/MFA/SSO, external key files, TAP,
user scripts and plugins are outside this release. Imported configuration is
validated data, never an arbitrary privileged command file.

The compact 472 × 480 interface and English/Russian localization are retained.
New tray actions distinguish work connections. Bottom-panel traffic is VLESS-only.
The pinned Xray 26.9.30 prerelease remains unchanged.

See [work VPN behavior](work-vpn.md), [D-Bus interfaces](interfaces.md) and
[validation](VALIDATION.md). ARM64 is cross-compiled and requires device testing.
