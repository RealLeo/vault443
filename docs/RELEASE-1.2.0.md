# Vault 443 1.2.0

WireGuard and AmneziaWG can now be imported and controlled alongside VLESS and
OpenVPN. Each connection has its own controls, private journal and diagnostics.
The compact 472 × 480 interface and English/Russian language switching remain.

- Import `.conf`, pasted configurations and autonomous Amnezia `vpn://` / `.vpn`
  client exports with per-profile emblems and duplicate review.
- WireGuard uses Linux's kernel. AmneziaWG is bundled as a foreground Go core
  pinned to v3.1.20260828, commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`.
- Multi-peer IPv4/IPv6, PSK, DNS, MTU and supported AWG settings through 3.1 are
  retained. The Peers tab shows endpoints, handshakes and protected networks.
- Healthy peers remain usable when another peer fails. Destination protection
  survives retry, engine crashes and service recovery. Work VPNs start manually;
  full tunnels pause VLESS, while specific work routes retain Docker precedence.
- Generic work D-Bus operations are additive. Existing APIs retain their
  contracts. Work schema v1 migrates to v2 with a durable private backup and
  unchanged OpenVPN IDs, settings, journal scope and rules.

The package includes the AWG source/toolchain lock, build manifest and dependency
licenses. Its private Go 1.25.14 toolchain does not replace system Go. Xray remains
the pinned 26.9.30 prerelease. ARM64 is a cross-build requiring hardware acceptance.

Amnezia Premium/Free API subscriptions, SSH/server administration, QR scanning,
server creation and configuration export are outside this release.

See [WireGuard behavior](wireguard.md), [migration](work-vpn.md#validation-and-installation)
and the [validation record](VALIDATION.md). Test credentials are generated in
isolated fixtures; no user endpoints or installed host VPNs are used.
