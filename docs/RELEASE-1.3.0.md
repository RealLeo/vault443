# Vault 443 1.3.0

Adds Trojan, Shadowsocks AEAD/2022 and dynamic Outline to the main Internet
connection selector. The compact 472 × 480 interface remains English/Russian.
OpenVPN, WireGuard and AmneziaWG keep their independent work sessions.

- Mixed link/file/subscription imports retain preview, duplicate detection and
  individual emblems. Trojan uses verified TLS; unsupported significant options
  fail explicitly.
- Outline HTTPS/ssconf sources retain stable IDs, checked caches and refresh
  status. Updates never silently restart an active connection.
- Extended Outline supports split TCP/UDP, prefixes, WebSocket, encrypted chains
  and first-supported using a pinned SDK adapter and private authenticated SOCKS.
- Only verified outer transport endpoints receive marked physical permissions.
  Missing directions and failed adapters remain under the traffic guard.
- Main store v2 migrates atomically to v3 with a private backup. Existing VLESS
  identities, subscriptions, boot selections and work data are preserved.
- Forwarded Internet replies retain their Docker/LAN return path when a work VPN advertises an overlapping subnet; tracked replies do not become a physical bypass.
- The stable forms, dropdowns and journal controls introduced in 1.2.1 remain.

Xray stays at upstream prerelease 26.9.30. The adapter uses Outline SDK
v0.1.0-rc1 and the separate pinned Go 1.25.14 toolchain; the supervisor toolchain
is unchanged. ARM64 is a cross-build, pending device acceptance.

See [protocol scope and rollback](proxy-protocols.md), [API additions](interfaces.md),
and [validation](VALIDATION.md). Packages are local build artifacts; this task
does not install, publish or push a release.
