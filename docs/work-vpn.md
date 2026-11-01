# Managed work VPNs

Vault 443 manages OpenVPN, WireGuard and AmneziaWG clients alongside one main
Internet connection: VLESS, Trojan or Shadowsocks/Outline. The GUI remains
unprivileged. All protocols use the same authenticated local D-Bus caller and
`vault443` operator group.

## Import

Choose one or more `.ovpn`, `.conf` or `.vpn` files in the GUI, or paste a native
WG/AWG configuration or autonomous `vpn://` export. Their contents, not home-directory
paths, are sent to the service. Preparation is read-only, scoped to the calling
UID, and expires after ten minutes or a service restart. Confirmation atomically
stores the validated profiles and icon choices. Existing duplicates are retained.
Imports accept at most 32 files / 8 MiB JSON per batch and 1 MiB per file, with up
to 1024 work profiles per UID and a bounded 32 MiB private work store.

OpenVPN profiles must be self-contained TUN clients with certificate authentication and
inline CA, certificate and unencrypted private key. UDP and TCP clients, server
hostnames, multiple remotes, TLS authentication keys and the validated network,
keepalive and cryptographic options are supported. Certificate and key contents
are validated before storing. Names, icons and logging preferences do not affect
connection identity. `UV_ID` and `UV_NAME` metadata are private.

The parser rejects scripts, plugins, nested configuration, external files,
management overrides, server mode, TAP, password/MFA/SSO and unknown significant
options. `ignore-unknown-option` cannot bypass validation. The service generates
its own runtime configuration and fixed event handler. It does not execute the
user's original file as root.

## WireGuard and AmneziaWG

WG/AWG profiles use the same import preview, independent controls, journal,
route/DNS choices and ownership rules. Linux WireGuard is configured through
`wg`; AmneziaWG uses the bundled, pinned Go engine with a private Unix socket.
Neither backend runs `wg-quick` scripts. The Peers tab shows safe endpoint,
handshake and allowed-network details. Partial availability preserves healthy
peers while blocking unavailable destinations. See [WireGuard/AWG behavior](wireguard.md)
for supported parameters, import formats and handshake semantics.

## Lifecycle and protection

Up to 16 work profiles may run at once, with one owner for the complete active
connection set. Each has its own operation, cancellation, protected endpoint,
TUN and log session. Disconnecting the main VPN does not disconnect work profiles. Closing
the GUI does not disconnect either. Recovery waits 1, 2, 4, 8, 16, then 30 seconds
from the end of the failed attempt. Cancellation is persisted before stopping
the process; failed cleanup retains ownership and can be retried.

The daemon uses `/usr/sbin/openvpn` from the distribution package (2.6 or later).
Management and event sockets live in private runtime directories. User scripts
are never admitted; a fixed packaged handler supplies bounded interface, route
and DNS events to the supervisor. Network changes are serialized, while DNS,
handshake waits, retries and snapshot reads remain independent.

The coordinator receives numeric routes and DNS from authenticated events. With
`route-noexec`, OpenVPN does not export the server's `redirect-gateway` flags to
the event environment, so a narrow adapter reads only those flags from the same
child's private management stream before applying a full-tunnel policy. Raw
`PUSH_REPLY` data and authentication tokens are never written to journals. See
the upstream [management interface](https://openvpn.net/community-docs/management-interface/)
and [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/).

Work profile data and manual route/DNS rules live in schema-v2 `work-vpn.json` beside the
main schema-v3 store. Files are root-owned and private. Known work
prefixes remain blocked after unexpected tunnel or supervisor failure. A service
restart in the same OS boot restores the requested set; a new OS boot does not
autoconnect work profiles. Boot autoconnect selects one main Internet profile.

Explicitly disconnecting a work profile removes its owned policy and restores
the remaining routing choices. Unrelated Pritunl, NetworkManager and Docker
configuration is not rewritten. Journals use the same seven-day / 10 MiB per
profile / 50 MiB per UID limits; certificates, keys and known metadata secrets
are redacted.

## Overlapping networks

Effective order is explicit destination rules, work routes, ordinary local or
Docker routes, then main Internet routing. Transport and physical gateway paths
are handled independently. Work routes use their own policy-routing layer, so a
more-specific Docker route cannot accidentally win over a corporate prefix.
Owned tables 52783–52787 separate transport, manual, work, full-tunnel and local
reply routing. Replies to a Docker client use its actual connected bridge even
when the corporate destination overlaps that bridge's subnet.
Tables 52800–52831 contain only per-tunnel DNS host routes. Table 52832 provides
DNS reply validation with the kernel's normal reverse-path filtering. This lets two work
networks use the same resolver IP for different domains without sending queries
through the wrong tunnel; a failed provider keeps its DNS destinations blocked.
For example, a work route for `192.168.0.0/16` must reach a work server at
`192.168.100.15` even when a local Docker bridge owns `192.168.96.0/20`.

The Routes window shows the source and effective destination. Explicit rules
select a work profile, or an existing directly connected LAN/Docker destination.
They cannot allow arbitrary direct Internet traffic. A narrower rule overrides a
broader one. Equal prefixes from different work profiles retain the incumbent
and show a conflict until explicitly assigned. DNS rules select a provider for
a routing domain; unrelated DNS retains its current path. A full-tunnel provider
pauses the requested main connection; competing full tunnels require a choice.

The bottom counters show main VPN traffic only. A connected work tunnel
confirms tunnel setup and policy application; it does not prove authorization to
every corporate server or application port.

## Validation and installation

Version 1.2.0 migrates work schema v1 atomically, retaining OpenVPN IDs, metadata,
rules and requested sessions. A private `work-vpn.v1.backup.json` is durably
published before conversion. Unknown versions or conflicting backups are refused
without replacing data. This work migration is separate from the
[main store migration in 1.3.0](proxy-protocols.md#storage-upgrade-and-rollback). An older 1.1.x daemon
cannot read work schema v2; downgrade requires a deliberate offline restore of
the saved v1 work file after stopping/releasing managed connections. Keep the v2
file separately if newer WG/AWG profiles must be retained.

Use synthetic certificates in the opt-in, network-isolated
[E2E fixture](../tests/e2e/README.md). Never commit real exports, private keys or
local connection logs. Production corporate connectivity requires a separate
acceptance check with the organization's server; release tests do not connect
to the user's real work endpoint.

Install the release through APT so the system OpenVPN dependency is available.
The 1.3.1 package upgrade is validated from 1.3.0 and preserves profiles and access rights.
