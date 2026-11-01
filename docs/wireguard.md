# WireGuard and AmneziaWG

Use Import to select `.conf` / `.vpn` files or paste native configuration text
or an autonomous Amnezia `vpn://` client export. Review profiles and choose
emblems before saving. Each profile starts manually without sudo, independent
of VLESS/OpenVPN. Closing the window does not disconnect it. Same-boot daemon
recovery restores requested connections; reboot does not autostart work profiles.

## Engines and configuration

Standard WireGuard uses the Linux kernel and distribution `wg`/`ip` tools.
AmneziaWG uses a separate foreground Go process shipped with Vault 443. Its
source commit, archive checksum and build toolchain are in
[amneziawg-lock.json](../packaging/amneziawg-lock.json). It supports legacy
parameters, 1.5 CPS, 2.0 ranges/padding and 3.x features through 3.1. No DKMS
module or third-party repository is required. Control sockets live privately
under `/run/vault443/amneziawg`; keys never appear in process arguments.

Native client profiles require `[Interface]` with PrivateKey and Address plus
one or more `[Peer]` sections with PublicKey, Endpoint and AllowedIPs. Optional
PSK, IPv4/IPv6 addresses, DNS servers/domains, ListenPort, MTU and persistent
keepalive are supported. The default MTU is 1280; explicit MTU is retained
subject to address-family and transport validation. Equal prefixes belonging
to different peers are ambiguous and rejected. More-specific prefixes retain
their own peer even if that peer is temporarily unavailable.

Hooks, external key paths, arbitrary FwMark/Table and SaveConfig=true are
unsupported. Table=auto and SaveConfig=false are accepted. Unknown meaningful
parameters produce an error with a line/field, never its secret value. Input is
bounded by existing work import limits, including after decompression.

Autonomous vpn:// exports are decoded locally using Base64 and Qt-compatible
compression; WG/AWG client containers become preview entries. No import contacts
Amnezia or a VPN server. Premium/Free API subscriptions, SSH/admin keys and
containers without a ready client configuration are unsupported. Export a
self-contained client `.conf` from Amnezia instead. QR scanning, server setup
and configuration export are not included.

## Status, routing and DNS

Connected requires an authenticated handshake followed by successful policy
installation. Bounded probes are sent only through the verified owned interface
while ordinary destinations remain closed. The Peers tab shows endpoint, last
successful handshake, state and AllowedIPs. An old handshake alone does not mean
failure: the service first requests an exchange. Partial profiles keep healthy
peers usable and block the other peers' destinations. A timeout means no
authenticated reply, not proof of an incorrect key.

AllowedIPs supplies route destinations. Manual rules and DNS addresses must fit
within their complete coverage; the application never expands cryptographic
routing silently. DNS domains select split-DNS zones. DNS servers without
domains request the root zone and use existing provider-conflict resolution.
Domain-only DNS settings without a server are rejected.

All managed protocols share the [work routing coordinator](work-vpn.md).
Specific work routes beat Docker; full tunnels pause VLESS. Failed peers,
engine crashes and supervisor recovery retain destination protection. Explicit
Disconnect releases the selected connection only. IPv4/IPv6 and Docker forwarded
traffic use the same guard. The bottom counters still measure VLESS only.

Owned interfaces carry service-generated names and ownership metadata. A kernel
WireGuard interface surviving daemon death is validated before reuse/removal.
Externally managed tunnels are never adopted merely by their name. Foreign
users cannot inspect private peers, operations or journals.

The tests generate credentials in isolated containers. Real server policy,
provider reachability, ARM64 hardware and physical sleep/network switching need
separate acceptance; see [validation](VALIDATION.md).
