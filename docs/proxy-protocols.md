# Main Internet protocols — 1.3.1

Vault 443 runs one main Internet connection at a time: VLESS, Trojan or
Shadowsocks/Outline. Choosing another profile switches that tunnel. Work
OpenVPN/WireGuard/AmneziaWG sessions remain independent. Main session counters,
boot autoconnect, protection, logs and retry behavior apply to every main protocol.

| Import | Supported behavior |
| --- | --- |
| `trojan://` | Mandatory verified TLS; TCP/RAW, WebSocket, gRPC, XHTTP; password, SNI/peer, fingerprint, ALPN and validated transport options. |
| `ss://` | SIP002, Base64 user info or historical whole-configuration Base64; IPv4/IPv6 endpoints; percent-encoded passwords. Static Outline keys use the same parser. |
| AEAD | `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`. |
| SS2022 | `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`; validated Base64 key lengths and AES client key chains. |
| Lists / subscriptions | Mixed VLESS, Trojan and Shadowsocks; plain or Base64 text. Significant unknown parameters produce errors. |
| Dynamic Outline | `ssconf://` or an HTTPS URL in the explicit Outline import mode; response is an `ss://` link, JSON or YAML. |

Trojan-Go, Trojan REALITY/legacy flow, disabled TLS verification and external
Shadowsocks plugins are unsupported. Encryption is never silently substituted.

## Switching main profiles safely

While candidate B's source, endpoints and core configuration are prepared, the
confirmed connection A keeps serving traffic. A's card, journal and counters stay
associated with A. Only one main TUN exists: after preparation there can be a
brief protected interruption while it is replaced and B passes DNS/HTTPS checks.
The saved connection intent and `activeProfileId` change only after that succeeds.

Preparation failures leave A untouched. Later failures restore A's last working
configuration and preserve its logical traffic session, excluding B's probe
traffic. If restoration fails, protection remains armed and A is retried. A known
source denial is never bypassed using cached credentials. Failed B is not retried
automatically while A remains selected; its card offers **Retry**.

**Cancel** on B cancels the switch and preserves/restores A. **Disconnect** on A
or in the tray cancels both intentions and releases the main VPN only after
cleanup. Work VPNs remain independent. After a service crash, the persisted
confirmed profile is recovered; a pending candidate is never persisted early.

## Dynamic Outline and extended transports

Simple configurations use the pinned Xray 26.9.30 directly, including SS2022.
Extended profiles use the bundled `vault443-outline` adapter: Outline SDK
v0.1.0-rc1, its pinned WebSocket extension and dependencies. This supports split
TCP/UDP endpoints, prefixes, WebSocket endpoints, encrypted Shadowsocks chains
and `first-supported`. The latter selects the first understood configuration;
it is not network failover. Missing TCP/UDP directions are blocked. Extended
transports require AES-GCM or ChaCha20 AEAD; SS2022 and XChaCha20 combinations
are rejected explicitly. Prefixes must leave at least eight unpredictable salt
bytes (AES-128: at most eight prefix bytes; others: at most sixteen).

Direct transports, reporters, commands, plugins and arbitrary core JSON are
rejected. Imports are limited to 1 MiB, YAML depth 24 and 4096 expanded nodes,
chains/alternative lists to eight, and alternative selection to 256 complete configurations (plus a bounded traversal budget). TCP alternatives are explored before UDP, each in source order; selection checks the complete graph and final Xray/SDK capabilities. Thus direct SS2022 remains usable inside alternatives, while unsupported extended SS2022 is skipped. No remote YAML references are resolved.

A source keeps one profile ID even when its server or secret changes. Preparation
fetches once; confirmation stores the checked result and icon atomically. Updates
run before a new connection, manually, and daily. Automatic retries fetch at most
once a minute. A temporary failure retains the last verified configuration and
shows a warning. A provider expiry/quota/denial response blocks new cached
connections until a successful refresh. Active connections retain their immutable
configuration until reconnect. Invalid documents never replace the cache.

HTTPS downloads verify certificates, have bounded time/body/redirect limits,
and reject local, link-local and service destinations after resolution. During
protection, only root-owned marked sockets get temporary endpoint-specific
HTTPS permissions. Table 52789 and priorities 5098/5099 are dedicated to these
downloads; they do not overlap work routing. Permissions expire, close with the
request and are cleared during supervisor recovery. Source URLs and transport
credentials remain in private service storage. Provider error prose is reduced
to fixed safe categories before display.

The adapter inherits private TCP/UDP sockets and receives checked configuration
on stdin. Xray authenticates with fresh session credentials. A separate nftables
gate requires the service's socket mark, root ownership and service cgroup where
available, including UDP. Only outermost chain endpoints get physical transport
permissions; inner hops use their enclosing encrypted transport. Adapter failure
retains the traffic guard and triggers normal recovery. Xray continues to own TUN
and DNS. The Vision-specific UDP/443 rule applies only to VLESS Vision.

## Storage upgrade and rollback

The main store migrates v2 to v3 under the exclusive daemon lock. A synced,
root-only `state.v2.backup.json` is published before changing `state.json`.
Profile IDs, metadata, subscriptions, desired connection, boot selection and
journals are retained. The work store is unchanged. Unknown versions and
conflicting backups fail without overwriting the store. 1.2.1 cannot read v3.

Rollback restores the pre-upgrade main library; profiles or edits made after the
upgrade will not appear in 1.2.1. Keep a private copy of the complete current data
first. With the daemon stopped and its traffic guard left armed:

```sh
sudo systemctl stop vault443.service
# Run the still-installed 1.3.0 binary: expire temporary source routes, retain guards.
sudo vault443d --boot-guard
# Remove only the stopped private adapter gate, if Outline was used.
if sudo nft list table inet vault443_outline >/dev/null 2>&1; then
  sudo nft delete table inet vault443_outline
fi
sudo cp -a /var/lib/vault443 /var/lib/vault443-rollback-1.3.0
sudo install -o root -g root -m 600 /var/lib/vault443/state.v2.backup.json /var/lib/vault443/.restore-v2
sudo mv /var/lib/vault443/.restore-v2 /var/lib/vault443/state.json
sudo apt install --allow-downgrades ./vault443_1.2.1_amd64.deb
sudo systemctl start vault443.service
```

Choose a new backup destination if it already exists. Do not purge the package or
run `--release-network` as part of rollback. The old version cannot reconnect a
Trojan/SS/Outline profile; it restores the pre-upgrade VLESS selection. Retain the
v3 copy if you later return to 1.3.0. The installer never merges two stores.

Format references: [SIP002](https://shadowsocks.org/doc/sip002.html),
[Outline configuration](https://github.com/OutlineFoundation/outline-apps/blob/master/client/config.md).
