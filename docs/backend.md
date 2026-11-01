# Service and profile behavior

Managed OpenVPN, WireGuard and AmneziaWG connections use the shared
[work coordinator](work-vpn.md) and independent lifecycle workers. WG/AWG import,
engines and peer behavior are described in [WireGuard support](wireguard.md).
Their work schema v2 migrates existing OpenVPN profiles with a private backup;
the separate VLESS v2 data and API remain intact.

The GUI talks to `org.vault443.Service1` on the system bus. Its wire contract
is in [interfaces.md](interfaces.md). JSON replies omit UUIDs, public keys,
subscription URLs, and original share links. The `Changed` signal has no payload.

The service authenticates each call using the unique D-Bus sender's Unix UID.
The UID must have an active local logind user session and membership of the
`vault443` group. Membership of `sudo` or `admin` additionally permits boot
profile selection and external VPN binding changes. Method arguments cannot
select or impersonate another UID. Each UID has an independent profile library.
Taking control of another user's active connection is an explicit operation.

Both packaged systemd units need `CAP_SYS_PTRACE` for kernel-gated reads of a
root OpenVPN process's `/proc/<pid>/exe` and `fdinfo`. Root UID alone is not enough
when the service has a smaller capability set than its peer. `ptrace`,
`process_vm_readv` and `process_vm_writev` syscalls are denied with `EPERM`;
`NoNewPrivileges` and the existing filesystem/network restrictions remain.
This is not a blanket read-only capability: the service still runs as a trusted
privileged supervisor. Discovery validates root ownership, executable and TUN
descriptor association; an interface name alone never grants a bypass.

diagnostics include `network.message`, the controller's safe state
description. Arming failures return that same reason to the owning GUI, without
exposing raw subprocess errors. Unrecognized tunnel errors include the interface
name when it passes the existing strict interface-name validation. Another user's
active session still yields only its generic state and busy flag.

## Supported imports

- `vless://UUID@host:port` links, a multiline list, or a Base64-encoded list.
- TCP/RAW, WebSocket, gRPC, and XHTTP; TLS and REALITY. REALITY with WebSocket is
  rejected. Vision flows require TCP.
- TLS SNI, selected uTLS fingerprints, ALPN; REALITY public key, short ID,
  spider path; WebSocket/XHTTP path and host; gRPC service name, authority, and
  `gun`/`multi`; XHTTP `auto`, `packet-up`, `stream-up`, and `stream-one` modes.
- A maximum of 1 MiB per import, 1024 profile entries, 16 KiB per link, and
  1024 stored profiles per user. Names contain at most 80 characters.
- the REALITY URI compatibility hint `support-x25519mlkem768=true`
  is accepted with Chrome, Firefox, Safari or the default Chrome fingerprint.
  Go boolean true aliases (including `1`) are accepted. The pinned uTLS presets
  already include the hybrid key share; the hint creates no extra Xray JSON
  setting and does not change the connection ID. False, invalid values, duplicate
  occurrences, TLS use, and fingerprints without verified native ML-KEM support
  fail with an explicit error instead of silently changing connection semantics.

Unknown, duplicated, insecure, or unsupported options are rejected with a
sanitized explanation. This includes unencrypted VLESS, `allowInsecure`, VLESS
Encryption, XHTTP `extra`, and full Xray/Clash JSON or YAML. No received document
is executed as root configuration. A canonical connection hash deduplicates
identical links, independently of their display names and parameter ordering.
Direct multiline import adds valid, unique rows and returns per-line errors.

Subscriptions use public HTTPS endpoints, valid certificates, bounded redirects,
20-second downloads, and the same 1 MiB decoded-body limit. DNS addresses are
checked immediately before dialing to reject private/link-local endpoints and
rebinding. A maximum of 32 subscriptions per user is supported. Mixed-protocol
sources are rejected in this version; use a provider's VLESS-only source.

Source updates run daily or on explicit request. Any invalid row prevents the
entire source replacement. Failed updates keep the previous library. Active and
boot-selected profiles are retained even when removed by the provider, and a
refresh never restarts a live connection. Removing a subscription detaches its
profiles so they remain available for manual management.

## Persistence and startup

The root-owned state directory is mode 0700. `state.json` is mode 0600, contains
per-UID libraries and desired/boot selections, and is replaced through a synced
temporary file and atomic rename. Unsafe permissions, symlinks, unknown schema
versions, and corruption fail closed. An OS file lock prevents simultaneous
daemon and maintenance writers. Secrets are available before desktop login, so
boot autoconnect does not depend on a user's unlocked keyring or home directory.

`--boot-guard` is the root pre-network stage: on a new system boot it arms
protection for the selected boot profile; on a daemon restart within the same
boot it arms only for an existing desired session. It does not contact D-Bus or
start Xray. This preserves a user's explicit disconnect across daemon restarts.
The normal daemon reconciles kernel link/address/route notifications after a
150 ms coalescing interval, retaining a two-second timer for retries and remote
health. Failed connection attempts use a capped exponential retry delay. Its
exit does not explicitly disarm the guard.

After stopping the daemon, root can run `vault443d --release-network`.
It clears desired/boot selections, preserves profile libraries, and asks the
network manager to remove only its own resources. Failure returns nonzero.
It refuses to run while the daemon's state lock is held.

## Verification without changing host networking

`vault443d --check` and `--dry-run` inspect paths without creating state,
opening D-Bus, or changing networking. `--check-profile` accepts bounded stdin
and prints only a redacted import preview.

Parser fuzz tests, storage transaction/permission tests, UID and session policy
tests, lifecycle tests, and subscription update tests use inert network fakes.
The IPC integration test starts a private D-Bus instance, checks its real peer
UID, sanitized signals, invalid extra arguments, and service reappearance.
It needs permission to create a local Unix socket; it does not use the system
bus or modify host networking.

For an optional GUI integration session, set `VAULT443_GUI_DBUS_ADDRESS_FILE` to a
new private file and run only `TestPrivateDBusGUIFixture`. Give the file's
contents to the GUI as `DBUS_SYSTEM_BUS_ADDRESS`. The fixture uses an inert
runtime and expires after five minutes. No test authentication bypass exists in
the production daemon.

The [isolated E2E runner](../tests/e2e/README.md) exercises real Xray, TUN,
systemd-resolved and nftables inside network-isolated Ubuntu containers, including
core/process death and persisted recovery. It never changes host networking.

## Metadata and connection history

`iconId` and `debugLogging` are user metadata outside the canonical connection
hash. Refreshing a subscription preserves them and the user-assigned name.
The current persistent schema is v2. Unsupported schema versions are rejected
without rewriting their files; there is no pre-1.0 conversion in this release.

Prepared imports are UID-owned, bounded in-memory drafts with a ten-minute
lifetime. The preview and commit use the same validated data, including a single
HTTPS fetch for the initial subscription. Commit rechecks duplicates and limits
against current storage, then saves profile icons and subscription metadata in
one transaction. A cancelled, expired or pre-restart draft cannot be committed.

Connection history lives in a separate private journal tree. A new immutable
session binds the initiating UID, profile ID and credential-redaction context
before starting Xray. Delayed output from an old child retains that identity.
Xray access logs are disabled; error output is captured at warning or opt-in
debug verbosity. Core pipes drain independently of journal disk writes, with
bounded line sizes and a bounded queue that records dropped-message counts.

History is retained for seven days, up to 10 MiB per profile and 50 MiB per UID,
removing oldest entries first. Log reads and clears authenticate ownership and
do not acquire the service's potentially slow network-operation mutex. Cursor
`tail` opens the newest page; `before:<id>` loads older entries and a numeric
cursor polls forwards. The GUI copies only the loaded records. Early boot guard
and explicit maintenance cleanup do not depend on journal availability.

## NetworkManager connectivity reporting

After a verified connection, the service reapplies only NetworkManager's
existing generated/volatile TUN profile. It verifies the live core, TUN kind,
interface, IPv4 address and prefix before doing so. A version-guarded Reapply
with `preserve-external-ip` registers a main-table IPv4 default via the TUN peer
and the existing TUN DNS / `~.` domain. Private policy tables, physical
connections and other VPN profiles remain separate. The main default is owned
by the ephemeral TUN; deleting the device removes it even after daemon death.

The networkManagerState/networkManagerMessage diagnostic fields describe the
integration (`inactive`, `pending`, `registered`, `unavailable`, `skipped`).
`registered` means the real probe is enabled on TUN, not a fabricated claim of
Internet access. NetworkManager reports the result of its own HTTP request.
No `CheckConnectivity` call delays the network worker; bounded D-Bus operations
are retried during reconciliation, at most once per five seconds. No bus is
opened for dry runs, early boot protection, or without a live core.

GNOME may choose a generic network symbol when TUN becomes the primary
connection. Physical Wi-Fi configuration is unchanged. The app neither disables
OS connectivity checks nor creates a firewall exception for them. If NM is
absent or refuses a user-managed tunnel, the VPN remains usable and protected.

## Vault 443 identity and traffic accounting

The product now uses `vault443` for its package, commands, operator group,
service units, private directories, and desktop resources. The system bus is
`org.vault443.Service1`, the TUN interface is `vault4430`, and the application
nftables table is `vault443`. Numeric routing tables, priorities and socket marks
remain stable across 1.x updates. Normal package upgrades retain profile IDs
and the requested/boot connection; they do not convert or merge pre-Vault stores. The documented work-schema
migration from 1.1.1 is separate from the unchanged VLESS store.

A service-owned sampler reads real kernel RX/TX counters once per second without
waiting for connection work. RX means downloaded IP bytes and TX uploaded IP
bytes on the owned TUN; outer VLESS transport overhead is excluded. Core epoch
and interface index identify counter resets and recreated devices. A final
observation is taken before an orderly stop; abrupt core death retains the last
successful sample. Rates use monotonic elapsed time rather than assuming a
perfect one-second interval.

The logical session starts on its first successful connection. Retries and
external-VPN pauses preserve its start and totals; pause/retry speed is zero.
A manual disconnect freezes the last duration and totals. New manual connection,
profile/owner changes and service/OS restarts reset them. Closing the GUI does
not reset anything. Counters are not written to disk and are visible only to
the owning UID. The GUI uses the `traffic` snapshot object rather than raw
interface lifetime counters.
