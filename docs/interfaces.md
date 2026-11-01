# Internal integration contract

System D-Bus name `org.vault443.Service1`, object `/org/vault443/Service1`, interface `org.vault443.Service1`.
Calls are asynchronous in the GUI. Structured replies are JSON UTF-8 strings, not arbitrary executable core configuration.

- `GetSnapshot() -> s`: caller's profiles (id/name/server/transport/security/iconId/debugLogging only), subscriptions (id/name/updatedAt only), runtime status, activeProfileId only when owned by caller, busyByOtherUser, bootProfileId for authorized caller.
- `PrepareImport(s source,s kind,s name) -> s`: kind is `text` (links, Base64 or GUI-read file contents) or `subscription` (HTTPS URL, validated name). Returns `{draftId,expiresAt,profiles:[{line,id,name,server,iconId,duplicate}],errors:[{line,message}]}`. `expiresAt` is Unix seconds. Draft is UID-bound, expires after ten minutes, and is invalid after a daemon restart. At most four drafts per UID and 64 total are held. No credentials are returned.
- `CommitImport(s draftId,s iconsJSON) -> s`: iconsJSON is an object mapping preview profile IDs to catalog icon IDs; omitted choices use the default antenna. Returns the final preview. The checked profiles and selected icons are saved in a single state transaction. Duplicates are rechecked against current state and never overwrite existing metadata. Subscription content is not fetched again; an invalid subscription is rejected as a whole. A text import can retain valid rows alongside errors. A successful commit consumes its draft; replay is rejected.
- `CancelImport(s draftId)`: discard only this caller's pending preview. No profiles or subscriptions are created by preparing or canceling.
- Legacy `PreviewImport(s text) -> s` and `ImportProfiles(s text) -> s` remain available with per-line results. New clients use prepare/commit for atomic icon selection.
- `RequestConnect(s profileId) -> s`, `RequestDisconnect() -> s`: return `{operationId}` after authorization and durable intent persistence; network work is queued on a single cancellable worker. Disconnect clears persistent intent before cancellation and retains the owner until cleanup completes. New requests supersede stale results; other users cannot see operation details or take the cleanup owner implicitly.
- `Connect(s profileId)`, `Disconnect()`, `TakeControl()`: compatible waiting wrappers over the same worker. An accepted asynchronous request lives with the daemon context, not the short D-Bus reply deadline.
- `RemoveProfile(s profileId)`, `RenameProfile(s profileId,s name)` (legacy).
- `UpdateProfile(s profileId,s name,s iconId)`: atomically update caller-owned name and catalog icon; icon is never a filesystem path.
- `SetProfileDebug(s profileId,b enabled)`: save the caller's debug preference. It applies at the next connection attempt, without restarting the current core process.
- `GetProfileLogs(s profileId,s cursor,i limit) -> s`: `{entries:[{id,time,level,message,sessionId}],nextCursor,previousCursor}`. `time` is RFC3339Nano and entries are chronological. Empty cursor starts from the oldest retained row; `tail` starts at the newest page. Pass numeric `nextCursor` to get subsequent pages or poll new records; on an empty forward result it remains unchanged. `previousCursor` uses `before:<id>` for loading older retained history. Default limit is 200, maximum 500; D-Bus `i` is signed int32. The GUI can bound its rendered history independently. Access checks use the authenticated caller's library even if another user has the same connection ID.
- `ClearProfileLogs(s profileId)`: clear the caller's history for this profile, including queued entries that predate the clear. New messages can appear afterward while the connection remains active.
- `AddSubscription(s url,s name) -> s`, `RefreshSubscriptions() -> s`.
- `RemoveSubscription(s id)`: remove this caller's source and detach its profiles; existing profiles and active/boot selections remain usable.
- `SetBootProfile(s profileId)` (empty disables; requires administrator policy).
- `GetDiagnostics() -> s`, `GetProfileDiagnostics(s profileId) -> s`: cached sanitized network/runtime observations, operation, lastFailure, capturedAt, profileCount and subscription diagnostics. The second validates the caller-owned profile and returns its last failure. Neither waits for the network worker. A foreign session returns only state/busyByOtherUser. No credentials or connection UUIDs are exposed. GUI deadline is three seconds, independently of other operations; a timeout shows the timestamped previous response or snapshot.
- `GetVPNCompatibility() -> s`: read-only `{busyByOtherUser,items:[{interface,manager,application,source,active,verified,fullIPv4,fullIPv6,message?}],message?}`. Source is `automatic`, `manual`, or `unknown`; routes are observed independently from verification, so `fullIPv4`/`fullIPv6` never grants a bypass to an unverified row. Missing manual interfaces are inactive and unverified. Discovery runs afresh while VLESS is disconnected, with a four-second deadline and one inspection in flight. Expected inspection errors are safe inline messages, not modal D-Bus errors. The query never calls connection/reconciliation operations, changes controller state, persists trust, or modifies routes, DNS, or firewall. Other users' active sessions return only `{busyByOtherUser:true,items:[],message:"Используется другим пользователем"}`; ownership is checked before and after discovery. No endpoint addresses, cgroups, configuration, process arguments, or credentials are returned. Callers cannot supply a UID.
- `SetVPNBinding(s json)`: explicit interface + manager binding for manual tunnels, admin only.
- `Changed()` signal contains no arguments/secrets; GUI refreshes its own snapshot.

Snapshot shape: `{profiles:[],subscriptions:[],runtime:{state,message,stage,stageStartedAt,failureCode,connectedAt,rxBytes,txBytes,guardArmed,externalVpns},operation?,lastFailure?,activeProfileId,busyByOtherUser,bootProfileId,canAdmin,traffic?}`.

`traffic` is `{sessionId,startedAt,durationSeconds,downloadBytes,uploadBytes,downloadBytesPerSecond,uploadBytesPerSecond,measuredAt,valid}`. Timestamps are Unix milliseconds; rates are bytes per second and may be fractional. The object is omitted for a foreign owner. Before the first successful connection it contains valid zero totals and no session identity. Connected measurements older than three seconds are invalid; unavailable readings never masquerade as reliable zeros. Paused/retry states retain confirmed totals and elapsed session time with zero speed. A completed manual disconnect freezes the last values for its owner. A new manual connection, profile/owner switch or daemon restart clears them. Existing `runtime.rxBytes`, `runtime.txBytes` and `runtime.connectedAt` remain available for compatibility but are not the logical-session accounting source.

`operation` is `{id,action,profileId,stage,stageStartedAt,attempt,nextRetryAt?}`; `action` is connect/disconnect. `stageStartedAt` and `nextRetryAt` are Unix milliseconds. Stages: requested, checking_vpn, enabling_guard, resolving_endpoint, starting_core, configuring_network, checking_connection, retry_wait, connected, paused_external, restoring_network, cleanup_failed, disconnected. A failed cleanup keeps its owner and permits an explicit retry of Disconnect. Retry delays are 1,2,4,8,16,30 seconds, measured from completion of each failed attempt.

`lastFailure` is `{profileId,time,code,message}`, with Unix millisecond time. It is independent of the current stage: retries and Disconnect preserve it. During a session the snapshot prefers that profile's error; without a session it returns the caller's latest error. Recovery reads structured failureCode/failureTime journal metadata within the existing retention window and supports prior unstructured error entries. Profile/UID ownership comes from the journal scope; secret redaction applies to message text, not identity or machine metadata. Clearing a profile journal clears its corresponding cached historical failure. Foreign sessions expose neither operation nor lastFailure.
States: disconnected, connecting, connected, reconnecting, disconnecting, paused_external, error.

`connected` requires verified HTTPS through a fresh TUN-bound host
TCP socket, in addition to DNS. A DNS-only success is insufficient. New safe
failure codes retained by both runtime and seven-day journal are
`vpn_dns_failed`, `vpn_https_timeout`, `vpn_https_tls`, `vpn_https_response`, and
`vpn_https_failed`. HTTPS probes never use the bootstrap physical exception,
environment proxies or redirects, and respect operation cancellation.

the network diagnostics include `ipv6State` and `ipv6Message`.
States are `inactive`, `checking`, `available`, `unavailable`. IPv6 availability
belongs to one core session, not to the persisted profile. Unavailable IPv6 does
not change a working IPv4 connection's `connected` state; ordinary IPv6 sockets
are rejected before entering TUN so clients can choose IPv4. The daemon checks
IPv6 HTTPS with a four-second total budget before enabling it and at the normal
health-check cadence while available. Once unavailable, it is retried only on
the next connection. Local/corporate IPv6 routes are independent of this gate.

Network runtime contract (`internal/network`): `New(Config) *Manager`, `Connect(context.Context,model.Profile) error`, `Disconnect(context.Context) error`, `Reconcile(context.Context) error`, `Status() model.RuntimeStatus`, `Arm(context.Context) error`, `SetVPNBinding(context.Context,string) error`, `Diagnostics(context.Context) interface{}`. The optional `Watch(context.Context) (<-chan struct{},error)` supplies coalesced kernel network notifications; the daemon disables closed channels and retains timer reconciliation if subscribing fails.
`Config` must support `StateDir`, `RuntimeDir`, `XrayPath`, `DryRun bool`. Constructor has no side effects. Only live Connect/Arm changes networking, never tests or UI preview.
Daemon owns user authorization, desired session owner/profile persistence, subscriptions and retries. Network owns Xray and all owned route/DNS/firewall resources. Reconcile keeps protection after crash and external VPN takeover. Explicit Disconnect is the only ordinary operation disarming protection.

The optional network `SetLogSession(*journal.Session)` binds callbacks to an immutable UID, profile and session identity before starting a core process. Old output retains the old identity after a profile/user switch. `service.New(store,runtime,journal)` accepts the persistent journal, with the two-argument form retained for fixtures. Producers sanitize and enqueue without blocking; the journal worker handles private persistence and oldest-first rotation. Read/clear avoid the service network-operation mutex. Journal polling contains neither another user's records nor raw core credentials; access logs remain disabled. Warning is the default Xray level, debug is opt-in.

State schema version 2 adds `iconId` and `debugLogging` as display/diagnostic metadata, excluded from the canonical connection identity. Only schema v2 is supported; older or unknown versions are refused without writing to the document. Subscription refresh preserves user-selected name, icon and debug mode; new nodes start with antenna and debug disabled. History lives separately in the private `journal/` directory, retained for seven days with 10 MiB/profile and 50 MiB/UID limits. Early boot protection and root maintenance cleanup do not require the journal to open, so damaged history cannot block those operations. Normal daemon initialization resolves boot/restart intent before exposing mutable D-Bus calls.

Network progress is published via optional `SetProgressHandler(func(model.RuntimeStatus))`.
The callback receives a copy and performs no network calls. The service rejects
canceled-generation updates. Manager status and diagnostic reads use immutable
published snapshots, while mutations are serialized by the service worker.

The optional network traffic interface exposes `TrafficCounters() model.TUNCounters`
without taking the network mutation lock. It validates the owned core epoch and
interface index around sysfs RX/TX reads. `SetTrafficHandler` provides a final
observation before orderly core shutdown. The service samples independently once
per second, calculates deltas using Go’s monotonic time, and rejects late
observations from superseded operations. The accounting state is memory-only.

## Managed OpenVPN additions (1.1.0)

Existing methods and VLESS `profiles`, `runtime`, `operation`, and `traffic`
semantics are retained. `GetSnapshot` additionally returns `workProfiles`, private
to the caller. Each row contains `id,name,iconId,debugLogging,kind:"openvpn",server,
transport,runtime,operation?,lastFailure?`. Operations have the existing shape
and independent IDs. `busyByOtherUser` covers the complete active connection set;
foreign session metadata is never returned. A prepared client with no work
profiles continues to use the 1.0 API unchanged.

Additional methods on `org.vault443.Service1`:

| Method | Result / behavior |
| --- | --- |
| `PrepareOpenVPNImport(s filesJSON) → s` | Input `[{name,content}]`; private ten-minute draft. Reply `{draftId,expiresAt,profiles:[{id,name,iconId,duplicate,server,transport}],errors:[{line,message}]}`. Contains no certificates or key material. |
| `CommitOpenVPNImport(s draftId,s iconsJSON) → s` | Atomically add valid nonduplicate profiles with icon choices. Does not reread files. |
| `CancelOpenVPNImport(s draftId)` | Discard this caller's draft. |
| `UpdateOpenVPNProfile(s id,s name,s iconId)` | Edit private display metadata. |
| `RemoveOpenVPNProfile(s id)` | Requires disconnection and removal of referencing route/DNS rules. |
| `SetOpenVPNDebug(s id,b enabled)` | Applies to a subsequent connection, without restarting an active process. |
| `RequestOpenVPNConnect(s id) → s` | Accept `{operationId}` immediately; independent cancellable work actor. |
| `RequestOpenVPNDisconnect(s id) → s` | Persist cancellation before cleanup; leave other profiles running. |
| `GetOpenVPNDiagnostics(s id) → s` | Cached runtime, operation, last failure, routes and capture timestamp. |
| `GetOpenVPNLogs(s id,s cursor,i limit) → s` | Existing private journal paging format and retention limits. |
| `ClearOpenVPNLogs(s id)` | Clear only the caller's selected work journal. |
| `GetWorkRoutes() → s` | `{items,rules,dnsRules,profiles,busyByOtherUser,message?}`. Read-only. Items identify CIDR or DNS domain, source, target, interface, state and conflicts. |
| `SetWorkRoute(s cidr,s target)` | Canonical IP/CIDR to owned work profile ID or `local`; local requires a connected subnet. |
| `RemoveWorkRoute(s id)` | Restore automatic routing for this destination. |
| `SetWorkDNS(s domain,s target)` | Canonical DNS routing zone to an owned work profile; `.` identifies the full DNS namespace. |
| `RemoveWorkDNS(s id)` | Restore automatic DNS provider selection. |

Work state uses a separate versioned private `work-vpn.json`; VLESS schema v2
and its IDs are unchanged. Canonical work IDs have the `ovpn-` prefix and exclude
name/icon/logging metadata. No public method accepts executable paths, scripts,
UIDs or arbitrary privileged configuration. `Changed()` remains payload-free.

## Generic work protocols (1.2.0)

The existing `workProfiles` array now reports `kind` as `openvpn`, `wireguard`
or `amneziawg`. Its runtime additionally contains `peers`, each with
`id,endpoint,state,lastHandshakeAt?,allowedIPs`. Peer IDs are stable fingerprints,
handshake times are Unix seconds, and private/PSK/header-protection keys are never
returned. Configured peers remain visible while disconnected. `partial` means
some peers are connected while the remaining destinations stay protected.
New stages include `creating_interface`, `exchanging_keys` and `partial`.

General operations use the same input/result shapes and authorization as their
OpenVPN equivalents:

| Method | Behavior |
| --- | --- |
| `PrepareWorkImport(s filesJSON) → s` | Content-based OpenVPN/WG/AWG/autonomous-Amnezia validation; entries additionally contain `kind`. No network access. |
| `CommitWorkImport(s draftId,s iconsJSON) → s` / `CancelWorkImport(s draftId)` | Atomic UID-owned ten-minute draft confirmation/cancellation. |
| `UpdateWorkProfile(s id,s name,s iconId)` / `RemoveWorkProfile(s id)` | Metadata and removal for any work type. |
| `SetWorkDebug(s id,b enabled)` | Apply logging preference on the next attempt. |
| `RequestWorkConnect(s id) → s` / `RequestWorkDisconnect(s id) → s` | Immediate accepted operation; existing work owner/limit/cancellation rules. |
| `GetWorkDiagnostics(s id) → s` | Cached operation/failure/runtime including safe peers. |
| `GetWorkLogs(s id,s cursor,i limit) → s` / `ClearWorkLogs(s id)` | Existing journal pagination, privacy and retention. |

Old OpenVPN methods remain compatible and reject non-OpenVPN IDs/drafts. The
existing route/DNS methods accept the new work profile IDs, validating that WG/AWG
targets cover the requested network/DNS destinations in AllowedIPs. VLESS API,
boot selection and traffic-counter semantics are unchanged.

Work schema v2 adds the protocol discriminator and typed WireGuard payload.
Schema-v1 migration durably publishes `work-vpn.v1.backup.json` before atomic
replacement, retaining old IDs/rules/intent. The separate network recovery record
retains protocol ownership metadata and protected peer routes; secrets are not
stored there. Unknown schemas are refused without overwriting them.
