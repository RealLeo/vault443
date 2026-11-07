# R6 native acceptance controllers

These are QA scripts for the explicitly provisioned `vault443-win10` and
`vault443-win11` VirtualBox guests. They are external test provenance, added after
R6 was frozen: they do not change its installer, binaries, manifest or source ZIP.
The historical failed boot rearm experiment is intentionally excluded.

| R6 identity | SHA-256 |
| --- | --- |
| Installer | `0cd92b64b464b7b429be85691ba2fac0008f72fb673c6d53642872f703e5a3cb` |
| Installed `build-manifest.json` | `392faa05130ab32278b4d64cec0f51e452fc947f412b1841fcfa517dc2766ee7` |
| `vault443d.exe` | `9cedea599af02f8afe3434f2b7a56aa167075be4cd7ced21ef3dea924140bf25` |
| `vault443.exe` | `53bc41422de5c1940a3e486c7d5a6442a2074d94fc22f8d33cfef91e5eb140df` |
| Frozen source ZIP | `07043a2d106bfc9a783858ed2a4a0f63c82cb6bc5753eda0db2b53b6b5efd1f2` |

Use Windows PowerShell 5.1, the ordinary **active local console** account for
full/work/fault/UI controllers, and explicit same-controller UAC only for boot
setup. Guest Control login credentials do not switch the active console. Never
print private fixture profiles, keys, subscription URLs or passwords.

## Stage once

The existing reviewed `qa-bootstrap.ps1` must already have installed the fixed
SYSTEM tasks and protected `C:\Program Files\Vault443QA` (`$q` below), including
`qa-runner.ps1`, `main-matrix.ps1`, `work-smoke.ps1`, `openvpn-smoke.ps1`, the exact
R6 installer and fixture CA. Its private marker/config remain under
`C:\ProgramData\Vault443-QA`. Do not weaken these ACLs or add a generic task action.

Copy the five `r6-*.ps1` controllers to `C:\Users\Public\Vault443Exchange` (`$x`).
Stage `ui-native-smoke.ps1` and `set-display-scale.ps1` under
`C:\Users\Public\qa-source-r6`; their pinned hashes are respectively
`a54331cd56fc5e7b1af326a3fb61e9ba000191a6f269c8c5e7c0a423b2615cc3` and
`3fd5dc99abd1b9b2cf096e4df3ce59e3da7dacbddd4d6f1a5553607fdb06c7f1`.
The protected main matrix hash is
`fc633896542f0e00fa452fca180c5dc473339b2309779b0def2dedf398e999e8`.

The isolated Linux fixture already generates the inputs below. Transfer them
privately to `$x` with the same basename; do not regenerate credentials during a
running acceptance sequence.

| Fixture source | Guest input |
| --- | --- |
| `/home/vaultfixture/main-profiles.json` | `main-profiles.json` |
| `/home/vaultfixture/wireguard/wireguard-multi-import.json` | `wireguard-multi-import.json` |
| `/home/vaultfixture/wireguard/amneziawg-import.json` | `amneziawg-import.json` |
| `/home/vaultfixture/wireguard/wireguard-full-import.json` | `wireguard-full-import.json` |
| `/home/vaultfixture/openvpn-import.json` | `openvpn-import.json` |
| `/home/vaultfixture/openvpn-full-import.json` | `openvpn-full-import.json` |

Parse each controller on the guest before execution:

```powershell
$q='C:\Program Files\Vault443QA'; $x='C:\Users\Public\Vault443Exchange'
$t=$null; $e=$null
[void][Management.Automation.Language.Parser]::ParseFile("$x\r6-full-work.ps1",[ref]$t,[ref]$e)
if($e.Count){throw 'Native PS5 parser rejected controller'}
```

## Full work and service/network faults

Prerequisite: current own VLESS is connected with guard armed; exactly
`Vault443 Fixture wireguard-multi`, `amneziawg` and `openvpn` are connected.
The existing main matrix must have produced
`$x\r6-protocols\main\state.json`, including a verified positive physical
baseline and the current own VLESS ID. On a fresh fixture, run main `-Phase all`
then `-Phase connect -Protocol vless` with that `-OutputDirectory`, and the work
smoke `-Phase begin`/`-Phase verify` for those three profiles.

```powershell
powershell.exe -NoProfile -File "$x\r6-full-work.ps1"
powershell.exe -NoProfile -File "$x\r6-service-faults.ps1"
```

Require `passed=true`, `restored=true`, `completed=true` in respectively
`$x\r6-full-work\result.json` and `$x\r6-service-faults\result.json`.
Full WG replaces WG multi while testing; full OpenVPN replaces split OpenVPN.
The variants share credentials/server sessions and must not run concurrently.
The controllers restore the original work connections in `finally`.
Fault tasks are fixed SYSTEM actions with fresh protected reports and
`LastTaskResult=0`; explicit stop checks SCM absence throughout all 13 probes.
A crash may recover before probes and is reported with that limitation.

## Pre-service reboot: a fresh, untested boot fixture only

Do not repeat the temporary-Manual test after it has passed. First pin the own
VLESS boot profile through the existing UAC access helper/UI and verify its
ordinary `bootProfileId` readback. Keep its guard armed. Capture the eight
positive physical endpoint checks before arming, and start fixture packet capture
before the actual reboot; retain the matching UTC interval and pcap separately.

The setup intentionally reads this fixed source filename, so copy the promoted
wrapper **with the required rename**:

```powershell
Copy-Item "$x\r6-boot-startup.ps1" "$x\vault443-r6-boot-startup.ps1"
Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList ('-NoProfile -File "'+$x+'\r6-boot-setup.ps1"')
```

Setup performs no reboot. It pins the wrapper bytes, R6 identities, controller,
physical GUID/MAC, exact preferred addresses and original Automatic/delayed flag,
then creates only `Vault443-QA-r6-prescm` and temporarily makes Vault443 Manual.
Root performs a real reboot. The protected startup wrapper requires BFE and both
physical default gateways, SCM stopped/PID zero/no engines before and throughout
13 existing probes. A lost window is inconclusive. Its `finally` restores the
original SCM configuration, starts only Vault443 and removes only its owned task.
Inspect `$q\reports\r6-boot\result.json`: require 13 passed checks,
`restored=true`, `taskRemoved=true`; retain the private ownership journal.

A cold boot may renumber the physical interface. Match its recorded **GUID/MAC**,
not its old ifIndex. The boot wrapper compares address identity after removing
only numeric `%zone` suffixes from both lists, but writes the actual current
scoped addresses/new ifIndex to the protected helper state. Before ordinary
postboot recovery, archive any stale `$x\r6-protocols\main\state.json` and rebind
only its baseline index/addresses after the same GUID/MAC, normalized address
identity and Preferred states have been verified; keep profile IDs unchanged.

Run ordinary main `-Phase recovery -Protocol vless -Fault service-killed` against
`$x\r6-protocols\main` and require 23 checks, then verify the work connections.
Record actual saved-work behavior: Win11 R6 restored all three work connections
without a new RequestConnect; do not assume reboot clears them.
A **separate normal Automatic reboot**, with no Manual setup/task or service/connect
requests after boot, must prove boot-profile recovery, work behavior, HKCU Run
startup, one new ordinary-user GUI PID/session and real main/work traffic.
The pre-service test does not isolate boot-time filter execution before BFE.

## Six real UI cases

Start with the GUI closed using its normal quit action, with active VPNs, one
monitor and sufficient display resolution to expose real 200%. Run in MTA:

```powershell
powershell.exe -MTA -NoProfile -File "$x\r6-ui-matrix.ps1"
```

This runs EN and RU at actual OS 100/150/200%, `QT_SCALE_FACTOR=1`, with the
existing native fixture AppScale preference `0.5`; it checks HWND
DPI 96/144/192, close-to-tray, same-instance reopen and quit with service state
unchanged. Reports are under `$x\r6-ui`; require six passed cases in
`controller-result.json`. It uses freshly enumerated protected Settings HWNDs.
Before final 150% restoration, RU/200 status and reopen PNGs are preserved under
`r6-ui\ru200-at200`. `-LeaveScale200` keeps 200% instead. Desktop-pixel captures
can include occlusion; review separate VM screenshots too. The combined six-case
controller and PNG preservation are the small follow-up to the native-passed R2
UI workflow; its next complete Win10 rerun is separate evidence.

## Partial WireGuard peer failure

`r6-partial.ps1` runs ordinary active-console `baseline`, `blocked`, and
`recovered` phases. The baseline must pass first with both peers authenticated.
It checks four IPv4/IPv6 HTTP endpoints, direct UDP/TCP DNS to all four tunnel
resolvers, split DNS, main VPN and the other two work tunnels. Shared WireGuard
client addresses on the multi-peer adapter are accepted only from its four
configured addresses. A failed peer must return no HTTP or direct DNS response.

The reviewed host controller `r6-partial-host.py` currently targets **Win11**.
Stage the PS script as `C:\Users\Public\r6-partial.ps1`; run its baseline before
the host controller. The host validates the isolated fixture marker/MAC, creates
only two token-owned UDP51822 DROP rules, waits at most 300 seconds for partial
state, and removes only its exact rules in `finally`. It then verifies automatic
recovery without RequestConnect. Capture control is external: retain continuous
baseline/fault capture identities and explicit stop timestamps. An interrupted or
incomplete run is not a pass. Native Win11 R6 passed all three phases; packet
analysis and the separate Win10 rerun remain separately recorded evidence.

## External QA provenance

Full-work, service-faults and startup wrapper bytes match their native-passed
versions. Boot setup changes only its expected wrapper hash to the passed scope
normalization version; UI combines all six cases and adds one PNG copy operation.
These QA changes do not imply a new R6 binary/source archive.

| Controller | SHA-256 |
| --- | --- |
| `r6-boot-setup.ps1` | `50c08f90844a265e3d7f682a8f879128ec3c3831fa3dad06ec495a84b835ea96` |
| `r6-boot-startup.ps1` | `0080e25e5eb1c44f2f45111c74e2e3bdb16f24e7d5f0ce83811408e4ebeb2400` |
| `r6-full-work.ps1` | `e50ee88ac10553072a0b1eb0df32065a3041883b26308a58de128e3127695f07` |
| `r6-service-faults.ps1` | `763cb6363529f98848f4844fd4f13f3cfec521975a95bb01c87c50759ea68a9c` |
| `r6-ui-matrix.ps1` | `b2f89693a9a8825d55ab77849ee470747a70311693683d7c1e9eaba2b289770d` |
| `r6-partial.ps1` | `987634bab78d7b97db675f227ee99ecebbe387f95196376f36f6c8077aeb9ca0` |
| `r6-partial-host.py` | `9256257f1fd7949003e9ff1ccdd65062d51dad4730fd80db714210c465c2c930` |
