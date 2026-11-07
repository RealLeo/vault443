# R7 acceptance controllers: checkpoint and resume

These QA-only files were copied byte-for-byte from the current `/tmp` controllers after native use. `r7-route-conflict.ps1` comes from `/tmp/r7-route-conflict-fresh.ps1`; the other basenames are unchanged. Legacy R6 comments/function names in that file are preserved: its actual daemon pin and output namespace are R7. These files are external QA provenance, added **after** the immutable R7 source archive; they do not describe a rebuilt candidate. No product, installer, frozen archive, or VM change was made while preserving them.

## Immutable candidate

Directory: `dist/windows/candidate-2026-11-07-r7/`. Unsigned local installer; full acceptance remains pending.

| Artifact | SHA-256 |
| --- | --- |
| `Vault443-1.3.4-windows-x64-setup.exe` | `491085f2d124fcaf2c1e047f15e9764f8b07c7b7fbc064892c1d52b2a0359f5d` |
| `build-manifest.json` | `3a0fdae5ca17d00717ce1282cf51c280627c9331acd8bc094e2bcfc2075c8a6d` |
| `source.zip` | `69d82a39026a20d9d0cfc6ba3d4b18670fa4ab7c10c767792bc5d05da4ddb76c` |
| Installed `vault443d.exe` | `2ad9a62ab0e14825cf265100891a16f74e80911e03b2d63cb036f3d976f3b1c6` |

## Controller byte hashes

| File | SHA-256 |
| --- | --- |
| `r7-route-conflict.ps1` | `3871aa82ad5fe3e004bc1d9a6841c5167e84cc28fc16b4cd2059b07f5138ab18` |
| `r7-overlap-admin.ps1` | `e254644eb8ece2a5a1de20aceadfeb185321e00c7bf743150e3445e5f00f31a9` |
| `r7-overlap.ps1` | `7b4018d394cbc811edc241812d51fa217a58225348fb5e41f5c0298c9b3e8b36` |
| `r7-external-admin.ps1` | `b41b3aa8f134491903239cda52a2219ad00b5ec393d24b2d309711c222ef528f` |
| `r7-external-verify.ps1` | `b9f350d4002eb124839fff571c88fb9f94f8092052993cbe1396ee07aff3775b` |
| `r7-dns6-positive.ps1` | `4a0e1db4a532839bc51932c35ff39f6fe744816121b1a45d7025151e2da295c0` |

## Native status at preservation

The following are root-controller reported results on the current Win10 R7 acceptance VM, with evidence exported under `dist/windows/native-win10-r7/`. They are not claims about the complete Win10/Win11 matrix.

- Fresh route-conflict run: **16 checks / 9 steps PASS**, completed and `restored=true`. Real new OpenVPN IPv4/IPv6 flows and subsequent WireGuard flows were confirmed separately by capture. Earlier keep-alive failures are not substituted for this successful run.
- Overlap: **baseline / run / recovered PASS**; explicit admin IP removal completed and remaining owned secondary IP count was zero; evidence exported.
- External dual-stack OpenVPN: **11 checks PASS**, including fresh ordinary-user HTTPS4/6, DNS, and main pause/guard.
- External IPv6-only: **NOT TESTED**. The UAC transition failed at `Start-Service` (controller line 26). Source audit of the QA-only wrapper's `validateConfig` (`tests/windows/external-openvpn-service/main_windows.go:84–111`) shows an exact allowlist entry for `redirect-gateway def1 ipv6`, but none for `redirect-gateway ipv6 !ipv4`. Attributing the start failure to that allowlist is a source-backed inference; this is not evidence of a Vault443 IPv6-only product failure or pass.
- External cleanup: **COMPLETE PASS at 23:46:34 UTC**: fixture service absent, `corp-external` adapter count zero, binding removed, main automatically connected. Ordinary `afterstop` **PASS at 23:47 UTC**, including the main helper's **22 real traffic checks**, without RequestConnect.
- External evidence exported under `dist/windows/native-win10-r7/`: `r7-external/`, admin dual/v6only/cleanup JSON reports, `r7-external.pcap`, and capture metadata.
- `r7-dns6-positive.ps1`: **NOT RUN**; native PS5 parser validation pending. It requires every VPN already disconnected and guard false.
- Native PS5 parsing passed for route, overlap, and external controllers. Preserving bytes did not rerun parsing, traffic checks, or builds.

## Preconditions and staging

Use only the named isolated VirtualBox VM `VAULT443-WIN10` or `VAULT443-WIN11`, with the exact installed R7 daemon above and the existing protected QA bootstrap (`C:\Program Files\Vault443QA\qa-runner.ps1`, private marker/inputs under `C:\ProgramData\Vault443-QA`). Ordinary phases run as the active console owner, unelevated, in Windows PowerShell 5.1. Admin phases require explicit same-controller UAC. Run PS5 ParseFile before a controller's first use; do not treat a parser pass as a native scenario pass.

Copy these public, secret-free scripts to `C:\Users\Public\Vault443Exchange\` using their repository basenames. Preserve their hashes. Existing protected helpers `main-matrix.ps1`, `work-smoke.ps1`, `openvpn-smoke.ps1` and their private/owned fixture preparations must already be installed. The main VLESS cache is `C:\Users\Public\Vault443Exchange\r7-protocols\main\state.json`.

After a reboot, an interface index or link-local `%zone` may change. Rebind a cached baseline only after verifying the same adapter GUID/MAC and expected global addresses/gateways; retain actual current scoped addresses. Never substitute another interface merely to make a check pass.

Route/overlap require own connected VLESS plus the connected `Vault443 Fixture wireguard-multi`, `amneziawg`, and split `openvpn` profiles. Route also requires imported, initially disconnected `wireguard-full` and `openvpn-full`. Full/split WG variants share a key; full/split/external OpenVPN share a temporary certificate and must not run simultaneously. Root performs the explicit preconditions/restoration outside these controllers where specified.

Do not overwrite existing user rules or foreign resources. Route refuses existing root manual policy. Overlap refuses preexisting overlap rules/IP/journal. External dual refuses an existing service and existing ordinary owner-state file. For a repeat, use the clean QA baseline or archive only verified owned prior QA state/reports; never remove foreign state to bypass a refusal.

## Scenario commands

Commands below are sequential native console actions, not host VM-management commands. Keep admin cleanup in the root controller's `finally`, and inspect `passed`, `completed`, restoration flags, and child exit codes before accepting the result.

```powershell
# Ordinary: full WG incumbent, conflict, manual route/DNS owner switches, restoration.
& C:\Users\Public\Vault443Exchange\r7-route-conflict.ps1

# Ordinary baseline BEFORE adding the secondary address.
& C:\Users\Public\Vault443Exchange\r7-overlap.ps1 -Phase baseline
# Explicit same-controller UAC:
& C:\Users\Public\Vault443Exchange\r7-overlap-admin.ps1 -Mode add
# Ordinary:
& C:\Users\Public\Vault443Exchange\r7-overlap.ps1 -Phase run
# Explicit UAC, even if run failed:
& C:\Users\Public\Vault443Exchange\r7-overlap-admin.ps1 -Mode remove
# Ordinary, after removal:
& C:\Users\Public\Vault443Exchange\r7-overlap.ps1 -Phase recovered
```

Overlap adds only `198.19.44.22/25`, `SkipAsSource=true`, on the verified physical adapter. It exercises automatic work policy, manual WG `/24`, manual local `/25`, invalid wider-local rejection, and restoration. Real WG response source is `198.19.44.2`; real physical response source remains `192.0.2.2`. This is one IPv4 connected-prefix conflict, not an actual Docker/HNS/NAT installation or IPv6 overlap.

For external OpenVPN, first explicitly disconnect built-in OpenVPN (both split/full variants). Keep the fixture profile **private**, at `$env:LOCALAPPDATA\Vault443\qa-ui-import\fixture-openvpn.ovpn`; never copy keys or raw profiles into Public/Exchange, reports, or Git. The controller accepts only that fixed private path. Stage only the secret-free setup script and fixture executable into Exchange:

- `external-setup.ps1`: SHA-256 `0376db231c99a26f79c2a5dc7d0e117a595da25a8aa3b85078fbc3cd7c8d5ca5` (existing `tests/windows/external-openvpn-service/setup.ps1`).
- `vault443-external-openvpn.exe`: SHA-256 `e97f245bd1e7a7631c5dd4d857a188fab98af25e050c211690896440fae9a009` (existing QA fixture build, never shipping stage).

```powershell
# Explicit UAC, fresh service only:
& C:\Users\Public\Vault443Exchange\r7-external-admin.ps1 -Mode dual
# Ordinary:
& C:\Users\Public\Vault443Exchange\r7-external-verify.ps1 -Phase dual
# Explicit UAC: stop/unbind, wait exact adapter departure, rewrite one redirect line,
# restart/rebind the same protected service image; no install/delete cycle.
& C:\Users\Public\Vault443Exchange\r7-external-admin.ps1 -Mode v6only
# Ordinary:
& C:\Users\Public\Vault443Exchange\r7-external-verify.ps1 -Phase v6only
# Explicit UAC cleanup, also on failure:
& C:\Users\Public\Vault443Exchange\r7-external-admin.ps1 -Mode cleanup
# Ordinary: automatic main recovery; does not send RequestConnect.
& C:\Users\Public\Vault443Exchange\r7-external-verify.ps1 -Phase afterstop
```

External checks use `GetVPNCompatibility`, verified `corp-external`, family-specific full flags, main pause/guard, real corp HTTP4/6 and DNS, fresh default HTTPS4/6, and no IPv4 response in IPv6-only mode. DNS uses longest matching zone: external default answers an otherwise unclaimed name with `93.184.215.14`; existing specific `wg.e2e.test` remains `198.19.44.10`. Reports go to protected `Vault443QA\reports\r7-external-*.json` and public sanitized `Vault443Exchange\r7-external\`.

Do not run the DNS6 positive helper as part of shutdown/checkpoint. On a later explicitly resumed QA run, after native parser validation and after every VPN has already been explicitly disconnected with guard false:

```powershell
& C:\Users\Public\Vault443Exchange\r7-dns6-positive.ps1
```

That helper only proves unique raw UDP/TCP IPv6 DNS A responses from `2001:db8:44::1:53` to the physical `2001:db8:44::2`, with ID/header/answer validation. It does not alter VPN or DNS configuration or replace negative leak checks. Root owns the separate capture. Its report is `Vault443Exchange\r7-dns6-positive.json`.

## Open items, not new work authorized by this checkpoint

The current external test is finished and its cleanup/recovery evidence is exported. Stop work and shut VMs down as requested. Tomorrow, before attempting IPv6-only again, narrowly extend the QA wrapper's exact redirect allowlist, rebuild **only the QA helper**, and refresh its QA executable hash pins; this does not require rebuilding the frozen R7 product. Then continue from the overall Windows checkpoint and actual reports; do not restart completed scenarios merely because these scripts were preserved. The rare OpenVPN metadata-before-authentication restoration error and the separately identified shared-cleanup-deadline risk remain open investigations, with no R8/product changes made here. Full matrix completion, including remaining Win11/R7 coverage and final consolidated evidence, is not claimed.
