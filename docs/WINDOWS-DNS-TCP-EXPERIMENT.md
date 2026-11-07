# Windows default TCP DNS: bounded NRPT experiment

Windows 10 22H2 native observations on 2026-11-06:

- Raw TCP DNS to `127.0.0.1:53` and `[::1]:53` returned RCode 0 and the fixture answer.
- `Resolve-DnsName -TcpOnly -Server 127.0.0.1` and `-Server ::1` succeeded.
- Default-server `Resolve-DnsName -TcpOnly` returned Winsock 10057 immediately.
- Setting both physical and application-owned TUN DNS to `127.0.0.1` / `::1`
  removed the TUN's `fec0` placeholders but did not fix the default TCP query.
- The same raw TCP socket succeeded with `IP_UNICAST_IF` set to the loopback
  interface, and failed when explicitly bound to the physical or main TUN index.

Microsoft documents that interface-configured DNS servers cause the DNS client
to bind its query to that interface. Servers designated by NRPT policy avoid
that binding; the article explicitly includes Windows 10. This explains the
observed difference and supports an NRPT experiment, while the exact internal
path converting the failed bind into 10057 remains an inference.
[Microsoft DNS client behavior](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-in-windows-server-2016#dns-client).

The next test is one temporary local catch-all NRPT rule with the existing
loopback coordinator as its explicit server. This tests the documented DNS client
path without opening another listener, changing WFP, or changing adapter DNS.
The script uses the official add, effective-policy inspection and exact-name
removal commands. With no GPO/server arguments the rule is local.
[Add-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule),
[Get-DnsClientNrptPolicy](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientnrptpolicy),
[Remove-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/remove-dnsclientnrptrule).

Run `tests/windows/dns-nrpt-experiment.ps1` in an elevated QA process on either
project Windows VM, with the VPN connected and the private Linux fixture up:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\Vault443Exchange\dns-nrpt-experiment.ps1
```

The experiment records baseline TCP/UDP and explicit-loopback queries, adds one
rule, tests default A/AAAA over TCP/UDP, removes only its uniquely marked rule in
`finally`, checks NRPT and adapter DNS against their original snapshots, and
tests default TCP once more. Fresh names under `webdual.e2e.example.com` avoid
cache effects; the fixture must support that suffix. Existing catch-all policy
causes refusal before any rule is added. More-specific foreign rules are never
edited. No DNS cache flush, interface change, WFP change or service restart occurs.

The JSON report is written incrementally to
`C:\Users\Public\Vault443Exchange\nrpt-results\<token>.json`; it includes the
created rule name and unique marker for recovery if the QA process is forcibly
terminated before `finally`. Exit 0 means the hypothesis was supported and cleanup
verified; 1 means it was not supported; 2 means a precondition or cleanup check
failed. Never remove another rule by namespace or a broad Vault443 prefix.

The ordinary-user Windows 10 A/B/A test is now complete (2026-11-06,
Windows 10 build 19045.6456). With the main VPN connected, default UDP A/AAAA
queries returned the fixture addresses and both default TCP queries failed with
10057. While the fixed SYSTEM experiment held its temporary effective catch-all
pointing to `127.0.0.1` and `::1`, all four ordinary-user queries succeeded.
After verified cleanup, both TCP queries again failed with 10057; UDP remained
successful. The SYSTEM report recorded `hypothesisSupported=true` and
`cleanupComplete=true`. The initial background-job timeout attempt is a harness
failure and is not DNS evidence. On Windows 11, the bounded SYSTEM experiment
returned all twelve before/during/after queries successfully; its baseline did
not reproduce the Windows 10 defect.

Evidence is in `dist/windows/native-win10/ordinary-nrpt-baseline-sequential.txt`,
`ordinary-nrpt-start-during.txt`, and `ordinary-nrpt-after.txt`. The ordinary
observer `tests/windows/dns-nrpt-ordinary.ps1` uses four same-process sequential
queries with `QuickTimeout`, unique names, actual error IDs and durations.
Its `after` phase can be repeated while the fixed SYSTEM task owns cleanup.

Production now uses one application-owned local catch-all NRPT rule to the
existing four loopback listeners. `DNS.Start` reserves the listeners before
installing policy; pre-Start plans remain blocked. An embedded fixed PowerShell
5.1 script runs only as LocalSystem from the absolute System32 path, with fixed
inbox module loading, bounded JSON, a 15-second context and a kill-on-close Job
Object. Input contains data and an action enum; profiles cannot supply commands,
paths, GPO names, remote servers or executable arguments.

The private `windows-dns.json` records an unpredictable owner GUID and creating,
active or removing phase. The token is durable before Add, including retries
following a failed write. Recovery adopts only one exact-token rule with the
expected display/comment, namespace and two loopback servers. A saved rule GUID
must still match; changed or ambiguous identities are refused. Recreating a
missing known GUID first durably clears the obsolete GUID. Removal verifies the
exact owned rule and is idempotent when that rule is already absent; it never
removes a rule by namespace or a broad application prefix. Cleanup failures
retain identity and abort maintenance/uninstall.

A foreign catch-all is refused. More-specific foreign rules remain untouched;
conflicts with protected work zones are reported. New or changed plans stay
blocked until verification, while an unchanged healthy plan can continue under
verified policy when a different zone conflicts. If the owned/effective policy
itself cannot be verified, coordinator queries fail closed. The existing main
VPN prohibition on physical fallback and WFP protection remain in force.
Successful identical plan states are cached; ordinary underlay refresh does not
start PowerShell.

New connections do not change physical adapter DNS. Legacy loopback overrides
are restored only after effective owned NRPT during migration, using a separate
per-adapter durable recovery journal without clearing desired plans. Independent
adapter changes and disappeared adapters retain the recovery entry for review.
Explicit final release restores legacy settings first, then removes the exact
owned NRPT rule, then clears the journal. Service shutdown/crash leaves the rule
in place. Without a legacy override, fallback discovery always uses the live IP
Helper DNS list, including DHCP/RDNSS changes.

Focused injected-runner lifecycle tests cover pre-Start behavior, write failures,
crash-after-Add recovery, missing-GUID recreation, exact-removal failure, full
work root namespaces, partial-zone protection and state caching. Native packaged
production validation of activation, restart/crash persistence, legacy migration,
foreign policy conflicts and uninstall remains required on both Windows versions.
