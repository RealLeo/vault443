#Requires -Version 5.1
#Requires -RunAsAdministrator
# One-shot QA A/B only. Run with the VPN and private Linux fixture already up.
# Microsoft: interface-configured DNS binds to that interface; NRPT-selected
# DNS does not: https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-in-windows-server-2016#dns-client
# The rule is local (no GpoName/Server), receives its own GUID from Add, and is
# removed only after its unique comment/display name are verified in finally.
param(
    [ValidateRange(0,90)][int]$HoldSeconds = 0,
    [string]$Suffix = 'webdual.e2e.example.com',
    [string]$ExpectedA = '93.184.215.14',
    [string]$ExpectedAAAA = '2001:db8:66::14',
    [string]$OutputDirectory = 'C:\Users\Public\Vault443Exchange\nrpt-results'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11')) { throw 'This experiment is restricted to the project QA VMs' }
$token = [Guid]::NewGuid().ToString('D')
$comment = 'Vault443 temporary DNS NRPT QA ' + $token
$display = 'Vault443 QA ' + $token
$checks = New-Object 'System.Collections.Generic.List[object]'
$report = [ordered]@{ experiment = 'dns-nrpt-loopback'; token = $token; ruleName = $null; phase = 'initialization'; holdSeconds = $HoldSeconds; holdUntilUtc = $null; cleanupComplete = $false; hypothesisSupported = $false; failure = $null; checks = @() }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$reportPath = Join-Path $OutputDirectory ($token + '.json')
function Save-Report {
    $report.checks = @($checks.ToArray())
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8
}
function Rule-Snapshot {
    @(Get-DnsClientNrptRule | Sort-Object Name | Select-Object Name,Namespace,NameServers,DisplayName,Comment) | ConvertTo-Json -Depth 5 -Compress
}
function Query-DNS([string]$Phase, [string]$Type, [bool]$TCP, [string]$Server = '') {
    # New names avoid changing the system DNS cache or accepting cached answers.
    $name = 'nrpt-' + [Guid]::NewGuid().ToString('N') + '.' + $Suffix
    $options = @{ Name=$name; Type=$Type; DnsOnly=$true; NoHostsFile=$true; QuickTimeout=$true; ErrorAction='Stop' }
    if ($TCP) { $options.TcpOnly = $true }
    if ($Server) { $options.Server = $Server }
    $result = [ordered]@{ phase=$Phase; type=$Type; tcp=$TCP; server=$Server; passed=$false; errorId=$null; addresses=@() }
    try {
        $answer = @(Resolve-DnsName @options | Where-Object IPAddress | Select-Object -ExpandProperty IPAddress)
        $expected = if ($Type -eq 'A') {$ExpectedA} else {$ExpectedAAAA}
        $result.addresses = $answer
        $result.passed = $answer -contains $expected
    } catch { $result.errorId = $_.FullyQualifiedErrorId }
    $checks.Add($result)
    Save-Report
}
$beforeRules = Rule-Snapshot
$beforeDNS = @(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses) | ConvertTo-Json -Depth 5 -Compress
try {
    # More-specific foreign rules are not changed. Refuse an existing catch-all
    # instead of competing with it or masking a domain policy in this A/B.
    if (@(Get-DnsClientNrptPolicy -Effective | Where-Object { @($_.Namespace) -contains '.' }).Count -gt 0 -or
        @(Get-DnsClientNrptRule | Where-Object { @($_.Namespace) -contains '.' }).Count -gt 0) { throw 'An existing catch-all NRPT policy prevents this isolated experiment' }
    foreach ($type in @('A','AAAA')) {
        Query-DNS 'baseline' $type $true
        Query-DNS 'baseline' $type $false
    }
    Query-DNS 'explicit-loopback' 'A' $true '127.0.0.1'
    Query-DNS 'explicit-loopback' 'AAAA' $true '::1'
    if (@($checks | Where-Object { $_.phase -eq 'explicit-loopback' -and !$_.passed }).Count) { throw 'The loopback coordinator/fixture precondition failed' }
    $rule = Add-DnsClientNrptRule -Namespace '.' -NameServers @('127.0.0.1','::1') -Comment $comment -DisplayName $display -PassThru -Confirm:$false
    $report.ruleName = [string]$rule.Name
    Save-Report
    if (!$report.ruleName) { throw 'The temporary NRPT rule identity was not returned' }
    $effective = @(Get-DnsClientNrptPolicy -Effective | Where-Object { @($_.Namespace) -contains '.' })
    if (!$effective.Count) { throw 'The local NRPT rule is not effective; domain policy may take precedence' }
    if ($HoldSeconds -gt 0) {
        # Let the parent issue an independent ordinary-user query while this
        # SYSTEM-owned rule is active. Cleanup still runs through finally.
        $report.phase = 'nrpt-hold'
        $report.holdUntilUtc = [DateTime]::UtcNow.AddSeconds($HoldSeconds).ToString('o')
        Save-Report
        Start-Sleep -Seconds $HoldSeconds
    }
    $report.phase = 'nrpt-testing'
    Save-Report
    foreach ($type in @('A','AAAA')) {
        Query-DNS 'nrpt' $type $true
        Query-DNS 'nrpt' $type $false
    }
    $report.hypothesisSupported = (@($checks | Where-Object { $_.phase -eq 'baseline' -and $_.tcp -and !$_.passed }).Count -gt 0 -and
        @($checks | Where-Object { $_.phase -eq 'nrpt' -and !$_.passed }).Count -eq 0)
} catch { $report.failure = $_.Exception.Message }
finally {
    $report.phase = 'cleanup'
    try { Save-Report } catch { } # A progress-write failure must not skip removal.
    try {
        # Search the unique marker even if Add created a rule but failed before
        # returning its GUID. Never remove by namespace or a broad prefix.
        $owned = @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $comment -and $_.DisplayName -eq $display })
        foreach ($item in $owned) { Remove-DnsClientNrptRule -Name $item.Name -Force -Confirm:$false }
        if (@(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $comment -and $_.DisplayName -eq $display }).Count) { throw 'Temporary rule removal did not complete' }
        if ((Rule-Snapshot) -ne $beforeRules) { throw 'NRPT state differs from its baseline; no foreign rule will be rewritten automatically' }
        $afterDNS = @(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses) | ConvertTo-Json -Depth 5 -Compress
        if ($afterDNS -ne $beforeDNS) { throw 'Adapter DNS state changed independently during the experiment; no settings will be rewritten automatically' }
        $report.cleanupComplete = $true
        foreach ($type in @('A','AAAA')) { Query-DNS 'after-removal' $type $true }
    } catch { $report.failure = 'Cleanup verification: ' + $_.Exception.Message }
    $report.phase = 'complete'
    Save-Report
}
$report | ConvertTo-Json -Depth 8
if (!$report.cleanupComplete -or $report.failure) { exit 2 }
if (!$report.hypothesisSupported) { exit 1 }
