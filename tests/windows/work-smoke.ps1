param(
    [ValidateSet('wireguard','amneziawg','wireguard-full','wireguard-multi')][string]$Profile = 'wireguard',
    [ValidateSet('begin','status','verify','disconnect','logs')][string]$Phase = 'status',
    [ValidateRange(0,45)][int]$WaitSeconds = 30,
    [string]$AppDirectory = (Join-Path $env:ProgramFiles 'Vault443')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$cli = Join-Path $AppDirectory 'vault443-cli.exe'
function Invoke-Vault([string]$Method, [object[]]$Parameters = @()) {
    $json = ConvertTo-Json -InputObject $Parameters -Compress -Depth 12
    $reply = $json | & $cli $Method
    if ($LASTEXITCODE) { throw "$Method failed: $reply" }
    if ($reply) { return ($reply | ConvertFrom-Json) }
}
$name = 'Vault443 Fixture ' + $Profile
if ($Phase -eq 'begin') {
    $raw = Get-Content "C:\Users\Public\Vault443Exchange\$Profile-import.json" -Raw
    $answer = $raw | & $cli PrepareWorkImport
    if ($LASTEXITCODE) { throw 'Work import preparation failed' }
    $draft = $answer | ConvertFrom-Json
    if ($draft.errors.Count -or !$draft.profiles.Count) { throw 'The fixture work profile was not accepted' }
    Invoke-Vault CommitWorkImport @($draft.draftId, '{}') | Out-Null
}
$snapshot = Invoke-Vault GetSnapshot
$work = $snapshot.workProfiles | Where-Object Name -eq $name | Select-Object -First 1
if (!$work) { throw "Fixture profile is missing: $name" }
if ($Phase -eq 'begin') {
    Invoke-Vault RequestWorkConnect @($work.id) | ConvertTo-Json -Depth 8
} elseif ($Phase -eq 'disconnect') {
    Invoke-Vault RequestWorkDisconnect @($work.id) | ConvertTo-Json -Depth 8
} elseif ($Phase -eq 'logs') {
    Invoke-Vault GetWorkLogs @($work.id, 'tail', 100) | ConvertTo-Json -Depth 12
} elseif ($Phase -eq 'verify') {
    $workID = [string]$work.id
    $deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
    do {
        # Poll only the originally selected ID; verify never requests a connect.
        # Refresh the whole snapshot so main/full-tunnel state is current too.
        $snapshot = Invoke-Vault GetSnapshot
        $work = $snapshot.workProfiles | Where-Object Id -eq $workID | Select-Object -First 1
        if (!$work) { throw 'The selected fixture work profile disappeared while waiting' }
        if ($work.runtime.state -in @('connected','partial')) { break }
        $remaining = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($remaining -le 0) { break }
        Start-Sleep -Milliseconds ([int][Math]::Min(500, [Math]::Ceiling($remaining)))
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($work.runtime.state -notin @('connected','partial')) { throw "Not connected after waiting up to $WaitSeconds seconds: $($work.runtime | ConvertTo-Json -Compress -Depth 8)" }
    $subnet = if ($Profile -eq 'amneziawg') {45} else {44}
    $v6 = if ($Profile -eq 'amneziawg') {81} else {80}
    $uris = @("http://198.19.$subnet.10:18080/", "http://[2001:db8:$v6`::10]:18080/")
    if ($Profile -eq 'wireguard-full') { $uris += 'https://web.e2e.example.com/' }
    foreach ($uri in $uris) {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 12
        $text = if ($response.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }
        $body = $text | ConvertFrom-Json
        if ($body.marker -notin @('work-e2e-ok','vless-e2e-ok')) { throw "Fixture marker is missing for $uri" }
        if ($body.peer -notin @("198.19.$subnet.2", "2001:db8:$v6`::2")) { throw "Traffic did not traverse the work tunnel: $($body.peer)" }
        $text
    }
    $zone = if ($Profile -eq 'amneziawg') {'awg.e2e.test'} else {'wg.e2e.test'}
    if ($Profile -ne 'wireguard-full') {
        $answers = Resolve-DnsName "probe.$zone" -Type A -DnsOnly -ErrorAction Stop
        if (!( $answers | Where-Object IPAddress -eq "198.19.$subnet.10" )) { throw 'Split DNS did not use the selected work tunnel' }
        $answers | Select-Object Name,Type,IPAddress | ConvertTo-Json
    }
    Invoke-Vault GetWorkDiagnostics @($work.id) | ConvertTo-Json -Depth 12
} else {
    $work | ConvertTo-Json -Depth 12
}
