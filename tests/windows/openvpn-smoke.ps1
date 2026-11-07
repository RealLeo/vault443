param(
    [ValidateSet('openvpn','openvpn-full')][string]$Profile = 'openvpn',
    [ValidateSet('begin','status','verify','disconnect','logs')][string]$Phase = 'status',
    [ValidateRange(0,45)][int]$WaitSeconds = 30
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$cli = 'C:\Program Files\Vault443\vault443-cli.exe'
function Invoke-Vault([string]$Method, [object[]]$Parameters = @()) {
    $reply = (ConvertTo-Json -InputObject $Parameters -Compress -Depth 12) | & $cli $Method
    if ($LASTEXITCODE) { throw "$Method failed: $reply" }
    if ($reply) { return ($reply | ConvertFrom-Json) }
}
$name = 'Vault443 Fixture ' + $Profile
if ($Phase -eq 'begin') {
    $raw = Get-Content "C:\Users\Public\Vault443Exchange\$Profile-import.json" -Raw
    $reply = $raw | & $cli PrepareWorkImport
    if ($LASTEXITCODE) { throw 'OpenVPN import preparation failed' }
    $draft = $reply | ConvertFrom-Json
    if ($draft.errors.Count -or !$draft.profiles.Count) { throw 'The temporary OpenVPN fixture profile was rejected' }
    Invoke-Vault CommitWorkImport @($draft.draftId, '{}') | Out-Null
}
$snapshot = Invoke-Vault GetSnapshot
$work = $snapshot.workProfiles | Where-Object Name -eq $name | Select-Object -First 1
if (!$work) { throw "OpenVPN fixture profile is missing: $name" }
if ($Phase -eq 'begin') {
    Invoke-Vault RequestWorkConnect @($work.id) | ConvertTo-Json -Depth 8
} elseif ($Phase -eq 'disconnect') {
    Invoke-Vault RequestWorkDisconnect @($work.id) | ConvertTo-Json -Depth 8
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    do {
        $snapshot = Invoke-Vault GetSnapshot
        $work = $snapshot.workProfiles | Where-Object Id -eq $work.id | Select-Object -First 1
        if ($work.runtime.state -eq 'disconnected') { $work | ConvertTo-Json -Depth 10; return }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'OpenVPN disconnection did not finish'
} elseif ($Phase -eq 'logs') {
    Invoke-Vault GetWorkLogs @($work.id, 'tail', 100) | ConvertTo-Json -Depth 12
} elseif ($Phase -eq 'verify') {
    $workID = [string]$work.id
    $deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
    do {
        # Keep main/full-tunnel state and the selected work ID from the same
        # fresh snapshot. This phase never starts or restarts a connection.
        $snapshot = Invoke-Vault GetSnapshot
        $work = $snapshot.workProfiles | Where-Object Id -eq $workID | Select-Object -First 1
        if (!$work) { throw 'The selected OpenVPN fixture profile disappeared while waiting' }
        if ($work.runtime.state -eq 'connected') { break }
        $remaining = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($remaining -le 0) { break }
        Start-Sleep -Milliseconds ([int][Math]::Min(500, [Math]::Ceiling($remaining)))
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($work.runtime.state -ne 'connected') { throw "OpenVPN is not connected after waiting up to $WaitSeconds seconds: $($work.runtime | ConvertTo-Json -Compress -Depth 8)" }
    foreach ($uri in @('http://10.77.8.10:8080/', 'http://[fd77:443:8::10]:8080/')) {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 12
        $body = $response.Content | ConvertFrom-Json
        if ($body.marker -ne 'openvpn-e2e-ok') { throw "OpenVPN fixture marker is missing for $uri" }
        $peer = [Net.IPAddress]::Parse($body.peer).ToString().ToLowerInvariant()
        if (!$peer.StartsWith('10.77.0.') -and !$peer.StartsWith('fd77:443::')) { throw "Traffic used a different path: $peer" }
        $response.Content
    }
    $query = ([Guid]::NewGuid().ToString('N')) + '.corp.openvpn.test'
    $answers4 = Resolve-DnsName $query -Type A -DnsOnly -ErrorAction Stop
    $answers6 = Resolve-DnsName $query -Type AAAA -DnsOnly -ErrorAction Stop
    if (!($answers4 | Where-Object IPAddress -eq '10.77.8.10')) { throw 'OpenVPN split DNS A lookup used a different resolver' }
    if (!($answers6 | Where-Object IPAddress -eq 'fd77:443:8::10')) { throw 'OpenVPN split DNS AAAA lookup used a different resolver' }
    @($answers4; $answers6) | Select-Object Name,Type,IPAddress | ConvertTo-Json
    if ($Profile -eq 'openvpn-full') {
        $response = Invoke-WebRequest -UseBasicParsing -Uri 'https://web.e2e.example.com/' -TimeoutSec 12
        $body = $response.Content | ConvertFrom-Json
        if ($body.marker -ne 'vless-e2e-ok' -or !$body.peer.StartsWith('10.77.0.')) { throw 'The default HTTPS request did not traverse OpenVPN' }
        $response.Content
    }
    Invoke-Vault GetWorkDiagnostics @($work.id) | ConvertTo-Json -Depth 12
    [pscustomobject]@{MainState=$snapshot.runtime.state;WorkState=$work.runtime.state} | ConvertTo-Json
} else {
    $work | ConvertTo-Json -Depth 12
}
