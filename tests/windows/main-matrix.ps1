# Run in the isolated fixture VM as the ordinary authorized desktop user.
# main-profiles.json is private input; reports contain only IDs, counters and
# test observations. Never print CLI replies or caught exception messages.
param(
    [ValidateSet('baseline','import','connect','switch','verify','protection','recovery','subscription','disconnect','all')][string]$Phase = 'verify',
    [ValidateSet('vless','trojan','shadowsocks','outline')][string]$Protocol = 'vless',
    [ValidateSet('engine-killed','service-killed','network-down','network-restored')][string]$Fault = 'engine-killed',
    [string]$ProfilesPath = 'C:\Users\Public\Vault443Exchange\main-profiles.json',
    [string]$OutputDirectory = 'C:\Users\Public\Vault443Exchange\main-results',
    [int]$PhysicalInterfaceIndex = 0,
    [int]$ConnectTimeoutSeconds = 90
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.WebRequest]::DefaultWebProxy = $null
$cli = 'C:\Program Files\Vault443\vault443-cli.exe'
$protocols = @('vless','trojan','shadowsocks','outline')
$script:checks = New-Object 'System.Collections.Generic.List[object]'
$script:current = 'initialization'
$script:failed = $false
$script:completed = $false
$started = [DateTime]::UtcNow
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$statePath = Join-Path $OutputDirectory 'state.json'
$reportPath = Join-Path $OutputDirectory ($started.ToString('yyyyMMddTHHmmssfffZ') + '-' + $Phase + '-' + $Protocol + '.json')
$script:state = @{ profiles = @{}; baseline = $null }
if (Test-Path $statePath) {
    $saved = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    foreach ($p in $saved.profiles.PSObject.Properties) { $script:state.profiles[$p.Name] = [string]$p.Value }
    $script:state.baseline = $saved.baseline
}
function Save-State { $script:state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8 }
function Save-Report {
    [ordered]@{ schema = 1; phase = $Phase; protocol = $Protocol; startedUtc = $started.ToString('o');
        fault = $(if ($Phase -eq 'protection' -or $Phase -eq 'recovery') {$Fault} else {$null});
        completed = $script:completed; passed = ($script:completed -and !$script:failed);
        finishedUtc = $(if ($script:completed) {[DateTime]::UtcNow.ToString('o')} else {$null});
        checks = @($script:checks.ToArray());
        limits = @('Fault injection and packet-capture correlation are performed separately. A link-down negative alone does not establish filter enforcement.')
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8
}
function Check([string]$Name, [bool]$Passed, [object]$Observation = $null, [bool]$ContinueOnFailure = $false) {
    $script:current = $Name
    $script:checks.Add([ordered]@{ check = $Name; passed = $Passed; utc = [DateTime]::UtcNow.ToString('o'); observation = $Observation })
    if (!$Passed) { $script:failed = $true }
    Save-Report
    if (!$Passed -and !$ContinueOnFailure) { throw 'Acceptance check failed' }
}
function Invoke-Vault([string]$Method, [object[]]$Parameters = @()) {
    $script:current = 'rpc-' + $Method
    $json = ConvertTo-Json -InputObject $Parameters -Compress -Depth 12
    $reply = $json | & $cli $Method 2>&1
    if ($LASTEXITCODE) { throw 'RPC operation failed' }
    if ($reply) { return (($reply -join "`n") | ConvertFrom-Json) }
}
function Snapshot { Invoke-Vault GetSnapshot }
# Service-down is an expected fault. Bound this diagnostic independently of the
# CLI's normal RPC timeout so it cannot delay or suppress the network probes.
function Optional-Snapshot {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $cli; $start.Arguments = 'GetSnapshot'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (!$process.Start()) { return $null }
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine('[]'); $process.StandardInput.Close()
        if (!$process.WaitForExit(3000)) {
            $process.Kill(); [void]$process.WaitForExit(1000)
            return $null
        }
        if ($process.ExitCode -ne 0) { return $null }
        return ($output.GetAwaiter().GetResult() | ConvertFrom-Json)
    } catch { return $null }
    finally { $process.Dispose() }
}
function Runtime-Observation($Snapshot) {
    if (!$Snapshot) { return @{ ipcAvailable = $false } }
    return @{ ipcAvailable = $true; activeProfileId = $Snapshot.activeProfileId;
        state = $Snapshot.runtime.state; stage = $Snapshot.runtime.stage;
        failureCode = $Snapshot.runtime.failureCode; guardArmed = $Snapshot.runtime.guardArmed }
}
function Profile-ID([string]$Kind) {
    $id = $script:state.profiles[$Kind]
    if (!$id) { throw 'Import phase must be completed first' }
    return $id
}
function Physical-Index {
    if ($PhysicalInterfaceIndex -gt 0) { return $PhysicalInterfaceIndex }
    $adapters = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
    if ($adapters.Count -ne 1) { throw 'Specify PhysicalInterfaceIndex when more than one physical adapter is up' }
    return [int]$adapters[0].ifIndex
}
# Raw numeric-address sockets avoid proxies and DNS. For physical negative tests,
# IP_UNICAST_IF/IPV6_UNICAST_IF force the underlay rather than the VPN route.
function Raw-Probe([string]$Address, [int]$Port, [byte[]]$Payload, [bool]$UDP, [int]$InterfaceIndex = 0) {
    $script:current = 'socket-' + $Address + '-' + $Port + '-udp' + $UDP + '-physical' + ($InterfaceIndex -gt 0)
    $ip = [Net.IPAddress]::Parse($Address)
    $type = if ($UDP) {[Net.Sockets.SocketType]::Dgram} else {[Net.Sockets.SocketType]::Stream}
    $transport = if ($UDP) {[Net.Sockets.ProtocolType]::Udp} else {[Net.Sockets.ProtocolType]::Tcp}
    $socket = [Net.Sockets.Socket]::new($ip.AddressFamily, $type, $transport)
    try {
        $socket.SendTimeout = 3000; $socket.ReceiveTimeout = 3000
        if ($InterfaceIndex -gt 0) {
            $level = [Net.Sockets.SocketOptionLevel]::IPv6; $index = $InterfaceIndex
            if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                $level = [Net.Sockets.SocketOptionLevel]::IP
                $index = [Net.IPAddress]::HostToNetworkOrder([int]$InterfaceIndex)
            }
            $socket.SetSocketOption($level, [Net.Sockets.SocketOptionName]31, [int]$index)
        }
        $async = $socket.BeginConnect($ip, $Port, $null, $null)
        try {
            if (!$async.AsyncWaitHandle.WaitOne(3000)) { return $null }
            $socket.EndConnect($async)
        } finally { $async.AsyncWaitHandle.Close() }
        $sent = 0
        while ($sent -lt $Payload.Length) {
            $written = $socket.Send($Payload, $sent, $Payload.Length - $sent, [Net.Sockets.SocketFlags]::None)
            if ($written -le 0) { return $null }
            $sent += $written
        }
        if (!$socket.Poll(3000000, [Net.Sockets.SelectMode]::SelectRead)) { return $null }
        $buffer = New-Object byte[] 8192
        $received = $socket.Receive($buffer)
        if ($received -le 0) { return $null }
        return ,([byte[]]$buffer[0..($received - 1)])
    } catch [Net.Sockets.SocketException] { return $null }
    finally { $socket.Dispose() }
}
function DNS-Query {
    $bytes = New-Object 'System.Collections.Generic.List[byte]'
    # One recursive A question. A unique name bypasses the client DNS cache.
    $bytes.AddRange([byte[]]@(0x44,0x33,1,0,0,1,0,0,0,0,0,0))
    foreach ($label in (('probe-' + [Guid]::NewGuid().ToString('N') + '.e2e.example.com') -split '\.')) {
        $bytes.Add([byte]$label.Length); $bytes.AddRange([Text.Encoding]::ASCII.GetBytes($label))
    }
    $bytes.AddRange([byte[]]@(0,0,1,0,1))
    return ,$bytes.ToArray()
}
function UDP-Result([string]$Address, [int]$Index = 0) {
    $nonce = [Guid]::NewGuid().ToString('N')
    $bytes = Raw-Probe $Address 18081 ([Text.Encoding]::ASCII.GetBytes('vault443-main-udp:' + $nonce)) $true $Index
    if (!$bytes) { return $null }
    $body = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    if ($body.marker -ne 'main-udp-e2e-ok' -or $body.nonce -ne $nonce) { throw 'Unexpected UDP reply' }
    return $body
}
function Baseline {
    $snapshot = Snapshot
    Check 'baseline-guard-off' (!$snapshot.runtime.guardArmed -and $snapshot.runtime.state -eq 'disconnected')
    $index = Physical-Index
    $request = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: web.e2e.example.com`r`n`r`n")
    foreach ($address in @('93.184.215.14','2001:db8:66::14')) {
        $http = Raw-Probe $address 8080 $request $false $index
        Check ('baseline-physical-tcp-' + $address) ([bool]$http) @{ interfaceIndex = $index }
        $reply = UDP-Result $address $index
        $assigned = @(Get-NetIPAddress -InterfaceIndex $index | Select-Object -ExpandProperty IPAddress)
        Check ('baseline-physical-udp-' + $address) ([bool]$reply -and $reply.peer -in $assigned) @{ peer = $reply.peer; interfaceIndex = $index }
    }
    $query = DNS-Query
    $reply = Raw-Probe '192.0.2.1' 53 $query $true $index
    Check 'baseline-physical-dns-udp' ([bool]$reply)
    $framed = [byte[]](@([byte]($query.Length -shr 8), [byte]($query.Length -band 255)) + $query)
    $reply = Raw-Probe '192.0.2.1' 53 $framed $false $index
    Check 'baseline-physical-dns-tcp' ([bool]$reply)
    $script:state.baseline = @{ interfaceIndex = $index; addresses = @($assigned | Sort-Object); utc = [DateTime]::UtcNow.ToString('o') }
    Save-State
}
function Import-Profiles {
    $private = Get-Content -LiteralPath $ProfilesPath -Raw | ConvertFrom-Json
    foreach ($kind in $protocols) {
        $source = [string]$private.$kind
        if (!$source) { throw 'Fixture source is missing' }
        $importKind = if ($kind -eq 'outline') {'outline'} else {'text'}
        $draft = Invoke-Vault PrepareImport @($source, $importKind, ('Windows matrix ' + $kind))
        Check ('import-preview-' + $kind) (!$draft.errors.Count -and $draft.profiles.Count -eq 1)
        $committed = Invoke-Vault CommitImport @($draft.draftId, '{}')
        $script:state.profiles[$kind] = [string]$committed.profiles[0].id
        Save-State
        $snapshot = Snapshot
        Check ('import-commit-' + $kind) ([bool]($snapshot.profiles | Where-Object id -eq $script:state.profiles[$kind]))
    }
}
function Connect-Profile([string]$Kind, [bool]$Switch) {
    $id = Profile-ID $Kind
    $before = Snapshot
    if ($Switch) { Check ('switch-start-' + $Kind) ($before.runtime.state -eq 'connected' -and $before.activeProfileId -ne $id) }
    Invoke-Vault RequestConnect @($id) | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds($ConnectTimeoutSeconds)
    do {
        $snapshot = Snapshot
        if ($snapshot.runtime.state -eq 'connected' -and $snapshot.activeProfileId -eq $id) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    Check ('connected-' + $Kind) ($snapshot.runtime.state -eq 'connected' -and $snapshot.activeProfileId -eq $id -and $snapshot.runtime.guardArmed) @{
        state = $snapshot.runtime.state; stage = $snapshot.runtime.stage; failureCode = $snapshot.runtime.failureCode; guardArmed = $snapshot.runtime.guardArmed }
    if ($Switch) { Check ('switch-session-' + $Kind) ($snapshot.traffic.sessionId -and $snapshot.traffic.sessionId -ne $before.traffic.sessionId) }
}
function Physical-Protection([string]$Kind, [bool]$LinkDown = $false, [bool]$ContinueOnFailure = $false) {
    Check 'guard-baseline-present' ([bool]$script:state.baseline)
    $index = [int]$script:state.baseline.interfaceIndex
    $adapters = @(Get-NetAdapter -Physical | Where-Object ifIndex -eq $index)
    Check 'guard-baseline-interface' ($adapters.Count -eq 1 -and ($PhysicalInterfaceIndex -eq 0 -or $PhysicalInterfaceIndex -eq $index)) @{ interfaceIndex = $index } $ContinueOnFailure
    $assigned = @(Get-NetIPAddress -InterfaceIndex $index -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress | Sort-Object)
    Check 'guard-baseline-addresses' ($LinkDown -or ($assigned -join ',') -eq ($script:state.baseline.addresses -join ',')) @{
        addresses = $assigned; adapterStatus = [string]$adapters[0].Status; expectedLinkDown = $LinkDown } $ContinueOnFailure
    $request = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: web.e2e.example.com`r`n`r`n")
    foreach ($address in @('93.184.215.14','2001:db8:66::14')) {
        $direct = Raw-Probe $address 8080 $request $false $index
        Check ('guard-direct-tcp-' + $Kind + '-' + $address) (!$direct) @{ receivedBytes = $direct.Length } $ContinueOnFailure
        $packet = [Text.Encoding]::ASCII.GetBytes('vault443-main-udp:' + [Guid]::NewGuid().ToString('N'))
        $direct = Raw-Probe $address 18081 $packet $true $index
        Check ('guard-direct-udp-' + $Kind + '-' + $address) (!$direct) @{ receivedBytes = $direct.Length } $ContinueOnFailure
    }
    $query = DNS-Query
    $framed = [byte[]](@([byte]($query.Length -shr 8), [byte]($query.Length -band 255)) + $query)
    foreach ($address in @('192.0.2.1','2001:db8:44::1')) {
        $direct = Raw-Probe $address 53 $query $true $index
        Check ('guard-lan-dns-udp-' + $Kind + '-' + $address) (!$direct) @{ receivedBytes = $direct.Length } $ContinueOnFailure
        $direct = Raw-Probe $address 53 $framed $false $index
        Check ('guard-lan-dns-tcp-' + $Kind + '-' + $address) (!$direct) @{ receivedBytes = $direct.Length } $ContinueOnFailure
    }
}
function Protection {
    $before = Optional-Snapshot
    # SCM can restart a crashed service during these probes. An explicit stop
    # does not trigger recovery; after a crash, available IPC must report guard armed.
    $expected = if ($Fault -eq 'service-killed') {!$before -or [bool]$before.runtime.guardArmed} else {[bool]$before}
    Check 'protection-ipc-before' $expected (Runtime-Observation $before) $true
    # All eight probes run even if an earlier probe discovers a leak. No tunnel
    # payload or connected-state requirement is imposed during the fault.
    Physical-Protection $Protocol ($Fault -eq 'network-down') $true
    $after = Optional-Snapshot
    $expected = if ($Fault -eq 'service-killed') {!$after -or [bool]$after.runtime.guardArmed} else {[bool]$after}
    Check 'protection-ipc-after' $expected (Runtime-Observation $after) $true
}
function Recovery {
    $id = Profile-ID $Protocol
    $deadline = [DateTime]::UtcNow.AddSeconds($ConnectTimeoutSeconds)
    do {
        $snapshot = Optional-Snapshot
        if ($snapshot -and $snapshot.runtime.state -eq 'connected' -and $snapshot.activeProfileId -eq $id) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    Check ('recovered-' + $Protocol) ($snapshot -and $snapshot.runtime.state -eq 'connected' -and $snapshot.activeProfileId -eq $id -and $snapshot.runtime.guardArmed) (Runtime-Observation $snapshot)
    Verify-Profile $Protocol
}
function Verify-Profile([string]$Kind) {
    $snapshot = Snapshot
    Check ('verify-owner-' + $Kind) ($snapshot.activeProfileId -eq (Profile-ID $Kind) -and $snapshot.runtime.state -eq 'connected' -and $snapshot.runtime.guardArmed)
    $before = $snapshot.traffic
    foreach ($name in @('web.e2e.example.com','web6.e2e.example.com')) {
        $script:current = 'https-' + $Kind + '-' + $name
        $response = Invoke-WebRequest -UseBasicParsing -Uri ('https://' + $name + '/') -TimeoutSec 12
        $text = if ($response.Content -is [byte[]]) {[Text.Encoding]::UTF8.GetString($response.Content)} else {[string]$response.Content}
        $body = $text | ConvertFrom-Json
        $expected = if ($name -eq 'web6.e2e.example.com') {'2001:db8:66::14'} else {'93.184.215.14'}
        Check ('tunnel-tcp-' + $Kind + '-' + $name) ($body.marker -eq 'vless-e2e-ok' -and $body.peer -eq $expected) @{ peer = $body.peer }
    }
    foreach ($address in @('93.184.215.14','2001:db8:66::14')) {
        $reply = UDP-Result $address
        Check ('tunnel-udp-' + $Kind + '-' + $address) ([bool]$reply -and $reply.peer -eq $address) @{ peer = $reply.peer }
    }
    foreach ($type in @('A','AAAA')) {
        foreach ($tcp in @($false,$true)) {
            $name = 'probe-' + [Guid]::NewGuid().ToString('N') + '.webdual.e2e.example.com'
            $script:current = 'resolve-' + $Kind + '-' + $type + '-tcp' + $tcp
            $answers = Resolve-DnsName $name -Type $type -DnsOnly -TcpOnly:$tcp -ErrorAction Stop
            $expected = if ($type -eq 'A') {'93.184.215.14'} else {'2001:db8:66::14'}
            Check ('system-dns-' + $Kind + '-' + $type + '-tcp' + $tcp) ([bool]($answers | Where-Object IPAddress -eq $expected)) @{ address = $expected }
        }
    }
    Physical-Protection $Kind
    # A successful tunnel reply after the negatives rules out a dead fixture.
    $reply = UDP-Result '93.184.215.14'
    Check ('tunnel-still-live-' + $Kind) ([bool]$reply -and $reply.peer -eq '93.184.215.14')
    Start-Sleep -Milliseconds 1500
    $after = (Snapshot).traffic
    Check ('traffic-counters-' + $Kind) ($after.valid -and $after.sessionId -eq $before.sessionId -and $after.downloadBytes -gt $before.downloadBytes -and $after.uploadBytes -gt $before.uploadBytes) @{
        downloadDelta = ($after.downloadBytes - $before.downloadBytes); uploadDelta = ($after.uploadBytes - $before.uploadBytes) }
}
function Subscription {
    $before = Snapshot
    $private = Get-Content -LiteralPath $ProfilesPath -Raw | ConvertFrom-Json
    $name = 'Windows matrix subscription'
    $known = @($before.subscriptions | Where-Object name -eq $name)
    if (!$known.Count) {
        $draft = Invoke-Vault PrepareImport @([string]$private.subscription, 'subscription', $name)
        Check 'subscription-preview' (!$draft.errors.Count -and $draft.profiles.Count -eq 3)
        Invoke-Vault CommitImport @($draft.draftId, '{}') | Out-Null
    }
    $snapshot = Snapshot
    Check 'subscription-committed' (@($snapshot.subscriptions | Where-Object name -eq $name).Count -eq 1)
    $sub = $snapshot.subscriptions | Where-Object name -eq $name | Select-Object -First 1
    $refresh = @(Invoke-Vault RefreshSubscriptions)
    Check 'subscription-refresh' ([bool]($refresh | Where-Object { $_.id -eq $sub.id -and $_.updated }))
    $after = Snapshot
    Check 'subscription-keeps-connection' ($after.activeProfileId -eq $before.activeProfileId -and $after.runtime.state -eq $before.runtime.state -and $after.traffic.sessionId -eq $before.traffic.sessionId)
}
function Disconnect {
    Invoke-Vault RequestDisconnect | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $snapshot = Snapshot
        if ($snapshot.runtime.state -eq 'disconnected' -and !$snapshot.runtime.guardArmed) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    Check 'explicit-disconnect' ($snapshot.runtime.state -eq 'disconnected' -and !$snapshot.runtime.guardArmed)
}
try {
    switch ($Phase) {
        'baseline' { Baseline }
        'import' { Import-Profiles }
        'connect' { Connect-Profile $Protocol $false }
        'switch' { Connect-Profile $Protocol $true }
        'verify' { Verify-Profile $Protocol }
        'protection' { Protection }
        'recovery' { Recovery }
        'subscription' { Subscription }
        'disconnect' { Disconnect }
        'all' {
            Baseline; Import-Profiles
            for ($i = 0; $i -lt $protocols.Count; $i++) {
                Connect-Profile $protocols[$i] ($i -gt 0)
                Verify-Profile $protocols[$i]
            }
            Subscription
            Verify-Profile 'outline'
            Disconnect
        }
    }
} catch {
    $script:failed = $true
    $script:checks.Add([ordered]@{ check = $script:current; passed = $false; utc = [DateTime]::UtcNow.ToString('o'); exceptionType = $_.Exception.GetType().FullName })
} finally { $script:completed = $true; Save-Report }
[ordered]@{ passed = !$script:failed; report = $reportPath; checks = $script:checks.Count } | ConvertTo-Json -Compress
if ($script:failed) { exit 1 }
