param([Parameter(Mandatory=$true)][ValidateSet('fixture-network','nat-network','nrpt','service-stop','service-start','service-crash','engine-crash','engine-crash-xray','engine-crash-outline','engine-crash-wireguard','engine-crash-amneziawg','engine-crash-openvpn','network-down','network-up','installer-inspect','installer-upgrade','installer-uninstall')][string]$Mode)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Join-Path $env:ProgramFiles 'Vault443QA'
$private = Join-Path $env:ProgramData 'Vault443-QA'
$app = Join-Path $env:ProgramFiles 'Vault443'
if ($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11') -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Fixed SYSTEM QA task required' }
function Protected([string]$Path, [bool]$PrivatePath) {
    $item = Get-Item -LiteralPath $Path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'QA input is a reparse point' }
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18','S-1-5-32-544')
    # Program Files grants TrustedInstaller maintenance rights to installed app
    # directories. Accept that SID only within the exact public application
    # tree; Vault443QA and every private path retain the original trust list.
    $checkedPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $installedRoot = [IO.Path]::GetFullPath($app).TrimEnd('\')
    if (!$PrivatePath -and ($checkedPath.Equals($installedRoot,[StringComparison]::OrdinalIgnoreCase) -or $checkedPath.StartsWith(($installedRoot+'\'),[StringComparison]::OrdinalIgnoreCase))) {
        $trusted += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    }
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'QA input has an untrusted owner' }
    $mask = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    if ($PrivatePath) { $mask = $mask -bor [Security.AccessControl.FileSystemRights]::ReadData -bor [Security.AccessControl.FileSystemRights]::ExecuteFile }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $rule.IdentityReference.Value -notin $trusted -and ($rule.FileSystemRights -band $mask)) { throw 'QA input permits untrusted access' }
    }
}
Protected $root $false
Protected $private $true
Protected (Join-Path $private 'marker') $true
if ([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim() -ne 'Vault443 isolated Windows fixture') { throw 'Protected QA marker is missing' }
Protected (Join-Path $private 'qa-inputs.json') $true
$config = [IO.File]::ReadAllText((Join-Path $private 'qa-inputs.json')) | ConvertFrom-Json
if ($config.machine -ne $env:COMPUTERNAME -or $config.installerSha256 -notmatch '^[a-f0-9]{64}$' -or $config.installer -notmatch '^Vault443-[0-9]+\.[0-9]+\.[0-9]+-windows-x64-setup\.exe$') { throw 'Protected QA configuration does not match this VM' }
$allowed = @('qa-runner.ps1','qa-bootstrap.ps1','installer-smoke.ps1','dns-nrpt-experiment.ps1','fixture-ca.crt','main-matrix.ps1','main-smoke.ps1','work-smoke.ps1','openvpn-smoke.ps1',$config.installer)
foreach ($entry in $config.files.PSObject.Properties) {
    if ($entry.Name -notin $allowed) { throw 'Unknown QA input in protected manifest' }
    $path = Join-Path $root $entry.Name
    Protected $path $false
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw 'Protected QA input hash changed' }
}
if ($config.files.PSObject.Properties[$config.installer].Value -ne $config.installerSha256) { throw 'Pinned installer identity differs' }
# Publicly readable reports live under the protected Program Files parent.
# No SYSTEM output follows a caller-writable Public directory or junction.
$reports = Join-Path $root 'reports'
Protected $reports $false
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$report = @{ mode = $Mode; utc = [DateTime]::UtcNow.ToString('o'); passed = $false; details = @{}; exceptionType = $null }
function Adapter {
    $items = @(Get-NetAdapter -Physical | Where-Object { [string]$_.InterfaceGuid -eq $config.adapterGuid -and $_.MacAddress -eq $config.adapterMAC })
    if ($items.Count -ne 1) { throw 'The bound isolated QA uplink changed' }
    return $items[0]
}
function Daemon {
    $service = Get-CimInstance Win32_Service -Filter "Name='Vault443'"
    if (!$service -or $service.ProcessId -le 0 -or $service.StartName -ne 'LocalSystem') { throw 'Vault443 service PID is not active' }
    $process = [Diagnostics.Process]::GetProcessById([int]$service.ProcessId)
    [void]$process.Handle
    if ($process.HasExited -or $process.MainModule.FileName -ne (Join-Path $app 'vault443d.exe')) { $process.Dispose(); throw 'SCM PID does not belong to the installed daemon' }
    return $process
}
function Engine-PrivateJSON([string]$Name, [int]$MaxBytes) {
    $dataRoot = Join-Path $env:ProgramData 'Vault443'
    Protected $dataRoot $true
    $path = Join-Path $dataRoot $Name
    Protected $path $true
    $item = Get-Item -LiteralPath $path
    if ($item.PSIsContainer -or $item.Length -gt $MaxBytes) { throw 'Invalid bounded engine ownership state' }
    return ([IO.File]::ReadAllText($path) | ConvertFrom-Json)
}
function Engine-Owner([string]$Selector) {
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.Model -ne 'VirtualBox' -or !$computer.UserName -or $config.controllerSID -notmatch '^S-1-5-21-[0-9-]+$' -or ([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value -ne $config.controllerSID) { throw 'Bound active-console QA controller required' }
    $users = Engine-PrivateJSON 'windows-users.json' 1MB
    $uidProperty = $users.users.PSObject.Properties[$config.controllerSID]
    if (!$uidProperty -or [uint64]$uidProperty.Value -le 0 -or [uint64]$uidProperty.Value -gt [uint32]::MaxValue) { throw 'Bound controller has no private application UID' }
    $uid = [uint32]$uidProperty.Value
    if ($Selector -in @('xray','outline')) {
        $state = Engine-PrivateJSON 'state.json' 40MB
        if (!$state.desired -or [uint32]$state.desired.uid -ne $uid) { throw 'The bound controller must own the requested main VPN' }
        $profiles = @($state.users.PSObject.Properties[[string]$uid].Value.profiles | Where-Object id -eq $state.desired.profileId)
        if ($profiles.Count -ne 1) { throw 'Requested main profile identity is ambiguous' }
        $kind = if ($profiles[0].kind) { [string]$profiles[0].kind } else { 'vless' }
        if ($kind -notin @('vless','trojan','shadowsocks') -or ($Selector -eq 'outline' -and ($kind -ne 'shadowsocks' -or !$profiles[0].outline -or $profiles[0].transport -ne 'outline'))) { throw 'Requested main family does not match the fixed engine selector' }
        return @{ profileID=[string]$profiles[0].id; family=$kind; uid=$uid }
    }
    $state = Engine-PrivateJSON 'work-vpn.json' 40MB
    $wanted = @()
    foreach ($desired in @($state.desired)) {
        $profile = @($state.users.PSObject.Properties[[string]$desired.uid].Value.profiles | Where-Object id -eq $desired.profileId)
        if ($profile.Count -ne 1) { throw 'Requested work profile identity is ambiguous' }
        $kind = if ($profile[0].kind) { [string]$profile[0].kind } else { 'openvpn' }
        if (($Selector -in @('wireguard','amneziawg') -and $kind -in @('wireguard','amneziawg')) -or ($Selector -eq 'openvpn' -and $kind -eq 'openvpn')) {
            $wanted += @{ profileID=[string]$profile[0].id; family=$kind; uid=[uint32]$desired.uid }
        }
    }
    # WG and AWG share a no-arguments executable and private stdin protocol.
    # Requiring one requested WG/AWG across all users makes the unique process
    # selector exact without guessing a PID-to-Wintun association.
    if ($wanted.Count -ne 1 -or $wanted[0].family -ne $Selector -or $wanted[0].uid -ne $uid) { throw 'One unambiguous caller-owned requested work family required' }
    return $wanted[0]
}
function Crash-FixedEngine([string]$Selector) {
    $relative = switch ($Selector) {
        'xray' { 'xray.exe' }
        'outline' { 'vault443-outline.exe' }
        'wireguard' { 'vault443-tunnel.exe' }
        'amneziawg' { 'vault443-tunnel.exe' }
        'openvpn' { 'openvpn/openvpn.exe' }
        default { throw 'Unknown fixed engine selector' }
    }
    $pins = $config.engineFaults
    if (!$pins -or $pins.schema -ne 1 -or $pins.manifestSha256 -notmatch '^[a-f0-9]{64}$') { throw 'Explicit engine-fault candidate pins were not installed by bootstrap' }
    $manifestPath = Join-Path $app 'build-manifest.json'
    Protected $app $false
    Protected $manifestPath $false
    if ((Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant() -ne $pins.manifestSha256) { throw 'Installed engine-fault candidate manifest differs' }
    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    foreach ($name in @('vault443d.exe',$relative)) {
        $hash = [string]$pins.images.PSObject.Properties[$name].Value
        $file = Join-Path $app ($name -replace '/', '\')
        Protected (Split-Path -Parent $file) $false
        Protected $file $false
        if ($hash -notmatch '^[a-f0-9]{64}$' -or [string]$manifest.files.PSObject.Properties[$name].Value.sha256 -ne $hash -or (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant() -ne $hash) { throw 'Installed fixed engine/daemon hash differs' }
    }
    $owner = Engine-Owner $Selector
    # Work IDs include their protocol prefix (workvpn parser/wireguard schema);
    # main IDs use the unprefixed 128-bit content identifier.
    $idPattern = switch ($Selector) {
        'xray' { '^[a-f0-9]{32}$' }
        'outline' { '^[a-f0-9]{32}$' }
        'wireguard' { '^wg-[a-f0-9]{32}$' }
        'amneziawg' { '^awg-[a-f0-9]{32}$' }
        'openvpn' { '^ovpn-[a-f0-9]{32}$' }
        default { throw 'Unknown fixed engine selector' }
    }
    if ($owner.profileID -notmatch $idPattern) { throw 'Invalid private target profile identity' }
    $path = Join-Path $app ($relative -replace '/', '\')
    $daemon = Daemon
    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='Vault443'"
        if ($service.State -ne 'Running' -or $service.PathName.Trim('"') -ne (Join-Path $app 'vault443d.exe')) { throw 'Exact running LocalSystem service required' }
        $children = @(Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $daemon.Id) | Where-Object ExecutablePath -eq $path)
        if ($children.Count -ne 1) { throw 'No unique daemon-owned fixed engine to crash' }
        $engine = [Diagnostics.Process]::GetProcessById([int]$children[0].ProcessId)
        try {
            [void]$engine.Handle
            $created = $engine.StartTime.ToUniversalTime()
            $current = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $engine.Id)
            $service = Get-CimInstance Win32_Service -Filter "Name='Vault443'"
            $again = Engine-Owner $Selector
            # CIM datetime exposes microseconds; native Process.StartTime keeps
            # 100ns ticks. Compare the same precision while holding the original
            # process handle, so PID reuse can never redirect Kill to a new PID.
            $cimTicks = if ($current.CreationDate) { $current.CreationDate.ToUniversalTime().Ticks } else { 0L }
            $nativeTicks = $created.Ticks
            $sameCreation = ($cimTicks - ($cimTicks % 10)) -eq ($nativeTicks - ($nativeTicks % 10))
            if ($engine.HasExited -or $daemon.HasExited -or $service.ProcessId -ne $daemon.Id -or $current.ParentProcessId -ne $daemon.Id -or $current.ExecutablePath -ne $path -or $engine.MainModule.FileName -ne $path -or !$current.CreationDate -or !$sameCreation -or $created -lt $daemon.StartTime.ToUniversalTime() -or $again.profileID -ne $owner.profileID -or $again.family -ne $owner.family -or $again.uid -ne $owner.uid) { throw 'Fixed engine PID, creation, ancestry or private owner changed' }
            $report.details = @{ selector=$Selector; family=$owner.family; profileID=$owner.profileID; daemonPid=$daemon.Id; daemonCreatedUTC=$daemon.StartTime.ToUniversalTime().ToString('o'); enginePid=$engine.Id; engineCreatedUTC=$created.ToString('o'); engine=[IO.Path]::GetFileName($path); engineSha256=[string]$pins.images.PSObject.Properties[$relative].Value; killedUTC=[DateTime]::UtcNow.ToString('o') }
            $engine.Kill()
            if (!$engine.WaitForExit(10000)) { throw 'Fixed engine termination was not confirmed' }
            $report.details.terminationConfirmed = $true
        } finally { $engine.Dispose() }
    } finally { $daemon.Dispose() }
}

function Run-Harness([string]$Name, [string]$Arguments) {
    $output = Join-Path $private ($stamp + '-' + $Mode + '.stdout')
    $errorLog = Join-Path $private ($stamp + '-' + $Mode + '.stderr')
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argsFixed = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $root $Name) + '" ' + $Arguments
    $process = Start-Process -FilePath $ps -ArgumentList $argsFixed -RedirectStandardOutput $output -RedirectStandardError $errorLog -PassThru
    [void]$process.Handle
    if (!$process.WaitForExit(300000)) { throw 'Fixed QA harness exceeded its bounded wait' }
    $report.details = @{ exitCode = $process.ExitCode; privateOutput = $output; privateErrors = $errorLog }
    $childDir = if ($Name -eq 'dns-nrpt-experiment.ps1') { Join-Path $private 'nrpt-results' } else { Join-Path $private 'installer-results' }
    $childPath = Get-ChildItem -LiteralPath $childDir -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if ($childPath -and $childPath.LastWriteTimeUtc -ge [DateTime]::ParseExact($stamp,'yyyyMMddTHHmmssfffZ',[Globalization.CultureInfo]::InvariantCulture).AddSeconds(-1)) {
        $child = Get-Content -LiteralPath $childPath.FullName -Raw | ConvertFrom-Json
        if ($Name -eq 'dns-nrpt-experiment.ps1') {
            $report.details.result = @{ cleanupComplete = $child.cleanupComplete; hypothesisSupported = $child.hypothesisSupported;
                checks = @($child.checks | Select-Object phase,type,tcp,passed,errorId,addresses) }
        } else {
            $report.details.result = @{ phase = $child.phase; completed = $child.completed; passed = $child.passed; guiProbeSkipped = $child.guiProbeSkipped;
                checks = @($child.checks | Select-Object check,passed,observation) }
        }
    }
    if ($process.ExitCode -ne 0) { throw 'Fixed QA harness failed; inspect private output' }
}
try {
    switch ($Mode) {
        'fixture-network' {
            $adapter = Adapter; $index = $adapter.ifIndex
            Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled
            Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false
            Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
            New-NetIPAddress -InterfaceIndex $index -IPAddress 192.0.2.2 -PrefixLength 24 -DefaultGateway 192.0.2.1 | Out-Null
            Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses 192.0.2.1
            Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -RouterDiscovery Disabled
            Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv6 | Where-Object { $_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -notlike 'fe80:*' } | Remove-NetIPAddress -Confirm:$false
            Get-NetRoute -InterfaceIndex $index -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
            New-NetIPAddress -InterfaceIndex $index -IPAddress 2001:db8:44::2 -PrefixLength 64 -DefaultGateway 2001:db8:44::1 | Out-Null
            Import-Certificate -FilePath (Join-Path $root 'fixture-ca.crt') -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
            $report.details = @{ interfaceIndex = $index; ipv4 = '192.0.2.2'; ipv6 = '2001:db8:44::2' }
        }
        'nat-network' {
            $adapter = Adapter; $index = $adapter.ifIndex
            Get-NetIPAddress -InterfaceIndex $index | Where-Object { $_.IPAddress -in @('192.0.2.2','2001:db8:44::2') } | Remove-NetIPAddress -Confirm:$false
            Get-NetRoute -InterfaceIndex $index -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') -and $_.NextHop -in @('192.0.2.1','2001:db8:44::1') } | Remove-NetRoute -Confirm:$false
            Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Enabled
            Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -RouterDiscovery Enabled
            Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses
            & (Join-Path $env:SystemRoot 'System32\ipconfig.exe') /renew $adapter.Name | Out-Null
            if ($LASTEXITCODE) { throw 'QA uplink DHCP renewal failed' }
            $report.details = @{ interfaceIndex = $index; dhcp = $true }
        }
        'nrpt' { Run-Harness 'dns-nrpt-experiment.ps1' ('-HoldSeconds 45 -OutputDirectory "' + (Join-Path $private 'nrpt-results') + '"') }
        'service-stop' {
            $service = Get-Service -Name Vault443
            try { $service.Stop(); $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35)) } finally { $service.Dispose() }
            $report.details = @{ service = 'Vault443'; state = 'stopped' }
        }
        'service-start' {
            $service = Get-Service -Name Vault443
            try { $service.Start(); $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(35)) } finally { $service.Dispose() }
            $report.details = @{ service = 'Vault443'; state = 'running' }
        }
        'service-crash' { $daemon = Daemon; try { $report.details = @{ daemonPid = $daemon.Id }; $daemon.Kill() } finally { $daemon.Dispose() } }
        'engine-crash' {
            $daemon = Daemon
            try {
                $children = @(Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $daemon.Id))
                $chosen = @($children | Where-Object ExecutablePath -eq (Join-Path $app 'xray.exe'))
                if (!$chosen.Count) { $chosen = @($children | Where-Object { $_.ExecutablePath -in @((Join-Path $app 'vault443-tunnel.exe'),(Join-Path $app 'openvpn\openvpn.exe')) }) }
                if ($chosen.Count -ne 1) { throw 'No unambiguous daemon-owned VPN engine to crash' }
                $engine = [Diagnostics.Process]::GetProcessById([int]$chosen[0].ProcessId)
                try {
                    [void]$engine.Handle
                    $current = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $engine.Id)
                    if ($engine.HasExited -or $current.ParentProcessId -ne $daemon.Id -or $engine.MainModule.FileName -ne $chosen[0].ExecutablePath) { throw 'VPN engine identity changed' }
                    $report.details = @{ daemonPid = $daemon.Id; enginePid = $engine.Id; engine = [IO.Path]::GetFileName($engine.MainModule.FileName) }
                    $engine.Kill()
                } finally { $engine.Dispose() }
            } finally { $daemon.Dispose() }
        }
        'engine-crash-xray' { Crash-FixedEngine 'xray' }
        'engine-crash-outline' { Crash-FixedEngine 'outline' }
        'engine-crash-wireguard' { Crash-FixedEngine 'wireguard' }
        'engine-crash-amneziawg' { Crash-FixedEngine 'amneziawg' }
        'engine-crash-openvpn' { Crash-FixedEngine 'openvpn' }
        'network-down' { $adapter = Adapter; $adapter | Disable-NetAdapter -Confirm:$false; $report.details = @{ interfaceIndex = $adapter.ifIndex; requested = 'disabled' } }
        'network-up' { $adapter = Adapter; $adapter | Enable-NetAdapter -Confirm:$false; $report.details = @{ interfaceIndex = $adapter.ifIndex; requested = 'enabled' } }
        default {
            $phase = $Mode.Substring('installer-'.Length)
            Run-Harness 'installer-smoke.ps1' ('-Phase ' + $phase + ' -InstallerPath "' + (Join-Path $root $config.installer) + '" -InstallerSha256 ' + $config.installerSha256 + ' -OutputDirectory "' + (Join-Path $private 'installer-results') + '" -SkipGuiProbe')
        }
    }
    $report.passed = $true
} catch { $report.exceptionType = $_.Exception.GetType().FullName }
finally {
    $json = $report | ConvertTo-Json -Depth 6
    $path = Join-Path $reports ($stamp + '-' + $Mode + '.json')
    if (Test-Path -LiteralPath $path) { throw 'Refusing to overwrite an existing public report' }
    # CreateNew refuses a planted file. The report contains only allowlisted
    # facts/counts/log paths, never captured stdout or private store contents.
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $bytes = [Text.Encoding]::UTF8.GetBytes($json); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}
if (!$report.passed) { exit 1 }
