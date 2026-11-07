# Run this reviewed bootstrap once after explicit UAC approval in the isolated
# Windows QA VM. No installed VPN binary or connection intent is changed.
param(
    [Parameter(Mandatory=$true)][string]$SourceDir,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$InstallerSha256,
    [ValidatePattern('^Vault443-[0-9]+\.[0-9]+\.[0-9]+-windows-x64-setup\.exe$')][string]$InstallerFileName = 'Vault443-1.3.4-windows-x64-setup.exe',
    [switch]$EnableEngineFaults,
    [ValidatePattern('^$|^[a-f0-9]{64}$')][string]$EngineFaultManifestSha256 = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11')) { throw 'Isolated Windows QA VM required' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Manual UAC approval is required' }
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { throw 'VirtualBox QA guest required' }
$consoleName = (Get-CimInstance Win32_ComputerSystem).UserName
if (!$consoleName) { throw 'An interactive QA administrator must approve bootstrap' }
$controllerSID = ([Security.Principal.NTAccount]::new($consoleName)).Translate([Security.Principal.SecurityIdentifier]).Value
if ($controllerSID -ne $identity.User.Value) { throw 'The active QA console administrator must approve bootstrap with the same account' }
# Optional fixed engine tasks pin the candidate before upgrade. They refuse use
# until that exact manifest and protected binaries are installed. No PID/path is
# accepted from an ordinary caller and no private profile is staged here.
$engineFaults = $null
if ($EnableEngineFaults) {
    if (!$EngineFaultManifestSha256) { throw 'Engine fault tasks require the independently recorded candidate manifest SHA-256' }
    $candidatePath = Join-Path $SourceDir 'build-manifest.json'
    $candidateItem = Get-Item -LiteralPath $candidatePath
    if ($candidateItem.PSIsContainer -or ($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $candidateItem.Length -gt 2MB -or (Get-FileHash -LiteralPath $candidatePath).Hash.ToLowerInvariant() -ne $EngineFaultManifestSha256) { throw 'Candidate engine-fault manifest identity differs' }
    $candidate = [IO.File]::ReadAllText($candidatePath) | ConvertFrom-Json
    $imageHashes = @{}
    foreach ($relative in @('vault443d.exe','xray.exe','vault443-outline.exe','vault443-tunnel.exe','openvpn/openvpn.exe')) {
        $sha = [string]$candidate.files.PSObject.Properties[$relative].Value.sha256
        if ($sha -notmatch '^[a-f0-9]{64}$') { throw 'Candidate manifest lacks a fixed engine identity' }
        $imageHashes[$relative] = $sha
    }
    $engineFaults = @{ schema=1; manifestSha256=$EngineFaultManifestSha256; images=$imageHashes }
} elseif ($EngineFaultManifestSha256) { throw 'Engine fault manifest SHA requires -EnableEngineFaults' }

$root = Join-Path $env:ProgramFiles 'Vault443QA'
$private = Join-Path $env:ProgramData 'Vault443-QA'
function Secure-Path([string]$Path, [bool]$Directory, [bool]$UsersRead) {
    if (Test-Path -LiteralPath $Path) {
        if ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'QA paths must not be reparse points' }
    } elseif ($Directory) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    $security = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-32-545')) {
        if ($sid -eq 'S-1-5-32-545' -and !$UsersRead) { continue }
        $rights = if ($sid -eq 'S-1-5-32-545') {'ReadAndExecute'} else {'FullControl'}
        $inherit = if ($Directory) {'ContainerInherit,ObjectInherit'} else {'None'}
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), $rights, $inherit, 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}
Secure-Path $root $true $true
Secure-Path $private $true $false
Secure-Path (Join-Path $root 'reports') $true $true
$marker = Join-Path $private 'marker'
[IO.File]::WriteAllText($marker, 'Vault443 isolated Windows fixture')
Secure-Path $marker $false $false
$required = @('qa-runner.ps1','installer-smoke.ps1','dns-nrpt-experiment.ps1','fixture-ca.crt',$InstallerFileName)
$optional = @('qa-bootstrap.ps1','main-matrix.ps1','main-smoke.ps1','work-smoke.ps1','openvpn-smoke.ps1')
$files = @{}
foreach ($name in $required + $optional) {
    $source = Join-Path $SourceDir $name
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) {
        if ($name -in $required) { throw ('Required QA input is missing: ' + $name) }
        continue
    }
    if ((Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'QA input is a reparse point' }
    $destination = Join-Path $root $name
    if (Test-Path -LiteralPath $destination) { Secure-Path $destination $false $true }
    [IO.File]::WriteAllBytes($destination, [IO.File]::ReadAllBytes($source))
    Secure-Path $destination $false $true
    $files[$name] = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
}
if ($files[$InstallerFileName] -ne $InstallerSha256.ToLowerInvariant()) { throw 'Exact installer SHA-256 did not match; no tasks registered' }
$adapters = @(Get-NetAdapter -Physical | Where-Object { $_.InterfaceDescription -notmatch 'Wintun|WireGuard|VPN' })
if ($adapters.Count -ne 1) { throw 'Expected exactly one isolated physical QA uplink' }
$config = @{ machine = $env:COMPUTERNAME; adapterGuid = [string]$adapters[0].InterfaceGuid; adapterMAC = $adapters[0].MacAddress;
    controllerSID = $controllerSID; installer = $InstallerFileName; installerSha256 = $InstallerSha256.ToLowerInvariant(); files = $files }
if ($engineFaults) { $config.engineFaults = $engineFaults }
$manifestPath = Join-Path $private 'qa-inputs.json'
[IO.File]::WriteAllText($manifestPath, ($config | ConvertTo-Json -Depth 6))
Secure-Path $manifestPath $false $false
# Remove only the known legacy QA entry points that executed mutable Public
# scripts. Non-QA tasks are never changed by this bootstrap.
$legacy = @('service','build-compiler','build-core','build-gui','build-package')
foreach ($suffix in $legacy) {
    $task = Get-ScheduledTask -TaskName ('Vault443-QA-' + $suffix) -ErrorAction SilentlyContinue
    if ($task -and @($task.Actions | Where-Object { $_.Arguments -match '\\Users\\Public\\' }).Count) {
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
    }
}
$modes = @('fixture-network','nat-network','nrpt','service-stop','service-start','service-crash','engine-crash','network-down','network-up','installer-inspect','installer-upgrade','installer-uninstall')
if ($EnableEngineFaults) { $modes += @('engine-crash-xray','engine-crash-outline','engine-crash-wireguard','engine-crash-amneziawg','engine-crash-openvpn') }
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$runner = Join-Path $root 'qa-runner.ps1'
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
foreach ($mode in $modes) {
    $name = 'Vault443-QA-' + $mode
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $runner + '" -Mode ' + $mode)
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $name -Action $action -Principal $taskPrincipal -Settings $settings -Force | Out-Null
    # The explicitly authorized QA console SID may read/run fixed actions even
    # with its filtered desktop token. It cannot modify the task or its DACL.
    # Ownership is Administrators, so the controller has no owner WRITE_DAC.
    # Standard qa2 receives no task access.
    $sddl = 'O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;' + $controllerSID + ')'
    $scheduler.GetFolder('\').GetTask($name).SetSecurityDescriptor($sddl,0)
}
& (Join-Path $env:SystemRoot 'System32\powercfg.exe') /change monitor-timeout-ac 0
if ($LASTEXITCODE) { throw 'Display timeout configuration failed' }
& (Join-Path $env:SystemRoot 'System32\powercfg.exe') /change standby-timeout-ac 0
if ($LASTEXITCODE) { throw 'Sleep timeout configuration failed' }
Set-TimeZone -Id 'UTC'
@{ bootstrap = 'complete'; protectedRunner = $runner; tasks = $modes.Count; installerSha256 = $files[$InstallerFileName] } | ConvertTo-Json -Compress
