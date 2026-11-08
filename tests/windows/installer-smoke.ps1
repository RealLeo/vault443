# Elevated acceptance only. No host/foreign network resource is deleted by this
# harness; install/uninstall delegates to the exact reviewed Inno executable.
param(
    [ValidateSet('install','upgrade','uninstall','inspect')][string]$Phase = 'inspect',
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$InstallerSha256,
    [string]$InstallerPath = 'C:\Users\Public\Vault443Exchange\Vault443-1.3.5-windows-x64-setup.exe',
    [string]$AppDirectory = '',
    [string]$OutputDirectory = 'C:\Users\Public\Vault443Exchange\installer-results',
    [switch]$SkipGuiProbe
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11') -or !(Test-Path -LiteralPath 'C:\ProgramData\Vault443-QA\marker' -PathType Leaf)) {
    throw 'This acceptance script requires the marked Vault443 Windows QA VM'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this QA script elevated' }
$registration = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B7547E6A-E316-4C92-9407-1B0F0D4A3443}_is1'
if (!$AppDirectory) {
    $installed = Get-ItemProperty -LiteralPath $registration -ErrorAction SilentlyContinue
    if ($installed -and $installed.InstallLocation) { $AppDirectory = $installed.InstallLocation }
    else { $AppDirectory = Join-Path $env:ProgramFiles 'Vault443' }
}
$app = [IO.Path]::GetFullPath($AppDirectory).TrimEnd('\')
$data = Join-Path $env:ProgramData 'Vault443'
$private = 'C:\ProgramData\Vault443-QA\installer-private'
New-Item -ItemType Directory -Force -Path $private | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $identity = [Security.Principal.SecurityIdentifier]::new($sid)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
Set-Acl -LiteralPath $private -AclObject $acl
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$reportPath = Join-Path $OutputDirectory ($stamp + '-' + $Phase + '.json')
$logPath = Join-Path $OutputDirectory ($stamp + '-' + $Phase + '-inno.log')
$script:checks = New-Object 'System.Collections.Generic.List[object]'
$script:failed = $false; $script:completed = $false; $script:step = 'initialization'
function Save-Report {
    [ordered]@{ schema = 1; phase = $Phase; installerSha256 = $InstallerSha256.ToLowerInvariant();
        machine = $env:COMPUTERNAME; completed = $script:completed; passed = ($script:completed -and !$script:failed);
        utc = [DateTime]::UtcNow.ToString('o'); innoLog = $logPath; checks = @($script:checks.ToArray());
        guiProbeSkipped = [bool]$SkipGuiProbe;
        limits = @('Ordinary-user UAC/IPC, guard-failure abort and full protocol acceptance are separate checks. SYSTEM session0 cannot validate desktop GUI.')
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8
}
function Check([string]$Name, [bool]$Passed, [object]$Observation = $null) {
    $script:step = $Name
    $script:checks.Add([ordered]@{ check = $Name; passed = $Passed; utc = [DateTime]::UtcNow.ToString('o'); observation = $Observation })
    if (!$Passed) { $script:failed = $true }
    Save-Report
    if (!$Passed) { throw 'Installer acceptance check failed' }
}
function Read-PrivateJSON([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    if ((Get-Item -LiteralPath $Path).Length -gt 40MB) { throw 'Oversized private state' }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}
function Profile-IDs {
    $result = @{ main = @(); work = @() }
    foreach ($entry in @(@('main','state.json'), @('work','work-vpn.json'))) {
        $store = Read-PrivateJSON (Join-Path $data $entry[1])
        if ($store) {
            foreach ($user in $store.users.PSObject.Properties) {
                foreach ($profile in $user.Value.profiles) { $result[$entry[0]] += ($user.Name + '/' + $profile.id) }
            }
        }
        $result[$entry[0]] = @($result[$entry[0]] | Sort-Object -Unique)
    }
    return $result
}
function Preserved($Before, $After) {
    foreach ($kind in @('main','work')) {
        $missing = @($Before[$kind] | Where-Object { $_ -notin $After[$kind] })
        Check ('preserved-' + $kind + '-profiles') ($missing.Count -eq 0) @{ before = @($Before[$kind]).Count; after = @($After[$kind]).Count; missing = $missing.Count }
    }
}
function ACL-Safe([string]$Path, [bool]$PrivatePath) {
    if (!(Test-Path -LiteralPath $Path)) { return $false }
    if ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
    $security = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18','S-1-5-32-544')
    if (!$PrivatePath) {
        $trusted += ([Security.Principal.NTAccount]::new('NT SERVICE\TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($security.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { return $false }
    $mask = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    if ($PrivatePath) { $mask = $mask -bor [Security.AccessControl.FileSystemRights]::ReadData -bor [Security.AccessControl.FileSystemRights]::ExecuteFile }
    foreach ($rule in $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $rule.IdentityReference.Value -notin $trusted -and ($rule.FileSystemRights -band $mask)) { return $false }
    }
    return $true
}
function Service { Get-CimInstance Win32_Service -Filter "Name='Vault443'" }
function Native-Setup([string]$Executable) {
    $script:step = 'inno-' + $Phase
    $arguments = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/LOG="' + $logPath + '"'))
    if ($Phase -in @('install','upgrade')) { $arguments += '/DIR="' + $app + '"' }
    $process = Start-Process -FilePath $Executable -ArgumentList $arguments -PassThru
    [void]$process.Handle
    if (!$process.WaitForExit(180000)) { throw 'Installer exceeded the bounded QA wait; inspect its process and log' }
    Check 'inno-exit-code' ($process.ExitCode -eq 0) @{ exitCode = $process.ExitCode; log = $logPath }
}
function Installed {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $service = Service
        if ($service -and $service.State -eq 'Running') { break }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    Check 'service-running-system' ($service -and $service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem') @{ state = $service.State; account = $service.StartName }
    $expected = Join-Path $app 'vault443d.exe'
    if ($expected -match '[ \t]') { $expected = '"' + $expected + '"' }
    Check 'service-protected-path' ([string]::Equals($service.PathName,$expected,[StringComparison]::OrdinalIgnoreCase) -and (ACL-Safe $app $false) -and (ACL-Safe (Join-Path $app 'vault443d.exe') $false))
    $installed = Get-ItemProperty -LiteralPath $registration
    Check 'registered-path-and-publisher' ([string]::Equals([IO.Path]::GetFullPath($installed.InstallLocation).TrimEnd('\'),$app,[StringComparison]::OrdinalIgnoreCase) -and $installed.Publisher -eq 'Vault 443')
    $uiVersion = (Get-Item -LiteralPath (Join-Path $app 'vault443.exe')).VersionInfo
    Check 'gui-version-and-publisher' ($uiVersion.CompanyName -eq 'Vault 443' -and $uiVersion.ProductVersion -match '^1\.3\.5(\.0)?$') @{company=$uiVersion.CompanyName;version=$uiVersion.ProductVersion}
    Check 'private-programdata-acl' (ACL-Safe $data $true)
    foreach ($name in @('state.json','work-vpn.json')) {
        $path = Join-Path $data $name
        if (Test-Path -LiteralPath $path) { Check ('private-' + $name + '-acl') (ACL-Safe $path $true) }
    }
    $manifestPath = Join-Path $app 'build-manifest.json'
    $manifest = Read-PrivateJSON $manifestPath
    Check 'installed-build-manifest' ([bool]$manifest -and $manifest.platform -eq 'windows' -and $manifest.architecture -eq 'amd64')
    Check 'installed-build-identity' $true @{ manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant(); daemonSha256 = $manifest.backend.binaries.'vault443d.exe'; sourceSha256 = $manifest.source.sha256 }
    $required = @('vault443.exe','vault443d.exe','vault443-cli.exe','vault443-access.exe','vault443-tunnel.exe','vault443-outline.exe','xray.exe','wintun.dll','openvpn/openvpn.exe','openvpn/wintun.dll','Qt6Core.dll','Qt6Gui.dll','Qt6Widgets.dll','Qt6Network.dll','Qt6Qml.dll','Qt6Quick.dll','Qt6QuickControls2.dll','platforms/qwindows.dll','qml/QtQuick/Controls/qmldir','msvcp140.dll','vcruntime140.dll','vcruntime140_1.dll')
    $bad = 0
    foreach ($name in $required) {
        $path = Join-Path $app ($name -replace '/', '\')
        $record = $manifest.files.PSObject.Properties[$name]
        if (!$record -or !(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.Value.sha256) { $bad++ }
    }
    Check 'self-contained-runtime-hashes' ($bad -eq 0) @{ checkedFiles = $required.Count; invalidFiles = $bad }
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $app 'wintun.dll')
    Check 'official-wintun-signature' ($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Subject -match 'WireGuard') @{ status = [string]$signature.Status }
    if ($SkipGuiProbe) { return }
    # Demo has no service/credential access and exits after a screenshot. Strip
    # Qt SDK search paths so only the installed runtime can satisfy its imports.
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $app 'vault443.exe'; $start.WorkingDirectory = $app
    $shot = Join-Path $OutputDirectory ($stamp + '-installed-demo.png')
    $start.Arguments = '--demo --screenshot "' + $shot + '"'
    $start.UseShellExecute = $false
    $start.EnvironmentVariables['PATH'] = $app + ';' + (Join-Path $env:SystemRoot 'System32')
    foreach ($key in @($start.EnvironmentVariables.Keys)) { if ($key -like 'QT_*' -or $key -like 'QML*') { $start.EnvironmentVariables.Remove($key) } }
    $gui = [Diagnostics.Process]::Start($start)
    $outside = @(); $observed = @()
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        if ($gui.HasExited) { break }
        try {
            foreach ($module in $gui.Modules) {
                if ($module.ModuleName -like 'Qt6*.dll' -or $module.ModuleName -eq 'qwindows.dll') {
                    $observed += $module.ModuleName
                    if (!$module.FileName.StartsWith($app + '\', [StringComparison]::OrdinalIgnoreCase)) { $outside += $module.ModuleName }
                }
            }
        } catch { }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $naturalExit = $gui.HasExited
    if (!$naturalExit) { $gui.Kill(); [void]$gui.WaitForExit(3000) }
    Check 'gui-without-sdk-path' ($naturalExit -and $gui.ExitCode -eq 0 -and (Test-Path -LiteralPath $shot) -and $observed.Count -gt 0 -and $outside.Count -eq 0) @{ screenshot = $shot; observedQtModules = @($observed | Sort-Object -Unique); externalQtModules = @($outside | Sort-Object -Unique); cleanWithoutKnownQtSDK = !(Test-Path -LiteralPath 'C:\Vault443SDK') }
}

# Native read-only lookups cover exact filter keys, including boot-time keys
# omitted by ordinary firewall cmdlets. No WFP Delete API is exposed here.
if (!('VaultInstallerReadOnly' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class VaultInstallerReadOnly {
 [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);
 [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server, uint authn, IntPtr identity, IntPtr session, out IntPtr engine);
 [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
 [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr data);
 [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderGetByKey0(IntPtr engine, ref Guid key, out IntPtr data);
 [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr data);
 [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr data);
 public static uint InterfaceIndex(ulong luid) { uint index; return ConvertInterfaceLuidToIndex(ref luid, out index)==0 ? index : 0; }
 public static bool Exists(Guid key, int kind) {
  IntPtr engine; uint code=FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine);
  if(code!=0) throw new InvalidOperationException("WFP engine lookup failed");
  try {
   IntPtr data; code=kind==0 ? FwpmFilterGetByKey0(engine,ref key,out data) : kind==1 ? FwpmProviderGetByKey0(engine,ref key,out data) : FwpmSubLayerGetByKey0(engine,ref key,out data);
   if(code==0) { FwpmFreeMemory0(ref data); return true; }
   if(code==(kind==0 ? 0x80320003U : kind==1 ? 0x80320005U : 0x80320007U)) return false;
   throw new InvalidOperationException("WFP owned-object lookup failed");
  } finally { FwpmEngineClose0(engine); }
 }
}
'@
}
function Owned-Resources {
    return @{ routes = (Read-PrivateJSON (Join-Path $data 'windows-routes.json')); dns = (Read-PrivateJSON (Join-Path $data 'windows-dns.json')); wfp = (Read-PrivateJSON (Join-Path $data 'windows-wfp.json')) }
}
function Stable-WfpGUID([string]$Label) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('Vault443.Windows.WFP.1:' + $Label)) } finally { $sha.Dispose() }
    $hex = ([BitConverter]::ToString($bytes) -replace '-', '').Substring(0,32)
    return [Guid]::Parse($hex.Substring(0,8)+'-'+$hex.Substring(8,4)+'-'+$hex.Substring(12,4)+'-'+$hex.Substring(16,4)+'-'+$hex.Substring(20,12))
}
function Convert-WfpGuidText($Value) {
    if ($Value -is [string] -or $Value -is [Guid]) { return ([Guid]$Value).ToString('D') }
    # wf.RuleID is a named windows.GUID struct, not an encoding.TextMarshaler.
    # Its JSON representation contains numeric Data1/2/3 and eight Data4 bytes.
    $tail = @($Value.Data4)
    if ($null -eq $Value.Data1 -or $null -eq $Value.Data2 -or $null -eq $Value.Data3 -or $tail.Count -ne 8) {
        throw 'Invalid stored WFP GUID representation'
    }
    $text = '{0:x8}-{1:x4}-{2:x4}-{3:x2}{4:x2}-{5:x2}{6:x2}{7:x2}{8:x2}{9:x2}{10:x2}' -f
        [uint32]$Value.Data1, [uint16]$Value.Data2, [uint16]$Value.Data3,
        [byte]$tail[0], [byte]$tail[1], [byte]$tail[2], [byte]$tail[3],
        [byte]$tail[4], [byte]$tail[5], [byte]$tail[6], [byte]$tail[7]
    return ([Guid]$text).ToString('D')
}
function DNS-Normalized([string]$Text) { return ((($Text -split '[,;\s]+' | Where-Object { $_ }) | Sort-Object) -join ',').ToLowerInvariant() }
function Removed($Owned, $InstalledManifest) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do { $service = Service; if (!$service) { break }; Start-Sleep -Milliseconds 300 } while ([DateTime]::UtcNow -lt $deadline)
    Check 'service-removed' (!$service)
    $files = 0
    foreach ($file in $InstalledManifest.files.PSObject.Properties) { if (Test-Path -LiteralPath (Join-Path $app ($file.Name -replace '/', '\'))) { $files++ } }
    if (Test-Path -LiteralPath (Join-Path $app 'build-manifest.json')) { $files++ }
    Check 'application-removed' ($files -eq 0) @{ remainingOwnedFiles = $files }
    $remaining = Owned-Resources
    $routeCount = 0
    foreach ($owner in $remaining.routes.PSObject.Properties) { $routeCount += @($owner.Value).Count }
    Check 'route-manifest-empty' ($routeCount -eq 0) @{ remaining = $routeCount }
    $found = 0
    $table = @(Get-NetRoute -PolicyStore ActiveStore)
    foreach ($owner in $Owned.routes.PSObject.Properties) {
        foreach ($route in $owner.Value) {
            $index = [VaultInstallerReadOnly]::InterfaceIndex([uint64]$route.luid)
            if (!$index) { continue }
            $metric = if ($route.priority) {0} else {443}
            $found += @($table | Where-Object { $_.ifIndex -eq $index -and $_.DestinationPrefix -eq $route.prefix -and $_.NextHop -eq $route.gateway -and $_.RouteMetric -eq $metric }).Count
        }
    }
    Check 'owned-native-routes-removed' ($found -eq 0) @{ remaining = $found }
    Check 'dns-backups-empty' (@($remaining.dns.backups.PSObject.Properties).Count -eq 0)
    $badDNS = 0
    foreach ($entry in $Owned.dns.backups.PSObject.Properties) {
        $backup = $entry.Value; $family = if ($backup.ipv6) {'Tcpip6'} else {'Tcpip'}
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $family + '\Parameters\Interfaces\' + $backup.guid
        $current = (Get-ItemProperty -LiteralPath $key -Name NameServer -ErrorAction SilentlyContinue).NameServer
        if ((DNS-Normalized $current) -ne (DNS-Normalized $backup.nameServer)) { $badDNS++ }
    }
    Check 'original-static-dns-restored' ($badDNS -eq 0) @{ mismatches = $badDNS }
    $keys = @((@($Owned.wfp.ids) + @($remaining.wfp.ids)) | Where-Object { $null -ne $_ } |
        ForEach-Object { Convert-WfpGuidText $_ } | Sort-Object -Unique)
    $filters = 0
    foreach ($key in $keys) { if ([VaultInstallerReadOnly]::Exists([Guid]$key,0)) { $filters++ } }
    Check 'owned-wfp-filters-removed' ($filters -eq 0 -and @($remaining.wfp.parts.PSObject.Properties).Count -eq 0) @{ remainingFilters = $filters }
    $provider = [VaultInstallerReadOnly]::Exists((Stable-WfpGUID 'provider'),1)
    $sublayer = [VaultInstallerReadOnly]::Exists((Stable-WfpGUID 'sublayer'),2)
    Check 'owned-wfp-containers-removed' (!$provider -and !$sublayer) @{ providerPresent = $provider; sublayerPresent = $sublayer }
}
try {
    Check 'installer-sha256' ((Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash -eq $InstallerSha256)
    $before = Profile-IDs
    $owned = Owned-Resources
    @{ profiles = $before; resources = $owned } | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath (Join-Path $private ($stamp + '-' + $Phase + '-before.json')) -Encoding UTF8
    switch ($Phase) {
        'install' {
            Check 'clean-service-absent' (!(Service))
            Native-Setup $InstallerPath
            Installed
            Preserved $before (Profile-IDs)
        }
        'upgrade' {
            Check 'existing-service-present' ([bool](Service))
            Native-Setup $InstallerPath
            Installed
            Preserved $before (Profile-IDs)
        }
        'uninstall' {
            $uninstaller = Join-Path $app 'unins000.exe'
            Check 'protected-uninstaller' (ACL-Safe $uninstaller $false)
            $installedManifest = Read-PrivateJSON (Join-Path $app 'build-manifest.json')
            Check 'uninstall-build-manifest-present' ([bool]$installedManifest)
            Native-Setup $uninstaller
            Preserved $before (Profile-IDs)
            Removed $owned $installedManifest
        }
        'inspect' { Installed }
    }
} catch {
    $script:failed = $true
    $script:checks.Add(@{ check = $script:step; passed = $false; exceptionType = $_.Exception.GetType().FullName })
} finally { $script:completed = $true; Save-Report }
@{ passed = !$script:failed; report = $reportPath; innoLog = $logPath } | ConvertTo-Json -Compress
if ($script:failed) { exit 1 }
