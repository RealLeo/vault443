#Requires -Version 5.1
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$InstallerSha256,
    [Parameter(Mandatory=$true)][string]$AppDirectory,
    [string]$OutputDirectory='C:\Program Files\Vault443QA\reports\upgrade-path-refusal'
)
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
if ($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11') -or
    !(Test-Path 'C:\ProgramData\Vault443-QA\marker') -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'VirtualBox') {
    throw 'A marked Vault443 Windows QA VM is required'
}
if ((Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash -ne $InstallerSha256) { throw 'Installer pin differs' }
$app=[IO.Path]::GetFullPath($AppDirectory).TrimEnd('\')
$target=Join-Path $env:ProgramFiles ('Vault443-MoveRefused-'+[Guid]::NewGuid().ToString('N'))
$out=Join-Path $OutputDirectory ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Force -Path $out | Out-Null
$r=[ordered]@{schema=1; version='1.3.5'; machine=$env:COMPUTERNAME; startedUTC=[DateTime]::UtcNow.ToString('o');
    installerSHA256=$InstallerSha256.ToLowerInvariant(); originalDirectory=$app; requestedDirectory=$target;
    checks=@(); completed=$false; passed=$false}
function Save { $r | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8 }
function Check([string]$Name,[bool]$Pass,$Observation=$null) {
    $r.checks+=@{check=$Name;passed=$Pass;observation=$Observation}; Save
    if (!$Pass) { throw ('Upgrade path refusal check failed: '+$Name) }
}
function Hashes([string]$Directory) {
    $values=@{}
    foreach ($file in Get-ChildItem -LiteralPath $Directory -Recurse -File -Force) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse input refused' }
        $values[$file.FullName.Substring($Directory.Length)]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    return $values
}
try {
    $before=Get-CimInstance Win32_Service -Filter "Name='Vault443'"
    Check 'service-running-before' ($before -and $before.State -eq 'Running' -and $before.ProcessId -gt 0)
    $files=Hashes $app
    $state=@{}
    foreach ($name in @('state.json','work-vpn.json')) {
        $path=Join-Path 'C:\ProgramData\Vault443' $name
        if (Test-Path -LiteralPath $path) { $state[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    }
    $acl=(Get-Acl -LiteralPath $app).Sddl
    $log=Join-Path $out 'installer.log'
    $p=Start-Process -FilePath $InstallerPath -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/DIR="'+$target+'"'),('/LOG="'+$log+'"')) -PassThru
    [void]$p.Handle
    if (!$p.WaitForExit(120000)) { throw 'Installer deadline exceeded; child retained for review' }
    Check 'installer-refused-location-change' ($p.ExitCode -ne 0) @{exitCode=$p.ExitCode}
    $p.Dispose()
    Check 'refusal-reason-is-location' ((Get-Content -LiteralPath $log -Raw) -match '(Updates keep the existing installation folder|Обновление сохраняет прежнюю папку установки)')
    $after=Get-CimInstance Win32_Service -Filter "Name='Vault443'"
    Check 'same-service-process-and-path' ($after.State -eq 'Running' -and $after.ProcessId -eq $before.ProcessId -and $after.PathName -ceq $before.PathName)
    Check 'no-second-location-created' (!(Test-Path -LiteralPath $target))
    Check 'original-directory-acl-retained' ((Get-Acl -LiteralPath $app).Sddl -ceq $acl)
    $current=Hashes $app; $changed=@()
    foreach ($name in $files.Keys) { if (!$current.ContainsKey($name) -or $files[$name] -cne $current[$name]) { $changed+=$name } }
    Check 'exact-original-payload-retained' ($current.Count -eq $files.Count -and $changed.Count -eq 0) @{files=$files.Count;changed=$changed.Count}
    $changed=@()
    foreach ($path in $state.Keys) { if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $state[$path]) { $changed+=$path } }
    Check 'private-profile-stores-retained' ($changed.Count -eq 0) @{stores=$state.Count;changed=$changed.Count}
    $r.passed=$true
} catch { $r.error=$_.Exception.Message; $r.errorLine=$_.InvocationInfo.ScriptLineNumber }
finally { $r.completed=$true; $r.finishedUTC=[DateTime]::UtcNow.ToString('o'); Save }
if (!$r.passed) { exit 1 }
