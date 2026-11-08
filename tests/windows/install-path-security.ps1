#Requires -Version 5.1
#Requires -RunAsAdministrator
# Run on a clean marked QA VM before installing either released candidate.
param(
    [Parameter(Mandatory=$true)][string]$DaemonPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$DaemonSha256,
    [string]$OutputDirectory = 'C:\Users\Public\Vault443Exchange\install-path-results',
    [string]$TestDrive = 'C:'
)
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11') -or
    !(Test-Path -LiteralPath 'C:\ProgramData\Vault443-QA\marker' -PathType Leaf) -or
    (Get-CimInstance Win32_ComputerSystem).Model -ne 'VirtualBox') {
    throw 'A marked Vault443 Windows QA VM is required'
}
if (Get-Service Vault443 -ErrorAction SilentlyContinue) { throw 'Use a clean VM before service installation' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B7547E6A-E316-4C92-9407-1B0F0D4A3443}_is1') { throw 'Uninstall previous product before fresh path tests' }
if ($TestDrive -notmatch '^[A-Za-z]:$' -or !(Test-Path ($TestDrive+'\'))) { throw 'Select an existing fixed test drive' }
if ((Get-FileHash -LiteralPath $DaemonPath -Algorithm SHA256).Hash -ne $DaemonSha256) { throw 'Daemon pin differs' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$token = [Guid]::NewGuid().ToString('N')
$root = $TestDrive+'\Vault443PathQA-'+$token
$report = Join-Path $OutputDirectory ($stamp+'-security.json')
$script:checks = New-Object 'System.Collections.Generic.List[object]'
$r = [ordered]@{schema=1; version='1.3.5'; startedUTC=[DateTime]::UtcNow.ToString('o'); machine=$env:COMPUTERNAME;
    daemonSHA256=$DaemonSha256.ToLowerInvariant(); root=$root; checks=@(); passed=$false; completed=$false; cleanup=$false}
function Save { $r.checks=@($script:checks.ToArray()); $r | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $report -Encoding UTF8 }
function Check([string]$Name, [bool]$Passed, $Observation=$null) {
    $script:checks.Add([ordered]@{check=$Name; passed=$Passed; observation=$Observation; utc=[DateTime]::UtcNow.ToString('o')}); Save
    if (!$Passed) { throw ('Path security check failed: '+$Name) }
}
function Native([string]$Operation, [string]$Path) {
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$DaemonPath; $start.WorkingDirectory=[IO.Path]::GetDirectoryName($DaemonPath); $start.Arguments='--'+$Operation+'="'+$Path+'"'
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.RedirectStandardError=$true; $start.RedirectStandardOutput=$true
    $p=[Diagnostics.Process]::Start($start)
    if (!$p.WaitForExit(30000)) { throw 'Bounded native helper wait expired' }
    $result=[ordered]@{exitCode=$p.ExitCode; stdout=$p.StandardOutput.ReadToEnd(); stderr=$p.StandardError.ReadToEnd()}
    $p.Dispose(); return $result
}
function ACL([string]$Path, [string]$Additional='') {
    $security=New-Object Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'+$Additional)
    Set-Acl -LiteralPath $Path -AclObject $security
}
function New-TestDirectory([string]$Path) { New-Item -ItemType Directory -Path $Path | Out-Null; ACL $Path }
try {
    Save
    $safe=$root+'\Папка с пробелами\Vault 443'
    $result=Native 'prepare-install-path' $safe
    Check 'fresh-cyrillic-space-path' ($result.exitCode -eq 0 -and (Test-Path -LiteralPath $safe -PathType Container)) $result
    Check 'fresh-explicit-admin-owner' ((Get-Acl -LiteralPath $safe).GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544')
    Check 'fresh-readonly-directory-validation' ((Native 'check-install-path' $safe).exitCode -eq 0)
    foreach ($bad in @('C:\','C:relative','\\server\share\Vault443','\\?\C:\Apps\Vault443','C:\Apps\..\Windows','C:\Apps\file:stream')) {
        $result=Native 'prepare-install-path' $bad
        Check ('ambiguous-or-network-'+$bad) ($result.exitCode -ne 0) $result
    }
    $foreign=$root+'\foreign'; New-TestDirectory $foreign
    $marker=Join-Path $foreign 'foreign.txt'; [IO.File]::WriteAllText($marker,'preserve-'+$token)
    $markerBefore=(Get-FileHash -LiteralPath $marker).Hash
    $before=(Get-Acl -LiteralPath $foreign).Sddl
    $result=Native 'prepare-install-path' $foreign
    Check 'nonempty-unregistered-target-refused' ($result.exitCode -ne 0 -and (Get-FileHash -LiteralPath $marker).Hash -eq $markerBefore -and (Get-Acl -LiteralPath $foreign).Sddl -eq $before) $result
    $unsafe=$root+'\unsafe-parent'; New-TestDirectory $unsafe; ACL $unsafe '(A;;0x40;;;BU)'
    $before=(Get-Acl -LiteralPath $unsafe).Sddl
    $result=Native 'prepare-install-path' ($unsafe+'\Vault443')
    Check 'untrusted-delete-child-parent-refused' ($result.exitCode -ne 0 -and !(Test-Path -LiteralPath ($unsafe+'\Vault443')) -and (Get-Acl -LiteralPath $unsafe).Sddl -eq $before) $result
    ACL $unsafe
    $unsafe=$root+'\unsafe-target'; New-TestDirectory $unsafe; ACL $unsafe '(A;;0x2;;;BU)'
    $before=(Get-Acl -LiteralPath $unsafe).Sddl
    $result=Native 'prepare-install-path' $unsafe
    Check 'untrusted-child-creation-target-refused' ($result.exitCode -ne 0 -and (Get-Acl -LiteralPath $unsafe).Sddl -eq $before) $result
    ACL $unsafe
    foreach ($right in @('0x10','0x100')) {
        $unsafe=$root+'\unsafe-metadata-'+$right; New-TestDirectory $unsafe; ACL $unsafe ('(A;;'+$right+';;;BU)')
        $before=(Get-Acl -LiteralPath $unsafe).Sddl
        $result=Native 'prepare-install-path' $unsafe
        Check ('untrusted-metadata-'+$right+'-refused') ($result.exitCode -ne 0 -and (Get-Acl -LiteralPath $unsafe).Sddl -eq $before) $result
        ACL $unsafe
    }
    $create=$root+'\create-only-parent'; New-TestDirectory $create; ACL $create '(A;;0x6;;;BU)'
    $before=(Get-Acl -LiteralPath $create).Sddl
    $result=Native 'prepare-install-path' ($create+'\Vault443')
    Check 'parent-unrelated-child-creation-allowed' ($result.exitCode -eq 0 -and (Get-Acl -LiteralPath $create).Sddl -eq $before -and (Native 'check-install-path' ($create+'\Vault443')).exitCode -eq 0) $result
    ACL $create
    $junction=$root+'\junction'
    & "$env:SystemRoot\System32\cmd.exe" /d /c ('mklink /J "'+$junction+'" "'+$foreign+'"') | Out-Null
    if ($LASTEXITCODE) { throw 'QA junction creation failed' }
    try {
        $result=Native 'prepare-install-path' ($junction+'\Vault443')
        Check 'junction-ancestor-refused' ($result.exitCode -ne 0 -and !(Test-Path -LiteralPath ($foreign+'\Vault443'))) $result
        Check 'recursive-reparse-refused' ((Native 'check-install-path' $root).exitCode -ne 0)
    } finally {
        & "$env:SystemRoot\System32\cmd.exe" /d /c ('rmdir "'+$junction+'"') | Out-Null
        if ($LASTEXITCODE) { throw 'QA junction cleanup failed' }
    }
    Check 'foreign-marker-retained' ((Get-FileHash -LiteralPath $marker).Hash -eq $markerBefore)
    Check 'scm-remains-unmodified' (!(Get-Service Vault443 -ErrorAction SilentlyContinue))
    $r.passed=$true
} catch { $r.error=$_.Exception.Message; $r.errorLine=$_.InvocationInfo.ScriptLineNumber }
finally {
    if (Test-Path -LiteralPath $root) {
        # Exact fresh token path only; all junctions were removed explicitly.
        $links=@(Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint})
        if ($links.Count -eq 0) { Remove-Item -LiteralPath $root -Recurse -Force }
    }
    $r.cleanup=!(Test-Path -LiteralPath $root); $r.completed=$true; $r.finishedUTC=[DateTime]::UtcNow.ToString('o'); Save
}
if (!$r.passed -or !$r.cleanup) { exit 1 }
