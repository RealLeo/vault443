#Requires -Version 5.1
#Requires -RunAsAdministrator
# Explicit controller UAC only. Fixed local standard account; no tasks or VPN changes.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$inputPath = 'C:\Users\Public\Vault443Exchange\qa2-password.input'
$root = 'C:\Program Files\Vault443QA'
$private = 'C:\ProgramData\Vault443-QA'
$journalPath = Join-Path $private 'qa-user-vaultqa2.json'
$report = [ordered]@{UTC=[DateTime]::UtcNow.ToString('o');Name='vaultqa2';Created=$false;Reused=$false;SID=$null;StandardUser=$false;InputDeleted=$false;Passed=$false;ErrorType=$null;ErrorCommand=$null;ErrorLine=0}
$cleanupInput = $false
$canReport = $false
function Protected([string]$Path,[bool]$PrivatePath) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'QA path is a reparse point.' }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Untrusted QA owner.' }
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'Null QA DACL.' }
    $mask = 0x500D0156
    if ($PrivatePath) { $mask = $mask -bor 0x80000021 }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and (([long]$rule.FileSystemRights -band $mask) -ne 0)) { throw 'Untrusted QA access.' }
    }
}
function Save-Journal {
    $temp = Join-Path $private ('.qa-user-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($journal | ConvertTo-Json -Compress))
        $stream = [IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        $security = New-Object Security.AccessControl.FileSecurity
        $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
        Set-Acl -LiteralPath $temp -AclObject $security
        if (Test-Path -LiteralPath $journalPath) { [IO.File]::Replace($temp,$journalPath,[NullString]::Value) } else { [IO.File]::Move($temp,$journalPath) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}
try {
    if ($env:COMPUTERNAME -notin @('vault443-win10','vault443-win11') -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { throw 'Named VirtualBox QA VM required.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Explicit UAC approval required.' }
    Protected $root $false; Protected $private $true
    Protected (Join-Path $private 'marker') $true; Protected (Join-Path $private 'qa-inputs.json') $true
    if ([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim() -ne 'Vault443 isolated Windows fixture') { throw 'Private QA marker missing.' }
    $config = [IO.File]::ReadAllText((Join-Path $private 'qa-inputs.json')) | ConvertFrom-Json
    $console = (Get-CimInstance Win32_ComputerSystem).UserName
    if (!$console -or $config.machine -ne $env:COMPUTERNAME -or $config.controllerSID -ne $identity.User.Value -or ([Security.Principal.NTAccount]::new($console)).Translate([Security.Principal.SecurityIdentifier]).Value -ne $identity.User.Value) { throw 'The bound console controller must approve UAC with the same account.' }
    Protected (Join-Path $root 'reports') $false
    $canReport = $true
    foreach ($path in @('C:\Users\Public','C:\Users\Public\Vault443Exchange',$inputPath)) {
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Password input must not traverse a reparse point.' }
    }
    $cleanupInput = $true
    $file = Get-Item -LiteralPath $inputPath
    if ($file.PSIsContainer -or $file.Length -lt 16 -or $file.Length -gt 512) { throw 'Bounded QA password input required.' }
    $inputACL = Get-Acl -LiteralPath $inputPath
    if ($inputACL.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544',$identity.User.Value)) { throw 'Password input has a foreign owner.' }
    $inputACL.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'); Set-Acl -LiteralPath $inputPath -AclObject $inputACL
    $plain = [IO.File]::ReadAllText($inputPath).TrimEnd([char[]]"`r`n")
    if ($plain.Length -lt 16 -or $plain.Length -gt 127 -or $plain.Contains("`r") -or $plain.Contains("`n") -or $plain.Contains([char]0)) { throw 'Invalid bounded QA password input.' }
    $password = ConvertTo-SecureString -String $plain -AsPlainText -Force
    $plain = $null
    $account = Get-LocalUser -Name 'vaultqa2' -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $journalPath) {
        Protected $journalPath $true
        if ((Get-Item -LiteralPath $journalPath).Length -gt 8192) { throw 'Invalid ownership journal.' }
        $journal = [IO.File]::ReadAllText($journalPath) | ConvertFrom-Json
        $token = [guid]::Empty
        if ($journal.Name -ne 'vaultqa2' -or $journal.Machine -ne $env:COMPUTERNAME -or $journal.ControllerSID -ne $identity.User.Value -or ![guid]::TryParse([string]$journal.Token,[ref]$token) -or $token -eq [guid]::Empty -or $journal.Phase -notin @('creating','created','active')) { throw 'Ownership journal does not match this controller/VM.' }
    } else {
        if ($account) { throw 'The existing vaultqa2 name is foreign; no account was changed.' }
        $journal = [pscustomobject]@{Name='vaultqa2';Machine=$env:COMPUTERNAME;ControllerSID=$identity.User.Value;Token=[Guid]::NewGuid().ToString('D');SID='';Phase='creating'}
        Save-Journal
    }
    $description = 'Vault443QA ' + $journal.Token
    if ($account) {
        if (!$journal.SID -or $account.SID.Value -ne $journal.SID -or $account.Description -cne $description) { throw 'Existing account SID/description does not match the private ownership journal.' }
        $report.Reused = $true
    } else {
        if ($journal.SID) { throw 'Previously owned SID disappeared; refusing to replace its identity.' }
        $account = New-LocalUser -Name 'vaultqa2' -Password $password -Description $description -ErrorAction Stop
        $journal.SID = $account.SID.Value; $journal.Phase = 'created'; Save-Journal
        $report.Created = $true
    }
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    if (@(Get-LocalGroupMember -SID $admins | Where-Object { $_.SID.Value -eq $account.SID.Value }).Count) { throw 'Owned QA account unexpectedly belongs to Administrators; no membership was rewritten.' }
    $beforeGroups = @(Get-LocalGroup | Where-Object { @(Get-LocalGroupMember -SID $_.SID | Where-Object { $_.SID.Value -eq $account.SID.Value }).Count } | ForEach-Object { $_.SID.Value })
    if (@($beforeGroups | Where-Object { $_ -ne 'S-1-5-32-545' }).Count -or !$account.Enabled) { throw 'Owned QA account has unexpected membership or is disabled.' }
    if ($report.Reused) { Set-LocalUser -SID $account.SID -Password $password -ErrorAction Stop }
    if (!@(Get-LocalGroupMember -SID $users | Where-Object { $_.SID.Value -eq $account.SID.Value }).Count) { Add-LocalGroupMember -SID $users -Member $account -ErrorAction Stop }
    $groups = @(Get-LocalGroup | Where-Object { @(Get-LocalGroupMember -SID $_.SID | Where-Object { $_.SID.Value -eq $account.SID.Value }).Count } | ForEach-Object { $_.SID.Value })
    if ($groups.Count -ne 1 -or $groups[0] -ne 'S-1-5-32-545') { throw 'QA account has unexpected local group membership.' }
    $journal.Phase = 'active'; Save-Journal
    $report.SID = $account.SID.Value; $report.StandardUser = $true; $report.Passed = $true
} catch {
    $report.ErrorType = $_.Exception.GetType().FullName
    $command = [IO.Path]::GetFileName([string]$_.InvocationInfo.MyCommand.Name)
    $report.ErrorCommand = if ($command -match '^[A-Za-z0-9_.-]{1,80}$') {$command} else {'unavailable'}
    $report.ErrorLine = [int]$_.InvocationInfo.ScriptLineNumber
}
finally {
    $plain = $null
    if ($password) { $password.Dispose() }
    if ($cleanupInput) { try {
        foreach ($path in @('C:\Users\Public','C:\Users\Public\Vault443Exchange',$inputPath)) { if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Cleanup path changed.' } }
        Remove-Item -LiteralPath $inputPath -Force -ErrorAction Stop; $report.InputDeleted = $true
    } catch { $report.Passed = $false; $report.ErrorType = 'PasswordInputCleanupFailed' } }
    if ($canReport) {
        $path = Join-Path (Join-Path $root 'reports') ('qa-user-vaultqa2-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '.json')
        $stream = [IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $bytes = [Text.Encoding]::UTF8.GetBytes(($report | ConvertTo-Json -Compress)); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    }
    $report | ConvertTo-Json -Compress
}
if (!$report.Passed) { throw 'QA standard-user bootstrap failed; inspect the sanitized report.' }
