# Ordinary-user A/B observations only. The fixed SYSTEM task owns NRPT cleanup.
# Run baseline, start, during, then after (repeat after while Result=pending).
# Waits are split across invocations; DNS uses QuickTimeout in this process.
[CmdletBinding()]
param(
    [ValidateSet('baseline','start','during','after')][string]$Phase = 'baseline',
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'Vault443\dns-nrpt-ordinary')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use the ordinary filtered console token, not an elevated shell.' }
if ($env:COMPUTERNAME -notin @('vault443-win10','vault443-win11') -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { throw 'Named VirtualBox QA guest required.' }
if (-not ('Vault443NrptConsole' -as [type])) {
    Add-Type 'using System.Runtime.InteropServices; public static class Vault443NrptConsole { [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId(); }'
}
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
if ($session -eq 0 -or $session -ne [Vault443NrptConsole]::WTSGetActiveConsoleSessionId()) { throw 'Use the active local console session.' }
$qaRoot = 'C:\Program Files\Vault443QA'
$runner = Join-Path $qaRoot 'qa-runner.ps1'
foreach ($path in @($qaRoot,$runner)) {
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($path -eq $qaRoot -and !$item.PSIsContainer) -or ($path -eq $runner -and $item.PSIsContainer)) { throw 'QA runner/root must be a regular file/directory without reparse points.' }
    $acl = Get-Acl -LiteralPath $path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'QA runner/root owner is not SYSTEM/Administrators.' }
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'QA runner/root has a null DACL.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and (([long]$rule.FileSystemRights -band 0x500D0156) -ne 0)) { throw 'QA runner/root permits untrusted writes.' }
    }
}
[IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$statePath = Join-Path $OutputDirectory 'ordinary.state.json'
$report = [ordered]@{Phase=$Phase; UTC=[DateTime]::UtcNow.ToString('o'); Result='initializing'; UserSID=$identity.User.Value; SessionId=$session; Queries=@(); CleanupOwner='Fixed SYSTEM task finally block; this script never edits NRPT or adapter DNS.'; TransportNote='TcpOnly=false uses normal Windows UDP/default resolution, including its normal fallback behavior.'}
$state = $null
function Save-State { $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8 }
function Main-Connected {
    # Bound the read-only CLI independently of its own 60-second IPC timeout.
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = 'C:\Program Files\Vault443\vault443-cli.exe'; $info.Arguments = 'GetSnapshot'
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine('[]'); $process.StandardInput.Close()
        if (!$process.WaitForExit(3000)) { $process.Kill(); throw 'Read-only GetSnapshot exceeded 3 seconds.' }
        if ($process.ExitCode) { throw 'GetSnapshot failed; enroll the console user explicitly before this experiment.' }
        $snapshot = $stdout.Result | ConvertFrom-Json
        if ($snapshot.runtime.state -ne 'connected' -or $snapshot.busyByOtherUser -or !$snapshot.activeProfileId) { throw 'The ordinary console user must own a connected main VPN.' }
        if ($null -ne $state -and $snapshot.activeProfileId -ne $state.MainProfileId) { throw 'The main VPN profile changed since baseline.' }
        return [ordered]@{State=[string]$snapshot.runtime.state; MainProfileId=[string]$snapshot.activeProfileId; GuardArmed=[bool]$snapshot.runtime.guardArmed}
    } finally { $process.Dispose() }
}
function CatchAll-Policy {
    return @(Get-DnsClientNrptPolicy -Effective | Where-Object { @($_.Namespace) -contains '.' } | Select-Object Namespace,NameServers)
}
function Loopback-Policy($Rules) {
    if (@($Rules).Count -ne 1) { return $false }
    $servers = @((@($Rules[0].NameServers) -join ',') -split '[,;\s]+' | Where-Object { $_ } | Sort-Object -Unique)
    return $servers.Count -eq 2 -and $servers -contains '127.0.0.1' -and $servers -contains '::1'
}
function Queries {
    $report.QueryExecution = 'Same-process sequential Resolve-DnsName -QuickTimeout; no background workers'
    foreach ($type in @('A','AAAA')) {
        foreach ($tcp in @($false,$true)) {
            $name = 'ordinary-' + [Guid]::NewGuid().ToString('N') + '.webdual.e2e.example.com'
            $expected = if ($type -eq 'A') {'93.184.215.14'} else {'2001:db8:66::14'}
            $result = [ordered]@{Name=$name;Type=$type;TcpOnly=$tcp;UTC=[DateTime]::UtcNow.ToString('o');Expected=$expected;Addresses=@();Passed=$false;ErrorId=$null;DurationMilliseconds=0}
            $elapsed = [Diagnostics.Stopwatch]::StartNew()
            try {
                $options = @{Name=$name;Type=$type;DnsOnly=$true;NoHostsFile=$true;QuickTimeout=$true;ErrorAction='Stop'}
                if ($tcp) { $options.TcpOnly = $true }
                $result.Addresses = @(Resolve-DnsName @options | Where-Object IPAddress | Select-Object -ExpandProperty IPAddress)
                $result.Passed = $result.Addresses -contains $expected
            } catch { $result.ErrorId = $_.FullyQualifiedErrorId }
            finally { $elapsed.Stop(); $result.DurationMilliseconds = $elapsed.ElapsedMilliseconds }
            $report.Queries += [pscustomobject]$result
        }
    }
    $report.AllQueriesPassed = $report.Queries.Count -eq 4 -and @($report.Queries | Where-Object { !$_.Passed }).Count -eq 0
}

try {
    if ($Phase -ne 'baseline') {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.UserSID -ne $identity.User.Value -or $state.SessionId -ne $session) { throw 'Saved baseline belongs to another user/session.' }
    }
    $report.MainBefore = Main-Connected
    $scheduler = New-Object -ComObject Schedule.Service
    $scheduler.Connect(); $task = $scheduler.GetFolder('\').GetTask('Vault443-QA-nrpt')
    $definition = $task.Definition
    $expectedArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $runner + '" -Mode nrpt'
    if ($definition.Principal.UserId -notin @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -or $definition.Principal.LogonType -ne 5 -or $definition.Actions.Count -ne 1 -or $definition.Actions.Item(1).Path -ne (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -or $definition.Actions.Item(1).Arguments -ne $expectedArgs) { throw 'The fixed QA NRPT task definition differs from the protected SYSTEM runner.' }
    $report.PolicyBefore = @(CatchAll-Policy)
    if ($Phase -eq 'baseline') {
        if ($task.State -in @(2,4) -or $report.PolicyBefore.Count) { throw 'Baseline requires the fixed task idle and no effective catch-all NRPT policy.' }
        $state = [pscustomobject]@{UserSID=$identity.User.Value;SessionId=$session;MainProfileId=$report.MainBefore.MainProfileId;BaselineUTC=[DateTime]::UtcNow.ToString('o');StartedUTC='';CleanupConfirmed=$false}
        Queries; Save-State
    } elseif ($Phase -eq 'start') {
        if ($state.StartedUTC -or $task.State -in @(2,4) -or $report.PolicyBefore.Count) { throw 'This baseline already started or another catch-all experiment is active.' }
        $instance = $task.Run($null)
        $state.StartedUTC = [DateTime]::UtcNow.ToString('o'); Save-State
        $report.TaskInstance = $instance.InstanceGuid
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            $policy = @(CatchAll-Policy)
            if (Loopback-Policy $policy) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        $report.EffectiveLoopback = Loopback-Policy $policy
        if (!$report.EffectiveLoopback) { throw 'The fixed task did not expose effective loopback catch-all policy within 20 seconds; inspect its SYSTEM report.' }
    } elseif ($Phase -eq 'during') {
        if (!$state.StartedUTC -or $state.CleanupConfirmed -or $task.State -notin @(2,4) -or !(Loopback-Policy $report.PolicyBefore)) { throw 'During requires the active loopback catch-all from the running fixed experiment.' }
        Queries
    } elseif ($Phase -eq 'after') {
        if (!$state.StartedUTC) { throw 'Start the fixed experiment before requesting cleanup confirmation.' }
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $policy = @(CatchAll-Policy)
            $clean = $task.State -notin @(2,4) -and $policy.Count -eq 0
            if ($clean) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        if (!$clean) {
            if (([DateTime]::UtcNow - [DateTime]::Parse($state.StartedUTC)).TotalSeconds -gt 100) { throw 'SYSTEM task/rule cleanup did not finish within 100 seconds. No rules were changed by this observer.' }
            $report.Result = 'pending'; $report.Note = 'Re-run after; cleanup belongs to the SYSTEM task finally block.'
        } else { $state.CleanupConfirmed = $true; Save-State; $report.CleanupConfirmed = $true; Queries }
    }
    $report.PolicyAfter = @(CatchAll-Policy)
    if ($Phase -in @('baseline','after') -and $report.Result -ne 'pending' -and $report.PolicyAfter.Count) { throw 'A catch-all policy appeared during the no-NRPT phase; observations are retained without claiming a clean window.' }
    if ($Phase -eq 'during' -and !(Loopback-Policy $report.PolicyAfter)) { throw 'The catch-all disappeared during queries; results are retained but this is not a complete during window.' }
    $report.MainAfter = Main-Connected
    $report.TaskState = $task.State; $report.TaskLastResult = $task.LastTaskResult
    if ($report.Result -ne 'pending') { $report.Result = 'observed' }
} catch { $report.Result = 'failed'; $report.Error = $_.Exception.Message }
finally {
    $path = Join-Path $OutputDirectory ('ordinary-' + $Phase + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '.json')
    $report.ReportFile = $path
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
    $report | ConvertTo-Json -Depth 10
}
if ($report.Result -eq 'failed') { throw $report.Error }
