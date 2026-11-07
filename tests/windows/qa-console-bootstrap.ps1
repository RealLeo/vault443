#Requires -Version 5.1
# setup: explicit controller UAC. export: fixed SYSTEM task only.
param([ValidateSet('setup','export')][string]$Mode = 'setup')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = 'C:\Program Files\Vault443QA'
$private = 'C:\ProgramData\Vault443-QA'
$exporter = Join-Path $root 'qa-console-export.ps1'
$cmdPath = Join-Path $root 'diagnostic.cmd'
$stdoutPath = Join-Path $private 'console.stdout'
$stderrPath = Join-Path $private 'console.stderr'
$exe = 'C:\Program Files\Vault443\vault443d.exe'
if ($env:COMPUTERNAME -notin @('vault443-win10','vault443-win11') -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { throw 'Named VirtualBox QA VM required.' }
function Protected([string]$Path,[bool]$PrivatePath) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'QA reparse point refused.' }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Untrusted QA owner.' }
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(),0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'Null QA DACL.' }
    $mask = 0x500D0156; if ($PrivatePath) { $mask = $mask -bor 0x80000021 }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and (([long]$rule.FileSystemRights -band $mask) -ne 0)) { throw 'Untrusted QA access.' }
    }
}
Protected $root $false; Protected $private $true
Protected (Join-Path $private 'marker') $true; Protected (Join-Path $private 'qa-inputs.json') $true
Protected (Join-Path $root 'reports') $false
if ([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim() -ne 'Vault443 isolated Windows fixture') { throw 'Private QA marker missing.' }
$config = [IO.File]::ReadAllText((Join-Path $private 'qa-inputs.json')) | ConvertFrom-Json
if ($config.machine -ne $env:COMPUTERNAME) { throw 'Bound QA VM mismatch.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($Mode -eq 'export') {
    if ($identity.User.Value -ne 'S-1-5-18') { throw 'Export requires the fixed SYSTEM task.' }
    $frames = @(); $reason = 'No recognized Go fatal header in bounded private tails.'; $sourceReasons = [ordered]@{}
    $serviceLog = 'C:\ProgramData\Vault443\service.log'
    $blocks = @()
    function Private-Tail([string]$Path) {
        # Fixed byte and line budgets. Do not stream an unbounded growing log.
        $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            $count = [int][Math]::Min(2097152,$stream.Length)
            $start = $stream.Length-$count; [void]$stream.Seek($start,[IO.SeekOrigin]::Begin)
            $bytes = New-Object byte[] $count; $read = 0
            while ($read -lt $count) { $n=$stream.Read($bytes,$read,$count-$read); if(!$n){break}; $read+=$n }
            $lines = @([Text.Encoding]::UTF8.GetString($bytes,0,$read) -split '\r?\n')
            return @{lines=@($lines | Select-Object -Last 8000); bytes=$read; truncated=($start -gt 0 -or $lines.Count -gt 8000)}
        } finally { $stream.Dispose() }
    }
    function Crash-Header([string]$Line) {
        if ($Line -match '^panic:') {
            if ($Line -match '(send on closed channel|close of closed channel|assignment to entry in nil map|invalid memory address(?: or nil pointer dereference)?|index out of range|slice bounds out of range)') { return 'panic: '+$Matches[1] }
            return 'panic: [message omitted]'
        }
        if ($Line -match '^fatal error:') {
            if ($Line -match '(concurrent map writes|concurrent map iteration and map write|all goroutines are asleep - deadlock!|stack overflow|unexpected signal during runtime execution|traceback did not unwind completely|unexpected fault address)') { return 'fatal error: '+$Matches[1] }
            return 'fatal error: [message omitted]'
        }
        if ($Line -match '^(Exception 0x[0-9a-f]+(?:\s+0x[0-9a-f]+){0,5})\s*$') { return $Matches[1] }
        if ($Line -match '^(PC=0x[0-9a-f]+)(?:\s|$)') { return $Matches[1] }
        if ($Line -match '^runtime:') {
            if ($Line -match '(unexpected return pc|unknown pc|unexpected fault address|invalid pointer|stack split|stack growth|goroutine stack exceeds|morestack|cgocall|sigpanic)') { return 'runtime: '+$Matches[1] }
            return 'runtime: [message omitted]'
        }
        if ($Line -match '^signal arrived during (external code execution|cgo execution)$') { return $Line }
        if ($Line -match '^\[signal (SIGSEGV|SIGBUS|SIGABRT|SIGILL|SIGFPE)\b') { return '[signal '+$Matches[1]+'; other text omitted]' }
        return $null
    }
    foreach ($capturePath in @($stderrPath,$serviceLog)) {
        if (!(Test-Path -LiteralPath $capturePath)) { continue }
        Protected $capturePath $true
        $sourceTag = [IO.Path]::GetFileName($capturePath)
        $capture = Private-Tail $capturePath
        $lines = $capture.lines; $begin = -1; $fallback = -1
        for ($i=0;$i -lt $lines.Count;$i++) {
            # The LAST primary header starts the newest fatal block. Generic
            # runtime/PC headers are fallbacks, not boundaries inside its dump.
            if ($lines[$i] -match '^(panic:|fatal error:|Exception 0x)') { $begin=$i }
            elseif ($lines[$i] -match '^(PC=0x|runtime:)') { $fallback=$i }
        }
        if ($begin -lt 0) { $begin=$fallback }
        $blockFrames=@(); $headers=@()
        if ($begin -ge 0) {
            # Include contiguous leading signal/runtime metadata, never an
            # earlier goroutine dump from another failure.
            for ($n=0;$n -lt 16 -and $begin -gt 0;$n++) {
                if (!$lines[$begin-1].Trim() -or (Crash-Header $lines[$begin-1])) { $begin-- } else { break }
            }
        } else { $begin=0 }
        foreach ($line in @($lines | Select-Object -Skip $begin)) {
            $header=Crash-Header $line
            if ($header) { $headers+=$header; $blockFrames+=$header; continue }
            if ($line.Length -gt 4096) { continue }
            if ($line -match '^goroutine\s+([0-9]+)\b.*?\[([A-Za-z0-9 ,/;=._+\-]{1,120})\]:\s*$') { $blockFrames += ('goroutine '+$Matches[1]+' ['+$Matches[2]+']:'); continue }
            if ($line -match '^\s+(?:.*[\\/])?([A-Za-z0-9_.-]+\.(?:go|s|c|h)):([0-9]+)(.*)$') {
                $file=$Matches[1];$number=$Matches[2];$suffix=$Matches[3].Trim()
                # Source line suffix accepts only numeric offsets/addresses;
                # raw argument values and other free text are never exported.
                if ($suffix -match '^(?:\+0x[0-9a-f]+)?(?:\s*(?:fp|sp|pc)=0x[0-9a-f]+)*$') { $blockFrames += ($file+':'+$number+$(if($suffix){' '+$suffix}else{''})) }
                continue
            }
            $frame = $line; $created = $false
            if ($frame.StartsWith('created by ')) { $created = $true; $frame = $frame.Substring(11) -replace ' in goroutine [0-9]+$','' }
            $open = $frame.LastIndexOf('('); if ($open -gt 0 -and !$created) { $frame = $frame.Substring(0,$open) }
            if ($frame -match '^(main\.|vault443[/.]|runtime\.|internal/|sync[/.]|net[/.]|os[/.]|reflect\.|bufio\.|io[/.]|syscall[/.]|time\.|golang\.org/|github\.com/|golang\.zx2c4\.com/)' -and $frame -match '^[A-Za-z0-9_./*\[\]{}()+:<>-]+$') { $blockFrames += $(if ($created) {'created by ' + $frame.Substring(0,[Math]::Min(240,$frame.Length))} else {$frame.Substring(0,[Math]::Min(240,$frame.Length))}) }
        }
        $summary=if($headers.Count){$headers[0]}else{'No recognized Go fatal header in bounded tail.'}
        $sourceReasons[$sourceTag]=$summary
        $blocks+=@{source=$sourceTag;modified=(Get-Item -LiteralPath $capturePath).LastWriteTimeUtc;headerFound=($headers.Count -gt 0);reason=$summary;frames=$blockFrames;privateInputBytes=$capture.bytes;privateTailTruncated=$capture.truncated}
    }
    # The newest source comes first, including its header/current goroutine.
    # An older source with a recognized header cannot crowd out a newer dump.
    $ordered=@($blocks | Sort-Object @{Expression='modified';Descending=$true},@{Expression='headerFound';Descending=$true})
    if($ordered.Count){$reason=$ordered[0].reason}
    foreach($block in $ordered){$frames+='[source: '+$block.source+']';$frames+=@($block.frames)}
    $tail = @()
    if (Test-Path -LiteralPath $serviceLog) {
        Protected $serviceLog $true
        foreach ($line in @((Private-Tail $serviceLog).lines | Select-Object -Last 40)) {
            $stamp = if ($line -match '^([0-9/ :.-]{19})') {$Matches[1]} else {'timestamp omitted'}
            $category = 'message omitted'
            foreach ($word in @('panic','closed channel','DNS','NRPT','route','WFP','timeout','permission','certificate','OpenVPN','WireGuard')) { if ($line.IndexOf($word,[StringComparison]::OrdinalIgnoreCase) -ge 0) { $category = $word; break } }
            $tail += $stamp + ' [' + $category + '; raw message private]'
        }
    }
    $report = @{mode='console-stack-export';utc=[DateTime]::UtcNow.ToString('o');reason=$reason;sourceReasons=$sourceReasons;selectedSource=$(if($ordered.Count){$ordered[0].source}else{$null});inputBudgets=@{bytesPerSource=2097152;linesPerSource=8000};stack=@($frames | Select-Object -First 1800);stackTruncated=($frames.Count -gt 1800);serviceLogTail=$tail;privateStderr=$stderrPath;privateStdout=$stdoutPath}
    $json = $report | ConvertTo-Json -Depth 5
    while ([Text.Encoding]::UTF8.GetByteCount($json) -gt 131072 -and $report.stack.Count -gt 16) {
        $report.stack=@($report.stack | Select-Object -First ([Math]::Max(16,$report.stack.Count-100)));$report.stackTruncated=$true
        $json=$report | ConvertTo-Json -Depth 5
    }
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 131072) { throw 'Sanitized header metadata exceeds limit; private capture retained.' }
    $path = Join-Path (Join-Path $root 'reports') ('console-stack-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '.json')
    $stream = [IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $bytes = [Text.Encoding]::UTF8.GetBytes($json); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    return
}
if (!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Explicit controller UAC approval required.' }
$console = (Get-CimInstance Win32_ComputerSystem).UserName
if (!$console -or $config.controllerSID -ne $identity.User.Value -or ([Security.Principal.NTAccount]::new($console)).Translate([Security.Principal.SecurityIdentifier]).Value -ne $identity.User.Value) { throw 'Bound active console controller must approve with the same account.' }
$scheduler = New-Object -ComObject Schedule.Service; $scheduler.Connect()
foreach ($name in @('Vault443-QA-console-diagnostic','Vault443-QA-console-export')) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw 'Existing diagnostic task refused; no task is overwritten.' }
}
foreach ($path in @($cmdPath,$exporter,$stdoutPath,$stderrPath)) { if (Test-Path -LiteralPath $path) { Protected $path ($path.StartsWith($private)) } }
$cmdText = '@echo off' + "`r`n" + '"C:\Program Files\Vault443\vault443d.exe" --console 1>"C:\ProgramData\Vault443-QA\console.stdout" 2>"C:\ProgramData\Vault443-QA\console.stderr"' + "`r`nexit /b %errorlevel%`r`n"
[IO.File]::WriteAllText($cmdPath,$cmdText,[Text.Encoding]::ASCII)
[IO.File]::WriteAllBytes($exporter,[IO.File]::ReadAllBytes($PSCommandPath))
foreach ($path in @($cmdPath,$exporter)) {
    $security = New-Object Security.AccessControl.FileSecurity
    $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)')
    Set-Acl -LiteralPath $path -AclObject $security; Protected $path $false
}
$principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$actions = @((New-ScheduledTaskAction -Execute $cmd -Argument ('/d /c ""' + $cmdPath + '""')),(New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $exporter + '" -Mode export')))
$names = @('Vault443-QA-console-diagnostic','Vault443-QA-console-export')
for ($i=0;$i -lt 2;$i++) {
    Register-ScheduledTask -TaskName $names[$i] -Action $actions[$i] -Principal $principal -Settings $settings | Out-Null
    $scheduler.GetFolder('\').GetTask($names[$i]).SetSecurityDescriptor(('O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;' + $config.controllerSID + ')'),0)
}
$service = Get-Service -Name Vault443
try { if ($service.Status -ne 'Stopped') { $service.Stop(); $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) } } finally { $service.Dispose() }
$running = $scheduler.GetFolder('\').GetTask('Vault443-QA-console-diagnostic').Run($null)
Start-Sleep -Milliseconds 500
$daemon = @(Get-CimInstance Win32_Process -Filter "Name='vault443d.exe'" | Where-Object { $_.ExecutablePath -eq $exe -and $_.CommandLine -match '(?:^|\s)--console(?:\s|$)' } | Select-Object -ExpandProperty ProcessId)
@{mode='console-capture-started';taskInstance=$running.InstanceGuid;consolePIDs=$daemon;privateStderr=$stderrPath;privateStdout=$stdoutPath;exportTask='Vault443-QA-console-export';service='Stopped';limitSeconds=180} | ConvertTo-Json -Compress
