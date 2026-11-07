# Temporary ordinary-console R6 acceptance; only existing fixed SYSTEM QA tasks.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$qa='C:\Program Files\Vault443QA';$exchange='C:\Users\Public\Vault443Exchange'
$main=Join-Path $exchange 'r6-protocols\main';$directory=Join-Path $exchange 'r6-service-faults'
$cli='C:\Program Files\Vault443\vault443-cli.exe';$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sha='9cedea599af02f8afe3434f2b7a56aa167075be4cd7ced21ef3dea924140bf25'
$report=[ordered]@{schema=1;startedUtc=[DateTime]::UtcNow.ToString('o');daemonSha256=$sha;completed=$false;passed=$false;restored=$false;steps=@();tasks=@();checks=@();errorType=$null;errorLine=0;limits=@('Crash recovery may precede probes; only the explicit SCM stop phase proves absence throughout probes.','Existing work smoke checks corporate IPv4/IPv6 and split DNS; it does not constitute a new complete leak matrix.')}
$script:knownDaemons=@();$script:knownEngines=@();$script:step='preflight';$changed=$false;$physicalIndex=0
New-Item -ItemType Directory -Force -Path $directory|Out-Null
$reportPath=Join-Path $directory 'result.json'
function Save {$script:report|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $reportPath -Encoding UTF8}
function Facts {
 $service=Get-CimInstance Win32_Service -Filter "Name='Vault443'"
 if($service.ProcessId-gt0){$script:knownDaemons=@($script:knownDaemons+[int]$service.ProcessId|Sort-Object -Unique)}
 $engines=@(Get-CimInstance Win32_Process -Filter "Name='xray.exe' OR Name='vault443-tunnel.exe' OR Name='openvpn.exe'"|Where-Object {$_.ParentProcessId-in$script:knownDaemons-or$_.ProcessId-in$script:knownEngines-or$_.ExecutablePath-in@('C:\Program Files\Vault443\xray.exe','C:\Program Files\Vault443\vault443-tunnel.exe','C:\Program Files\Vault443\openvpn\openvpn.exe')}|ForEach-Object {@{pid=[int]$_.ProcessId;parentPid=[int]$_.ParentProcessId;name=$_.Name}})
 $script:knownEngines=@($script:knownEngines+@($engines|ForEach-Object {$_.pid})|Sort-Object -Unique)
 return @{utc=[DateTime]::UtcNow.ToString('o');serviceState=$service.State;daemonPID=[int]$service.ProcessId;ownedEngines=$engines}
}
function Child([string]$Program,[string]$Arguments,[string]$InputText,[int]$Seconds,[bool]$RequireStopped=$false) {
 $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=$Program;$start.Arguments=$Arguments
 $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process;$p.StartInfo=$start;$stoppedThroughout=$true;$timer=[Diagnostics.Stopwatch]::StartNew()
 try {
  [void]$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
  if($InputText){$p.StandardInput.WriteLine($InputText)};$p.StandardInput.Close()
  do {
   if($RequireStopped-and(Get-Service Vault443).Status-ne'Stopped'){$stoppedThroughout=$false}
   $done=$p.WaitForExit(250)
   if($timer.Elapsed.TotalSeconds-gt$Seconds){$p.Kill();[void]$p.WaitForExit(2000);throw 'Existing helper exceeded deadline'}
  }while(!$done)
  $text=$out.GetAwaiter().GetResult();[void]$err.GetAwaiter().GetResult()
  if($RequireStopped){$f=Facts;$script:report.checks+=@{check='explicit-service-stopped-through-probes';utc=[DateTime]::UtcNow.ToString('o');passed=($stoppedThroughout-and$f.serviceState-eq'Stopped'-and!$f.ownedEngines.Count);beforeAfterOnlyEngineAbsence=$true;facts=$f};Save
   if(!$stoppedThroughout-or$f.serviceState-ne'Stopped'-or$f.ownedEngines.Count){throw 'Explicit service stop did not persist through probes'}}
  if($p.ExitCode-ne0){throw 'Existing helper failed; raw stdout/stderr intentionally omitted'}
  return $text
 }finally{$timer.Stop();$p.Dispose()}
}
function RPC([string]$Method) {$s=Child $cli $Method '[]' 8;if($s){return($s|ConvertFrom-Json)}}
function Snapshot {RPC GetSnapshot}
function Task([string]$Mode) {
 if($Mode-notin@('service-stop','service-start','service-crash','network-down','network-up')){throw 'Unexpected task mode'}
 $name='Vault443-QA-'+$Mode;$folder=$script:scheduler.GetFolder('\');$registered=$folder.GetTask($name)
 $definition=$registered.Definition
 $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $qa 'qa-runner.ps1')+'" -Mode '+$Mode
 if($definition.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$definition.Actions.Count-ne1-or$definition.Actions.Item(1).Path-ne$ps-or$definition.Actions.Item(1).Arguments-ne$arguments-or$registered.State-eq4){throw 'Fixed SYSTEM task identity/state differs'}
 $before=@(Get-ChildItem -LiteralPath (Join-Path $qa 'reports') -Filter ('*-'+$Mode+'.json')|ForEach-Object {$_.FullName})
 $started=[DateTime]::UtcNow;$deadline=$started.AddSeconds(55);[void]$registered.Run($null);$fresh=$null
 do {
  # Fresh registered task each poll: IRunningTask.State can remain stale.
  $current=$folder.GetTask($name)
  $fresh=@(Get-ChildItem -LiteralPath (Join-Path $qa 'reports') -Filter ('*-'+$Mode+'.json')|Where-Object {$_.FullName-notin$before-and$_.LastWriteTimeUtc-ge$started.AddSeconds(-1)}|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1)
  if($current.State-ne4-and$fresh.Count-eq1){break};Start-Sleep -Milliseconds 300
 }while([DateTime]::UtcNow-lt$deadline)
 if($fresh.Count-ne1-or$current.State-eq4){throw 'Fresh SYSTEM task report deadline exceeded'}
 $answer=Get-Content -LiteralPath $fresh[0].FullName -Raw|ConvertFrom-Json
 $record=@{mode=$Mode;startedUtc=$started.ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');reportPath=$fresh[0].FullName;taskState=[int]$current.State;lastTaskResult=[long]$current.LastTaskResult;passed=$answer.passed;reportUTC=$answer.utc;daemonPID=$answer.details.daemonPid;enginePID=$answer.details.enginePid;interfaceIndex=$answer.details.interfaceIndex}
 $script:report.tasks+=,$record;Save
 if($current.LastTaskResult-ne0-or!$answer.passed-or$answer.mode-ne$Mode-or[DateTime]::Parse($answer.utc).ToUniversalTime()-lt$started.AddSeconds(-1)){throw 'SYSTEM task result/report failed'}
 return $answer
}
function Step([string]$Name,[scriptblock]$Action) {
 $script:step=$Name;$item=[ordered]@{name=$Name;startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null;passed=$false;before=$null;after=$null;errorType=$null;errorLine=0}
 try {$item.before=Facts;&$Action;$item.after=Facts;$item.passed=$true}
 catch {$item.errorType=$_.Exception.GetType().FullName;$item.errorLine=$_.InvocationInfo.ScriptLineNumber;throw}
 finally {$item.finishedUtc=[DateTime]::UtcNow.ToString('o');$script:report.steps+=,$item;Save}
}
function Main-Harness([string]$Phase,[string]$Fault,[int]$Expected,[bool]$Stopped=$false) {
 $before=@(Get-ChildItem -LiteralPath $main -Filter ('*-'+$Phase+'-vless.json')|ForEach-Object {$_.FullName})
 $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $qa 'main-matrix.ps1')+'" -Phase '+$Phase+' -Protocol vless -Fault '+$Fault+' -ConnectTimeoutSeconds 90 -OutputDirectory "'+$main+'"'
 [void](Child $ps $arguments '' 150 $Stopped)
 $files=@(Get-ChildItem -LiteralPath $main -Filter ('*-'+$Phase+'-vless.json')|Where-Object {$_.FullName-notin$before}|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1)
 if($files.Count-ne1){throw 'Fresh main harness report missing'}
 $answer=Get-Content -LiteralPath $files[0].FullName -Raw|ConvertFrom-Json
 $ok=$answer.completed-and$answer.passed-and$answer.checks.Count-eq$Expected
 $script:report.checks+=@{check=($script:step+'-main-'+$Phase);utc=[DateTime]::UtcNow.ToString('o');reportPath=$files[0].FullName;passed=$ok;checks=$answer.checks.Count;expected=$Expected};Save
 if(!$ok){throw 'Main protection/recovery report failed'}
}
function Work-Verify {
 foreach($name in @('wireguard-multi','amneziawg')){[void](Child $ps ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $qa 'work-smoke.ps1')+'" -Profile '+$name+' -Phase verify -WaitSeconds 45') '' 100)}
 [void](Child $ps ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $qa 'openvpn-smoke.ps1')+'" -Profile openvpn -Phase verify -WaitSeconds 45') '' 100)
 $s=Snapshot
 foreach($name in @('wireguard-multi','amneziawg','openvpn')){$p=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$name));if($p.Count-ne1-or$p[0].runtime.state-ne'connected'){throw 'Restored work fixture is not connected'}}
 $script:report.checks+=@{check=($script:step+'-three-work-real-verification');utc=[DateTime]::UtcNow.ToString('o');passed=$true;mainID=$s.activeProfileId;guardArmed=$s.runtime.guardArmed;work=@($s.workProfiles|Where-Object {$_.runtime.state-eq'connected'}|ForEach-Object {@{id=$_.id;name=$_.name;state=$_.runtime.state;peers=@($_.runtime.peers|ForEach-Object {@{id=$_.id;state=$_.state}})}})};Save
}
try {
 Step 'preflight' {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$machine=Get-CimInstance Win32_ComputerSystem
  if(([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ordinary controller token required'}
  if($machine.Name-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$machine.Model-notmatch'^VirtualBox$'-or![Diagnostics.Process]::GetCurrentProcess().SessionId-or!$machine.UserName-or([Security.Principal.NTAccount]::new($machine.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value){throw 'Named VirtualBox active console account required'}
  if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha){throw 'Exact R6 daemon required'}
  $full=Get-Content (Join-Path $exchange 'r6-full-work\result.json') -Raw|ConvertFrom-Json
  if(!$full.completed-or!$full.passed-or!$full.restored){throw 'Full-work controller must finish successfully first'}
  $state=Get-Content (Join-Path $main 'state.json') -Raw|ConvertFrom-Json;$script:physicalIndex=[int]$state.baseline.interfaceIndex
  if(!$physicalIndex){throw 'Existing main baseline missing'}
  $s=Snapshot
  if($s.canAdmin-or$s.busyByOtherUser-or$s.runtime.state-ne'connected'-or!$s.runtime.guardArmed-or$s.activeProfileId-ne$state.profiles.vless){throw 'Connected own R6 VLESS required'}
  foreach($name in @('wireguard-multi','amneziawg','openvpn')){$p=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$name));if($p.Count-ne1-or$p[0].runtime.state-ne'connected'){throw 'Initial three connected work fixtures required'}}
  $script:scheduler=New-Object -ComObject Schedule.Service;$script:scheduler.Connect()
 }
 Step 'baseline-protection' {Main-Harness 'protection' 'engine-killed' 13}
 $changed=$true
 Step 'explicit-service-stop' {[void](Task 'service-stop');$f=Facts;if($f.serviceState-ne'Stopped'-or$f.daemonPID-ne0-or$f.ownedEngines.Count){throw 'SCM stop left an owned engine active'}}
 Step 'explicit-stopped-protection' {Main-Harness 'protection' 'service-killed' 13 $true}
 Step 'explicit-service-start-recovery' {[void](Task 'service-start');Main-Harness 'recovery' 'service-killed' 23;Work-Verify}
 Step 'service-crash-protection' {[void](Task 'service-crash');Main-Harness 'protection' 'service-killed' 13}
 Step 'service-crash-recovery' {Main-Harness 'recovery' 'service-killed' 23;Work-Verify}
 Step 'network-down-protection' {[void](Task 'network-down');Main-Harness 'protection' 'network-down' 13}
 Step 'network-up-recovery' {[void](Task 'network-up');Main-Harness 'recovery' 'network-restored' 23;Work-Verify}
 $report.passed=$true
}catch{$report.errorType=$_.Exception.GetType().FullName;$report.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally {
 if($changed){try{
  Step 'finally-network-and-service-if-needed' {
   $adapter=@(Get-NetAdapter -Physical|Where-Object ifIndex -eq $physicalIndex)
   if($adapter.Count-ne1){throw 'Original physical QA adapter missing'}
   if($adapter[0].Status-eq'Disabled'-or[string]$adapter[0].AdminStatus-eq'Down'){[void](Task 'network-up')}
   $service=Get-Service Vault443
   if($service.Status-eq'Stopped'){[void](Task 'service-start')}
   elseif($service.Status-ne'Running'){$service.WaitForStatus('Running',[TimeSpan]::FromSeconds(40))}
   $report.restored=$true
  }
 }catch{$report.passed=$false}}
 $report.completed=$true;$report.finishedUtc=[DateTime]::UtcNow.ToString('o');Save
}
@{passed=$report.passed;restored=$report.restored;report=$reportPath}|ConvertTo-Json -Compress
if(!$report.passed){exit 1}
