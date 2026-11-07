# Ordinary active-console QA. Crashes one fixed pinned daemon-owned engine via
# its protected SYSTEM task; never imports, connects, disconnects or selects PID.
param(
 [Parameter(Mandatory=$true)][ValidateSet('xray','outline','wireguard','amneziawg','openvpn')][string]$Engine,
 [ValidateSet('vless','trojan','shadowsocks','outline')][string]$Protocol='vless',
 [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedBackendSha256='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Net.WebRequest]::DefaultWebProxy=$null
if($Engine-eq'outline'){
 if($PSBoundParameters.ContainsKey('Protocol')-and$Protocol-ne'outline'){throw 'Outline helper requires the Outline main profile'}
 $Protocol='outline'
}
$q='C:\Program Files\Vault443QA';$x='C:\Users\Public\Vault443Exchange';$cli='C:\Program Files\Vault443\vault443-cli.exe'
$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe';$main=Join-Path $x 'r8-protocols\main';$dir=Join-Path $x 'r8-outputs\engine-faults'
New-Item -ItemType Directory -Force -Path $dir|Out-Null
$reportPath=Join-Path $dir ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+$Engine+'-'+$Protocol+'.json')
$r=[ordered]@{schema=1;engine=$Engine;protocol=$Protocol;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;daemonSHA=$ExpectedBackendSha256;initial=$null;target=$null;task=$null;checks=@();errorType=$null;errorLine=0;noConnectOrResetRequested=$true;limits=@('Root owns continuous packet capture and its matching physical positive controls.','Automatic recovery may finish before ordinary protection probes; the protected task separately confirms exact child termination.','One requested WG or AWG across all users is required because both use the same private-stdin executable.','This helper never starts a VPN or restores failed connection intent on its own.')}
function Save{$script:r|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $reportPath -Encoding UTF8}
function Check([string]$Name,[bool]$Passed,$Observation=$null){$script:r.checks+=@{check=$Name;passed=$Passed;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation};Save;if(!$Passed){throw 'Engine fault acceptance failed; inspect sanitized report'}}
function Child([string]$Program,[string]$Arguments,[string]$InputText,[int]$Seconds){
 $i=New-Object Diagnostics.ProcessStartInfo;$i.FileName=$Program;$i.Arguments=$Arguments;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardInput=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process;$p.StartInfo=$i
 try{[void]$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();if($InputText){$p.StandardInput.WriteLine($InputText)};$p.StandardInput.Close();if(!$p.WaitForExit($Seconds*1000)){$p.Kill();[void]$p.WaitForExit(2000);throw 'Bounded engine QA child deadline'};$text=$out.GetAwaiter().GetResult();[void]$err.GetAwaiter().GetResult();if($p.ExitCode-ne0){throw 'Existing helper failed; raw output omitted'};return $text}finally{$p.Dispose()}
}
function Snapshot{(Child $cli 'GetSnapshot' '[]' 8)|ConvertFrom-Json}
function DaemonIdentity{$svc=Get-CimInstance Win32_Service -Filter "Name='Vault443'";$proc=Get-CimInstance Win32_Process -Filter ('ProcessId='+$svc.ProcessId);if($svc.State-ne'Running'-or$svc.StartName-ne'LocalSystem'-or!$proc.CreationDate){throw 'Running LocalSystem SCM identity required'};return @{pid=[int]$svc.ProcessId;created=$proc.CreationDate.ToUniversalTime().ToString('o')}}
function Assert-Owner($s){$now=DaemonIdentity;Check 'same-daemon-owner-and-main-intent' ($now.pid-eq$r.initial.daemon.pid-and$now.created-eq$r.initial.daemon.created-and!$s.busyByOtherUser-and!$s.canAdmin-and$s.activeProfileId-eq$r.initial.mainID-and$s.runtime.guardArmed) @{daemon=$now;mainID=$s.activeProfileId;mainState=$s.runtime.state;guard=$s.runtime.guardArmed}}
function Main-Harness([string]$Phase){
 $before=@(Get-ChildItem -LiteralPath $main -Filter ('*-'+$Phase+'-'+$Protocol+'.json')|ForEach-Object {$_.FullName})
 $started=[DateTime]::UtcNow
 [void](Child $ps ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$q+'\main-matrix.ps1" -Phase '+$Phase+' -Protocol '+$Protocol+' -Fault engine-killed -ConnectTimeoutSeconds 90 -OutputDirectory "'+$main+'"') '' 150)
 $fresh=@(Get-ChildItem -LiteralPath $main -Filter ('*-'+$Phase+'-'+$Protocol+'.json')|Where-Object {$_.FullName-notin$before-and$_.LastWriteTimeUtc-ge$started.AddSeconds(-1)}|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1)
 if($fresh.Count-ne1){throw 'Fresh main fault report missing'};$answer=Get-Content -LiteralPath $fresh[0].FullName -Raw|ConvertFrom-Json
 $expected=if($Phase-eq'protection'){13}elseif($Phase-eq'recovery'){23}else{22}
 Check ('main-'+$Phase+'-real-checks') ($answer.completed-and$answer.passed-and$answer.checks.Count-eq$expected) @{report=$fresh[0].FullName;checks=$answer.checks.Count}
}
function Work-Verify($Profile){
 if($Profile.kind-eq'openvpn'-and$Profile.name-eq'Vault443 Fixture openvpn'){$file='openvpn-smoke.ps1';$arguments='-Profile openvpn'}
 elseif($Profile.kind-eq'amneziawg'-and$Profile.name-eq'Vault443 Fixture amneziawg'){$file='work-smoke.ps1';$arguments='-Profile amneziawg'}
 elseif($Profile.kind-eq'wireguard'-and$Profile.name-in@('Vault443 Fixture wireguard','Vault443 Fixture wireguard-multi')){$file='work-smoke.ps1';$arguments='-Profile '+$Profile.name.Substring('Vault443 Fixture '.Length)}
 else{throw 'Only the known split work fixtures may participate in this fault controller'}
 [void](Child $ps ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $q $file)+'" '+$arguments+' -Phase verify -WaitSeconds 45') '' 100)
 Check ('work-real-recovery-'+$Profile.kind+'-'+$Profile.id) $true @{profileID=$Profile.id;kind=$Profile.kind;helper=$file}
}
function Fixed-Task{
 $mode='engine-crash-'+$Engine;$name='Vault443-QA-'+$mode;$folder=$scheduler.GetFolder('\');$task=$folder.GetTask($name);$d=$task.Definition
 $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$q+'\qa-runner.ps1" -Mode '+$mode
 if($d.Principal.UserId-notin@('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18')-or$d.Actions.Count-ne1-or$d.Actions.Item(1).Path-ne$ps-or$d.Actions.Item(1).Arguments-ne$arguments-or$task.State-in@(2,4)){throw 'Fixed SYSTEM engine task identity/state differs'}
 $before=@(Get-ChildItem -LiteralPath (Join-Path $q 'reports') -Filter ('*-'+$mode+'.json')|ForEach-Object {$_.FullName});$started=[DateTime]::UtcNow;$end=$started.AddSeconds(55)
 [void]$task.Run($null)
 do{$freshTask=$folder.GetTask($name);$files=@(Get-ChildItem -LiteralPath (Join-Path $q 'reports') -Filter ('*-'+$mode+'.json')|Where-Object {$_.FullName-notin$before-and$_.LastWriteTimeUtc-ge$started.AddSeconds(-1)}|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1);if($freshTask.State-notin@(2,4)-and$files.Count-eq1){break};Start-Sleep -Milliseconds 250}while([DateTime]::UtcNow-lt$end)
 if($freshTask.State-in@(2,4)-or$files.Count-ne1){throw 'Fresh fixed engine task report deadline'}
 $answer=Get-Content -LiteralPath $files[0].FullName -Raw|ConvertFrom-Json
 $r.task=@{mode=$mode;path=$files[0].FullName;startedUTC=$started.ToString('o');lastTaskResult=[long]$freshTask.LastTaskResult;passed=$answer.passed;details=$answer.details};Save
 Check 'exact-fixed-engine-terminated' ($freshTask.LastTaskResult-eq0-and$answer.passed-and$answer.mode-eq$mode-and[DateTime]::Parse($answer.utc).ToUniversalTime()-ge$started.AddSeconds(-1)-and$answer.details.selector-eq$Engine-and$answer.details.profileID-eq$r.target.id-and$answer.details.family-eq$r.target.kind-and$answer.details.daemonPid-eq$r.initial.daemon.pid-and$answer.details.terminationConfirmed) $r.task
}
try{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$computer=Get-CimInstance Win32_ComputerSystem
 if(([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or$env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$computer.Model-ne'VirtualBox'-or![Diagnostics.Process]::GetCurrentProcess().SessionId-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$id.User.Value){throw 'Ordinary active-console QA controller required'}
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$ExpectedBackendSha256){throw 'Exact candidate daemon required'}
 $state=Get-Content (Join-Path $main 'state.json') -Raw|ConvertFrom-Json;$s=Snapshot;$profile=@($s.profiles|Where-Object id -eq $s.activeProfileId)
 # Outline is a Shadowsocks profile with extended transport metadata, not a Kind.
 $expectedKind=if($Protocol-eq'outline'){'shadowsocks'}else{$Protocol}
 $outlineMatches=$Protocol-ne'outline'-or($profile.Count-eq1-and$profile[0].transport-eq'outline'-and$profile[0].source.kind-eq'outline')
 if($s.canAdmin-or$s.busyByOtherUser-or$s.runtime.state-ne'connected'-or!$s.runtime.guardArmed-or$profile.Count-ne1-or$profile[0].kind-ne$expectedKind-or!$outlineMatches-or$s.activeProfileId-ne$state.profiles.PSObject.Properties[$Protocol].Value){throw 'Own connected main fixture and matching R8 baseline required'}
 $r.initial=@{machine=$env:COMPUTERNAME;sid=$id.User.Value;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;daemon=(DaemonIdentity);mainID=$s.activeProfileId;mainKind=$profile[0].kind;work=@($s.workProfiles|Where-Object {$_.runtime.state-ne'disconnected'}|Select-Object id,kind,name)}
 if($Engine-in@('xray','outline')){$r.target=@{id=$s.activeProfileId;kind=$profile[0].kind}}
 else{
  $group=if($Engine-in@('wireguard','amneziawg')){@('wireguard','amneziawg')}else{@('openvpn')}
  $active=@($s.workProfiles|Where-Object {$_.kind-in$group-and$_.runtime.state-ne'disconnected'})
  if($active.Count-ne1-or$active[0].kind-ne$Engine-or$active[0].runtime.state-ne'connected'){throw 'Exactly one connected selected work engine required; explicitly stop the other WG/AWG first'}
  $r.target=@{id=$active[0].id;kind=$active[0].kind}
 }
 Save
 Main-Harness 'verify'
 foreach($work in $r.initial.work){Work-Verify $work}
 $scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect()
 Fixed-Task
 Main-Harness 'protection'
 Assert-Owner (Snapshot)
 Main-Harness 'recovery'
 foreach($work in $r.initial.work){Work-Verify $work}
 $after=Snapshot;Assert-Owner $after
 foreach($work in $r.initial.work){Check ('work-profile-still-connected-'+$work.id) (@($after.workProfiles|Where-Object {$_.id-eq$work.id-and$_.runtime.state-eq'connected'}).Count-eq1)}
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save}
@{passed=$r.passed;completed=$r.completed;report=$reportPath}|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
