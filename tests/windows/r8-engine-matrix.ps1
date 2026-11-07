# Ordinary orchestration only. Explicit profile setup/restoration surrounds each
# existing no-connect fault controller. OpenVPN engine fault is not repeated.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$x='C:\Users\Public\Vault443Exchange';$q='C:\Program Files\Vault443QA';$cli='C:\Program Files\Vault443\vault443-cli.exe';$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$main=Join-Path $x 'r8-protocols\main';$fault=Join-Path $x 'r8-engine-faults.ps1';$dir=Join-Path $x 'r8-outputs\engine-matrix';$sha='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'
$r=[ordered]@{schema=1;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;restored=$false;daemonSHA=$sha;baseline=$null;cases=@();steps=@();setupChanges=@();stage='preflight';errorType=$null;errorLine=0;restoreErrorType=$null;restoreErrorLine=0;limits=@('Explicit setup/restore calls occur only between fault cases; each reviewed child reports noConnectOrResetRequested=true.','Root owns continuous packet capture and matching physical positive controls.','OpenVPN engine fault is separate and is not repeated here.')}
$mainChanged=$false;$wgChanged=$false;$awgChanged=$false;$canRestore=$false;$mainIDs=@{};$workIDs=@{};$allowedMain=@()
New-Item -ItemType Directory -Force -Path $dir|Out-Null;$reportPath=Join-Path $dir ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-result.json')
function Save{$r|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $reportPath -Encoding UTF8}
function Child([string]$File,[string]$Arguments,[string]$InputText,[int]$Seconds){
 $p=New-Object Diagnostics.Process;$i=$p.StartInfo;$i.FileName=$File;$i.Arguments=$Arguments;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardInput=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true
 try{[void]$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();if($InputText){$p.StandardInput.WriteLine($InputText)};$p.StandardInput.Close();if(!$p.WaitForExit($Seconds*1000)){$p.Kill();[void]$p.WaitForExit(2000);throw 'Bounded matrix child deadline'};$text=$out.GetAwaiter().GetResult();[void]$err.GetAwaiter().GetResult();if($p.ExitCode-ne0){throw 'Existing QA child failed; raw output omitted'};return $text}finally{$p.Dispose()}
}
function RPC([string]$Method,[object[]]$Parameters=@()){$text=Child $cli $Method (ConvertTo-Json -InputObject $Parameters -Compress -Depth 8) 10;if($text){return($text|ConvertFrom-Json)}}
function Own-Snapshot{$s=RPC GetSnapshot;if($s.canAdmin-or$s.busyByOtherUser){throw 'Same ordinary owner required; no takeover is performed'};return $s}
function Step([string]$Name,[scriptblock]$Action){$r.stage=$Name;$item=[ordered]@{name=$Name;startedUTC=[DateTime]::UtcNow.ToString('o');finishedUTC=$null;passed=$false;errorType=$null;errorLine=0};Save;try{&$Action;$item.passed=$true}catch{$item.errorType=$_.Exception.GetType().FullName;$item.errorLine=$_.InvocationInfo.ScriptLineNumber;throw}finally{$item.finishedUTC=[DateTime]::UtcNow.ToString('o');$r.steps+=,$item;Save}}
function Setup-Work([string]$Name,[bool]$Connect){$s=Own-Snapshot;$id=$workIDs[$Name];$p=@($s.workProfiles|Where-Object id -eq $id);if($p.Count-ne1){throw 'Original caller-owned work profile disappeared'};$wanted=if($Connect){'connected'}else{'disconnected'};if($p[0].runtime.state-eq$wanted){return};if($Name-eq'wireguard-multi'){$script:wgChanged=$true}elseif($Name-eq'amneziawg'){$script:awgChanged=$true}else{throw 'Setup may change only the original WG/AWG pair'};$method=if($Connect){'RequestWorkConnect'}else{'RequestWorkDisconnect'};$r.setupChanges+=@{method=$method;profileID=$id;stage=$r.stage;utc=[DateTime]::UtcNow.ToString('o')};Save;[void](RPC $method @($id));$end=[DateTime]::UtcNow.AddSeconds(90);do{$s=Own-Snapshot;$p=@($s.workProfiles|Where-Object id -eq $id);if($p.Count-eq1-and$p[0].runtime.state-eq$wanted){return};Start-Sleep -Milliseconds 400}while([DateTime]::UtcNow-lt$end);throw 'Explicit work setup/restoration deadline'}
function Switch-Main([string]$Protocol){$s=Own-Snapshot;$id=$mainIDs[$Protocol];if($s.activeProfileId-eq$id-and$s.runtime.state-eq'connected'){return};if($s.activeProfileId-notin$allowedMain-or$s.runtime.state-ne'connected'){throw 'Connected main setup identity changed'};$script:mainChanged=$true;$r.setupChanges+=@{method='main-matrix switch';protocol=$Protocol;profileID=$id;stage=$r.stage;utc=[DateTime]::UtcNow.ToString('o')};Save;[void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$q+'\main-matrix.ps1" -Phase switch -Protocol '+$Protocol+' -OutputDirectory "'+$main+'"') '' 150)}
function Fault-Case([string]$Engine,[string]$Protocol){
 if((Get-FileHash $fault).Hash.ToLowerInvariant()-ne'29ccad7361df94415b75e54b5ea563ff0b539d6d98c4ee741999485484fd1687'){throw 'Reviewed fault controller bytes differ'}
 $reports=Join-Path $x 'r8-outputs\engine-faults';$before=@(Get-ChildItem $reports -Filter ('*-'+$Engine+'-'+$Protocol+'.json') -ErrorAction SilentlyContinue|ForEach-Object {$_.FullName});$started=[DateTime]::UtcNow
 [void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$fault+'" -Engine '+$Engine+' -Protocol '+$Protocol+' -ExpectedBackendSha256 '+$sha) '' 360)
 $files=@(Get-ChildItem $reports -Filter ('*-'+$Engine+'-'+$Protocol+'.json')|Where-Object {$_.FullName-notin$before-and$_.LastWriteTimeUtc-ge$started.AddSeconds(-1)}|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1)
 if($files.Count-ne1){throw 'Fresh exact fault result absent'};$v=Get-Content $files[0].FullName -Raw|ConvertFrom-Json
 $target=if($Engine-eq'wireguard'){$workIDs['wireguard-multi']}elseif($Engine-eq'amneziawg'){$workIDs['amneziawg']}else{$mainIDs[$Protocol]}
 $ok=$v.completed-and$v.passed-and$v.noConnectOrResetRequested-and$v.daemonSHA-eq$sha-and$v.engine-eq$Engine-and$v.protocol-eq$Protocol-and$v.target.id-eq$target-and$v.task.details.terminationConfirmed-and$v.task.details.daemonPid-eq$r.baseline.daemonPID
 $r.cases+=@{engine=$Engine;protocol=$Protocol;startedUTC=$started.ToString('o');finishedUTC=[DateTime]::UtcNow.ToString('o');report=$files[0].FullName;passed=$ok;targetID=$target;enginePID=$v.task.details.enginePid;noConnectInsideFaultController=$v.noConnectOrResetRequested;checks=$v.checks.Count};Save
 if(!$ok){throw 'Exact child fault proof failed'}
}
function Verify-Original{
 [void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$q+'\main-matrix.ps1" -Phase verify -Protocol vless -OutputDirectory "'+$main+'"') '' 120)
 foreach($entry in @(@('work-smoke.ps1','-Profile wireguard-multi -Phase verify -WaitSeconds 45'),@('work-smoke.ps1','-Profile amneziawg -Phase verify -WaitSeconds 45'),@('openvpn-smoke.ps1','-Phase verify -WaitSeconds 45'))){[void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$q+'\'+$entry[0]+'" '+$entry[1]) '' 100)}
 $s=Own-Snapshot;if($s.activeProfileId-ne$r.baseline.mainID-or$s.runtime.state-ne'connected'-or!$s.runtime.guardArmed){throw 'Original main was not restored'}
 foreach($name in @('wireguard-multi','amneziawg','openvpn')){if(@($s.workProfiles|Where-Object {$_.id-eq$workIDs[$name]-and$_.runtime.state-eq'connected'}).Count-ne1){throw 'An original split work profile was not restored'}}
 $svc=Get-CimInstance Win32_Service -Filter "Name='Vault443'";$proc=Get-CimInstance Win32_Process -Filter ('ProcessId='+$svc.ProcessId)
 if($svc.State-ne'Running'-or$svc.ProcessId-ne$r.baseline.daemonPID-or!$proc.CreationDate-or$proc.CreationDate.ToUniversalTime().ToString('o')-ne$r.baseline.daemonCreatedUTC){throw 'Service identity changed during engine-only faults'}
}
try{
 Step 'preflight' {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent();$computer=Get-CimInstance Win32_ComputerSystem
  if(!('Vault443R8EngineMatrixConsole'-as[type])){Add-Type 'using System.Runtime.InteropServices; public static class Vault443R8EngineMatrixConsole { [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId(); }'}
  if(([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or$env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$computer.Model-ne'VirtualBox'-or[Diagnostics.Process]::GetCurrentProcess().SessionId-ne[Vault443R8EngineMatrixConsole]::WTSGetActiveConsoleSessionId()-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$id.User.Value){throw 'Ordinary named active-console controller required'}
  if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha-or(Get-FileHash "$q\main-matrix.ps1").Hash.ToLowerInvariant()-ne'fc633896542f0e00fa452fca180c5dc473339b2309779b0def2dedf398e999e8'){throw 'Exact R8/backend helper bytes required'}
  $s=Own-Snapshot;$state=Get-Content (Join-Path $main 'state.json') -Raw|ConvertFrom-Json
  foreach($protocol in @('vless','trojan','shadowsocks','outline')){$cached=[string]$state.profiles.PSObject.Properties[$protocol].Value;$expectedKind=if($protocol-eq'outline'){'shadowsocks'}else{$protocol};$own=@($s.profiles|Where-Object {$_.id-eq$cached-and$_.kind-eq$expectedKind});$outlineMatches=$protocol-ne'outline'-or($own.Count-eq1-and$own[0].transport-eq'outline'-and$own[0].source.kind-eq'outline');if($cached-notmatch'^[a-f0-9]{32}$'-or$own.Count-ne1-or!$outlineMatches){throw 'Known own main protocol cache differs'};$mainIDs[$protocol]=$cached}
  $script:allowedMain=@($mainIDs.Values)
  if($s.activeProfileId-ne$mainIDs['vless']-or$s.runtime.state-ne'connected'-or!$s.runtime.guardArmed){throw 'Original protected VLESS must already be connected'}
  foreach($name in @('wireguard-multi','amneziawg','openvpn')){$p=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$name));if($p.Count-ne1-or$p[0].runtime.state-ne'connected'){throw 'Original three split fixtures required'};$workIDs[$name]=[string]$p[0].id}
  if(@($s.workProfiles|Where-Object {$_.id-notin@($workIDs.Values)-and$_.runtime.state-ne'disconnected'}).Count){throw 'Unexpected work intent; no profile will be adopted'}
  $svc=Get-CimInstance Win32_Service -Filter "Name='Vault443'";$proc=Get-CimInstance Win32_Process -Filter ('ProcessId='+$svc.ProcessId);if($svc.State-ne'Running'-or!$proc.CreationDate){throw 'Running SCM process required'}
  $r.baseline=@{machine=$env:COMPUTERNAME;sid=$id.User.Value;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;mainID=$mainIDs['vless'];workIDs=$workIDs.Clone();daemonPID=[int]$svc.ProcessId;daemonCreatedUTC=$proc.CreationDate.ToUniversalTime().ToString('o')};$script:canRestore=$true
 }
 foreach($protocol in @('vless','trojan','shadowsocks','outline')){
  $engine=if($protocol-eq'outline'){'outline'}else{'xray'}
  Step ('setup-main-'+$protocol) {Switch-Main $protocol}
  # The existing controller begins with main verify22 and all active work's real
  # traffic, so setup never needs an extra duplicate normal protocol matrix.
  Step ('fault-'+$engine+'-'+$protocol) {Fault-Case $engine $protocol}
 }
 Step 'setup-vless-and-stop-only-awg' {Switch-Main 'vless';Setup-Work 'amneziawg' $false}
 Step 'fault-wireguard-vless' {Fault-Case 'wireguard' 'vless'}
 Step 'setup-awg-on-then-wg-multi-off' {Setup-Work 'amneziawg' $true;Setup-Work 'wireguard-multi' $false}
 Step 'fault-amneziawg-vless' {Fault-Case 'amneziawg' 'vless'}
 if($r.cases.Count-ne6-or@($r.cases|Where-Object {!$_.passed}).Count){throw 'Six exact engine-family cases were not completed'}
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{
 if($canRestore){try{
  Step 'restore-only-explicitly-changed-original-ids' {
   $s=Own-Snapshot
   if($mainChanged-and($s.activeProfileId-ne$r.baseline.mainID-or$s.runtime.state-ne'connected')){if($s.activeProfileId-notin$allowedMain){throw 'Unexpected main owner intent; no adoption'};$r.setupChanges+=@{method='RequestConnect';profileID=$r.baseline.mainID;stage='restore';utc=[DateTime]::UtcNow.ToString('o')};Save;[void](RPC RequestConnect @($r.baseline.mainID));$end=[DateTime]::UtcNow.AddSeconds(90);do{$s=Own-Snapshot;if($s.activeProfileId-eq$r.baseline.mainID-and$s.runtime.state-eq'connected'){break};Start-Sleep -Milliseconds 400}while([DateTime]::UtcNow-lt$end);if($s.activeProfileId-ne$r.baseline.mainID-or$s.runtime.state-ne'connected'){throw 'Original main restoration deadline'}}
   if($wgChanged){Setup-Work 'wireguard-multi' $true};if($awgChanged){Setup-Work 'amneziawg' $true}
   Verify-Original;$r.restored=$true
  }
 }catch{$r.passed=$false;$r.restoreErrorType=$_.Exception.GetType().FullName;$r.restoreErrorLine=$_.InvocationInfo.ScriptLineNumber}}
 $r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save
}
@{passed=$r.passed;restored=$r.restored;cases=$r.cases.Count;report=$reportPath}|ConvertTo-Json -Compress
if(!$r.passed-or!$r.restored){exit 1}
