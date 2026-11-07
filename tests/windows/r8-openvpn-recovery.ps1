# Ordinary active-console integration controller; requires existing fixture IDs.
# Never imports profiles, resets users, modifies physical networking or kills PIDs.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$x='C:\Users\Public\Vault443Exchange';$q='C:\Program Files\Vault443QA';$cli='C:\Program Files\Vault443\vault443-cli.exe'
$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$out=Join-Path $x 'r8-outputs\openvpn-recovery';New-Item -ItemType Directory -Force $out|Out-Null
$r=[ordered]@{startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;steps=@();errorType=$null;errorLine=0}
function Save{$r|ConvertTo-Json -Depth 6|Set-Content (Join-Path $out 'result.json') -Encoding UTF8}
function RPC([string]$Method,[object[]]$Parameters=@()){$v=ConvertTo-Json -InputObject $Parameters -Depth 6 -Compress|& $cli $Method;if($LASTEXITCODE){throw 'RPC failed; raw reply omitted'};if($v){return ($v|ConvertFrom-Json)}}
function Child([string]$File,[string]$Arguments){
 $p=Start-Process $ps -WindowStyle Hidden -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$File+'" '+$Arguments) -PassThru
 [void]$p.Handle;try{if(!$p.WaitForExit(360000)){throw 'Child deadline exceeded; inspect child before further mutations'};if($p.ExitCode){throw 'Child failed; inspect individual sanitized report'}}finally{$p.Dispose()}
}
function Step([string]$Name,[scriptblock]$Action){$v=[ordered]@{name=$Name;startedUTC=[DateTime]::UtcNow.ToString('o');finishedUTC=$null;passed=$false};try{&$Action;$v.passed=$true}finally{$v.finishedUTC=[DateTime]::UtcNow.ToString('o');$r.steps+=,$v;Save}}
try{
 Step 'exact-candidate-and-console-preflight' {
  $i=[Security.Principal.WindowsIdentity]::GetCurrent();$m=Get-CimInstance Win32_ComputerSystem
  if(([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or$m.Name-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$m.Model-ne'VirtualBox'-or![Diagnostics.Process]::GetCurrentProcess().SessionId-or!$m.UserName-or([Security.Principal.NTAccount]::new($m.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$i.User.Value){throw 'Ordinary active console QA required'}
  if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne'4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'){throw 'Exact R8 daemon required'}
  $s=RPC GetSnapshot;if($s.canAdmin-or$s.busyByOtherUser-or$s.runtime.state-ne'disconnected'-or$s.runtime.guardArmed-or@($s.workProfiles|Where-Object {$_.runtime.state-ne'disconnected'}).Count){throw 'All own VPNs must start explicitly disconnected'}
 }
 Step 'connect-existing-main-and-three-work-fixtures' {
  $cache=Get-Content (Join-Path $x 'r8-protocols\main\state.json') -Raw|ConvertFrom-Json;$id=[string]$cache.profiles.vless
  if(!$id){throw 'Existing VLESS cache missing'};[void](RPC RequestConnect @($id));$s=RPC GetSnapshot
  foreach($name in @('wireguard-multi','amneziawg','openvpn')){$w=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$name));if($w.Count-ne1){throw 'Unique work fixture missing'};[void](RPC RequestWorkConnect @([string]$w[0].id))}
 }
 Step 'work-real-traffic' {
  Child "$q\work-smoke.ps1" '-Profile wireguard-multi -Phase verify -WaitSeconds 45'
  Child "$q\work-smoke.ps1" '-Profile amneziawg -Phase verify -WaitSeconds 45'
  Child "$q\openvpn-smoke.ps1" '-Phase verify -WaitSeconds 45'
 }
 Step 'main-real-traffic-and-guard' {Child "$q\main-matrix.ps1" ('-Phase recovery -Protocol vless -OutputDirectory "'+$x+'\r8-protocols\main"')}
 Step 'full-tunnel-pause-and-restoration' {Child "$x\r8-full-work.ps1" ''}
 Step 'full-route-conflict-manual-owner-fresh-flows-restoration' {Child "$x\r8-route-conflict.ps1" ''}
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save}
@{passed=$r.passed;report=(Join-Path $out 'result.json')}|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
