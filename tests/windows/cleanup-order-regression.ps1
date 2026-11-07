# Ordinary console-user regression for the isolated Windows acceptance VMs.
# Pass the exact installed candidate's daemon SHA-256; no privileged faults occur.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedDaemonSha256
)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run as the ordinary non-elevated QA console user'}
$machine=Get-CimInstance Win32_ComputerSystem
if($machine.Name -notin @('VAULT443-WIN10','VAULT443-WIN11') -or $machine.Model -notmatch '^VirtualBox$'){throw 'Named isolated VirtualBox acceptance VM required'}
$cli='C:\Program Files\Vault443\vault443-cli.exe'
$expected=$ExpectedDaemonSha256.ToLowerInvariant()
$out='C:\Users\Public\Vault443Exchange\cleanup-order-regression.json'
$r=[ordered]@{startedUtc=[DateTime]::UtcNow.ToString('o');daemonSha256=$expected;completed=$false;passed=$false;cycles=@();errorType=$null}
function Save { $script:r|ConvertTo-Json -Depth 10|Set-Content $out -Encoding UTF8 }
function RPC([string]$Method,[object[]]$Params=@()){$j=ConvertTo-Json -InputObject $Params -Compress;$v=$j|& $cli $Method;if($LASTEXITCODE){throw 'Fixture RPC failed'};if($v){return($v|ConvertFrom-Json)}}
try{
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$expected){throw 'Unexpected runtime hash'}
 $s=RPC GetSnapshot;$main=$s.profiles|Where-Object kind -eq vless|Select-Object -First 1
 $names=@('Vault443 Fixture wireguard-multi','Vault443 Fixture amneziawg','Vault443 Fixture openvpn')
 $profiles=@();foreach($n in $names){$p=$s.workProfiles|Where-Object name -eq $n;if(@($p).Count-ne1){throw 'Own fixture work profile missing'};$profiles+=@{id=$p.id;name=$p.name}}
 for($cycle=1;$cycle-le2;$cycle++){
  $c=[ordered]@{number=$cycle;startedUtc=[DateTime]::UtcNow.ToString('o');connected=$false;disconnected=$false;elapsedDisconnectMs=$null;states=@()}
  RPC RequestConnect @($main.id)|Out-Null
  foreach($p in $profiles){RPC RequestWorkConnect @($p.id)|Out-Null}
  $d=[DateTime]::UtcNow.AddSeconds(65)
  do{$s=RPC GetSnapshot;$w=@($s.workProfiles|Where-Object name -in $names);$ready=$s.runtime.state-eq'connected'-and$s.runtime.guardArmed-and$w.Count-eq3-and@($w|Where-Object {$_.runtime.state-ne'connected'}).Count-eq0;if($ready){break};Start-Sleep -Milliseconds 400}while([DateTime]::UtcNow-lt$d)
  $c.connected=$ready
  if(!$ready){$c.states=@($w|ForEach-Object {@{name=$_.name;state=$_.runtime.state;stage=$_.runtime.stage}});$r.cycles+=,$c;Save;throw 'Fixture connections did not become ready'}
  $timer=[Diagnostics.Stopwatch]::StartNew()
  foreach($p in $profiles){RPC RequestWorkDisconnect @($p.id)|Out-Null}
  RPC RequestDisconnect|Out-Null
  $d=[DateTime]::UtcNow.AddSeconds(35)
  do{$s=RPC GetSnapshot;$w=@($s.workProfiles|Where-Object name -in $names);$done=$s.runtime.state-eq'disconnected'-and!$s.runtime.guardArmed-and@($w|Where-Object {$_.runtime.state-ne'disconnected'}).Count-eq0;if($done){break};Start-Sleep -Milliseconds 400}while([DateTime]::UtcNow-lt$d)
  $timer.Stop();$c.elapsedDisconnectMs=$timer.ElapsedMilliseconds;$c.disconnected=$done;$c.states=@($w|ForEach-Object {@{name=$_.name;state=$_.runtime.state;stage=$_.runtime.stage}});$c.finishedUtc=[DateTime]::UtcNow.ToString('o');$r.cycles+=,$c;Save
  if(!$done){throw 'Cleanup failed or did not finish'}
 }
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUtc=[DateTime]::UtcNow.ToString('o');Save}
