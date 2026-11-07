# Ordinary active-console R7 QA. Root separately adds/removes the one owned IP.
param([Parameter(Mandatory=$true)][ValidateSet('baseline','run','recovered')][string]$Phase)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Net.WebRequest]::DefaultWebProxy=$null
$x='C:\Users\Public\Vault443Exchange';$q='C:\Program Files\Vault443QA';$dir=Join-Path $x 'r7-overlap';$cli='C:\Program Files\Vault443\vault443-cli.exe';$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sha='2ad9a62ab0e14825cf265100891a16f74e80911e03b2d63cb036f3d976f3b1c6';$address='198.19.44.22';$statePath=Join-Path $dir 'baseline.state.json'
$r=[ordered]@{phase=$Phase;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;rulesRestored=$false;daemonSHA=$sha;baseline=$null;progress=$null;checks=@();errorType=$null;errorLine=0;limits=@('One IPv4 connected-prefix overlap, not actual Docker/HNS/NAT or IPv6 overlap.','Physical positive uses 192.0.2.2 because the secondary IP has SkipAsSource=true.','No RequestConnect or privileged IP action is issued by this controller.')}
New-Item -ItemType Directory -Path $dir -Force|Out-Null;$reportPath=Join-Path $dir ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+$Phase+'.json');$baseline=$null;$attemptWG=$false;$attemptLocal=$false
function Save {$script:r|ConvertTo-Json -Depth 10|Set-Content $reportPath -Encoding UTF8}
function Check([string]$Name,[bool]$Passed,$Observation=$null){$script:r.checks+=@{check=$Name;passed=$Passed;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation};Save;if(!$Passed){throw 'Overlap acceptance check failed'}}
function Invoke-R7OverlapRPC([string]$Method,[object[]]$Parameters=@(),[switch]$ExpectLocalDenial){
 $i=New-Object Diagnostics.ProcessStartInfo;$i.FileName=$cli;$i.Arguments=$Method;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardInput=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true;$p=New-Object Diagnostics.Process;$p.StartInfo=$i
 try{[void]$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();$p.StandardInput.WriteLine((ConvertTo-Json -InputObject $Parameters -Compress));$p.StandardInput.Close();if(!$p.WaitForExit(15000)){$p.Kill();[void]$p.WaitForExit(2000);throw 'RPC deadline'};$text=$out.GetAwaiter().GetResult();$errorText=$err.GetAwaiter().GetResult();if($ExpectLocalDenial){return($p.ExitCode-ne0-and$errorText-match'local route must be contained in an existing connected network')};if($p.ExitCode-ne0){throw 'RPC failed; raw error omitted'};if($text){return($text|ConvertFrom-Json)}}finally{$p.Dispose()}
}
function Snapshot {Invoke-R7OverlapRPC GetSnapshot}
function Rules {Invoke-R7OverlapRPC GetWorkRoutes}
function Canonical($value){return(ConvertTo-Json -InputObject @($value|Sort-Object id) -Depth 6 -Compress)}
function Own($s,[string]$Name){$p=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$Name));if($p.Count-ne1){throw 'Own work fixture missing/ambiguous'};return $p[0]}
function Identity($s){$svc=Get-CimInstance Win32_Service -Filter "Name='Vault443'";$proc=Get-CimInstance Win32_Process -Filter ('ProcessId='+$svc.ProcessId);if(!$proc.CreationDate-or$svc.State-ne'Running'){throw 'Running SCM identity required'};return @{machine=$env:COMPUTERNAME;userSID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;daemonPID=[int]$svc.ProcessId;createdUTC=$proc.CreationDate.ToUniversalTime().ToString('o');mainID=$s.activeProfileId;wgID=(Own $s 'wireguard-multi').id;awgID=(Own $s 'amneziawg').id;ovpnID=(Own $s 'openvpn').id}}
function Physical {$items=@(Get-NetAdapter -Physical|Where-Object {[string]$_.InterfaceGuid-eq$script:baseline.physical.guid-and$_.MacAddress-eq$script:baseline.physical.mac});if($items.Count-ne1-or$items[0].Status-ne'Up'){throw 'Original physical identity changed'};return $items[0]}
function Wait-Ready {
 $end=[DateTime]::UtcNow.AddSeconds(90);$stableSince=$null
 do{$s=Snapshot;$now=Identity $s;foreach($key in @('machine','userSID','session','daemonPID','createdUTC')){if($now[$key]-ne$script:baseline.identity.$key){throw 'Owner/SCM continuity changed'}}
  foreach($pair in @(@('wireguard-multi','wgID'),@('amneziawg','awgID'),@('openvpn','ovpnID'))){if((Own $s $pair[0]).id-ne$script:baseline.identity.($pair[1])){throw 'Own fixture ID changed'}}
  $ok=!$s.busyByOtherUser-and$s.runtime.state-eq'connected'-and$s.runtime.guardArmed-and$s.activeProfileId-eq$script:baseline.identity.mainID
  foreach($name in @('wireguard-multi','amneziawg','openvpn')){if((Own $s $name).runtime.state-ne'connected'){$ok=$false}}
  if($Phase-eq'run'){$adapter=Physical;$ip=@(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore|Where-Object IPAddress -eq $address);if($ip.Count-ne1-or$ip[0].AddressState-ne'Preferred'){$ok=$false}}
  if($ok){if($null-eq$stableSince){$stableSince=[DateTime]::UtcNow};if(([DateTime]::UtcNow-$stableSince).TotalSeconds-ge6){return $s}}else{$stableSince=$null};$r.progress=@{utc=[DateTime]::UtcNow.ToString('o');state=$s.runtime.state;waitingAutomaticRecovery=$true};Save;Start-Sleep -Milliseconds 500
 }while([DateTime]::UtcNow-lt$end);throw 'Automatic network-change recovery deadline'
}
function Payload([string]$Label,[bool]$Local){$s=Wait-Ready;$a=Physical;$wg=Own $s 'wireguard-multi';$expectedIndex=if($Local){$a.ifIndex}else{(Get-NetAdapter -Name $wg.runtime.interface).ifIndex};$peer=if($Local){'192.0.2.2'}else{'198.19.44.2'}
 $best=@(Find-NetRoute -RemoteIPAddress '198.19.44.10');$indexes=@($best|ForEach-Object {$_.InterfaceIndex}|Where-Object {$_-gt0}|Sort-Object -Unique)
 Check ($Label+'-native-route') ($indexes.Count-eq1-and$indexes[0]-eq$expectedIndex) @{expectedIfIndex=$expectedIndex;best=@($best|Select-Object InterfaceIndex,InterfaceAlias,IPAddress,DestinationPrefix,NextHop,RouteMetric)}
 $v=Invoke-WebRequest -UseBasicParsing -Uri 'http://198.19.44.10:18080/' -TimeoutSec 8;$text=if($v.Content-is[byte[]]){[Text.Encoding]::UTF8.GetString($v.Content)}else{[string]$v.Content};$body=$text|ConvertFrom-Json
 Check ($Label+'-actual-payload') ($body.marker-eq'work-e2e-ok'-and$body.peer-eq$peer) @{peer=$body.peer;expectedPeer=$peer}
}
function Helper([string]$File,[string]$Arguments){$i=New-Object Diagnostics.ProcessStartInfo;$i.FileName=$ps;$i.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $q $File)+'" '+$Arguments;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true;$p=New-Object Diagnostics.Process;$p.StartInfo=$i;try{[void]$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();if(!$p.WaitForExit(120000)){$p.Kill();[void]$p.WaitForExit(2000);throw 'Existing helper deadline'};[void]$out.GetAwaiter().GetResult();[void]$err.GetAwaiter().GetResult();Check ('real-traffic-'+$File+'-'+$Arguments.Split(' ')[1]) ($p.ExitCode-eq0)}finally{$p.Dispose()}}
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$machine=Get-CimInstance Win32_ComputerSystem
 if(([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or$env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$machine.Model-ne'VirtualBox'-or![Diagnostics.Process]::GetCurrentProcess().SessionId-or!$machine.UserName-or([Security.Principal.NTAccount]::new($machine.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value){throw 'Ordinary active-console named QA required'}
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha){throw 'Exact R7 daemon required'}
 $s=Snapshot;$main=@($s.profiles|Where-Object id -eq $s.activeProfileId);if($s.canAdmin-or$main.Count-ne1-or$main[0].kind-ne'vless'){throw 'Own VLESS required'}
 if($Phase-eq'baseline'){
  $v=Rules;if(@($v.rules|Where-Object cidr -in @('198.19.44.0/24','198.19.44.0/25')).Count){throw 'Existing overlap manual rule refused'}
  if(@(Get-NetIPAddress -AddressFamily IPv4|Where-Object IPAddress -eq $address).Count){throw 'Baseline must precede admin IP add'}
  $a=@(Get-NetAdapter -Physical|Where-Object Status -eq 'Up');if($a.Count-ne1){throw 'One initial physical adapter required'}
  $script:baseline=[pscustomobject]@{identity=(Identity $s);physical=@{guid=[string]$a[0].InterfaceGuid;mac=$a[0].MacAddress};rules=@($v.rules);dnsRules=@($v.dnsRules);utc=[DateTime]::UtcNow.ToString('o')}
  [void](Wait-Ready);$r.baseline=$baseline;$baseline|ConvertTo-Json -Depth 8|Set-Content $statePath -Encoding UTF8
 }else{
  $script:baseline=Get-Content $statePath -Raw|ConvertFrom-Json;$r.baseline=$baseline;$a=Physical;[void](Wait-Ready)
  if($Phase-eq'run'){
   $ip=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore|Where-Object IPAddress -eq $address)
   Check 'owned-secondary-preferred-skip-source' ($ip.Count-eq1-and$ip[0].PrefixLength-eq25-and$ip[0].SkipAsSource-and$ip[0].AddressState-eq'Preferred')
   $v=Rules;Check 'user-policy-unchanged-before-test' ((Canonical $v.rules)-eq(Canonical $baseline.rules)-and(Canonical $v.dnsRules)-eq(Canonical $baseline.dnsRules))
   Payload 'A-automatic-work-over-connected25' $false
   $denied=Invoke-R7OverlapRPC SetWorkRoute @('198.19.44.0/24','local') -ExpectLocalDenial
   Check 'invalid-local24-wider-than-connected25-rejected' $denied
   $v=Rules;Check 'denied-write-restored-user-policy' ((Canonical $v.rules)-eq(Canonical $baseline.rules))
   $attemptWG=$true;[void](Invoke-R7OverlapRPC SetWorkRoute @('198.19.44.0/24',$baseline.identity.wgID));Payload 'B-manual-work24' $false
   $attemptLocal=$true;[void](Invoke-R7OverlapRPC SetWorkRoute @('198.19.44.0/25','local'))
   $v=Rules;Check 'manual-local25-active' (@($v.items|Where-Object {$_.cidr-eq'198.19.44.0/25'-and$_.source-eq'manual'-and$_.target-eq'local'-and$_.state-eq'active'}).Count-eq1)
   Payload 'C-manual-local25' $true
   $v=Rules;$local=@($v.rules|Where-Object {$_.cidr-eq'198.19.44.0/25'-and$_.target-eq'local'});if($local.Count-ne1){throw 'New local rule identity differs'};[void](Invoke-R7OverlapRPC RemoveWorkRoute @($local[0].id))
   Payload 'D-local-removed-back-to-work' $false
  }else{
   Check 'admin-secondary-removed' (!@(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore|Where-Object IPAddress -eq $address).Count)
   $v=Rules;Check 'recovered-baseline-policy' ((Canonical $v.rules)-eq(Canonical $baseline.rules)-and(Canonical $v.dnsRules)-eq(Canonical $baseline.dnsRules))
   Helper 'main-matrix.ps1' ('-Phase verify -Protocol vless -OutputDirectory "'+$x+'\r7-protocols\main"')
   Helper 'work-smoke.ps1' '-Profile wireguard-multi -Phase verify -WaitSeconds 0';Helper 'work-smoke.ps1' '-Profile amneziawg -Phase verify -WaitSeconds 0';Helper 'openvpn-smoke.ps1' '-Profile openvpn -Phase verify -WaitSeconds 0';[void](Wait-Ready)
  }
 }
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally {
 if($Phase-eq'run'-and$baseline){try{
  $v=Rules
  foreach($rule in @($v.rules|Where-Object {($attemptWG-and$_.cidr-eq'198.19.44.0/24')-or($attemptLocal-and$_.cidr-eq'198.19.44.0/25')})){
   $expectedTarget=if($rule.cidr-eq'198.19.44.0/25'){'local'}else{$baseline.identity.wgID}
   if($rule.id-in@($baseline.rules|ForEach-Object {$_.id})-or$rule.target-ne$expectedTarget){throw 'Foreign current policy cannot be removed'}
   [void](Invoke-R7OverlapRPC RemoveWorkRoute @($rule.id))
  }
  $v=Rules;Check 'finally-canonical-baseline-preserved' ((Canonical $v.rules)-eq(Canonical $baseline.rules)-and(Canonical $v.dnsRules)-eq(Canonical $baseline.dnsRules));$r.rulesRestored=$true
 }catch{$r.passed=$false}}
 $r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save
}
@{phase=$Phase;passed=$r.passed;rulesRestored=$r.rulesRestored;report=$reportPath}|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
