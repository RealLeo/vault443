# Ordinary active-console R6 QA. No privileged faults or fixture modifications.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Net.WebRequest]::DefaultWebProxy=$null
$x='C:\Users\Public\Vault443Exchange';$q='C:\Program Files\Vault443QA';$dir=Join-Path $x 'r7-route-conflict'
$cli='C:\Program Files\Vault443\vault443-cli.exe';$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sha='2ad9a62ab0e14825cf265100891a16f74e80911e03b2d63cb036f3d976f3b1c6'
$r=[ordered]@{schema=1;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;restored=$false;daemonSHA=$sha;baseline=$null;steps=@();checks=@();newRules=@();diagnostics=@();rpcFailure=$null;errorType=$null;errorLine=0;limits=@('Preexisting default route/root DNS manual rules cause a precondition refusal; no user rule is overwritten.','Default HTTPS uses numeric IPv4/IPv6 fixture certificate SANs, independent of DNS routing.','LAN/Docker overlap is a separate scenario.')}
New-Item -ItemType Directory -Force -Path $dir|Out-Null
$reportPath=Join-Path $dir 'result.json';$changed=$false;$mainID='';$multiID='';$splitID='';$awgID='';$wgID='';$ovpnID='';$baselineRoutes=@();$baselineDNS=@();$attemptedRoutes=@();$attemptedDNS=$false
function Save {$script:r|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $reportPath -Encoding UTF8}
function Check([string]$Name,[bool]$Passed,$Observation=$null){$script:r.checks+=@{check=$Name;passed=$Passed;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation};Save;if(!$Passed){throw 'Route conflict acceptance failed'}}
function Child([string]$Program,[string]$Arguments,[string]$InputText,[int]$Seconds){
 $i=New-Object Diagnostics.ProcessStartInfo;$i.FileName=$Program;$i.Arguments=$Arguments;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardInput=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process;$p.StartInfo=$i
 try{[void]$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();if($InputText){$p.StandardInput.WriteLine($InputText)};$p.StandardInput.Close();if(!$p.WaitForExit($Seconds*1000)){$script:r.rpcFailure=@{kind='deadline';method=$Arguments;seconds=$Seconds;utc=[DateTime]::UtcNow.ToString('o')};Save;$p.Kill();[void]$p.WaitForExit(2000);throw 'Bounded QA child deadline'};$text=$out.GetAwaiter().GetResult();$errorText=$err.GetAwaiter().GetResult();if($p.ExitCode-ne0){$script:r.rpcFailure=@{kind='exit';method=$Arguments;exitCode=$p.ExitCode;utc=[DateTime]::UtcNow.ToString('o');message=$(if($Program-eq$cli-and$Arguments-in@('SetWorkRoute','SetWorkDNS','RemoveWorkRoute','RemoveWorkDNS')){$errorText.Trim()}else{'omitted'})};Save;throw 'QA child failed'};return $text}finally{$p.Dispose()}
}
function Invoke-R6RouteRPC([string]$Method,[object[]]$Params=@()){$text=Child $cli $Method (ConvertTo-Json -InputObject $Params -Compress -Depth 8) 15;if($text){return($text|ConvertFrom-Json)}}
function Snapshot {Invoke-R6RouteRPC GetSnapshot}
function Routes {Invoke-R6RouteRPC GetWorkRoutes}
function Own($s,[string]$Name){$p=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$Name));if($p.Count-ne1){throw 'Expected one own work fixture'};return $p[0]}
function Wait-Work([string]$ID,[string[]]$States,[int]$Seconds=65){$end=[DateTime]::UtcNow.AddSeconds($Seconds);do{$s=Snapshot;$p=@($s.workProfiles|Where-Object id -eq $ID);if($p.Count-eq1-and$p[0].runtime.state-in$States){return $s};Start-Sleep -Milliseconds 400}while([DateTime]::UtcNow-lt$end);throw 'Work deadline'}
function Wait-Main([string]$State,[int]$Seconds=65){$end=[DateTime]::UtcNow.AddSeconds($Seconds);do{$s=Snapshot;if(!$s.busyByOtherUser-and$s.activeProfileId-eq$script:mainID-and$s.runtime.guardArmed-and$s.runtime.state-eq$State){return $s};Start-Sleep -Milliseconds 400}while([DateTime]::UtcNow-lt$end);throw 'Main state/guard deadline'}
function Projection($s){return @{mainID=$s.activeProfileId;mainState=$s.runtime.state;guard=$s.runtime.guardArmed;work=@($s.workProfiles|ForEach-Object {@{id=$_.id;name=$_.name;state=$_.runtime.state;interface=$_.runtime.interface}})}}
function Step([string]$Name,[scriptblock]$Action){$item=[ordered]@{name=$Name;startedUTC=[DateTime]::UtcNow.ToString('o');finishedUTC=$null;passed=$false;state=$null;errorType=$null;errorLine=0};try{&$Action;$item.state=Projection (Snapshot);$item.passed=$true}catch{$item.errorType=$_.Exception.GetType().FullName;$item.errorLine=$_.InvocationInfo.ScriptLineNumber;throw}finally{$item.finishedUTC=[DateTime]::UtcNow.ToString('o');$script:r.steps+=,$item;Save}}
function Save-DefaultFailure($Failure,[string]$Address,[string]$Engine) {
 $exception=$Failure.Exception;$web=$exception;$webStatus=$null
 while($web){if($web-is[Net.WebException]){$webStatus=[string]$web.Status;break};$web=$web.InnerException}
 $diag=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');address=$Address;expectedEngine=$Engine;errorType=$exception.GetType().FullName;webExceptionStatus=$webStatus;innerExceptionType=$(if($exception.InnerException){$exception.InnerException.GetType().FullName}else{$null});native=$null;diagnosticErrorType=$null}
 $script:r.diagnostics+=,$diag;Save
 try {
  # One bounded read-only child; no connectivity retries, no private configuration reads.
  $code=@'
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$cli='C:\Program Files\Vault443\vault443-cli.exe'
$s='[]'|& $cli GetSnapshot;if($LASTEXITCODE){throw 'Snapshot diagnostic RPC failed'};$s=$s|ConvertFrom-Json
$v='[]'|& $cli GetWorkRoutes;if($LASTEXITCODE){throw 'Route diagnostic RPC failed'};$v=$v|ConvertFrom-Json
$address='__ADDRESS__';$aliases=@(@('v443-main')+@($s.workProfiles|ForEach-Object {$_.runtime.interface}|Where-Object {$_})|Sort-Object -Unique)
$best=@(Find-NetRoute -RemoteIPAddress $address -ErrorAction SilentlyContinue|Select-Object InterfaceIndex,InterfaceAlias,IPAddress,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,AddressFamily)
$rows=@(Get-NetRoute -PolicyStore ActiveStore|Where-Object {$_.InterfaceAlias-in$aliases-or$_.DestinationPrefix-in@('0.0.0.0/0','::/0','0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')})
[ordered]@{utc=[DateTime]::UtcNow.ToString('o');bestRoute=$best;routeCount=$rows.Count;routeListTruncated=($rows.Count-gt512);routes=@($rows|Select-Object -First 512 InterfaceIndex,InterfaceAlias,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,AddressFamily,Protocol,State);
 workRoutes=@{busyByOtherUser=$v.busyByOtherUser;items=@($v.items|Select-Object -First 256 cidr,domain,source,target,interface,state,conflict);rules=@($v.rules|Select-Object id,cidr,target);dnsRules=@($v.dnsRules|Select-Object id,domain,target)};
 snapshot=@{mainID=$s.activeProfileId;mainState=$s.runtime.state;mainStage=$s.runtime.stage;guard=$s.runtime.guardArmed;work=@($s.workProfiles|ForEach-Object {@{id=$_.id;state=$_.runtime.state;stage=$_.runtime.stage;interface=$_.runtime.interface;peers=@($_.runtime.peers|ForEach-Object {@{id=$_.id;state=$_.state;endpoint=$_.endpoint;lastHandshakeAt=$_.lastHandshakeAt;allowedIPs=$_.allowedIPs}})}})}}|ConvertTo-Json -Depth 12 -Compress
'@
  if($Address-notin@('93.184.215.14','2001:db8:66::14')){throw 'Unexpected diagnostic address'}
  $code=$code.Replace('__ADDRESS__',$Address)
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
  $text=Child $ps ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded) '' 15
  $diag.native=$text|ConvertFrom-Json
 }catch{$diag.diagnosticErrorType=$_.Exception.GetType().FullName}
 Save
}
function Default-Traffic([string]$Engine){foreach($address in @('93.184.215.14','2001:db8:66::14')){
 try {
  $v6=$address.Contains(':');$uri=if($v6){'https://['+$address+']/'}else{'https://'+$address+'/'}
  $response=Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $uri -TimeoutSec 12;$text=if($response.Content-is[byte[]]){[Text.Encoding]::UTF8.GetString($response.Content)}else{[string]$response.Content};$body=$text|ConvertFrom-Json;$peer=[Net.IPAddress]::Parse([string]$body.peer).ToString().ToLowerInvariant()
  $valid=if($Engine-eq'wireguard'){if($v6){$peer-eq'2001:db8:80::2'}else{$peer-eq'198.19.44.2'}}else{if($v6){$peer.StartsWith('fd77:443::')}else{$peer.StartsWith('10.77.0.')}}
  Check ('default-'+$Engine+'-'+$address) ($body.marker-eq'vless-e2e-ok'-and$valid) @{destination=$address;peer=$peer;expectedEngine=$Engine}
 }catch{Save-DefaultFailure $_ $address $Engine;throw}
}}
function Select-Owner([string]$ID,[string]$Engine){
 foreach($cidr in @('0.0.0.0/0','::/0')){$script:attemptedRoutes=@($script:attemptedRoutes+$cidr|Sort-Object -Unique);[void](Invoke-R6RouteRPC SetWorkRoute @($cidr,$ID))}
 $script:attemptedDNS=$true;[void](Invoke-R6RouteRPC SetWorkDNS @('.',$ID))
 $end=[DateTime]::UtcNow.AddSeconds(20)
 do{$v=Routes;$good=$true;foreach($cidr in @('0.0.0.0/0','::/0')){if(@($v.rules|Where-Object {$_.cidr-eq$cidr-and$_.target-eq$ID}).Count-ne1-or@($v.items|Where-Object {$_.cidr-eq$cidr-and$_.source-eq'manual'-and$_.target-eq$ID-and$_.state-eq'active'}).Count-ne1){$good=$false}};if(@($v.dnsRules|Where-Object {$_.domain-eq'.'-and$_.target-eq$ID}).Count-ne1-or@($v.items|Where-Object {$_.domain-eq'.'-and$_.target-eq$ID-and!$_.conflict-and$_.state-eq'active'}).Count-ne1){$good=$false};if(!$good){Start-Sleep -Milliseconds 400}}while(!$good-and[DateTime]::UtcNow-lt$end)
 Check ('manual-routes-dns-'+$Engine) $good @{ownerID=$ID;rules=@($v.rules|Where-Object cidr -in @('0.0.0.0/0','::/0'));dnsRules=@($v.dnsRules|Where-Object domain -eq '.')}
 $script:r.newRules=@($v.rules|Where-Object cidr -in @('0.0.0.0/0','::/0'))+@($v.dnsRules|Where-Object domain -eq '.');Save
 [void](Wait-Main 'paused_external' 20);Default-Traffic $Engine
 # WG full advertises only '.', so this unique A answer distinguishes the selected root DNS provider.
 $expect=if($Engine-eq'wireguard'){'198.19.44.10'}else{'93.184.215.14'}
 $answer=Resolve-DnsName ('route-'+[Guid]::NewGuid().ToString('N')+'.wg.e2e.test') -Type A -DnsOnly -QuickTimeout -ErrorAction Stop
 Check ('default-dns-provider-'+$Engine) (@($answer|Where-Object IPAddress -eq $expect).Count-gt0) @{expectedIP=$expect;rootTarget=$ID}
 $zone=if($Engine-eq'wireguard'){'wg.e2e.test'}else{'corp.openvpn.test'};$expect6=if($Engine-eq'wireguard'){'2001:db8:80::10'}else{'fd77:443:8::10'}
 $answer=Resolve-DnsName ('route-'+[Guid]::NewGuid().ToString('N')+'.'+$zone) -Type AAAA -DnsOnly -QuickTimeout -ErrorAction Stop
 Check ('selected-vpn-dns-aaaa-'+$Engine) (@($answer|Where-Object IPAddress -eq $expect6).Count-gt0) @{expectedIP=$expect6;zone=$zone}
}
function Rule-Canonical($Rules){return(ConvertTo-Json -InputObject @($Rules|Sort-Object id) -Depth 6 -Compress)}
function Helper([string]$File,[string]$Arguments){[void](Child $ps ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $q $File)+'" '+$Arguments) '' 120)}
try {
 Step 'preflight-save-user-rules' {
  $i=[Security.Principal.WindowsIdentity]::GetCurrent();$m=Get-CimInstance Win32_ComputerSystem
  if(([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or$env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$m.Model-ne'VirtualBox'-or![Diagnostics.Process]::GetCurrentProcess().SessionId-or!$m.UserName-or([Security.Principal.NTAccount]::new($m.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$i.User.Value){throw 'Ordinary active-console named QA VM required'}
  if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha){throw 'Exact R6 daemon required'}
  $s=Snapshot;$p=@($s.profiles|Where-Object id -eq $s.activeProfileId)
  if($s.canAdmin-or$s.busyByOtherUser-or$p.Count-ne1-or$p[0].kind-ne'vless'-or$s.runtime.state-ne'connected'-or!$s.runtime.guardArmed){throw 'Own connected protected VLESS required'}
  $script:mainID=[string]$s.activeProfileId;$script:multiID=[string](Own $s 'wireguard-multi').id;$script:splitID=[string](Own $s 'openvpn').id;$script:awgID=[string](Own $s 'amneziawg').id;$script:wgID=[string](Own $s 'wireguard-full').id;$script:ovpnID=[string](Own $s 'openvpn-full').id
  foreach($id in @($multiID,$splitID,$awgID)){if(@($s.workProfiles|Where-Object {$_.id-eq$id-and$_.runtime.state-eq'connected'}).Count-ne1){throw 'Initial three work fixtures must be connected'}}
  foreach($id in @($wgID,$ovpnID)){if(@($s.workProfiles|Where-Object {$_.id-eq$id-and$_.runtime.state-eq'disconnected'}).Count-ne1){throw 'Full fixtures must initially be stopped'}}
  if(@($s.workProfiles|Where-Object {$_.runtime.state-ne'disconnected'}).Count-ne3){throw 'Unexpected overlapping work intent'}
  $v=Routes;$script:baselineRoutes=@($v.rules);$script:baselineDNS=@($v.dnsRules)
  $script:r.baseline=@{state=(Projection $s);rules=$baselineRoutes;dnsRules=$baselineDNS}
  if(@($v.rules|Where-Object cidr -in @('0.0.0.0/0','::/0')).Count-or@($v.dnsRules|Where-Object domain -eq '.').Count){throw 'Existing default/root manual policy must remain untouched; fixture precondition refused'}
 }
 $changed=$true
 Step 'stop-shared-credential-split-variants' {foreach($id in @($multiID,$splitID)){[void](Invoke-R6RouteRPC RequestWorkDisconnect @($id));[void](Wait-Work $id @('disconnected'))}}
 Step 'full-wg-incumbent' {[void](Invoke-R6RouteRPC RequestWorkConnect @($wgID));[void](Wait-Work $wgID @('connected'));[void](Wait-Main 'paused_external');Default-Traffic 'wireguard'}
 Step 'full-openvpn-conflict-retains-incumbent' {
  [void](Invoke-R6RouteRPC RequestWorkConnect @($ovpnID));[void](Wait-Work $ovpnID @('connected','conflict'));$end=[DateTime]::UtcNow.AddSeconds(25)
  do{$v=Routes;$ok=$true;foreach($cidr in @('0.0.0.0/0','::/0')){$claims=@($v.items|Where-Object {$_.cidr-eq$cidr-and$_.target-in@($wgID,$ovpnID)-and$_.conflict});if($claims.Count-ne2){$ok=$false}};if(!$ok){Start-Sleep -Milliseconds 400}}while(!$ok-and[DateTime]::UtcNow-lt$end)
  Check 'equal-default-v4-v6-conflict' $ok @{items=@($v.items|Where-Object cidr -in @('0.0.0.0/0','::/0'))};[void](Wait-Main 'paused_external' 20);Default-Traffic 'wireguard'
 }
 Step 'explicit-openvpn-owner' {Select-Owner $ovpnID 'openvpn'}
 Step 'explicit-wireguard-owner' {Select-Owner $wgID 'wireguard'}
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally {
 if($changed){
  try{Step 'finally-remove-only-new-owned-policy' {
   $v=Routes;$refused=$false
   foreach($rule in @($v.rules|Where-Object {$_.cidr-in$script:attemptedRoutes})){if($rule.id-in@($baselineRoutes|ForEach-Object {$_.id})-or$rule.target-notin@($wgID,$ovpnID)){$refused=$true;continue};[void](Invoke-R6RouteRPC RemoveWorkRoute @($rule.id))}
   foreach($rule in @($v.dnsRules|Where-Object {$script:attemptedDNS-and$_.domain-eq'.'})){if($rule.id-in@($baselineDNS|ForEach-Object {$_.id})-or$rule.target-notin@($wgID,$ovpnID)){$refused=$true;continue};[void](Invoke-R6RouteRPC RemoveWorkDNS @($rule.id))}
   $v=Routes;Check 'baseline-user-rules-preserved' (!$refused-and(Rule-Canonical $v.rules)-eq(Rule-Canonical $baselineRoutes)-and(Rule-Canonical $v.dnsRules)-eq(Rule-Canonical $baselineDNS))
  }}catch{$r.passed=$false}
  try{Step 'finally-stop-both-full-variants' {$failed=$false;foreach($id in @($wgID,$ovpnID)){try{[void](Invoke-R6RouteRPC RequestWorkDisconnect @($id));[void](Wait-Work $id @('disconnected'))}catch{$failed=$true}};if($failed){throw 'Full stop incomplete; shared-key restoration forbidden'}}}catch{$r.passed=$false}
  try{Step 'finally-restore-original-three-and-real-traffic' {
   $s=Snapshot;foreach($id in @($wgID,$ovpnID)){if(@($s.workProfiles|Where-Object {$_.id-eq$id-and$_.runtime.state-eq'disconnected'}).Count-ne1){throw 'Refusing shared credentials while full fixture active'}}
   foreach($id in @($multiID,$splitID)){[void](Invoke-R6RouteRPC RequestWorkConnect @($id))};foreach($id in @($multiID,$splitID,$awgID)){[void](Wait-Work $id @('connected'))};[void](Wait-Main 'connected')
   Helper 'main-matrix.ps1' ('-Phase verify -Protocol vless -OutputDirectory "'+$x+'\r7-protocols\main"')
   Helper 'work-smoke.ps1' '-Profile wireguard-multi -Phase verify -WaitSeconds 0';Helper 'work-smoke.ps1' '-Profile amneziawg -Phase verify -WaitSeconds 0';Helper 'openvpn-smoke.ps1' '-Profile openvpn -Phase verify -WaitSeconds 0'
  };$r.restored=$true}catch{$r.passed=$false}
 }
 $r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save
}
@{passed=$r.passed;restored=$r.restored;report=$reportPath}|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
