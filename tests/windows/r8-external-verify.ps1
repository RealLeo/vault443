# Ordinary active-console acceptance; no service/binding/connect mutations.
param([Parameter(Mandatory=$true)][ValidateSet('dual','v6only','afterstop')][string]$Phase)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Net.WebRequest]::DefaultWebProxy=$null
$x='C:\Users\Public\Vault443Exchange';$q='C:\Program Files\Vault443QA';$dir=Join-Path $x 'r8-external';$cli='C:\Program Files\Vault443\vault443-cli.exe';$sha='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50';$statePath=Join-Path $dir 'owner.state.json'
$r=[ordered]@{phase=$Phase;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;checks=@();main=$null;external=$null;errorType=$null;errorLine=0}
New-Item -ItemType Directory -Path $dir -Force|Out-Null;$outPath=Join-Path $dir ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+$Phase+'.json')
function Save {$script:r|ConvertTo-Json -Depth 8|Set-Content $outPath -Encoding UTF8}
function Check([string]$Name,[bool]$Passed,$Observation=$null){$script:r.checks+=@{check=$Name;passed=$Passed;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation};Save;if(!$Passed){throw 'External acceptance check failed'}}
function Invoke-R8ExternalRPC([string]$Method){$i=New-Object Diagnostics.ProcessStartInfo;$i.FileName=$cli;$i.Arguments=$Method;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardInput=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true;$p=New-Object Diagnostics.Process;$p.StartInfo=$i;try{[void]$p.Start();$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync();$p.StandardInput.WriteLine('[]');$p.StandardInput.Close();if(!$p.WaitForExit(15000)){$p.Kill();[void]$p.WaitForExit(2000);throw 'RPC deadline'};$raw=$o.GetAwaiter().GetResult();[void]$e.GetAwaiter().GetResult();if($p.ExitCode){throw 'RPC failed; raw output omitted'};return($raw|ConvertFrom-Json)}finally{$p.Dispose()}}
function HTTP([string]$Label,[string]$URI,[string]$Marker,[string]$PeerPrefix){$v=Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri $URI -TimeoutSec 8;$text=if($v.Content-is[byte[]]){[Text.Encoding]::UTF8.GetString($v.Content)}else{[string]$v.Content};$b=$text|ConvertFrom-Json;$peer=[Net.IPAddress]::Parse([string]$b.peer).ToString().ToLowerInvariant();Check $Label ($b.marker-eq$Marker-and$peer.StartsWith($PeerPrefix)) @{peer=$peer}}
function DNS([string]$Label,[string]$Domain,[string]$Type,[string]$Expected,[string]$Server=''){$n=[Guid]::NewGuid().ToString('N')+'.'+$Domain;$a=@{Name=$n;Type=$Type;DnsOnly=$true;QuickTimeout=$true;ErrorAction='Stop'};if($Server){$a.Server=$Server};$got=@(Resolve-DnsName @a|Where-Object IPAddress|ForEach-Object {[Net.IPAddress]::Parse($_.IPAddress).ToString().ToLowerInvariant()});Check $Label ($Expected-in$got) @{answers=$got;server=$Server}}
try{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$machine=Get-CimInstance Win32_ComputerSystem
 if(([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or$env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$machine.Model-ne'VirtualBox'-or![Diagnostics.Process]::GetCurrentProcess().SessionId-or!$machine.UserName-or([Security.Principal.NTAccount]::new($machine.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$id.User.Value){throw 'Ordinary active-console named QA VM required'}
 foreach($f in @($q,(Join-Path $q 'qa-runner.ps1'))){$item=Get-Item $f -Force;$acl=Get-Acl $f;if($item.Attributes-band[IO.FileAttributes]::ReparsePoint-or$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')){throw 'Protected QA identity required'};foreach($e in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and$e.IdentityReference.Value-notin@('S-1-5-18','S-1-5-32-544')-and([long]$e.FileSystemRights-band0x500D0156)){throw 'Untrusted QA write permissions'}}}
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha){throw 'Exact R8 daemon required'}
 $s=Invoke-R8ExternalRPC GetSnapshot;$p=@($s.profiles|Where-Object id -eq $s.activeProfileId);if($s.canAdmin-or$s.busyByOtherUser-or$p.Count-ne1-or$p[0].kind-ne'vless'){throw 'Own VLESS required'}
 $identity=@{machine=$env:COMPUTERNAME;sid=$id.User.Value;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;mainID=$s.activeProfileId}
 if($Phase-eq'dual'){if(Test-Path $statePath){throw 'Existing external owner state refused; archive previous own run first'};$identity|ConvertTo-Json|Set-Content $statePath -Encoding UTF8}else{$old=Get-Content $statePath -Raw|ConvertFrom-Json;foreach($k in @('machine','sid','session','mainID')){if($old.$k-ne$identity[$k]){throw 'Active owner/main identity changed'}}}
 $end=[DateTime]::UtcNow.AddSeconds(60)
 do{$s=Invoke-R8ExternalRPC GetSnapshot;$compat=Invoke-R8ExternalRPC GetVPNCompatibility;$corp=@($compat.items|Where-Object interface -eq 'corp-external');$ok=$s.runtime.guardArmed-and$s.activeProfileId-eq$identity.mainID-and!$s.busyByOtherUser
  if($Phase-eq'afterstop'){$ok=$ok-and$s.runtime.state-eq'connected'-and!@($corp|Where-Object active).Count}else{$ok=$ok-and$s.runtime.state-eq'paused_external'-and$corp.Count-eq1-and$corp[0].active-and$corp[0].verified-and$corp[0].fullIPv6-and([bool]$corp[0].fullIPv4-eq($Phase-eq'dual'))}
  if($ok){break};Start-Sleep -Milliseconds 500
 }while([DateTime]::UtcNow-lt$end)
 $r.main=@{state=$s.runtime.state;guard=$s.runtime.guardArmed;profileID=$s.activeProfileId};$r.external=@($corp|Select-Object interface,source,manager,application,active,verified,fullIPv4,fullIPv6);Check 'external-classification-main-guard' $ok $r.external
 if($Phase-eq'afterstop'){
  $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe';$info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$ps;$info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$q+'\main-matrix.ps1" -Phase verify -Protocol vless -OutputDirectory "'+$x+'\r8-protocols\main"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$child=New-Object Diagnostics.Process;$child.StartInfo=$info
  try{[void]$child.Start();$o=$child.StandardOutput.ReadToEndAsync();$e=$child.StandardError.ReadToEndAsync();if(!$child.WaitForExit(120000)){$child.Kill();[void]$child.WaitForExit(2000);throw 'Main verify deadline'};[void]$o.GetAwaiter().GetResult();[void]$e.GetAwaiter().GetResult();Check 'main-automatic-recovery-real-verify' ($child.ExitCode-eq0)}finally{$child.Dispose()}
 }else{
  HTTP 'corp-http4' 'http://10.77.8.10:8080/' 'openvpn-e2e-ok' '10.77.0.';HTTP 'corp-http6' 'http://[fd77:443:8::10]:8080/' 'openvpn-e2e-ok' 'fd77:443::'
  DNS 'coordinator-corp-A' 'corp.openvpn.test' 'A' '10.77.8.10';DNS 'coordinator-corp-AAAA' 'corp.openvpn.test' 'AAAA' 'fd77:443:8::10'
  DNS 'actual-corp-resolver-A' 'corp.openvpn.test' 'A' '10.77.8.10' '10.77.0.1';DNS 'actual-corp-resolver-AAAA' 'corp.openvpn.test' 'AAAA' 'fd77:443:8::10' '10.77.0.1'
  HTTP 'default-https6-fresh' 'https://[2001:db8:66::14]/' 'vless-e2e-ok' 'fd77:443::'
  if($Phase-eq'dual'){HTTP 'default-https4-fresh' 'https://93.184.215.14/' 'vless-e2e-ok' '10.77.0.'}else{$responded=$false;$status=$null;try{$v=Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri 'https://93.184.215.14/' -TimeoutSec 3;$responded=$true}catch{$responded=$null-ne$_.Exception.Response;if($_.Exception-is[Net.WebException]){$status=[string]$_.Exception.Status}};Check 'ipv6-only-default4-no-response' (!$responded) @{anyResponse=$responded;webExceptionStatus=$status}}
  DNS 'external-default-root-DNS' 'outside.external.e2e.test' 'A' '93.184.215.14';DNS 'specific-work-DNS-preserved' 'wg.e2e.test' 'A' '198.19.44.10'
 }
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save}
@{phase=$Phase;passed=$r.passed;report=$outPath}|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
