# Ordinary Win10 core refresh only. No fault injection or work profile import.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$x='C:\Users\Public\Vault443Exchange';$q='C:\Program Files\Vault443QA';$app='C:\Program Files\Vault443';$cli=Join-Path $app 'vault443-cli.exe';$ps='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$main=Join-Path $x 'r8-protocols\main';$out=Join-Path $x 'r9-core';$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ');$workIDs=@{}
$r=[ordered]@{schema=1;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;stage='preflight';steps=@();setupChanges=@();sourceID='ee9fdf8aa48c5859b9580d1052588379';errorType=$null;errorLine=0;limits=@('Only core protocol and real coexistence traffic are refreshed; no fault is injected.','The recovery helper is used for connected traffic verification; its fault label does not claim a fault here.','Connection intents remain in place on failure for root inspection.')}
New-Item -ItemType Directory -Force -Path $out|Out-Null
function Save{$r|ConvertTo-Json -Depth 9|Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8}
function Pin([string]$Path,[string]$SHA){if((Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()-cne$SHA){throw 'Reviewed input hash differs'}}
function Child([string]$File,[string]$Arguments,[int]$Seconds,[string]$InputText=''){
 $p=New-Object Diagnostics.Process;$i=$p.StartInfo;$i.FileName=$File;$i.Arguments=$Arguments;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardInput=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true
 try{[void]$p.Start();$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync();if($InputText){$p.StandardInput.WriteLine($InputText)};$p.StandardInput.Close();if(!$p.WaitForExit($Seconds*1000)){throw 'Bounded child deadline; process retained for inspection'};$text=$o.GetAwaiter().GetResult();[void]$e.GetAwaiter().GetResult();if($p.ExitCode-ne0){throw 'Existing QA child failed; raw output omitted'};return $text}finally{$p.Dispose()}
}
function RPC([string]$Method,[object[]]$Parameters=@()){$text=Child $cli $Method 15 (ConvertTo-Json -InputObject $Parameters -Compress -Depth 8);if($text){return($text|ConvertFrom-Json)}}
function Own{$s=RPC GetSnapshot;if($s.canAdmin-or$s.busyByOtherUser){throw 'Ordinary own caller required; no takeover'};return $s}
function Step([string]$Name,[scriptblock]$Action){$r.stage=$Name;Save;$v=[ordered]@{name=$Name;startedUTC=[DateTime]::UtcNow.ToString('o');passed=$false};try{&$Action;$v.passed=$true}finally{$v.finishedUTC=[DateTime]::UtcNow.ToString('o');$r.steps+=,$v;Save}}
function Main-Phase([string]$Phase){
 $start=[DateTime]::UtcNow;$prior=@(Get-ChildItem $main -Filter ('*-'+$Phase+'-vless.json') -ErrorAction SilentlyContinue|ForEach-Object FullName)
 [void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$q+'\main-matrix.ps1" -Phase '+$Phase+' -Protocol vless -OutputDirectory "'+$main+'"') $(if($Phase-eq'all'){900}else{150}))
 $files=@(Get-ChildItem $main -Filter ('*-'+$Phase+'-vless.json')|Where-Object {$_.FullName-notin$prior-and$_.LastWriteTimeUtc-ge$start.AddSeconds(-1)})
 if($files.Count-ne1){throw 'Fresh unique main report absent'};$v=Get-Content $files[0].FullName -Raw|ConvertFrom-Json
 if(!$v.completed-or!$v.passed-or$v.phase-ne$Phase-or$v.protocol-ne'vless'-or[DateTime]$v.startedUtc-lt$start.AddSeconds(-1)){throw 'Fresh main report failed'}
 $r[$Phase+'Report']=@{path=$files[0].FullName;checks=@($v.checks).Count};Save
}
try{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$m=Get-CimInstance Win32_ComputerSystem
 if(!('Vault443R9CoreConsole'-as[type])){Add-Type 'using System.Runtime.InteropServices; public static class Vault443R9CoreConsole { [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId(); }'}
 if($env:COMPUTERNAME-ne'VAULT443-WIN10'-or$m.Model-ne'VirtualBox'-or!$m.UserName-or([Security.Principal.NTAccount]::new($m.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$id.User.Value-or[Diagnostics.Process]::GetCurrentProcess().SessionId-ne[Vault443R9CoreConsole]::WTSGetActiveConsoleSessionId()-or([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ordinary named Win10 active-console controller required'}
 Pin "$app\build-manifest.json" '3b39812785f9441b33ac02ced564f30bbc918253b27edbbaed4ef4bb1c65c09a';Pin "$app\vault443d.exe" '4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50';Pin $cli '514c067b23e6adbfd8a245f592aa338ec62105f08de59c3286065fd1a278f1c6'
 foreach($entry in @(@('main-matrix.ps1','fc633896542f0e00fa452fca180c5dc473339b2309779b0def2dedf398e999e8'),@('r8-dns6-positive.ps1','c633f8d6823ed304b304431aabc9fbbbe96526d2839fe6f2073d916a84638301'),@('work-smoke.ps1','aac73e3f4191d60e8c211ad08896ef518d1d1eaaaf11ea68a5a4adc43a34ed36'),@('openvpn-smoke.ps1','b47aeac72beeee26eb45086881dac0156e1d675e683d3eb001491ccf5bb9950f'))){$base=if($entry[0]-eq'r8-dns6-positive.ps1'){$x}else{$q};Pin (Join-Path $base $entry[0]) $entry[1]}
 $s=Own;if($s.runtime.state-ne'disconnected'-or$s.runtime.guardArmed-or@($s.workProfiles|Where-Object {$_.runtime.state-ne'disconnected'-or$_.runtime.guardArmed}).Count){throw 'All own VPNs must already be explicitly off'}
 $old=Join-Path $main 'state.json';if(!(Test-Path $old)){throw 'Existing main QA cache required'};$r.previousMainState=Join-Path $out ('previous-main-state-'+$stamp+'.json');Copy-Item -LiteralPath $old -Destination $r.previousMainState
 $cached=Get-Content $old -Raw|ConvertFrom-Json;$outline=@($s.profiles|Where-Object {$_.id-eq$r.sourceID-and$_.kind-eq'shadowsocks'-and$_.source.kind-eq'outline'})
 if($cached.profiles.outline-ne$r.sourceID-or$outline.Count-ne1){throw 'Existing exact own Outline source differs'}
 foreach($name in @('wireguard-multi','amneziawg','openvpn')){$p=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$name));$kind=if($name-eq'wireguard-multi'){'wireguard'}else{$name};if($p.Count-ne1-or$p[0].kind-ne$kind){throw 'Unique existing canonical split work profile required'};$workIDs[$name]=[string]$p[0].id};$r.originalWorkIDs=$workIDs.Clone();Save
 Step 'refresh-same-outline-source' {
  $epoch=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$accepted=RPC RequestSourceRefresh @($r.sourceID);$token=[string]$accepted.operationId;if($token-notmatch'^source-[0-9]+$'){throw 'Source refresh token differs'};$end=[DateTime]::UtcNow.AddSeconds(35)
  do{$s=Own;$p=@($s.profiles|Where-Object id -eq $r.sourceID);$good=$p.Count-eq1-and$p[0].kind-eq'shadowsocks'-and$p[0].transport-eq'outline'-and$p[0].source.kind-eq'outline'-and!$p[0].source.updating-and!$p[0].source.blocked-and!$p[0].source.usingCached-and!$p[0].source.lastError-and$p[0].source.updatedAt-ge$epoch;if($good){break};Start-Sleep -Milliseconds 300}while([DateTime]::UtcNow-lt$end)
  if(!$good){throw 'Fresh extended Outline source not confirmed'};$r.sourceRefresh=@{id=$r.sourceID;updatedAt=$p[0].source.updatedAt;transport=$p[0].transport}
 }
 Step 'physical-dns6-positive' {
  $start=[DateTime]::UtcNow;[void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$x+'\r8-dns6-positive.ps1"') 45);$path=Join-Path $x 'r8-dns6-positive.json';$v=Get-Content $path -Raw|ConvertFrom-Json
  if(!$v.completed-or!$v.passed-or[DateTime]$v.startedUtc-lt$start.AddSeconds(-1)-or@($v.probes).Count-ne2){throw 'Fresh physical DNS6 positive report failed'};Copy-Item $path (Join-Path $out ('physical-dns6-'+$stamp+'.json'))
 }
 Step 'fresh-main-all' {Main-Phase all}
 Step 'setup-existing-main-and-three-split-work' {
  $cache=Get-Content (Join-Path $main 'state.json') -Raw|ConvertFrom-Json;$mainID=[string]$cache.profiles.vless;$s=Own;if(@($s.profiles|Where-Object {$_.id-eq$mainID-and$_.kind-eq'vless'}).Count-ne1){throw 'Fresh own VLESS cache differs'}
  $r.setupChanges+=@{method='RequestConnect';id=$mainID;utc=[DateTime]::UtcNow.ToString('o')};Save;[void](RPC RequestConnect @($mainID))
  foreach($name in @('wireguard-multi','amneziawg','openvpn')){$r.setupChanges+=@{method='RequestWorkConnect';id=$workIDs[$name];utc=[DateTime]::UtcNow.ToString('o')};Save;[void](RPC RequestWorkConnect @($workIDs[$name]))}
  $end=[DateTime]::UtcNow.AddSeconds(100);do{$s=Own;$good=$s.activeProfileId-eq$mainID-and$s.runtime.state-eq'connected'-and$s.runtime.guardArmed;foreach($name in $workIDs.Keys){if(@($s.workProfiles|Where-Object {$_.id-eq$workIDs[$name]-and$_.runtime.state-eq'connected'}).Count-ne1){$good=$false}};if($good){break};Start-Sleep -Milliseconds 400}while([DateTime]::UtcNow-lt$end);if(!$good){throw 'Existing four-tunnel setup deadline'};$r.mainID=$mainID
 }
 Step 'main-connected-recovery-traffic' {Main-Phase recovery}
 foreach($entry in @(@('work-smoke.ps1','-Profile wireguard-multi -Phase verify -WaitSeconds 45'),@('work-smoke.ps1','-Profile amneziawg -Phase verify -WaitSeconds 45'),@('openvpn-smoke.ps1','-Profile openvpn -Phase verify -WaitSeconds 45'))){Step ('real-work-'+$entry[1].Split(' ')[1]) {[void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$q+'\'+$entry[0]+'" '+$entry[1]) 100)}}
 $r.stage='complete';$r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save}
if(!$r.passed){exit 1}
