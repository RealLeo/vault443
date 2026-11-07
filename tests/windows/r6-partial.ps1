# Ordinary active-console R6 partial-peer acceptance; no fault actions or connects.
param([Parameter(Mandatory=$true)][ValidateSet('baseline','blocked','recovered')][string]$Phase)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Net.WebRequest]::DefaultWebProxy=$null
$x='C:\Users\Public\Vault443Exchange';$q='C:\Program Files\Vault443QA';$directory=Join-Path $x 'r6-partial'
$cli='C:\Program Files\Vault443\vault443-cli.exe';$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sha='9cedea599af02f8afe3434f2b7a56aa167075be4cd7ced21ef3dea924140bf25'
$started=[DateTime]::UtcNow;$reportPath=Join-Path $directory ($started.ToString('yyyyMMddTHHmmssfffZ')+'-'+$Phase+'.json');$statePath=Join-Path $directory 'baseline.state.json'
$r=[ordered]@{schema=1;phase=$Phase;startedUTC=$started.ToString('o');finishedUTC=$null;completed=$false;passed=$false;fixturePreconditionFailure=$false;daemonSHA=$sha;identity=$null;progress=$null;checks=@();errorType=$null;errorLine=0;noConnectOrResetRequested=$true;limits=@('Root owns exact fixture UDP51822 DROP, pcap and finally cleanup.','peer2.wg.e2e.test may resolve through the healthy DNS coordinator while peer2 transport fails.','Missing fixture positives invalidate the precondition, not the product.')}
New-Item -ItemType Directory -Force -Path $directory|Out-Null
function Save {$script:r|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $reportPath -Encoding UTF8}
function Check([string]$Name,[bool]$Passed,$Observation=$null){$script:r.checks+=@{check=$Name;passed=$Passed;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation};Save;if(!$Passed){if($Phase-eq'baseline'){$script:r.fixturePreconditionFailure=$true};throw 'Partial-peer check failed; inspect sanitized report'}}
function Invoke-R6RPC([string]$Method){$text='[]'|& $cli $Method;if($LASTEXITCODE){throw 'Read-only RPC failed'};return($text|ConvertFrom-Json)}
function Own($s,[string]$Name){$p=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$Name));if($p.Count-ne1){throw 'Expected one caller-owned work fixture'};return $p[0]}
function Identity($s){$service=Get-CimInstance Win32_Service -Filter "Name='Vault443'";$process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$service.ProcessId);if($service.State-ne'Running'-or!$process.CreationDate){throw 'Cannot establish live SCM process identity'};return @{machine=$env:COMPUTERNAME;userSID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;sessionID=[Diagnostics.Process]::GetCurrentProcess().SessionId;daemonPID=[int]$service.ProcessId;daemonCreated=$process.CreationDate.ToUniversalTime().ToString('o');mainID=$s.activeProfileId;multiID=(Own $s 'wireguard-multi').id;awgID=(Own $s 'amneziawg').id;openvpnID=(Own $s 'openvpn').id}}
function Continuity($s){$now=Identity $s;foreach($key in @('machine','userSID','sessionID','daemonPID','daemonCreated','mainID','multiID','awgID','openvpnID')){if($now[$key]-ne$script:expected.$key){throw 'Owner/profile/SCM continuity changed'}};if($s.busyByOtherUser-or!$s.runtime.guardArmed-or$s.runtime.state-ne'connected'-or(Own $s 'amneziawg').runtime.state-ne'connected'-or(Own $s 'openvpn').runtime.state-ne'connected'){throw 'Main/other work health changed'};return(Own $s 'wireguard-multi')}
function HTTP([string]$Address,[bool]$Expected){$uri=if($Address.Contains(':')){'http://['+$Address+']:18080/'}else{'http://'+$Address+':18080/'};$ok=$false;$received=$false;$peer=$null;$kind=$null
 try{$v=Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 4;$received=$true;$text=if($v.Content-is[byte[]]){[Text.Encoding]::UTF8.GetString($v.Content)}else{[string]$v.Content};$body=$text|ConvertFrom-Json;$peer=[string]$body.peer;$expectedPeers=if($Address.Contains(':')){@('2001:db8:80::2','2001:db8:82::2')}else{@('198.19.44.2','198.19.46.2')};$ok=$body.marker-eq'work-e2e-ok'-and$peer-in$expectedPeers;if(!$ok){$kind='marker-or-shared-client-source-mismatch'}}catch{$kind=$_.Exception.GetType().FullName;if($_.Exception.Response){$received=$true}}
 Check ('http-'+$Address) ($(if($Expected){$ok}else{!$received})) @{expectedSuccess=$Expected;received=$received;validFixtureResponse=$ok;peer=$peer;failureClass=$kind}
}
function Raw-Probe([string]$Address, [int]$Port, [byte[]]$Payload, [bool]$UDP, [int]$InterfaceIndex = 0) {
    $ip = [Net.IPAddress]::Parse($Address)
    $type = if ($UDP) {[Net.Sockets.SocketType]::Dgram} else {[Net.Sockets.SocketType]::Stream}
    $transport = if ($UDP) {[Net.Sockets.ProtocolType]::Udp} else {[Net.Sockets.ProtocolType]::Tcp}
    $socket = [Net.Sockets.Socket]::new($ip.AddressFamily, $type, $transport)
    try {
        $socket.SendTimeout = 3000; $socket.ReceiveTimeout = 3000
        if ($InterfaceIndex -gt 0) {
            $level = [Net.Sockets.SocketOptionLevel]::IPv6; $index = $InterfaceIndex
            if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
                $level = [Net.Sockets.SocketOptionLevel]::IP
                $index = [Net.IPAddress]::HostToNetworkOrder([int]$InterfaceIndex)
            }
            $socket.SetSocketOption($level, [Net.Sockets.SocketOptionName]31, [int]$index)
        }
        $async = $socket.BeginConnect($ip, $Port, $null, $null)
        try {
            if (!$async.AsyncWaitHandle.WaitOne(3000)) { return $null }
            $socket.EndConnect($async)
        } finally { $async.AsyncWaitHandle.Close() }
        $sent = 0
        while ($sent -lt $Payload.Length) {
            $written = $socket.Send($Payload, $sent, $Payload.Length - $sent, [Net.Sockets.SocketFlags]::None)
            if ($written -le 0) { return $null }
            $sent += $written
        }
        if (!$socket.Poll(3000000, [Net.Sockets.SelectMode]::SelectRead)) { return $null }
        $buffer = New-Object byte[] 8192
        $received = $socket.Receive($buffer)
        if ($received -le 0) { return $null }
        return ,([byte[]]$buffer[0..($received - 1)])
    } catch [Net.Sockets.SocketException] { return $null }
    finally { $socket.Dispose() }
}

# Static Raw-Probe/DNS-Query pattern from main-matrix; exact fixture responses only.
function DNS-Query([string]$Zone,[bool]$AAAA){
 $bytes=New-Object 'System.Collections.Generic.List[byte]';$bytes.AddRange([byte[]]@(0x44,0x33,1,0,0,1,0,0,0,0,0,0))
 foreach($label in (('partial-'+[Guid]::NewGuid().ToString('N')+'.'+$Zone)-split'\.')){$bytes.Add([byte]$label.Length);$bytes.AddRange([Text.Encoding]::ASCII.GetBytes($label))}
 $type=if($AAAA){28}else{1};$bytes.AddRange([byte[]]@(0,0,$type,0,1));return ,$bytes.ToArray()
}
function DirectDNS([string]$Server,[string]$Zone,[bool]$Expected){foreach($tcp in @($false,$true)){foreach($aaaa in @($false,$true)){
 $query=DNS-Query $Zone $aaaa;$payload=$query;if($tcp){$payload=[byte[]](@([byte]($query.Length-shr8),[byte]($query.Length-band255))+$query)}
 $answer=Raw-Probe $Server 53 $payload (!$tcp);$got=($null-ne$answer-and$answer.Length-gt0);$valid=$false
 if($got){if($tcp-and$answer.Length-ge2){$answer=[byte[]]$answer[2..($answer.Length-1)]};$destination=if($Zone-like'peer2.*'){if($aaaa){'2001:db8:82::10'}else{'198.19.46.10'}}else{if($aaaa){'2001:db8:80::10'}else{'198.19.44.10'}};$ip=[Net.IPAddress]::Parse($destination).GetAddressBytes()
  if($answer.Length-ge(12+$ip.Length)){$tail=[byte[]]$answer[($answer.Length-$ip.Length)..($answer.Length-1)];$valid=$answer[0]-eq0x44-and$answer[1]-eq0x33-and($answer[2]-band0x80)-ne0-and($answer[3]-band15)-eq0-and(($answer[6]-shl8)+$answer[7])-gt0-and[Convert]::ToBase64String($tail)-eq[Convert]::ToBase64String($ip)}
 }
 Check ('direct-dns-'+$Server+'-tcp'+$tcp+'-aaaa'+$aaaa) ($(if($Expected){$valid}else{!$got})) @{expectedSuccess=$Expected;received=$got;validFixtureAnswer=$valid;tcp=$tcp;aaaa=$aaaa}
}}}
function CoordinatorDNS {foreach($zone in @('wg.e2e.test','peer2.wg.e2e.test')){foreach($type in @('A','AAAA')){
 $expectedIP=if($zone-like'peer2.*'){if($type-eq'AAAA'){'2001:db8:82::10'}else{'198.19.46.10'}}else{if($type-eq'AAAA'){'2001:db8:80::10'}else{'198.19.44.10'}}
 $ok=$false;$kind=$null;try{$answers=Resolve-DnsName ('partial-'+[Guid]::NewGuid().ToString('N')+'.'+$zone) -Type $type -DnsOnly -QuickTimeout -ErrorAction Stop;$ok=@($answers|Where-Object IPAddress -eq $expectedIP).Count-gt0}catch{$kind=$_.FullyQualifiedErrorId}
 Check ('coordinator-'+$zone+'-'+$type) $ok @{expectedIP=$expectedIP;failureClass=$kind}
}}}
function OtherTraffic {foreach($entry in @(@('main-matrix.ps1',('-Phase verify -Protocol vless -OutputDirectory "'+$x+'\r6-protocols\main"')),@('work-smoke.ps1','-Profile amneziawg -Phase verify -WaitSeconds 0'),@('openvpn-smoke.ps1','-Profile openvpn -Phase verify -WaitSeconds 0'))){
 $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=$ps;$start.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $q $entry[0])+'" '+$entry[1];$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$p=New-Object Diagnostics.Process;$p.StartInfo=$start
 try{[void]$p.Start();$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();if(!$p.WaitForExit(100000)){$p.Kill();[void]$p.WaitForExit(2000);throw 'Existing helper deadline'};[void]$out.GetAwaiter().GetResult();[void]$err.GetAwaiter().GetResult();Check ('other-real-traffic-'+$entry[0]) ($p.ExitCode-eq0)}finally{$p.Dispose()}
}}
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$machine=Get-CimInstance Win32_ComputerSystem
 if(([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or$env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$machine.Model-ne'VirtualBox'-or![Diagnostics.Process]::GetCurrentProcess().SessionId-or!$machine.UserName-or([Security.Principal.NTAccount]::new($machine.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value){throw 'Ordinary named active-console QA required'}
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha){throw 'Exact R6 daemon required'}
 $s=Invoke-R6RPC GetSnapshot;$mainProfile=@($s.profiles|Where-Object id -eq $s.activeProfileId)
 if($s.canAdmin-or$mainProfile.Count-ne1-or$mainProfile[0].kind-ne'vless'){throw 'Own VLESS required'}
 if($Phase-eq'baseline'){$script:expected=Identity $s}else{$script:expected=Get-Content $statePath -Raw|ConvertFrom-Json}
 $r.identity=$script:expected;$multi=Continuity $s
 $peer1=@($multi.runtime.peers|Where-Object endpoint -eq '192.0.2.1:51820');$peer2=@($multi.runtime.peers|Where-Object endpoint -eq '192.0.2.1:51822')
 Check 'exact-two-peer-fixture' ($multi.runtime.peers.Count-eq2-and$peer1.Count-eq1-and$peer2.Count-eq1)
 if($Phase-eq'baseline'){Check 'baseline-both-authenticated' ($multi.runtime.state-eq'connected'-and$peer1[0].state-eq'connected'-and$peer2[0].state-eq'connected')}
 else {
  $wait=if($Phase-eq'blocked'){300}else{90};$deadline=[DateTime]::UtcNow.AddSeconds($wait);$ready=$false
  do {$s=Invoke-R6RPC GetSnapshot;$multi=Continuity $s;$peers=@($multi.runtime.peers);$dead=@($peers|Where-Object endpoint -eq '192.0.2.1:51822');$healthy=@($peers|Where-Object endpoint -eq '192.0.2.1:51820')
   $ready=if($Phase-eq'blocked'){$multi.runtime.state-eq'partial'-and$dead.Count-eq1-and$dead[0].state-eq'reconnecting'-and$healthy.Count-eq1-and$healthy[0].state-eq'connected'}else{$multi.runtime.state-eq'connected'-and$peers.Count-eq2-and!@($peers|Where-Object state -ne 'connected').Count}
   $r.progress=@{utc=[DateTime]::UtcNow.ToString('o');deadlineUTC=$deadline.ToString('o');elapsedSeconds=[int]([DateTime]::UtcNow-$started).TotalSeconds;ready=$ready;workState=$multi.runtime.state;peers=@($peers|ForEach-Object {@{id=$_.id;endpoint=$_.endpoint;state=$_.state;lastHandshakeAt=$_.lastHandshakeAt}})};Save
   if(!$ready){Start-Sleep -Seconds 5}
  }while(!$ready-and[DateTime]::UtcNow-lt$deadline)
  Check ('automatic-'+$Phase+'-state') $ready
 }
 $deadExpected=$Phase-ne'blocked'
 HTTP '198.19.44.10' $true;HTTP '2001:db8:80::10' $true;HTTP '198.19.46.10' $deadExpected;HTTP '2001:db8:82::10' $deadExpected
 CoordinatorDNS
 DirectDNS '198.19.44.1' 'wg.e2e.test' $true;DirectDNS '2001:db8:80::1' 'wg.e2e.test' $true
 DirectDNS '198.19.46.1' 'peer2.wg.e2e.test' $deadExpected;DirectDNS '2001:db8:82::1' 'peer2.wg.e2e.test' $deadExpected
 OtherTraffic;[void](Continuity (Invoke-R6RPC GetSnapshot));$r.passed=$true
 if($Phase-eq'baseline'){$expected|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $statePath -Encoding UTF8}
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save}
@{passed=$r.passed;phase=$Phase;report=$reportPath}|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
