# Ordinary active-console QA only; root owns the separate packet capture.
# No VPN, service, route, DNS setting, account or registry mutation.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$path='C:\Users\Public\Vault443Exchange\r7-dns6-positive.json'
$cli='C:\Program Files\Vault443\vault443-cli.exe'
$expected='2ad9a62ab0e14825cf265100891a16f74e80911e03b2d63cb036f3d976f3b1c6'
$r=[ordered]@{startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null;passed=$false;completed=$false;daemonSha256=$expected;server='2001:db8:44::1';localIP='2001:db8:44::2';physical=$null;preconditionPassed=$false;probes=@();udpBytes=0;tcpBytes=0;errorType=$null;errorLine=0;failedStage=$null}
$stage='preflight';$usedQueryIDs=@{}
function Snapshot {
 $p=[Diagnostics.Process]::new();$p.StartInfo.FileName=$cli;$p.StartInfo.Arguments='GetSnapshot';$p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
 $p.StartInfo.RedirectStandardInput=$true;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
 try{[void]$p.Start();$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync();$p.StandardInput.WriteLine('[]');$p.StandardInput.Close()
  if(!$p.WaitForExit(5000)){throw 'Snapshot timeout; no probes permitted'}
  if($p.ExitCode -ne 0){throw 'Snapshot denied or unavailable'}
  return($stdout.GetAwaiter().GetResult()|ConvertFrom-Json)
 }finally{$p.Dispose()}
}
function Assert-Off {
 $s=Snapshot
 if($s.canAdmin -or $s.busyByOtherUser -or $s.runtime.state -ne 'disconnected' -or $s.runtime.guardArmed -ne $false -or @($s.workProfiles|Where-Object {$_.runtime.state -ne 'disconnected'}).Count){throw 'All VPNs must already be explicitly disconnected with guard false'}
}
function Word([byte[]]$b,[int]$i){if($i -lt 0 -or $i+2 -gt $b.Length){throw 'DNS bounds'};return [int]$b[$i]*256+[int]$b[$i+1]}
function Skip-Name([byte[]]$b,[ref]$offset){
 $i=[int]$offset.Value
 for($labels=0;$labels -lt 128;$labels++){
  if($i -ge $b.Length){throw 'DNS name bounds'};$length=[int]$b[$i];$i++
  if($length -eq 0){$offset.Value=$i;return}
  if(($length -band 0xc0) -eq 0xc0){if($i -ge $b.Length -or ((($length -band 63)*256+[int]$b[$i]) -ge $b.Length)){throw 'DNS compression pointer bounds'};$offset.Value=$i+1;return}
  if($length -gt 63 -or $i+$length -gt $b.Length){throw 'DNS label bounds'};$i+=$length
 };throw 'DNS name exceeds bounds'
}
function Validate-DNS([byte[]]$b,[int]$id){
 if($b.Length -lt 12 -or (Word $b 0) -ne $id){throw 'DNS ID mismatch'}
 $flags=Word $b 2;$answers=Word $b 6;$rcode=$flags -band 15
 if(($flags -band 0x8000) -eq 0 -or ($flags -band 0x7800) -ne 0 -or ($flags -band 0x0200) -ne 0 -or $rcode -ne 0 -or (Word $b 4) -ne 1 -or $answers -lt 1 -or $answers -gt 64){throw 'DNS response header mismatch'}
 $i=12;Skip-Name $b ([ref]$i)
 if((Word $b $i) -ne 1 -or (Word $b ($i+2)) -ne 1){throw 'DNS A/IN question mismatch'};$i+=4;$a=@()
 for($n=0;$n -lt $answers;$n++){
  Skip-Name $b ([ref]$i)
  $type=Word $b $i;$class=Word $b ($i+2);$size=Word $b ($i+8);$i+=10
  if($i+$size -gt $b.Length){throw 'DNS RDATA bounds'}
  if($type -eq 1 -and $class -eq 1 -and $size -eq 4){$a+=([string]$b[$i]+'.'+$b[$i+1]+'.'+$b[$i+2]+'.'+$b[$i+3])};$i+=$size
 }
 if('93.184.215.14' -notin $a){throw 'DNS expected A answer missing'}
 return @{rcode=$rcode;answerCount=$answers;actualIP='93.184.215.14';responseID=(Word $b 0)}
}
function Read-Exact($socket,[int]$length){
 $b=New-Object byte[] $length;$n=0
 while($n -lt $length){$got=$socket.Receive($b,$n,$length-$n,[Net.Sockets.SocketFlags]::None);if($got -le 0){throw 'TCP DNS EOF'};$n+=$got};return ,$b
}
function Probe([bool]$UDP){
 Assert-Off
 $random=New-Object byte[] 2;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($random)}finally{$rng.Dispose()};$qid=[int]$random[0]*256+[int]$random[1]
 if($usedQueryIDs.ContainsKey($qid)){$qid=($qid+1)%65536;$random[0]=[byte]($qid -shr 8);$random[1]=[byte]($qid -band 255)};$usedQueryIDs[$qid]=$true
 $name='probe-'+[Guid]::NewGuid().ToString('N')+'.e2e.example.com';$bytes=[Collections.Generic.List[byte]]::new();$bytes.AddRange([byte[]]@($random[0],$random[1],1,0,0,1,0,0,0,0,0,0))
 foreach($label in ($name -split '\.')){$bytes.Add([byte]$label.Length);$bytes.AddRange([Text.Encoding]::ASCII.GetBytes($label))};$bytes.AddRange([byte[]]@(0,0,1,0,1));$query=$bytes.ToArray()
 $row=[ordered]@{transport=$(if($UDP){'UDP'}else{'TCP'});startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null;queryID=$qid;queryName=$name;sourceIf=[int]$adapter.ifIndex;sourceIP=$null;sourcePort=0;sent=$false;queryBytes=$query.Length;rawPositive=$false;responseBytes=0;wireResponseBytes=0;actualIP=$null;responseID=$null;rcode=$null;answerCount=0;passed=$false}
 $r.probes+=,$row
 $type=if($UDP){[Net.Sockets.SocketType]::Dgram}else{[Net.Sockets.SocketType]::Stream};$protocol=if($UDP){[Net.Sockets.ProtocolType]::Udp}else{[Net.Sockets.ProtocolType]::Tcp};$socket=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetworkV6,$type,$protocol)
 try{
  $socket.SendTimeout=3000;$socket.ReceiveTimeout=3000;$socket.SetSocketOption([Net.Sockets.SocketOptionLevel]::IPv6,[Net.Sockets.SocketOptionName]31,[int]$adapter.ifIndex)
  $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Parse('2001:db8:44::2'),0));$pending=$socket.BeginConnect([Net.IPAddress]::Parse('2001:db8:44::1'),53,$null,$null)
  try{if(!$pending.AsyncWaitHandle.WaitOne(3000)){throw 'DNS connect timeout'};$socket.EndConnect($pending)}finally{$pending.AsyncWaitHandle.Close()}
  $row.sourceIP=$socket.LocalEndPoint.Address.ToString();$row.sourcePort=$socket.LocalEndPoint.Port
  if($row.sourceIP -ne '2001:db8:44::2'){throw 'DNS physical source mismatch'}
  if($UDP){if($socket.Send($query) -ne $query.Length){throw 'Incomplete UDP DNS send'};$row.sent=$true;$buf=New-Object byte[] 8192;$got=$socket.Receive($buf);if($got -le 0){throw 'Empty UDP DNS response'};$response=[byte[]]$buf[0..($got-1)];$row.wireResponseBytes=$got}
  else{$frame=[byte[]](@([byte]($query.Length -shr 8),[byte]($query.Length -band 255))+$query);$n=0;while($n -lt $frame.Length){$got=$socket.Send($frame,$n,$frame.Length-$n,[Net.Sockets.SocketFlags]::None);if($got -le 0){throw 'Incomplete TCP DNS send'};$n+=$got};$row.sent=$true;$prefix=Read-Exact $socket 2;$size=Word $prefix 0;if($size -lt 12 -or $size -gt 8192){throw 'TCP DNS frame bounds'};$response=Read-Exact $socket $size;$row.wireResponseBytes=$size+2}
  $row.responseBytes=$response.Length;$row.rawPositive=$response.Length -gt 0;$valid=Validate-DNS $response $qid
  foreach($key in $valid.Keys){$row[$key]=$valid[$key]};$row.passed=$true
  if($UDP){$r.udpBytes=$row.wireResponseBytes}else{$r.tcpBytes=$row.wireResponseBytes}
 }finally{$socket.Dispose();$row.finishedUtc=[DateTime]::UtcNow.ToString('o')}
}
try{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 if(([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ordinary console user required'}
 $machine=Get-CimInstance Win32_ComputerSystem
 if($machine.Name -notin @('VAULT443-WIN10','VAULT443-WIN11') -or $machine.Model -ne 'VirtualBox'){throw 'Named isolated VM required'}
 if(!('Vault443R7DNSConsole' -as [type])){Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class Vault443R7DNSConsole { [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId(); }
'@
 }
 $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
 if(!$session -or $session -ne [Vault443R7DNSConsole]::WTSGetActiveConsoleSessionId()){throw 'ACTIVE console session required'}
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe' -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){throw 'Exact R7 daemon required'}
 Assert-Off
 $adapters=@(Get-NetAdapter -Physical|Where-Object Status -eq 'Up')
 if($adapters.Count -ne 1){throw 'Unique physical uplink required'};$adapter=$adapters[0]
 $g=[Guid]::Empty;if(![Guid]::TryParse([string]$adapter.InterfaceGuid,[ref]$g) -or $g -eq [Guid]::Empty){throw 'Invalid physical GUID'}
 $preferred=@(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6|Where-Object {$_.IPAddress -eq '2001:db8:44::2' -and $_.AddressState -eq 'Preferred'})
 $gateway=@(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -DestinationPrefix '::/0' -PolicyStore ActiveStore|Where-Object NextHop -eq '2001:db8:44::1')
 if($preferred.Count -ne 1 -or !$gateway.Count -or $adapter.MacAddress -notmatch '^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$'){throw 'Physical IPv6 preferred address/gateway/MAC precondition failed'}
 $r.physical=@{interfaceIndex=[int]$adapter.ifIndex;guid=[string]$adapter.InterfaceGuid;mac=$adapter.MacAddress;address='2001:db8:44::2';addressState='Preferred';gateway='2001:db8:44::1'};$r.preconditionPassed=$true
 $stage='UDP53';Probe $true;$stage='TCP53';Probe $false;$stage='final-guard-off';Assert-Off
 $r.completed=$true;$r.passed=(@($r.probes|Where-Object passed -ne $true).Count -eq 0 -and $r.probes.Count -eq 2)
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber;$r.failedStage=$stage}
finally{$r.finishedUtc=[DateTime]::UtcNow.ToString('o');$r|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $path -Encoding UTF8}
$r|ConvertTo-Json -Depth 7
if(!$r.passed){exit 1}
