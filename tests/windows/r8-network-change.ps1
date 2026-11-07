# Isolated static underlay change, not DHCP/RDNSS. UAC change holds a bounded
# window and restores its exact mutations in finally. Root owns packet capture.
param(
 [Parameter(Mandatory=$true)][ValidateSet('change','verify','restore')][string]$Mode,
 [ValidateSet('changed','restored')][string]$ExpectedState='changed',
 [ValidateRange(60,300)][int]$HoldSeconds=240
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Net.WebRequest]::DefaultWebProxy=$null
$q='C:\Program Files\Vault443QA';$private='C:\ProgramData\Vault443-QA';$cli='C:\Program Files\Vault443\vault443-cli.exe';$x='C:\Users\Public\Vault443Exchange'
$journalPath=Join-Path $private 'r8-network-change.json';$signalPath=Join-Path $q 'reports\r8-network-change-state.json';$journal=$null;$canReport=$false;$changed=$false
$sha='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50';$old4='192.0.2.2';$old6='2001:db8:44::2';$new4='192.0.2.3';$new6='2001:db8:44::3';$dnsOld='192.0.2.1';$dnsNew='2001:db8:44::1'
$r=[ordered]@{schema=1;mode=$Mode;expectedState=$ExpectedState;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;restored=$false;stage='preflight';checks=@();errorType=$null;errorLine=0;cleanupErrorType=$null;cleanupErrorLine=0;limits=@('One static IPv4/IPv6 source and resolver change on the bound isolated uplink, not DHCP or RDNSS.','Root owns capture including .2/.3 and ::2/::3; packet analysis is separate.','Verify never imports, connects, restarts, or mutates network settings.')}
function Protected([string]$Path,[bool]$PrivatePath){$i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse QA input'};$a=Get-Acl $Path;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')){throw 'Untrusted QA owner'};$raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if($null-eq$raw.DiscretionaryAcl){throw 'Null QA DACL'};$mask=0x500D0156;if($PrivatePath){$mask=$mask-bor0x80000021};foreach($e in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and!($e.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$e.IdentityReference.Value-notin@('S-1-5-18','S-1-5-32-544')-and([long]$e.FileSystemRights-band$mask)){throw 'Untrusted QA permissions'}}}
function Atomic-JSON([string]$Path,$Value,[bool]$PrivatePath){$temp=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp';try{$bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 9));$f=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};$acl=New-Object Security.AccessControl.FileSecurity;$sddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)';if(!$PrivatePath){$sddl+='(A;;FR;;;BU)'};$acl.SetSecurityDescriptorSddlForm($sddl);Set-Acl $temp $acl;if(Test-Path $Path){Protected $Path $PrivatePath;[IO.File]::Replace($temp,$Path,[NullString]::Value)}else{[IO.File]::Move($temp,$Path)}}finally{if(Test-Path $temp){Remove-Item $temp -Force}}}
function Save-Journal{Atomic-JSON $journalPath $journal $true}
function Signal([string]$Phase){$journal.phase=$Phase;Save-Journal;Atomic-JSON $signalPath @{schema=1;machine=$journal.machine;controllerSID=$journal.controllerSID;token=$journal.token;guid=$journal.guid;mac=$journal.mac;mainID=$journal.mainID;work=$journal.work;phase=$Phase;utc=[DateTime]::UtcNow.ToString('o');newIPv4=$new4;newIPv6=$new6;oldIPv4=$old4;oldIPv6=$old6;oldDNS=$dnsOld;newDNS=$dnsNew;holdSeconds=$HoldSeconds} $false}
function Check([string]$Name,[bool]$Pass,$Observation=$null){$script:r.checks+=@{check=$Name;passed=$Pass;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation};if(!$Pass){throw 'Network change acceptance check failed'}}
function Call([string]$Method){$p=New-Object Diagnostics.Process;$i=$p.StartInfo;$i.FileName=$cli;$i.Arguments=$Method;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardInput=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true;try{[void]$p.Start();$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync();$p.StandardInput.WriteLine('[]');$p.StandardInput.Close();if(!$p.WaitForExit(8000)){$p.Kill();throw 'Snapshot deadline'};$text=$o.GetAwaiter().GetResult();[void]$e.GetAwaiter().GetResult();if($p.ExitCode){throw 'Snapshot denied'};return($text|ConvertFrom-Json)}finally{$p.Dispose()}}
function Physical($Binding){$a=@(Get-NetAdapter -Physical|Where-Object {[Guid]$_.InterfaceGuid-eq[Guid]$Binding.guid-and$_.MacAddress-eq$Binding.mac});if($a.Count-ne1-or$a[0].Status-ne'Up'){throw 'Exact physical GUID/MAC/up state required'};return $a[0]}
function DNS($Adapter){return @((Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex).ServerAddresses|Where-Object {$_}|ForEach-Object {[Net.IPAddress]::Parse([string]$_).ToString()}|Sort-Object -Unique)}
# The cmdlet keeps the other address family's static list unless reset explicitly.
# Original fixture: one IPv4 resolver and an empty IPv6 list. Both transitions
# are covered by the existing write-ahead dnsChanged intent and exact DNS guard.
function Set-PhysicalDNS($Adapter,[bool]$UseChanged){
 $v4=@(Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4);$v6=@(Get-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv6)
 if($v4.Count-ne1-or$v6.Count-ne1){throw 'Exact physical DNS family instances required'}
 if($UseChanged){Set-DnsClientServerAddress -InputObject $v4[0] -ResetServerAddresses;Set-DnsClientServerAddress -InputObject $v6[0] -ServerAddresses @($dnsNew)}
 else{Set-DnsClientServerAddress -InputObject $v6[0] -ResetServerAddresses;Set-DnsClientServerAddress -InputObject $v4[0] -ServerAddresses @($dnsOld)}
}
function Globals($Adapter){return @(Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex -PolicyStore ActiveStore|Where-Object {$_.IPAddress-notlike'fe80:*'})}
function Address($Adapter,[string]$IP,[int]$Prefix){$rows=@(Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex -PolicyStore ActiveStore|Where-Object IPAddress -eq $IP);if($rows.Count-gt1){throw 'Ambiguous owned IP'};if($rows.Count-and($rows[0].PrefixLength-ne$Prefix-or$rows[0].PrefixOrigin-ne'Manual'-or$rows[0].SkipAsSource)){throw 'Owned IP identity changed'};return $rows}
function Gateways($Adapter){$g4=@(Get-NetRoute -InterfaceIndex $Adapter.ifIndex -PolicyStore ActiveStore -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue);$g6=@(Get-NetRoute -InterfaceIndex $Adapter.ifIndex -PolicyStore ActiveStore -DestinationPrefix '::/0' -ErrorAction SilentlyContinue);if($g4.Count-ne1-or$g4[0].NextHop-ne'192.0.2.1'-or$g6.Count-ne1-or[Net.IPAddress]::Parse($g6[0].NextHop).ToString()-ne'2001:db8:44::1'){throw 'Static physical gateways changed'}}
function Static-Mode($Adapter){$v4=Get-NetIPInterface -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4;$v6=Get-NetIPInterface -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv6;if([string]$v4.Dhcp-ne'Disabled'-or[string]$v6.RouterDiscovery-ne'Disabled'){throw 'Static fixture DHCP/RouterDiscovery precondition differs; no dynamic setting will be rewritten'}}
function Wait-Address($Adapter,[string]$IP,[int]$Prefix){$end=[DateTime]::UtcNow.AddSeconds(10);do{$v=@(Address $Adapter $IP $Prefix);if($v.Count-eq1-and$v[0].AddressState-eq'Preferred'){return};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow-lt$end);throw 'Preferred owned IP deadline'}
function Read-Journal{Protected $journalPath $true;if((Get-Item $journalPath).Length-gt64KB){throw 'Oversized ownership journal'};$j=Get-Content $journalPath -Raw|ConvertFrom-Json;$token=[Guid]::Empty;if($j.schema-ne1-or$j.machine-ne$env:COMPUTERNAME-or$j.controllerSID-ne$id.User.Value-or![Guid]::TryParse([string]$j.token,[ref]$token)-or$token-eq[Guid]::Empty-or$j.old4-ne$old4-or$j.old6-ne$old6-or$j.new4-ne$new4-or$j.new6-ne$new6-or$j.oldDNS-ne$dnsOld-or$j.newDNS-ne$dnsNew-or$j.phase-notin@('creating','changed','restoring','restored','restore_failed')){throw 'Foreign network-change journal'};return $j}
function Restore-Owned{
 $a=Physical $journal;Static-Mode $a;$journal.phase='restoring';Save-Journal
 $currentDNS=@(DNS $a);$dnsOwned=$currentDNS.Count-le2-and!@($currentDNS|Where-Object {$_-notin@($dnsOld,$dnsNew)}).Count
 foreach($row in @(@($old4,24,'removed4'),@($old6,64,'removed6'))){if($journal.($row[2])){$v=@(Address $a $row[0] $row[1]);if(!$v.Count){New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $row[0] -PrefixLength $row[1] -PolicyStore ActiveStore|Out-Null};Wait-Address $a $row[0] $row[1]}}
 if($journal.dnsChanged-and$dnsOwned){Set-PhysicalDNS $a $false}
 foreach($row in @(@($new4,24,'created4'),@($new6,64,'created6'))){if($journal.($row[2])){$v=@(Address $a $row[0] $row[1]);if($v.Count){Remove-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $row[0] -PolicyStore ActiveStore -Confirm:$false}}}
 Gateways $a;$v=@(Globals $a);$dns=@(DNS $a)
 if($v.Count-ne2-or!@($v|Where-Object IPAddress -eq $old4).Count-or!@($v|Where-Object IPAddress -eq $old6).Count-or$dns.Count-ne1-or$dns[0]-ne$dnsOld){throw 'Exact original underlay restoration differs; no foreign resource overwritten'}
 Signal 'restored';$script:r.restored=$true
}
function Raw([string]$IP,[int]$Port,[byte[]]$Payload,[bool]$UDP,[int]$Index=0){$address=[Net.IPAddress]::Parse($IP);$type=if($UDP){[Net.Sockets.SocketType]::Dgram}else{[Net.Sockets.SocketType]::Stream};$proto=if($UDP){[Net.Sockets.ProtocolType]::Udp}else{[Net.Sockets.ProtocolType]::Tcp};$socket=[Net.Sockets.Socket]::new($address.AddressFamily,$type,$proto);try{$socket.SendTimeout=3000;$socket.ReceiveTimeout=3000;if($Index){$level=if($address.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetwork){[Net.Sockets.SocketOptionLevel]::IP}else{[Net.Sockets.SocketOptionLevel]::IPv6};$number=if($address.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetwork){[Net.IPAddress]::HostToNetworkOrder($Index)}else{$Index};$socket.SetSocketOption($level,[Net.Sockets.SocketOptionName]31,[int]$number)};$pending=$socket.BeginConnect($address,$Port,$null,$null);try{if(!$pending.AsyncWaitHandle.WaitOne(3000)){return $null};$socket.EndConnect($pending)}finally{$pending.AsyncWaitHandle.Close()};$sent=0;while($sent-lt$Payload.Length){$n=$socket.Send($Payload,$sent,$Payload.Length-$sent,[Net.Sockets.SocketFlags]::None);if(!$n){return $null};$sent+=$n};if(!$socket.Poll(3000000,[Net.Sockets.SelectMode]::SelectRead)){return $null};$buffer=New-Object byte[] 8192;$n=$socket.Receive($buffer);if($n){return ,([byte[]]$buffer[0..($n-1)])};return $null}catch [Net.Sockets.SocketException]{return $null}finally{$socket.Dispose()}}
function DNS-Payload{$b=New-Object 'System.Collections.Generic.List[byte]';$b.AddRange([byte[]]@(68,51,1,0,0,1,0,0,0,0,0,0));foreach($label in (([Guid]::NewGuid().ToString('N')+'.e2e.example.com')-split'\.')){$b.Add([byte]$label.Length);$b.AddRange([Text.Encoding]::ASCII.GetBytes($label))};$b.AddRange([byte[]]@(0,0,1,0,1));return ,$b.ToArray()}
function Traffic($Binding){
 $a=Physical $Binding;Static-Mode $a;Gateways $a;$want4=if($ExpectedState-eq'changed'){$new4}else{$old4};$want6=if($ExpectedState-eq'changed'){$new6}else{$old6};$wantDNS=if($ExpectedState-eq'changed'){$dnsNew}else{$dnsOld};$ips=@(Globals $a);$dns=@(DNS $a)
 Check 'exact-address-resolver-state' ($ips.Count-eq2-and@($ips|Where-Object {$_.IPAddress-eq$want4-and$_.PrefixLength-eq24-and$_.AddressState-eq'Preferred'}).Count-eq1-and@($ips|Where-Object {$_.IPAddress-eq$want6-and$_.PrefixLength-eq64-and$_.AddressState-eq'Preferred'}).Count-eq1-and$dns.Count-eq1-and$dns[0]-eq$wantDNS) @{addresses=@($ips.IPAddress);dns=$dns;index=$a.ifIndex}
 $end=[DateTime]::UtcNow.AddSeconds(90);do{$s=Call GetSnapshot;$good=!$s.busyByOtherUser-and!$s.canAdmin-and$s.runtime.state-eq'connected'-and$s.runtime.guardArmed-and$s.activeProfileId-eq$Binding.mainID;foreach($work in $Binding.work){if(@($s.workProfiles|Where-Object {$_.id-eq$work.id-and$_.runtime.state-eq'connected'}).Count-ne1){$good=$false}};if($good){break};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow-lt$end)
 Check 'automatic-main-three-work-recovery' $good
 foreach($entry in @(@('web.e2e.example.com','93.184.215.14'),@('web6.e2e.example.com','2001:db8:66::14'))){$v=Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri ('https://'+$entry[0]+'/') -TimeoutSec 12;$body=if($v.Content-is[byte[]]){[Text.Encoding]::UTF8.GetString($v.Content)|ConvertFrom-Json}else{$v.Content|ConvertFrom-Json};Check ('main-http-'+$entry[0]) ($body.marker-eq'vless-e2e-ok'-and$body.peer-eq$entry[1]) @{peer=$body.peer}}
 foreach($ip in @('93.184.215.14','2001:db8:66::14')){$nonce=[Guid]::NewGuid().ToString('N');$reply=Raw $ip 18081 ([Text.Encoding]::ASCII.GetBytes('vault443-main-udp:'+$nonce)) $true;if(!$reply){throw 'Main UDP did not recover'};$body=[Text.Encoding]::UTF8.GetString($reply)|ConvertFrom-Json;Check ('main-udp-'+$ip) ($body.marker-eq'main-udp-e2e-ok'-and$body.nonce-eq$nonce-and$body.peer-eq$ip)}
 foreach($type in @('A','AAAA')){foreach($tcp in @($false,$true)){$target=if($type-eq'A'){'93.184.215.14'}else{'2001:db8:66::14'};$answers=@(Resolve-DnsName ([Guid]::NewGuid().ToString('N')+'.webdual.e2e.example.com') -Type $type -TcpOnly:$tcp -DnsOnly -QuickTimeout -ErrorAction Stop);Check ('main-dns-'+$type+'-tcp'+$tcp) (@($answers|Where-Object IPAddress -eq $target).Count-gt0)}}
 foreach($ip in @('93.184.215.14','2001:db8:66::14')){Check ('physical-tcp-block-'+$ip) (!(Raw $ip 8080 ([Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`n`r`n")) $false $a.ifIndex));Check ('physical-udp-block-'+$ip) (!(Raw $ip 18081 ([Text.Encoding]::ASCII.GetBytes('vault443-main-udp:'+ [Guid]::NewGuid().ToString('N'))) $true $a.ifIndex))}
 foreach($ip in @($dnsOld,$dnsNew)){$payload=DNS-Payload;Check ('physical-dns-udp-block-'+$ip) (!(Raw $ip 53 $payload $true $a.ifIndex));$tcpPayload=[byte[]]@([byte]($payload.Length-shr8),[byte]($payload.Length-band255))+$payload;Check ('physical-dns-tcp-block-'+$ip) (!(Raw $ip 53 $tcpPayload $false $a.ifIndex))}
 $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 foreach($entry in @(@('work-smoke.ps1','-Profile wireguard-multi -Phase verify -WaitSeconds 45'),@('work-smoke.ps1','-Profile amneziawg -Phase verify -WaitSeconds 45'),@('openvpn-smoke.ps1','-Phase verify -WaitSeconds 45'))){$p=New-Object Diagnostics.Process;$p.StartInfo.FileName=$ps;$p.StartInfo.Arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$q+'\'+$entry[0]+'" '+$entry[1];$p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true;try{[void]$p.Start();$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync();if(!$p.WaitForExit(100000)){$p.Kill();throw 'Work verify deadline'};[void]$o.GetAwaiter().GetResult();[void]$e.GetAwaiter().GetResult();Check ('real-work-'+$entry[1].Split(' ')[1]) ($p.ExitCode-eq0)}finally{$p.Dispose()}}
 $fresh=Get-Content $signalPath -Raw|ConvertFrom-Json;Check 'same-complete-change-window' ($fresh.token-eq$Binding.token-and$fresh.phase-eq$ExpectedState)
}
try{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$admin=([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);$computer=Get-CimInstance Win32_ComputerSystem
 if(!('Vault443R8NetworkConsole'-as[type])){Add-Type 'using System.Runtime.InteropServices; public static class Vault443R8NetworkConsole { [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId(); }'}
 if([Diagnostics.Process]::GetCurrentProcess().SessionId-ne[Vault443R8NetworkConsole]::WTSGetActiveConsoleSessionId()){throw 'Actual active console session required'}
 if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$computer.Model-ne'VirtualBox'-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$id.User.Value-or! [Diagnostics.Process]::GetCurrentProcess().SessionId-or(($Mode-eq'verify')-eq$admin)){throw 'Same active-console controller; change/restore UAC, verify ordinary required'}
 Protected $q $false;Protected (Join-Path $q 'reports') $false;$canReport=$true
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha){throw 'Exact R8 daemon required'}
 if($Mode-eq'verify'){
  Protected $signalPath $false;$binding=Get-Content $signalPath -Raw|ConvertFrom-Json
  if($binding.schema-ne1-or$binding.machine-ne$env:COMPUTERNAME-or$binding.controllerSID-ne$id.User.Value-or$binding.phase-ne$ExpectedState){throw 'Exact protected change-window signal required'}
  Traffic $binding;$r.passed=$true
 }else{
  Protected $private $true;Protected (Join-Path $private 'marker') $true;Protected (Join-Path $private 'qa-inputs.json') $true
  if([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'Private QA marker differs'}
  $config=Get-Content (Join-Path $private 'qa-inputs.json') -Raw|ConvertFrom-Json
  if($config.machine-ne$env:COMPUTERNAME-or$config.controllerSID-ne$id.User.Value){throw 'Bound QA controller differs'}
  if($Mode-eq'restore'){$journal=Read-Journal;if([Guid]$journal.guid-ne[Guid]$config.adapterGuid-or$journal.mac-ne$config.adapterMAC){throw 'Bound physical journal differs'};Restore-Owned;$r.passed=$true}
  else{
   if((Test-Path $journalPath)-or(Test-Path $signalPath)){throw 'Previous network-change ownership state refused'}
   $binding=@{guid=$config.adapterGuid;mac=$config.adapterMAC};$a=Physical $binding;Static-Mode $a;Gateways $a;$ips=@(Globals $a);$dns=@(DNS $a)
   if($ips.Count-ne2-or$dns.Count-ne1-or$dns[0]-ne$dnsOld){throw 'Exact original static fixture addresses/DNS required'}
   Wait-Address $a $old4 24;Wait-Address $a $old6 64
   foreach($ip in @($new4,$new6)){if(@(Get-NetIPAddress -PolicyStore ActiveStore|Where-Object IPAddress -eq $ip).Count-or@(Get-NetIPAddress -PolicyStore PersistentStore -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $ip).Count){throw 'Target IP already exists; refusing adoption'}}
   $s=Call GetSnapshot;$main=@($s.profiles|Where-Object id -eq $s.activeProfileId);$work=@()
   if($s.busyByOtherUser-or$s.runtime.state-ne'connected'-or!$s.runtime.guardArmed-or$main.Count-ne1-or$main[0].kind-ne'vless'){throw 'Own connected protected VLESS required'}
   foreach($name in @('wireguard-multi','amneziawg','openvpn')){$w=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$name));if($w.Count-ne1-or$w[0].runtime.state-ne'connected'){throw 'Three original connected split work fixtures required'};$work+=@{id=$w[0].id;kind=$w[0].kind}}
   $journal=[pscustomobject]@{schema=1;machine=$env:COMPUTERNAME;controllerSID=$id.User.Value;guid=[string]$a.InterfaceGuid;mac=$a.MacAddress;token=[Guid]::NewGuid().ToString('D');phase='creating';mainID=$s.activeProfileId;work=$work;old4=$old4;old6=$old6;new4=$new4;new6=$new6;oldDNS=$dnsOld;newDNS=$dnsNew;created4=$false;created6=$false;removed4=$false;removed6=$false;dnsChanged=$false};Save-Journal;$changed=$true
   $r.stage='add-owned-new-addresses';$journal.created4=$true;Save-Journal;New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $new4 -PrefixLength 24 -PolicyStore ActiveStore|Out-Null
   $journal.created6=$true;Save-Journal;New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $new6 -PrefixLength 64 -PolicyStore ActiveStore|Out-Null;Wait-Address $a $new4 24;Wait-Address $a $new6 64
   $r.stage='remove-original-active-addresses';$journal.removed4=$true;Save-Journal;Remove-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $old4 -PolicyStore ActiveStore -Confirm:$false
   $journal.removed6=$true;Save-Journal;Remove-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress $old6 -PolicyStore ActiveStore -Confirm:$false
   $r.stage='change-static-resolver';$journal.dnsChanged=$true;Save-Journal;Set-PhysicalDNS $a $true;Gateways $a
   $dns=@(DNS $a);if($dns.Count-ne1-or$dns[0]-ne$dnsNew){throw 'Changed resolver readback differs'}
   Signal 'changed';$r.stage='bounded-ordinary-verification-window';$end=[DateTime]::UtcNow.AddSeconds($HoldSeconds);do{Start-Sleep -Seconds 1}while([DateTime]::UtcNow-lt$end);$r.passed=$true
  }
 }
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{
 if($changed){try{Restore-Owned}catch{$r.passed=$false;$r.cleanupErrorType=$_.Exception.GetType().FullName;$r.cleanupErrorLine=$_.InvocationInfo.ScriptLineNumber;$journal.phase='restore_failed';try{Save-Journal}catch{}}}
 $r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o')
 if($canReport){
  if($Mode-eq'verify'){$dir=Join-Path $x 'r8-outputs\network-change';New-Item -ItemType Directory -Force -Path $dir|Out-Null;$out=Join-Path $dir ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+$ExpectedState+'.json');$r|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $out -Encoding UTF8}
  else{$out=Join-Path $q ('reports\r8-network-change-'+$Mode+'-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json');Atomic-JSON $out $r $false}
 }
}
$r|ConvertTo-Json -Depth 8
if(!$r.passed){exit 1}
