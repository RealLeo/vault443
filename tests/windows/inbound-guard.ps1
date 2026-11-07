# Isolated inbound WFP proof. Setup/cleanup require approved administration;
# server/readiness require the ordinary active-console user. No tasks are added.
# Fixture clients bind LAN or off-link source before connecting. TCP echoes raw
# chunks on the same connection, so pre-existing flows can be tested after arm.
param(
    [ValidateSet('setup','server','readiness','cleanup')][string]$Mode = 'readiness',
    [ValidateRange(1,180)][int]$DurationSeconds = 180
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$qa = 'C:\Program Files\Vault443QA'
$private = 'C:\ProgramData\Vault443-QA'
$bindingPath = Join-Path $qa 'inbound-binding.json'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11') -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { throw 'Named isolated VirtualBox acceptance VM required' }
if (($Mode -in @('setup','cleanup')) -ne $admin) { throw 'Setup/cleanup require elevation; server/readiness must run without elevation' }
if ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -ne $powershell) { throw 'Use the installed x64 Windows PowerShell 5.1 executable' }
function Protected([string]$Path,[bool]$PrivatePath=$false) {
    $item=Get-Item -LiteralPath $Path -Force
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'QA path is a reparse point'}
    $acl=Get-Acl -LiteralPath $Path
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'QA path has an untrusted owner'}
    $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
    if($null -eq $raw.DiscretionaryAcl){throw 'QA path has a null DACL'}
    $mask=0x500D0156
    if($PrivatePath){$mask=$mask -bor 0x21}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and ([long]$rule.FileSystemRights -band $mask)){throw 'QA path grants untrusted access'}
    }
}
Protected $qa
Protected (Join-Path $qa 'qa-runner.ps1')
$rules=@(
    @{Name='Vault443-QA-Inbound-TCP4-18082';Protocol='TCP';Port=18082;Local='192.0.2.2';Remote=@('192.0.2.1','93.184.215.14')},
    @{Name='Vault443-QA-Inbound-TCP6-18082';Protocol='TCP';Port=18082;Local='2001:db8:44::2';Remote=@('2001:db8:44::1','2001:db8:66::14')},
    @{Name='Vault443-QA-Inbound-UDP4-18083';Protocol='UDP';Port=18083;Local='192.0.2.2';Remote=@('192.0.2.1','93.184.215.14')},
    @{Name='Vault443-QA-Inbound-UDP6-18083';Protocol='UDP';Port=18083;Local='2001:db8:44::2';Remote=@('2001:db8:44::1','2001:db8:66::14')}
)
function Adapter($Config) {
    $adapters=@(Get-NetAdapter -Physical | Where-Object {[string]$_.InterfaceGuid -eq $Config.adapterGuid -and $_.MacAddress -eq $Config.adapterMAC})
    if($adapters.Count -ne 1 -or $adapters[0].Name -match '[*?\[\]]'){throw 'The protected QA uplink binding changed'}
    return $adapters[0]
}
function Binding {
    Protected $bindingPath
    $value=Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json
    if($value.version -ne 1 -or $value.machine -ne $env:COMPUTERNAME -or $value.token -notmatch '^[a-f0-9-]{36}$'){throw 'Invalid protected inbound binding'}
    return $value
}
function Addresses([object[]]$Values) { return (@($Values | ForEach-Object {([Net.IPAddress]::Parse($_)).ToString().ToLowerInvariant()} | Sort-Object) -join ',') }
function Own-Rule($Actual,$Expected,$Binding,$Adapter) {
    if($Actual.Description -ne ('Vault443 isolated inbound QA '+$Binding.token) -or $Actual.Group -ne 'Vault443 isolated inbound QA' -or $Actual.Direction -ne 'Inbound' -or $Actual.Action -ne 'Allow'){return $false}
    $port=$Actual | Get-NetFirewallPortFilter
    $address=$Actual | Get-NetFirewallAddressFilter
    $iface=$Actual | Get-NetFirewallInterfaceFilter
    $program=$Actual | Get-NetFirewallApplicationFilter
    $number=if($Expected.Protocol -eq 'TCP'){6}else{17}
    return ($port.Protocol -in @($Expected.Protocol,[string]$number) -and [string]$port.LocalPort -eq [string]$Expected.Port -and
        (Addresses $address.LocalAddress) -eq (Addresses @($Expected.Local)) -and (Addresses $address.RemoteAddress) -eq (Addresses $Expected.Remote) -and
        @($iface.InterfaceAlias).Count -eq 1 -and @($iface.InterfaceAlias)[0] -eq $Adapter.Name -and $program.Program -eq $powershell)
}
if($Mode -in @('setup','cleanup')) {
    Protected $private $true
    Protected (Join-Path $private 'marker') $true
    if([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim() -ne 'Vault443 isolated Windows fixture'){throw 'Protected QA marker is missing'}
    Protected (Join-Path $private 'qa-inputs.json') $true
    $config=Get-Content (Join-Path $private 'qa-inputs.json') -Raw | ConvertFrom-Json
    if($config.machine -ne $env:COMPUTERNAME){throw 'QA configuration belongs to another VM'}
    $adapter=Adapter $config
    if($Mode -eq 'setup') {
        if(Test-Path -LiteralPath $bindingPath){throw 'Existing inbound binding must be cleaned up first'}
        foreach($rule in $rules){if(Get-NetFirewallRule -PolicyStore ActiveStore -Name $rule.Name -ErrorAction SilentlyContinue){throw 'An exact firewall rule name already exists; no foreign rule is overwritten'}}
        $binding=@{version=1;machine=$env:COMPUTERNAME;token=[Guid]::NewGuid().ToString('D');adapterGuid=$config.adapterGuid;adapterMAC=$config.adapterMAC}
        # Publish ownership before the first firewall change, allowing cleanup
        # after an interrupted setup without deleting by a broad name prefix.
        $stream=[IO.File]::Open($bindingPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$bytes=[Text.Encoding]::UTF8.GetBytes(($binding | ConvertTo-Json));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
        $acl=New-Object Security.AccessControl.FileSecurity
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-32-545')){
            $rights=if($sid -eq 'S-1-5-32-545'){'Read'}else{'FullControl'}
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,'Allow'))
        }
        Set-Acl -LiteralPath $bindingPath -AclObject $acl
        foreach($rule in $rules){
            New-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -DisplayName $rule.Name -Description ('Vault443 isolated inbound QA '+$binding.token) -Group 'Vault443 isolated inbound QA' -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol $rule.Protocol -LocalPort $rule.Port -LocalAddress $rule.Local -RemoteAddress $rule.Remote -InterfaceAlias $adapter.Name -Program $powershell -EdgeTraversalPolicy Block | Out-Null
        }
    } else {
        $binding=Binding
        if($binding.adapterGuid -ne $config.adapterGuid -or $binding.adapterMAC -ne $config.adapterMAC){throw 'Inbound owner does not match protected QA metadata'}
        # Verify all extant rules before deleting any, including a partial setup.
        foreach($rule in $rules){
            $actual=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -ErrorAction SilentlyContinue)
            if($actual.Count -gt 1 -or ($actual.Count -eq 1 -and !(Own-Rule $actual[0] $rule $binding $adapter))){throw 'A firewall rule differs from its exact owned definition; cleanup aborted'}
        }
        foreach($rule in $rules){Get-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule}
        Remove-Item -LiteralPath $bindingPath
    }
    $result=@{mode=$Mode;passed=$true;utc=[DateTime]::UtcNow.ToString('o');ruleCount=$rules.Count;interfaceIndex=$adapter.ifIndex}
    $result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $qa ('reports\inbound-'+$Mode+'-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')) -Encoding UTF8
    $result | ConvertTo-Json -Compress
    exit 0
}
if(!('Vault443InboundEcho' -as [type])){Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
public sealed class Vault443InboundEcho : IDisposable {
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
 sealed class Counts { public long TcpConnections,TcpReceived,TcpSent,UdpReceived,UdpSent,Errors; }
 public class Peer { public string Address; public long TcpConnections,TcpReceivedBytes,TcpSentBytes,UdpReceivedDatagrams,UdpSentDatagrams,Errors; }
 readonly Dictionary<string,Counts> counts=new Dictionary<string,Counts>();
 readonly List<Socket> listeners=new List<Socket>(); readonly List<Socket> clients=new List<Socket>();
 readonly List<Task> tasks=new List<Task>(); volatile bool closing; int active; readonly int index; long rejected;
 public Vault443InboundEcho(int physicalIndex) {
  index=physicalIndex; foreach(string peer in new[]{"192.0.2.1","93.184.215.14","2001:db8:44::1","2001:db8:66::14"})counts.Add(peer,new Counts());
  try { foreach(string local in new[]{"192.0.2.2","2001:db8:44::2"}) {
   var address=IPAddress.Parse(local);
   foreach(bool udp in new[]{false,true}) {
    var socket=new Socket(address.AddressFamily,udp?SocketType.Dgram:SocketType.Stream,udp?ProtocolType.Udp:ProtocolType.Tcp);
    listeners.Add(socket); if(address.AddressFamily==AddressFamily.InterNetworkV6)socket.DualMode=false;
    Pin(socket); socket.Bind(new IPEndPoint(address,udp?18083:18082)); socket.ReceiveTimeout=1000;socket.SendTimeout=1000;
    if(udp)tasks.Add(Task.Run(()=>Datagrams(socket)));else {socket.Listen(16);tasks.Add(Task.Run(()=>Accept(socket)));}
   }
  }} catch { Dispose(); throw; }
 }
 void Pin(Socket socket) {
  if(socket.AddressFamily==AddressFamily.InterNetwork)socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(index));
  else socket.SetSocketOption(SocketOptionLevel.IPv6,(SocketOptionName)31,index);
 }
 bool Allowed(EndPoint endpoint,out Counts counter) { return counts.TryGetValue(((IPEndPoint)endpoint).Address.ToString(),out counter); }
 void Accept(Socket listener) {
  while(!closing)try {
   var client=listener.Accept(); Counts counter;
   if(!Allowed(client.RemoteEndPoint,out counter) || Interlocked.Increment(ref active)>16) {
    if(counter!=null)Interlocked.Decrement(ref active);Interlocked.Increment(ref rejected);client.Dispose();continue;
   }
   try { Pin(client);client.ReceiveTimeout=1000;client.SendTimeout=1000;lock(clients)clients.Add(client);Interlocked.Increment(ref counter.TcpConnections);
    Task.Run(()=>Echo(client,counter));
   } catch {Interlocked.Decrement(ref active);client.Dispose();Interlocked.Increment(ref counter.Errors);}
  } catch(SocketException){if(!closing)Interlocked.Increment(ref rejected);}catch(ObjectDisposedException){break;}
 }
 void Echo(Socket client,Counts counter) {
  try {byte[] buffer=new byte[512];while(!closing){int size;
   try {size=client.Receive(buffer);}catch(SocketException e){if(e.SocketErrorCode==SocketError.TimedOut)continue;throw;}
   if(size==0)break;Interlocked.Add(ref counter.TcpReceived,size);int sent=0;
   while(sent<size){int n=client.Send(buffer,sent,size-sent,SocketFlags.None);if(n<=0)return;sent+=n;Interlocked.Add(ref counter.TcpSent,n);}
  }}catch(SocketException){if(!closing)Interlocked.Increment(ref counter.Errors);}catch(ObjectDisposedException){}
  finally{lock(clients)clients.Remove(client);client.Dispose();Interlocked.Decrement(ref active);}
 }
 void Datagrams(Socket socket) {
  byte[] buffer=new byte[513];
  while(!closing)try {EndPoint peer=new IPEndPoint(socket.AddressFamily==AddressFamily.InterNetwork?IPAddress.Any:IPAddress.IPv6Any,0);
   int size=socket.ReceiveFrom(buffer,ref peer);Counts counter;if(size>512 || !Allowed(peer,out counter)){Interlocked.Increment(ref rejected);continue;}
   Interlocked.Increment(ref counter.UdpReceived);
   try {if(socket.SendTo(buffer,0,size,SocketFlags.None,peer)==size)Interlocked.Increment(ref counter.UdpSent);}catch(SocketException){Interlocked.Increment(ref counter.Errors);}
  }catch(SocketException e){if(!closing && e.SocketErrorCode!=SocketError.TimedOut)Interlocked.Increment(ref rejected);}catch(ObjectDisposedException){break;}
 }
 public Peer[] Snapshot(){var result=new List<Peer>();foreach(var entry in counts){var c=entry.Value;result.Add(new Peer{Address=entry.Key,TcpConnections=Interlocked.Read(ref c.TcpConnections),TcpReceivedBytes=Interlocked.Read(ref c.TcpReceived),TcpSentBytes=Interlocked.Read(ref c.TcpSent),UdpReceivedDatagrams=Interlocked.Read(ref c.UdpReceived),UdpSentDatagrams=Interlocked.Read(ref c.UdpSent),Errors=Interlocked.Read(ref c.Errors)});}return result.ToArray();}
 public int Active {get{return Interlocked.CompareExchange(ref active,0,0);}} public long Rejected {get{return Interlocked.Read(ref rejected);}}
 public void Dispose(){closing=true;foreach(var socket in listeners)socket.Dispose();lock(clients){foreach(var client in clients)client.Dispose();}try{Task.WaitAll(tasks.ToArray(),2000);}catch(AggregateException){}}
}
'@
}
$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
if(!$session -or $session -ne [Vault443InboundEcho]::WTSGetActiveConsoleSessionId()){throw 'Active local console user required'}
$binding=Binding
$adapter=Adapter $binding
$assigned=@(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex | Select-Object -ExpandProperty IPAddress)
if('192.0.2.2' -notin $assigned -or '2001:db8:44::2' -notin $assigned){throw 'Both fixed physical fixture addresses must be configured'}
$output=Join-Path $env:LOCALAPPDATA 'Vault443\inbound-guard'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$statePath=Join-Path $output 'server-state.json'
if($Mode -eq 'readiness'){
    $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $process=Get-Process -Id $state.processId -ErrorAction Stop
    $ready=($state.ready -and $state.userSID -eq $identity.User.Value -and $state.sessionId -eq $session -and $state.bindingToken -eq $binding.token -and
        $process.Path -eq $powershell -and $process.StartTime.ToUniversalTime().Ticks.ToString() -eq $state.startTimeTicks -and [DateTime]::Parse($state.expiresUtc) -gt [DateTime]::UtcNow)
    @{ready=$ready;processId=$state.processId;interfaceIndex=$adapter.ifIndex;stateFile=$statePath;peers=$state.peers} | ConvertTo-Json -Depth 6
    if(!$ready){exit 1};exit 0
}
$server=$null
$process=[Diagnostics.Process]::GetCurrentProcess()
$state=@{ready=$false;userSID=$identity.User.Value;sessionId=$session;processId=$process.Id;startTimeTicks=$process.StartTime.ToUniversalTime().Ticks.ToString();
    bindingToken=$binding.token;interfaceIndex=$adapter.ifIndex;startedUtc=[DateTime]::UtcNow.ToString('o');expiresUtc=[DateTime]::UtcNow.AddSeconds($DurationSeconds).ToString('o');
    localAddresses=@('192.0.2.2','2001:db8:44::2');tcpPort=18082;udpPort=18083;physicalRepliesPinned=$true;peers=@();activeTcp=0;rejected=0;stateWriteFailures=0}
function Save-State {
    $json=$state | ConvertTo-Json -Depth 6
    $temporary=$statePath+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    [IO.File]::WriteAllText($temporary,$json)
    try{
        if(Test-Path -LiteralPath $statePath){[IO.File]::Replace($temporary,$statePath,[NullString]::Value)}else{[IO.File]::Move($temporary,$statePath)}
    }catch [IO.IOException]{
        # A concurrent ordinary readiness reader must not stop the echo server.
        # The preceding atomic snapshot stays valid; publish fresh counters on
        # the next tick and preserve the final report in its separate file.
        $state.stateWriteFailures++
        Remove-Item -LiteralPath $temporary -ErrorAction SilentlyContinue
    }
}
try {
    $deadline=[DateTime]::UtcNow.AddSeconds($DurationSeconds)
    $server=[Vault443InboundEcho]::new([int]$adapter.ifIndex)
    $state.ready=$true;Save-State
    do{
        $remaining=($deadline-[DateTime]::UtcNow).TotalMilliseconds
        if($remaining -le 0){break}
        Start-Sleep -Milliseconds ([int][Math]::Min(500,[Math]::Ceiling($remaining)))
        $state.peers=$server.Snapshot();$state.activeTcp=$server.Active;$state.rejected=$server.Rejected;Save-State
    }while([DateTime]::UtcNow -lt $deadline)
}finally{
    if($server){$server.Dispose();$state.peers=$server.Snapshot();$state.rejected=$server.Rejected}
    $state.ready=$false;$state.activeTcp=0;$state.finishedUtc=[DateTime]::UtcNow.ToString('o');Save-State
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output ('server-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')) -Encoding UTF8
}
$state | ConvertTo-Json -Depth 6
