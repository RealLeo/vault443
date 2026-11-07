# Windows PowerShell 5.1, ordinary authorized active-console user only.
# Basic framing probes run by default. Admission is deliberately opt-in: deploy
# the new backend with maxPipePeers=64/firstPipeFrameTimeout=8s first, then pass
# its independently recorded exact daemon SHA-256 and -Admission.
param(
    [switch]$Admission,
    [switch]$CompileOnly,
    [ValidatePattern('^$|^[a-fA-F0-9]{64}$')][string]$ExpectedBackendSha256 = '',
    [string]$ReportDirectory = (Join-Path $env:LOCALAPPDATA 'Vault443\ipc-security')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run without elevation as the authorized console user' }
if ($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11') -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { throw 'Only the isolated Windows acceptance VMs are allowed' }
# Ordinary users cannot read the private ProgramData QA marker. Prove the
# protected root/runner identity instead, as in set-display-scale.ps1.
foreach ($path in @('C:\Program Files\Vault443QA','C:\Program Files\Vault443QA\qa-runner.ps1')) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected QA paths cannot be reparse points' }
    if (($path -eq 'C:\Program Files\Vault443QA' -and !$item.PSIsContainer) -or ($path -like '*.ps1' -and $item.PSIsContainer)) { throw 'Protected QA root/runner type is invalid' }
    $acl = Get-Acl -LiteralPath $path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Untrusted QA root/runner owner' }
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
    if ($null -eq $raw.DiscretionaryAcl) { throw 'Protected QA path has a null DACL' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and ([long]$rule.FileSystemRights -band 0x500D0156)) { throw 'Protected QA path permits untrusted writes' }
    }
}
$daemonPath = 'C:\Program Files\Vault443\vault443d.exe'
$backendSHA = (Get-FileHash -LiteralPath $daemonPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ExpectedBackendSha256 -and $backendSHA -ne $ExpectedBackendSha256.ToLowerInvariant()) { throw 'Installed backend does not match the independently recorded expected SHA-256' }
# This published pending candidate predates the admission/first-frame limits.
$oldCandidateBackend = '1a63e4ce93a5b5245e61cdd469b9077ea2a48006889a20eacbd0ffd8add2db3e'
if ($Admission -and (!$ExpectedBackendSha256 -or $backendSHA -eq $oldCandidateBackend)) { throw 'Admission requires the new limited backend and its exact expected hash; do not run it on the old candidate' }
if (!('Vault443IPCSecurity' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
public static class Vault443IPCSecurity {
 public const string PipePath = @"\\.\pipe\Vault443.Service1";
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafePipeHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WaitNamedPipe(string name,uint timeout);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
 [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,uint kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
 [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 public class Proof { public string Owner; public bool NonNullDACL; public bool TrustedServerRights; public uint ServerPid; public bool TokenAvailable; public string TokenUser; }
 public class Closed { public long ElapsedMilliseconds; public string Reason; }
 public class Session : IDisposable {
  NamedPipeClientStream stream; StreamReader reader; Stopwatch clock=Stopwatch.StartNew();
  public Proof Security; public Task<Closed> Closure;
  internal Session(SafePipeHandle handle) {
   stream=new NamedPipeClientStream(PipeDirection.InOut,true,true,handle);
   reader=new StreamReader(stream,new UTF8Encoding(false,true),false,4096,true);
   try { Security=Inspect(handle); if(Security.Owner!="S-1-5-18" || !Security.NonNullDACL || !Security.TrustedServerRights || (Security.TokenAvailable && Security.TokenUser!="S-1-5-18")) throw new IOException("Unsafe server identity"); }
   catch { Dispose(); throw; }
  }
  void Await(Task task,int timeout) {
   try { if(!task.Wait(timeout)) { Dispose(); throw new TimeoutException("Bounded pipe operation timed out"); } }
   catch(AggregateException e) { throw new IOException("Pipe operation failed",e.InnerException); }
  }
  public void Send(byte[] frame,int timeout) { Await(stream.WriteAsync(frame,0,frame.Length),timeout); }
  public string ReadLine(int timeout) {
   var task=reader.ReadLineAsync(); Await(task,timeout); string line=task.GetAwaiter().GetResult();
   if(line!=null && line.Length>4*1024*1024) throw new IOException("Oversized server frame"); return line;
  }
  public void StartCloseWatch() { if(Closure!=null) throw new InvalidOperationException(); Closure=WatchClose(); }
  async Task<Closed> WatchClose() {
   string reason="eof";
   try { while(await reader.ReadLineAsync()!=null) {} }
   catch(IOException) { reason="io-closed"; }
   catch(ObjectDisposedException) { reason="client-disposed"; }
   return new Closed { ElapsedMilliseconds=clock.ElapsedMilliseconds,Reason=reason };
  }
  public bool RejectsOversizedFrame() {
   byte[] frame=new byte[4*1024*1024+2]; for(int i=0;i<frame.Length-1;i++) frame[i]=32; frame[frame.Length-1]=10;
   try {
    Send(frame,4000); var reading=Stopwatch.StartNew();
    while(reading.ElapsedMilliseconds<4000) {
     string line=ReadLine(Math.Max(1,4000-(int)reading.ElapsedMilliseconds));
     if(line==null) return true;
     if(line!="{\"jsonrpc\":\"2.0\",\"method\":\"Changed\"}") return false;
    }
    return false;
   } catch(IOException) { return true; }
  }
  public void Dispose() { if(stream!=null) stream.Dispose(); }
 }
 static Proof Inspect(SafePipeHandle handle) {
  IntPtr owner,group,dacl,sacl,descriptor;
  uint code=GetSecurityInfo(handle.DangerousGetHandle(),6,5,out owner,out group,out dacl,out sacl,out descriptor);
  if(code!=0) throw new IOException("Cannot inspect server security");
  Proof proof=new Proof { TrustedServerRights=true };
  try {
   uint size=GetSecurityDescriptorLength(descriptor); if(size==0 || size>65536) throw new IOException("Invalid server descriptor");
   byte[] bytes=new byte[size]; Marshal.Copy(descriptor,bytes,0,(int)size); var sd=new RawSecurityDescriptor(bytes,0);
   proof.Owner=sd.Owner.Value; proof.NonNullDACL=sd.DiscretionaryAcl!=null;
   if(sd.DiscretionaryAcl!=null) foreach(GenericAce ace in sd.DiscretionaryAcl) {
    var allowed=ace as CommonAce; if(allowed==null || allowed.AceQualifier!=AceQualifier.AccessAllowed) continue;
    string sid=allowed.SecurityIdentifier.Value;
    if(sid!="S-1-5-18" && sid!="S-1-5-32-544" && ((uint)allowed.AccessMask & 0x500C0004U)!=0) proof.TrustedServerRights=false;
   }
  } finally { LocalFree(descriptor); }
  uint pid; if(GetNamedPipeServerProcessId(handle,out pid)) proof.ServerPid=pid;
  IntPtr process=OpenProcess(0x1000,false,proof.ServerPid);
  if(process!=IntPtr.Zero) try {
   IntPtr token; if(OpenProcessToken(process,8,out token)) try {
    try { using(var identity=new WindowsIdentity(token)) { proof.TokenUser=identity.User.Value; proof.TokenAvailable=true; } }
    catch(System.Security.SecurityException) { proof.TokenAvailable=false; }
    catch(UnauthorizedAccessException) { proof.TokenAvailable=false; }
   } finally { CloseHandle(token); }
  } finally { CloseHandle(process); }
  return proof;
 }
 public static Session Open(int timeout) {
  var clock=Stopwatch.StartNew();
  do {
   // Exact CLI rights, overlapped I/O, SECURITY_IDENTIFICATION. GENERIC_WRITE
   // would wrongly request FILE_CREATE_PIPE_INSTANCE and fail the pipe DACL.
   var handle=CreateFile(PipePath,0x0012019b,3,IntPtr.Zero,3,0x40110000,IntPtr.Zero);
   if(!handle.IsInvalid) return new Session(handle);
   int error=Marshal.GetLastWin32Error(); handle.Dispose();
   if(error!=231 && error!=2) throw new IOException("Cannot open installed service pipe");
   int remaining=timeout-(int)clock.ElapsedMilliseconds; if(remaining<=0) break;
   WaitNamedPipe(PipePath,(uint)Math.Min(remaining,30));
  } while(clock.ElapsedMilliseconds<timeout);
  throw new TimeoutException("Installed service pipe connection timed out");
 }
}
'@
}
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
if (!$sessionId -or $sessionId -ne [Vault443IPCSecurity]::WTSGetActiveConsoleSessionId()) { throw 'Active local console session required' }
if ($CompileOnly) { @{compileOnly=$true;compiled=$true;ipcProbesExecuted=$false;backendSha256=$backendSHA} | ConvertTo-Json -Compress; exit 0 }
New-Item -ItemType Directory -Force -Path $ReportDirectory | Out-Null
$reportPath = Join-Path $ReportDirectory ('ipc-security-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '.json')
$script:checks = New-Object 'System.Collections.Generic.List[object]'
$script:failed = $false; $script:completed = $false; $script:step = 'baseline'; $script:serverPid = 0
$report = @{ backendSha256=$backendSHA; pipe='\\.\pipe\Vault443.Service1'; admissionEnabled=[bool]$Admission; sessionId=$sessionId; checks=@(); completed=$false; passed=$false;
    limits=@('Authorized ordinary console user required. Admission is opt-in and must follow deployment of the new 64-peer/8-second backend; old candidate is excluded.',
        'Existing UI/CLI connections consume the shared budget, so 64 accepted idle clients are not required.',
        'Pipe owner/DACL are mandatory; optional service-token inspection may be denied to an ordinary user. No admin method, profile payload or privileged runner is used.') }
function Save-Report { $report.checks=@($script:checks.ToArray()); $report.completed=$script:completed; $report.passed=($script:completed -and !$script:failed); $report | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath $reportPath -Encoding UTF8 }
function Check([string]$Name,[bool]$Passed,$Observation=$null) {
    $script:step=$Name; $script:checks.Add(@{check=$Name;passed=$Passed;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation})
    if(!$Passed){$script:failed=$true}; Save-Report; if(!$Passed){throw 'IPC acceptance check failed'}
}
function Read-Reply($Pipe) {
    do {
        $line=$Pipe.ReadLine(4000)
        if($null -eq $line){throw 'Pipe closed before reply'}
        $reply=$line | ConvertFrom-Json
    } while($reply.method -eq 'Changed' -and !$reply.id)
    return $reply
}
function Snapshot([string]$After) {
    $script:step='snapshot-'+$After; $pipe=[Vault443IPCSecurity]::Open(1500)
    try {
        $proof=$pipe.Security
        if(!$script:serverPid){$script:serverPid=$proof.ServerPid; $report.serverSecurity=$proof}
        $pipe.Send([Text.Encoding]::UTF8.GetBytes('{"jsonrpc":"2.0","id":1,"method":"GetSnapshot","params":[]}' + "`n"),4000)
        $reply=Read-Reply $pipe
        Check ('snapshot-after-'+$After) (!$reply.error -and $reply.id -eq 1 -and $reply.result.runtime -and $proof.ServerPid -eq $script:serverPid) @{
            serverPid=$proof.ServerPid;state=$reply.result.runtime.state;guardArmed=$reply.result.runtime.guardArmed;profileCount=$reply.result.profiles.Count;workCount=$reply.result.workProfiles.Count }
    } finally {$pipe.Dispose()}
}
function Frame([string]$Name,[string]$Text,[int]$Code) {
    $script:step=$Name; $pipe=[Vault443IPCSecurity]::Open(1500)
    try {
        $pipe.Send([Text.Encoding]::UTF8.GetBytes($Text+"`n"),4000)
        $reply=Read-Reply $pipe
        Check $Name ($reply.error.code -eq $Code) @{errorCode=$reply.error.code}
    } finally {$pipe.Dispose()}
    Snapshot $Name
}
try {
    Snapshot 'baseline'
    Check 'server-identity' ($script:serverPid -gt 0 -and $report.serverSecurity.Owner -eq 'S-1-5-18' -and $report.serverSecurity.TrustedServerRights)
    Frame 'malformed-json' '{' -32600
    Frame 'invalid-json-frame' '[]' -32600
    Frame 'multiple-json-values' '{} {}' -32600
    Frame 'wrong-rpc-version' '{"jsonrpc":"1.0","id":2,"method":"GetSnapshot","params":[]}' -32600
    Frame 'unknown-field' '{"jsonrpc":"2.0","id":2,"method":"GetSnapshot","params":[],"unexpected":true}' -32600
    Frame 'invalid-method' '{"jsonrpc":"2.0","id":2,"method":"Vault443.QA.NoSuchMethod","params":[]}' -32601
    Frame 'invalid-parameters' '{"jsonrpc":"2.0","id":2,"method":"GetSnapshot","params":["unexpected"]}' -32602
    $script:step='oversize-frame'; $pipe=[Vault443IPCSecurity]::Open(1500)
    try { Check 'oversize-frame-rejected' ($pipe.RejectsOversizedFrame()) } finally {$pipe.Dispose()}
    Snapshot 'oversize-frame'
    if ($Admission) {
        $idle=New-Object 'System.Collections.Generic.List[object]'
        try {
            $opening=[Diagnostics.Stopwatch]::StartNew(); $unavailable=0
            for($i=0;$i -lt 72;$i++) {
                try { $candidate=[Vault443IPCSecurity]::Open(40); $candidate.StartCloseWatch(); $idle.Add($candidate) }
                catch { $unavailable++ }
            }
            Check 'admission-opening-window' ($opening.ElapsedMilliseconds -lt 3000) @{attempts=72;opened=$idle.Count;unavailable=$unavailable;elapsedMs=$opening.ElapsedMilliseconds}
            Start-Sleep -Milliseconds 1500
            $held=@($idle | Where-Object {!$_.Closure.IsCompleted})
            Check 'admission-shared-cap' ($held.Count -gt 0 -and $held.Count -le 64 -and ($idle.Count-$held.Count+$unavailable) -gt 0) @{held=$held.Count;immediateClosures=($idle.Count-$held.Count);unavailable=$unavailable;limit=64}
            $deadline=[DateTime]::UtcNow.AddSeconds(11)
            do { $remaining=@($held | Where-Object {!$_.Closure.IsCompleted}); if(!$remaining.Count){break}; Start-Sleep -Milliseconds 100 } while([DateTime]::UtcNow -lt $deadline)
            $elapsed=@($held | Where-Object {$_.Closure.IsCompleted} | ForEach-Object {$_.Closure.GetAwaiter().GetResult().ElapsedMilliseconds})
            $bad=@($elapsed | Where-Object {$_ -lt 6500 -or $_ -gt 12000})
            Check 'idle-first-frame-timeout' ($remaining.Count -eq 0 -and $bad.Count -eq 0 -and $elapsed.Count -eq $held.Count) @{elapsedMs=$elapsed;remaining=$remaining.Count;expectedMs=8000}
        } finally {foreach($connection in $idle){$connection.Dispose()}}
        Snapshot 'idle-admission-release'
        $pipe=[Vault443IPCSecurity]::Open(1500)
        try {
            $pipe.Send([Text.Encoding]::UTF8.GetBytes('{"jsonrpc":'),4000); $pipe.StartCloseWatch()
            $deadline=[DateTime]::UtcNow.AddSeconds(12)
            do { if($pipe.Closure.IsCompleted){break}; Start-Sleep -Milliseconds 100 } while([DateTime]::UtcNow -lt $deadline)
            $elapsed=if($pipe.Closure.IsCompleted){$pipe.Closure.GetAwaiter().GetResult().ElapsedMilliseconds}else{0}
            Check 'partial-first-frame-timeout' ($elapsed -ge 6500 -and $elapsed -le 12000) @{elapsedMs=$elapsed;expectedMs=8000}
        } finally {$pipe.Dispose()}
        Snapshot 'partial-frame-release'
    }
} catch {$script:failed=$true; $script:checks.Add(@{check=$script:step;passed=$false;exceptionType=$_.Exception.GetType().FullName})}
finally {
    # This runs after idle handles are disposed even when a negative probe or
    # limit assertion failed, and detects a crash hidden by automatic recovery.
    try { Snapshot 'final-health' }
    catch { $script:failed=$true; $script:checks.Add(@{check='final-health';passed=$false;exceptionType=$_.Exception.GetType().FullName}) }
    $script:completed=$true; Save-Report
}
@{passed=(!$script:failed);admissionEnabled=[bool]$Admission;report=$reportPath} | ConvertTo-Json -Compress
if($script:failed){exit 1}
