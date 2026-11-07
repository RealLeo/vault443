# Ordinary ACTIVE console user. The controller creates/switches accounts and
# approves enrollment outside this script. No TakeControl or admin helper runs.
# Isolated phase starts with a fresh second user's empty profile store. Optional
# text fixture import may legitimately produce the SAME ID as the first user:
# IDs identify content; authorization/journals are scoped by UID plus ID.
param(
    [ValidateSet('unauthorized','capture','isolated')][string]$Phase = 'capture',
    [string]$ExpectedOtherIDsJSON = '',
    [string]$CompareCaptureJSON = '',
    [string]$FixtureImportJSON = '',
    [string]$ReportDirectory = (Join-Path $env:LOCALAPPDATA 'Vault443\user-isolation')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run without elevation as the signed-in console user'}
if($env:COMPUTERNAME -notin @('VAULT443-WIN10','VAULT443-WIN11') -or (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox'){throw 'Named isolated Windows QA VM required'}
foreach($path in @('C:\Program Files\Vault443QA','C:\Program Files\Vault443QA\qa-runner.ps1')){
    $item=Get-Item -LiteralPath $path -Force
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Protected QA root/runner cannot be reparse points'}
    if(($path -like '*.ps1' -and $item.PSIsContainer) -or ($path -notlike '*.ps1' -and !$item.PSIsContainer)){throw 'Protected QA root/runner type is invalid'}
    $acl=Get-Acl -LiteralPath $path
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Untrusted QA root/runner owner'}
    $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
    if($null -eq $raw.DiscretionaryAcl){throw 'QA root/runner has a null DACL'}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and ([long]$rule.FileSystemRights -band 0x500D0156)){throw 'QA root/runner permits untrusted writes'}
    }
}
if(!('Vault443IsolationIdentity' -as [type])){Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class Vault443IsolationIdentity {
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafePipeHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(SafePipeHandle handle,out uint pid);
 [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,uint type,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
 [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr handle,uint flags,StringBuilder path,ref uint size);
 [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr handle,out long creation,out long exit,out long kernel,out long user);
 public class Proof { public uint ServerPid; public string PipeOwnerSID; public string ExecutablePath; public long CreationFileTime; }
 public static Proof Server() {
  using(var pipe=CreateFile(@"\\.\pipe\Vault443.Service1",0x0012019b,3,IntPtr.Zero,3,0x00110000,IntPtr.Zero)) {
   if(pipe.IsInvalid)throw new IOException("Cannot inspect installed service pipe");
   uint pid;if(!GetNamedPipeServerProcessId(pipe,out pid))throw new IOException("Cannot identify installed service PID");
   IntPtr owner,group,dacl,sacl,sd;
   if(GetSecurityInfo(pipe.DangerousGetHandle(),6,1,out owner,out group,out dacl,out sacl,out sd)!=0)throw new IOException("Cannot inspect pipe owner");
   string sid;try{sid=new SecurityIdentifier(owner).Value;}finally{LocalFree(sd);}
   if(sid!="S-1-5-18")throw new IOException("Service pipe is not owned by SYSTEM");
   var proof=new Proof{ServerPid=pid,PipeOwnerSID=sid};var process=OpenProcess(0x1000,false,pid);
   if(process!=IntPtr.Zero)try{
    var path=new StringBuilder(32768);uint size=32768;if(QueryFullProcessImageName(process,0,path,ref size))proof.ExecutablePath=path.ToString();
    long creation,exit,kernel,user;if(GetProcessTimes(process,out creation,out exit,out kernel,out user))proof.CreationFileTime=creation;
   }finally{CloseHandle(process);}return proof;
  }
 }
}
'@
}
$process=[Diagnostics.Process]::GetCurrentProcess()
$session=$process.SessionId
if(!$session -or $session -ne [Vault443IsolationIdentity]::WTSGetActiveConsoleSessionId()){throw 'An active local console session is required'}
New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$reportPath=Join-Path $ReportDirectory ($stamp+'-'+$Phase+'.json')
$script:checks=New-Object 'System.Collections.Generic.List[object]'
$script:failed=$false;$script:completed=$false;$script:step='initialization'
$server=[Vault443IsolationIdentity]::Server()
if($server.ExecutablePath -and $server.ExecutablePath -ne 'C:\Program Files\Vault443\vault443d.exe'){throw 'Pipe PID does not belong to the installed daemon'}
$report=@{phase=$Phase;userSID=$identity.User.Value;sessionId=$session;processId=$process.Id;server=$server;checks=@();passed=$false;completed=$false;
    limits=@('Isolated phase requires a fresh second-user empty store before its optional import. Nonempty own profiles are a fixture precondition failure, not automatic evidence of a leak.',
        'Same profile ID in two UID namespaces is valid. Foreign log/diagnostic probes run before importing any colliding own ID.',
        'User2 cannot see the private active owner ID. Return to User1 and use capture -CompareCaptureJSON <first capture> for exact owner/session continuity.')}
function Save-Report{$report.checks=@($script:checks.ToArray());$report.completed=$script:completed;$report.passed=($script:completed -and !$script:failed);$report | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath $reportPath -Encoding UTF8}
function Check([string]$Name,[bool]$Passed,$Observation=$null){$script:step=$Name;$script:checks.Add(@{check=$Name;passed=$Passed;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation});if(!$Passed){$script:failed=$true};Save-Report;if(!$Passed){throw 'User isolation acceptance check failed'}}
function Call([string]$Method,[object[]]$Parameters=@()){
    $script:step='rpc-'+$Method
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName='C:\Program Files\Vault443\vault443-cli.exe';$start.Arguments=$Method;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $rpc=New-Object Diagnostics.Process;$rpc.StartInfo=$start
    try{
        [void]$rpc.Start();$stdout=$rpc.StandardOutput.ReadToEndAsync();$stderr=$rpc.StandardError.ReadToEndAsync()
        $rpc.StandardInput.WriteLine((ConvertTo-Json -InputObject $Parameters -Compress -Depth 10));$rpc.StandardInput.Close()
        if(!$rpc.WaitForExit(5000)){$rpc.Kill();[void]$rpc.WaitForExit(1000);return @{ok=$false;kind='timeout'}}
        if($rpc.ExitCode -eq 0){return @{ok=$true;value=($stdout.GetAwaiter().GetResult() | ConvertFrom-Json)}}
        $errorText=$stderr.GetAwaiter().GetResult().Trim()
        $kind=if($errorText -match '^Access denied: '){'auth-denied'}elseif($errorText -match '(?:^|: )administrator membership is required$'){'admin-denied'}elseif($errorText -match '(?:^|: )another user owns the VPN; explicitly take control first$'){'busy-denied'}elseif($errorText -match '(?:^|: )profile not found$'){'profile-not-found'}else{'other-error'}
        return @{ok=$false;kind=$kind}
    }finally{$rpc.Dispose()}
}
function Snapshot{
    $reply=Call GetSnapshot
    Check 'snapshot-access' $reply.ok
    return $reply.value
}
function Administrative-Denials{
    foreach($entry in @(@('GrantConsoleOperator',@()),@('SetBootProfile',@('Vault443-QA-NoSuchProfile')),@('SetVPNBinding',@('{}')))){
        $reply=Call $entry[0] $entry[1]
        Check ('deny-'+$entry[0]) (!$reply.ok -and $reply.kind -in @('auth-denied','admin-denied')) @{failureClass=$reply.kind}
    }
}
function Private-Reads([bool]$WorkExpected){
    $paths=@('state.json','windows-users.json','runtime\core.json')
    if($WorkExpected){$paths+='work-vpn.json'}
    foreach($name in $paths){
        $denied=$false;$kind='opened'
        try{$file=[IO.File]::Open((Join-Path 'C:\ProgramData\Vault443' $name),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);$file.Dispose()}
        catch{$errorObject=$_.Exception;while($errorObject.InnerException){$errorObject=$errorObject.InnerException};$denied=$errorObject -is [UnauthorizedAccessException];$kind=$errorObject.GetType().FullName}
        Check ('private-read-'+$name) $denied @{failureClass=$kind}
    }
}
function Busy-View($Snapshot){
    Check 'other-user-busy' $Snapshot.busyByOtherUser @{state=$Snapshot.runtime.state;guardArmed=$Snapshot.runtime.guardArmed}
    Check 'foreign-session-metadata-hidden' (!$Snapshot.activeProfileId -and !$Snapshot.bootProfileId -and !$Snapshot.traffic -and !$Snapshot.operation -and !$Snapshot.lastFailure -and !$Snapshot.runtime.message -and !$Snapshot.runtime.stage -and !$Snapshot.runtime.failureCode -and !$Snapshot.runtime.connectedAt -and !$Snapshot.runtime.rxBytes -and !$Snapshot.runtime.txBytes -and !$Snapshot.runtime.stageStartedAt -and !$Snapshot.runtime.externalVpns.Count)
}
try{
    if($Phase -eq 'unauthorized'){
        $reply=Call GetSnapshot
        Check 'unenrolled-snapshot-denied' (!$reply.ok -and $reply.kind -eq 'auth-denied') @{failureClass=$reply.kind}
        Administrative-Denials
        $reply=Call GetSnapshot
        Check 'still-unenrolled-after-admin-denials' (!$reply.ok -and $reply.kind -eq 'auth-denied') @{failureClass=$reply.kind}
        Private-Reads $true
    }elseif($Phase -eq 'capture'){
        $snapshot=Snapshot
        Check 'ordinary-token-not-admin' (!$snapshot.canAdmin)
        $capture=@{schema=1;userSID=$identity.User.Value;sessionId=$session;server=$server;utc=[DateTime]::UtcNow.ToString('o');
            profileIDs=@($snapshot.profiles | ForEach-Object {$_.id} | Sort-Object -Unique);workIDs=@($snapshot.workProfiles | ForEach-Object {$_.id} | Sort-Object -Unique);
            mainState=$snapshot.runtime.state;guardArmed=$snapshot.runtime.guardArmed;activeProfileId=$snapshot.activeProfileId;busyByOtherUser=$snapshot.busyByOtherUser;trafficSessionId=$snapshot.traffic.sessionId}
        if($CompareCaptureJSON){
            $before=Get-Content -LiteralPath $CompareCaptureJSON -Raw | ConvertFrom-Json
            Check 'same-owner-session-after-other-user' ($before.userSID -eq $identity.User.Value -and !$snapshot.busyByOtherUser -and $snapshot.activeProfileId -eq $before.activeProfileId -and $snapshot.runtime.state -eq $before.mainState -and $snapshot.runtime.guardArmed -eq $before.guardArmed -and $snapshot.traffic.sessionId -eq $before.trafficSessionId -and $server.ServerPid -eq $before.server.ServerPid -and $server.CreationFileTime -eq $before.server.CreationFileTime)
        }
        $capturePath=Join-Path $ReportDirectory ($stamp+'-ids.json')
        $capture | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $capturePath -Encoding UTF8
        Check 'own-ids-captured' $true @{capturePath=$capturePath;profileCount=$capture.profileIDs.Count;workCount=$capture.workIDs.Count;mainState=$capture.mainState;busyByOtherUser=$capture.busyByOtherUser}
    }else{
        if(!$ExpectedOtherIDsJSON){throw 'Controller must supply the first user ID-only capture'}
        $other=Get-Content -LiteralPath $ExpectedOtherIDsJSON -Raw | ConvertFrom-Json
        Check 'different-user-active-owner-fixture' ($other.userSID -ne $identity.User.Value -and $other.activeProfileId -and $other.guardArmed -and !$other.busyByOtherUser -and $other.mainState -eq 'connected' -and $other.server.ServerPid -eq $server.ServerPid -and $other.server.CreationFileTime -eq $server.CreationFileTime)
        $snapshot=Snapshot;Busy-View $snapshot
        Check 'fresh-second-user-empty-fixture' (!$snapshot.profiles.Count -and !$snapshot.workProfiles.Count -and !$snapshot.subscriptions.Count)
        Private-Reads ([bool]$other.workIDs.Count)
        Administrative-Denials
        if($other.profileIDs.Count){
            $foreign=[string]$other.profileIDs[0]
            foreach($entry in @(@('GetProfileLogs',@($foreign,'',20)),@('GetProfileDiagnostics',@($foreign)))){
                $reply=Call $entry[0] $entry[1];Check ('foreign-'+$entry[0]) (!$reply.ok -and $reply.kind -eq 'profile-not-found') @{failureClass=$reply.kind}
            }
        }
        if($other.workIDs.Count){
            $foreign=[string]$other.workIDs[0]
            foreach($entry in @(@('GetWorkLogs',@($foreign,'',20)),@('GetWorkDiagnostics',@($foreign)))){
                $reply=Call $entry[0] $entry[1];Check ('foreign-'+$entry[0]) (!$reply.ok -and $reply.kind -eq 'profile-not-found') @{failureClass=$reply.kind}
            }
        }
        $diagnostics=Call GetDiagnostics
        Check 'global-diagnostics-redacted' ($diagnostics.ok -and $diagnostics.value.busyByOtherUser -and !$diagnostics.value.network)
        $target=[string]$other.activeProfileId
        if($FixtureImportJSON){
            if((Get-Item -LiteralPath $FixtureImportJSON).Length -gt 1MB){throw 'Fixture import is oversized'}
            $parameters=Get-Content -LiteralPath $FixtureImportJSON -Raw | ConvertFrom-Json
            if($parameters.Count -ne 3 -or $parameters[1] -ne 'text'){throw 'Optional fixture input must be [textURI,"text",name]'}
            $draft=Call PrepareImport $parameters
            Check 'own-fixture-preview' ($draft.ok -and !$draft.value.errors.Count -and $draft.value.profiles.Count -eq 1)
            $committed=Call CommitImport @($draft.value.draftId,'{}')
            Check 'own-fixture-committed' $committed.ok
            $target=[string]$committed.value.profiles[0].id
            $snapshot=Snapshot;Busy-View $snapshot
            Check 'only-own-import-visible' ($snapshot.profiles.Count -eq 1 -and $snapshot.profiles[0].id -eq $target -and !$snapshot.workProfiles.Count) @{sameContentIDAsOther=($target -in $other.profileIDs)}
        }
        foreach($entry in @(@('RequestDisconnect',@()),@('RequestConnect',@($target)))){
            $reply=Call $entry[0] $entry[1];Check ('foreign-owner-'+$entry[0]) (!$reply.ok -and $reply.kind -eq 'busy-denied') @{failureClass=$reply.kind}
            $after=Snapshot;Busy-View $after
            Check ('owner-projection-unchanged-'+$entry[0]) ($after.runtime.state -eq $other.mainState -and $after.runtime.guardArmed -eq $other.guardArmed)
        }
        $afterServer=[Vault443IsolationIdentity]::Server()
        Check 'same-service-after-denied-actions' ($afterServer.ServerPid -eq $server.ServerPid -and $afterServer.CreationFileTime -eq $server.CreationFileTime)
    }
}catch{$script:failed=$true;$script:checks.Add(@{check=$script:step;passed=$false;exceptionType=$_.Exception.GetType().FullName})}
finally{$script:completed=$true;Save-Report}
@{passed=(!$script:failed);phase=$Phase;report=$reportPath} | ConvertTo-Json -Compress
if($script:failed){exit 1}
