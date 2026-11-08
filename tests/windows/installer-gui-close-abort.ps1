#Requires -Version 5.1
#Requires -RunAsAdministrator
# Isolated, same-console UAC QA. Suspend only the verified GUI UI thread;
# never terminate a process. A timeout leaves the uninstaller for root review.
param(
 [Parameter(Mandatory=$true)][string]$AppDirectory,
 [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ManifestSha256,
 [string]$QAPath='C:\Program Files\Vault443QA'
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$app=[IO.Path]::GetFullPath($AppDirectory).TrimEnd('\');$q=$QAPath;$private='C:\ProgramData\Vault443-QA'
$manifestSHA=$ManifestSha256.ToLowerInvariant();$guiSHA='';$daemonSHA='';$cliSHA=''
$out=Join-Path $q ('reports\1.3.5-gui-close-abort\'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
$canReport=$false;$hold=$null;$gui=$null;$uninstaller=$null
$r=[ordered]@{schema=1;machine=$env:COMPUTERNAME;startedUTC=[DateTime]::UtcNow.ToString('o');stage='preflight';completed=$false;passed=$false;checks=@();threadSuspended=$false;threadResumed=$false;childProcessRetained=$false;errorType=$null;errorLine=0;cleanupErrorType=$null;limits=@('Only the exact GUI in the active controller console is suspended.','The original native process and thread handles remain open; no process is killed.','On a 120-second uninstaller timeout the UI thread is resumed and the uninstaller is retained for root review; no further mutation follows.')}
function Protected([string]$Path,[bool]$PrivatePath){
 $i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse QA input'}
 $trusted=@('S-1-5-18','S-1-5-32-544')
 $checked=[IO.Path]::GetFullPath($Path).TrimEnd('\');$installed=[IO.Path]::GetFullPath($app).TrimEnd('\')
 if(!$PrivatePath-and($checked.Equals($installed,[StringComparison]::OrdinalIgnoreCase)-or$checked.StartsWith(($installed+'\'),[StringComparison]::OrdinalIgnoreCase))){$trusted+='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}
 $a=Get-Acl -LiteralPath $Path;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin$trusted){throw 'Untrusted QA owner'}
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if($null-eq$raw.DiscretionaryAcl){throw 'Null QA DACL'}
 $mask=0x500D0156;if($PrivatePath){$mask=$mask-bor0x80000021}
 foreach($e in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and!($e.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$e.IdentityReference.Value-notin$trusted-and([long]$e.FileSystemRights-band$mask)){throw 'Untrusted QA permissions'}}
}
function Save{if($canReport){$r|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8}}
function Check([string]$Name,[bool]$Pass,$Observation=$null){$r.checks+=@{check=$Name;passed=$Pass;utc=[DateTime]::UtcNow.ToString('o');observation=$Observation};Save;if(!$Pass){throw 'GUI abort safety check failed'}}
function Pin([string]$Path,[string]$SHA){if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$SHA){throw 'Reviewed input hash differs'}}
function IDs{
 $v=@();foreach($name in @('state.json','work-vpn.json')){
  $path=Join-Path 'C:\ProgramData\Vault443' $name;Protected $path $true;if((Get-Item $path).Length-gt40MB){throw 'Oversized state'}
  $s=Get-Content $path -Raw|ConvertFrom-Json
  foreach($u in $s.users.PSObject.Properties){if($u.Name-notmatch'^[0-9]{1,10}$'){throw 'Unexpected UID'};$v+=($name+'/'+$u.Name);foreach($p in $u.Value.profiles){$v+=($name+'/'+$u.Name+'/profile/'+$p.id)};foreach($sub in $u.Value.subscriptions){$v+=($name+'/'+$u.Name+'/subscription/'+$sub.id)}}
 };return @($v|Sort-Object)
}
function Files{return @(Get-ChildItem -LiteralPath $app -File -Recurse -Force|ForEach-Object {if($_.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse app file'};$_.FullName.Substring($app.Length)}|Sort-Object)}
function Snapshot{
 $p=New-Object Diagnostics.Process;$p.StartInfo.FileName=Join-Path $app 'vault443-cli.exe';$p.StartInfo.Arguments='GetSnapshot';$p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true;$p.StartInfo.RedirectStandardInput=$true;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
 try{[void]$p.Start();$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync();$p.StandardInput.WriteLine('[]');$p.StandardInput.Close();if(!$p.WaitForExit(15000)){throw 'Snapshot deadline; child retained'};if($p.ExitCode-ne0){throw 'Snapshot failed'};[void]$e.GetAwaiter().GetResult();return ($o.GetAwaiter().GetResult()|ConvertFrom-Json)}finally{$p.Dispose()}
}
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public sealed class Vault443InstallerHang : IDisposable {
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,uint tid);
 [DllImport("kernel32.dll")] static extern uint GetProcessIdOfThread(IntPtr thread);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder path,ref uint length);
 [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr process,out long creation,out long end,out long kernel,out long user);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint SuspendThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 IntPtr process,thread;bool ownSuspend;readonly string image;readonly uint pid;readonly long creation;
 public uint ThreadId {get;private set;} public long CreationFileTime {get{return creation;}}
 public Vault443InstallerHang(uint wantedPid,IntPtr window,string expectedImage) {
  pid=wantedPid;image=expectedImage;
  try {
   process=OpenProcess(0x101000,false,pid);if(process==IntPtr.Zero)throw new InvalidOperationException("Process handle unavailable");
   long end,kernel,user;if(!GetProcessTimes(process,out creation,out end,out kernel,out user))throw new InvalidOperationException("Creation time unavailable");
   uint owner;ThreadId=GetWindowThreadProcessId(window,out owner);if(ThreadId==0||owner!=pid)throw new InvalidOperationException("UI window owner differs");
   thread=OpenThread(0x0802,false,ThreadId);if(thread==IntPtr.Zero||GetProcessIdOfThread(thread)!=pid)throw new InvalidOperationException("UI thread owner differs");
   Validate();
  }catch{Dispose();throw;}
 }
 public void Validate() {
  if(process==IntPtr.Zero||thread==IntPtr.Zero||WaitForSingleObject(process,0)!=258||GetProcessIdOfThread(thread)!=pid)throw new InvalidOperationException("Original GUI no longer alive");
  var path=new StringBuilder(32768);uint size=32768;long now,end,kernel,user;
  if(!QueryFullProcessImageName(process,0,path,ref size)||!String.Equals(path.ToString(),image,StringComparison.OrdinalIgnoreCase)||!GetProcessTimes(process,out now,out end,out kernel,out user)||now!=creation)throw new InvalidOperationException("Held GUI identity differs");
 }
 public void Suspend() {
  Validate();uint previous=SuspendThread(thread);if(previous==0xffffffff)throw new InvalidOperationException("UI suspend failed");ownSuspend=true;
  if(previous!=0){Resume();throw new InvalidOperationException("UI was already suspended");}
 }
 public void Resume() {
  if(!ownSuspend)return;
  uint previous=ResumeThread(thread);if(previous==0xffffffff)throw new InvalidOperationException("UI resume failed");
  ownSuspend=false;if(previous!=1)throw new InvalidOperationException("Unexpected external suspension change");
 }
 public void Dispose(){try{Resume();}finally{if(thread!=IntPtr.Zero){CloseHandle(thread);thread=IntPtr.Zero;}if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}}}
}
'@
try{
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$computer=Get-CimInstance Win32_ComputerSystem;$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
 if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$computer.Model-ne'VirtualBox'-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value-or!$session-or$session-ne[Vault443InstallerHang]::WTSGetActiveConsoleSessionId()){throw 'Same active-console named QA controller UAC required'}
 foreach($path in @($q,(Join-Path $q 'reports'),$app)){Protected $path $false};foreach($path in @($private,(Join-Path $private 'marker'),(Join-Path $private 'qa-inputs.json'))){Protected $path $true}
 if([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'Private QA marker differs'}
 $inputs=Get-Content (Join-Path $private 'qa-inputs.json') -Raw|ConvertFrom-Json;if($inputs.machine-ne$env:COMPUTERNAME-or$inputs.controllerSID-ne$identity.User.Value){throw 'Protected QA SID differs'}
 $parent=Split-Path $out -Parent;if(Test-Path $parent){Protected $parent $false}else{New-Item -ItemType Directory -Path $parent|Out-Null};New-Item -ItemType Directory -Path $out|Out-Null;Protected $out $false;$canReport=$true;Save
 Pin (Join-Path $app 'build-manifest.json') $manifestSHA
 $manifest=Get-Content (Join-Path $app 'build-manifest.json') -Raw|ConvertFrom-Json
 if($manifest.productVersion-ne'1.3.5'){throw 'Expected 1.3.5 installed build manifest'}
 $guiSHA=$manifest.files.'vault443.exe'.sha256;$daemonSHA=$manifest.files.'vault443d.exe'.sha256;$cliSHA=$manifest.files.'vault443-cli.exe'.sha256
 foreach($hash in @($guiSHA,$daemonSHA,$cliSHA)){if($hash-notmatch'^[0-9a-f]{64}$'){throw 'Missing exact production file pin'}}
 Pin (Join-Path $app 'vault443.exe') $guiSHA;Pin (Join-Path $app 'vault443d.exe') $daemonSHA;Pin (Join-Path $app 'vault443-cli.exe') $cliSHA
 $s=Snapshot;$terminal=!$s.operation-or($s.operation.action-eq'disconnect'-and$s.operation.stage-eq'disconnected')
 Check 'all-vpn-off' (!$s.busyByOtherUser-and$s.runtime.state-eq'disconnected'-and!$s.runtime.guardArmed-and$terminal-and@($s.workProfiles|Where-Object {$_.runtime.state-ne'disconnected'-or$_.runtime.guardArmed-or($_.operation-and!($_.operation.action-eq'disconnect'-and$_.operation.stage-eq'disconnected'))}).Count-eq0)
 $main=Get-Content 'C:\ProgramData\Vault443\state.json' -Raw|ConvertFrom-Json;$work=Get-Content 'C:\ProgramData\Vault443\work-vpn.json' -Raw|ConvertFrom-Json;Check 'all-uid-desired-off' (!$main.desired-and@($work.desired|Where-Object {$null-ne$_}).Count-eq0)
 $beforeIDs=@(IDs);$beforeFiles=@(Files);$service=Get-CimInstance Win32_Service -Filter "Name='Vault443'";Check 'service-running-before' ($service.State-eq'Running'-and$service.ProcessId-gt0);$servicePid=[int]$service.ProcessId
 $matches=@(Get-Process -Name vault443 -ErrorAction SilentlyContinue|Where-Object {$_.SessionId-eq$session-and[string]::Equals($_.MainModule.FileName,(Join-Path $app 'vault443.exe'),[StringComparison]::OrdinalIgnoreCase)})
 Check 'one-exact-console-gui' ($matches.Count-eq1);$gui=$matches[0];[void]$gui.Handle;$gui.Refresh();if(!$gui.MainWindowHandle){throw 'Visible GUI main window required'}
 $hold=[Vault443InstallerHang]::new([uint32]$gui.Id,$gui.MainWindowHandle,(Join-Path $app 'vault443.exe'));$r.gui=@{pid=$gui.Id;creationFileTime=$hold.CreationFileTime;session=$session;uiThread=$hold.ThreadId;imageSHA=$guiSHA};$r.servicePID=$servicePid;$r.profileIdentityCount=$beforeIDs.Count;$r.fileCount=$beforeFiles.Count
 $unins=Join-Path $app 'unins000.exe';Protected $unins $false;$uninsSHA=(Get-FileHash $unins -Algorithm SHA256).Hash.ToLowerInvariant();$r.uninstallerSHA=$uninsSHA
 $r.stage='suspend-ui';Save;$hold.Suspend();$r.threadSuspended=$true;Save
 $r.stage='uninstall-must-abort';$r.uninstallerStartedUTC=[DateTime]::UtcNow.ToString('o');Save
 Pin $unins $uninsSHA;$uninstaller=Start-Process -FilePath $unins -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $out 'uninstall.log')+'"')) -PassThru
 $r.uninstallerPID=$uninstaller.Id;Save
 if(!$uninstaller.WaitForExit(120000)){$r.childProcessRetained=$true;throw 'Uninstaller deadline; retained for root review'}
 $r.uninstallerExitCode=$uninstaller.ExitCode;Check 'uninstaller-aborted-exit1' ($uninstaller.ExitCode-eq1)
 $logText=Get-Content -LiteralPath (Join-Path $out 'uninstall.log') -Raw;Check 'abort-at-graceful-gui-shutdown' ($logText-match'(Graceful interface shutdown failed: Windows error [0-9]+|Installed interface is still running after the shutdown deadline\.)')
 $r.stage='verify-retained';$hold.Validate();Pin (Join-Path $app 'vault443.exe') $guiSHA;Check 'original-gui-alive' (!$gui.HasExited)
 $afterService=Get-CimInstance Win32_Service -Filter "Name='Vault443'";Check 'same-service-running' ($afterService.State-eq'Running'-and[int]$afterService.ProcessId-eq$servicePid)
 Pin (Join-Path $app 'build-manifest.json') $manifestSHA;Check 'same-manifest-retained' $true
 $afterIDs=@(IDs);Check 'exact-all-profile-identities-retained' ((ConvertTo-Json -InputObject $beforeIDs -Compress)-ceq(ConvertTo-Json -InputObject $afterIDs -Compress)) @{before=$beforeIDs.Count;after=$afterIDs.Count}
 $afterFiles=@(Files);Check 'exact-app-file-set-retained' ((ConvertTo-Json -InputObject $beforeFiles -Compress)-ceq(ConvertTo-Json -InputObject $afterFiles -Compress)) @{before=$beforeFiles.Count;after=$afterFiles.Count}
 $r.stage='complete';$r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{
 if($null-ne$hold){try{$hold.Resume();$r.threadResumed=$true;$hold.Validate()}catch{$r.cleanupErrorType=$_.Exception.GetType().FullName;$r.passed=$false}finally{try{$hold.Dispose()}catch{$r.cleanupErrorType=$_.Exception.GetType().FullName;$r.passed=$false}}}
 if($null-ne$gui){$gui.Dispose()};if($null-ne$uninstaller){$uninstaller.Dispose()}
 $r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save
}
if(!$r.passed){exit 1}
