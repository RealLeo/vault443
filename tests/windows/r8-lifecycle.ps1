#Requires -Version 5.1
#Requires -RunAsAdministrator
# Same-console isolated QA only. Root explicitly disconnects every VPN first.
# GUI validation is a separate ordinary-user step after reinstall.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$app='C:\Program Files\Vault443';$q='C:\Program Files\Vault443QA';$private='C:\ProgramData\Vault443-QA';$x='C:\Users\Public\Vault443Exchange'
$ps='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$installerSHA='12896544881b15553c8b8c60d3f07d09f8e9ff02ec64f856e1583551b1d5ca3e'
$daemonSHA='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'
$manifestSHA='bc6692d6939e0798de19465963e24de765eb84938b33866e4e295ea5bba65f19'
$nrptSHA='d26d7eab01e7ef70288e407c2f88bdedc813da8f640baf8502a23de0e95cd3b4';$smokeSHA='e40f24409955c450b620a9a831046aa63e202bbe6ac4f775d6d1b0f9b14312e0'
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ');$out=Join-Path $q ('reports\r8-lifecycle\'+$stamp)
$journal=Join-Path $private 'r8-foreign-nrpt.json';$canReport=$false;$ownNRPT=$false;$childActive=$false
$r=[ordered]@{schema=1;machine=$env:COMPUTERNAME;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;stage='preflight';checks=@();childReports=@();errorType=$null;errorLine=0;cleanupErrorType=$null;cleanupErrorLine=0;limits=@('Root must explicitly disconnect all VPNs before this controller.','Ordinary-user GUI launch after reinstall is separate.','Only the exact journal-owned foreign NRPT fixture is removed.')}
function Protected([string]$Path,[bool]$PrivatePath){
 $i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse QA input'}
 $a=Get-Acl -LiteralPath $Path;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')){throw 'Untrusted QA owner'}
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if($null-eq$raw.DiscretionaryAcl){throw 'Null QA DACL'}
 $mask=0x500D0156;if($PrivatePath){$mask=$mask-bor0x80000021}
 foreach($e in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and!($e.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$e.IdentityReference.Value-notin@('S-1-5-18','S-1-5-32-544')-and([long]$e.FileSystemRights-band$mask)){throw 'Untrusted QA permissions'}}
}
function Save{if($canReport){$r|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8}}
function Check([string]$Name,[bool]$Pass,$Observation=$null){$r.checks+=@{check=$Name;passed=$Pass;observation=$Observation};Save;if(!$Pass){throw 'Lifecycle acceptance check failed'}}
function Pin([string]$Path,[string]$SHA){if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$SHA){throw 'Reviewed input hash differs'}}
function Exact-R8{Pin (Join-Path $app 'vault443d.exe') $daemonSHA;Pin (Join-Path $app 'build-manifest.json') $manifestSHA}
function IDs{
 $v=@()
 foreach($name in @('state.json','work-vpn.json')){
  $path=Join-Path 'C:\ProgramData\Vault443' $name;Protected $path $true
  if((Get-Item $path).Length-gt40MB){throw 'Oversized private state'}
  $s=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
  foreach($u in $s.users.PSObject.Properties){
   if($u.Name-notmatch'^[0-9]{1,10}$'){throw 'Unexpected private UID'};$v+=($name+'/'+$u.Name)
   foreach($p in $u.Value.profiles){$v+=($name+'/'+$u.Name+'/profile/'+$p.id)}
   foreach($sub in $u.Value.subscriptions){$v+=($name+'/'+$u.Name+'/subscription/'+$sub.id)}
  }
 }
 return @($v|Sort-Object)
}
function Same-IDs([string]$When){$now=@(IDs);Check ('exact-all-uid-profile-sets-'+$When) ((ConvertTo-Json -InputObject $before -Compress)-ceq(ConvertTo-Json -InputObject $now -Compress)) @{before=$before.Count;after=$now.Count}}
function Child([string]$File,[string]$Arguments,[int]$Seconds,[string]$InputText=''){
 $p=New-Object Diagnostics.Process;$i=$p.StartInfo;$i.FileName=$File;$i.Arguments=$Arguments;$i.UseShellExecute=$false;$i.CreateNoWindow=$true;$i.RedirectStandardInput=$true;$i.RedirectStandardOutput=$true;$i.RedirectStandardError=$true
 try{
  [void]$p.Start();$script:childActive=$true;$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
  if($InputText){$p.StandardInput.WriteLine($InputText)};$p.StandardInput.Close()
  if(!$p.WaitForExit($Seconds*1000)){throw 'Child deadline; process retained, no further mutation is attempted'}
  $script:childActive=$false;$text=$stdout.GetAwaiter().GetResult();[void]$stderr.GetAwaiter().GetResult()
  if($p.ExitCode-ne0){throw 'Reviewed child failed; raw output omitted'};return $text
 }finally{$p.Dispose()}
}
function NRPT([string]$Mode){
 Pin $nrptScript $nrptSHA;$start=[DateTime]::UtcNow;$r.stage='foreign-nrpt-'+$Mode;Save
 [void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$nrptScript+'" -Mode '+$Mode) 60)
 $report=Join-Path $q ('reports\r8-foreign-nrpt-'+$Mode+'.json');Protected $report $false;$v=Get-Content $report -Raw|ConvertFrom-Json
 Check ('fresh-foreign-nrpt-'+$Mode) ($v.completed-and$v.passed-and$v.mode-eq$Mode-and[DateTime]$v.startedUTC-ge$start.AddSeconds(-1)-and[DateTime]$v.finishedUTC-ge$start)
 $copy=Join-Path $out ($r.stage+'-'+[DateTime]::UtcNow.ToString('HHmmssfff')+'.json');Copy-Item -LiteralPath $report -Destination $copy;$r.childReports+=@{phase=$r.stage;report=$copy};Save
}
function Installer([string]$Phase){
 Pin $smokeScript $smokeSHA;Pin $installer $installerSHA;$r.stage='installer-'+$Phase;Save
 $dir=Join-Path $out $Phase;New-Item -ItemType Directory -Path $dir|Out-Null;Protected $dir $false;$start=[DateTime]::UtcNow
 [void](Child $ps ('-NoProfile -ExecutionPolicy Bypass -File "'+$smokeScript+'" -Phase '+$Phase+' -InstallerPath "'+$installer+'" -InstallerSha256 '+$installerSHA+' -OutputDirectory "'+$dir+'" -SkipGuiProbe') 240)
 $reports=@(Get-ChildItem -LiteralPath $dir -Filter ('*-'+$Phase+'.json')|Where-Object {$_.LastWriteTimeUtc-ge$start.AddSeconds(-1)})
 if($reports.Count-ne1){throw 'Fresh unique installer phase report absent'};Protected $reports[0].FullName $false;$v=Get-Content $reports[0].FullName -Raw|ConvertFrom-Json
 Check ('fresh-installer-'+$Phase) ($v.completed-and$v.passed-and$v.phase-eq$Phase-and$v.machine-eq$env:COMPUTERNAME-and$v.installerSha256-ceq$installerSHA-and$v.guiProbeSkipped-and[DateTime]$v.utc-ge$start)
 $r.childReports+=@{phase=$r.stage;report=$reports[0].FullName};Save
}
try{
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$computer=Get-CimInstance Win32_ComputerSystem
 if(!('Vault443R8LifecycleConsole'-as[type])){Add-Type 'using System.Runtime.InteropServices; public static class Vault443R8LifecycleConsole { [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId(); }'}
 if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$computer.Model-ne'VirtualBox'-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value-or[Diagnostics.Process]::GetCurrentProcess().SessionId-ne[Vault443R8LifecycleConsole]::WTSGetActiveConsoleSessionId()){throw 'Same active-console named QA controller UAC required'}
 foreach($path in @($q,(Join-Path $q 'reports'))){Protected $path $false}
 foreach($path in @($private,(Join-Path $private 'marker'),(Join-Path $private 'qa-inputs.json'))){Protected $path $true}
 if([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'Private QA marker differs'}
 $inputs=Get-Content (Join-Path $private 'qa-inputs.json') -Raw|ConvertFrom-Json
 if($inputs.machine-ne$env:COMPUTERNAME-or$inputs.controllerSID-ne$identity.User.Value){throw 'Protected QA controller SID differs'}
 $parent=Split-Path $out -Parent;if(Test-Path $parent){Protected $parent $false}else{New-Item -ItemType Directory -Path $parent|Out-Null}
 New-Item -ItemType Directory -Path $out|Out-Null;Protected $out $false;$canReport=$true;Save
 Exact-R8;$installer=Join-Path $q 'Vault443-1.3.4-windows-x64-setup.exe';Pin $installer $installerSHA;Protected $installer $false
 $smokeScript=Join-Path $q 'installer-smoke.ps1';Protected $smokeScript $false;Pin $smokeScript $smokeSHA
 if((Test-Path $journal)-or(Test-Path ($journal+'.tmp'))){throw 'Existing foreign NRPT ownership state refused'}
 if(Test-Path (Join-Path $private 'foreign-reference.json')){throw 'Foreign WFP fixture must be explicitly cleaned first'}
 # Copy reviewed bytes out of the writable exchange before starting an elevated child.
 $source=Join-Path $x 'r8-foreign-nrpt.ps1';Pin $source $nrptSHA;$nrptScript=Join-Path $out 'r8-foreign-nrpt.ps1';Copy-Item -LiteralPath $source -Destination $nrptScript;Protected $nrptScript $false;Pin $nrptScript $nrptSHA
 Pin (Join-Path $app 'vault443-cli.exe') '514c067b23e6adbfd8a245f592aa338ec62105f08de59c3286065fd1a278f1c6'
 $snapshot=(Child (Join-Path $app 'vault443-cli.exe') 'GetSnapshot' 15 '[]')|ConvertFrom-Json
 # The API retains the completed disconnect operation for the UI. It is not
 # active work; require its exact terminal action/stage plus fully stopped state.
 $terminalDisconnect=!$snapshot.operation-or($snapshot.operation.action-eq'disconnect'-and$snapshot.operation.stage-eq'disconnected')
 Check 'explicit-all-vpn-off' (!$snapshot.busyByOtherUser-and$snapshot.runtime.state-eq'disconnected'-and!$snapshot.runtime.guardArmed-and$terminalDisconnect-and@($snapshot.workProfiles|Where-Object {$_.runtime.state-ne'disconnected'-or$_.runtime.guardArmed-or($_.operation-and!($_.operation.action-eq'disconnect'-and$_.operation.stage-eq'disconnected'))}).Count-eq0) @{main=$snapshot.runtime.state;guard=$snapshot.runtime.guardArmed;operationAction=$snapshot.operation.action;operationStage=$snapshot.operation.stage}
 $main=Get-Content 'C:\ProgramData\Vault443\state.json' -Raw|ConvertFrom-Json;$work=Get-Content 'C:\ProgramData\Vault443\work-vpn.json' -Raw|ConvertFrom-Json
 Check 'all-uid-desired-off' (!$main.desired-and@($work.desired|Where-Object {$null-ne$_}).Count-eq0)
 $before=@(IDs);$r.beforeIDs=$before;Save
 # Refused preexisting journals above: any durable journal created by this
 # reviewed child belongs to this attempt, including interrupted Add intent.
 $ownNRPT=$true;NRPT add
 Installer uninstall;Same-IDs 'uninstalled';NRPT verify
 Installer install;Exact-R8;Same-IDs 'reinstalled';NRPT verify
 NRPT remove;$ownNRPT=$false;Check 'foreign-nrpt-journal-removed' (!(Test-Path $journal)-and!(Test-Path ($journal+'.tmp')))
 $r.stage='complete';$r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{
 if($ownNRPT-and!$childActive-and((Test-Path $journal)-or(Test-Path ($journal+'.tmp')))){
  try{NRPT remove;$ownNRPT=$false}catch{$r.cleanupErrorType=$_.Exception.GetType().FullName;$r.cleanupErrorLine=$_.InvocationInfo.ScriptLineNumber}
 }
 $r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');$r.childProcessRetained=$childActive;Save
}
if(!$r.passed){exit 1}
