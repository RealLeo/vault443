#Requires -Version 5.1
#Requires -RunAsAdministrator
# Approve once as the active QA console controller. Execute reviewed bootstrap
# bytes; ConfigSha256 is supplied independently by the host, not read from Public.
param([Parameter(Mandatory=$true)][string]$SourceDirectory,[Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ConfigSha256)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$computer=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$computer.Model-ne'VirtualBox'-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value-or[Diagnostics.Process]::GetCurrentProcess().SessionId-eq0){throw 'Same active QA console controller UAC required'}
$sourceConfig=Join-Path $SourceDirectory 'release135-inputs.json'
if((Get-FileHash -LiteralPath $sourceConfig).Hash-ne$ConfigSha256){throw 'Host-provided config pin differs'}
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class Vault443Release135Files {
 [StructLayout(LayoutKind.Sequential)]struct SA{public int length;public IntPtr descriptor;public int inherit;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint revision,out IntPtr descriptor,out uint size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateDirectory(string name,ref SA attributes);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string name,uint access,uint share,ref SA attributes,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr ptr);
 static IntPtr Descriptor(bool privatePath){IntPtr p;uint size;string s="O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"+(privatePath?"":"(A;OICI;0x1200a9;;;BU)");if(!ConvertStringSecurityDescriptorToSecurityDescriptor(s,1,out p,out size))throw new System.ComponentModel.Win32Exception();return p;}
 public static void DirectoryNew(string path,bool privatePath){IntPtr d=Descriptor(privatePath);try{var a=new SA{length=Marshal.SizeOf(typeof(SA)),descriptor=d,inherit=0};if(!CreateDirectory(path,ref a))throw new System.ComponentModel.Win32Exception();}finally{LocalFree(d);}}
 public static FileStream FileNew(string path,bool privatePath){IntPtr d=Descriptor(privatePath);try{var a=new SA{length=Marshal.SizeOf(typeof(SA)),descriptor=d,inherit=0};var h=CreateFile(path,0x40000000,1,ref a,1,0x80,IntPtr.Zero);if(h.IsInvalid){h.Dispose();throw new System.ComponentModel.Win32Exception();}return new FileStream(h,FileAccess.Write);}finally{LocalFree(d);}}
 public static void CopyNew(string source,string target,bool privatePath){using(var input=File.Open(source,FileMode.Open,FileAccess.Read,FileShare.Read))using(var output=FileNew(target,privatePath)){input.CopyTo(output);output.Flush(true);}}
 public static void TextNew(string text,string path,bool privatePath){using(var output=FileNew(path,privatePath)){var bytes=new System.Text.UTF8Encoding(false).GetBytes(text);output.Write(bytes,0,bytes.Length);output.Flush(true);}}
}
'@
$q=Join-Path $env:ProgramFiles 'Vault443QA';$private=Join-Path $env:ProgramData 'Vault443-QA'
function Protected([string]$Path,[bool]$PrivatePath){
 $i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'QA reparse input'};$a=Get-Acl -LiteralPath $Path;$trusted=@('S-1-5-18','S-1-5-32-544');if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin$trusted){throw 'QA owner differs'}
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if(!$raw.DiscretionaryAcl){throw 'Null QA DACL'};$mask=0x500D0156;if($PrivatePath){$mask=$mask-bor0x80000021}
 foreach($e in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and!($e.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$e.IdentityReference.Value-notin$trusted-and([long]$e.FileSystemRights-band$mask)){throw 'QA access differs'}}
}
foreach($pair in @(@($q,$false),@($private,$true),@((Join-Path $q 'reports'),$false))){if(!(Test-Path -LiteralPath $pair[0])){[Vault443Release135Files]::DirectoryNew($pair[0],$pair[1])};Protected $pair[0] $pair[1]}
$protectedConfig=Join-Path $private 'release135-inputs.json'
if(Test-Path -LiteralPath $protectedConfig){Protected $protectedConfig $true;if((Get-FileHash -LiteralPath $protectedConfig).Hash-ne$ConfigSha256){throw 'Existing config differs'}}else{[Vault443Release135Files]::CopyNew($sourceConfig,$protectedConfig,$true)}
if((Get-FileHash -LiteralPath $protectedConfig).Hash-ne$ConfigSha256){throw 'Protected config SHA differs'}
# Parse only the immutable protected copy authenticated by the independent host pin.
$c=[IO.File]::ReadAllText($protectedConfig)|ConvertFrom-Json
if($c.schema-ne1-or$c.machine-ne$env:COMPUTERNAME-or$c.controllerSID-ne$identity.User.Value){throw 'Host configuration controller/machine differs'}
$allowed=@('release135-admin.ps1','release135-bootstrap.ps1','installer-smoke.ps1','install-path-security.ps1','installer-upgrade-path-refusal.ps1','installer-gui-close-abort.ps1','main-matrix.ps1','main-smoke.ps1','work-smoke.ps1','openvpn-smoke.ps1','ui-native-smoke.ps1','qa-runner.ps1','fixture-ca.crt','vault443d.exe','build-manifest.json','Vault443-1.3.5-windows-x64-setup.exe','Vault443-1.3.4-windows-x64-setup.exe')
$required=@('release135-admin.ps1','installer-smoke.ps1','install-path-security.ps1','installer-upgrade-path-refusal.ps1','installer-gui-close-abort.ps1','fixture-ca.crt','vault443d.exe','build-manifest.json','Vault443-1.3.5-windows-x64-setup.exe','Vault443-1.3.4-windows-x64-setup.exe')
foreach($name in $required){if(!$c.files.PSObject.Properties[$name]){throw ('Missing fixed QA input: '+$name)}}
foreach($entry in $c.files.PSObject.Properties){if($entry.Name-notin$allowed-or$entry.Value-notmatch'^[a-f0-9]{64}$'){throw 'Unknown QA input or invalid SHA'};if((Get-FileHash -LiteralPath (Join-Path $SourceDirectory $entry.Name)).Hash.ToLowerInvariant()-ne$entry.Value){throw 'Source SHA differs'}}
if($c.files.'Vault443-1.3.4-windows-x64-setup.exe'-ne'f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d'-or$c.files.'Vault443-1.3.5-windows-x64-setup.exe'-ne$c.installerSha256-or$c.files.'build-manifest.json'-ne$c.manifestSha256-or$c.files.'vault443d.exe'-ne$c.daemonSha256){throw 'Candidate/baseline identities differ'}
foreach($entry in $c.files.PSObject.Properties){$target=Join-Path $q $entry.Name;if(Test-Path -LiteralPath $target){Protected $target $false;if((Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant()-ne$entry.Value){throw 'Existing protected QA input differs; use fresh QA root'}}else{[Vault443Release135Files]::CopyNew((Join-Path $SourceDirectory $entry.Name),$target,$false)};Protected $target $false;if((Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant()-ne$entry.Value){throw 'Protected copy SHA differs'}}
$marker=Join-Path $private 'marker';if(!(Test-Path -LiteralPath $marker)){[Vault443Release135Files]::TextNew('Vault443 isolated Windows fixture',$marker,$true)};Protected $marker $true
if([IO.File]::ReadAllText($marker)-ne'Vault443 isolated Windows fixture'){throw 'Existing QA marker differs'}
$adapter=@(Get-NetAdapter -Physical|Where-Object {$_.InterfaceDescription-notmatch'Wintun|WireGuard|VPN'});if($adapter.Count-ne1){throw 'One physical QA uplink required'}
$compat=@{machine=$env:COMPUTERNAME;controllerSID=$c.controllerSID;adapterGuid=[string]$adapter[0].InterfaceGuid;adapterMAC=$adapter[0].MacAddress;files=$c.files;installer='Vault443-1.3.5-windows-x64-setup.exe';installerSha256=$c.installerSha256}
$compatPath=Join-Path $private 'qa-inputs.json';if(!(Test-Path -LiteralPath $compatPath)){[Vault443Release135Files]::TextNew(($compat|ConvertTo-Json -Depth 8),$compatPath,$true)};Protected $compatPath $true
$modes=@('pathsecurity','installbaselineR9','refusalupgradeR9','upgradeDefault','uninstallDefault','installCustom','inspectCustom','hungGUIabort','uninstallCustom','fixture-network','bootOn','bootOff')
$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe';$runner=Join-Path $q 'release135-admin.ps1';$scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect()
foreach($mode in $modes){
 $name='Vault443-135-'+$mode;$action=New-ScheduledTaskAction -Execute $ps -WorkingDirectory $q -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$runner+'" -Mode '+$mode)
 $principal=New-ScheduledTaskPrincipal -UserId $c.controllerSID -LogonType Interactive -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force|Out-Null
 $scheduler.GetFolder('\').GetTask($name).SetSecurityDescriptor(('O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$c.controllerSID+')'),0)
}
@{bootstrap='complete';tasks=$modes;controllerSID=$c.controllerSID;configSHA256=$ConfigSha256.ToLowerInvariant()}|ConvertTo-Json -Compress
