#Requires -Version 5.1
#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][ValidateSet('pathsecurity','installbaselineR9','refusalupgradeR9','upgradeDefault','uninstallDefault','installCustom','inspectCustom','hungGUIabort','uninstallCustom','fixture-network','bootOn','bootOff')][string]$Mode)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$q=Join-Path $env:ProgramFiles 'Vault443QA';$private=Join-Path $env:ProgramData 'Vault443-QA'
$default=Join-Path $env:ProgramFiles 'Vault443';$custom='V:\Программы VPN\Vault443'
$newName='Vault443-1.3.5-windows-x64-setup.exe';$oldName='Vault443-1.3.4-windows-x64-setup.exe'
function Protected([string]$Path,[bool]$PrivatePath=$false){
 $i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'QA reparse input'}
 $a=Get-Acl -LiteralPath $Path;$trusted=@('S-1-5-18','S-1-5-32-544');if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin$trusted){throw 'QA owner differs'}
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if(!$raw.DiscretionaryAcl){throw 'Null QA DACL'}
 $mask=0x500D0156;if($PrivatePath){$mask=$mask-bor0x80000021}
 foreach($e in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and!($e.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$e.IdentityReference.Value-notin$trusted-and([long]$e.FileSystemRights-band$mask)){throw 'QA access differs'}}
}
function Pin([string]$Path,[string]$Sha){Protected $Path;if($Sha-notmatch'^[a-f0-9]{64}$'-or(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$Sha){throw 'QA pin differs'}}
Protected $q;Protected $private $true;Protected (Join-Path $private 'marker') $true;Protected (Join-Path $private 'release135-inputs.json') $true
if([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'QA marker differs'}
$c=[IO.File]::ReadAllText((Join-Path $private 'release135-inputs.json'))|ConvertFrom-Json
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$computer=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$computer.Model-ne'VirtualBox'-or$c.machine-ne$env:COMPUTERNAME-or$c.controllerSID-ne$identity.User.Value-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$c.controllerSID-or[Diagnostics.Process]::GetCurrentProcess().SessionId-eq0){throw 'Fixed interactive QA controller required'}
$allowed=@('release135-admin.ps1','release135-bootstrap.ps1','installer-smoke.ps1','install-path-security.ps1','installer-upgrade-path-refusal.ps1','installer-gui-close-abort.ps1','main-matrix.ps1','main-smoke.ps1','work-smoke.ps1','openvpn-smoke.ps1','ui-native-smoke.ps1','qa-runner.ps1','fixture-ca.crt','vault443d.exe','build-manifest.json',$newName,$oldName)
foreach($entry in $c.files.PSObject.Properties){if($entry.Name-notin$allowed){throw 'Unknown protected QA input'};Pin (Join-Path $q $entry.Name) ([string]$entry.Value)}
if($c.files.$newName-ne$c.installerSha256-or$c.files.'build-manifest.json'-ne$c.manifestSha256-or$c.files.'vault443d.exe'-ne$c.daemonSha256-or$c.files.$oldName-ne'f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d'){throw 'Artifact config pins differ'}
$manifest=[IO.File]::ReadAllText((Join-Path $q 'build-manifest.json'))|ConvertFrom-Json
if($manifest.productVersion-ne'1.3.5'-or$manifest.files.'vault443d.exe'.sha256-ne$c.daemonSha256){throw 'Candidate daemon manifest differs'}
$reports=Join-Path $q 'reports';Protected $reports
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ');$out=Join-Path $reports ('release135-'+$stamp+'-'+$Mode)
New-Item -ItemType Directory -Path $out|Out-Null;Protected $out
$r=[ordered]@{schema=1;version='1.3.5';mode=$Mode;machine=$env:COMPUTERNAME;startedUTC=[DateTime]::UtcNow.ToString('o');passed=$false;completed=$false;details=@{}}
function Save{$r|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding UTF8}
function Child([string]$Exe,[string]$Arguments,[int]$Seconds=300){
 $p=Start-Process -FilePath $Exe -WorkingDirectory ([IO.Path]::GetDirectoryName($Exe)) -ArgumentList $Arguments -RedirectStandardOutput (Join-Path $private ($stamp+'-'+$Mode+'.stdout')) -RedirectStandardError (Join-Path $private ($stamp+'-'+$Mode+'.stderr')) -PassThru
 [void]$p.Handle;if(!$p.WaitForExit($Seconds*1000)){throw 'Fixed QA child deadline; child retained'};$exitCode=$p.ExitCode;$p.Dispose();if($exitCode-ne0){throw ('Fixed QA child failed: '+$exitCode)}
}
function Harness([string]$Name,[string]$Arguments){Pin (Join-Path $q $Name) ([string]$c.files.$Name);Child (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $q $Name)+'" '+$Arguments)}
function Smoke([string]$Phase,[string]$Directory){Harness 'installer-smoke.ps1' ('-Phase '+$Phase+' -InstallerPath "'+(Join-Path $q $newName)+'" -InstallerSha256 '+$c.installerSha256+' -AppDirectory "'+$Directory+'" -OutputDirectory "'+$out+'" -SkipGuiProbe')}
function CurrentApp{
 $key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B7547E6A-E316-4C92-9407-1B0F0D4A3443}_is1';$a=[IO.Path]::GetFullPath((Get-ItemProperty -LiteralPath $key).InstallLocation).TrimEnd('\')
 if($a-ne$default-and$a-ne$custom){throw 'Unknown installed QA location'}
 if((Get-FileHash -LiteralPath (Join-Path $a 'build-manifest.json')).Hash.ToLowerInvariant()-ne$c.manifestSha256){throw 'Installed candidate manifest differs'}
 return $a
}
try{
 Save
 switch($Mode){
  'pathsecurity'{Harness 'install-path-security.ps1' ('-DaemonPath "'+(Join-Path $q 'vault443d.exe')+'" -DaemonSha256 '+$c.daemonSha256+' -OutputDirectory "'+$out+'" -TestDrive V:')}
  'installbaselineR9'{Child (Join-Path $q $oldName) ('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR="'+$default+'" /LOG="'+(Join-Path $out 'baseline.log')+'"');$s=Get-CimInstance Win32_Service -Filter "Name='Vault443'";if(!$s-or$s.State-ne'Running'-or$s.StartName-ne'LocalSystem'){throw 'Baseline service not running'}}
  'refusalupgradeR9'{Harness 'installer-upgrade-path-refusal.ps1' ('-InstallerPath "'+(Join-Path $q $newName)+'" -InstallerSha256 '+$c.installerSha256+' -AppDirectory "'+$default+'" -OutputDirectory "'+$out+'"')}
  'upgradeDefault'{Smoke 'upgrade' $default}
  'uninstallDefault'{Smoke 'uninstall' $default}
  'installCustom'{Smoke 'install' $custom}
  'inspectCustom'{Smoke 'inspect' $custom}
  'hungGUIabort'{Harness 'installer-gui-close-abort.ps1' ('-AppDirectory "'+$custom+'" -ManifestSha256 '+$c.manifestSha256+' -QAPath "'+$q+'"')}
  'uninstallCustom'{Smoke 'uninstall' $custom}
  'fixture-network'{
   Protected (Join-Path $private 'qa-inputs.json') $true;$binding=[IO.File]::ReadAllText((Join-Path $private 'qa-inputs.json'))|ConvertFrom-Json
   $a=@(Get-NetAdapter -Physical|Where-Object {[string]$_.InterfaceGuid-eq$binding.adapterGuid-and$_.MacAddress-eq$binding.adapterMAC});if($a.Count-ne1){throw 'Bound physical uplink differs'};$index=$a[0].ifIndex
   Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Disabled
   Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4|Remove-NetIPAddress -Confirm:$false
   Get-NetRoute -InterfaceIndex $index -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Remove-NetRoute -Confirm:$false
   New-NetIPAddress -InterfaceIndex $index -IPAddress 192.0.2.2 -PrefixLength 24 -DefaultGateway 192.0.2.1|Out-Null
   Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses 192.0.2.1
   Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv6 -RouterDiscovery Disabled
   Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv6|Where-Object {$_.PrefixOrigin-eq'Manual'-and$_.IPAddress-notlike'fe80:*'}|Remove-NetIPAddress -Confirm:$false
   Get-NetRoute -InterfaceIndex $index -DestinationPrefix '::/0' -ErrorAction SilentlyContinue|Remove-NetRoute -Confirm:$false
   New-NetIPAddress -InterfaceIndex $index -IPAddress 2001:db8:44::2 -PrefixLength 64 -DefaultGateway 2001:db8:44::1|Out-Null
   Pin (Join-Path $q 'fixture-ca.crt') ([string]$c.files.'fixture-ca.crt');Import-Certificate -FilePath (Join-Path $q 'fixture-ca.crt') -CertStoreLocation Cert:\LocalMachine\Root|Out-Null
   $r.details=@{interfaceIndex=$index;adapterGUID=$binding.adapterGuid;ipv4='192.0.2.2';ipv6='2001:db8:44::2'}
  }
  {$_-in@('bootOn','bootOff')}{
   $app=CurrentApp;$helper=Join-Path $app 'vault443-access.exe';Pin $helper ([string]$manifest.files.'vault443-access.exe'.sha256)
   $id=''
   if($Mode-eq'bootOn'){
    $cli=Join-Path $app 'vault443-cli.exe';Pin $cli ([string]$manifest.files.'vault443-cli.exe'.sha256)
    $reply='[]'|& $cli GetSnapshot;if($LASTEXITCODE){throw 'Snapshot failed'};$snapshot=($reply-join"`n")|ConvertFrom-Json
    $profiles=@($snapshot.profiles|Where-Object {$_.kind-eq'vless'});if($profiles.Count-ne1-or$profiles[0].id-notmatch'^[a-f0-9]{32}$'){throw 'Exactly one VLESS QA profile required'};$id=[string]$profiles[0].id
   }
   $request=@{method='SetBootProfile';params=@($id)}|ConvertTo-Json -Compress
   $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($request)).TrimEnd('=').Replace('+','-').Replace('/','_')
   Child $helper ('--request '+$encoded) 60;$r.details=@{bootEnabled=($Mode-eq'bootOn');profileId=$id;appDirectory=$app}
  }
 }
 $r.passed=$true
}catch{$r.error=$_.Exception.Message;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');Save}
if(!$r.passed){exit 1}
