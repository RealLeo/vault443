# Explicit same-controller UAC. Sets only Vault443 to Manual; DOES NOT reboot.
# Copy the exact reviewed startup file to the fixed Exchange source first.
#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedManifestSha256)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$qa='C:\Program Files\Vault443QA';$private='C:\ProgramData\Vault443-QA'
$taskName='Vault443-QA-r8-prescm';$code=Join-Path $qa 'r8-boot';$data=Join-Path $private 'r8-boot'
$source='C:\Users\Public\Vault443Exchange\vault443-r8-boot-startup.ps1';$wrapper=Join-Path $code 'startup.ps1'
$wrapperSHA='8bba082469aa01dfd081a7ab15be712aaf5ec6b2ea3844d43cc8cc91a5be276b'
$daemonSHA='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'
$manifestSHA=$ExpectedManifestSha256
$matrixSHA='fc633896542f0e00fa452fca180c5dc473339b2309779b0def2dedf398e999e8'
$cliSHA='514c067b23e6adbfd8a245f592aa338ec62105f08de59c3286065fd1a278f1c6'
$journal=$null;$registered=$false;$manual=$false;$success=$false
function Protected([string]$Path,[bool]$PrivatePath) {
 $i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse QA path'}
 $a=Get-Acl -LiteralPath $Path;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')){throw 'Untrusted QA owner'}
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if($null-eq$raw.DiscretionaryAcl){throw 'Null DACL'}
 $mask=0x500D0156;if($PrivatePath){$mask=$mask-bor0x80000021}
 foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.AccessControlType-eq'Allow'-and!($r.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$r.IdentityReference.Value-notin@('S-1-5-18','S-1-5-32-544')-and([long]$r.FileSystemRights-band$mask)){throw 'Untrusted QA access'}}
}
function Secure([string]$Path,[bool]$Directory,[bool]$UsersRead=$false) {
 if($Directory){New-Item -ItemType Directory -Path $Path -ErrorAction Stop|Out-Null}
 $a=if($Directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
 $sddl='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)';if(!$Directory){$sddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'}
 if($UsersRead){$sddl+='(A;OICI;0x1200a9;;;BU)'}
 $a.SetSecurityDescriptorSddlForm($sddl);Set-Acl -LiteralPath $Path -AclObject $a
}
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$machine=Get-CimInstance Win32_ComputerSystem
 if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$machine.Model-notmatch'^VirtualBox$'-or!$machine.UserName-or([Security.Principal.NTAccount]::new($machine.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value){throw 'Same active-console controller UAC required'}
 foreach($p in @($qa,(Join-Path $qa 'reports'))){Protected $p $false}
 foreach($p in @($private,(Join-Path $private 'marker'),(Join-Path $private 'qa-inputs.json'))){Protected $p $true}
 if([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'Private QA marker differs'}
 $config=Get-Content (Join-Path $private 'qa-inputs.json') -Raw|ConvertFrom-Json
 if($config.machine-ne$env:COMPUTERNAME-or$config.controllerSID-ne$identity.User.Value){throw 'Bound controller differs'}
 $scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect()
 $existing=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 if($existing-or(Test-Path $code)-or(Test-Path $data)-or(Test-Path (Join-Path $qa 'reports\r8-boot'))){throw 'Existing boot QA task/journal/path; refuse foreign or previous ownership'}
 foreach($entry in @(@('C:\Program Files\Vault443\vault443d.exe',$daemonSHA),@('C:\Program Files\Vault443\build-manifest.json',$manifestSHA),@('C:\Program Files\Vault443\vault443-cli.exe',$cliSHA),@((Join-Path $qa 'main-matrix.ps1'),$matrixSHA),@($source,$wrapperSHA))){
  if((Get-Item -LiteralPath $entry[0]).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Pinned file is a reparse point'}
  if((Get-FileHash -LiteralPath $entry[0]).Hash.ToLowerInvariant()-ne$entry[1]){throw 'Pinned R8/helper identity differs'}
 }
 $tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Startup PS5 parser rejected source'}
 $raw='[]'|& 'C:\Program Files\Vault443\vault443-cli.exe' GetSnapshot
 if($LASTEXITCODE){throw 'Same-console authenticated snapshot failed'};$snapshot=$raw|ConvertFrom-Json
 $p=@($snapshot.profiles|Where-Object id -eq $snapshot.activeProfileId)
 if($snapshot.busyByOtherUser-or$p.Count-ne1-or$p[0].kind-ne'vless'-or$snapshot.runtime.state-ne'connected'-or!$snapshot.runtime.guardArmed-or$snapshot.bootProfileId-ne$snapshot.activeProfileId){throw 'Own VLESS must be connected/protected and separately pinned for boot'}
 $service=Get-CimInstance Win32_Service -Filter "Name='Vault443'"
 if($service.StartMode-ne'Auto'-or$service.StartName-ne'LocalSystem'-or$service.State-ne'Running'-or$service.PathName.Trim('"')-ne'C:\Program Files\Vault443\vault443d.exe'){throw 'Installed Automatic LocalSystem service identity differs'}
 $delayed=Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Vault443' DelayedAutoStart -ErrorAction SilentlyContinue
 if([int]$delayed-notin@(0,1)){throw 'Unexpected delayed-start flag'}
 $adapters=@(Get-NetAdapter -Physical|Where-Object {[string]$_.InterfaceGuid-eq$config.adapterGuid-and$_.MacAddress-eq$config.adapterMAC})
 if($adapters.Count-ne1-or$adapters[0].Status-ne'Up'){throw 'Bound physical QA adapter differs'}
 $ips=@(Get-NetIPAddress -InterfaceIndex $adapters[0].ifIndex)
 if(@($ips|Where-Object AddressState -ne 'Preferred').Count-or!@($ips|Where-Object {$_.IPAddress-eq'192.0.2.2'-and$_.PrefixOrigin-eq'Manual'-and$_.PrefixLength-eq24}).Count-or!@($ips|Where-Object {$_.IPAddress-eq'2001:db8:44::2'-and$_.PrefixOrigin-eq'Manual'-and$_.PrefixLength-eq64}).Count){throw 'Preferred static dual-stack fixture IPs required'}
 Secure $code $true;Secure $data $true;Secure (Join-Path $data 'matrix') $true;Secure (Join-Path $qa 'reports\r8-boot') $true $true
 [IO.File]::WriteAllBytes($wrapper,[IO.File]::ReadAllBytes($source));Secure $wrapper $false
 if((Get-FileHash $wrapper).Hash.ToLowerInvariant()-ne$wrapperSHA){throw 'Copied wrapper identity differs'}
 $journal=@{schema=1;machine=$env:COMPUTERNAME;controllerSID=$identity.User.Value;token=[Guid]::NewGuid().ToString('D');armedUTC=[DateTime]::UtcNow.ToString('o');preBootUTC=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');startMode=$service.StartMode;delayed=[int]$delayed;mainID=$snapshot.activeProfileId;adapterGUID=[string]$adapters[0].InterfaceGuid;adapterMAC=$adapters[0].MacAddress;addresses=@($ips|ForEach-Object {$_.IPAddress}|Sort-Object);wrapperSHA=$wrapperSHA;manifestSHA=$manifestSHA;daemonSHA=$daemonSHA}
 $bytes=[Text.Encoding]::UTF8.GetBytes(($journal|ConvertTo-Json -Depth 5));$stream=[IO.File]::Open((Join-Path $data 'journal.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 Secure (Join-Path $data 'journal.json') $false
 $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$wrapper+'"'
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $arguments
 $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $settings -Description ('Vault443 R8 pre-SCM '+$journal.token)|Out-Null
 $registered=$true
 $scheduler.GetFolder('\').GetTask($taskName).SetSecurityDescriptor(('O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$identity.User.Value+')'),0)
 & "$env:SystemRoot\System32\sc.exe" config Vault443 start= demand|Out-Null;if($LASTEXITCODE){throw 'Cannot arm temporary Manual start'}
 $manual=$true
 if((Get-CimInstance Win32_Service -Filter "Name='Vault443'").StartMode-ne'Manual'){throw 'Manual readback differs'}
 $success=$true
 @{armed=$true;rebootPerformed=$false;task=$taskName;journal=(Join-Path $data 'journal.json');report=(Join-Path $qa 'reports\r8-boot\result.json');originalStart=$journal.startMode;originalDelayed=$journal.delayed;mainID=$journal.mainID}|ConvertTo-Json -Compress
}finally {
 if(!$success-and$journal){
  if($manual){$start=if($journal.delayed-eq1){'delayed-auto'}else{'auto'};& "$env:SystemRoot\System32\sc.exe" config Vault443 start= $start|Out-Null;if($LASTEXITCODE){throw 'Setup rollback failed; keep private journal and task for recovery'}}
  if($registered){$t=$scheduler.GetFolder('\').GetTask($taskName);if($t.Definition.RegistrationInfo.Description-eq('Vault443 R8 pre-SCM '+$journal.token)){$scheduler.GetFolder('\').DeleteTask($taskName,0)}}
 }
}
