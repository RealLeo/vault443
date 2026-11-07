# Explicit same-controller UAC only. One ActiveStore secondary IP; no gateways/tasks.
#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][ValidateSet('add','remove')][string]$Mode)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$q='C:\Program Files\Vault443QA';$p='C:\ProgramData\Vault443-QA';$journalPath=Join-Path $p 'r7-overlap-ip.json'
$sha='2ad9a62ab0e14825cf265100891a16f74e80911e03b2d63cb036f3d976f3b1c6';$address='198.19.44.22';$journal=$null;$canReport=$false
$r=[ordered]@{mode=$Mode;utc=[DateTime]::UtcNow.ToString('o');passed=$false;created=$false;removed=$false;guid=$null;mac=$null;interfaceIndex=0;address=$address;prefix=25;skipAsSource=$true;gatewayChanged=$false;errorType=$null;errorLine=0}
function Protected([string]$Path,[bool]$Private){$i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse QA path'};$a=Get-Acl $Path;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')){throw 'Foreign QA owner'};$raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if($null-eq$raw.DiscretionaryAcl){throw 'Null QA DACL'};$mask=0x500D0156;if($Private){$mask=$mask-bor0x80000021};foreach($e in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and!($e.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$e.IdentityReference.Value-notin@('S-1-5-18','S-1-5-32-544')-and([long]$e.FileSystemRights-band$mask)){throw 'Untrusted QA permissions'}}}
function Save-Journal {$temp=Join-Path $p ('.overlap-'+[Guid]::NewGuid().ToString('N')+'.tmp');try{$bytes=[Text.Encoding]::UTF8.GetBytes(($journal|ConvertTo-Json -Depth 5));$f=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};$a=New-Object Security.AccessControl.FileSecurity;$a.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)');Set-Acl $temp $a;if(Test-Path $journalPath){[IO.File]::Replace($temp,$journalPath,[NullString]::Value)}else{[IO.File]::Move($temp,$journalPath)}}finally{if(Test-Path $temp){Remove-Item $temp -Force}}}
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$machine=Get-CimInstance Win32_ComputerSystem
 if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$machine.Model-ne'VirtualBox'-or!$machine.UserName-or([Security.Principal.NTAccount]::new($machine.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value){throw 'Same active-console named QA controller UAC required'}
 Protected $q $false;Protected (Join-Path $q 'reports') $false;Protected $p $true;Protected (Join-Path $p 'marker') $true;Protected (Join-Path $p 'qa-inputs.json') $true
 if([IO.File]::ReadAllText((Join-Path $p 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'Private QA marker differs'}
 $c=Get-Content (Join-Path $p 'qa-inputs.json') -Raw|ConvertFrom-Json
 if($c.machine-ne$env:COMPUTERNAME-or$c.controllerSID-ne$identity.User.Value){throw 'Bound QA controller differs'};$canReport=$true
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha){throw 'Exact R7 daemon required'}
 $a=@(Get-NetAdapter -Physical|Where-Object {[string]$_.InterfaceGuid-eq$c.adapterGuid-and$_.MacAddress-eq$c.adapterMAC});if($a.Count-ne1-or$a[0].Status-ne'Up'){throw 'Bound physical QA adapter differs'}
 $r.guid=[string]$a[0].InterfaceGuid;$r.mac=$a[0].MacAddress;$r.interfaceIndex=$a[0].ifIndex
 $active=@(Get-NetIPAddress -PolicyStore ActiveStore -AddressFamily IPv4|Where-Object IPAddress -eq $address)
 $persistent=@(Get-NetIPAddress -PolicyStore PersistentStore -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $address)
 if($Mode-eq'add'){
  if((Test-Path $journalPath)-or$active.Count-or$persistent.Count){throw 'Existing overlap journal/IP refused'}
  $journal=[pscustomobject]@{machine=$env:COMPUTERNAME;controllerSID=$identity.User.Value;token=[Guid]::NewGuid().ToString('D');guid=$r.guid;mac=$r.mac;address=$address;prefix=25;skipAsSource=$true;policyStore='ActiveStore';phase='creating';createdUTC=[DateTime]::UtcNow.ToString('o')};Save-Journal
  New-NetIPAddress -InterfaceIndex $a[0].ifIndex -AddressFamily IPv4 -IPAddress $address -PrefixLength 25 -SkipAsSource $true -PolicyStore ActiveStore|Out-Null
  $found=@(Get-NetIPAddress -InterfaceIndex $a[0].ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore|Where-Object IPAddress -eq $address)
  if($found.Count-ne1-or$found[0].PrefixLength-ne25-or!$found[0].SkipAsSource-or$found[0].PrefixOrigin-ne'Manual'){throw 'Created IP identity/readback differs'}
  $journal.phase='active';Save-Journal;$r.created=$true
 }else{
  Protected $journalPath $true;$journal=Get-Content $journalPath -Raw|ConvertFrom-Json;$token=[Guid]::Empty
  if($journal.machine-ne$env:COMPUTERNAME-or$journal.controllerSID-ne$identity.User.Value-or$journal.guid-ne$r.guid-or$journal.mac-ne$r.mac-or$journal.address-ne$address-or$journal.prefix-ne25-or!$journal.skipAsSource-or$journal.policyStore-ne'ActiveStore'-or$journal.phase-notin@('creating','active','removed')-or![Guid]::TryParse($journal.token,[ref]$token)-or$token-eq[Guid]::Empty){throw 'Foreign overlap ownership journal'}
  if($persistent.Count){throw 'Persistent foreign IP prevents removal'}
  if($active.Count){if($active.Count-ne1-or$active[0].InterfaceIndex-ne$a[0].ifIndex-or$active[0].PrefixLength-ne25-or!$active[0].SkipAsSource-or$active[0].PrefixOrigin-ne'Manual'){throw 'Foreign IP change prevents removal'};$active[0]|Remove-NetIPAddress -Confirm:$false}
  if(@(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore|Where-Object IPAddress -eq $address).Count){throw 'IP removal not confirmed'}
  $journal.phase='removed';Save-Journal;$r.removed=$true
 }
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{if($canReport){$out=Join-Path $q ('reports\r7-overlap-'+$Mode+'-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json');$f=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$bytes=[Text.Encoding]::UTF8.GetBytes(($r|ConvertTo-Json));$f.Write($bytes,0,$bytes.Length)}finally{$f.Dispose()}}}
$r|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
