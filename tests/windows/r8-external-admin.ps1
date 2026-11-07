#Requires -RunAsAdministrator
param([ValidateSet('dual','v6only','cleanup')][string]$Mode='dual', [string]$ProfilePath=(Join-Path $env:LOCALAPPDATA 'Vault443\qa-ui-import\fixture-openvpn.ovpn'))
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$q='C:\Program Files\Vault443QA';$x='C:\Users\Public\Vault443Exchange';$setup=Join-Path $x 'external-setup.ps1';$cli='C:\Program Files\Vault443\vault443-cli.exe';$name='CorpExternalOpenVPNFixture'
$sha='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'
$r=[ordered]@{mode=$Mode;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;errorType=$null;errorLine=0;adapter=$null;main=$null;external=$null;routes6=@()}
function Binding([bool]$Remove){$b=if($Remove){'{"interface":"corp-external","remove":true}'}else{'{"interface":"corp-external","manager":"openvpn","unit":"CorpExternalOpenVPNFixture","routes":["10.77.8.0/24","fd77:443:8::/64"],"dnsServers":["10.77.0.1"],"dnsDomains":["corp.openvpn.test"],"endpoints":[{"address":"192.0.2.1","port":1194,"protocol":"udp"}]}'};ConvertTo-Json -InputObject @($b) -Compress|& $cli SetVPNBinding|Out-Null;if($LASTEXITCODE){throw 'Binding RPC failed'}}
function OwnService { $v=Get-CimInstance Win32_Service|Where-Object Name -eq $name;if(!$v-or$v.StartName-ne'LocalSystem'-or$v.PathName.Trim('"')-ne'C:\Program Files\Vault443ExternalFixture\vault443-external-openvpn.exe'){throw 'Exact fixture SCM ownership required'};if((Get-FileHash -LiteralPath ($v.PathName.Trim('"'))).Hash.ToLowerInvariant()-ne'b9237d65249bbc5b23b2d98d95e1b75af857940b5b98dfbaf236832244bca084'){throw 'Installed fixture image differs'};return $v }
try{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$machine=Get-CimInstance Win32_ComputerSystem
 if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$machine.Model-ne'VirtualBox'-or!$machine.UserName-or([Security.Principal.NTAccount]::new($machine.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$id.User.Value){throw 'Same active-console named VM controller UAC required'}
 $privateRoot='C:\ProgramData\Vault443-QA';if([IO.File]::ReadAllText((Join-Path $privateRoot 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'Private QA marker missing'}
 $qaInputs=Get-Content (Join-Path $privateRoot 'qa-inputs.json') -Raw|ConvertFrom-Json;if($qaInputs.machine-ne$env:COMPUTERNAME-or$qaInputs.controllerSID-ne$id.User.Value){throw 'Bound QA controller differs'}
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$sha){throw 'Exact R8 daemon required'}
 $ownSnapshot='[]'|& $cli GetSnapshot|ConvertFrom-Json;if($LASTEXITCODE-or$ownSnapshot.busyByOtherUser){throw 'Own RPC preflight failed'}
 if($Mode-ne'cleanup'-and@($ownSnapshot.workProfiles|Where-Object {$_.kind-eq'openvpn'-and$_.runtime.state-ne'disconnected'}).Count){throw 'Stop built-in OpenVPN profiles before external fixture; certificate is shared'}
 if((Get-FileHash $setup).Hash.ToLowerInvariant()-ne'0376db231c99a26f79c2a5dc7d0e117a595da25a8aa3b85078fbc3cd7c8d5ca5'){throw 'Setup hash mismatch'}
 if((Get-FileHash (Join-Path $x 'vault443-external-openvpn.exe')).Hash.ToLowerInvariant()-ne'b9237d65249bbc5b23b2d98d95e1b75af857940b5b98dfbaf236832244bca084'){throw 'Fixture PE hash mismatch'}
 if($Mode-eq'dual'){if(Get-Service $name -ErrorAction SilentlyContinue){throw 'Fresh dual setup refuses existing SCM service'};if([IO.Path]::GetFullPath($ProfilePath)-ne[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Vault443\qa-ui-import\fixture-openvpn.ovpn'))){throw 'Only the fixed private fixture profile is allowed'};$private=Get-Item -LiteralPath $ProfilePath;if($private.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Private fixture profile is a reparse point'};& $setup -FullTunnel -ProfilePath $ProfilePath|Out-Null}
 else{[void](OwnService);Stop-Service $name -ErrorAction Stop;Binding $true
  $end=[DateTime]::UtcNow.AddSeconds(15);do{$left=@(Get-NetAdapter -IncludeHidden -Name corp-external -ErrorAction SilentlyContinue);if(!$left.Count){break};Start-Sleep -Milliseconds 250}while([DateTime]::UtcNow-lt$end);if($left.Count){throw 'Exact corp-external adapter departure deadline'}
  if($Mode-eq'cleanup'){& $setup -Uninstall|Out-Null}
  else{$f='C:\ProgramData\Vault443ExternalFixture\client.ovpn';$raw=[IO.File]::ReadAllText($f);if([regex]::Matches($raw,'(?m)^redirect-gateway def1 ipv6\r?$').Count-ne1){throw 'Exact dual redirect fixture required'};$raw=[regex]::Replace($raw,'(?m)^redirect-gateway def1 ipv6\r?$','redirect-gateway ipv6 !ipv4');[IO.File]::WriteAllText($f,$raw,[Text.UTF8Encoding]::new($false))}
 }
 if($Mode-ne'cleanup'){
  [void](OwnService);Start-Service $name;$end=[DateTime]::UtcNow.AddSeconds(20)
  do{$a=@(Get-NetAdapter -IncludeHidden -Name corp-external -ErrorAction SilentlyContinue);if($a.Count-eq1){break};Start-Sleep -Milliseconds 250}while([DateTime]::UtcNow-lt$end)
  if($a.Count-ne1){throw 'No unique fixture adapter'};Binding $false
  $end=[DateTime]::UtcNow.AddSeconds(35)
  do{$ips=@(Get-NetIPAddress -InterfaceIndex $a[0].ifIndex -ErrorAction SilentlyContinue|Where-Object {$_.AddressState-eq'Preferred'});if(@($ips|Where-Object IPAddress -like 'fd77:443::*').Count){break};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow-lt$end)
  if(!@($ips|Where-Object IPAddress -like 'fd77:443::*').Count){throw 'Fixture IPv6 preferred address deadline'}
  $r.adapter=@{guid=[string]$a[0].InterfaceGuid;index=$a[0].ifIndex;addresses=@($ips|Select-Object IPAddress,AddressFamily,PrefixLength,AddressState)}
  $r.routes6=@(Get-NetRoute -InterfaceIndex $a[0].ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue|Select-Object DestinationPrefix,NextHop,RouteMetric)
 }
 $s='[]'|& $cli GetSnapshot|ConvertFrom-Json;$r.main=@{state=$s.runtime.state;stage=$s.runtime.stage;guard=$s.runtime.guardArmed;activeProfileID=$s.activeProfileId};$r.external='[]'|& $cli GetVPNCompatibility|ConvertFrom-Json
 $r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');$r|ConvertTo-Json -Depth 9|Set-Content (Join-Path $q ('reports\r8-external-'+$Mode+'.json')) -Encoding UTF8}

@{mode=$Mode;passed=$r.passed;report=(Join-Path $q ('reports\r8-external-'+$Mode+'.json'))}|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
