#Requires -RunAsAdministrator
# Read-only, fixed-interval diagnostics for the isolated R8 Windows shutdown fault.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$q='C:\Program Files\Vault443QA';$out=Join-Path $q 'reports\r8-shutdown-diagnostic.json'
if($env:COMPUTERNAME-ne'VAULT443-WIN11'-or(Get-CimInstance Win32_ComputerSystem).Model-ne'VirtualBox'){throw 'Named QA VM required'}
if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne'4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'){throw 'Exact R8 required'}
$r=[ordered]@{schema=1;readOnly=$true;machine=$env:COMPUTERNAME;utc=[DateTime]::UtcNow.ToString('o');bootUTC=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');service=Get-CimInstance Win32_Service -Filter "Name='Vault443'"|Select-Object Name,State,StartMode,ProcessId;events=@();serviceLog=@();diagnostics=@()}
$start=[DateTime]::Parse('2026-11-07T12:17:30Z').ToLocalTime();$end=[DateTime]::Parse('2026-11-07T12:31:30Z').ToLocalTime()
$providers=@('Service Control Manager','User32','EventLog','Microsoft-Windows-Kernel-General','Microsoft-Windows-Kernel-Power','Microsoft-Windows-Kernel-PnP')
foreach($e in @(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$start;EndTime=$end} -ErrorAction Stop|Where-Object {$_.ProviderName-in$providers})){
 $xml=[xml]$e.ToXml();$data=@($xml.Event.EventData.Data|ForEach-Object {@{name=[string]$_.Name;value=[string]$_.'#text'}})
 if($e.ProviderName-eq'Service Control Manager'-and($data.value-join' ')-notmatch'Vault443|Vault 443|VBox|VirtualBox|Base Filtering|\bBFE\b|Network Store|\bnsi\b'){continue}
 $r.events+=@{utc=$e.TimeCreated.ToUniversalTime().ToString('o');provider=$e.ProviderName;id=$e.Id;recordId=$e.RecordId;level=$e.Level;data=$data}
}
foreach($f in @('C:\ProgramData\Vault443\service.log.previous','C:\ProgramData\Vault443\service.log')){
 if(!(Test-Path $f)){continue}
 $entries=@();foreach($line in @(Get-Content $f -Tail 500)){
  if($line-notmatch'2026/11/07 12:(17|18|19|2[0-9]|30):'){continue}
  # Never export raw private log lines, profile URLs, configuration or credentials.
  $tags=@();foreach($tag in @('Windows work cleanup','run-cancelled','deadline exceeded','context canceled','FWP_E_IN_USE','panic','fatal','shutdown','stopped','started','ready','error')){if($line-match[regex]::Escape($tag)){$tags+=$tag}}
  if(!$tags.Count){continue};$stamp=[regex]::Match($line,'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?').Value
  $profile=[regex]::Match($line,'profile=([a-z0-9-]+)').Groups[1].Value;$stage=[regex]::Match($line,'stage=([a-z0-9-]+)').Groups[1].Value
  $entries+=@{time=$stamp;tags=$tags;profile=$profile;stage=$stage}
 };$r.serviceLog+=@{file=[IO.Path]::GetFileName($f);bytes=(Get-Item $f).Length;entries=$entries}
}
try{$log=Get-WinEvent -ListLog 'Microsoft-Windows-Diagnostics-Performance/Operational' -ErrorAction Stop;if($log.IsEnabled){$r.diagnostics=@(Get-WinEvent -FilterHashtable @{LogName=$log.LogName;StartTime=$start;EndTime=$end} -MaxEvents 30 -ErrorAction SilentlyContinue|ForEach-Object {@{utc=$_.TimeCreated.ToUniversalTime().ToString('o');id=$_.Id;xml=$_.ToXml()}})}}catch{$r.diagnosticsUnavailable=$true}
$r|ConvertTo-Json -Depth 8|Set-Content $out -Encoding UTF8
