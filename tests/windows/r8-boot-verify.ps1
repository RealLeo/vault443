# Ordinary verification only: no service start, connect, network or account mutation.
param([ValidateSet('boot1','boot2')][string]$Label='boot1')
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$x='C:\Users\Public\Vault443Exchange';$q='C:\Program Files\Vault443QA'
$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$r=[ordered]@{phase=$Label;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;checks=@();errorType=$null;errorLine=0;noConnectOrServiceStart=$true}
try{
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne'4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'){throw 'Exact R8 required'}
 # Windows may renumber ifIndex on reboot. Rebind only QA metadata using the
 # protected successful pre-SCM identity; retain the original positive-control
 # time and require identical address bytes (link-local scope follows ifIndex).
 $proof=Get-Content "$q\reports\r8-boot\result.json" -Raw|ConvertFrom-Json
 $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
 if(!$proof.passed-or!$proof.restored-or$proof.matrixChecks-ne13-or
    ($Label-eq'boot1'-and$boot-ne[DateTime]::Parse($proof.bootUTC).ToUniversalTime())-or
    ($Label-eq'boot2'-and$boot-le[DateTime]::Parse($proof.bootUTC).ToUniversalTime())){throw 'Successful corresponding pre-SCM boot identity required'}
 $a=@(Get-NetAdapter -Physical|Where-Object {[Guid]$_.InterfaceGuid-eq[Guid]$proof.physical.guid-and$_.MacAddress-eq$proof.physical.mac})
 if($a.Count-ne1-or$a[0].Status-ne'Up'){throw 'Original physical GUID/MAC differs'}
 $cachePath="$x\r8-protocols\main\state.json";$cache=Get-Content $cachePath -Raw|ConvertFrom-Json
 $ips=@(Get-NetIPAddress -InterfaceIndex $a[0].ifIndex|Select-Object -ExpandProperty IPAddress|Sort-Object)
 $oldBytes=@($cache.baseline.addresses|ForEach-Object {($_-split'%')[0]}|Sort-Object)
 $newBytes=@($ips|ForEach-Object {($_-split'%')[0]}|Sort-Object)
 if(!$cache.baseline.utc-or($oldBytes-join',')-cne($newBytes-join',')){throw 'Original positive-control physical address bytes differ'}
 $r.baselineRebind=@{guid=[string]$a[0].InterfaceGuid;mac=$a[0].MacAddress;oldIndex=$cache.baseline.interfaceIndex;newIndex=$a[0].ifIndex;oldAddresses=$cache.baseline.addresses;newAddresses=$ips;positiveControlUTC=$cache.baseline.utc;newPositiveControlClaimed=$false}
 if($cache.baseline.interfaceIndex-ne$a[0].ifIndex-or($cache.baseline.addresses-join',')-cne($ips-join',')){
  Copy-Item $cachePath (Join-Path $x ('r8-'+$Label+'-original-baseline.json'))
  $cache.baseline.interfaceIndex=[int]$a[0].ifIndex;$cache.baseline.addresses=$ips
  $cache|ConvertTo-Json -Depth 8|Set-Content $cachePath -Encoding UTF8
 }
 $plan=@(
  @{file='main-matrix.ps1';arguments=('-Phase recovery -Protocol vless -OutputDirectory "'+$x+'\r8-protocols\main"')},
  @{file='work-smoke.ps1';arguments='-Profile wireguard-multi -Phase verify -WaitSeconds 45'},
  @{file='work-smoke.ps1';arguments='-Profile amneziawg -Phase verify -WaitSeconds 45'},
  @{file='openvpn-smoke.ps1';arguments='-Phase verify -WaitSeconds 45'}
 )
 foreach($step in $plan){
  $start=[DateTime]::UtcNow;$p=Start-Process $ps -WindowStyle Hidden -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "'+$q+'\'+$step.file+'" '+$step.arguments) -PassThru -Wait
  $r.checks+=@{helper=$step.file;arguments=$step.arguments;startedUTC=$start.ToString('o');finishedUTC=[DateTime]::UtcNow.ToString('o');exit=$p.ExitCode}
  if($p.ExitCode){throw 'Native traffic helper failed'}
 }
 $s='[]'|& 'C:\Program Files\Vault443\vault443-cli.exe' GetSnapshot|ConvertFrom-Json
 $r.snapshot=@{main=$s.runtime.state;guard=$s.runtime.guardArmed;mainID=$s.activeProfileId;bootID=$s.bootProfileId;work=@($s.workProfiles|Select-Object id,@{n='state';e={$_.runtime.state}})}
 $r.gui=@(Get-Process vault443 -ErrorAction SilentlyContinue|Select-Object Id,SessionId,Path,StartTime)
 $r.bootUTC=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
 $r.passed=$s.runtime.state-eq'connected'-and$s.runtime.guardArmed-and$s.activeProfileId-eq$s.bootProfileId-and@($r.gui).Count-eq1
 if(!$r.passed){throw 'Automatic main/GUI startup differs'}
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');$r|ConvertTo-Json -Depth 6|Set-Content (Join-Path $x ('r8-'+$Label+'-verify.json')) -Encoding UTF8}
if(!$r.passed){exit 1}
