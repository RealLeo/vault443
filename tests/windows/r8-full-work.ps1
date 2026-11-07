param([ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedBackendSha256='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50')
# Temporary R8 acceptance controller. Ordinary ACTIVE console user only.
# Existing helpers validate real traffic. No privileged faults or fixture changes.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$qa='C:\Program Files\Vault443QA'
$exchange='C:\Users\Public\Vault443Exchange'
$directory=Join-Path $exchange 'r8-outputs\full-work'
$mainResults=Join-Path $exchange 'r8-protocols\main'
$cli='C:\Program Files\Vault443\vault443-cli.exe'
$powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$expected=$ExpectedBackendSha256
$result=[ordered]@{schema=1;startedUtc=[DateTime]::UtcNow.ToString('o');daemonSha256=$expected;completed=$false;passed=$false;restored=$false;initial=$null;steps=@();errorType=$null;errorLine=0}
$changed=$false;$mainID='';$multiID='';$openID='';$awgID=''
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$reportPath=Join-Path $directory 'result.json'
function Save {$script:result|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $reportPath -Encoding UTF8}
function Invoke-Child([string]$Program,[string]$Arguments,[string]$InputText,[int]$Seconds) {
 $start=New-Object Diagnostics.ProcessStartInfo
 $start.FileName=$Program;$start.Arguments=$Arguments;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
 $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $child=New-Object Diagnostics.Process;$child.StartInfo=$start
 try {
  [void]$child.Start();$output=$child.StandardOutput.ReadToEndAsync();$errors=$child.StandardError.ReadToEndAsync()
  if($null-ne$InputText){$child.StandardInput.WriteLine($InputText)};$child.StandardInput.Close()
  if(!$child.WaitForExit($Seconds*1000)){$child.Kill();[void]$child.WaitForExit(2000);throw 'QA child deadline exceeded'}
  $text=$output.GetAwaiter().GetResult();[void]$errors.GetAwaiter().GetResult()
  if($child.ExitCode-ne0){throw 'QA child failed; raw output intentionally omitted'}
  return $text
 }finally{$child.Dispose()}
}
function RPC([string]$Method,[object[]]$Parameters=@()) {
 $text=Invoke-Child $cli $Method (ConvertTo-Json -InputObject $Parameters -Compress -Depth 8) 8
 if($text){return($text|ConvertFrom-Json)}
}
function Snapshot {RPC GetSnapshot}
function Projection($s) {
 return @{mainID=$s.activeProfileId;mainState=$s.runtime.state;mainStage=$s.runtime.stage;guardArmed=$s.runtime.guardArmed;
  work=@($s.workProfiles|ForEach-Object {@{id=$_.id;name=$_.name;state=$_.runtime.state;stage=$_.runtime.stage}})}
}
function Own($s,[string]$Name) {
 $items=@($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$Name))
 if($items.Count-ne1){throw 'Expected exactly one own fixture profile'};return $items[0]
}
function Wait-Work([string]$ID,[string]$State,[int]$Seconds=60) {
 $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
 do {$s=Snapshot;$p=@($s.workProfiles|Where-Object id -eq $ID)
  if($p.Count-eq1-and$p[0].runtime.state-eq$State){return $s}
  Start-Sleep -Milliseconds 400
 }while([DateTime]::UtcNow-lt$deadline)
 throw 'Work state deadline exceeded'
}
function Wait-Main([string]$State,[int]$Seconds=60) {
 $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
 do {$s=Snapshot
  if($s.activeProfileId-eq$script:mainID-and$s.runtime.state-eq$State-and$s.runtime.guardArmed){return $s}
  Start-Sleep -Milliseconds 400
 }while([DateTime]::UtcNow-lt$deadline)
 throw 'Main state/guard deadline exceeded'
}
function Helper([string]$File,[string]$Arguments,[int]$Seconds=120) {
 [void](Invoke-Child $powershell ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $qa $File)+'" '+$Arguments) $null $Seconds)
}
function Step([string]$Name,[scriptblock]$Action) {
 $step=[ordered]@{name=$Name;startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null;passed=$false;state=$null;errorType=$null;errorLine=0}
 try {& $Action;$step.state=Projection (Snapshot);$step.passed=$true}
 catch {$step.errorType=$_.Exception.GetType().FullName;$step.errorLine=$_.InvocationInfo.ScriptLineNumber;throw}
 finally {$step.finishedUtc=[DateTime]::UtcNow.ToString('o');$script:result.steps+=,$step;Save}
}
try {
 Step 'preflight' {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  if(([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ordinary console token required'}
  $machine=Get-CimInstance Win32_ComputerSystem
  if($machine.Name-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$machine.Model-notmatch'^VirtualBox$'){throw 'Named isolated VirtualBox required'}
  if(!('Vault443FullConsole' -as [type])){Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class Vault443FullConsole { [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId(); }'}
  if([Diagnostics.Process]::GetCurrentProcess().SessionId-ne[Vault443FullConsole]::WTSGetActiveConsoleSessionId()){throw 'Active console session required'}
  if((Get-FileHash -LiteralPath 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$expected){throw 'Exact R8 daemon required'}
  foreach($file in @('work-smoke.ps1','openvpn-smoke.ps1','main-matrix.ps1')){if(!(Test-Path -LiteralPath (Join-Path $qa $file) -PathType Leaf)){throw 'Existing protected QA helper missing'}}
  foreach($file in @('wireguard-full-import.json','openvpn-full-import.json')){if(!(Test-Path -LiteralPath (Join-Path $exchange $file) -PathType Leaf)){throw 'Existing full fixture import missing; copy it from isolated fixture first'}}
  $mainState=Get-Content -LiteralPath (Join-Path $mainResults 'state.json') -Raw|ConvertFrom-Json
  $s=Snapshot;$p=@($s.profiles|Where-Object id -eq $s.activeProfileId)
  if($s.canAdmin-or$s.busyByOtherUser-or$p.Count-ne1-or$p[0].kind-ne'vless'-or$s.runtime.state-ne'connected'-or!$s.runtime.guardArmed-or$s.activeProfileId-ne$mainState.profiles.vless){throw 'Current R8 VLESS owner precondition failed'}
  $script:mainID=[string]$s.activeProfileId
  $multi=Own $s 'wireguard-multi';$open=Own $s 'openvpn';$awg=Own $s 'amneziawg'
  foreach($w in @($multi,$open,$awg)){if($w.runtime.state-ne'connected'){throw 'Initial three work VPNs must be connected'}}
  if(@($s.workProfiles|Where-Object {$_.runtime.state-ne'disconnected'}).Count-ne3){throw 'Unexpected overlapping requested work profile'}
  $script:multiID=[string]$multi.id;$script:openID=[string]$open.id;$script:awgID=[string]$awg.id
  $script:result.initial=Projection $s
 }
 $changed=$true
 Step 'wg-multi-disconnect' {[void](RPC RequestWorkDisconnect @($multiID));[void](Wait-Work $multiID 'disconnected')}
 Step 'wg-full-connect-verify-pause' {
  Helper 'work-smoke.ps1' '-Profile wireguard-full -Phase begin'
  Helper 'work-smoke.ps1' '-Profile wireguard-full -Phase verify -WaitSeconds 45'
  [void](Wait-Main 'paused_external' 20)
 }
 Step 'wg-full-disconnect-main-resume' {
  $full=Own (Snapshot) 'wireguard-full';[void](RPC RequestWorkDisconnect @($full.id));[void](Wait-Work $full.id 'disconnected')
  [void](Wait-Main 'connected')
  Helper 'main-matrix.ps1' ('-Phase verify -Protocol vless -OutputDirectory "'+$mainResults+'"')
 }
 Step 'wg-multi-restore' {[void](RPC RequestWorkConnect @($multiID));[void](Wait-Work $multiID 'connected')}
 Step 'openvpn-split-disconnect' {[void](RPC RequestWorkDisconnect @($openID));[void](Wait-Work $openID 'disconnected')}
 Step 'openvpn-full-connect-verify-pause' {
  Helper 'openvpn-smoke.ps1' '-Profile openvpn-full -Phase begin'
  Helper 'openvpn-smoke.ps1' '-Profile openvpn-full -Phase verify -WaitSeconds 45'
  [void](Wait-Main 'paused_external' 20)
 }
 Step 'openvpn-full-disconnect-main-resume' {
  $full=Own (Snapshot) 'openvpn-full';[void](RPC RequestWorkDisconnect @($full.id));[void](Wait-Work $full.id 'disconnected')
  [void](Wait-Main 'connected')
  Helper 'main-matrix.ps1' ('-Phase verify -Protocol vless -OutputDirectory "'+$mainResults+'"')
 }
 $result.passed=$true
}catch{$result.errorType=$_.Exception.GetType().FullName;$result.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally {
 if($changed){
  try {
   Step 'finally-stop-only-full-fixtures' {
    $s=Snapshot;$stopFailed=$false
    foreach($name in @('wireguard-full','openvpn-full')){
     foreach($p in @($s.workProfiles|Where-Object name -eq ('Vault443 Fixture '+$name))){
      try{[void](RPC RequestWorkDisconnect @($p.id));[void](Wait-Work $p.id 'disconnected')}catch{$stopFailed=$true}
     }
    }
    if($stopFailed){throw 'A full fixture could not be stopped'}
   }
  }catch{$result.passed=$false}
  try {
   Step 'finally-restore-initial-connections' {
    $s=Snapshot
    if(@($s.workProfiles|Where-Object {$_.name-in@('Vault443 Fixture wireguard-full','Vault443 Fixture openvpn-full')-and$_.runtime.state-ne'disconnected'}).Count){throw 'Refusing shared-key overlap while a full fixture remains requested'}
    foreach($id in @($multiID,$openID)){[void](RPC RequestWorkConnect @($id))}
    foreach($id in @($multiID,$openID,$awgID)){[void](Wait-Work $id 'connected')}
    [void](Wait-Main 'connected')
   }
   $result.restored=$true
  }catch{$result.passed=$false}
 }
 $result.completed=$true;$result.finishedUtc=[DateTime]::UtcNow.ToString('o');Save
}
@{passed=$result.passed;restored=$result.restored;report=$reportPath}|ConvertTo-Json -Compress
if(!$result.passed){exit 1}
