# Fixed SYSTEM pre-service acceptance wrapper; no arguments or public input.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$qa='C:\Program Files\Vault443QA';$private='C:\ProgramData\Vault443-QA\r8-boot'
$taskName='Vault443-QA-r8-prescm';$wrapper=Join-Path $qa 'r8-boot\startup.ps1'
$matrix=Join-Path $private 'matrix';$reportPath=Join-Path $qa 'reports\r8-boot\result.json'
$daemonSHA='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'
$matrixSHA='fc633896542f0e00fa452fca180c5dc473339b2309779b0def2dedf398e999e8'
$manifestSHA=$null
$report=[ordered]@{schema=1;startedUtc=[DateTime]::UtcNow.ToString('o');task=$taskName;ownerToken=$null;bootUTC=$null;passed=$false;inconclusive=$false;restored=$false;taskRemoved=$false;facts=@();matrixReport=$null;matrixChecks=0;errorType=$null;errorLine=0;restoreErrorType=$null;limits=@('Proves persistent policy after reboot before Vault443; does not isolate pre-BFE boot-time filter execution.','Shipping automatic startup requires a separate normal reboot.')}
$journal=$null;$owned=$false;$child=$null
function Protected([string]$Path,[bool]$PrivatePath) {
 $i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse QA path'}
 $a=Get-Acl -LiteralPath $Path;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')){throw 'Untrusted QA owner'}
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if($null-eq$raw.DiscretionaryAcl){throw 'Null DACL'}
 $mask=0x500D0156;if($PrivatePath){$mask=$mask-bor0x80000021}
 foreach($r in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($r.AccessControlType-eq'Allow'-and!($r.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$r.IdentityReference.Value-notin@('S-1-5-18','S-1-5-32-544')-and([long]$r.FileSystemRights-band$mask)){throw 'Untrusted QA access'}}
}
function Task-Owned {
 $task=$script:scheduler.GetFolder('\').GetTask($taskName);$d=$task.Definition
 $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$wrapper+'"'
 if($d.RegistrationInfo.Description-ne('Vault443 R8 pre-SCM '+$journal.token)-or$d.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$d.Actions.Count-ne1-or$d.Actions.Item(1).Path-ne(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')-or$d.Actions.Item(1).Arguments-ne$args){throw 'Foreign task identity'}
 return $task
}
function No-Service {
 $s=Get-CimInstance Win32_Service -Filter "Name='Vault443'"
 $engines=@(Get-CimInstance Win32_Process -Filter "Name='vault443d.exe' OR Name='xray.exe' OR Name='vault443-tunnel.exe' OR Name='openvpn.exe'")
 $f=@{utc=[DateTime]::UtcNow.ToString('o');service=$s.State;daemonPID=[int]$s.ProcessId;engines=@($engines|ForEach-Object {@{name=$_.Name;pid=[int]$_.ProcessId;parentPID=[int]$_.ParentProcessId}});bfe=[string](Get-Service BFE).Status}
 $script:report.facts+=,$f
 if($s.State-ne'Stopped'-or$s.ProcessId-ne0-or$engines.Count){$script:report.inconclusive=$true;throw 'Pre-service window was lost'}
}
function Restore-Service {
 $identity=Get-CimInstance Win32_Service -Filter "Name='Vault443'"
 if($identity.StartName-ne'LocalSystem'-or$identity.PathName.Trim('"')-ne'C:\Program Files\Vault443\vault443d.exe'){throw 'Refusing foreign SCM identity during restore'}
 $start=if($journal.delayed-eq1){'delayed-auto'}else{'auto'}
 & "$env:SystemRoot\System32\sc.exe" config Vault443 start= $start |Out-Null;if($LASTEXITCODE){throw 'SCM restoration failed'}
 $now=Get-CimInstance Win32_Service -Filter "Name='Vault443'";$d=Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Vault443' DelayedAutoStart -ErrorAction SilentlyContinue
 if($now.StartMode-ne'Auto'-or[int]$d-ne[int]$journal.delayed){throw 'SCM restoration readback differs'}
 $s=Get-Service Vault443;try{if($s.Status-eq'Stopped'){$s.Start()};$s.WaitForStatus('Running',[TimeSpan]::FromSeconds(40))}finally{$s.Dispose()}
 $script:report.restored=$true
}
try {
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value-ne'S-1-5-18'-or$env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or(Get-CimInstance Win32_ComputerSystem).Model-notmatch'^VirtualBox$'){throw 'Named SYSTEM QA task required'}
 foreach($p in @('C:\ProgramData\Vault443-QA',$private,(Join-Path $private 'journal.json'))){Protected $p $true}
 Protected 'C:\ProgramData\Vault443-QA\marker' $true
 if([IO.File]::ReadAllText('C:\ProgramData\Vault443-QA\marker').Trim()-ne'Vault443 isolated Windows fixture'){throw 'QA marker missing'}
 $journal=Get-Content (Join-Path $private 'journal.json') -Raw|ConvertFrom-Json
 $token=[Guid]::Empty
 if($journal.machine-ne$env:COMPUTERNAME-or$journal.startMode-ne'Auto'-or$journal.delayed-notin@(0,1)-or![Guid]::TryParse([string]$journal.token,[ref]$token)-or$token-eq[Guid]::Empty-or$journal.controllerSID-notmatch'^S-1-5-21-[0-9-]+$'-or$journal.mainID-notmatch'^[a-f0-9]{32}$'-or$journal.wrapperSHA-notmatch'^[a-f0-9]{64}$'-or$journal.manifestSHA-notmatch'^[a-f0-9]{64}$'-or$journal.daemonSHA-ne$daemonSHA){throw 'Invalid owned boot journal'}
 $manifestSHA=[string]$journal.manifestSHA
 $script:scheduler=New-Object -ComObject Schedule.Service;$script:scheduler.Connect();[void](Task-Owned)
 $owned=$true;$report.ownerToken=$journal.token
 foreach($p in @($qa,(Join-Path $qa 'r8-boot'),$wrapper,(Join-Path $qa 'main-matrix.ps1'),(Join-Path $qa 'reports'),(Join-Path $qa 'reports\r8-boot'))){Protected $p ($p-like'*\r8-boot\startup.ps1'-or$p-eq(Join-Path $qa 'r8-boot'))}
 if((Get-FileHash $wrapper).Hash.ToLowerInvariant()-ne$journal.wrapperSHA-or(Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne$daemonSHA-or(Get-FileHash 'C:\Program Files\Vault443\build-manifest.json').Hash.ToLowerInvariant()-ne$manifestSHA-or(Get-FileHash (Join-Path $qa 'main-matrix.ps1')).Hash.ToLowerInvariant()-ne$matrixSHA){throw 'Pinned source/runtime identity differs'}
 $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime();$report.bootUTC=$boot.ToString('o')
 if($boot-le[DateTime]::Parse($journal.preBootUTC).ToUniversalTime()-or$boot-le[DateTime]::Parse($journal.armedUTC).ToUniversalTime()){$report.inconclusive=$true;throw 'A real new reboot is required'}
 $events=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';StartTime=$boot;Id=@(7036,7031,7034,7023,7024)} -ErrorAction SilentlyContinue|Where-Object {@(([xml]$_.ToXml()).Event.EventData.Data|ForEach-Object {$_.InnerText})-contains'Vault443'-or@(([xml]$_.ToXml()).Event.EventData.Data|ForEach-Object {$_.InnerText})-contains'Vault 443 VPN'})
 if($events.Count){$report.inconclusive=$true;throw 'Earlier Vault443 SCM activity this boot'}
 $deadline=[DateTime]::UtcNow.AddSeconds(60);$ready=$false
 do {
  No-Service
  $a=@(Get-NetAdapter -Physical|Where-Object {[string]$_.InterfaceGuid-eq$journal.adapterGUID-and$_.MacAddress-eq$journal.adapterMAC})
  if($a.Count-ne1){throw 'Bound physical QA adapter changed'}
  $ips=@(Get-NetIPAddress -InterfaceIndex $a[0].ifIndex);$addresses=@($ips|ForEach-Object {$_.IPAddress}|Sort-Object)
  $gateway4=@(Get-NetRoute -InterfaceIndex $a[0].ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Where-Object NextHop -eq '192.0.2.1')
  $gateway6=@(Get-NetRoute -InterfaceIndex $a[0].ifIndex -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue|Where-Object NextHop -eq '2001:db8:44::1')
  $addressIdentity=@($addresses|ForEach-Object {$_ -replace '%[0-9]+$',''}|Sort-Object)
  $expectedIdentity=@($journal.addresses|ForEach-Object {$_ -replace '%[0-9]+$',''}|Sort-Object)
  $ready=$gateway4.Count-gt0-and$gateway6.Count-gt0-and(Get-Service BFE).Status-eq'Running'-and$a[0].Status-eq'Up'-and!@($ips|Where-Object AddressState -ne 'Preferred').Count-and($addressIdentity-join',')-eq($expectedIdentity-join',')
  if(!$ready){Start-Sleep -Milliseconds 400}
 }while(!$ready-and[DateTime]::UtcNow-lt$deadline)
 if(!$ready){$report.inconclusive=$true;throw 'BFE/physical baseline was not ready'}
 $report.physical=@{physicalDefaultIPv4=$true;physicalDefaultIPv6=$true;guid=$journal.adapterGUID;mac=$journal.adapterMAC;index=$a[0].ifIndex;addresses=$addresses;link=[string]$a[0].Status;bfe=[string](Get-Service BFE).Status}
 $state=@{profiles=@{vless=$journal.mainID};baseline=@{interfaceIndex=$a[0].ifIndex;addresses=$addresses;utc=$journal.armedUTC}}
 [IO.File]::WriteAllText((Join-Path $matrix 'state.json'),($state|ConvertTo-Json -Depth 5))
 No-Service
 $probeUTC=[DateTime]::UtcNow
 $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $start.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $qa 'main-matrix.ps1')+'" -Phase protection -Protocol vless -Fault service-killed -PhysicalInterfaceIndex '+$a[0].ifIndex+' -OutputDirectory "'+$matrix+'"'
 $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $child=New-Object Diagnostics.Process;$child.StartInfo=$start;[void]$child.Start();$out=$child.StandardOutput.ReadToEndAsync();$err=$child.StandardError.ReadToEndAsync();$deadline=[DateTime]::UtcNow.AddSeconds(120)
 do{No-Service;$done=$child.WaitForExit(250);if([DateTime]::UtcNow-gt$deadline){throw 'Protection helper deadline'}}while(!$done)
 No-Service;[void]$out.GetAwaiter().GetResult();[void]$err.GetAwaiter().GetResult();if($child.ExitCode-ne0){throw 'Existing protection helper failed'}
 $file=Get-ChildItem $matrix -Filter '*-protection-vless.json'|Where-Object {$_.LastWriteTimeUtc-ge$probeUTC}|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1
 if(!$file){throw 'Fresh protection report absent'}
 $answer=Get-Content $file.FullName -Raw|ConvertFrom-Json;$report.matrixReport=$file.FullName;$report.matrixChecks=$answer.checks.Count;$report.checks=$answer.checks
 if(!$answer.completed-or!$answer.passed-or$answer.checks.Count-ne13){throw 'Fresh 13-check proof failed'}
 $report.passed=$true
}catch{$report.errorType=$_.Exception.GetType().FullName;$report.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally {
 if($child){try{if(!$child.HasExited){$child.Kill();[void]$child.WaitForExit(2000)}}catch{};$child.Dispose()}
 if($owned){
  try{Restore-Service;[void](Task-Owned);$scheduler.GetFolder('\').DeleteTask($taskName,0);$report.taskRemoved=$true}catch{$report.passed=$false;$report.restoreErrorType=$_.Exception.GetType().FullName}
  $report.finishedUtc=[DateTime]::UtcNow.ToString('o');[IO.File]::WriteAllText($reportPath,($report|ConvertTo-Json -Depth 12))
 }
}
if(!$report.passed-or!$report.restored){exit 1}
