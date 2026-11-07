# Explicit same-controller UAC READ-ONLY diagnostic. It never calls Crash/Kill,
# changes a task, starts/stops a process, writes app stores, or mutates networking.
#Requires -RunAsAdministrator
param([ValidateSet('xray','outline','wireguard','amneziawg','openvpn')][string]$Selector='openvpn')
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$root='C:\Program Files\Vault443QA';$private='C:\ProgramData\Vault443-QA';$app='C:\Program Files\Vault443';$runner=Join-Path $root 'qa-runner.ps1'
$expectedRunner='733f8c2c8bbd59d49e14caab009c1e7750e66909e65b84c4466a2238298a7f1b'
$r=[ordered]@{schema=1;readOnly=$true;selector=$Selector;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;stage='preflight';exceptionType=$null;reason=$null;owner=$null;images=@();process=$null}
$allowedReasons=@('Bound active-console QA controller required','Bound controller has no private application UID','The bound controller must own the requested main VPN','Requested main profile identity is ambiguous','Requested main family does not match the fixed engine selector','Requested work profile identity is ambiguous','One unambiguous caller-owned requested work family required','QA input is a reparse point','QA input has an untrusted owner','QA input permits untrusted access','Invalid bounded engine ownership state','Pinned candidate manifest differs','Pinned candidate image differs','No unique daemon-owned fixed engine','Same PID creation identity differs','Private engine owner changed')
try{
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$computer=Get-CimInstance Win32_ComputerSystem
 if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$computer.Model-ne'VirtualBox'-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value){throw 'Bound active-console QA controller required'}
 if((Get-FileHash -LiteralPath $runner).Hash.ToLowerInvariant()-ne$expectedRunner){throw 'Protected QA runner identity differs'}
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Protected QA runner parser failed'}
 # Execute only these exact, pinned, read-only function definitions. The runner
 # top-level switch and Crash-FixedEngine definition are deliberately excluded.
 foreach($name in @('Protected','Engine-PrivateJSON','Engine-Owner','Daemon')){
  $nodes=@($ast.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-eq$name},$true))
  if($nodes.Count-ne1){throw 'Read-only function identity differs'}
  . ([scriptblock]::Create($nodes[0].Extent.Text))
 }
 $r.stage='qa-inputs';Protected $root $false;Protected $private $true;Protected (Join-Path $private 'qa-inputs.json') $true
 $config=Get-Content (Join-Path $private 'qa-inputs.json') -Raw|ConvertFrom-Json
 if($config.machine-ne$env:COMPUTERNAME-or$config.controllerSID-ne$identity.User.Value){throw 'Bound active-console QA controller required'}
 $r.stage='candidate-pins';$pins=$config.engineFaults;$relative=switch($Selector){'xray'{'xray.exe'}'outline'{'vault443-outline.exe'}'wireguard'{'vault443-tunnel.exe'}'amneziawg'{'vault443-tunnel.exe'}'openvpn'{'openvpn/openvpn.exe'}}
 $manifestPath=Join-Path $app 'build-manifest.json';Protected $app $false;Protected $manifestPath $false
 if(!$pins-or$pins.schema-ne1-or(Get-FileHash $manifestPath).Hash.ToLowerInvariant()-ne$pins.manifestSha256){throw 'Pinned candidate manifest differs'}
 $manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
 foreach($name in @('vault443d.exe',$relative)){
  $r.stage='image-'+$name;$hash=[string]$pins.images.PSObject.Properties[$name].Value;$file=Join-Path $app ($name-replace'/','\');Protected (Split-Path -Parent $file) $false;Protected $file $false
  $matches=$hash-match'^[a-f0-9]{64}$'-and[string]$manifest.files.PSObject.Properties[$name].Value.sha256-eq$hash-and(Get-FileHash $file).Hash.ToLowerInvariant()-eq$hash
  $r.images+=@{name=$name;matches=$matches};if(!$matches){throw 'Pinned candidate image differs'}
 }
 $r.stage='private-owner';$owner=Engine-Owner $Selector;$r.owner=@{profileID=[string]$owner.profileID;family=[string]$owner.family;uid=[uint32]$owner.uid}
 $r.stage='daemon';$daemon=Daemon
 try{
  $path=Join-Path $app ($relative-replace'/','\');$r.stage='unique-child';$children=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId='+$daemon.Id)|Where-Object ExecutablePath -eq $path)
  if($children.Count-ne1){throw 'No unique daemon-owned fixed engine'}
  $engine=[Diagnostics.Process]::GetProcessById([int]$children[0].ProcessId)
  try{
   [void]$engine.Handle;$created=$engine.StartTime.ToUniversalTime();$current=Get-CimInstance Win32_Process -Filter ('ProcessId='+$engine.Id);$service=Get-CimInstance Win32_Service -Filter "Name='Vault443'"
   $r.stage='second-private-owner';$again=Engine-Owner $Selector
   if($again.profileID-ne$owner.profileID-or$again.family-ne$owner.family-or$again.uid-ne$owner.uid){throw 'Private engine owner changed'}
   $cimTicks=if($current.CreationDate){$current.CreationDate.ToUniversalTime().Ticks}else{0L};$nativeTicks=$created.Ticks
   $sameCreation=($cimTicks-($cimTicks%10))-eq($nativeTicks-($nativeTicks%10))
   $r.process=@{daemonPID=$daemon.Id;enginePID=$engine.Id;engineHasExited=$engine.HasExited;daemonHasExited=$daemon.HasExited;servicePIDMatches=($service.ProcessId-eq$daemon.Id);parentMatches=($current.ParentProcessId-eq$daemon.Id);cimPathMatches=($current.ExecutablePath-eq$path);nativePathMatches=($engine.MainModule.FileName-eq$path);cimCreatedUTC=if($current.CreationDate){$current.CreationDate.ToUniversalTime().ToString('o')}else{$null};nativeCreatedUTC=$created.ToString('o');creationTickDifference=($nativeTicks-$cimTicks);sameCreation=$sameCreation;createdAfterDaemon=($created-ge$daemon.StartTime.ToUniversalTime())}
   $r.stage='pid-creation-ancestry'
   if($engine.HasExited-or$daemon.HasExited-or$service.ProcessId-ne$daemon.Id-or$current.ParentProcessId-ne$daemon.Id-or$current.ExecutablePath-ne$path-or$engine.MainModule.FileName-ne$path-or!$current.CreationDate-or!$sameCreation-or$created-lt$daemon.StartTime.ToUniversalTime()){throw 'Same PID creation identity differs'}
   $r.stage='all-readonly-checks-passed';$r.passed=$true
  }finally{$engine.Dispose()}
 }finally{$daemon.Dispose()}
}catch{$r.exceptionType=$_.Exception.GetType().FullName;$message=[string]$_.Exception.Message;$r.reason=if($message-in$allowedReasons){$message}else{'Non-allowlisted error text omitted'}}
finally{
 $r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');$out=Join-Path $root ('reports\r8-engine-selector-diagnostic-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json');$bytes=[Text.Encoding]::UTF8.GetBytes(($r|ConvertTo-Json -Depth 8));$f=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length)}finally{$f.Dispose()}
}
@{passed=$r.passed;stage=$r.stage;report=$out}|ConvertTo-Json -Compress
if(!$r.passed){exit 1}
