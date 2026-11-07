#Requires -RunAsAdministrator
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$app='C:\Program Files\Vault443';$q='C:\Program Files\Vault443QA';$x='C:\Users\Public\Vault443Exchange';$out="$q\reports\r8-foreign-abort"
$private='C:\ProgramData\Vault443-QA';$canReport=$false
$r=[ordered]@{targetMachine='VAULT443-WIN11';expectedUninstallerExit=1;foreignRuleID='8CE0BA94-4F2C-469D-8EB8-58435F7F6223';completed=$false;startedUTC=[DateTime]::UtcNow.ToString('o');passed=$false;stage='preflight';checks=@()}
function Check([string]$Name,[bool]$Passed,$Observation=$null){$r.checks+=@{check=$Name;passed=$Passed;observation=$Observation};if(!$Passed){throw $Name}}
# QA/private paths remain SYSTEM/Administrators-owned and non-writable by
# ordinary accounts. Installed app ACLs are checked by installer-smoke instead.
function Protected([string]$Path,[bool]$PrivatePath){$i=Get-Item -LiteralPath $Path -Force;if($i.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse QA input'};$a=Get-Acl $Path;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')){throw 'Untrusted QA owner'};$raw=[Security.AccessControl.RawSecurityDescriptor]::new($a.GetSecurityDescriptorBinaryForm(),0);if($null-eq$raw.DiscretionaryAcl){throw 'Null QA DACL'};$mask=0x500D0156;if($PrivatePath){$mask=$mask-bor0x80000021};foreach($e in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and!($e.PropagationFlags-band[Security.AccessControl.PropagationFlags]::InheritOnly)-and$e.IdentityReference.Value-notin@('S-1-5-18','S-1-5-32-544')-and([long]$e.FileSystemRights-band$mask)){throw 'Untrusted QA permissions'}}}
function Exact-Reference{
 $path=Join-Path $private 'foreign-reference.json';Protected $path $true
 if((Get-Item $path).Length-gt8192){throw 'Oversized foreign ownership journal'}
 $ref=Get-Content $path -Raw|ConvertFrom-Json
 if($ref.version-ne1-or$ref.machine-ne$env:COMPUTERNAME-or$ref.controllerSID-ne$identity.User.Value-or[Guid]$ref.ruleId-ne$guid-or$ref.token-notmatch'^[a-f0-9]{32}$'-or$ref.name-ne('Vault443 QA foreign-reference '+$ref.token)){throw 'Exact Win11 foreign reference journal differs'}
}
function IDs{$v=@();foreach($name in @('state.json','work-vpn.json')){$s=Get-Content (Join-Path 'C:\ProgramData\Vault443' $name) -Raw|ConvertFrom-Json;foreach($u in $s.users.PSObject.Properties){foreach($p in $u.Value.profiles){$v+=($name+'/'+$u.Name+'/'+$p.id)}}};return @($v|Sort-Object)}
try{
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$computer=Get-CimInstance Win32_ComputerSystem
 if(!('Vault443R8ForeignConsole'-as[type])){Add-Type 'using System.Runtime.InteropServices; public static class Vault443R8ForeignConsole { [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId(); }'}
 if($env:COMPUTERNAME-ne'VAULT443-WIN11'-or$computer.Model-ne'VirtualBox'-or!$computer.UserName-or([Security.Principal.NTAccount]::new($computer.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$identity.User.Value-or[Diagnostics.Process]::GetCurrentProcess().SessionId-ne[Vault443R8ForeignConsole]::WTSGetActiveConsoleSessionId()){throw 'Same active-console named Win11 controller UAC required'}
 foreach($path in @($q,(Join-Path $q 'reports'))){Protected $path $false}
 foreach($path in @($private,(Join-Path $private 'marker'),(Join-Path $private 'qa-inputs.json'))){Protected $path $true}
 if([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'Private QA marker differs'}
 $config=Get-Content (Join-Path $private 'qa-inputs.json') -Raw|ConvertFrom-Json
 if($config.machine-ne$env:COMPUTERNAME-or$config.controllerSID-ne$identity.User.Value){throw 'Protected QA controller SID differs'}
 if(Test-Path $out){Protected $out $false}else{New-Item -ItemType Directory -Path $out|Out-Null};$canReport=$true
 Check 'exact-r8-daemon' ((Get-FileHash "$app\vault443d.exe").Hash.ToLowerInvariant()-eq'4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50')
 Check 'exact-r8' ((Get-FileHash "$app\build-manifest.json").Hash.ToLowerInvariant()-eq'bc6692d6939e0798de19465963e24de765eb84938b33866e4e295ea5bba65f19')
 $inspectUTC=[DateTime]::UtcNow
 & "$q\installer-smoke.ps1" -Phase inspect -InstallerSha256 '12896544881b15553c8b8c60d3f07d09f8e9ff02ec64f856e1583551b1d5ca3e' -InstallerPath "$q\Vault443-1.3.4-windows-x64-setup.exe" -OutputDirectory $out -SkipGuiProbe|Out-Null
 $inspect=@(Get-ChildItem $out -Filter '*-inspect.json'|Where-Object {$_.LastWriteTimeUtc-ge$inspectUTC.AddSeconds(-1)}|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1)
 if($inspect.Count-ne1){throw 'Fresh installed runtime inspection report absent'};$inspection=Get-Content $inspect[0].FullName -Raw|ConvertFrom-Json
 Check 'fresh-installed-runtime-inspect-pass' ($inspection.completed-and$inspection.passed-and$inspection.phase-eq'inspect'-and$inspection.installerSha256-eq'12896544881b15553c8b8c60d3f07d09f8e9ff02ec64f856e1583551b1d5ca3e')
 $guid=[Guid]'8CE0BA94-4F2C-469D-8EB8-58435F7F6223';Exact-Reference;Check 'foreign-exact-guid-before' ([VaultInstallerReadOnly]::Exists($guid,0))
 $before=IDs;$files=@(Get-ChildItem $app -File -Recurse|ForEach-Object {$_.FullName.Substring($app.Length)}|Sort-Object)
 $r.stage='uninstall-abort';$p=Start-Process "$app\unins000.exe" -ArgumentList ('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="'+$out+'\uninstall-abort.log"') -PassThru
 try{[void]$p.Handle;if(!$p.WaitForExit(180000)){throw 'Uninstaller deadline; process retained for inspection'};Check 'uninstall-aborted' ($p.ExitCode-eq1) @{exit=$p.ExitCode}}finally{$p.Dispose()}
 Check 'service-retained' ([bool](Get-Service Vault443 -ErrorAction SilentlyContinue))
 $after=IDs;Check 'exact-profiles-retained' ((ConvertTo-Json -InputObject $before -Compress)-ceq(ConvertTo-Json -InputObject $after -Compress)) @{before=$before.Count;after=$after.Count}
 $afterFiles=@(Get-ChildItem $app -File -Recurse|ForEach-Object {$_.FullName.Substring($app.Length)}|Sort-Object)
 Check 'all-app-files-retained' ((ConvertTo-Json -InputObject $files -Compress)-ceq(ConvertTo-Json -InputObject $afterFiles -Compress)) @{before=$files.Count;after=$afterFiles.Count}
 Check 'foreign-exact-guid-after-abort' ([VaultInstallerReadOnly]::Exists($guid,0))
 Check 'exact-qa-cleanup-image' ((Get-FileHash "$x\vault443-wfp-foreign.exe").Hash.ToLowerInvariant()-eq'57f5e09a57d2c08b19fa93540f09416e9d1a949f7b544ba80bce4caa385edb68')
 $r.stage='exact-foreign-cleanup';Exact-Reference;$cleanupText=@(& "$x\vault443-wfp-foreign.exe" cleanup)-join"`n";if($LASTEXITCODE){throw 'Exact foreign cleanup failed'};$cleanup=$cleanupText|ConvertFrom-Json;Check 'cleanup-only-exact-reference' ($cleanup.mode-eq'cleanup'-and$cleanup.result-eq'complete'-and[Guid]$cleanup.ruleId-eq$guid);$r.cleanup=@{mode=$cleanup.mode;ruleId=$cleanup.ruleId;result=$cleanup.result}
 Check 'foreign-exact-guid-removed' (![VaultInstallerReadOnly]::Exists($guid,0))
 $r.stage='restart-retained-service';$service=Get-Service Vault443;try{if($service.Status-eq'Stopped'){$service.Start()};$service.WaitForStatus('Running',[TimeSpan]::FromSeconds(40))}finally{$service.Dispose()};Check 'service-running-after-exact-cleanup' ((Get-Service Vault443).Status-eq'Running');$r.stage='complete';$r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');if($canReport){$r|ConvertTo-Json -Depth 6|Set-Content "$out\result.json" -Encoding UTF8}}
if(!$r.passed){exit 1}
