#Requires -Version 5.1
#Requires -RunAsAdministrator
# Same-console UAC; never recreates qa2 or modifies its password/profiles.
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$InstallerSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha256,
 [string]$SourceDir='C:\Users\Public\qa-source-r8'
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$q='C:\Program Files\Vault443QA'
$r=[ordered]@{startedUtc=[DateTime]::UtcNow.ToString('o');passed=$false;stage='bootstrap';existingUserPreserved=$false;passwordTouched=$false;errorType=$null;errorLine=0}
try {
 & "$SourceDir\qa-bootstrap.ps1" -SourceDir $SourceDir -InstallerSha256 $InstallerSha256 -EnableEngineFaults -EngineFaultManifestSha256 $ManifestSha256|Out-Null
 $r.stage='existing-qa2-readonly-check'
 $u=Get-LocalUser -Name vaultqa2 -ErrorAction Stop
 $admin=@(Get-LocalGroupMember -SID 'S-1-5-32-544'|Where-Object {$_.SID.Value-eq$u.SID.Value})
 $users=@(Get-LocalGroupMember -SID 'S-1-5-32-545'|Where-Object {$_.SID.Value-eq$u.SID.Value})
 if(!$u.Enabled-or$admin.Count-ne0-or$users.Count-ne1){throw 'Existing standard qa2 precondition failed'}
 $r.existingUserPreserved=$true;$r.stage='interactive-session-upgrade'
 $ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $argsFixed=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$q+'\installer-smoke.ps1"'),'-Phase','upgrade','-InstallerPath',('"'+$q+'\Vault443-1.3.4-windows-x64-setup.exe"'),'-InstallerSha256',$InstallerSha256,'-OutputDirectory',('"'+$q+'\reports\interactive-r8"'),'-SkipGuiProbe')
 $child=Start-Process -FilePath $ps -ArgumentList $argsFixed -PassThru
 [void]$child.Handle
 if(!$child.WaitForExit(240000)){throw 'Interactive upgrade wait exceeded; inspect without killing'}
 if($child.ExitCode-ne0){throw 'Interactive upgrade failed; inspect native report'}
 if((Get-FileHash 'C:\Program Files\Vault443\build-manifest.json').Hash.ToLowerInvariant()-ne$ManifestSha256){throw 'R8 installed manifest mismatch'}
 if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne'4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'){throw 'R8 installed daemon mismatch'}
 $r.stage='complete';$r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.finishedUtc=[DateTime]::UtcNow.ToString('o');if(Test-Path "$q\reports"){$r|ConvertTo-Json -Depth 5|Set-Content "$q\reports\interactive-r8-entry.json" -Encoding UTF8}}
$r|ConvertTo-Json -Depth 5
if(!$r.passed){exit 1}
