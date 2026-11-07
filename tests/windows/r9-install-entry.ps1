#Requires -RunAsAdministrator
param([ValidateSet('install','upgrade')][string]$Phase='install')
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$src='C:\Users\Public\qa-source-r9';$q='C:\Program Files\Vault443QA';$canReport=$false
$r=[ordered]@{candidate='R9';phase=$Phase;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false}
try{
 foreach($pin in @(@('qa-bootstrap.ps1','f7cb15e11a8bc2d534c1b7660b3771b0cd532b9af8b9f2706f23b0d9cfef8cda'),@('build-manifest.json','3b39812785f9441b33ac02ced564f30bbc918253b27edbbaed4ef4bb1c65c09a'),@('Vault443-1.3.4-windows-x64-setup.exe','f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d'))){if((Get-FileHash (Join-Path $src $pin[0])).Hash.ToLowerInvariant()-ne$pin[1]){throw 'Pinned R9 QA input differs'}}
 & "$src\qa-bootstrap.ps1" -SourceDir $src -InstallerSha256 'f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d' -EnableEngineFaults -EngineFaultManifestSha256 '3b39812785f9441b33ac02ced564f30bbc918253b27edbbaed4ef4bb1c65c09a'|Out-Null
 $out=Join-Path $q ('reports\r9-entry\'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'));New-Item -ItemType Directory $out|Out-Null;$canReport=$true
 if((Get-FileHash "$q\installer-smoke.ps1").Hash.ToLowerInvariant()-ne'e40f24409955c450b620a9a831046aa63e202bbe6ac4f775d6d1b0f9b14312e0'){throw 'Protected installer harness differs'}
 & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$q\installer-smoke.ps1" -Phase $Phase -InstallerPath "$q\Vault443-1.3.4-windows-x64-setup.exe" -InstallerSha256 'f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d' -OutputDirectory $out -SkipGuiProbe|Out-Null
 if($LASTEXITCODE){throw 'Native installer harness failed'};$r.passed=$true
}catch{$r.errorType=$_.Exception.GetType().FullName;$r.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$r.completed=$true;$r.finishedUTC=[DateTime]::UtcNow.ToString('o');if($canReport){$r|ConvertTo-Json|Set-Content (Join-Path $out 'entry-result.json') -Encoding UTF8}}
if(!$r.passed){exit 1}
