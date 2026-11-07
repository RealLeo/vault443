#Requires -RunAsAdministrator
# One bounded QA clock correction; no persistent time-service configuration.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME-ne'VAULT443-WIN10'-or(Get-CimInstance Win32_ComputerSystem).Model-ne'VirtualBox'){throw 'Named QA VM required'}
$id=[Security.Principal.WindowsIdentity]::GetCurrent();$cfg=Get-Content 'C:\ProgramData\Vault443-QA\qa-inputs.json' -Raw|ConvertFrom-Json
if($cfg.machine-ne$env:COMPUTERNAME-or$cfg.controllerSID-ne$id.User.Value){throw 'Bound QA controller required'}
if((Get-FileHash 'C:\Program Files\Vault443\build-manifest.json').Hash.ToLowerInvariant()-ne'3b39812785f9441b33ac02ced564f30bbc918253b27edbbaed4ef4bb1c65c09a'){throw 'Exact R9 required'}
$s='[]'|& 'C:\Program Files\Vault443\vault443-cli.exe' GetSnapshot|ConvertFrom-Json
if($s.runtime.state-ne'disconnected'-or$s.runtime.guardArmed-or@($s.workProfiles|Where-Object {$_.runtime.state-ne'disconnected'}).Count){throw 'Explicit all-off required'}
[Net.WebRequest]::DefaultWebProxy=$null
$before=[DateTime]::UtcNow;$timer=[Diagnostics.Stopwatch]::StartNew()
$response=Invoke-WebRequest -UseBasicParsing -Method Head -Uri 'http://93.184.215.14:8080/' -TimeoutSec 5
$target=[DateTime]::ParseExact([string]$response.Headers.Date,'r',[Globalization.CultureInfo]::InvariantCulture,([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
$timer.Stop();$offset=($target-$before).TotalSeconds
if($target.Kind-ne[DateTimeKind]::Utc-or$target.Date-ne$before.Date-or$offset-lt0-or$offset-gt900-or$timer.Elapsed.TotalSeconds-gt3){throw 'Bounded controlled-fixture clock reference differs'}
Set-Date -Date $target.ToLocalTime()|Out-Null
@{passed=$true;beforeUTC=$before.ToString('o');targetUTC=$target.ToString('o');afterUTC=[DateTime]::UtcNow.ToString('o');offsetSeconds=$offset;reference='isolated Linux fixture HTTP Date header';persistentTimeConfigurationChanged=$false}|ConvertTo-Json|Set-Content 'C:\Program Files\Vault443QA\reports\r9-clock-sync.json' -Encoding UTF8
