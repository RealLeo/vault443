# Full R6 UI matrix: EN/RU at real OS scale 100%, 150%, 200%.
# Run only as the ordinary ACTIVE console user: powershell.exe -MTA -NoProfile -File <this-file>
[CmdletBinding()]
param([switch]$LeaveScale200)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$source='C:\Users\Public\qa-source-r6'
$reports='C:\Users\Public\Vault443Exchange\r6-ui'
$app='C:\Program Files\Vault443\vault443.exe'
$ui=Join-Path $source 'ui-native-smoke.ps1';$scaleScript=Join-Path $source 'set-display-scale.ps1'
$manifestPath='C:\Program Files\Vault443\build-manifest.json'
$expectedManifest='392faa05130ab32278b4d64cec0f51e452fc947f412b1841fcfa517dc2766ee7';$expectedGUI='53bc41422de5c1940a3e486c7d5a6442a2074d94fc22f8d33cfef91e5eb140df'
$run=[ordered]@{startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null;passed=$false;completed=$false;cases=@();errorType=$null;errorLine=0;errorMessage=$null;failedStage=$null;finalSelectedScale=$null;restoreScale150Requested=(!$LeaveScale200);guiSha256=$expectedGUI;manifestSha256=$expectedManifest;noForcedTermination=$true}
$stage='preflight';$case=$null
$safeMessages=@('ACTIVE local console session required','Exact R6 GUI identity mismatch','Final150% HWND verification failed','Fresh Settings HWND owner path or session mismatch','Fresh Settings identity changed before WM_CLOSE','Fresh Settings window identity is invalid','MTA PowerShell required','Multiple fresh protected Settings windows; refusing WM_CLOSE','Named isolated VM required','No unique fresh visible protected Settings window','Non-elevated user required','OS scale or HWND DPI mismatch','Protected Settings executable is a reparse point','Protected Settings remained visible after WM_CLOSE; manual closure required','Quit/language restoration incomplete','R6 manifest identity mismatch','Reviewed QA script identity mismatch','Settings WM_CLOSE failed','Status HWND DPI mismatch','UI phase failed')
function Save { $run|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $reports 'controller-result.json') -Encoding UTF8 }
function Invoke-UI([string]$Phase) {
    $script:stage=$case.name+':'+$Phase
    $text=@(& $ui -Phase $Phase -AppPath $app -Language $case.language -QtScaleFactor '1' -AppScale 0.5 -CaseName $case.name -ReportDirectory $reports -RequireActiveVPN -CapturePng) -join "`n"
    $report=$text|ConvertFrom-Json
    if($report.Result -ne 'pass' -or !$report.ServiceStateUnchanged -or !$report.ActiveVPNPersistenceVerified){throw 'UI phase failed'}
    $case.phases+=@{phase=$Phase;passed=$true;report=$report.ReportFile;windowDpi=$report.WindowOSDpi}
    Save;return $report
}
function Get-FreshSettingsWindows {
    $expectedSettings=Join-Path $env:SystemRoot 'ImmersiveControlPanel\SystemSettings.exe'
    $expectedHost=Join-Path $env:SystemRoot 'System32\ApplicationFrameHost.exe'
    foreach($path in @($expectedSettings,$expectedHost)){
        if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Protected Settings executable is a reparse point'}
    }
    $settings=@(Get-Process -Name SystemSettings -ErrorAction SilentlyContinue|Where-Object {$_.SessionId -eq $session -and $_.Path -eq $expectedSettings})
    $unique=@{}
    foreach($process in $settings){foreach($w in @([Vault443DisplayScale]::Windows([uint32]$process.Id,$true))){
        if([long]$w.Handle -eq 0 -or [int]$w.ProcessId -le 0){throw 'Fresh Settings window identity is invalid'}
        $owner=Get-Process -Id ([int]$w.ProcessId) -ErrorAction Stop
        if($owner.SessionId -ne $session -or $owner.Path -notin @($expectedSettings,$expectedHost)){throw 'Fresh Settings HWND owner path or session mismatch'}
        # Windows10 frame HWND is accepted only through this live protected SystemSettings child mapping.
        $unique[([string]$w.Handle+':'+[string]$w.ProcessId)]=$w
    }}
    return @($unique.Values)
}
function Close-VerifiedSettings($Report) {
    $script:stage=$case.name+':close-settings'
    # DPI changes can recreate the Settings HWND/PID. The scale report's old HWND is diagnostic only.
    $deadline=[DateTime]::UtcNow.AddSeconds(3)
    do {
        $windows=@(Get-FreshSettingsWindows)
        if($windows.Count -gt 1){throw 'Multiple fresh protected Settings windows; refusing WM_CLOSE'}
        if($windows.Count -eq 1){break}
        Start-Sleep -Milliseconds 150
    }while([DateTime]::UtcNow -lt $deadline)
    if($windows.Count -ne 1){throw 'No unique fresh visible protected Settings window'}
    $w=$windows[0]
    $case.settingsClosures+=@{scaleReport=$Report.ReportFile;oldHandle=$Report.SettingsWindow.Handle;oldPID=$Report.SettingsWindow.ProcessId;freshHandle=$w.Handle;freshPID=$w.ProcessId;identityRecreated=($Report.SettingsWindow.Handle -ne $w.Handle -or $Report.SettingsWindow.ProcessId -ne $w.ProcessId);utc=[DateTime]::UtcNow.ToString('o')}
    Save
    # Re-enumerate just before posting; never send to the pre-scale report HWND.
    $verified=@(Get-FreshSettingsWindows)
    if($verified.Count -ne 1 -or $verified[0].Handle -ne $w.Handle -or $verified[0].ProcessId -ne $w.ProcessId){throw 'Fresh Settings identity changed before WM_CLOSE'}
    if(![Vault443NativeUI]::PostMessage([IntPtr]([long]$w.Handle),0x0010,[IntPtr]::Zero,[IntPtr]::Zero)){throw 'Settings WM_CLOSE failed'}
    $deadline=[DateTime]::UtcNow.AddSeconds(5)
    do {
        Start-Sleep -Milliseconds 150
        if(@(Get-FreshSettingsWindows).Count -eq 0){return}
    }while([DateTime]::UtcNow -lt $deadline)
    throw 'Protected Settings remained visible after WM_CLOSE; manual closure required'
}
function Set-VerifiedScale([int]$Percent) {
    $script:stage=$case.name+':scale-'+$Percent
    $statePath=Join-Path $reports ($case.name+'.state.json')
    $text=@(& $scaleScript -Scale $Percent -UiStatePath $statePath -ReportDirectory $reports) -join "`n"
    $report=$text|ConvertFrom-Json
    if($report.Result -ne 'pass' -or !$report.ScaleSelectionInvoked -or [int]$report.SelectedScaleAfter -ne $Percent -or [int]$report.VaultDpiAfter -ne [int](96*$Percent/100)){throw 'OS scale or HWND DPI mismatch'}
    $case.scales+=@{requested=$Percent;selected=[int]$report.SelectedScaleAfter;windowDpi=[int]$report.VaultDpiAfter;passed=$true;report=$report.ReportFile}
    $run.finalSelectedScale=[int]$report.SelectedScaleAfter;Save
    Close-VerifiedSettings $report
}
try {
    if([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::MTA){throw 'MTA PowerShell required'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if(([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Non-elevated user required'}
    $machine=Get-CimInstance Win32_ComputerSystem
    if($machine.Name -notin @('VAULT443-WIN10','VAULT443-WIN11') -or $machine.Model -ne 'VirtualBox'){throw 'Named isolated VM required'}
    if(!('Vault443R6UIController' -as [type])){Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class Vault443R6UIController {
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
}
'@
    }
    $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    if(!$session -or $session -ne [Vault443R6UIController]::WTSGetActiveConsoleSessionId()){throw 'ACTIVE local console session required'}
    if((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedManifest){throw 'R6 manifest identity mismatch'}
    $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    if($m.files.'vault443.exe'.sha256 -ne $expectedGUI -or (Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash.ToLowerInvariant() -ne $m.files.'vault443.exe'.sha256){throw 'Exact R6 GUI identity mismatch'}
    foreach($entry in @(@($ui,'a54331cd56fc5e7b1af326a3fb61e9ba000191a6f269c8c5e7c0a423b2615cc3'),@($scaleScript,'3fd5dc99abd1b9b2cf096e4df3ce59e3da7dacbddd4d6f1a5553607fdb06c7f1'))){
        if((Get-FileHash -LiteralPath $entry[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry[1]){throw 'Reviewed QA script identity mismatch'}
    }
    [IO.Directory]::CreateDirectory($reports)|Out-Null
    $plans=@(@{language='en';percent=100},@{language='en';percent=150},@{language='en';percent=200},@{language='ru';percent=100},@{language='ru';percent=150},@{language='ru';percent=200})
    foreach($plan in $plans){
        $language=$plan.language;$percent=[int]$plan.percent
        $case=[ordered]@{name=('r6-'+$language+$percent);language=$language;requestedScale=$percent;startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null;passed=$false;phases=@();scales=@();settingsClosures=@();errorType=$null;errorLine=0;errorMessage=$null}
        $run.cases+=,$case;Save
        $launch=Invoke-UI 'launch' # Launch at the current real DPI; no Qt scale simulation.
        Set-VerifiedScale $percent
        $null=Invoke-UI 'reopen' # Legitimate single-instance focus request after Settings closes.
        $status=Invoke-UI 'status'
        if([int]$status.WindowOSDpi -ne [int](96*$percent/100)){throw 'Status HWND DPI mismatch'}
        $null=Invoke-UI 'close';$null=Invoke-UI 'reopen'
        if($language -eq 'ru' -and $percent -eq 200 -and !$LeaveScale200){
            # Preserve both real-200% images before later phases overwrite their PNG names.
            $preserved=Join-Path $reports 'ru200-at200'
            [IO.Directory]::CreateDirectory($preserved)|Out-Null
            Copy-Item -LiteralPath @((Join-Path $reports ($case.name+'-status.png')),(Join-Path $reports ($case.name+'-reopen.png'))) -Destination $preserved -ErrorAction Stop
            # Restore real150% using this last live case, never a new cleanup case.
            Set-VerifiedScale 150
            $null=Invoke-UI 'reopen'
            $restored=Invoke-UI 'status'
            if([int]$restored.WindowOSDpi -ne 144){throw 'Final150% HWND verification failed'}
        }
        $quit=Invoke-UI 'quit'
        if(!$quit.LanguageRestored -or $quit.ProcessRunning){throw 'Quit/language restoration incomplete'}
        $case.passed=$true;$case.finishedUtc=[DateTime]::UtcNow.ToString('o');Save
    }
    $run.passed=$true;$run.completed=$true
}catch{
    $run.errorType=$_.Exception.GetType().FullName;$run.failedStage=$stage
    $run.errorLine=[int]$_.InvocationInfo.ScriptLineNumber
    $message=[string]$_.Exception.Message
    $run.errorMessage=if($message -in $safeMessages){$message}else{'Existing QA harness or Windows API failure; inspect its saved phase report'}
    if($null -ne $case){$case.errorType=$run.errorType;$case.errorLine=$run.errorLine;$case.errorMessage=$run.errorMessage;$case.finishedUtc=[DateTime]::UtcNow.ToString('o')}
    # Preserve UI, state and reports on failure. No process kill or automatic follow-up case.
}finally{
    $run.finishedUtc=[DateTime]::UtcNow.ToString('o')
    if(Test-Path -LiteralPath $reports){Save}
}
$run|ConvertTo-Json -Depth 10
if(!$run.passed){exit 1}
