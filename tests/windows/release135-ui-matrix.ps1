# Release 1.3.5 UI matrix: EN/RU at real OS scale 100%, 150%, 200%.
# AppDirectory supports the installer-selected local path; all product identities are explicit inputs.
# Run only as the ordinary ACTIVE console user: powershell.exe -MTA -NoProfile -File <this-file>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$AppDirectory,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedManifestSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedBackendSha256,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedGuiSha256,
 [string]$InstallerPath='',
 [ValidatePattern('^(?:[a-f0-9]{64})?$')][string]$ExpectedInstallerSha256='',
 [string]$SourceDirectory=$PSScriptRoot,
 [string]$ReportDirectory='C:\Users\Public\Vault443Exchange\release135-outputs\ui',
 [switch]$RequireActiveVPN,
 [switch]$LeaveScale200
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$source=[IO.Path]::GetFullPath($SourceDirectory)
$reports=[IO.Path]::GetFullPath($ReportDirectory)
$appRoot=[IO.Path]::GetFullPath($AppDirectory).TrimEnd('\')
$app=Join-Path $appRoot 'vault443.exe'
$ui=Join-Path $source 'ui-native-smoke.ps1';$scaleScript=Join-Path $source 'set-display-scale.ps1'
$manifestPath=Join-Path $appRoot 'build-manifest.json'
$expectedManifest=$ExpectedManifestSha256;$expectedGUI=$ExpectedGuiSha256
[IO.Directory]::CreateDirectory($reports)|Out-Null
$run=[ordered]@{productVersion='1.3.5';startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null;passed=$false;completed=$false;cases=@();errorType=$null;errorLine=0;errorMessage=$null;failedStage=$null;finalSelectedScale=$null;restoreScale150Requested=(!$LeaveScale200);guiSha256=$expectedGUI;backendSha256=$ExpectedBackendSha256;manifestSha256=$expectedManifest;appDirectory=$appRoot;requireActiveVPN=[bool]$RequireActiveVPN;shellEvidence=$null;noForcedTermination=$true}
$stage='preflight';$case=$null
$safeMessages=@('ACTIVE local console session required','Exact release GUI identity mismatch','Final150% HWND verification failed','Fresh Settings HWND owner path or session mismatch','Fresh Settings identity changed before WM_CLOSE','Fresh Settings window identity is invalid','MTA PowerShell required','Multiple fresh protected Settings windows; refusing WM_CLOSE','Named isolated VM required','No unique fresh visible protected Settings window','Non-elevated user required','OS scale or HWND DPI mismatch','Protected Settings executable is a reparse point','Protected Settings remained visible after WM_CLOSE; manual closure required','Quit/language restoration incomplete','Release manifest identity mismatch','Reviewed QA script identity mismatch','Exact release daemon required','Settings WM_CLOSE failed','Status HWND DPI mismatch','UI phase failed','Missing native EXE icon resource','Publisher or file version mismatch','Installed-app publisher or display icon mismatch','Start shortcut is missing','Start shortcut points to a different installation','Installer path and checksum must be supplied together','Installer identity mismatch','Live icon HWND owner mismatch','Expected product version 1.3.5')
function Save { $run|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $reports 'controller-result.json') -Encoding UTF8 }
function Invoke-UI([string]$Phase) {
    $script:stage=$case.name+':'+$Phase
    $arguments=@{Phase=$Phase;AppPath=$app;Language=$case.language;QtScaleFactor='1';AppScale=0.5;CaseName=$case.name;ReportDirectory=$reports;CapturePng=$true;RequireActiveVPN=[bool]$RequireActiveVPN}
    $text=@(& $ui @arguments) -join "`n"
    $report=$text|ConvertFrom-Json
    if($report.Result -ne 'pass' -or !$report.ServiceStateUnchanged -or ($RequireActiveVPN -and !$report.ActiveVPNPersistenceVerified)){throw 'UI phase failed'}
    $case.phases+=@{phase=$Phase;passed=$true;report=$report.ReportFile;windowDpi=$report.WindowOSDpi}
    Save;return $report
}
function Initialize-ShellIcons {
    if('Vault443Release135Icons' -as [type]){return}
    Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public static class Vault443Release135Icons {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct SHFILEINFO {
        public IntPtr Icon; public int IconIndex; public uint Attributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string DisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=80)] public string TypeName;
    }
    [DllImport("shell32.dll", CharSet=CharSet.Unicode)]
    static extern uint ExtractIconEx(string path, int index, IntPtr[] large, IntPtr[] small, uint count);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode)]
    static extern IntPtr SHGetFileInfo(string path, uint attributes, out SHFILEINFO info, uint size, uint flags);
    [DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr icon);
    [DllImport("user32.dll", SetLastError=true)]
    static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr wParam, IntPtr lParam, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32.dll", EntryPoint="GetClassLongPtrW")]
    static extern IntPtr GetClassLongPtr(IntPtr window, int index);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint owner);
    public static uint Owner(long handle) {
        uint owner; GetWindowThreadProcessId(new IntPtr(handle), out owner); return owner;
    }
    static void Save(IntPtr handle, string output) {
        if(handle==IntPtr.Zero) throw new InvalidOperationException("No native icon handle");
        using(Icon borrowed=Icon.FromHandle(handle))
        using(Bitmap bitmap=borrowed.ToBitmap()) bitmap.Save(output, ImageFormat.Png);
    }
    public static uint GroupCount(string path) { return ExtractIconEx(path,-1,null,null,0); }
    public static void SaveShellIcon(string path, string output, bool small) {
        SHFILEINFO info;
        if(SHGetFileInfo(path,0,out info,(uint)Marshal.SizeOf(typeof(SHFILEINFO)),0x100u|(small?1u:0u))==IntPtr.Zero || info.Icon==IntPtr.Zero)
            throw new InvalidOperationException("Shell icon extraction failed");
        try { Save(info.Icon,output); } finally { DestroyIcon(info.Icon); }
    }
    public static void SaveWindowIcon(long handle, string output, bool small) {
        IntPtr window=new IntPtr(handle); UIntPtr result;
        IntPtr ok=SendMessageTimeout(window,0x7F,new UIntPtr(small?0u:1u),IntPtr.Zero,2,1000,out result);
        IntPtr icon=ok==IntPtr.Zero?IntPtr.Zero:new IntPtr(unchecked((long)result.ToUInt64()));
        if(icon==IntPtr.Zero) icon=GetClassLongPtr(window,small?-34:-14);
        // Window/class icon handles remain owned by the application.
        Save(icon,output);
    }
}
'@
}
function Read-FileIcons([string]$Path,[string]$Prefix,[bool]$RequireResource) {
    $groups=[Vault443Release135Icons]::GroupCount($Path)
    if($RequireResource -and $groups -lt 1){throw 'Missing native EXE icon resource'}
    $images=@()
    foreach($size in @('large','small')){
        $png=Join-Path $reports ($Prefix+'-'+$size+'.png')
        [Vault443Release135Icons]::SaveShellIcon($Path,$png,($size -eq 'small'))
        $images+=@{file=$png;sha256=(Get-FileHash -LiteralPath $png -Algorithm SHA256).Hash.ToLowerInvariant();shellSize=$size}
    }
    return @{path=$Path;nativeIconGroups=$groups;images=$images}
}
function Read-VersionMetadata([string]$Path) {
    $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    # Inno reserves space-padded VERSIONINFO strings in the setup loader.
    # Preserve the raw evidence while comparing its visible publisher value.
    $company=$version.CompanyName.TrimEnd(' ')
    if($company -cne 'Vault 443' -or $version.FileMajorPart -ne 1 -or $version.FileMinorPart -ne 3 -or $version.FileBuildPart -ne 5){throw 'Publisher or file version mismatch'}
    return @{companyName=$company;rawCompanyName=$version.CompanyName;fileVersion=$version.FileVersion;productName=$version.ProductName;productVersion=$version.ProductVersion;fileDescription=$version.FileDescription}
}
function Read-ShellEvidence {
    Initialize-ShellIcons
    if(!('Vault443Release135ShellLink' -as [type])){Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Vault443Release135ShellLink {
    [ComImport, Guid("000214F9-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IShellLinkW {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int count, IntPtr findData, uint flags);
        void GetIDList(out IntPtr idList);
        void SetIDList(IntPtr idList);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder text, int count);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string text);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int count);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string path);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder text, int count);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string text);
        void GetHotkey(out short hotkey);
        void SetHotkey(short hotkey);
        void GetShowCmd(out int show);
        void SetShowCmd(int show);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int count, out int index);
    }
    public sealed class LinkData {
        public string TargetPath, WorkingDirectory, IconLocation;
    }
    public static LinkData Read(string filename) {
        object instance=Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("00021401-0000-0000-C000-000000000046")));
        try {
            // STGM_READ only. Never call Resolve, Save or any setter.
            ((System.Runtime.InteropServices.ComTypes.IPersistFile)instance).Load(filename,0);
            var link=(IShellLinkW)instance;
            var target=new StringBuilder(32768);var working=new StringBuilder(32768);var icon=new StringBuilder(32768);int index;
            link.GetPath(target,target.Capacity,IntPtr.Zero,0); // Unicode target path; no Resolve call
            link.GetWorkingDirectory(working,working.Capacity);
            link.GetIconLocation(icon,icon.Capacity,out index);
            return new LinkData{TargetPath=target.ToString(),WorkingDirectory=working.ToString(),IconLocation=icon.ToString()+","+index};
        } finally { Marshal.FinalReleaseComObject(instance); }
    }
}
'@}
    $registry='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B7547E6A-E316-4C92-9407-1B0F0D4A3443}_is1'
    $installed=Get-ItemProperty -LiteralPath $registry
    $displayIcon=([string]$installed.DisplayIcon -replace ',\s*-?\d+\s*$','').Trim('"')
    if($installed.Publisher -cne 'Vault 443' -or $installed.DisplayVersion -ne '1.3.5' -or [IO.Path]::GetFullPath($displayIcon) -ne $app){throw 'Installed-app publisher or display icon mismatch'}
    $shortcut=Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Vault 443.lnk'
    if(!(Test-Path -LiteralPath $shortcut -PathType Leaf)){throw 'Start shortcut is missing'}
    $link=[Vault443Release135ShellLink]::Read($shortcut)
    if([IO.Path]::GetFullPath($link.TargetPath) -ne $app){throw 'Start shortcut points to a different installation'}
    $shortcutInfo=@{path=$shortcut;targetPath=$link.TargetPath;iconLocation=$link.IconLocation;workingDirectory=$link.WorkingDirectory;reader='IShellLinkW/IPersistFile STGM_READ'}
    $result=[ordered]@{metadata=(Read-VersionMetadata $app);exe=(Read-FileIcons $app 'shell-exe' $true);shortcut=$shortcutInfo;startIcon=(Read-FileIcons $shortcut 'shell-start' $false);installedApp=@{publisher=$installed.Publisher;version=$installed.DisplayVersion;displayIcon=$installed.DisplayIcon};installer=$null}
    if([bool]$InstallerPath -ne [bool]$ExpectedInstallerSha256){throw 'Installer path and checksum must be supplied together'}
    if($InstallerPath){
        if((Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedInstallerSha256){throw 'Installer identity mismatch'}
        $result.installer=@{sha256=$ExpectedInstallerSha256;metadata=(Read-VersionMetadata $InstallerPath);icons=(Read-FileIcons $InstallerPath 'shell-installer' $true)}
    }
    return $result
}
function Save-WindowIcons($Status) {
    $windows=@($Status.Windows|Where-Object {$_.Title -eq 'Vault 443' -and $_.Visible})
    if($windows.Count -ne 1 -or [Vault443Release135Icons]::Owner([long]$windows[0].Handle) -ne [uint32]$Status.ProcessId){throw 'Live icon HWND owner mismatch'}
    $images=@()
    foreach($size in @('large','small')){
        $png=Join-Path $reports ($case.name+'-window-icon-'+$size+'.png')
        [Vault443Release135Icons]::SaveWindowIcon([long]$windows[0].Handle,$png,($size -eq 'small'))
        $images+=@{file=$png;sha256=(Get-FileHash -LiteralPath $png -Algorithm SHA256).Hash.ToLowerInvariant();windowHandle=$windows[0].Handle;processId=$Status.ProcessId;windowDpi=$Status.WindowOSDpi;iconSize=$size}
    }
    return $images
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
    if(!('Vault443Release135UIController' -as [type])){Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class Vault443Release135UIController {
 [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
}
'@
    }
    $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    if(!$session -or $session -ne [Vault443Release135UIController]::WTSGetActiveConsoleSessionId()){throw 'ACTIVE local console session required'}
    if((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedManifest){throw 'Release manifest identity mismatch'}
    if((Get-FileHash -LiteralPath (Join-Path $appRoot 'vault443d.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedBackendSha256){throw 'Exact release daemon required'}
    $m=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    if($m.productVersion -ne '1.3.5'){throw 'Expected product version 1.3.5'}
    if($m.files.'vault443.exe'.sha256 -ne $expectedGUI -or (Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash.ToLowerInvariant() -ne $m.files.'vault443.exe'.sha256){throw 'Exact release GUI identity mismatch'}
    foreach($entry in @(@($ui,'a54331cd56fc5e7b1af326a3fb61e9ba000191a6f269c8c5e7c0a423b2615cc3'),@($scaleScript,'3fd5dc99abd1b9b2cf096e4df3ce59e3da7dacbddd4d6f1a5553607fdb06c7f1'))){
        if((Get-FileHash -LiteralPath $entry[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry[1]){throw 'Reviewed QA script identity mismatch'}
    }
    [IO.Directory]::CreateDirectory($reports)|Out-Null
    $run.shellEvidence=Read-ShellEvidence;Save
    $plans=@(@{language='en';percent=100},@{language='en';percent=150},@{language='en';percent=200},@{language='ru';percent=100},@{language='ru';percent=150},@{language='ru';percent=200})
    foreach($plan in $plans){
        $language=$plan.language;$percent=[int]$plan.percent
        $case=[ordered]@{name=('release135-'+$language+$percent);language=$language;requestedScale=$percent;startedUtc=[DateTime]::UtcNow.ToString('o');finishedUtc=$null;passed=$false;phases=@();scales=@();settingsClosures=@();windowIcons=@();errorType=$null;errorLine=0;errorMessage=$null}
        $run.cases+=,$case;Save
        $launch=Invoke-UI 'launch' # Launch at the current real DPI; no Qt scale simulation.
        Set-VerifiedScale $percent
        $null=Invoke-UI 'reopen' # Legitimate single-instance focus request after Settings closes.
        $status=Invoke-UI 'status'
        if([int]$status.WindowOSDpi -ne [int](96*$percent/100)){throw 'Status HWND DPI mismatch'}
        $case.windowIcons=Save-WindowIcons $status
        Save
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
