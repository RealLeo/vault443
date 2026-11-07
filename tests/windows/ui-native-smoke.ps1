# Run in the interactive console user's non-elevated Windows PowerShell 5.1.
# Example: launch/close/reopen/status/quit, then repeat for en/ru and 1/1.5/2.
# QT_SCALE_FACTOR exercises Qt scaling; it is NOT evidence of OS display scaling.
# UAC prompts and tray appearance require separate manual/native screenshots.
# quit restores the prior language; restore handles manual cleanup after failure.
# Use one CaseName per language/scale and the same ReportDirectory for its phases.
[CmdletBinding()]
param(
    [ValidateSet('launch','close','reopen','status','quit','restore')][string]$Phase = 'status',
    [string]$AppPath = 'C:\Program Files\Vault443\vault443.exe',
    [string]$CliPath = '',
    [ValidateSet('en','ru')][string]$Language = 'en',
    [ValidateSet('1','1.5','2')][string]$QtScaleFactor = '1',
    [ValidateRange(0.4,3.0)][double]$AppScale = 0.5,
    [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$CaseName = 'native-ui',
    [string]$ReportDirectory = (Join-Path $env:LOCALAPPDATA 'Vault443\ui-native-smoke'),
    [switch]$RequireActiveVPN,
    [switch]$CapturePng
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this harness as the signed-in console user without elevation. It never approves UAC.'
}
if (-not ('Vault443NativeUI' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class Vault443NativeUI {
    public class Window {
        public long Handle; public uint ProcessId; public string Title; public string ClassName;
        public bool Visible; public bool Minimized; public int Left; public int Top;
        public int Width; public int Height; public uint Dpi;
    }
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    delegate bool EnumCallback(IntPtr window, IntPtr data);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumCallback callback, IntPtr data);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int size);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder text, int size);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr window, out RECT rect);
    [DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern uint GetDpiForSystem();
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("user32.dll", SetLastError=true)] public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx, dy; public uint data, flags, time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort vk, scan; public uint flags, time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Explicit)] struct INPUTUNION { [FieldOffset(0)] public KEYBDINPUT key; [FieldOffset(0)] public MOUSEINPUT mouse; }
    [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public INPUTUNION data; }
    [DllImport("user32.dll", SetLastError=true)] static extern uint SendInput(uint count, INPUT[] inputs, int size);
    public static Window[] Windows(uint wantedProcess) {
        var result = new List<Window>();
        EnumWindows(delegate(IntPtr handle, IntPtr data) {
            uint process; GetWindowThreadProcessId(handle, out process);
            if (process != wantedProcess) return true;
            var title = new StringBuilder(1024); var name = new StringBuilder(256); RECT rect;
            GetWindowText(handle, title, title.Capacity); GetClassName(handle, name, name.Capacity);
            if (!GetWindowRect(handle, out rect)) return true;
            result.Add(new Window { Handle=handle.ToInt64(), ProcessId=process, Title=title.ToString(),
                ClassName=name.ToString(), Visible=IsWindowVisible(handle), Minimized=IsIconic(handle),
                Left=rect.Left, Top=rect.Top, Width=rect.Right-rect.Left, Height=rect.Bottom-rect.Top,
                Dpi=GetDpiForWindow(handle) }); return true;
        }, IntPtr.Zero);
        return result.ToArray();
    }
    public static bool QuitShortcut(IntPtr window) {
        // Never send keys to another application or a UAC dialog.
        if (GetForegroundWindow() != window) return false;
        var inputs = new INPUT[4];
        ushort[] keys = { 0x11, 0x51, 0x51, 0x11 };
        for (int i=0; i<4; i++) { inputs[i].type=1; inputs[i].data.key.vk=keys[i]; inputs[i].data.key.flags=i>=2 ? 2u : 0u; }
        return SendInput(4, inputs, Marshal.SizeOf(typeof(INPUT))) == 4;
    }
}
'@
}
$currentSession = [Diagnostics.Process]::GetCurrentProcess().SessionId
if ($currentSession -eq 0 -or $currentSession -ne [Vault443NativeUI]::WTSGetActiveConsoleSessionId()) {
    throw 'An interactive local console session is required; service/session-0 and RDP runs are not this UI acceptance case.'
}
# Obtain physical HWND bounds even when this PowerShell host is DPI unaware.
$previousDpiContext = [Vault443NativeUI]::SetThreadDpiAwarenessContext([IntPtr](-4))
$ReportDirectory = [IO.Path]::GetFullPath($ReportDirectory)
[IO.Directory]::CreateDirectory($ReportDirectory) | Out-Null
$statePath = Join-Path $ReportDirectory ($CaseName + '.state.json')
$registryPath = 'Software\Vault443\vault443\ui'
$state = $null
$report = [ordered]@{
    Phase=$Phase; Case=$CaseName; TimeUTC=[DateTime]::UtcNow.ToString('o');
    UserSID=$identity.User.Value; SessionId=$currentSession; Elevated=$false;
    ScalingEvidence='QT_SCALE_FACTOR override only; OS 100/150/200% acceptance must be tested separately.';
    SystemDpi=[Vault443NativeUI]::GetDpiForSystem(); Result='running'
}
function Save-State {
    $state | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $statePath -Encoding UTF8
}
function Set-LanguagePreference {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($registryPath)
    try {
        $exists = $key.GetValueNames() -contains 'language'
        $prior = [ordered]@{Exists=$exists; Kind='String'; Value=$null}
        if ($exists) {
            $prior.Kind = $key.GetValueKind('language').ToString()
            $prior.Value = $key.GetValue('language', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
        $state.PreviousLanguage = $prior
        Save-State # Record restoration data before modifying the preference.
        $key.SetValue('language', $Language, [Microsoft.Win32.RegistryValueKind]::String)
    } finally { $key.Close() }
}
function Restore-LanguagePreference {
    if ($state.LanguageRestored -or $null -eq $state.PreviousLanguage) { return }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($registryPath)
    try {
        if ($state.PreviousLanguage.Exists) {
            $kind = [Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$state.PreviousLanguage.Kind)
            $value = $state.PreviousLanguage.Value
            switch ($state.PreviousLanguage.Kind) {
                'Binary' { $value = [byte[]]$value }
                'MultiString' { $value = [string[]]$value }
                'DWord' { $value = [int]$value }
                'QWord' { $value = [long]$value }
            }
            $key.SetValue('language', $value, $kind)
        } else { $key.DeleteValue('language', $false) }
    } finally { $key.Close() }
    $state.LanguageRestored = $true; Save-State
}
function Get-ServiceState {
    $raw = '[]' | & $state.CliPath GetSnapshot
    if ($LASTEXITCODE) { throw 'GetSnapshot failed. Enroll the console user explicitly; this harness does not approve UAC.' }
    $snapshot = $raw | ConvertFrom-Json
    if ($snapshot.busyByOtherUser) { throw 'The service belongs to another user; this harness must not take control.' }
    $work = @($snapshot.workProfiles | Where-Object { $null -ne $_ } | Sort-Object id | ForEach-Object {
        [ordered]@{Id=[string]$_.id; State=[string]$_.runtime.state}
    })
    $active = @($work | Where-Object { $_.State -in @('connected','partial') }).Count -gt 0
    if ([string]$snapshot.runtime.state -in @('connected','paused_external')) { $active = $true }
    return [ordered]@{ActiveProfileId=[string]$snapshot.activeProfileId; MainState=[string]$snapshot.runtime.state;
        GuardArmed=[bool]$snapshot.runtime.guardArmed; TrafficSessionId=[string]$snapshot.traffic.sessionId;
        Work=$work; HasActiveVPN=$active}
}
function Get-GuiProcess {
    if (-not $state.ProcessId) { return $null }
    $process = Get-Process -Id $state.ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    if ($process.SessionId -ne $currentSession -or $process.Path -ne $state.AppPath -or
        $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $state.StartTimeTicks) {
        throw 'Saved PID no longer identifies the test application. No window messages or input were sent.'
    }
    return $process
}
function Get-MainWindow {
    $process = Get-GuiProcess
    if ($null -eq $process) { return $null }
    return [Vault443NativeUI]::Windows([uint32]$process.Id) | Where-Object Title -eq 'Vault 443' | Select-Object -First 1
}
function Wait-MainWindow([bool]$Visible) {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $window = Get-MainWindow
        if ($null -ne $window -and $window.Visible -eq $Visible) { return $window }
        if ($null -eq (Get-GuiProcess)) { throw 'The native UI exited while waiting for its window.' }
        Start-Sleep -Milliseconds 150
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "The native UI did not reach Visible=$Visible within 15 seconds."
}
function Start-TestProcess {
    $names = @('QT_QPA_PLATFORM','QT_SCALE_FACTOR','QT_SCALE_FACTOR_ROUNDING_POLICY','QT_SCREEN_SCALE_FACTORS','QT_FONT_DPI','QT_QUICK_BACKEND')
    $prior = @{}
    foreach ($name in $names) { $prior[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    try {
        $env:QT_QPA_PLATFORM = 'windows'; $env:QT_SCALE_FACTOR = $state.QtScaleFactor
        $env:QT_SCALE_FACTOR_ROUNDING_POLICY = 'PassThrough'
        foreach ($name in @('QT_SCREEN_SCALE_FACTORS','QT_FONT_DPI','QT_QUICK_BACKEND')) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
        $arguments = @('--scale', ([double]$state.AppScale).ToString([Globalization.CultureInfo]::InvariantCulture))
        return Start-Process -FilePath $state.AppPath -ArgumentList $arguments -PassThru
    } finally {
        foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $prior[$name], 'Process') }
    }
}
function Reopen-Existing {
    if ($null -eq (Get-GuiProcess)) { throw 'The original native UI process has exited.' }
    $second = Start-TestProcess
    if (-not $second.WaitForExit(10000)) { throw 'The second invocation did not exit through the single-instance handshake.' }
    if ($second.ExitCode -ne 0) { throw "The second invocation failed with exit code $($second.ExitCode)." }
    $report.SecondInvocationProcessId = $second.Id
    $report.SecondInvocationExitCode = $second.ExitCode
    $window = Wait-MainWindow $true
    if ($window.ProcessId -ne $state.ProcessId) { throw 'Reopening did not raise the original PID.' }
    return $window
}
try {
    if ($Phase -eq 'launch') {
        if (Test-Path -LiteralPath $statePath) {
            $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            if (-not $previous.LanguageRestored) { throw 'The previous case is unfinished. Run its quit/restore phase before launching another case.' }
        }
        $AppPath = (Resolve-Path -LiteralPath $AppPath).Path
        if (-not $CliPath) { $CliPath = Join-Path (Split-Path -Parent $AppPath) 'vault443-cli.exe' }
        $CliPath = (Resolve-Path -LiteralPath $CliPath).Path
        $existing = @(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($AppPath)) -ErrorAction SilentlyContinue | Where-Object SessionId -eq $currentSession)
        if ($existing.Count) { throw 'An application instance already exists in this session. Quit it normally before this test.' }
        $state = [pscustomobject][ordered]@{Version=1; UserSID=$identity.User.Value; SessionId=$currentSession;
            AppPath=$AppPath; CliPath=$CliPath; Language=$Language; QtScaleFactor=$QtScaleFactor;
            AppScale=$AppScale; RequireActiveVPN=[bool]$RequireActiveVPN; PreviousLanguage=$null;
            LanguageRestored=$false; ProcessId=0; StartTimeTicks=''; LastPhase='launch'; Completed=$false}
        $report.BeforeService = Get-ServiceState
        if ($state.RequireActiveVPN -and -not $report.BeforeService.HasActiveVPN) { throw 'Connect a fixture VPN before this case to verify VPN persistence.' }
        Set-LanguagePreference
        $process = Start-TestProcess
        $state.ProcessId = $process.Id; $state.StartTimeTicks = $process.StartTime.ToUniversalTime().Ticks.ToString(); Save-State
        $window = Wait-MainWindow $true
    } else {
        if (-not (Test-Path -LiteralPath $statePath)) { throw 'No saved case exists. Run launch first.' }
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.UserSID -ne $identity.User.Value -or $state.SessionId -ne $currentSession) { throw 'This case belongs to a different Windows user/session.' }
        if ($Phase -eq 'restore') {
            if ($null -ne (Get-GuiProcess)) { throw 'Quit the test UI normally before restoring its language setting.' }
            Restore-LanguagePreference
            $report.ServiceSnapshotSkipped = 'Preference restoration does not depend on service availability.'
        } else { $report.BeforeService = Get-ServiceState }
        if ($Phase -eq 'close') {
            $window = Wait-MainWindow $true
            if (-not [Vault443NativeUI]::PostMessage([IntPtr]$window.Handle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)) { throw 'WM_CLOSE failed.' }
            $window = Wait-MainWindow $false # Process must survive: close hides to tray.
            Start-Sleep -Milliseconds 500
        } elseif ($Phase -eq 'reopen') {
            $window = Reopen-Existing
        } elseif ($Phase -eq 'quit') {
            $window = Reopen-Existing
            [Vault443NativeUI]::SetForegroundWindow([IntPtr]$window.Handle) | Out-Null
            Start-Sleep -Milliseconds 250
            if (-not [Vault443NativeUI]::QuitShortcut([IntPtr]$window.Handle)) { throw 'Could not send Ctrl+Q to the verified foreground app; quit it manually. No process was killed.' }
            $process = Get-GuiProcess
            if ($null -ne $process -and -not $process.WaitForExit(10000)) { throw 'Ctrl+Q did not quit the UI within 10 seconds. No process was killed.' }
            $state.Completed = $true
            Restore-LanguagePreference
            Start-Sleep -Milliseconds 500
        }
    }
    $report.AppPath = $state.AppPath; $report.LanguagePreference = $state.Language
    $report.QPAPlatformOverride = 'windows'; $report.Demo = $false
    $report.QtScaleFactor = $state.QtScaleFactor; $report.AppReferenceScale = $state.AppScale
    $report.ProcessId = $state.ProcessId; $report.ProcessRunning = $null -ne (Get-GuiProcess)
    $report.Windows = @([Vault443NativeUI]::Windows([uint32]$state.ProcessId))
    $main = Get-MainWindow
    if ($null -ne $main) {
        $report.WindowOSDpi = $main.Dpi; $report.WindowOSScalePercent = 100.0 * $main.Dpi / 96.0
        if ($CapturePng -and $main.Visible -and -not $main.Minimized) {
            Add-Type -AssemblyName System.Drawing
            $bitmap = New-Object Drawing.Bitmap($main.Width, $main.Height)
            $graphics = [Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.CopyFromScreen($main.Left, $main.Top, 0, 0, $bitmap.Size)
                $png = Join-Path $ReportDirectory ($CaseName + '-' + $Phase + '.png')
                $bitmap.Save($png, [Drawing.Imaging.ImageFormat]::Png)
                $report.ScreenCapture = $png; $report.ScreenCaptureNote = 'Desktop pixels at HWND bounds; may include occlusion. Inspect a separate VM screenshot too.'
            } finally { $graphics.Dispose(); $bitmap.Dispose() }
        }
    }
    if ($Phase -ne 'restore') {
        $report.AfterService = Get-ServiceState
        $before = $report.BeforeService | ConvertTo-Json -Compress -Depth 12
        $after = $report.AfterService | ConvertTo-Json -Compress -Depth 12
        $report.ServiceStateUnchanged = $before -eq $after
        $report.ActiveVPNPersistenceVerified = $report.ServiceStateUnchanged -and $report.BeforeService.HasActiveVPN
        if (-not $report.ServiceStateUnchanged) { throw 'Stable VPN service identity/state changed during the UI operation; inspect the before/after report.' }
        if ($state.RequireActiveVPN -and -not $report.ActiveVPNPersistenceVerified) { throw 'No active VPN was available to verify persistence.' }
    }
    $state.LastPhase = $Phase; Save-State
    $report.LanguageRestored = $state.LanguageRestored; $report.Result = 'pass'
} catch {
    $report.Result = 'fail'; $report.Error = $_.Exception.Message
    if ($Phase -eq 'launch' -and $null -ne $state -and $null -eq (Get-GuiProcess)) {
        Restore-LanguagePreference
    }
} finally {
    if ($previousDpiContext -ne [IntPtr]::Zero) { [Vault443NativeUI]::SetThreadDpiAwarenessContext($previousDpiContext) | Out-Null }
    $reportPath = Join-Path $ReportDirectory ($CaseName + '-' + $Phase + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '.json')
    $report.ReportFile = $reportPath
    $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    $report | ConvertTo-Json -Depth 16
}
if ($report.Result -ne 'pass') { throw $report.Error }
