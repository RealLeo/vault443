# Windows PowerShell 5.1: powershell.exe -MTA -NoProfile -File .\set-display-scale.ps1 -Scale 150 -UiStatePath <ui-native-smoke state.json>
# Changes the real Windows Display scale through the documented Settings URI/UIA.
# No custom DPI registry/API, arbitrary control clicks, UAC, or VPN operations.
[CmdletBinding()]
param(
    [ValidateSet(100,150,200)][int]$Scale = 100,
    [string]$UiStatePath = (Join-Path $env:LOCALAPPDATA 'Vault443\ui-native-smoke\native-ui.state.json'),
    [string]$ReportDirectory = (Join-Path $env:LOCALAPPDATA 'Vault443\ui-native-smoke'),
    [switch]$InventoryOnly
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run without elevation as the signed-in console user.' }
if ($env:COMPUTERNAME -notin @('vault443-win10','vault443-win11')) { throw 'Only the named Windows acceptance VMs are allowed.' }
$machine = Get-CimInstance Win32_ComputerSystem
if ($machine.Model -notmatch 'VirtualBox') { throw 'This UI scale operation requires the private VirtualBox acceptance VM.' }
# The private ProgramData marker is deliberately unreadable to this user. The
# existing QA runner/root provide a read-only integrity marker without new UAC.
$qaRoot = 'C:\Program Files\Vault443QA'
$qaRunner = Join-Path $qaRoot 'qa-runner.ps1'
foreach ($path in @($qaRoot, $qaRunner)) {
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        ($path -eq $qaRoot -and -not $item.PSIsContainer) -or
        ($path -eq $qaRunner -and $item.PSIsContainer)) { throw 'The protected QA runner/root must be a regular file/directory without reparse points.' }
    $acl = Get-Acl -LiteralPath $path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'The QA runner/root must be owned by SYSTEM or Administrators.' }
    $rawAcl = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $rawAcl.DiscretionaryAcl) { throw 'The QA runner/root cannot have a null DACL.' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        # Data/append/EA/attribute writes, delete/delete-child, owner/DACL changes,
        # GENERIC_WRITE and GENERIC_ALL; ordinary Users read/execute is allowed.
        if ($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and
            (([long]$rule.FileSystemRights -band 0x500D0156) -ne 0)) { throw 'The QA runner/root grants write access to an untrusted account.' }
    }
}
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
if (-not ('Vault443DisplayScale' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class Vault443DisplayScale {
    public class Window { public long Handle; public uint ProcessId; public string Title; public string ClassName; public uint Dpi; }
    delegate bool EnumCallback(IntPtr window, IntPtr data);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumCallback callback, IntPtr data);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, EnumCallback callback, IntPtr data);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int size);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder text, int size);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] public static extern IntPtr GetWindowDpiAwarenessContext(IntPtr window);
    [DllImport("user32.dll")] public static extern int GetAwarenessFromDpiAwarenessContext(IntPtr context);
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
    public static Window[] Windows(uint wanted, bool includeChildOwner) {
        var result = new List<Window>();
        EnumWindows(delegate(IntPtr handle, IntPtr data) {
            if (!IsWindowVisible(handle)) return true;
            uint owner; GetWindowThreadProcessId(handle, out owner); bool matches=owner==wanted;
            // Windows 10 UWP Settings may be hosted by ApplicationFrameHost.
            if (!matches && includeChildOwner) EnumChildWindows(handle, delegate(IntPtr child, IntPtr unused) {
                uint process; GetWindowThreadProcessId(child, out process);
                if (process==wanted) matches=true; return !matches;
            }, IntPtr.Zero);
            if (!matches) return true;
            var title=new StringBuilder(1024); var name=new StringBuilder(256);
            GetWindowText(handle,title,title.Capacity); GetClassName(handle,name,name.Capacity);
            result.Add(new Window { Handle=handle.ToInt64(), ProcessId=owner, Title=title.ToString(), ClassName=name.ToString(), Dpi=GetDpiForWindow(handle) });
            return true;
        }, IntPtr.Zero);
        return result.ToArray();
    }
}
'@
}
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
if ($session -eq 0 -or $session -ne [Vault443DisplayScale]::WTSGetActiveConsoleSessionId()) { throw 'An active local console session is required.' }
[IO.Directory]::CreateDirectory($ReportDirectory) | Out-Null
$report = [ordered]@{TimeUTC=[DateTime]::UtcNow.ToString('o'); RequestedScale=$Scale; Result='inventory'; ScaleSelectionInvoked=$false;
    SessionId=$session; UserSID=$identity.User.Value; InventoryOnly=[bool]$InventoryOnly;
    Evidence='Real OS Display Scale UIA selection plus Vault443 GetDpiForWindow; QT_SCALE_FACTOR must be 1.';
    Sources=@('https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-settings',
        'https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.expandcollapsepattern',
        'https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.selectionitempattern.select',
        'https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdpiforwindow',
        'https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-threading',
        'https://learn.microsoft.com/en-us/dotnet/api/system.windows.automation.itemcontainerpattern.finditembyproperty',
        'https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-workingwithvirtualizeditems')}
$expanded = $null
function Get-ControlInventory($Root) {
    $condition = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::ComboBox)
    return @($Root.FindAll([Windows.Automation.TreeScope]::Descendants, $condition) | Select-Object -First 40 | ForEach-Object {
        $info = $_.Current
        [ordered]@{AutomationId=$info.AutomationId; Name=$info.Name; Enabled=$info.IsEnabled; Offscreen=$info.IsOffscreen;
            ProcessId=$info.ProcessId; Bounds=$info.BoundingRectangle.ToString(); Patterns=@($_.GetSupportedPatterns() | ForEach-Object ProgrammaticName)}
    })
}
function Get-ScaleCombo($Root) {
    $condition = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::ComboBox)
    $ids = @('SystemSettings_Display_Scale_ComboBox','SystemSettings_Display_ScaleComboBox',
        'SystemSettings_Display_Scaling_ComboBox','SystemSettings_Display_ScaleFactor_ComboBox','SystemSettings_Display_ScaleFactorComboBox',
        'SystemSettings_Display_Scaling_ItemSizeOverride_ComboBox')
    $names = @('Scale','Масштаб','Change the size of text, apps, and other items','Изменение размера текста, приложений и других элементов')
    return @($Root.FindAll([Windows.Automation.TreeScope]::Descendants, $condition) | Where-Object {
        $_.Current.IsEnabled -and -not $_.Current.IsOffscreen -and ($_.Current.AutomationId -in $ids -or $_.Current.Name -in $names)
    })
}
function Get-Percent([string]$Name) {
    $match = [regex]::Match($Name, '^\s*(\d{2,3})\s*%\s*(?:\([^\r\n]*\))?\s*$')
    if ($match.Success) { return [int]$match.Groups[1].Value }
    return 0
}
function Get-SelectedPercent($Combo) {
    $pattern = [Windows.Automation.SelectionPattern]$Combo.GetCurrentPattern([Windows.Automation.SelectionPattern]::Pattern)
    $items = @($pattern.Current.GetSelection())
    if ($items.Count -ne 1) { throw 'Scale ComboBox does not report exactly one selected item.' }
    return Get-Percent $items[0].Current.Name
}
function Realize-ScaleItem($Item) {
    $virtual = $null
    if ($Item.TryGetCurrentPattern([Windows.Automation.VirtualizedItemPattern]::Pattern, [ref]$virtual)) {
        ([Windows.Automation.VirtualizedItemPattern]$virtual).Realize()
        $report.VirtualizedItemsRealized = 1 + [int]$report.VirtualizedItemsRealized
    }
    return $Item
}
function Find-ContainerScaleItem($Combo) {
    $pattern = $null
    $supported = $Combo.TryGetCurrentPattern([Windows.Automation.ItemContainerPattern]::Pattern, [ref]$pattern)
    $report.ItemContainerSupported = $supported
    if (-not $supported) { throw 'Scale ComboBox does not expose ItemContainerPattern; visible items do not prove the complete option range.' }
    $container = [Windows.Automation.ItemContainerPattern]$pattern
    $name = [string]$Scale + '%'
    $found = $null
    try {
        $found = $container.FindItemByProperty($null, [Windows.Automation.AutomationElement]::NameProperty, $name)
        $report.ItemContainerExactName = $name
        $report.ItemContainerExactFound = $null -ne $found
        if ($null -ne $found) {
            $duplicate = $container.FindItemByProperty($found, [Windows.Automation.AutomationElement]::NameProperty, $name)
            if ($null -ne $duplicate) { throw 'Scale ItemContainer returned more than one exact requested-name item.' }
        }
    } catch {
        $report.ItemContainerNameLookupError = $_.Exception.Message
        # A provider may not support Name lookup. Its documented property=null
        # iterator is still safe to query within this same verified ComboBox.
        $found = $null
    }
    if ($null -ne $found) { return Realize-ScaleItem $found }
    $items = @(); $inventory = @(); $seen = @{}; $previous = $null
    $report.ItemContainerEnumerationComplete = $false
    for ($index = 0; $index -lt 32; $index++) {
        # .NET maps a null AutomationProperty to UIA propertyId=0: next item.
        $item = $container.FindItemByProperty($previous, $null, $null)
        if ($null -eq $item) { $report.ItemContainerEnumerationComplete = $true; break }
        $item = Realize-ScaleItem $item
        $runtime = [string]::Join(':', [string[]]$item.GetRuntimeId())
        if ($seen.ContainsKey($runtime)) { throw 'Scale ItemContainer repeated an item; enumeration is incomplete and no scale was selected.' }
        $seen[$runtime] = $true
        $items += $item
        $inventory += [ordered]@{Name=$item.Current.Name; Percent=(Get-Percent $item.Current.Name); Enabled=$item.Current.IsEnabled}
        $report.ItemContainerOptions = $inventory
        $previous = $item
    }
    $report.ItemContainerMaximumExposedPercent = ($inventory | Measure-Object -Property Percent -Maximum).Maximum
    if (-not $report.ItemContainerEnumerationComplete) { throw 'Scale ItemContainer inventory exceeded its bounded limit; no complete range is claimed.' }
    if (@($inventory | Where-Object Percent -eq 0).Count) { throw 'Scale ItemContainer returned an unrecognized non-percent item; inspect inventory without selecting a scale.' }
    $targets = @($items | Where-Object { $_.Current.IsEnabled -and (Get-Percent $_.Current.Name) -eq $Scale })
    if ($targets.Count -ne 1) { throw ('The complete ItemContainer inventory exposes no unique requested percent. Maximum exposed percent=' + $report.ItemContainerMaximumExposedPercent + '; no scale selection was made.') }
    return $targets[0]
}
try {
    # UIA runs outside the application UI thread; MTA is recommended by Microsoft.
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne [Threading.ApartmentState]::MTA) { throw 'Use powershell.exe -MTA -NoProfile -File for this UIAutomation script.' }
    Start-Process 'ms-settings:display'
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    $settingsWindow = $null
    do {
        $settings = @(Get-Process -Name SystemSettings -ErrorAction SilentlyContinue | Where-Object {
            $_.SessionId -eq $session -and $_.Path -eq (Join-Path $env:SystemRoot 'ImmersiveControlPanel\SystemSettings.exe')
        })
        $windows = @($settings | ForEach-Object { [Vault443DisplayScale]::Windows([uint32]$_.Id, $true) })
        $report.SettingsWindowsInventory = $windows
        if ($windows.Count -eq 1) { $settingsWindow = $windows[0]; break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $settingsWindow) { throw 'A unique visible window hosted by the protected SystemSettings.exe was not found.' }
    $report.SettingsWindow = $settingsWindow
    $root = [Windows.Automation.AutomationElement]::FromHandle([IntPtr]$settingsWindow.Handle)
    $report.ComboBoxes = Get-ControlInventory $root
    $report.MonitorCount = [Vault443DisplayScale]::GetSystemMetrics(80)
    if ($report.MonitorCount -ne 1) { throw 'Multiple monitors require explicit manual display selection; no scale control was changed.' }
    if (-not (Test-Path -LiteralPath $UiStatePath)) { throw 'Provide the real ui-native-smoke launch state to prove QT_SCALE_FACTOR=1 and the exact Vault443 PID.' }
    $state = Get-Content -LiteralPath $UiStatePath -Raw | ConvertFrom-Json
    if ($state.UserSID -ne $identity.User.Value -or $state.SessionId -ne $session -or [string]$state.QtScaleFactor -ne '1') { throw 'UI launch state must belong to this user/session and record QT_SCALE_FACTOR=1.' }
    $gui = Get-Process -Id $state.ProcessId -ErrorAction Stop
    if ($gui.SessionId -ne $session -or $gui.Path -ne $state.AppPath -or $gui.StartTime.ToUniversalTime().Ticks.ToString() -ne $state.StartTimeTicks) { throw 'Saved PID/start time does not identify the running Vault443 application.' }
    $guiWindows = @([Vault443DisplayScale]::Windows([uint32]$gui.Id, $false) | Where-Object { $_.Title -eq 'Vault 443' -and $_.ClassName -like 'Qt*QWindow*' })
    if ($guiWindows.Count -ne 1) { throw 'A unique visible real Vault443 QWindow was not found.' }
    $targetWindow = $guiWindows[0]
    $report.VaultWindowBefore = $targetWindow; $report.QtScaleFactor = '1'; $report.UiLaunchState = $UiStatePath
    $awareness = [Vault443DisplayScale]::GetAwarenessFromDpiAwarenessContext([Vault443DisplayScale]::GetWindowDpiAwarenessContext([IntPtr]$targetWindow.Handle))
    $report.VaultDpiAwareness = $awareness
    if ($awareness -ne 2) { throw 'Vault443 HWND is not per-monitor DPI aware; its DPI cannot prove this scale acceptance case.' }
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        $combos = @(Get-ScaleCombo $root)
        if ($combos.Count -eq 1) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $report.ComboBoxes = Get-ControlInventory $root
    if ($combos.Count -ne 1) { throw 'No unique visible recognized Display Scale ComboBox; inspect ComboBoxes inventory. No arbitrary controls were invoked.' }
    $combo = $combos[0]
    $report.ScaleControl = [ordered]@{AutomationId=$combo.Current.AutomationId; Name=$combo.Current.Name}
    $report.PreviousScale = Get-SelectedPercent $combo
    if (-not $report.PreviousScale) { throw 'The current scale is not a recognized percent value; no setting was changed.' }
    if ($InventoryOnly) { $report.Note = 'Read-only inventory requested; no ComboBox expansion or selection.' }
    else {
        $expanded = [Windows.Automation.ExpandCollapsePattern]$combo.GetCurrentPattern([Windows.Automation.ExpandCollapsePattern]::Pattern)
        $expanded.Expand()
        Start-Sleep -Milliseconds 400
        $condition = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::ListItem)
        $options = @($combo.FindAll([Windows.Automation.TreeScope]::Descendants, $condition))
        $report.Options = @($options | ForEach-Object { [ordered]@{Name=$_.Current.Name; Percent=(Get-Percent $_.Current.Name); Enabled=$_.Current.IsEnabled} })
        if (@($report.Options | Where-Object Percent -eq 0).Count) { throw 'Scale items are not exposed as percent ListItems under this ComboBox. No scale selection was made.' }
        $matches = @($options | Where-Object { $_.Current.IsEnabled -and (Get-Percent $_.Current.Name) -eq $Scale })
        if ($matches.Count -gt 1) { throw 'The requested percent is not unique among realized items; no scale selection was made.' }
        $item = if ($matches.Count -eq 1) { $matches[0] } else { Find-ContainerScaleItem $combo }
        if (-not $item.Current.IsEnabled -or (Get-Percent $item.Current.Name) -ne $Scale -or
            $item.Current.ControlType -ne [Windows.Automation.ControlType]::ListItem) { throw 'The located scale item is not an enabled percent ListItem matching the request.' }
        $scroll = $null
        if ($item.Current.IsOffscreen -and $item.TryGetCurrentPattern([Windows.Automation.ScrollItemPattern]::Pattern, [ref]$scroll)) {
            ([Windows.Automation.ScrollItemPattern]$scroll).ScrollIntoView()
            $report.TargetScrolledIntoView = $true
        }
        $report.TargetItem = [ordered]@{Name=$item.Current.Name; Percent=(Get-Percent $item.Current.Name); Offscreen=$item.Current.IsOffscreen}
        if ($item.Current.IsOffscreen) { throw 'The exact scale item could not be made visible through its documented ScrollItemPattern.' }
        $selection = [Windows.Automation.SelectionItemPattern]$item.GetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern)
        $report.ScaleSelectionInvoked = $true; $selection.Select()
        $expectedDpi = [uint32](96 * $Scale / 100)
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            Start-Sleep -Milliseconds 250
            $report.VaultDpiAfter = [Vault443DisplayScale]::GetDpiForWindow([IntPtr]$targetWindow.Handle)
            try {
                $current = @(Get-ScaleCombo $root)
                if ($current.Count -eq 1) { $report.SelectedScaleAfter = Get-SelectedPercent $current[0] }
            } catch { $report.SelectionReadError = $_.Exception.Message }
            if ($report.VaultDpiAfter -eq $expectedDpi -and $report.SelectedScaleAfter -eq $Scale) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        $report.ExpectedVaultDpi = $expectedDpi
        if ($report.VaultDpiAfter -ne $expectedDpi -or $report.SelectedScaleAfter -ne $Scale) { throw 'Settings selection and real Vault443 DPI did not both reach the requested scale. Inspect Settings; sign-out/custom-scale conditions need manual review.' }
        $report.Result = 'pass'
    }
} catch {
    $report.Error = $_.Exception.Message
    if ($report.ScaleSelectionInvoked) { $report.Result = 'verification-failed' }
    else { $report.Result = 'inventory-only-no-scale-change' }
} finally {
    if ($null -ne $expanded) { try { $expanded.Collapse() } catch { } }
    $path = Join-Path $ReportDirectory ('os-display-scale-' + $Scale + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff') + '.json')
    $report.ReportFile = $path
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
    $report | ConvertTo-Json -Depth 12
}
if ($report.Error) { throw $report.Error }
