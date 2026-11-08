; Inno Setup 7.1.1, native x64. All payload paths come from package.py.
#ifndef StageDir
  #error StageDir must name the complete Windows runtime staging directory
#endif
#ifndef OutputDir
  #error OutputDir must name the local installer output directory
#endif
#ifndef AppVersion
  #error AppVersion is required
#endif

[Setup]
AppId={{B7547E6A-E316-4C92-9407-1B0F0D4A3443}
AppName=Vault 443
AppVersion={#AppVersion}
AppPublisher=Vault 443
AppPublisherURL=https://github.com/RealLeo/vault443
DefaultDirName={autopf}\Vault443
DefaultGroupName=Vault 443
DisableDirPage=no
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
AllowUNCPath=no
AllowNetworkDrive=no
SetupArchitecture=x64
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19045
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename=Vault443-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#SourcePath}\vault443.ico
SetupLogging=yes
CloseApplications=yes
CloseApplicationsFilter=*.exe,*.dll
RestartApplications=no
UninstallDisplayIcon={app}\vault443.exe
UninstallDisplayName=Vault 443
SignedUninstaller=no
VersionInfoVersion={#AppVersion}
VersionInfoCompany=Vault 443
VersionInfoDescription=Vault 443 Windows x64 installer
LicenseFile={#StageDir}\licenses\Vault443-LICENSE.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"; InfoAfterFile: "{#StageDir}\INSTALLATION-en.txt"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"; InfoAfterFile: "{#StageDir}\INSTALLATION-ru.txt"

[CustomMessages]
english.ServiceStopFailed=The existing VPN service could not stop safely. Close Vault 443 and retry. No files have been replaced.
russian.ServiceStopFailed=Не удалось безопасно остановить службу VPN. Закройте Vault 443 и повторите установку. Файлы не заменены.
english.InstallLocation=Choose an empty folder on a fixed local disk with protected parent folders. Network paths, links and folders writable by other users are not supported. No existing service has been stopped and no application files have been copied.
russian.InstallLocation=Выберите пустую папку на локальном несъёмном диске с защищёнными родительскими каталогами. Сетевые пути, ссылки и папки, доступные другим пользователям для изменения, не поддерживаются. Существующая служба не остановлена, файлы приложения не скопированы.
english.UpgradeLocation=Updates keep the existing installation folder. To move Vault 443, uninstall it with profiles retained, then install it in the new folder.
russian.UpgradeLocation=Обновление сохраняет прежнюю папку установки. Для переноса Vault 443 удалите приложение с сохранением профилей, затем установите его в новую папку.
english.ServiceInstallFailed=The VPN service could not start. The application files and profiles have been retained. Run this installer again to repair the installation.
russian.ServiceInstallFailed=Не удалось запустить службу VPN. Файлы приложения и профили сохранены. Повторите установку для восстановления.
english.OperatorGrantFailed=The VPN service is installed, but access for the active user could not be granted. Start Vault 443 and approve its request for administrator access.
russian.OperatorGrantFailed=Служба VPN установлена, но не удалось предоставить доступ активному пользователю. Запустите Vault 443 и подтвердите запрос прав администратора.
english.NetworkCleanupFailed=VPN network restoration failed. Uninstallation was stopped and application files and profiles were retained. Reconnect unavailable network adapters, then retry uninstallation.
russian.NetworkCleanupFailed=Не удалось восстановить сетевые настройки VPN. Удаление остановлено, файлы приложения и профили сохранены. Подключите недоступные сетевые адаптеры и повторите удаление.
english.InterfaceCloseFailed=Vault 443 could not close its interface safely. Close Vault 443 using Quit interface in every signed-in Windows session, then retry uninstallation. Application files, the service and profiles have been retained.
russian.InterfaceCloseFailed=Не удалось безопасно завершить интерфейс Vault 443. Выберите выход из интерфейса в каждой вошедшей сессии Windows и повторите удаление. Файлы приложения, служба и профили сохранены.
english.OpenApplication=Open Vault 443
russian.OpenApplication=Открыть Vault 443

[Files]
; Never execute privileged installer code from a user-writable exchange/TEMP.
; This embedded copy is authenticated again after copying to a protected folder.
Source: "{#StageDir}\vault443d.exe"; DestName: "vault443-setup-helper.exe"; Flags: dontcopy
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs notimestamp; Excludes: "build-manifest.json,*.pdb,*.ilk,*.exp,*.lib"
; This final callback runs after the whole runtime is present, including DLLs.
Source: "{#StageDir}\build-manifest.json"; DestDir: "{app}"; Flags: ignoreversion notimestamp; AfterInstall: ConfigureInstalledService

[Icons]
Name: "{autoprograms}\Vault 443"; Filename: "{app}\vault443.exe"; WorkingDir: "{app}"

[Run]
Filename: "{app}\vault443.exe"; Description: "{cm:OpenApplication}"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent runasoriginaluser; Check: InstallationOperational

[Code]
const
  SC_MANAGER_CONNECT = $0001;
  SERVICE_QUERY_STATUS = $0004;
  SERVICE_START = $0010;
  SERVICE_STOP = $0020;
  SERVICE_CONTROL_STOP = $0001;
  SERVICE_STOPPED = $0001;
  SERVICE_STOP_PENDING = $0003;
  SERVICE_RUNNING = $0004;
  ERROR_SERVICE_DOES_NOT_EXIST = 1060;
  ERROR_SERVICE_NOT_ACTIVE = 1062;
  TH32CS_SNAPPROCESS = $00000002;
  PROCESS_QUERY_LIMITED_INFORMATION = $00001000;
  ERROR_INVALID_PARAMETER = 87;
  ERROR_NO_MORE_FILES = 18;

type
  { SECURITY_ATTRIBUTES uses native pointer alignment in x64 Setup. }
  TNativeSecurityAttributes = record
    Length: DWORD;
    AlignmentPad: DWORD;
    SecurityDescriptor: NativeUInt;
    InheritHandle: BOOL;
    TailPad: DWORD;
  end;
  TServiceStatus = record
    ServiceType: DWORD;
    CurrentState: DWORD;
    ControlsAccepted: DWORD;
    Win32ExitCode: DWORD;
    ServiceSpecificExitCode: DWORD;
    CheckPoint: DWORD;
    WaitHint: DWORD;
  end;
  { PROCESSENTRY32W has explicit Win64 padding. SetupArchitecture is x64. }
  TNativeProcessEntry = record
    Size: DWORD;
    Usage: DWORD;
    ProcessId: DWORD;
    AlignmentPad: DWORD;
    DefaultHeapId: NativeUInt;
    ModuleId: DWORD;
    ThreadCount: DWORD;
    ParentProcessId: DWORD;
    BasePriority: LONG;
    Flags: DWORD;
    ExeFile: array[0..259] of Char;
    TailPad: DWORD;
  end;
  TRestartManagerProcess = record
    ProcessId: DWORD;
    StartTime: TFileTime;
  end;
  TRestartManagerProcesses = array of TRestartManagerProcess;

function OpenSCManager(MachineName, DatabaseName: NativeUInt; Access: DWORD): THandle;
  external 'OpenSCManagerW@advapi32.dll stdcall';
function OpenService(Manager: THandle; ServiceName: String; Access: DWORD): THandle;
  external 'OpenServiceW@advapi32.dll stdcall';
function QueryServiceStatus(Service: THandle; var Status: TServiceStatus): BOOL;
  external 'QueryServiceStatus@advapi32.dll stdcall';
function ControlService(Service: THandle; Control: DWORD; var Status: TServiceStatus): BOOL;
  external 'ControlService@advapi32.dll stdcall';
function CloseServiceHandle(Handle: THandle): BOOL;
  external 'CloseServiceHandle@advapi32.dll stdcall';
function WTSGetActiveConsoleSessionId: DWORD;
  external 'WTSGetActiveConsoleSessionId@kernel32.dll stdcall';
function CurrentSetupProcessId: DWORD;
  external 'GetCurrentProcessId@kernel32.dll stdcall';
function QuerySetupProcessSession(ProcessId: DWORD; var SessionId: DWORD): BOOL;
  external 'ProcessIdToSessionId@kernel32.dll stdcall';
function ConvertDirectorySecurity(SDDL: String; Revision: DWORD;
  var Descriptor: NativeUInt; var Size: DWORD): BOOL;
  external 'ConvertStringSecurityDescriptorToSecurityDescriptorW@advapi32.dll stdcall setuponly';
function CreateProtectedDirectory(Path: String; var Attributes: TNativeSecurityAttributes): BOOL;
  external 'CreateDirectoryW@kernel32.dll stdcall setuponly';
function FreeSecurityDescriptor(Descriptor: NativeUInt): NativeUInt;
  external 'LocalFree@kernel32.dll stdcall setuponly';
function CreateHelperFile(Path: String; Access, Share: DWORD;
  var Attributes: TNativeSecurityAttributes; Disposition, Flags: DWORD;
  Template: NativeUInt): THandle;
  external 'CreateFileW@kernel32.dll stdcall setuponly';
function CloseSetupHandle(Handle: THandle): BOOL;
  external 'CloseHandle@kernel32.dll stdcall setuponly';
function CreateProcessSnapshot(Flags, ProcessId: DWORD): THandle;
  external 'CreateToolhelp32Snapshot@kernel32.dll stdcall uninstallonly';
function FirstProcess(Snapshot: THandle; var Entry: TNativeProcessEntry): BOOL;
  external 'Process32FirstW@kernel32.dll stdcall uninstallonly';
function NextProcess(Snapshot: THandle; var Entry: TNativeProcessEntry): BOOL;
  external 'Process32NextW@kernel32.dll stdcall uninstallonly';
function OpenGuiProcess(Access: DWORD; Inherit: BOOL; ProcessId: DWORD): THandle;
  external 'OpenProcess@kernel32.dll stdcall uninstallonly';
function QueryGuiImage(Process: THandle; Flags: DWORD; ImageName: String; var Size: DWORD): BOOL;
  external 'QueryFullProcessImageNameW@kernel32.dll stdcall uninstallonly';
function QueryGuiTimes(Process: THandle; var Creation, Finished, Kernel, User: TFileTime): BOOL;
  external 'GetProcessTimes@kernel32.dll stdcall uninstallonly';
function CloseNativeHandle(Handle: THandle): BOOL;
  external 'CloseHandle@kernel32.dll stdcall uninstallonly';
function RmStartSession(var Session: DWORD; Flags: DWORD; SessionKey: String): DWORD;
  external 'RmStartSession@rstrtmgr.dll stdcall uninstallonly';
function RmRegisterGui(Session, FileCount: DWORD; FileNames: NativeUInt;
  ProcessCount: DWORD; var Process: TRestartManagerProcess;
  ServiceCount: DWORD; ServiceNames: NativeUInt): DWORD;
  external 'RmRegisterResources@rstrtmgr.dll stdcall uninstallonly';
function RmShutdown(Session, Flags: DWORD; Callback: NativeUInt): DWORD;
  external 'RmShutdown@rstrtmgr.dll stdcall uninstallonly';
function RmEndSession(Session: DWORD): DWORD;
  external 'RmEndSession@rstrtmgr.dll stdcall uninstallonly';

var
  StoppedExistingService: Boolean;
  ServiceConfigured: Boolean;
  SetupResultCode: Integer;
  ExistingInstallDir: String;
  PrivateHelperDir: String;

function PreviousInstallDir: String;
begin
  Result := '';
  RegQueryStringValue(HKLM64,
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B7547E6A-E316-4C92-9407-1B0F0D4A3443}_is1',
    'InstallLocation', Result);
  if Result <> '' then Result := RemoveBackslashUnlessRoot(ExpandFileName(Result));
end;

procedure InitializeWizard;
var
  Explanation: TNewStaticText;
begin
  ExistingInstallDir := PreviousInstallDir;
  if ExistingInstallDir <> '' then begin
    { /DIR overrides are checked again in PrepareToInstall. Do not silently
      install a second copy or move a service while an upgrade is in progress. }
    WizardForm.DirEdit.ReadOnly := True;
    WizardForm.DirBrowseButton.Enabled := False;
    Explanation := TNewStaticText.Create(WizardForm);
    Explanation.Parent := WizardForm.SelectDirPage;
    Explanation.Left := WizardForm.DirEdit.Left;
    Explanation.Top := WizardForm.DirEdit.Top + WizardForm.DirEdit.Height + ScaleY(12);
    Explanation.Width := WizardForm.DirEdit.Width + WizardForm.DirBrowseButton.Width + ScaleX(8);
    Explanation.Height := ScaleY(64);
    Explanation.WordWrap := True;
    Explanation.Caption := CustomMessage('UpgradeLocation');
  end;
end;

function PrepareAuthenticatedHelper: Boolean;
var
  Candidate, Helper: String;
  Attributes: TNativeSecurityAttributes;
  Descriptor: NativeUInt;
  HelperHandle: THandle;
  Data: AnsiString;
  Size: DWORD;
begin
  Result := False;
  if PrivateHelperDir = '' then begin
    Candidate := ExpandConstant('{autopf}\Vault443.Setup-') +
      IntToStr(CurrentSetupProcessId) + '-' + GetDateTimeString('yyyymmddhhnnsszzz', #0, #0);
    Descriptor := 0;
    Size := 0;
    if not ConvertDirectorySecurity(
      'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)',
      1, Descriptor, Size) then Exit;
    try
      Attributes.Length := 24;
      Attributes.AlignmentPad := 0;
      Attributes.SecurityDescriptor := Descriptor;
      Attributes.InheritHandle := False;
      Attributes.TailPad := 0;
      { Never adopt/re-ACL an existing directory, even if the name collides. }
      if not CreateProtectedDirectory(Candidate, Attributes) then Exit;
      PrivateHelperDir := Candidate;
    finally
      FreeSecurityDescriptor(Descriptor);
    end;
  end;
  Helper := AddBackslash(PrivateHelperDir) + 'vault443-setup-helper.exe';
  try
    if not FileExists(Helper) then begin
      ExtractTemporaryFile('vault443-setup-helper.exe');
      if not LoadStringFromFile(ExpandConstant('{tmp}\vault443-setup-helper.exe'), Data) then Exit;
      Descriptor := 0;
      if not ConvertDirectorySecurity(
        'O:BAG:BAD:P(A;FA;;;SY)(A;FA;;;BA)(A;0x1200a9;;;BU)',
        1, Descriptor, Size) then Exit;
      try
        Attributes.Length := 24;
        Attributes.AlignmentPad := 0;
        Attributes.SecurityDescriptor := Descriptor;
        Attributes.InheritHandle := False;
        Attributes.TailPad := 0;
        { CREATE_NEW with the final owner/DACL from birth. CopyFile/source
          security and the creator's implicit owner rights cannot introduce a
          writable interval, even with alternate-credential UAC elevation. }
        HelperHandle := CreateHelperFile(Helper, $40000000, 1, Attributes, 1, $80, 0);
        if HelperHandle = THandle(-1) then Exit;
        CloseSetupHandle(HelperHandle);
      finally
        FreeSecurityDescriptor(Descriptor);
      end;
      { Existing-file truncation preserves that explicit owner/DACL. AnsiString
        retains every binary byte, including NUL; no source ACL is copied. }
      if not SaveStringToFile(Helper, Data, False) then Exit;
    end;
    { A replacement in the temporary extraction directory can only fail this
      check; it can never be executed. The authenticated destination is RX. }
    Result := CompareText(GetSHA256OfFile(Helper),
      '{#GetSHA256OfFile(StageDir + "\vault443d.exe")}') = 0;
  except
    Log('Could not prepare the authenticated installation-path helper.');
    Result := False;
  end;
end;

function ServiceHandle(Access: DWORD; var OpenError: DWORD): THandle;
var
  Manager: THandle;
begin
  Result := 0;
  OpenError := 0;
  Manager := OpenSCManager(0, 0, SC_MANAGER_CONNECT);
  if Manager = 0 then begin
    OpenError := DLLGetLastError;
    Exit;
  end;
  try
    Result := OpenService(Manager, 'Vault443', Access);
    if Result = 0 then OpenError := DLLGetLastError;
  finally
    CloseServiceHandle(Manager);
  end;
end;

function WaitForService(State: DWORD; TimeoutMS: Integer): Boolean;
var
  Service: THandle;
  Status: TServiceStatus;
  Elapsed: Integer;
  OpenError: DWORD;
begin
  Result := False;
  Service := ServiceHandle(SERVICE_QUERY_STATUS, OpenError);
  if Service = 0 then Exit;
  try
    Elapsed := 0;
    repeat
      if not QueryServiceStatus(Service, Status) then Exit;
      if Status.CurrentState = State then begin
        Result := True;
        Exit;
      end;
      Sleep(100);
      Elapsed := Elapsed + 100;
    until Elapsed >= TimeoutMS;
  finally
    CloseServiceHandle(Service);
  end;
end;

function StopExistingService: Boolean;
var
  Service: THandle;
  Status: TServiceStatus;
  OpenError: DWORD;
begin
  Result := False;
  Service := ServiceHandle(SERVICE_QUERY_STATUS or SERVICE_STOP, OpenError);
  if Service = 0 then begin
    Result := OpenError = ERROR_SERVICE_DOES_NOT_EXIST;
    Exit;
  end;
  try
    if not QueryServiceStatus(Service, Status) then Exit;
    if Status.CurrentState = SERVICE_STOPPED then begin
      Result := True;
      Exit;
    end;
    if Status.CurrentState <> SERVICE_STOP_PENDING then begin
      if not ControlService(Service, SERVICE_CONTROL_STOP, Status) then begin
        if DLLGetLastError <> ERROR_SERVICE_NOT_ACTIVE then Exit;
      end;
    end;
    StoppedExistingService := True;
  finally
    CloseServiceHandle(Service);
  end;
  Result := WaitForService(SERVICE_STOPPED, 30000);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Destination, Helper: String;
  ResultCode: Integer;
begin
  Result := '';
  Destination := RemoveBackslashUnlessRoot(ExpandFileName(WizardDirValue));
  if Pos('"', Destination) <> 0 then begin
    Result := CustomMessage('InstallLocation');
    Exit;
  end;
  ExistingInstallDir := PreviousInstallDir;
  if (ExistingInstallDir <> '') and (CompareText(Destination, ExistingInstallDir) <> 0) then begin
    Result := CustomMessage('UpgradeLocation');
    Exit;
  end;
  if not PrepareAuthenticatedHelper then begin
    Result := CustomMessage('InstallLocation');
    Exit;
  end;
  Helper := AddBackslash(PrivateHelperDir) + 'vault443-setup-helper.exe';
  if not Exec(Helper, '--prepare-install-path="' + Destination + '"',
    PrivateHelperDir, SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then begin
    Log('Protected installation path validation failed.');
    Result := CustomMessage('InstallLocation');
    Exit;
  end;
  { Stop only: persistent intent/guard survive an upgrade. Release is reserved
    for explicit uninstall, so a failed update cannot silently remove protection. }
  if not StopExistingService then Result := CustomMessage('ServiceStopFailed');
end;

procedure ConfigureInstalledService;
var
  ResultCode: Integer;
  ActiveConsoleSessionId, InstallerSessionId: DWORD;
  ConsoleSessionMatches: Boolean;
begin
  ServiceConfigured := Exec(ExpandConstant('{app}\vault443d.exe'),
    '--install-service', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);
  ServiceConfigured := ServiceConfigured and (ResultCode = 0);
  if ServiceConfigured then ServiceConfigured := WaitForService(SERVICE_RUNNING, 30000);
  if not ServiceConfigured then begin
    SetupResultCode := 10;
    Log(CustomMessage('ServiceInstallFailed'));
    if not WizardSilent then MsgBox(CustomMessage('ServiceInstallFailed'), mbError, MB_OK);
    Exit;
  end;
  { The helper derives the active console SID. It never trusts an installer-
    supplied user identifier, including alternate-credential UAC elevation. }
  ActiveConsoleSessionId := WTSGetActiveConsoleSessionId;
  InstallerSessionId := $FFFFFFFF;
  ConsoleSessionMatches := False;
  if ActiveConsoleSessionId <> $FFFFFFFF then begin
    if QuerySetupProcessSession(CurrentSetupProcessId, InstallerSessionId) then
      ConsoleSessionMatches := (InstallerSessionId <> 0) and
        (InstallerSessionId = ActiveConsoleSessionId);
  end;
  if ConsoleSessionMatches then begin
    if not Exec(ExpandConstant('{app}\vault443-access.exe'), '--grant-console',
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then begin
      SetupResultCode := 11;
      Log(CustomMessage('OperatorGrantFailed'));
      if not WizardSilent then MsgBox(CustomMessage('OperatorGrantFailed'), mbError, MB_OK);
    end;
  end else
    Log('Console authorization deferred: setup is outside the active interactive console session.');
end;

function InstallationOperational: Boolean;
begin
  Result := ServiceConfigured and (SetupResultCode = 0);
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := SetupResultCode;
end;

procedure DeinitializeSetup;
var
  IgnoredCode: Integer;
begin
  { If a file-copy/installer failure rolls back an upgrade, restart the retained
    executable. This does not clear persistent intent or networking protection. }
  if StoppedExistingService and not ServiceConfigured and
     FileExists(ExpandConstant('{app}\vault443d.exe')) then
    Exec(ExpandConstant('{app}\vault443d.exe'), '--install-service',
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, IgnoredCode);
  if PrivateHelperDir <> '' then begin
    DeleteFile(AddBackslash(PrivateHelperDir) + 'vault443-setup-helper.exe');
    RemoveDir(PrivateHelperDir);
  end;
end;

function FindInstalledInterfaces(var Processes: TRestartManagerProcesses): Boolean;
var
  Snapshot, Process: THandle;
  Entry: TNativeProcessEntry;
  Name, ImageName, InstalledImage: String;
  ImageSize, Error: DWORD;
  Finished, Kernel, User: TFileTime;
  Unique: TRestartManagerProcess;
  Index, Count: Integer;
  More: BOOL;
begin
  Result := False;
  SetArrayLength(Processes, 0);
  InstalledImage := ExpandFileName(ExpandConstant('{app}\vault443.exe'));
  Snapshot := CreateProcessSnapshot(TH32CS_SNAPPROCESS, 0);
  try
    Entry.Size := 568;
    More := FirstProcess(Snapshot, Entry);
    if not More then Exit;
    repeat
      Name := '';
      for Index := 0 to 259 do begin
        if Entry.ExeFile[Index] = #0 then Break;
        Name := Name + Entry.ExeFile[Index];
      end;
      if CompareText(Name, 'vault443.exe') = 0 then begin
        Process := OpenGuiProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, Entry.ProcessId);
        if Process = 0 then begin
          { A process that exited between snapshot and OpenProcess is harmless.
            An inaccessible same-name process cannot be proven foreign. }
          Error := DLLGetLastError;
          if Error <> ERROR_INVALID_PARAMETER then begin
            Log('Cannot verify interface process ' + IntToStr(Entry.ProcessId) +
              ': Windows error ' + IntToStr(Error));
            Exit;
          end;
        end else begin
          try
            ImageSize := 32768;
            ImageName := StringOfChar(#0, ImageSize);
            if not QueryGuiImage(Process, 0, ImageName, ImageSize) then begin
              Log('Cannot verify interface executable path.');
              Exit;
            end;
            ImageName := Copy(ImageName, 1, ImageSize);
            if CompareText(ImageName, InstalledImage) = 0 then begin
              Unique.ProcessId := Entry.ProcessId;
              if not QueryGuiTimes(Process, Unique.StartTime, Finished, Kernel, User) then begin
                Log('Cannot verify interface process creation time.');
                Exit;
              end;
              Count := GetArrayLength(Processes);
              if Count >= 64 then begin
                Log('Too many installed interface instances; refusing uninstallation.');
                Exit;
              end;
              SetArrayLength(Processes, Count + 1);
              Processes[Count] := Unique;
            end;
          finally
            CloseNativeHandle(Process);
          end;
        end;
      end;
      More := NextProcess(Snapshot, Entry);
      if not More then begin
        Error := DLLGetLastError;
        if Error <> ERROR_NO_MORE_FILES then begin
          Log('Could not complete the interface process snapshot: ' + IntToStr(Error));
          Exit;
        end;
      end;
    until not More;
    Result := True;
  finally
    CloseNativeHandle(Snapshot);
  end;
end;

function CloseInstalledInterfaces: Boolean;
var
  Processes, Remaining: TRestartManagerProcesses;
  Session, Error: DWORD;
  SessionKey: String;
  Index, Elapsed: Integer;
begin
  Result := False;
  if not FindInstalledInterfaces(Processes) then Exit;
  if GetArrayLength(Processes) = 0 then begin
    Result := True;
    Exit;
  end;
  SessionKey := StringOfChar(#0, 33);
  Error := RmStartSession(Session, 0, SessionKey);
  if Error <> 0 then begin
    Log('Could not start interface shutdown session: ' + IntToStr(Error));
    Exit;
  end;
  try
    for Index := 0 to GetArrayLength(Processes) - 1 do begin
      { PID + creation time prevent PID reuse. No file/service resources are
        registered, so unrelated users of a DLL can never be shut down. }
      Error := RmRegisterGui(Session, 0, 0, 1, Processes[Index], 0, 0);
      if Error <> 0 then begin
        Log('Could not register installed interface: ' + IntToStr(Error));
        Exit;
      end;
      Log('Requesting graceful shutdown of verified interface PID ' +
        IntToStr(Processes[Index].ProcessId));
    end;
    { No RmForceShutdown. Qt handles WM_ENDSESSION with QApplication::quit;
      ordinary WM_CLOSE only hides the window to the tray. Restart Manager
      applies its bounded shutdown timeout. Cross-session restrictions or an
      unresponsive app must abort uninstall, never fall back to a process kill. }
    Error := RmShutdown(Session, 0, 0);
    if Error <> 0 then begin
      Log('Graceful interface shutdown failed: Windows error ' + IntToStr(Error));
      Exit;
    end;
  finally
    RmEndSession(Session);
  end;
  Elapsed := 0;
  repeat
    if not FindInstalledInterfaces(Remaining) then Exit;
    if GetArrayLength(Remaining) = 0 then begin
      Result := True;
      Exit;
    end;
    Sleep(100);
    Elapsed := Elapsed + 100;
  until Elapsed >= 10000;
  Log('Installed interface is still running after the shutdown deadline.');
end;

procedure RemoveOwnedAutostart;
var
  Users: TArrayOfString;
  Index: Integer;
  Key, Value, Executable: String;
begin
  { Only an exact application-owned value in loaded user hives is removed.
    Profile data, unrelated Run entries, and other users' settings are retained. }
  Executable := ExpandConstant('{app}\vault443.exe');
  if not RegGetSubkeyNames(HKU, '', Users) then Exit;
  for Index := 0 to GetArrayLength(Users) - 1 do begin
    Key := Users[Index] + '\Software\Microsoft\Windows\CurrentVersion\Run';
    if RegQueryStringValue(HKU, Key, 'Vault443', Value) and
      ((CompareText(Value, '"' + Executable + '"') = 0) or
       (CompareText(Value, Executable) = 0)) then
      RegDeleteValue(HKU, Key, 'Vault443');
  end;
end;

procedure CurUninstallStepChanged(Step: TUninstallStep);
var
  ResultCode: Integer;
begin
  if Step = usUninstall then begin
    { This runs before service/network cleanup and before deleting any payload.
      Failure preserves a working installation, including its service. }
    if not CloseInstalledInterfaces then begin
      Log(CustomMessage('InterfaceCloseFailed'));
      if not UninstallSilent then MsgBox(CustomMessage('InterfaceCloseFailed'), mbError, MB_OK);
      Abort;
    end;
    { Abort from this event is explicitly supported by Inno Setup. Nothing in
      the uninstall log is deleted until privileged restoration succeeds. }
    if not Exec(ExpandConstant('{app}\vault443d.exe'), '--uninstall-service',
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then begin
      Log(CustomMessage('NetworkCleanupFailed'));
      if not UninstallSilent then MsgBox(CustomMessage('NetworkCleanupFailed'), mbError, MB_OK);
      Abort;
    end;
    RemoveOwnedAutostart;
  end;
end;
