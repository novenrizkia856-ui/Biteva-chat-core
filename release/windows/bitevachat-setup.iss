; ==========================================================================
; Bitevachat Installer - Inno Setup Script
; ==========================================================================
; Build: ISCC.exe bitevachat-setup.iss
;
; Directory structure:
;
;   bitevachat-setup.iss
;   files/
;     icon.ico
;     LICENSE.txt
;   bin/
;     bitevachat.exe
;     bitevachat-gui.exe
;     bitevachat-node.exe
;
; ==========================================================================

#define MyAppName      "Bitevachat"
#define MyAppVersion   "1.0"
#define MyAppPublisher "Biteva"
#define MyAppURL       "https://bitevachat.net"
#define MyAppExeName   "bitevachat-gui.exe"

[Setup]
AppId={{B17EFA01-3C8D-4A2F-9E6B-DC5A72F08E4A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=files\LICENSE.txt
OutputDir=output
OutputBaseFilename=BitevachatSetup-{#MyAppVersion}
Compression=lzma2/ultra
SolidCompression=yes
SetupIconFile=files\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checked
Name: "launchstartup"; Description: "Start Bitevachat when Windows starts"; GroupDescription: "System:"

[Files]
Source: "bin\bitevachat-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\bitevachat-node.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\bitevachat.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "files\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "files\icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--minimized"; Tasks: launchstartup

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Code]
procedure KillRunningProcesses();
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM bitevachat-gui.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM bitevachat-node.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM bitevachat.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  KillRunningProcesses();
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    KillRunningProcesses();
end;
