#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

#ifndef PayloadRoot
  #error PayloadRoot must point to the PyInstaller distribution directory.
#endif

#ifndef OutputRoot
  #define OutputRoot ".\output"
#endif

; Configure the Setup installer section.
[Setup]
AppId={{C91BE3F5-5246-4F25-A8DF-0B1893EF5077}
AppName=Lynceus
AppVersion={#AppVersion}
AppPublisher=Lynceus
DefaultDirName={autopf}\Lynceus
DefaultGroupName=Lynceus
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir={#OutputRoot}
OutputBaseFilename=Lynceus-Setup-{#AppVersion}-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\control\LynceusControl.exe
SetupLogging=yes
CloseApplications=yes
RestartApplications=no

; Configure the Dirs installer section.
[Dirs]
Name: "{commonappdata}\Lynceus"
Name: "{commonappdata}\Lynceus\logs"
Name: "{commonappdata}\Lynceus\backups"

; Configure the Files installer section.
[Files]
Source: "{#PayloadRoot}\LynceusRuntime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#PayloadRoot}\LynceusControl\*"; DestDir: "{app}\control"; Flags: ignoreversion recursesubdirs createallsubdirs

; Configure the Icons installer section.
[Icons]
Name: "{commondesktop}\Lynceus Control Panel"; Filename: "{app}\control\LynceusControl.exe"; WorkingDir: "{app}"
Name: "{group}\Lynceus Control Panel"; Filename: "{app}\control\LynceusControl.exe"; WorkingDir: "{app}"
Name: "{group}\Open Lynceus"; Filename: "{sys}\rundll32.exe"; Parameters: "url.dll,FileProtocolHandler http://127.0.0.1:7321"
Name: "{group}\Uninstall Lynceus"; Filename: "{uninstallexe}"

; Configure the Run installer section.
[Run]
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\Lynceus"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F"; StatusMsg: "Securing Lynceus data and encryption keys..."; Flags: runhidden waituntilterminated
Filename: "{app}\runtime\LynceusRuntime.exe"; Parameters: "db upgrade"; WorkingDir: "{app}"; StatusMsg: "Preparing the Lynceus database..."; Flags: runhidden waituntilterminated
Filename: "{app}\control\LynceusControl.exe"; Parameters: "--create-admin"; WorkingDir: "{app}"; StatusMsg: "Waiting for initial administrator setup..."; Flags: waituntilterminated
Filename: "{app}\control\LynceusControl.exe"; Parameters: "--install-task"; WorkingDir: "{app}"; StatusMsg: "Installing the Lynceus server task..."; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Lynceus Server"" dir=in action=allow protocol=TCP localport=7321 profile=private,domain"; StatusMsg: "Configuring Windows Firewall..."; Flags: runhidden waituntilterminated
Filename: "{sys}\schtasks.exe"; Parameters: "/Run /TN ""Lynceus Server"""; StatusMsg: "Starting Lynceus..."; Flags: runhidden waituntilterminated
Filename: "{app}\control\LynceusControl.exe"; WorkingDir: "{app}"; Description: "Open Lynceus Control Panel"; Flags: postinstall nowait skipifsilent
Filename: "https://nmap.org/download.html"; Description: "Download Nmap/Npcap (required for network scans)"; Flags: postinstall shellexec nowait skipifsilent; Check: not NmapInstalled

; Configure the UninstallRun installer section.
[UninstallRun]
Filename: "{sys}\schtasks.exe"; Parameters: "/End /TN ""Lynceus Server"""; Flags: runhidden waituntilterminated; RunOnceId: "StopLynceusTask"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""Lynceus Server"" /F"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteLynceusTask"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Lynceus Server"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteLynceusFirewallRule"

; Configure the UninstallDelete installer section.
[UninstallDelete]
; ProgramData is intentionally preserved so upgrades/uninstalls do not destroy
; the database, encryption keys, logs, or backups.
Type: filesandordirs; Name: "{app}"

; Configure the Code installer section.
[Code]
function NmapInstalled: Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{pf}\Nmap\nmap.exe')) or
    FileExists(ExpandConstant('{pf32}\Nmap\nmap.exe')) or
    FileExists(ExpandConstant('{pf64}\Nmap\nmap.exe'));
end;
