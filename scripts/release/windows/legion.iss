; Rendered only by finalize-installer.mjs.  Keep payload roots explicit: a
; Windows installer must never package a checkout, build output, or symlink.
#define ProductVersion "@@VERSION@@"
#define SourceRoot "@@SOURCE_ROOT@@"
#define OutputRoot "@@OUTPUT_ROOT@@"
#define SetupName "@@SETUP_NAME@@"

[Setup]
AppId={{A34A13B9-B8BC-4A06-8D7E-6CD71298F27E}
AppName=Legion
AppVersion={#ProductVersion}
AppPublisher=Orthic Labs
DefaultDirName={localappdata}\Orthic Labs\Legion
DefaultGroupName=Legion
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputRoot}
OutputBaseFilename={#SetupName}
Compression=lzma2
SolidCompression=yes
UninstallDisplayName=Legion
Uninstallable=yes

[Files]
Source: "{#SourceRoot}\bin\*"; DestDir: "{app}\versions\{#ProductVersion}\bin"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\plugin\*"; DestDir: "{app}\versions\{#ProductVersion}\plugin"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\share\*"; DestDir: "{app}\versions\{#ProductVersion}\share"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Legion"; Filename: "{app}\current\bin\legion.exe"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
const PathKey = 'Environment';

procedure BroadcastEnvironmentChange;
var
  ResultCode: DWORD;
begin
  SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
    Integer(PChar('Environment')), SMTO_ABORTIFHUNG, 5000, ResultCode);
end;

function PathContains(const Value, Segment: String): Boolean;
begin
  Result := Pos(';' + Lowercase(Segment) + ';', ';' + Lowercase(Value) + ';') > 0;
end;

procedure AddCurrentToUserPath;
var
  Existing, Segment: String;
begin
  Segment := ExpandConstant('{app}\current\bin');
  if not RegQueryStringValue(HKCU, PathKey, 'Path', Existing) then Existing := '';
  if not PathContains(Existing, Segment) then begin
    if Existing <> '' then Existing := Existing + ';';
    RegWriteExpandStringValue(HKCU, PathKey, 'Path', Existing + Segment);
    BroadcastEnvironmentChange;
  end;
end;

procedure RemoveCurrentFromUserPath;
var
  Existing, Segment: String;
begin
  Segment := ExpandConstant('{app}\current\bin');
  if RegQueryStringValue(HKCU, PathKey, 'Path', Existing) then begin
    StringChangeEx(Existing, ';' + Segment, '', True);
    StringChangeEx(Existing, Segment + ';', '', True);
    if CompareText(Existing, Segment) = 0 then Existing := '';
    RegWriteExpandStringValue(HKCU, PathKey, 'Path', Existing);
    BroadcastEnvironmentChange;
  end;
end;

procedure ActivateCurrent;
var
  CurrentPath, VersionPath, Params: String;
  ResultCode: Integer;
begin
  CurrentPath := ExpandConstant('{app}\current');
  VersionPath := ExpandConstant('{app}\versions\{#ProductVersion}');
  RemoveDir(CurrentPath);
  Params := '/c mklink /J "' + CurrentPath + '" "' + VersionPath + '"';
  if not Exec(ExpandConstant('{cmd}'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException('Could not activate Legion current install');
  if ResultCode <> 0 then RaiseException('Could not activate Legion current install');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    ActivateCurrent;
    AddCurrentToUserPath;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then begin
    RemoveCurrentFromUserPath;
    RemoveDir(ExpandConstant('{app}\current'));
  end;
end;
