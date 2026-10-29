; Rendered only by xtask (release::windows_finalize_installer).  Keep payload roots explicit: a
; Windows installer must never package a checkout, build output, or symlink.
#define ProductVersion "@@VERSION@@"
#define SourceRoot "@@SOURCE_ROOT@@"
#define OutputRoot "@@OUTPUT_ROOT@@"
#define SetupName "@@SETUP_NAME@@"
#define DevelopmentInstall @@DEVELOPMENT_INSTALL@@

[Setup]
AppId={{A34A13B9-B8BC-4A06-8D7E-6CD71298F27E}
AppName=Legion
AppVersion={#ProductVersion}
AppPublisher=Orthic Labs
DefaultDirName={localappdata}\Orthic Labs\Legion
UsePreviousAppDir=no
SetupMutex=Local\OrthicLabs.Legion.Setup
DefaultGroupName=Legion
DisableProgramGroupPage=yes
; Legion installs without a wizard. Every page is disabled so no command
; can surface an interactive prompt, whatever flags reach the installer.
DisableWelcomePage=yes
DisableDirPage=yes
DisableReadyPage=yes
DisableReadyMemo=yes
DisableFinishedPage=yes
DisableStartupPrompt=yes
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
Source: "@@ACTIVATION_SCRIPT@@"; Flags: dontcopy
; Stage into a fresh root.  Same-version installs must not merge into the
; existing current tree: removed payload entries would otherwise survive.
; This directory is nonrunning staging only; activation moves it to current.
Source: "{#SourceRoot}\bin\*"; DestDir: "{app}\.next-version-{#ProductVersion}\bin"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\plugin\*"; DestDir: "{app}\.next-version-{#ProductVersion}\plugin"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\share\*"; DestDir: "{app}\.next-version-{#ProductVersion}\share"; Flags: ignoreversion recursesubdirs createallsubdirs
; Marketplace catalogs are sealed at payload root and must retain their exact
; release.json digests so native clients can bind their cache to stable current.
Source: "{#SourceRoot}\.claude-plugin\*"; DestDir: "{app}\.next-version-{#ProductVersion}\.claude-plugin"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceRoot}\.agents\plugins\*"; DestDir: "{app}\.next-version-{#ProductVersion}\.agents\plugins"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Legion"; Filename: "{app}\current\bin\legion.exe"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
const PathKey = 'Environment';
const WM_SETTINGCHANGE = $001A;
const SMTO_ABORTIFHUNG = $0002;
function SendMessageTimeout(hWnd: HWND; Msg: UINT; wParam: Longint; lParam: String; fuFlags: UINT; uTimeout: UINT; var lpdwResult: DWORD): Longint;
  external 'SendMessageTimeoutW@user32.dll stdcall';
var
  ActivationExitCode: Integer;
  DevelopmentRetryPrepared: Boolean;

procedure BroadcastEnvironmentChange;
var
  ResultCode: DWORD;
begin
  SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
    'Environment', SMTO_ABORTIFHUNG, 5000, ResultCode);
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
  Params: String;
  ResultCode: Integer;
begin
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\activate.ps1') +
    '" -InstallRoot "' + ExpandConstant('{app}') + '" -Version "{#ProductVersion}"';
  { Mode is fixed when this installer is built, never selected by caller flags. }
#if DevelopmentInstall
  Params := Params + ' -DevelopmentInstall';
  Params := Params + ' -InstallerPath "' + ExpandConstant('{srcexe}') + '"';
  if DevelopmentRetryPrepared then Params := Params + ' -ResumeDevelopmentRetry';
#endif
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    ActivationExitCode := 4;
    RaiseException('Could not launch Legion activation');
  end;
  Log('Legion activation exit=' + IntToStr(ResultCode));
  if ResultCode <> 0 then begin
    ActivationExitCode := 4;
    RaiseException('Could not activate Legion current install');
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := ActivationExitCode;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  Params: String;
begin
  DevelopmentRetryPrepared := False;
  { Always use this installer's bundled script, including retry preflight. }
  ExtractTemporaryFile('activate.ps1');
  { Preserve any unfinished or foreign stage rather than merging or deleting it.
    SetupMutex serializes installers before this check & all payload writes. }
  if DirExists(ExpandConstant('{app}\.next-version-{#ProductVersion}')) then begin
#if DevelopmentInstall
    Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\activate.ps1') +
      '" -InstallRoot "' + ExpandConstant('{app}') + '" -Version "{#ProductVersion}" -DevelopmentInstall -PrepareDevelopmentRetry -InstallerPath "' + ExpandConstant('{srcexe}') + '"';
    if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then begin
      Result := 'Could not validate interrupted Legion development replacement';
      Exit;
    end;
    if ResultCode <> 0 then begin
      Result := 'Preserving unfinished Legion payload stage; exact installer recovery could not be validated';
      Exit;
    end;
    DevelopmentRetryPrepared := True;
#else
    Result := 'Preserving unfinished Legion payload stage; recovery is required';
    Exit;
#endif
  end;
  { A client keeps `legion serve --stdio` running, and Windows will not replace
    a running executable, so an upgrade aborted with the previous version left
    in place. Stop the product's own processes first; clients restart the MCP
    server on their next request. Failure here is not fatal: the file-copy step
    reports anything still locked. }
  Exec(ExpandConstant('{cmd}'),
       '/c taskkill /F /IM legion.exe /IM legion-hook.exe /IM legion-mcp.exe >nul 2>&1',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1500);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    ActivateCurrent;
    AddCurrentToUserPath;
  end;
end;

{ Deregister native client marketplaces/plugins while the payload that knows
  how to remove them still exists.  Runs before any file deletion; returning
  False aborts the uninstall and leaves the payload in place (fail closed).  A
  missing executable means a broken install with nothing to deregister, so it
  is skipped.  The wait is bounded and the result must be status=complete, the
  same contract activate.ps1 enforces during rollback. }
function EscapePowerShellSingleQuoted(const Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '''', '''''', True);
end;

function InitializeUninstall: Boolean;
var
  Legion, Script, Params, Detail: String;
  ResultCode: Integer;
begin
  Result := True;
  Legion := ExpandConstant('{app}\current\bin\legion.exe');
  if not FileExists(Legion) then begin
    Log('Legion uninstall: ' + Legion + ' absent; skipping native client deregistration');
    Exit;
  end;
  Script := '$o = Join-Path $env:TEMP ''legion-uninstall-setup-remove.json''; ' +
    '$p = Start-Process -FilePath ''' + EscapePowerShellSingleQuoted(Legion) + ''' ' +
    '-ArgumentList ''--json'',''setup'',''remove'',''--confirm'' -PassThru -WindowStyle Hidden ' +
    '-RedirectStandardOutput $o; $null = $p.Handle; ' +
    'if (-not $p.WaitForExit(120000)) { try { $p.Kill() } catch {}; exit 124 }; ' +
    '$code = $p.ExitCode; if ($null -eq $code -or $code -ne 0) { exit 127 }; ' +
    'try { $r = Get-Content -Raw -LiteralPath $o | ConvertFrom-Json -ErrorAction Stop } catch { exit 125 }; ' +
    'if ($r.status -ne ''complete'') { exit 126 }; exit 0';
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Log('Legion uninstall: setup remove exit=' + IntToStr(ResultCode));
  if ResultCode <> 0 then begin
    Detail := 'Legion could not remove its native client registrations (exit ' + IntToStr(ResultCode) +
      '). Nothing was uninstalled; the installed payload was kept so the removal can be retried.';
    Log(Detail);
    SuppressibleMsgBox(Detail, mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then begin
    RemoveCurrentFromUserPath;
    RemoveDir(ExpandConstant('{app}\current'));
  end;
end;
