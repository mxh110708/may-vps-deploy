#ifndef BundleRoot
  #error BundleRoot is required
#endif
#ifndef AppVersion
  #error AppVersion is required
#endif
#ifndef OutputPath
  #error OutputPath is required
#endif
#ifndef OutputName
  #define OutputName "may-vps-deploy-v" + AppVersion + "-windows-amd64-setup"
#endif
#ifndef IsTestBuild
  #define IsTestBuild "0"
#endif

[Setup]
; Independent May installation; the old application is not upgraded or uninstalled.
AppId=may-vps-deploy-desktop
AppName=May VPS Deploy
AppVersion={#AppVersion}
AppPublisher=May
AppPublisherURL=https://github.com/mxh110708/may-vps-deploy
AppSupportURL=https://github.com/mxh110708/may-vps-deploy/issues
DefaultDirName=C:\Programs\May VPS Deploy
DefaultGroupName=May VPS Deploy
PrivilegesRequired=lowest
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19041
OutputDir={#OutputPath}
OutputBaseFilename={#OutputName}
SetupIconFile={#BundleRoot}\assets\gui\app.ico
UninstallDisplayIcon={app}\May-VPS-Deploy.exe
UninstallDisplayName=May VPS Deploy
AppMutex=Local\may-vps-deploy-desktop
SetupMutex=Local\may-vps-deploy-setup
WizardStyle=modern dynamic
WizardSizePercent=100
Compression=lzma2/normal
SolidCompression=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableWelcomePage=no
CloseApplications=no
RestartApplications=no
UsePreviousAppDir=yes
UsePreviousTasks=yes
#if IsTestBuild == "1"
CreateUninstallRegKey=no
#endif

[Languages]
Name: "chinesesimplified"; MessagesFile: "{#SourcePath}\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; Flags: checkedonce

[Files]
#include "files.iss"
Source: "{#BundleRoot}\application-files.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BundleRoot}\app-helpers\SetupGuard.exe"; Flags: dontcopy
Source: "{#BundleRoot}\app-helpers\PrivateData.exe"; Flags: dontcopy
Source: "{#BundleRoot}\application-files.json"; DestName: "new-application-files.json"; Flags: dontcopy

[Icons]
#if IsTestBuild == "0"
Name: "{autoprograms}\May VPS Deploy"; Filename: "{app}\May-VPS-Deploy.exe"; AppUserModelID: "May.VPSDeploy.Desktop"
Name: "{autodesktop}\May VPS Deploy"; Filename: "{app}\May-VPS-Deploy.exe"; Tasks: desktopicon; AppUserModelID: "May.VPSDeploy.Desktop"
#endif

[Run]
#if IsTestBuild == "0"
Filename: "{app}\May-VPS-Deploy.exe"; Description: "启动 May VPS Deploy"; Flags: nowait postinstall skipifsilent
#endif

[Code]
var
  DeleteApplicationData: Boolean;
  PrivateDataHelper: String;
#if IsTestBuild == "1"
  QaProgressRecorded: Boolean;

procedure CurInstallProgressChanged(CurProgress, MaxProgress: Integer);
begin
  if not QaProgressRecorded and WizardSilent and WizardForm.Visible and WizardForm.ProgressGauge.Visible then begin
    ForceDirectories(ExpandConstant('{app}\.tmp'));
    SaveStringToFile(ExpandConstant('{app}\.tmp/qa-install-window.json'),
      '{"version":"{#AppVersion}","progress_window_visible":true,"progress_gauge_visible":true}', False);
    QaProgressRecorded := True;
  end;
end;
#endif

function DataPathSafe(const Directory: String): Boolean;
var
  Entry: TFindRec;
  Current, Parent: String;
begin
  Result := True;
  Current := Directory;
  while Length(Current) > 3 do begin
    if FindFirst(Current, Entry) then begin
      try
        if (Entry.Attributes and $400) <> 0 then begin Result := False; exit; end;
      finally FindClose(Entry); end;
    end;
    Parent := ExtractFileDir(Current);
    if Parent = Current then exit;
    Current := Parent;
  end;
end;

function DataTreeSafe(const Directory: String): Boolean;
var
  Entry: TFindRec;
  Child: String;
begin
  Result := True;
  if FindFirst(Directory, Entry) then begin
    try
      if (Entry.Attributes and $400) <> 0 then begin Result := False; exit; end;
    finally FindClose(Entry); end;
  end;
  if FindFirst(AddBackslash(Directory) + '*', Entry) then begin
    try
      repeat
        if (Entry.Name <> '.') and (Entry.Name <> '..') then begin
          if (Entry.Attributes and $400) <> 0 then begin Result := False; exit; end;
          Child := AddBackslash(Directory) + Entry.Name;
          if (Entry.Attributes and $10) <> 0 then
            if not DataTreeSafe(Child) then begin Result := False; exit; end;
        end;
      until not FindNext(Entry);
    finally FindClose(Entry); end;
  end;
end;

function InitializeUninstall(): Boolean;
var
  Form: TSetupForm;
  Keep, Remove: TNewRadioButton;
  LabelText: TNewStaticText;
  Proceed, Cancel: TNewButton;
  AppDirectory: String;
  HelperResult: Integer;
begin
  DeleteApplicationData := False;
  Result := True;
  if UninstallSilent then begin
    DeleteApplicationData := ExpandConstant('{param:REMOVEDATA|0}') = '1';
  end else begin
    Form := CreateCustomForm(ScaleX(440), ScaleY(245), False, False);
    try
      Form.Caption := '卸载 May VPS Deploy';
      LabelText := TNewStaticText.Create(Form); LabelText.Parent := Form;
      LabelText.Left := ScaleX(24); LabelText.Top := ScaleY(20); LabelText.Caption := '选择如何处理这台电脑上的应用数据';
      Keep := TNewRadioButton.Create(Form); Keep.Parent := Form;
      Keep.SetBounds(ScaleX(24), ScaleY(56), ScaleX(390), ScaleY(24));
      Keep.Caption := '保留私人归档和本地配置'; Keep.Checked := True;
      Remove := TNewRadioButton.Create(Form); Remove.Parent := Form;
      Remove.SetBounds(ScaleX(24), ScaleY(94), ScaleX(390), ScaleY(24));
      Remove.Caption := '彻底删除应用及本地数据';
      LabelText := TNewStaticText.Create(Form); LabelText.Parent := Form;
      LabelText.SetBounds(ScaleX(24), ScaleY(132), ScaleX(392), ScaleY(52));
      LabelText.AutoSize := False; LabelText.WordWrap := True;
      LabelText.Caption := '彻底删除应用安装目录及本应用的私人归档目录，包含归档、密钥、配置、日志和缓存。';
      Proceed := TNewButton.Create(Form); Proceed.Parent := Form;
      Proceed.SetBounds(ScaleX(230), ScaleY(204), ScaleX(88), ScaleY(28));
      Proceed.Caption := '继续卸载'; Proceed.ModalResult := mrOk; Proceed.Default := True;
      Cancel := TNewButton.Create(Form); Cancel.Parent := Form;
      Cancel.SetBounds(ScaleX(328), ScaleY(204), ScaleX(88), ScaleY(28));
      Cancel.Caption := '取消'; Cancel.ModalResult := mrCancel; Cancel.Cancel := True;
      Result := Form.ShowModal() = mrOk;
      DeleteApplicationData := Result and Remove.Checked;
    finally Form.Free(); end;
  end;
  if Result and DeleteApplicationData then begin
    AppDirectory := ExpandConstant('{app}');
    if (Length(AppDirectory) < 4) or DirExists(AddBackslash(AppDirectory) + '.git') or
       not DataPathSafe(AppDirectory) or not DataTreeSafe(AppDirectory) then begin
      SuppressibleMsgBox('数据目录包含链接或不受支持的内容，未开始卸载。请先核对应用目录。', mbError, MB_OK, IDOK);
      Result := False;
    end;
    if Result then begin
      PrivateDataHelper := ExpandConstant('{tmp}\MXH-PrivateData.exe');
      if not FileCopy(AddBackslash(AppDirectory) + 'app-helpers\PrivateData.exe', PrivateDataHelper, False) or
         not Exec(PrivateDataHelper, 'validate ' + AddQuotes(AppDirectory), '', SW_HIDE, ewWaitUntilTerminated, HelperResult) or
         (HelperResult <> 0) then begin
        SuppressibleMsgBox('私人归档目录不可用、归属不一致或含链接，未开始卸载。请先核对归档目录。', mbError, MB_OK, IDOK);
        Result := False;
      end;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  GuardResult: Integer;
begin
  Result := '';
  if DirExists(ExpandConstant('{app}\.git')) then begin
    Result := '请选择独立的应用安装目录。安装包不覆盖 Git 开发或使用副本。';
    exit;
  end;
  if (FileExists(ExpandConstant('{app}\May-VPS-Deploy.exe')) or
      FileExists(ExpandConstant('{app}\MXH-VPS-Deploy.exe'))) and
     not FileExists(ExpandConstant('{app}\installation.json')) then begin
    Result := '此目录包含便携版或未受管文件。请选择独立安装目录，以保留原文件。';
    exit;
  end;
  ExtractTemporaryFile('SetupGuard.exe');
  ExtractTemporaryFile('new-application-files.json');
  if not Exec(ExpandConstant('{tmp}\SetupGuard.exe'),
    AddQuotes(ExpandConstant('{app}')) + ' ' + AddQuotes(ExpandConstant('{tmp}\new-application-files.json')),
    '', SW_HIDE, ewWaitUntilTerminated, GuardResult) or (GuardResult <> 0) then
    Result := '应用文件有改动、文件冲突或目录不受支持。安装已停止，原文件和私人数据保留。';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    SaveStringToFile(ExpandConstant('{app}\installation.json'),
      '{"schema_version":1,"type":"installed","app_id":"may-vps-deploy-desktop","version":"{#AppVersion}"}', False);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  HelperResult: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DeleteFile(ExpandConstant('{app}\installation.json'));
    if DeleteApplicationData then begin
      if not Exec(PrivateDataHelper, 'remove ' + AddQuotes(ExpandConstant('{app}')), '', SW_HIDE, ewWaitUntilTerminated, HelperResult) or (HelperResult <> 0) then
        SuppressibleMsgBox('应用已卸载，私人归档未能安全删除，剩余数据保留。请核对数据目录。', mbError, MB_OK, IDOK)
      else if not DataPathSafe(ExpandConstant('{app}')) or not DataTreeSafe(ExpandConstant('{app}')) then
        SuppressibleMsgBox('应用已卸载，但数据目录发生变化，剩余数据保留。请核对安装目录。', mbError, MB_OK, IDOK)
      else if not DelTree(ExpandConstant('{app}'), True, True, True) then
        SuppressibleMsgBox('应用已卸载，部分数据仍被占用，未能全部删除。请关闭相关程序后核对安装目录。', mbError, MB_OK, IDOK);
    end;
  end;
end;
