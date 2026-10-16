#requires -Version 7.4
[CmdletBinding()]
param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[string]$InitialPackageJson,[string]$Proxy,[string]$EvidenceDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $IsWindows){throw '安装生命周期验证需要 Windows。'}
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$fixture=Join-Path $ProjectRoot ('.test-output/desktop-installer-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture)|Out-Null
$script:desktopPassed=0
$fixtureFailure=$null
function Assert-Desktop([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:desktopPassed++}
function Invoke-DesktopFixtureProcess {
 param([string]$Executable,[string[]]$Arguments,[switch]$MinimalPath,[int]$Timeout=240000)
 $start=[Diagnostics.ProcessStartInfo]::new($Executable);$start.UseShellExecute=$false;$start.CreateNoWindow=$true
 foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
 if($MinimalPath){$start.Environment['PATH']=Join-Path $env:WINDIR 'System32'}
 $process=[Diagnostics.Process]::Start($start)
 try{if(-not $process.WaitForExit($Timeout)){$process.Kill($true);throw 'Desktop fixture process timed out.'};return $process.ExitCode}finally{$process.Dispose()}
}
$app=Join-Path $fixture '应用 测试'
try{
 Import-Module (Join-Path $ProjectRoot 'src/VpsDeploy.Update.psm1') -Force
 if($InitialPackageJson){$first=Get-Content -Raw -LiteralPath $InitialPackageJson|ConvertFrom-Json -AsHashtable}
 else{$first=& (Join-Path $ProjectRoot 'scripts/New-VpsReleasePackage.ps1') -ProjectRoot $ProjectRoot -Destination (Join-Path $fixture 'initial-package') -Development -TestBuild -PackageVersion '1.0.0' -Proxy $Proxy}
 if(-not $first.TestBuild){throw 'Tests accept only a build without shortcuts or uninstall registry entries.'}
 $v=[version]$first.Version;$nextVersion="$($v.Major).$($v.Minor).$($v.Build+1)"
 $next=& (Join-Path $ProjectRoot 'scripts/New-VpsReleasePackage.ps1') -ProjectRoot $ProjectRoot -Destination (Join-Path $fixture 'next-package') -Development -TestBuild -PackageVersion $nextVersion -Proxy $Proxy
 $installArgs=@('/SP-','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOICONS',('/DIR='+$app))
 Assert-Desktop ((Invoke-DesktopFixtureProcess $first.Installer $installArgs) -eq 0) 'real installer installs to isolated directory with spaces and Chinese'
 Assert-Desktop (Test-Path -LiteralPath (Join-Path $app 'MXH-VPS-Deploy.exe')) 'native desktop EXE installed'
 $kernelCatalog=Get-Content -Raw -LiteralPath (Join-Path $app 'config/kernel-catalog.json')|ConvertFrom-Json -AsHashtable
 $kernelFile=Join-Path $app 'assets/kernel/kernel.deb'
 Assert-Desktop ((Get-Item -LiteralPath $kernelFile).Length -eq $kernelCatalog.Prebuilt.Bytes -and (Get-FileHash -LiteralPath $kernelFile).Hash.ToLowerInvariant() -eq $kernelCatalog.Prebuilt.Sha256) 'installer preserves the exact fixed precompiled kernel'
 Assert-Desktop (-not(Test-Path -LiteralPath (Join-Path $app 'assets/remote/kernel-latest.sh'))) 'obsolete floating kernel query is absent from the installed application'
 if($first.KernelSourceArchive){
  $kernelManifest=Get-Content -Raw -LiteralPath (Join-Path $app 'assets/kernel/build-manifest.json')|ConvertFrom-Json -AsHashtable
  $sourceDigest=(Get-FileHash -LiteralPath $first.KernelSourceArchive).Hash.ToLowerInvariant()
  $sourceChecksum=$sourceDigest+'  '+[IO.Path]::GetFileName($first.KernelSourceArchive)
  Assert-Desktop ($sourceDigest -eq $kernelManifest.SourceArchiveSha256 -and @(Get-Content -LiteralPath $first.Checksums).Contains($sourceChecksum)) 'matching kernel source is an independently checksummed release attachment'
  Assert-Desktop (-not(Test-Path -LiteralPath (Join-Path $app ([IO.Path]::GetFileName($first.KernelSourceArchive))))) 'full kernel source is not installed into every client application'
 }
 Assert-Desktop ((Get-VpsApplicationDistribution $app) -eq 'Installed') 'installer mode recognized'
 $exeBytes=[IO.File]::ReadAllBytes((Join-Path $app 'MXH-VPS-Deploy.exe'));$pe=[BitConverter]::ToInt32($exeBytes,0x3c)
 Assert-Desktop ([BitConverter]::ToUInt16($exeBytes,$pe+4) -eq 0x8664 -and [BitConverter]::ToUInt16($exeBytes,$pe+24+68) -eq 2) 'x64 Windows GUI EXE, no console subsystem'
 $proof=Join-Path $app 'runtime-proof.json'
 Assert-Desktop ((Invoke-DesktopFixtureProcess (Join-Path $app 'MXH-VPS-Deploy.exe') @('--verify-runtime',$proof) -MinimalPath) -eq 0) 'native EXE works without global PowerShell or Python on PATH'
 $runtimeProof=Get-Content -Raw -LiteralPath $proof|ConvertFrom-Json -AsHashtable
 Assert-Desktop ($runtimeProof.winui_loaded -and $runtimeProof.runtime_paths_local -and -not $runtimeProof.wpf_loaded -and -not $runtimeProof.powershell_loaded) 'real WinUI 3 and private .NET runtime loaded without PowerShell or WPF'
 Remove-Item -LiteralPath $proof
 if(Test-Path -LiteralPath ($proof+'.startup.txt')){Remove-Item -LiteralPath ($proof+'.startup.txt')}
 @{synthetic_only=$true}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $app 'qa-ui-review.fixture.json') -Encoding utf8
 $storageProof=Join-Path $app '.tmp/storage-ui/runtime-proof.json';[IO.Directory]::CreateDirectory((Split-Path -Parent $storageProof))|Out-Null
 $storageExit=Invoke-DesktopFixtureProcess (Join-Path $app 'MXH-VPS-Deploy.exe') @('--ui-smoke',$storageProof,'--app-root',$app,'--exercise-storage','--exercise-additions')
 if($storageExit -ne 0 -and (Test-Path -LiteralPath $storageProof)){
  $failure=Get-Content -Raw -LiteralPath $storageProof|ConvertFrom-Json
  Write-Host ('Native storage UI proof: '+($failure|ConvertTo-Json -Depth 5 -Compress))
 }
 Assert-Desktop ($storageExit -eq 0) 'native node picker, archive migration and deployment additions UI works'
 $storageUi=Get-Content -Raw -LiteralPath (Join-Path $app '.tmp/storage-ui/storage-regression-proof.json')|ConvertFrom-Json
 Assert-Desktop ($storageUi.migration_roundtrip -and $storageUi.backup_opt_in -and $storageUi.select_and_clear_visible -and $storageUi.custom_font_rendered) 'storage and selection behavior is verified by the real WinUI frontend'
 $additionsUi=Get-Content -Raw -LiteralPath (Join-Path $app '.tmp/storage-ui/additions-regression-proof.json')|ConvertFrom-Json
 Assert-Desktop ($additionsUi.inline_execution -and $additionsUi.explicit_completion_and_failure -and $additionsUi.drag_handles_and_scheme_order -and $additionsUi.generation_validation_export_guidance -and $additionsUi.separate_component_installation -and $additionsUi.remote_connections -eq 0) 'new deployment and configuration behavior is verified by the real WinUI frontend'
 Remove-Item -LiteralPath (Join-Path $app 'qa-ui-review.fixture.json')
 & (Join-Path $ProjectRoot 'tests/Test-BackgroundNative.ps1') -ApplicationDirectory $app -FixtureRoot (Join-Path $fixture 'background-native') -ProjectRoot $ProjectRoot -PythonRuntimeDirectory (Join-Path $app 'runtime/python')
 $backgroundProof=Get-Content -Raw -LiteralPath (Join-Path $fixture 'background-native/test-artifacts/native-flow.json')|ConvertFrom-Json
 Assert-Desktop ($backgroundProof.state -eq 'passed' -and $backgroundProof.window.window_activations -eq 0 -and $backgroundProof.window.foreground_samples -eq 0) 'background interface executes real controls and dialogs without taking foreground focus'
 [IO.Directory]::CreateDirectory((Join-Path $app 'private/instances'))|Out-Null
 [IO.Directory]::CreateDirectory((Join-Path $app '.cache/fixture'))|Out-Null
 'fixture archive'|Set-Content -LiteralPath (Join-Path $app 'private/instances/record.txt')
 'fixture local settings'|Set-Content -LiteralPath (Join-Path $app 'config/app-defaults.local.json')
 'fixture cache'|Set-Content -LiteralPath (Join-Path $app '.cache/fixture/record.txt')
 $fontSource=Join-Path $app 'Fonts/SourceSerif4-600.ttf';$fontDigest=(Get-FileHash -LiteralPath $fontSource).Hash.ToLowerInvariant()
 $fontRelative='private/fonts/'+$fontDigest+'.ttf';$fontPath=Join-Path $app $fontRelative
 [IO.Directory]::CreateDirectory((Split-Path -Parent $fontPath))|Out-Null;Copy-Item -LiteralPath $fontSource -Destination $fontPath
 @{Appearance='Light';FontId=('Custom:'+$fontDigest+'.ttf');FontSizes=@{Title='Large';Body='Large';Note='Large';Metric='Small'};AutoCheckUpdates=$false;UpdateProxy='http://127.0.0.1:2080'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $app 'private/desktop-settings.json') -Encoding utf8
 $privateHash=(Get-FileHash -LiteralPath (Join-Path $app 'private/instances/record.txt')).Hash
 $localHash=(Get-FileHash -LiteralPath (Join-Path $app 'config/app-defaults.local.json')).Hash
 $outside=Join-Path $fixture 'outside-authority.json';'fixture external authority'|Set-Content -LiteralPath $outside
 $outsideHash=(Get-FileHash -LiteralPath $outside).Hash
 $readme=Join-Path $app 'README.md';$original=[IO.File]::ReadAllBytes($readme)
 'fixture user edit'|Add-Content -LiteralPath $readme
 $editedHash=(Get-FileHash -LiteralPath $readme).Hash
 Assert-Desktop ((Invoke-DesktopFixtureProcess (Join-Path $app 'app-helpers/SetupGuard.exe') @($app,$next.FileManifest)) -ne 0) 'managed user edit blocks update'
 Assert-Desktop ((Invoke-DesktopFixtureProcess $next.Installer $installArgs) -ne 0) 'real installer refuses to overwrite managed user edit'
 Assert-Desktop ((Get-FileHash -LiteralPath $readme).Hash -eq $editedHash -and (Get-VpsApplicationVersion $app).ToString() -eq $first.Version) 'blocked install leaves files and version unchanged'
 [IO.File]::WriteAllBytes($readme,$original)
 $collision=Join-Path $app 'user-note.txt';'fixture unmanaged file'|Set-Content -LiteralPath $collision
 $fake=Get-Content -Raw -LiteralPath $next.FileManifest|ConvertFrom-Json -AsHashtable
 $fake.files+=@{path='user-note.txt';sha256=(Get-FileHash -LiteralPath $collision).Hash.ToLowerInvariant()}
 $fakePath=Join-Path $fixture 'collision-manifest.json';$fake|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $fakePath
 Assert-Desktop ((Invoke-DesktopFixtureProcess (Join-Path $app 'app-helpers/SetupGuard.exe') @($app,$fakePath)) -ne 0) 'new managed path cannot overwrite an unmanaged file'
 Remove-Item -LiteralPath $collision
 $updateFixture=Join-Path $app '.tmp/qa-update-fixture';[IO.Directory]::CreateDirectory($updateFixture)|Out-Null
 $setup=Join-Path $updateFixture "mxh-vps-deploy-v$nextVersion-windows-amd64-setup.exe"
 $files=Join-Path $updateFixture "mxh-vps-deploy-v$nextVersion-windows-amd64.files.json"
 Copy-Item -LiteralPath $next.Installer -Destination $setup
 Copy-Item -LiteralPath $next.FileManifest -Destination $files
 $checksums=Join-Path $updateFixture 'SHA256SUMS.txt'
 @($setup,$files)|ForEach-Object{(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetFileName($_)}|Set-Content -LiteralPath $checksums -Encoding ascii
 $assets=@($setup,$files,$checksums)|ForEach-Object{@{name=[IO.Path]::GetFileName($_);browser_download_url=('https://github.com/mxh110708/mxh-vps-deploy/releases/download/v'+$nextVersion+'/'+[IO.Path]::GetFileName($_));digest=('sha256:'+(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant());size=(Get-Item -LiteralPath $_).Length;state='uploaded'}}
 @{tag_name=('v'+$nextVersion);draft=$false;prerelease=$false;body="## 本次更新`n- 修正检查更新结束后的状态提示。`n- 在更新弹窗显示下载与校验进度。`n- 安装时显示进度窗口，保留私人归档和本地配置。`n`n这是隔离测试的示例更新说明。";assets=@($assets)}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $updateFixture 'release.json') -Encoding utf8
 Assert-Desktop ((Invoke-DesktopFixtureProcess (Join-Path $app 'MXH-VPS-Deploy.exe') @('--verify-installed-update') -MinimalPath) -eq 0) 'actual WinUI check-update and confirmation download and launch update'
 $uiProof=Get-Content -LiteralPath (Join-Path $app '.tmp/ui-update-proof.json') -Raw|ConvertFrom-Json -AsHashtable
 Assert-Desktop ($uiProof.ui_update_started -and $uiProof.confirmation_clicked -and $uiProof.launcher_pid_recorded) 'real update confirmation and parent process handoff verified'
 Assert-Desktop ($uiProof.release_notes_displayed) 'update dialog displays the release body returned by the GitHub-format metadata'
 Assert-Desktop ($uiProof.negative_checks.Count -eq 8) 'untrusted assets, corrupt downloads, size limits, cleanup and repeated version refused'
 $statusProof=Get-Content -LiteralPath (Join-Path $app '.tmp/update-status-proof.json') -Raw|ConvertFrom-Json -AsHashtable
 Assert-Desktop ($statusProof.cases.Count -eq 5) 'automatic/manual checks, failure, decline and cancelled download leave no busy status'
 Assert-Desktop ($uiProof.progress.Downloading.in_dialog -and $uiProof.progress.Downloading.percent -eq 100 -and $uiProof.progress.Verifying.in_dialog -and $uiProof.progress.Verifying.percent -eq 100 -and $uiProof.progress.Ready.percent -eq 100) 'real transfer and SHA256 verification report visible monotonic progress inside the update dialog'
 $stage=[string]$uiProof.stage;$restartProof=Join-Path $app '.tmp/update-restart-proof.json'
 $watch=[Diagnostics.Stopwatch]::StartNew();while((-not(Test-Path -LiteralPath $restartProof) -or (Test-Path -LiteralPath $stage)) -and $watch.ElapsedMilliseconds -lt 120000){[Threading.Thread]::Sleep(100)}
 Assert-Desktop (Test-Path -LiteralPath $restartProof) 'update automatically restarts the new native EXE'
 $restarted=Get-Content -LiteralPath $restartProof -Raw|ConvertFrom-Json -AsHashtable
 Assert-Desktop ($restarted.winui_loaded -and $restarted.initial_theme -eq 'Light' -and $restarted.initial_font -eq ('Custom:'+$fontDigest+'.ttf') -and -not $restarted.font_fallback) 'restart loads WinUI and retained appearance/custom font'
 Assert-Desktop ((Get-VpsApplicationVersion $app).ToString() -eq $nextVersion) 'app version updated without uninstalling'
 $installWindowProof=Get-Content -LiteralPath (Join-Path $app '.tmp/qa-install-window.json') -Raw|ConvertFrom-Json -AsHashtable
 Assert-Desktop ($installWindowProof.version -eq $nextVersion -and $installWindowProof.progress_window_visible -and $installWindowProof.progress_gauge_visible) 'in-place update displays the real installer progress window and gauge'
 Assert-Desktop ((Get-FileHash -LiteralPath (Join-Path $app 'private/instances/record.txt')).Hash -eq $privateHash -and (Get-FileHash -LiteralPath (Join-Path $app 'config/app-defaults.local.json')).Hash -eq $localHash) 'in-place installer update preserves archive and local settings'
 $preferences=Get-Content -LiteralPath (Join-Path $app 'private/desktop-settings.json') -Raw|ConvertFrom-Json -AsHashtable
 Assert-Desktop ((Get-FileHash -LiteralPath $fontPath).Hash.ToLowerInvariant() -eq $fontDigest -and $preferences.Appearance -eq 'Light' -and $preferences.FontId -eq ('Custom:'+$fontDigest+'.ttf') -and -not $preferences.AutoCheckUpdates -and $preferences.UpdateProxy -eq 'http://127.0.0.1:2080') 'in-place update preserves imported font and appearance preferences'
 Assert-Desktop ($preferences.FontSizes.Title -eq 'Large' -and $preferences.FontSizes.Body -eq 'Large' -and $preferences.FontSizes.Note -eq 'Large' -and $preferences.FontSizes.Metric -eq 'Small') 'in-place update preserves all four independent font-size preferences'
 $watch=[Diagnostics.Stopwatch]::StartNew();while((Test-Path -LiteralPath $stage) -and $watch.ElapsedMilliseconds -lt 15000){[Threading.Thread]::Sleep(50)}
 Assert-Desktop (-not(Test-Path -LiteralPath $stage)) 'successful installed update removes only its transient stage'
 Assert-Desktop (Test-Path -LiteralPath (Join-Path $app 'private/update-test-completed.txt')) 'tested update helper reaches restart handoff'
 if($EvidenceDirectory){
  $evidence=[IO.Path]::GetFullPath($EvidenceDirectory);$evidenceBoundary=[IO.Path]::GetFullPath((Join-Path $ProjectRoot '.tmp')).TrimEnd('\')+'\'
  if(-not $evidence.StartsWith($evidenceBoundary,[StringComparison]::OrdinalIgnoreCase)){throw 'Evidence must stay in this project temporary directory.'}
  [IO.Directory]::CreateDirectory($evidence)|Out-Null
  foreach($name in @('about-application-icon.png','completed-update-status.png','ui-update-notes.png','ui-update-downloading.png','ui-update-verifying.png')){Copy-Item -LiteralPath (Join-Path $updateFixture $name) -Destination (Join-Path $evidence $name)}
  foreach($name in @('ui-update-proof.json','update-status-proof.json','qa-install-window.json')){Copy-Item -LiteralPath (Join-Path $app ('.tmp/'+$name)) -Destination (Join-Path $evidence $name)}
 }
 $custom=Join-Path $fixture '自定义私人归档';$owner=[guid]::NewGuid().ToString('N')
 $oldPrivate=[IO.Path]::GetFullPath((Join-Path $app 'private'));$custom=[IO.Path]::GetFullPath($custom)
 if(-not $oldPrivate.StartsWith($fixture+'\',[StringComparison]::OrdinalIgnoreCase) -or -not $custom.StartsWith($fixture+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe archive fixture relocation.'}
 Move-Item -LiteralPath $oldPrivate -Destination $custom
 @{SchemaVersion=1;OwnerId=$owner;AppRoot=$app}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $custom '.mxh-private-directory.json') -Encoding utf8
 @{SchemaVersion=1;OwnerId=$owner;Directory=$custom}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $app 'archive-location.private.json') -Encoding utf8
 $customProof=Join-Path $app '.tmp/custom-location-proof.json'
 Assert-Desktop ((Invoke-DesktopFixtureProcess (Join-Path $app 'MXH-VPS-Deploy.exe') @('--verify-runtime',$customProof)) -eq 0) 'native EXE opens the custom private directory'
 $customRuntime=Get-Content -Raw -LiteralPath $customProof|ConvertFrom-Json
 Assert-Desktop (-not $customRuntime.font_fallback -and $customRuntime.initial_font -eq ('Custom:'+$fontDigest+'.ttf')) 'custom archive preserves imported font rendering'
 $uninstaller=Join-Path $app 'unins000.exe'
 Assert-Desktop ((Invoke-DesktopFixtureProcess $uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART')) -eq 0) 'normal uninstall defaults to keeping data'
 Assert-Desktop (-not(Test-Path -LiteralPath (Join-Path $app 'MXH-VPS-Deploy.exe')) -and (Get-FileHash -LiteralPath (Join-Path $custom 'instances/record.txt')).Hash -eq $privateHash -and (Get-FileHash -LiteralPath (Join-Path $app 'config/app-defaults.local.json')).Hash -eq $localHash -and (Test-Path -LiteralPath (Join-Path $app 'archive-location.private.json'))) 'keep-data uninstall preserves custom directory, locator and local settings'
 Assert-Desktop ((Invoke-DesktopFixtureProcess $next.Installer $installArgs) -eq 0) 'reinstall supports retained local data'
 Assert-Desktop ((Get-FileHash -LiteralPath (Join-Path $custom 'instances/record.txt')).Hash -eq $privateHash) 'reinstall does not replace retained custom archive'
 $outsideDirectory=Join-Path $fixture 'outside-data';[IO.Directory]::CreateDirectory($outsideDirectory)|Out-Null
 $outsideRecord=Join-Path $outsideDirectory 'record.txt';'fixture outside data'|Set-Content -LiteralPath $outsideRecord
 $outsideRecordHash=(Get-FileHash -LiteralPath $outsideRecord).Hash
 $junction=Join-Path $custom 'linked-data'
 New-Item -ItemType Junction -Path $junction -Target $outsideDirectory|Out-Null
 try{
  Assert-Desktop ((Invoke-DesktopFixtureProcess (Join-Path $app 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/REMOVEDATA=1')) -ne 0) 'complete removal refuses a linked data directory'
  Assert-Desktop ((Test-Path -LiteralPath (Join-Path $app 'MXH-VPS-Deploy.exe')) -and (Get-FileHash -LiteralPath $outsideRecord).Hash -eq $outsideRecordHash) 'blocked linked uninstall preserves app and external data'
 }finally{if(Test-Path -LiteralPath $junction){[IO.Directory]::Delete($junction)}}
 Assert-Desktop ((Invoke-DesktopFixtureProcess (Join-Path $app 'unins000.exe') @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/REMOVEDATA=1')) -eq 0) 'explicit delete-data uninstall succeeds'
 $watch=[Diagnostics.Stopwatch]::StartNew();while((Test-Path -LiteralPath $app) -and $watch.ElapsedMilliseconds -lt 15000){[Threading.Thread]::Sleep(50)}
 Assert-Desktop (-not(Test-Path -LiteralPath $app)) 'explicit complete removal deletes only isolated app directory'
 Assert-Desktop (-not(Test-Path -LiteralPath $custom)) 'explicit complete removal also deletes owned custom private directory'
 Assert-Desktop ((Get-FileHash -LiteralPath $outside).Hash -eq $outsideHash) 'external authority is unaffected by complete app removal'
 Write-Host "Windows installer lifecycle passed: $script:desktopPassed assertions"
}catch{
 $fixtureFailure=$_
 Write-Host ('Installer lifecycle failure before cleanup: '+$_.Exception.Message)
 throw
}finally{
 $prefix=[IO.Path]::GetFullPath((Join-Path $ProjectRoot '.test-output')).TrimEnd('\')+'\'
 if(-not [IO.Path]::GetFullPath($fixture).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe installer fixture cleanup.'}
 # An assertion must not remove files from an update still using this fixture.
 $owned=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue|Where-Object{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($fixture+'\',[StringComparison]::OrdinalIgnoreCase)})
 foreach($item in $owned){
  $process=Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
  if($process){try{if(-not $process.WaitForExit(30000)){$process.Kill($true);$process.WaitForExit()}}finally{$process.Dispose()}}
 }
 if(Test-Path -LiteralPath $fixture){
  try{Remove-Item -LiteralPath $fixture -Recurse -Force}
  catch{if(-not $fixtureFailure){throw};Write-Warning 'Failed QA fixture retained; original failure preserved.'}
 }
}
