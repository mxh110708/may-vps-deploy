#requires -Version 7.4
[CmdletBinding()]
param(
 [string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),
 [Parameter(Mandatory)][string]$Destination,
 [switch]$Development,
 [Parameter(DontShow)][switch]$TestBuild,
 [Parameter(DontShow)][string]$PackageVersion,
 [Parameter(DontShow)][switch]$KeepBundle,
 [string]$CacheDirectory,[string]$SourceDirectory,[string]$Proxy,
 [string]$KernelSourceArchive
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $IsWindows){throw 'Windows 桌面包需在 Windows 上编译。'}
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot);$Destination=[IO.Path]::GetFullPath($Destination)
Import-Module (Join-Path $ProjectRoot 'src/VpsDeploy.Update.psm1') -Force
$version=(Get-VpsApplicationVersion $ProjectRoot).ToString()
$application=Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config/application.json')|ConvertFrom-Json -AsHashtable
if($PackageVersion){if(-not($TestBuild -and $Development) -or $PackageVersion -notmatch '^\d+\.\d+\.\d+$'){throw '版本覆盖仅用于隔离安装测试。'};$version=$PackageVersion}
if($TestBuild -and -not $Development){throw '隔离测试包不能正式发行。'}
if(-not $Development){if($application.channel -ne 'stable'){throw '正式包需要 stable 应用版本。'};Assert-VpsGitApplicationClean $ProjectRoot}
& (Join-Path $ProjectRoot 'scripts/Test-NoSecrets.ps1') -ProjectRoot $ProjectRoot
$dependencies=& (Join-Path $ProjectRoot 'scripts/Initialize-DesktopBuild.ps1') -ProjectRoot $ProjectRoot -CacheDirectory $CacheDirectory -SourceDirectory $SourceDirectory -Proxy $Proxy -Names @('python','yaml','inno_setup')
$kernelCatalog=Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config/kernel-catalog.json')|ConvertFrom-Json -AsHashtable
$kernelManifest=Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets/kernel/build-manifest.json')|ConvertFrom-Json -AsHashtable
if(-not $Development -and -not $KernelSourceArchive){throw '正式发布需提供 -KernelSourceArchive（构建导出的完整对应源码包），随二进制一并发布。'}
if($KernelSourceArchive){
 $KernelSourceArchive=[IO.Path]::GetFullPath($KernelSourceArchive)
 if(-not(Test-Path -LiteralPath $KernelSourceArchive -PathType Leaf) -or (Get-Item -LiteralPath $KernelSourceArchive).Length -ne $kernelManifest.SourceArchiveBytes -or (Get-FileHash -LiteralPath $KernelSourceArchive).Hash.ToLowerInvariant() -ne $kernelManifest.SourceArchiveSha256){throw '对应内核源码包的大小或 SHA256 不匹配。'}
}
$paths=@(& git -c "safe.directory=$ProjectRoot" -c core.quotepath=false -C $ProjectRoot ls-files --cached --others --exclude-standard|Sort-Object -Unique)
if($LASTEXITCODE -ne 0 -or -not $paths.Count){throw '无法取得公开文件清单。'}
$buildRoot=Join-Path $ProjectRoot ('.tmp/desktop-package-'+[guid]::NewGuid().ToString('N'))
$bundle=Join-Path $buildRoot 'application';$installerSource=Join-Path $buildRoot 'installer'
[IO.Directory]::CreateDirectory($bundle)|Out-Null
try{
 foreach($relative in $paths){
  Assert-VpsApplicationFilePath $relative
  $source=Assert-VpsApplicationWritableScope $ProjectRoot $relative
  if(-not(Test-Path -LiteralPath $source -PathType Leaf)){throw '公开清单含缺失文件。'}
  $target=Join-Path $bundle $relative;[IO.Directory]::CreateDirectory((Split-Path -Parent $target))|Out-Null
  Copy-Item -LiteralPath $source -Destination $target
 }
 if($PackageVersion){$application.version=$version;$application.channel='stable';$application|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $bundle 'config/application.json') -Encoding utf8}
 $runtime=Join-Path $bundle 'runtime';[IO.Directory]::CreateDirectory($runtime)|Out-Null
 foreach($name in @('python')){[IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $dependencies.CacheDirectory $dependencies.Assets[$name].file),(Join-Path $runtime $name))}
 $python=Join-Path $runtime 'python'
 $kernelProof=@(& (Join-Path $python 'python.exe') (Join-Path $bundle 'scripts/check-kernel-prebuilt.py') --project $bundle)
 if($LASTEXITCODE -ne 0){$kernelProof|Write-Host;throw '内置内核包及构建来源校验失败。'}
 $site=Join-Path $python 'Lib/site-packages';[IO.Directory]::CreateDirectory($site)|Out-Null
 [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $dependencies.CacheDirectory $dependencies.Assets.yaml.file),$site)
 "python313.zip`n.`nLib/site-packages`n../../scripts`nimport site`n"|Set-Content -LiteralPath (Join-Path $python 'python313._pth') -Encoding ascii
 $env:DOTNET_CLI_HOME=Join-Path $ProjectRoot '.cache/dotnet-home'
 $env:NUGET_PACKAGES=Join-Path $ProjectRoot '.cache/nuget'
 $env:DOTNET_CLI_TELEMETRY_OPTOUT='1';$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
 if($Proxy){$env:HTTP_PROXY=$Proxy;$env:HTTPS_PROXY=$Proxy}
 $desktopProject=Join-Path $ProjectRoot 'desktop/Mxh.VpsDeploy.Desktop/Mxh.VpsDeploy.Desktop.csproj'
 & dotnet publish $desktopProject -c Release -p:Platform=x64 -p:RestoreLockedMode=true ("-p:Version=$version") -o $bundle -m:1 -nr:false -v minimal | Out-Host
 if($LASTEXITCODE -ne 0){throw 'WinUI 3 桌面与 .NET 运维核心构建失败。'}
 $compiler=Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
 if(-not(Test-Path -LiteralPath $compiler)){throw '缺少 Windows .NET Framework 编译器。'}
 $assembly=Join-Path $buildRoot 'AssemblyVersion.cs'
 ('[assembly:System.Reflection.AssemblyVersion("'+$version+'.0")][assembly:System.Reflection.AssemblyFileVersion("'+$version+'.0")]')|Set-Content -LiteralPath $assembly -Encoding utf8
 $helpers=Join-Path $bundle 'app-helpers';[IO.Directory]::CreateDirectory($helpers)|Out-Null
 $compile=@('/nologo','/target:winexe','/platform:x64','/optimize+','/r:System.Web.Extensions.dll','/r:System.Windows.Forms.dll','/r:System.Core.dll',('/win32manifest:'+(Join-Path $ProjectRoot 'src/desktop/app.manifest')))
 if($TestBuild){$compile+='/define:DESKTOP_TEST'}
 $targets=@(
  @{Name='app-helpers/SetupGuard.exe';Main='Mxh.VpsDeploy.Desktop.SetupGuard';Sources=@('src/desktop/SetupGuard.cs','src/desktop/DesktopFiles.cs')},
  @{Name='app-helpers/PrivateData.exe';Main='Mxh.VpsDeploy.Desktop.PrivateData';Sources=@('src/desktop/PrivateData.cs','src/desktop/DesktopFiles.cs')},
  @{Name='app-helpers/InstalledUpdate.exe';Main='Mxh.VpsDeploy.Desktop.InstalledUpdate';Sources=@('src/desktop/InstalledUpdate.cs','src/desktop/DesktopFiles.cs')},
  @{Name='app-helpers/CleanupUpdate.exe';Main='Mxh.VpsDeploy.Desktop.CleanupUpdate';Sources=@('src/desktop/CleanupUpdate.cs','src/desktop/DesktopFiles.cs')}
 )
 foreach($target in $targets){
  $compileArgs=$compile+@("/main:$($target.Main)","/out:$(Join-Path $bundle $target.Name)",$assembly)
  if($target.ContainsKey('Icon')){$compileArgs+='/win32icon:'+(Join-Path $ProjectRoot 'assets/gui/app.ico')}
  $compileArgs+=@($target.Sources|ForEach-Object{Join-Path $ProjectRoot $_})
  $compilerMessages=@(& $compiler @compileArgs)
  if($LASTEXITCODE -ne 0){$compilerMessages|Write-Host;throw ('桌面原生 EXE 编译失败：'+$target.Name)}
 }
 $critical=@('MXH-VPS-Deploy.exe','MXH-VPS-Deploy.dll','Mxh.VpsDeploy.Core.dll','Microsoft.WinUI.dll','System.Private.CoreLib.dll','runtime/python/python.exe','app-helpers/InstalledUpdate.exe','app-helpers/SetupGuard.exe','app-helpers/CleanupUpdate.exe','app-helpers/PrivateData.exe')
 @{schema_version=2;engine='dotnet';ui='winui3';test_build=[bool]$TestBuild;files=@($critical|ForEach-Object{@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $bundle $_)).Hash.ToLowerInvariant()}});versions=@{dotnet=(Get-Content -Raw -LiteralPath (Join-Path $bundle 'MXH-VPS-Deploy.runtimeconfig.json')|ConvertFrom-Json -AsHashtable).runtimeOptions.includedFrameworks[0].version;windows_app_sdk='1.8.260804001';ssh_net='2026.0.0';python=$dependencies.Assets.python.version;yaml=$dependencies.Assets.yaml.version}}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $bundle 'desktop-runtime.json') -Encoding utf8
 $proof=Join-Path $bundle 'runtime-proof.json'
 $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $bundle 'MXH-VPS-Deploy.exe'));$start.UseShellExecute=$false;$start.CreateNoWindow=$true
 $start.ArgumentList.Add('--verify-runtime');$start.ArgumentList.Add($proof)
 $native=[Diagnostics.Process]::Start($start)
 try{if(-not $native.WaitForExit(120000)){$native.Kill($true);throw 'WinUI 3 运行环境复核超时。'};if($native.ExitCode -ne 0){throw 'WinUI 3 窗口或 .NET 核心加载失败。'}}finally{$native.Dispose()}
 $verification=Get-Content -Raw -LiteralPath $proof|ConvertFrom-Json -AsHashtable
 if(-not $verification.winui_loaded -or $verification.wpf_loaded -or $verification.powershell_loaded -or -not $verification.runtime_paths_local){throw 'WinUI 3 或 .NET 内置运行环境未实际生效。'}
 Remove-Item -LiteralPath $proof
 if(Test-Path -LiteralPath ($proof+'.startup.txt')){Remove-Item -LiteralPath ($proof+'.startup.txt')}
 $testOutput=Join-Path $bundle '.test-output'
 if(Test-Path -LiteralPath $testOutput){Remove-Item -LiteralPath $testOutput -Recurse -Force}
 $files=@(Get-ChildItem -LiteralPath $bundle -File -Recurse|ForEach-Object{$relative=[IO.Path]::GetRelativePath($bundle,$_.FullName).Replace('\','/');Assert-VpsApplicationFilePath $relative;@{path=$relative;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}}|Sort-Object path)
 @{schema_version=1;version=$version;files=$files}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $bundle 'application-files.json') -Encoding utf8
 [IO.Directory]::CreateDirectory($Destination)|Out-Null
 $suffix=if($Development){'-ui-preview'}else{''};$stem="mxh-vps-deploy-v$version$suffix-windows-amd64"
 $archive=Join-Path $Destination ($stem+'.zip');$setup=Join-Path $Destination ($stem+'-setup.exe');$publicManifest=Join-Path $Destination ($stem+'.files.json')
 foreach($path in @($archive,$setup,$publicManifest)){if(Test-Path -LiteralPath $path){throw '目标发布附件已存在，未覆盖。'}}
 [IO.Directory]::CreateDirectory($installerSource)|Out-Null
 Copy-Item -LiteralPath (Join-Path $ProjectRoot 'assets/installer/Desktop.iss') -Destination $installerSource
 Copy-Item -LiteralPath (Join-Path $ProjectRoot 'assets/installer/ChineseSimplified.isl') -Destination $installerSource
 $entries=@(foreach($file in $files){$relative=$file.path.Replace('/','\');$directory=[IO.Path]::GetDirectoryName($relative);'Source: "{#BundleRoot}\'+$relative+'"; DestDir: "{app}'+$(if($directory){'\'+$directory}else{''})+'"; Flags: ignoreversion'})
 $entries|Set-Content -LiteralPath (Join-Path $installerSource 'files.iss') -Encoding utf8
 $arguments=@('/Qp',('/DBundleRoot='+$bundle),('/DAppVersion='+$version),('/DOutputPath='+$Destination),('/DOutputName='+$stem+'-setup'),('/DIsTestBuild='+[int][bool]$TestBuild),(Join-Path $installerSource 'Desktop.iss'))
 $installerMessages=@(& $dependencies.Compiler @arguments)
 if($LASTEXITCODE -ne 0){$installerMessages|Write-Host;throw 'Windows 安装包编译失败。'}
 [IO.Compression.ZipFile]::CreateFromDirectory($bundle,$archive,[IO.Compression.CompressionLevel]::Optimal,$false)
 Copy-Item -LiteralPath (Join-Path $bundle 'application-files.json') -Destination $publicManifest
 $checksumName=if($Development){'SHA256SUMS-ui-preview.txt'}else{'SHA256SUMS.txt'}
 $sourceAttachment=''
 if($KernelSourceArchive){
  $sourceAttachment=Join-Path $Destination ('google-bbr-v3-'+$kernelCatalog.Commit.Substring(0,12)+'-source.tar.xz')
  if(Test-Path -LiteralPath $sourceAttachment){throw '对应源码发布附件已存在，未覆盖。'}
  Copy-Item -LiteralPath $KernelSourceArchive -Destination $sourceAttachment
  if((Get-FileHash -LiteralPath $sourceAttachment).Hash.ToLowerInvariant() -ne $kernelManifest.SourceArchiveSha256){throw '复制后的对应源码附件校验失败。'}
 }
 @($archive,$setup,$publicManifest,$sourceAttachment)|Where-Object{$_}|ForEach-Object{(Get-FileHash -LiteralPath $_).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetFileName($_)}|Set-Content -LiteralPath (Join-Path $Destination $checksumName) -Encoding ascii
 [pscustomobject]@{Archive=$archive;Installer=$setup;FileManifest=$publicManifest;KernelSourceArchive=$sourceAttachment;Checksums=(Join-Path $Destination $checksumName);Version=$version;ManagedFiles=$files.Count;RuntimeVerification=$verification;Bundle=$(if($KeepBundle){$bundle}else{''});TestBuild=[bool]$TestBuild;Development=[bool]$Development}
}finally{
 $prefix=[IO.Path]::GetFullPath((Join-Path $ProjectRoot '.tmp')).TrimEnd('\')+'\'
 if(-not [IO.Path]::GetFullPath($buildRoot).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw '构建暂存清理范围异常。'}
 if(-not $KeepBundle -and (Test-Path -LiteralPath $buildRoot)){Remove-Item -LiteralPath $buildRoot -Recurse -Force}
}
