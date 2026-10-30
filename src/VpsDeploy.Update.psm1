#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:UpdateRepository = 'mxh110708/may-vps-deploy'
$script:UpdateApi = 'https://api.github.com/repos/' + $script:UpdateRepository

function Get-VpsApplicationVersion {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $path = Join-Path $ProjectRoot 'config/application.json'
    if (Test-Path -LiteralPath $path) {
        $value = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable
        if ([string]$value.version -notmatch '^\d+\.\d+\.\d+$') { throw '应用版本文件无效。' }
        return [version]$value.version
    }
    throw '缺少应用版本文件。请使用完整发布包。'
}
function Assert-VpsUpdateAssetUri {
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Tag)
    $parsed = [uri]$Uri
    $prefix = '/' + $script:UpdateRepository + '/releases/download/' + $Tag + '/'
    if ($parsed.Scheme -ne 'https' -or $parsed.Host -ne 'github.com' -or $parsed.Port -ne 443 -or -not $parsed.AbsolutePath.StartsWith($prefix, [StringComparison]::Ordinal) -or $parsed.Query -or $parsed.Fragment -or $parsed.UserInfo) {
        throw '更新资产地址不属于本项目的正式发布。'
    }
}
function Get-VpsApplicationUpdate {
    param([Parameter(Mandatory)][string]$ProjectRoot, [string]$Proxy)
    $current = Get-VpsApplicationVersion $ProjectRoot
    $request = @{ Uri = "$script:UpdateApi/releases/latest"; Headers = @{ 'User-Agent' = 'May-VPS-Deploy'; Accept = 'application/vnd.github+json' }; TimeoutSec = 30 }
    if ($Proxy) {
        $uri = [uri]$Proxy
        if ($uri.Scheme -notin @('http','https')) { throw '请填写 HTTP/HTTPS 代理地址。' }
        $request.Proxy = $Proxy
    }
    $release = Invoke-RestMethod @request
    if ($release.draft -or $release.prerelease -or $release.tag_name -notmatch '^v(\d+\.\d+\.\d+)$') { throw '未找到有效的正式版本。' }
    $version = [version]$Matches[1]
    $tag = [string]$release.tag_name
    $distribution=Get-VpsApplicationDistribution $ProjectRoot
    $result = @{
        Available = ($version -gt $current); CurrentVersion = $current.ToString(); Version = $version.ToString()
        Tag = $tag; Notes = [string]$release.body; ReleaseUrl = [string]$release.html_url
        Distribution=$distribution
    }
    if (-not $result.Available) { return $result }
    $name = "may-vps-deploy-$tag-windows-amd64.zip"
    $archives = @($release.assets | Where-Object name -CEQ $name)
    $checksums = @($release.assets | Where-Object name -CEQ 'SHA256SUMS.txt')
    if ($archives.Count -ne 1 -or $checksums.Count -ne 1) { throw '发布包或校验文件不完整。' }
    $required=@($archives[0],$checksums[0])
    if($distribution -eq 'Installed'){
        $setups=@($release.assets|Where-Object name -CEQ "may-vps-deploy-$tag-windows-amd64-setup.exe")
        $manifests=@($release.assets|Where-Object name -CEQ "may-vps-deploy-$tag-windows-amd64.files.json")
        if($setups.Count -ne 1 -or $manifests.Count -ne 1){throw '安装版更新附件不完整。'}
        $required+=@($setups[0],$manifests[0]);$result.Installer=$setups[0];$result.FileManifest=$manifests[0]
    }
    foreach ($asset in $required) {
        Assert-VpsUpdateAssetUri $asset.browser_download_url $tag
        if ($asset.size -le 0 -or $asset.size -gt 536870912) { throw '发布附件大小异常。' }
        if ($asset.digest -notmatch '^sha256:[0-9a-f]{64}$') { throw '发布附件缺少 SHA-256。' }
    }
    $result.Archive = $archives[0]; $result.Checksums = $checksums[0]
    return $result
}
function Get-VpsApplicationDistribution {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $marker=Join-Path $ProjectRoot 'installation.json'
    if(Test-Path -LiteralPath $marker){
        $value=Get-Content -Raw -LiteralPath $marker|ConvertFrom-Json -AsHashtable
        if($value.schema_version -ne 1 -or $value.type -ne 'installed' -or $value.app_id -ne 'may-vps-deploy-desktop'){throw '应用安装记录无效，请核对完整安装目录。'}
        return 'Installed'
    }
    if(Test-Path -LiteralPath (Join-Path $ProjectRoot '.git')){return 'Git'}
    return 'Portable'
}
function Assert-VpsApplicationFilePath {
    param([Parameter(Mandatory)][string]$RelativePath)
    if ($RelativePath -match '(^/|\\|:|(^|/)\.\.?(/|$)|[<>|?*\x00-\x1f])' -or $RelativePath -match '(^|/)(\.git|\.tmp|\.cache|private|logs|state|exports|data)(/|$)' -or $RelativePath -match '\.(local\.json|private\.(json|txt)|key|pem)$' -or $RelativePath -match '(^|/)(root\.txt|params\.json|id_ed25519|id_rsa|installation\.json)$') {
        throw '更新包包含不允许的路径。'
    }
    foreach ($part in $RelativePath.Split('/')) {
        if (-not $part -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)') { throw '更新文件名无效。' }
    }
}
function Read-VpsApplicationManifest {
    param([Parameter(Mandatory)][string]$Directory)
    $path = Join-Path $Directory 'application-files.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw '发布包缺少应用文件清单。' }
    $manifest = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable
    if ($manifest.schema_version -ne 1 -or $manifest.version -notmatch '^\d+\.\d+\.\d+$' -or -not @($manifest.files).Count) { throw '应用文件清单无效。' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $manifest.files) {
        Assert-VpsApplicationFilePath $file.path
        if (-not $seen.Add([string]$file.path) -or $file.sha256 -notmatch '^[0-9a-f]{64}$' -or $file.path -eq 'application-files.json') { throw '应用文件清单重复或校验值无效。' }
    }
    return $manifest
}
function Expand-VpsVerifiedApplicationPackage {
    param([Parameter(Mandatory)][string]$Archive, [Parameter(Mandatory)][string]$Destination)
    if (Test-Path -LiteralPath $Destination) { throw '更新解压目录必须为空。' }
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if($zip.Entries.Count -gt 3000){throw '更新包文件数量异常。'}
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [long]$total = 0
        foreach ($entry in $zip.Entries) {
            $entryPath = $entry.FullName.TrimEnd('/')
            Assert-VpsApplicationFilePath $entryPath
            if ($entry.FullName.EndsWith('/')) { continue }
            if (-not $names.Add($entry.FullName)) { throw '更新包存在重复文件。' }
            if (($entry.ExternalAttributes -shr 16 -band 0xF000) -eq 0xA000) { throw '更新包不能包含联接。' }
            $total += $entry.Length
            if ($total -gt 734003200 -or $names.Count -gt 2500) { throw '更新包解压大小异常。' }
        }
        [IO.Directory]::CreateDirectory($Destination) | Out-Null
        [IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip, $Destination)
    } finally { $zip.Dispose() }
    $manifest = Read-VpsApplicationManifest $Destination
    $listed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $manifest.files) {
        [void]$listed.Add([string]$file.path)
        $path = Join-Path $Destination $file.path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw '更新包内文件校验失败。' }
    }
    [void]$listed.Add('application-files.json')
    if (-not $listed.SetEquals($names)) { throw '更新包存在清单之外的文件。' }
    if ((Get-VpsApplicationVersion $Destination).ToString() -ne $manifest.version) { throw '包内应用版本与清单不一致。' }
    return $manifest
}
function Assert-VpsApplicationWritableScope {
    param([Parameter(Mandatory)][string]$ProjectRoot, [Parameter(Mandatory)][string]$RelativePath)
    Assert-VpsApplicationFilePath $RelativePath
    $root = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $target = [IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    if (-not $target.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw '更新目标超出应用目录。' }
    $cursor = $target
    while ($cursor.Length -ge $root.TrimEnd('\','/').Length) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '应用文件路径含联接，不能自动更新。' }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $target
}
function Install-VpsPortableApplicationUpdate {
    # Changed managed files only; current .local.json and unregistered files are never owned.
    param([Parameter(Mandatory)][string]$ProjectRoot, [Parameter(Mandatory)][string]$PackageDirectory,
          [Parameter(Mandatory)][string]$RollbackDirectory)
    if (Test-Path -LiteralPath $RollbackDirectory) { throw '更新恢复目录已存在。' }
    if (Test-Path -LiteralPath (Join-Path $ProjectRoot '.git')) { throw 'Git 工作树请使用标签快进更新。' }
    $old = Read-VpsApplicationManifest $ProjectRoot; $new = Read-VpsApplicationManifest $PackageDirectory
    if ((Get-VpsApplicationVersion $ProjectRoot).ToString() -ne $old.version) { throw '当前应用版本与文件清单不一致。' }
    if ([version]$new.version -le [version]$old.version) { throw '不能降级或重复安装当前版本。' }
    $owned = @{}
    foreach ($f in $old.files) {
        $path = Assert-VpsApplicationWritableScope $ProjectRoot $f.path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -ne $f.sha256) { throw '应用文件有本地改动，已停止更新以保留修改。' }
        $owned[$f.path] = $f
    }
    foreach ($f in $new.files) {
        $target = Assert-VpsApplicationWritableScope $ProjectRoot $f.path
        $source = Join-Path $PackageDirectory $f.path
        if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or (Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant() -ne $f.sha256) { throw '新应用文件校验失败。' }
        if ((Test-Path -LiteralPath $target) -and -not $owned.ContainsKey($f.path)) { throw '新版本与未受管文件冲突，未覆盖用户文件。' }
    }
    [IO.Directory]::CreateDirectory($RollbackDirectory) | Out-Null
    $changed = [Collections.Generic.List[string]]::new()
    $original = @{}
    try {
        foreach ($f in $new.files) {
            if ($owned.ContainsKey($f.path) -and $owned[$f.path].sha256 -eq $f.sha256) { continue }
            $target = Join-Path $ProjectRoot $f.path
            $backup = Join-Path $RollbackDirectory $f.path
            if (Test-Path -LiteralPath $target) {
                [IO.Directory]::CreateDirectory((Split-Path -Parent $backup)) | Out-Null
                Copy-Item -LiteralPath $target -Destination $backup
                $original[$f.path] = $backup
            }
            $changed.Add([string]$f.path)
            [IO.Directory]::CreateDirectory((Split-Path -Parent $target)) | Out-Null
            Copy-Item -LiteralPath (Join-Path $PackageDirectory $f.path) -Destination $target -Force
        }
        $newNames = @($new.files | ForEach-Object path)
        foreach ($f in $old.files) {
            if ($f.path -in $newNames) { continue }
            $target = Join-Path $ProjectRoot $f.path; $backup = Join-Path $RollbackDirectory $f.path
            [IO.Directory]::CreateDirectory((Split-Path -Parent $backup)) | Out-Null
            Copy-Item -LiteralPath $target -Destination $backup
            $original[$f.path] = $backup; $changed.Add([string]$f.path)
            Remove-Item -LiteralPath $target
        }
        $manifestBackup = Join-Path $RollbackDirectory 'application-files.json'
        Copy-Item -LiteralPath (Join-Path $ProjectRoot 'application-files.json') -Destination $manifestBackup
        $original['application-files.json'] = $manifestBackup; $changed.Add('application-files.json')
        Copy-Item -LiteralPath (Join-Path $PackageDirectory 'application-files.json') -Destination (Join-Path $ProjectRoot 'application-files.json') -Force
        foreach ($f in $new.files) {
            if ((Get-FileHash -LiteralPath (Join-Path $ProjectRoot $f.path)).Hash.ToLowerInvariant() -ne $f.sha256) { throw '更新后文件校验失败。' }
        }
    } catch {
        $failure = $_
        $restoreFailures = 0
        foreach ($relative in $changed) {
            $target = Join-Path $ProjectRoot $relative
            try {
                if ($original.ContainsKey($relative)) { Copy-Item -LiteralPath $original[$relative] -Destination $target -Force }
                elseif (Test-Path -LiteralPath $target -PathType Leaf) { Remove-Item -LiteralPath $target }
            } catch { $restoreFailures++ }
        }
        if ($restoreFailures) { throw '更新失败，部分文件需要从本次更新恢复目录手动恢复；恢复材料已保留。' }
        throw $failure
    }
}
function Invoke-VpsUpdateGit {
    param([string]$ProjectRoot,[string[]]$Arguments,[string]$Proxy,[switch]$AllowNonzero)
    $start = [Diagnostics.ProcessStartInfo]::new('git')
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $start.Environment['GIT_TERMINAL_PROMPT']='0'; $start.Environment['GCM_INTERACTIVE']='Never'
    foreach ($arg in @('-c',"safe.directory=$ProjectRoot",'-c','core.hooksPath=/dev/null','-C',$ProjectRoot)) { $start.ArgumentList.Add($arg) }
    if ($Proxy) { foreach ($arg in @('-c',"http.proxy=$Proxy")) { $start.ArgumentList.Add($arg) } }
    foreach ($arg in $Arguments) { $start.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) { $process.Kill($true); throw 'Git 更新请求超时。' }
        $output = $stdout.GetAwaiter().GetResult(); [void]$stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -and -not $AllowNonzero) { throw 'Git 更新步骤未完成；当前文件和私人数据保留。' }
        return @{ ExitCode=$process.ExitCode; Output=$output.Trim() }
    } finally { $process.Dispose() }
}
function Assert-VpsGitApplicationClean {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $branch = (Invoke-VpsUpdateGit $ProjectRoot @('branch','--show-current')).Output
    if ($branch -ne 'main') { throw '自动更新仅支持 main 使用副本；当前分支保留。' }
    $status = (Invoke-VpsUpdateGit $ProjectRoot @('status','--porcelain=v1','--untracked-files=all')).Output
    if ($status) { throw '应用源码有本地修改，已停止更新以保留用户改动。' }
}
function Complete-VpsGitApplicationUpdate {
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][string]$Tag,[Parameter(Mandatory)][string]$Version)
    if ($Tag -cne "v$Version" -or $Version -notmatch '^\d+\.\d+\.\d+$') { throw '更新标签无效。' }
    Assert-VpsGitApplicationClean $ProjectRoot
    if ([version]$Version -le (Get-VpsApplicationVersion $ProjectRoot)) { throw '不能降级或重复安装当前版本。' }
    $ancestry = Invoke-VpsUpdateGit $ProjectRoot @('merge-base','--is-ancestor','HEAD',"$Tag^{}") -AllowNonzero
    if ($ancestry.ExitCode -ne 0) { throw '新版本不能从当前提交快进，未改变 Git 历史。' }
    $application = (Invoke-VpsUpdateGit $ProjectRoot @('show',"${Tag}:config/application.json")).Output | ConvertFrom-Json -AsHashtable
    if ($application.version -ne $Version -or $application.channel -ne 'stable') { throw '标签中的应用版本无效。' }
    $oldPaths = @((Invoke-VpsUpdateGit $ProjectRoot @('ls-files')).Output -split '\r?\n')
    foreach ($relative in ((Invoke-VpsUpdateGit $ProjectRoot @('ls-tree','-r','--name-only',$Tag)).Output -split '\r?\n')) {
        Assert-VpsApplicationFilePath $relative
        $target = Assert-VpsApplicationWritableScope $ProjectRoot $relative
        if ((Test-Path -LiteralPath $target) -and $relative -cnotin $oldPaths) { throw '新版本与本地未受管文件冲突，未覆盖用户文件。' }
    }
    [void](Invoke-VpsUpdateGit $ProjectRoot @('merge','--ff-only','--no-edit',$Tag))
    if ((Get-VpsApplicationVersion $ProjectRoot).ToString() -ne $Version) { throw '更新后的版本复核失败，请查看本次更新恢复材料。' }
}
function Get-VpsGitApplicationRelease {
    param([Parameter(Mandatory)][string]$ProjectRoot,[Parameter(Mandatory)][string]$Tag,[string]$Proxy)
    $remote = (Invoke-VpsUpdateGit $ProjectRoot @('remote','get-url','origin')).Output
    if ($remote -notmatch '^(https://github\.com/|git@github\.com:)mxh110708/may-vps-deploy(?:\.git)?$') { throw '使用副本的 origin 不属于本项目，未更新。' }
    [void](Invoke-VpsUpdateGit $ProjectRoot @('fetch','--no-tags','--no-recurse-submodules','https://github.com/mxh110708/may-vps-deploy.git',"refs/tags/${Tag}:refs/tags/$Tag") $Proxy)
}
function Start-VpsApplicationUpdate {
    param([Parameter(Mandatory)][string]$ProjectRoot,[string]$Proxy,[Parameter(Mandatory)][int]$ParentProcessId,[AllowNull()][object]$InteractionSession)
    $info = Get-VpsApplicationUpdate $ProjectRoot $Proxy
    if (-not $info.Available) { throw '当前没有可安装的新版本。' }
    if($info.Distribution -eq 'Installed'){return Start-VpsInstalledApplicationUpdate $ProjectRoot $info $Proxy $ParentProcessId $InteractionSession}
    if (Test-Path -LiteralPath (Join-Path $ProjectRoot '.git')) { Assert-VpsGitApplicationClean $ProjectRoot }
    if ($InteractionSession -and $InteractionSession.CancelRequested) { throw [OperationCanceledException]::new('__MXH_VPS_WIZARD_CANCEL__') }
    $stage = Join-Path $ProjectRoot ('.tmp/app-update-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    try {
        $download = @{ TimeoutSec = 120 }
        if ($Proxy) { $download.Proxy = $Proxy }
        $archive = Join-Path $stage $info.Archive.name; $checksum = Join-Path $stage 'SHA256SUMS.txt'
        Invoke-WebRequest -Uri $info.Archive.browser_download_url -OutFile $archive @download
        Invoke-WebRequest -Uri $info.Checksums.browser_download_url -OutFile $checksum @download
        foreach ($pair in @(@($archive,$info.Archive),@($checksum,$info.Checksums))) {
            if ((Get-Item -LiteralPath $pair[0]).Length -ne $pair[1].size -or ('sha256:'+(Get-FileHash -LiteralPath $pair[0]).Hash.ToLowerInvariant()) -ne $pair[1].digest) { throw '更新附件与 GitHub SHA-256 不一致。' }
        }
        $hashLine = (Get-FileHash -LiteralPath $archive).Hash.ToLowerInvariant() + '  ' + $info.Archive.name
        if ($hashLine -cnotin @(Get-Content -LiteralPath $checksum)) { throw '发布校验文件与下载包不一致。' }
        $package = Join-Path $stage 'package'
        $manifest = Expand-VpsVerifiedApplicationPackage $archive $package
        if ($manifest.version -ne $info.Version) { throw '发布版本与下载包不一致。' }
        if ($InteractionSession -and $InteractionSession.CancelRequested) { throw [OperationCanceledException]::new('__MXH_VPS_WIZARD_CANCEL__') }
        $jobPath = Join-Path $stage 'update-job.private.json'
        $launcherPid=0;[void][int]::TryParse($env:MXH_VPS_DESKTOP_PARENT,[ref]$launcherPid)
        $job = @{ ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot); Stage=$stage; Package=$package; Version=$info.Version; Tag=$info.Tag; ParentPid=$ParentProcessId; LauncherPid=$launcherPid; Proxy=$Proxy }
        $job | ConvertTo-Json | Set-Content -LiteralPath $jobPath -Encoding utf8
        # The helper itself remains outside the application files being replaced.
        $helper = Join-Path $stage 'Complete-VpsAppUpdate.ps1'
        Copy-Item -LiteralPath (Join-Path $ProjectRoot 'scripts/Complete-VpsAppUpdate.ps1') -Destination $helper
        Copy-Item -LiteralPath (Join-Path $ProjectRoot 'src/VpsDeploy.Update.psm1') -Destination (Join-Path $stage 'VpsDeploy.Update.psm1')
        $helperRuntime=Join-Path $PSHOME 'pwsh.exe'
        if(Test-Path -LiteralPath (Join-Path $ProjectRoot 'desktop-runtime.json')){
            $runtime=Join-Path $stage 'helper-runtime'
            Copy-Item -LiteralPath (Join-Path $ProjectRoot 'runtime/powershell') -Destination $runtime -Recurse
            $helperRuntime=Join-Path $runtime 'pwsh.exe'
        }
        $process = [Diagnostics.ProcessStartInfo]::new($helperRuntime)
        $process.UseShellExecute=$false; $process.CreateNoWindow=$true
        foreach($a in @('-NoProfile','-STA','-WindowStyle','Hidden','-File',$helper,'-JobPath',$jobPath)) { $process.ArgumentList.Add($a) }
        [void][Diagnostics.Process]::Start($process)
        return @{ RestartRequired=$true; Version=$info.Version }
    } catch {
        # This is a new, validated staging directory under this application.
        if ([IO.Path]::GetFullPath($stage).StartsWith([IO.Path]::GetFullPath((Join-Path $ProjectRoot '.tmp')) + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
        throw
    }
}
function Start-VpsInstalledApplicationUpdate {
    param([string]$ProjectRoot,[Collections.IDictionary]$Info,[string]$Proxy,[int]$ParentProcessId,[AllowNull()][object]$InteractionSession)
    $stage=Join-Path $ProjectRoot ('.tmp/app-update-'+[guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($stage)|Out-Null
    try{
        $download=@{TimeoutSec=240};if($Proxy){$download.Proxy=$Proxy}
        foreach($asset in @($Info.Installer,$Info.FileManifest,$Info.Checksums)){
            $path=Join-Path $stage $asset.name
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $path @download
            if((Get-Item -LiteralPath $path).Length -ne $asset.size -or ('sha256:'+(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()) -ne $asset.digest){throw '安装版更新附件摘要不一致。'}
        }
        $checksumLines=@(Get-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt'))
        foreach($asset in @($Info.Installer,$Info.FileManifest)){
            $expected=(Get-FileHash -LiteralPath (Join-Path $stage $asset.name)).Hash.ToLowerInvariant()+'  '+$asset.name
            if($expected -cnotin $checksumLines){throw '安装版更新校验文件不一致。'}
        }
        $next=Join-Path $stage $Info.FileManifest.name
        Copy-Item -LiteralPath $next -Destination (Join-Path $stage 'application-files.json')
        $manifest=Read-VpsApplicationManifest $stage
        Remove-Item -LiteralPath (Join-Path $stage 'application-files.json')
        if($manifest.version -ne $Info.Version){throw '安装版更新版本不一致。'}
        $guard=[Diagnostics.ProcessStartInfo]::new((Join-Path $ProjectRoot 'app-helpers/SetupGuard.exe'))
        $guard.UseShellExecute=$false;$guard.CreateNoWindow=$true
        $guard.ArgumentList.Add($ProjectRoot);$guard.ArgumentList.Add($next)
        $check=[Diagnostics.Process]::Start($guard)
        try{if(-not $check.WaitForExit(120000) -or $check.ExitCode -ne 0){throw '应用文件有改动或与本地文件冲突，未开始更新。'}}finally{$check.Dispose()}
        if($InteractionSession -and $InteractionSession.CancelRequested){throw [OperationCanceledException]::new('__MXH_VPS_WIZARD_CANCEL__')}
        $launcherPid=0;[void][int]::TryParse($env:MXH_VPS_DESKTOP_PARENT,[ref]$launcherPid)
        $parent=Get-Process -Id $ParentProcessId -ErrorAction Stop
        $launcher=if($launcherPid){Get-Process -Id $launcherPid -ErrorAction Stop}else{$null}
        $job=@{ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot);Stage=[IO.Path]::GetFullPath($stage);Version=$Info.Version;ParentPid=$ParentProcessId;LauncherPid=$launcherPid;ParentStarted=$parent.StartTime.ToUniversalTime().ToString('o');LauncherStarted=$(if($launcher){$launcher.StartTime.ToUniversalTime().ToString('o')}else{''});InstallerSha256=(Get-FileHash -LiteralPath (Join-Path $stage $Info.Installer.name)).Hash.ToLowerInvariant();ManifestSha256=(Get-FileHash -LiteralPath $next).Hash.ToLowerInvariant();CurrentManifestSha256=(Get-FileHash -LiteralPath (Join-Path $ProjectRoot 'application-files.json')).Hash.ToLowerInvariant()}
        $jobPath=Join-Path $stage 'update-job.private.json';$job|ConvertTo-Json|Set-Content -LiteralPath $jobPath -Encoding utf8
        $helper=Join-Path $stage 'InstalledUpdate.exe'
        Copy-Item -LiteralPath (Join-Path $ProjectRoot 'app-helpers/InstalledUpdate.exe') -Destination $helper
        $start=[Diagnostics.ProcessStartInfo]::new($helper);$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.ArgumentList.Add($jobPath)
        [void][Diagnostics.Process]::Start($start)
        return @{RestartRequired=$true;Version=$Info.Version}
    }catch{
        $prefix=[IO.Path]::GetFullPath((Join-Path $ProjectRoot '.tmp')).TrimEnd('\')+'\'
        if([IO.Path]::GetFullPath($stage).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){Remove-Item -LiteralPath $stage -Recurse -Force}
        throw
    }
}
Export-ModuleMember -Function Get-VpsApplicationVersion, Get-VpsApplicationUpdate, Assert-VpsUpdateAssetUri, Assert-VpsApplicationFilePath,
    Read-VpsApplicationManifest, Expand-VpsVerifiedApplicationPackage, Assert-VpsApplicationWritableScope,
    Install-VpsPortableApplicationUpdate, Start-VpsApplicationUpdate, Assert-VpsGitApplicationClean,
    Complete-VpsGitApplicationUpdate, Get-VpsGitApplicationRelease, Get-VpsApplicationDistribution
