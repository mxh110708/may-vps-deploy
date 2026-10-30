[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CoreRoot,
    [Parameter(Mandatory)][string]$GoExecutable,
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Version = '1.14.2-may.xhttp20.0'
)

# Development source snapshot, not a claim that this revision has been released.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$CoreRoot = (Resolve-Path -LiteralPath $CoreRoot).Path
$GoExecutable = (Resolve-Path -LiteralPath $GoExecutable).Path
if ((Get-Content -Raw -LiteralPath (Join-Path $CoreRoot 'go.mod')) -notmatch 'module github.com/sagernet/sing-box' -or
    $Version -notmatch '^1\.14\.2-may\.xhttp20\.[0-9]+$') { throw '需要对应的 May Core 工作树和开发版本。' }
$revision = & git -C $CoreRoot -c "safe.directory=$($CoreRoot.Replace('\','/'))" rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') { throw '无法核对源代码提交。' }
$changes = @(& git -C $CoreRoot -c "safe.directory=$($CoreRoot.Replace('\','/'))" status --porcelain --untracked-files=all)
if ($LASTEXITCODE -ne 0) { throw '无法核对源代码工作树状态。' }
$files = @(& git -C $CoreRoot -c "safe.directory=$($CoreRoot.Replace('\','/'))" ls-files -c --others --exclude-standard | Sort-Object -Unique)
if ($LASTEXITCODE -ne 0 -or $files.Count -lt 100) { throw '无法列出完整公开源代码。' }
$sourceRoot = 'may-core-' + $Version + '-source'
$vendor = Join-Path $ProjectRoot 'vendor/test-cores/windows-amd64'
$work = Join-Path $ProjectRoot ('.tmp/may-core-validation-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory((Join-Path $work $sourceRoot)) | Out-Null
$hashLines = foreach ($file in $files) {
    if ($file.Contains('..') -or [IO.Path]::IsPathRooted($file)) { throw '源代码路径无效。' }
    $origin = Get-Item -LiteralPath (Join-Path $CoreRoot $file)
    # Gitlinks are separate client repositories, not part of the CLI build.
    if ($origin.PSIsContainer) { continue }
    if ($origin.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '源代码快照不能包含链接。' }
    $destination = Join-Path $work ($sourceRoot + '/' + $file)
    [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
    Copy-Item -LiteralPath $origin.FullName -Destination $destination
    $file + "`t" + (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
}
$utf8 = [Text.UTF8Encoding]::new($false)
$treeBytes = $utf8.GetBytes(($hashLines -join "`n") + "`n")
$treeHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($treeBytes)).ToLowerInvariant()
[IO.File]::WriteAllBytes((Join-Path $work ($sourceRoot + '/SOURCE-FILES.sha256')), $treeBytes)
$snapshot = Join-Path $work $sourceRoot
$tags = (Get-Content -Raw -LiteralPath (Join-Path $snapshot 'release/DEFAULT_BUILD_TAGS_OTHERS')).Trim()
$link = (Get-Content -Raw -LiteralPath (Join-Path $snapshot 'release/LDFLAGS')).Trim() + ' -X github.com/sagernet/sing-box/constant.Version=' + $Version
$toolchain = & $GoExecutable version
if ($LASTEXITCODE -ne 0 -or $toolchain -notmatch 'go1\.26\.8 windows/amd64') { throw '需要固定 Go 1.26.8 windows/amd64 工具链。' }
$exe = Join-Path $work 'may-core.exe'
# Build the very snapshot being archived, so concurrent workspace edits cannot
# make the executable differ from the corresponding source offered with it.
Push-Location (Join-Path $work $sourceRoot)
try {
    & $GoExecutable build -buildvcs=false -trimpath -tags $tags -ldflags $link -o $exe ./cmd/sing-box
    if ($LASTEXITCODE -ne 0) { throw 'May Core 构建失败。' }
} finally { Pop-Location }
$name = 'may-core-' + $Version + '-windows-amd64.zip'
$sourceName = $sourceRoot + '.zip'
Copy-Item -LiteralPath (Join-Path $snapshot 'LICENSE') -Destination (Join-Path $work 'LICENSE')
Copy-Item -LiteralPath (Join-Path $snapshot 'common/xhttpwire/LICENSE.mihomo') -Destination (Join-Path $work 'LICENSE.mihomo')
Copy-Item -LiteralPath (Join-Path $snapshot 'common/xhttpwire/THIRD-PARTY.md') -Destination (Join-Path $work 'THIRD-PARTY.md')
Compress-Archive -LiteralPath @($exe, (Join-Path $work 'LICENSE'), (Join-Path $work 'LICENSE.mihomo'), (Join-Path $work 'THIRD-PARTY.md')) -DestinationPath (Join-Path $work $name)
Compress-Archive -LiteralPath (Join-Path $work $sourceRoot) -DestinationPath (Join-Path $work $sourceName)
$artifact = [ordered]@{
    core = 'may-core'; version = $Version; file = $name
    sha256 = (Get-FileHash -LiteralPath (Join-Path $work $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    capabilities = @('vless-xhttp-round20')
    source_repository = 'https://github.com/mxh110708/may-route-core'
    source_revision = $revision.Trim(); source_working_tree = ($changes.Count -ne 0); source_tree_sha256 = $treeHash
    source_archive = $sourceName
    source_archive_sha256 = (Get-FileHash -LiteralPath (Join-Path $work $sourceName) -Algorithm SHA256).Hash.ToLowerInvariant()
    toolchain = $toolchain.Trim(); build_tags = $tags; build_ldflags = $link
    binary_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    build_options = @('-buildvcs=false', '-trimpath'); lifecycle = 'unreleased-development-snapshot'
}
$manifestFile = Join-Path $vendor 'checksums.json'
$manifest = Get-Content -Raw -LiteralPath $manifestFile | ConvertFrom-Json
$manifest.artifacts = @($manifest.artifacts | Where-Object core -ne 'may-core') + @($artifact)
Copy-Item -LiteralPath (Join-Path $work $name) -Destination (Join-Path $vendor $name) -Force
Copy-Item -LiteralPath (Join-Path $work $sourceName) -Destination (Join-Path $vendor $sourceName) -Force
[IO.File]::WriteAllText($manifestFile, ($manifest | ConvertTo-Json -Depth 20) + "`n", $utf8)
Write-Host ('已构建并记录配套 May Core、完整源码快照及 SHA-256：' + $treeHash)
