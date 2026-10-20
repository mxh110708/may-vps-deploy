[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$MayRouteBundlePath,
    [string]$SourceDirectory,
    [switch]$Offline,
    [switch]$RepairExisting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$vendorRoot = [IO.Path]::GetFullPath((Join-Path $ProjectRoot 'vendor/test-cores/windows-amd64'))
$manifest = Get-Content -Raw -LiteralPath (Join-Path $vendorRoot 'checksums.json') | ConvertFrom-Json
$versions = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config/versions.json') | ConvertFrom-Json
$work = Join-Path $ProjectRoot ('.tmp/client-assets-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null
if($SourceDirectory){$SourceDirectory=(Resolve-Path -LiteralPath $SourceDirectory -ErrorAction Stop).Path}

function Test-AssetHash([string]$Path, [string]$Hash) {
    return (Test-Path -LiteralPath $Path -PathType Leaf) -and
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -eq $Hash
}

function Get-AssetDestination([string]$Relative) {
    if($Relative -notmatch '^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?$'){throw '不支持的资产相对路径。'}
    $path=[IO.Path]::GetFullPath((Join-Path $vendorRoot $Relative))
    if(-not $path.StartsWith($vendorRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw '资产路径越界。'}
    return $path
}
function Install-VerifiedAsset([string]$Path,[string]$Relative,[string]$Hash) {
    if(-not(Test-AssetHash $Path $Hash)){throw "资产 SHA-256 不匹配：$Relative"}
    $destination=Get-AssetDestination $Relative
    if(Test-AssetHash $destination $Hash){return}
    if(Test-Path -LiteralPath $destination){
        if(-not $RepairExisting){throw "现有资产校验失败：$Relative；明确使用 -RepairExisting 后才会隔离并替换。"}
        $backup=Join-Path $work ('replaced/'+$Relative)
        [IO.Directory]::CreateDirectory((Split-Path -Parent $backup))|Out-Null
        Move-Item -LiteralPath $destination -Destination $backup
    }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $destination))|Out-Null
    Copy-Item -LiteralPath $Path -Destination $destination
    Write-Host "已校验并恢复资产：$Relative"
}
function Restore-RemoteAsset($Asset,[string]$Kind) {
    $destination=Get-AssetDestination $Asset.file
    if($Asset.sha256 -notmatch '^[0-9a-f]{64}$'){throw '资产校验值无效。'}
    if($Kind -eq 'Core'){
        if($Asset.file -notmatch '^[A-Za-z0-9.-]+\.zip$' -or $Asset.source -notmatch '^https://github\.com/(MetaCubeX/mihomo|SagerNet/sing-box)/releases/download/v[0-9.]+/[A-Za-z0-9.-]+\.zip$'){throw '不支持的核心资产来源。'}
    }elseif($Asset.file -notin @('mihomo-geodata/GeoSite.dat','mihomo-geodata/GeoIP.dat') -or
        $Asset.source -notmatch '^https://api\.github\.com/repos/MetaCubeX/meta-rules-dat/releases/assets/[0-9]+$'){
        throw 'GeoData 必须使用已记录的 GitHub 资产 ID，不能使用可变的 latest 下载地址。'
    }
    if(Test-AssetHash $destination $Asset.sha256){return}
    $source=if($SourceDirectory){Join-Path $SourceDirectory $Asset.file}else{''}
    if($source -and (Test-Path -LiteralPath $source)){
        Install-VerifiedAsset $source $Asset.file $Asset.sha256; return
    }
    if($Offline){throw "离线资产来源中缺少：$($Asset.file)"}
    $download=Join-Path $work $Asset.file
    [IO.Directory]::CreateDirectory((Split-Path -Parent $download))|Out-Null
    $headers=@{'User-Agent'='mxh-vps-deploy-assets'; Accept=if($Kind -eq 'GeoData'){'application/octet-stream'}else{'application/zip'}}
    Invoke-WebRequest -Uri $Asset.source -Headers $headers -OutFile $download -TimeoutSec 180
    Install-VerifiedAsset $download $Asset.file $Asset.sha256
}

foreach($asset in $manifest.artifacts){Restore-RemoteAsset $asset Core}
$geo=@($manifest.data_files|Where-Object consumer -eq 'mihomo')
if($geo.Count -ne 2){throw 'GeoData 清单须包含 GeoSite 和 GeoIP。'}
foreach($asset in $geo){Restore-RemoteAsset $asset GeoData}
$entries = @($manifest.data_files | Where-Object consumer -eq 'sing-box')
if($entries.Count -ne 5){throw '离线规则清单须包含五项规则。'}
$missing=@()
foreach ($entry in $entries) {
    if ($entry.tag -notmatch '^geo(site|ip)-[a-z-]+$' -or $entry.file -ne "mxh-route-public-rules/$($entry.tag).srs" -or $entry.sha256 -notmatch '^[0-9a-f]{64}$') {throw '离线规则清单无效。'}
    $destination=Get-AssetDestination $entry.file
    if(Test-AssetHash $destination $entry.sha256){continue}
    $source=if($SourceDirectory){Join-Path $SourceDirectory $entry.file}else{''}
    if($source -and (Test-Path -LiteralPath $source)){Install-VerifiedAsset $source $entry.file $entry.sha256}
    else{$missing+=$entry}
}
# A complete verified set needs neither network access nor the original bundle.
if($missing.Count){
    $bundle=$versions.client_compatibility.mxh_route.public_rules_bundle
    if(-not $MayRouteBundlePath){
        if($Offline){throw '离线来源缺少规则；请提供固定的 May Route 规则包。'}
        $MayRouteBundlePath=Join-Path $work 'public-rules-v1.json'
        Invoke-WebRequest -Uri $bundle.source -OutFile $MayRouteBundlePath -TimeoutSec 60
    }
    if(-not(Test-AssetHash $MayRouteBundlePath $bundle.sha256)){throw 'May Route 规则包 SHA-256 不匹配。'}
    $rules=Get-Content -Raw -LiteralPath $MayRouteBundlePath|ConvertFrom-Json
    if($rules.version -ne 1 -or $rules.files.Count -ne 5){throw '规则包结构无效。'}
    foreach($entry in $missing){
        $found=@($rules.files|Where-Object name -eq $entry.tag)
        if($found.Count -ne 1 -or $found[0].sha256 -ne $entry.sha256){throw '规则包与固定清单不一致。'}
        $bytes=[Convert]::FromBase64String($found[0].data)
        if($bytes.Length -lt 4 -or [Text.Encoding]::ASCII.GetString($bytes,0,3) -ne 'SRS'){throw '规则数据格式无效。'}
        $path=Join-Path $work ($entry.tag+'.srs');[IO.File]::WriteAllBytes($path,$bytes)
        Install-VerifiedAsset $path $entry.file $entry.sha256
    }
}
Write-Host '客户端核心、GeoData 和离线规则已按固定清单校验。' -ForegroundColor Green
