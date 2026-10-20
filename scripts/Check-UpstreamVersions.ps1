[CmdletBinding()]
param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$versions = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config\versions.json') | ConvertFrom-Json
$settings = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config\app-defaults.json') | ConvertFrom-Json
$headers = @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'may-vps-deploy-version-check' }
$components = @(
    @{Name='Xray-core'; Pinned=[string]$versions.xray.version; Api=$settings.release_apis.xray},
    @{Name='Komari Agent'; Pinned=[string]$versions.komari_agent.version; Api=$settings.release_apis.komari_agent},
    @{Name='Komari Controller'; Pinned=[string]$versions.komari_controller.version; Api=$settings.release_apis.komari_controller},
    @{Name='sing-box Linux'; Pinned=[string]$versions.sing_box.version; Api=$settings.release_apis.sing_box},
    @{Name='sing-box Windows'; Pinned=[string]$versions.sing_box.assets.windows_amd64.version; Api=$settings.release_apis.sing_box},
    @{Name='Mihomo'; Pinned=[string]$versions.mihomo.version; Api=$settings.release_apis.mihomo},
    @{Name='May Route'; Pinned=[string]$versions.client_compatibility.may_route.version; Api=$settings.release_apis.may_route}
)
$results = @{}
foreach ($component in $components) {
    $api=[string]$component.Api
    if (-not $results.ContainsKey($api)) {
        try {
            if ($api -notmatch '^https://api\.github\.com/repos/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/releases/latest$') { throw '版本查询地址不受支持。' }
            $release = Invoke-RestMethod -Headers $headers -Uri $api -TimeoutSec 30
            if ($release.draft -or $release.prerelease) { throw '版本查询返回了非正式版本。' }
            $results[$api] = @{Version=([string]$release.tag_name).TrimStart('v'); Error=''}
        } catch { $results[$api]=@{Version=''; Error=$_.Exception.Message} }
    }
    $result=$results[$api]
    [pscustomobject]@{
        Component=$component.Name; Pinned=$component.Pinned; Upstream=$result.Version
        Same=if($result.Error){$null}else{$component.Pinned -eq $result.Version}
        Status=if($result.Error){'查询失败'}elseif($component.Pinned -eq $result.Version){'一致'}else{'需审查'}
        Error=$result.Error
    }
}
Write-Host '仅报告版本，不会自动升级。变更固定版本前须核对发布说明、资产校验值、配置兼容性和隔离运行结果。' -ForegroundColor Yellow
