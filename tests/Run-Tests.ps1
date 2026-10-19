[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ProjectRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$passed = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERT FAILED: $Message" }
    $script:passed++
}

Write-Host '== PowerShell syntax ==' -ForegroundColor Cyan
$parseErrors = [Collections.Generic.List[object]]::new()
Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File | Where-Object Extension -in @('.ps1', '.psm1') | ForEach-Object {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    foreach ($parseError in $errors) {
        $parseErrors.Add([pscustomobject]@{ File = $_.FullName; Line = $parseError.Extent.StartLineNumber; Message = $parseError.Message })
    }
}
if ($parseErrors.Count -gt 0) { $parseErrors | Format-Table -AutoSize; throw 'PowerShell parse failed.' }
Assert-True $true 'PowerShell files parse'

Write-Host '== Manifest and module graph ==' -ForegroundColor Cyan
$manifest = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config\versions.json') | ConvertFrom-Json
Assert-True ($manifest.schema_version -eq 1) 'version manifest schema'
Assert-True ([string]$manifest.xray.version -match '^\d+\.\d+\.\d+$') 'Xray pinned version'
Assert-True ([string]$manifest.xray.installer_commit -match '^[0-9a-f]{40}$') 'Xray installer commit'
Assert-True ([string]$manifest.xray.installer_sha256 -match '^[0-9a-f]{64}$') 'Xray installer SHA-256'
Assert-True ([string]$manifest.komari_agent.assets.amd64.sha256 -match '^[0-9a-f]{64}$') 'Komari amd64 SHA-256'
Assert-True ([string]$manifest.komari_controller.version -eq '1.5.1') 'Komari controller pinned latest stable baseline'
Assert-True ([string]$manifest.komari_agent.version -eq '1.5.11') 'Komari agent pinned latest stable baseline'
Assert-True ([string]$manifest.sing_box.assets.windows_amd64.version -eq '1.14.2' -and [string]$manifest.sing_box.version -eq '1.14.2') 'Linux and Windows stable baselines were independently verified at 1.14.2'
Assert-True ([string]$manifest.komari_controller.assets.amd64.name -eq 'komari-linux-amd64') 'Komari controller amd64 asset name'
Assert-True ([string]$manifest.komari_controller.assets.amd64.sha256 -match '^[0-9a-f]{64}$') 'Komari controller amd64 SHA-256'
Assert-True ([string]$manifest.komari_controller.assets.arm64.sha256 -match '^[0-9a-f]{64}$') 'Komari controller arm64 SHA-256'
Assert-True ([string]$manifest.sing_box.version -match '^\d+\.\d+\.\d+$') 'sing-box pinned version'
Assert-True ([string]$manifest.sing_box.assets.amd64.sha256 -match '^[0-9a-f]{64}$') 'sing-box amd64 SHA-256'
Assert-True ([string]$manifest.sing_box.assets.windows_amd64.sha256 -match '^[0-9a-f]{64}$') 'sing-box Windows SHA-256'
Assert-True ([string]$manifest.mihomo.version -eq '1.19.32') 'Mihomo stable test core version is pinned'
$vendorManifest = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'vendor\test-cores\windows-amd64\checksums.json') | ConvertFrom-Json
Assert-True (@($vendorManifest.artifacts).Count -eq 2) 'vendor manifest contains both required Windows test cores'
foreach ($artifact in @($vendorManifest.artifacts)) {
    $archive = Join-Path $ProjectRoot ('vendor\test-cores\windows-amd64\' + [string]$artifact.file)
    Assert-True (Test-Path -LiteralPath $archive -PathType Leaf) "vendored archive exists: $($artifact.core)"
    Assert-True ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -eq [string]$artifact.sha256) "vendored archive checksum matches: $($artifact.core)"
}
Assert-True (@($vendorManifest.data_files | Where-Object consumer -eq 'mihomo').Count -eq 2) 'vendor manifest contains both required Mihomo GeoData files'
Assert-True (@($vendorManifest.data_files | Where-Object consumer -eq 'sing-box').Count -eq 5) 'vendor manifest contains all five MXH Route offline public rules'
foreach ($dataFile in @($vendorManifest.data_files)) {
    $path = Join-Path $ProjectRoot ('vendor\test-cores\windows-amd64\' + [string]$dataFile.file)
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) "vendored data file exists: $($dataFile.file)"
    Assert-True ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -eq [string]$dataFile.sha256) "vendored data checksum matches: $($dataFile.file)"
}
$appDefaults=Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config\app-defaults.json')|ConvertFrom-Json -AsHashtable
$clientDefaults=Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config\client-layout.default.json')|ConvertFrom-Json -AsHashtable
Assert-True ([int]$clientDefaults.schema_version -eq 2) 'portable client layout schema'
Assert-True ([string]::IsNullOrWhiteSpace([string]$clientDefaults.authority_defaults.clash) -and [string]::IsNullOrWhiteSpace([string]$clientDefaults.authority_defaults.sing_box)) 'generic client defaults contain no personal authority paths'
Assert-True (-not((Get-Content -Raw (Join-Path $ProjectRoot 'config\client-layout.default.json')) -match '(?i)F:\\VPS|20041114\.xyz|lenovo')) 'generic client defaults contain no personal environment values'
Assert-True (Test-Path (Join-Path $ProjectRoot 'templates\client\clash-general.template.yaml')) 'generic Clash authority template exists'
Assert-True (Test-Path (Join-Path $ProjectRoot 'templates\client\sing-box-general.template.json')) 'generic sing-box authority template exists'
Assert-True ([string]$appDefaults.instance_root -notmatch '^[A-Za-z]:') 'generic instance root is portable and relative'
$runtimeFiles = @(
    Get-Item -LiteralPath (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1')
    Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'src') -Recurse -File
    Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'modules') -Recurse -File
    Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'scripts') -Recurse -File
    Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'assets') -Recurse -File
    Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'config') -File | Where-Object Name -NotLike '*.local.json'
    Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'templates') -Recurse -File
)
$personalRuntimePattern = '(?i)F:\\VPS|D:\\Program Files|C:\\Users\\lenovo|20041114\.xyz|179\.(?:253|255)\.'
$personalRuntimeHits = @($runtimeFiles | Select-String -Pattern $personalRuntimePattern)
Assert-True ($personalRuntimeHits.Count -eq 0) 'runtime and versioned templates contain no personal paths, domains, or addresses'

# ValidateProject invokes this script from inside the already imported core
# module.  Forcing that same module to reload would tear down the caller's
# session state (including this script's Assert-True helper).  Direct test runs
# still import the module normally.
if (-not (Get-Command Get-VpsModules -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $ProjectRoot 'src\VpsDeploy.Core.psm1') -Force
}
$coreModule = Get-Module VpsDeploy.Core
$modules = @(Get-VpsModules -ProjectRoot $ProjectRoot)
Assert-True ($null -eq (Get-VpsMarkerValue -Text '' -Name OPTIONAL_EMPTY)) 'optional marker parser accepts empty remote stdout'
Assert-True ($null -eq (Get-VpsMarkerValue -Text $null -Name OPTIONAL_NULL)) 'optional marker parser accepts null remote stdout'
$pwshUtf8 = (Get-Command pwsh -ErrorAction Stop).Source
$utf8RoundTripText = 'ASCII-中文-✓'
$utf8RoundTrip = Invoke-VpsProcess -FilePath $pwshUtf8 -ArgumentList @(
    '-NoLogo', '-NoProfile', '-Command',
    '[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::Out.Write([Console]::In.ReadToEnd())'
) -InputText $utf8RoundTripText -TimeoutSeconds 30
Assert-True ($utf8RoundTrip.ExitCode -eq 0 -and $utf8RoundTrip.StdOut -eq $utf8RoundTripText) 'process stdin uses explicit UTF-8 for remote scripts and Unicode data'
$closedPipeResult = Invoke-VpsProcess -FilePath $pwshUtf8 -ArgumentList @(
    '-NoLogo', '-NoProfile', '-Command',
    '[Console]::In.Close(); exit 23'
) -InputText ('x' * 1MB) -TimeoutSeconds 30
Assert-True ($closedPipeResult.ExitCode -eq 23) 'process returns child exit details when stdin closes before a remote payload is fully written'
Assert-True ($modules.Count -ge 10) 'module count'
Assert-True (($modules.Id | Sort-Object -Unique).Count -eq $modules.Count) 'module IDs unique'
Assert-True ($modules[0].Id -eq 'bootstrap-access') 'bootstrap first'
Assert-True ($modules[-1].Id -eq 'private-archive') 'archive last'
Assert-True ('ssh-cutover' -in $modules.Id) 'safe SSH cutover module exists'
Assert-True ('sing-box-shadowsocks' -in $modules.Id) 'Shadowsocks server module exists'
Assert-True ('landing-client-export' -in $modules.Id) 'Shadowsocks client export module exists'
Assert-True ('certbot-dns' -in $modules.Id) 'Certbot DNS-01 module exists'
Assert-True ('local-https-target' -in $modules.Id) 'local Reality HTTPS target module exists'
Assert-True ('sing-box-anytls' -in $modules.Id) 'AnyTLS trusted TLS server module exists'
Assert-True ('anytls-client-export' -in $modules.Id) 'AnyTLS client export module exists'
Assert-True ('migration-preflight' -in $modules.Id) 'protocol migration preflight module exists'
Assert-True ('migration-arm-rollback' -in $modules.Id) 'protocol migration rollback timer module exists'
Assert-True ('migration-commit' -in $modules.Id) 'protocol migration commit module exists'
Assert-True ('migration-shadowsocks-probe' -in $modules.Id) 'trusted-entry Shadowsocks migration probe module exists'
Assert-True ('deployment-baseline' -in $modules.Id -and 'deployment-baseline-commit' -in $modules.Id) 'new deployments have a unified rollback baseline and commit module'
$deploymentBaselineModule = $modules | Where-Object Id -eq 'deployment-baseline'
$deploymentCommitModule = $modules | Where-Object Id -eq 'deployment-baseline-commit'
$migrationArmModule = $modules | Where-Object Id -eq 'migration-arm-rollback'
$certbotDnsModule = $modules | Where-Object Id -eq 'certbot-dns'
Assert-True ($deploymentBaselineModule.Order -eq 5 -and $deploymentBaselineModule.Requires -contains 'bootstrap-access') 'deployment baseline is armed immediately after bootstrap access'
Assert-True ($deploymentCommitModule.Order -gt ($modules | Where-Object Id -eq 'ssh-cutover').Order -and $deploymentCommitModule.Order -lt ($modules | Where-Object Id -eq 'private-archive').Order) 'deployment baseline is committed after SSH cutover and before final archive'
Assert-True ($migrationArmModule.Order -lt $certbotDnsModule.Order) 'protocol migration rollback is armed before Certbot or protocol mutations'
$transactionSelectionPlan = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'tests\fixtures\dry-run-plan.json') | ConvertFrom-Json -AsHashtable
$transactionSelectionPlan.DeploymentTransaction = [ordered]@{ SchemaVersion = 1; Id = ('a' * 32); Status = 'Planned'; RollbackScope = 'ManagedStateWithRecoveryKey' }
$transactionSelectionContext = & $coreModule {
    param($Root, $Plan)
    Initialize-VpsContext -ProjectRoot $Root -Plan $Plan -DryRun -NonInteractive
} $ProjectRoot $transactionSelectionPlan
$transactionSelection = @($modules | Where-Object { $transactionSelectionContext.Plan.Role -in @($_.Roles) -and (& $_.IsEnabled $transactionSelectionContext) })
Assert-True ('deployment-baseline' -in $transactionSelection.Id -and 'deployment-baseline-commit' -in $transactionSelection.Id) 'first-run module selection includes both baseline arm and later commit before state is armed'
$transactionSelectionContext.State.DeploymentTransaction = [ordered]@{ Status = 'Committed' }
$committedTransactionSelection = @($modules | Where-Object { $transactionSelectionContext.Plan.Role -in @($_.Roles) -and (& $_.IsEnabled $transactionSelectionContext) })
Assert-True ('deployment-baseline' -notin $committedTransactionSelection.Id -and 'deployment-baseline-commit' -notin $committedTransactionSelection.Id) 'a committed deployment cannot silently recreate or delete a new baseline'
$layoutFixture = @(
    [pscustomobject]@{ Order = 42; Id = 'certbot-dns'; Name = 'Certificate step' }
    [pscustomobject]@{ Order = 114; Id = 'protocol-lifecycle-final-firewall'; Name = 'Firewall step' }
)
$layoutLines = @(& $coreModule { param($items) Format-VpsModulePlanLines -Modules $items } $layoutFixture)
$layoutDescriptionColumns = @($layoutLines[0].IndexOf('Certificate step'), $layoutLines[1].IndexOf('Firewall step'))
Assert-True ($layoutLines.Count -eq 2 -and $layoutDescriptionColumns[0] -eq $layoutDescriptionColumns[1]) 'module plan dynamically aligns descriptions after the longest module id'
$legacyCompatibility=&$coreModule{param($plan)$copy=Copy-MxhHashtable $plan;$copy.Remove('NetworkTuning');ConvertTo-MxhCompatiblePlan $copy} (Get-Content -Raw (Join-Path $ProjectRoot 'tests\fixtures\dry-run-plan.json')|ConvertFrom-Json -AsHashtable)
Assert-True ($legacyCompatibility.Contains('NetworkTuning') -and [string]$legacyCompatibility.NetworkTuning.Mode -eq 'LegacyBaseline') 'legacy managed plans gain a non-invasive network tuning compatibility section'
Assert-True ($null -eq $legacyCompatibility.NetworkTuning.BandwidthMbps) 'legacy plan compatibility never invents nominal bandwidth'
$shadowsocksSelfTest = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\shadowsocks-self-test.sh')
$coreSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'src\VpsDeploy.Core.psm1')
Assert-True ($coreSource -match '显式模块执行完成' -and $coreSource -match '统一部署事务仍未完成' -and $coreSource -match '未据此宣称整套部署流程完成') 'OnlyModule completion never claims that an incomplete deployment is complete'
$deploymentBaseline = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\deployment-baseline-arm.sh')
Assert-True ($deploymentBaseline -match 'list-unit-files "\$service" --no-legend 2>/dev/null \|\| true' -and $deploymentBaseline -match 'VPSDEPLOY_BASELINE_FAILURE_PHASE') 'deployment baseline treats absent systemd units as inventory state and reports a sanitized failure phase'
Assert-True ($coreSource -notmatch 'Write-Progress -Id 4201' -and $coreSource -match 'Write-Host \("`r" \+ \$progressText \+ \$padding\) -NoNewline' -and $coreSource -match '已运行 \$elapsed，任务仍在执行') 'long remote commands use a compact single-line elapsed timer without a progress bar'
Assert-True ($coreSource -match 'Invoke-WebRequest[^\r\n]+-ProgressAction SilentlyContinue' -and $coreSource -match 'Invoke-RestMethod[^\r\n]+-ProgressAction SilentlyContinue') 'real HTTPS acceptance suppresses the built-in PowerShell transfer progress bar'
Assert-True ($coreSource -match 'function Invoke-VpsScpDownload[\s\S]*?\[string\]\$ProgressActivity[\s\S]*?-ProgressActivity \$ProgressActivity') 'SCP downloads can reuse the compact elapsed timer'
$privateArchiveSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\120-PrivateArchive.ps1')
Assert-True ($privateArchiveSource -match '下载配置并生成最终私有归档可能需要数分钟' -and $privateArchiveSource -match '下载最终私有归档配置' -and $privateArchiveSource -match '服务器配置下载完成（用时') 'final private archive downloads show timing guidance and per-download elapsed status'
Assert-True ($privateArchiveSource -match 'Secondary IPv6 User Key: \$secondaryUserKey' -and $privateArchiveSource -match "else \{ '<disabled>' \}" -and $privateArchiveSource -notmatch 'Secondary IPv6 User Key: \$\(\$ss\.SecondaryUserKey\)') 'IPv4-only Shadowsocks archive does not access a missing IPv6 user key'
Assert-True ($shadowsocksSelfTest -match 'VPSDEPLOY_UDP_B64') 'Shadowsocks self-test reports functional UDP result'
Assert-True ($shadowsocksSelfTest -match '"type": "direct"') 'Shadowsocks self-test creates a UDP tunnel inbound'
Assert-True ($shadowsocksSelfTest -match 'override_address') 'Shadowsocks UDP self-test uses an explicit DNS destination'
Assert-True ($shadowsocksSelfTest -match 'VPSDEPLOY_SELFTEST_FAILURE_PHASE' -and $shadowsocksSelfTest -match 'report_failure "\$\?"' -and $shadowsocksSelfTest -match "phase='https'" -and $shadowsocksSelfTest -match "phase='udp'") 'Shadowsocks self-test reports only a sanitized failing phase through an explicit ERR handler'
$shadowsocksModule = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\55-SingBoxShadowsocks.ps1')
Assert-True ($shadowsocksModule -match 'Invoke-MxhShadowsocksRealValidation' -and $coreSource -match 'SensitiveOutput -AllowFailure') 'Shadowsocks install and upgrade reuse the sanitized full protocol validation helper'
$anyTlsModule = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\52-SingBoxAnyTls.ps1')
Assert-True ($anyTlsModule -match '\$version = \[string\]\$Context\.Versions\.sing_box\.version' -and $anyTlsModule -match '\$Context\.Plan\.AnyTls\.SingBoxVersion = \$version') 'AnyTLS install keeps the requested version paired with the pinned asset catalog'
Assert-True ($shadowsocksModule -match '\$version = \[string\]\$Context\.Versions\.sing_box\.version' -and $shadowsocksModule -match '\$Context\.Plan\.Shadowsocks\.SingBoxVersion = \$version') 'Shadowsocks install keeps the requested version paired with the pinned asset catalog'
$migrationCommitModule = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\115-ProtocolMigrationCommit.ps1')
Assert-True ($migrationCommitModule -match "targetRole -eq 'ShadowsocksLanding'" -and $migrationCommitModule -match '现有 Reality/AnyTLS 入口保持原状态') 'Shadowsocks lifecycle commit message preserves concurrent entry protocol state'
$externalProbe = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\shadowsocks-external-probe.sh')
Assert-True ($externalProbe -match 'sha256sum --check --status') 'external Shadowsocks probe verifies pinned core checksum'
Assert-True ($externalProbe -match 'MetaCubeX/mihomo' -and $externalProbe -match 'SagerNet/sing-box' -and $externalProbe -match 'VPSDEPLOY_EXTERNAL_ACCEPTANCE_B64') 'external Shadowsocks probe runs pinned Mihomo and sing-box cores'
Assert-True ($externalProbe -match 'SOCKS5 UDP associate failed' -and $externalProbe -match 'generate_204' -and $externalProbe -match 'unexpected egress address family') 'external Shadowsocks probe requires client handshake, HTTPS, expected egress family, and UDP'
$externalProbeModule = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\95-MigrationShadowsocksProbe.ps1')
Assert-True ($externalProbeModule -match 'Invoke-MxhShadowsocksExternalValidation -Context \$Context') 'migration and maintenance reuse one Shadowsocks trusted-entry validation implementation'
Assert-True ($coreSource -match 'function Invoke-MxhShadowsocksExternalValidation' -and $coreSource -match 'foreach \(\$user in \$users\)' -and $coreSource -match 'mihomoAsset' -and $coreSource -match 'singBoxAsset') 'Shadowsocks external validation checks every configured address-family user with both cores'
Assert-True ($coreSource -match 'SING_BOX_VERSION = \[string\]\$Context\.Versions\.sing_box\.version') 'Shadowsocks external validation pairs the test core version with the pinned asset catalog'
Assert-True ($migrationCommitModule -match 'ShadowsocksSelfTest\.Results' -and $migrationCommitModule -match 'MigrationShadowsocksExternalProbe\.Results') 'Shadowsocks commit checks the current structured local and external acceptance results'
$singBoxInstaller = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\sing-box-install.sh')
Assert-True ($singBoxInstaller -match 'RestrictAddressFamilies=[^\r\n]*AF_NETLINK') 'sing-box systemd sandbox permits route-update netlink'
$anyTlsInstaller = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\sing-box-anytls-install.sh')
Assert-True ($anyTlsInstaller -match 'RestrictAddressFamilies=[^\r\n]*AF_NETLINK') 'AnyTLS sandbox permits route-update netlink'
Assert-True ($anyTlsInstaller -match 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE') 'AnyTLS receives only the privileged-port bind capability'
Assert-True ($anyTlsInstaller -notmatch '(?m)^User=root$') 'AnyTLS never runs as root'
$certbotSetup = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\certbot-dns-setup.sh')
Assert-True ($certbotSetup -match 'dns-cloudflare') 'Certbot uses Cloudflare DNS-01 plugin'
Assert-True ($certbotSetup -match 'mxh-certbot-renew\.timer') 'Certbot renewal timer is installed'
Assert-True ($certbotSetup -match 'disable --now certbot\.timer') 'distribution Certbot timer is disabled to avoid duplicate renewal owners'
Assert-True (([regex]::Matches($certbotSetup, '--no-random-sleep-on-renew')).Count -eq 2) 'Certbot deploy validation and timer rely on the systemd schedule instead of hidden random sleeps'
Assert-True ($certbotSetup -notmatch 'echo\s+.*CLOUDFLARE_TOKEN') 'Certbot setup never prints the Cloudflare token'
$certbotModuleSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\42-CertbotDns.ps1')
Assert-True ($certbotSetup -match '%\{local_ip\}' -and $certbotSetup -match 'VPSDEPLOY_CERTBOT_SAFE_ERROR_B64') 'Certbot preflight reports the actual Cloudflare API source address through a sanitized marker'
Assert-True ($certbotSetup -match 'trap report_failure ERR' -and $certbotSetup -match "phase='certificate-renewal-dry-run'") 'Certbot setup reports a sanitized stage for failures after Cloudflare preflight'
Assert-True ($certbotModuleSource -match 'SensitiveOutput -AllowFailure' -and $certbotModuleSource -match 'CERTBOT_SAFE_ERROR') 'Certbot module exposes only the sanitized remote stage error'
$anyTlsApply = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\anytls-apply-config.sh')
Assert-True ($anyTlsApply -match "rollback_needed='yes'") 'AnyTLS cutover arms automatic rollback'
Assert-True ($anyTlsApply -match 'systemctl start xray\.service') 'AnyTLS cutover restores an originally active Xray service on failure'
$migrationArm = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\protocol-migration-arm-rollback.sh')
Assert-True ($migrationArm -match 'mxh-protocol-migration-rollback\.timer') 'protocol migration installs a VPS-side rollback timer'
Assert-True ($migrationArm -match 'cp -a /etc/nftables\.conf') 'protocol migration backs up the source firewall'
$deploymentBaselineArm = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\deployment-baseline-arm.sh')
$deploymentBaselineRollback = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\deployment-baseline-rollback.sh')
$deploymentSnapshotDelete = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\deployment-snapshot-delete.sh')
$deploymentCommitSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\119-DeploymentBaselineCommit.ps1')
Assert-True ($deploymentBaselineArm -match 'backup-directories\.before' -and $deploymentBaselineArm -match 'packages\.before') 'deployment baseline records pre-existing server backups and packages'
Assert-True ($deploymentBaselineArm -match 'etc/nginx/sites-enabled/default' -and $deploymentBaselineArm -match 'var/log/xray') 'deployment baseline covers every project-managed nginx and Xray path'
Assert-True ($deploymentBaselineRollback -match 'rollback\.complete' -and $deploymentBaselineRollback -match 'packages\.preserved') 'deployment rollback records completion and reports intentionally preserved packages'
Assert-True ($deploymentSnapshotDelete -match 'deployment-rolled-back' -and $deploymentSnapshotDelete -match 'rollback\.complete' -and $deploymentSnapshotDelete -match 'backup-directories\.before') 'rollback snapshot cleanup requires a completed rollback and preserves pre-existing backup directories'
Assert-True ($deploymentSnapshotDelete -match '\^\[0-9\]\{8\}-\[0-9\]\{6\}\$' -and $deploymentSnapshotDelete -match 'for component in ssh certbot-dns' -and $deploymentSnapshotDelete -notmatch 'rm -rf -- "\$candidate_path"') 'rollback snapshot cleanup deletes only allowlisted components in validated timestamp children, never a whole unrelated backup directory'
Assert-True ($deploymentCommitSource -match "requiredModule = if .*AuditOnly.*audit.*ssh-cutover" -and $deploymentCommitSource -match "KIND = 'deployment-committed'") 'snapshot commit cannot bypass final audit or SSH cutover even through OnlyModule'
$migrationCommit = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\protocol-migration-commit.sh')
Assert-True ($migrationCommit -match 'FINAL_REALITY_ENABLED' -and $migrationCommit -match 'FINAL_ANYTLS_ENABLED') 'lifecycle commit applies explicit final service states'
Assert-True ($migrationCommit -match 'systemctl stop mxh-protocol-migration-rollback\.timer') 'migration commit cancels rollback only after target validation'
$lifecycleUninstall = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\protocol-lifecycle-uninstall.sh')
Assert-True ($lifecycleUninstall -match 'systemctl is-enabled' -and $lifecycleUninstall -match 'VPSDEPLOY_PROTOCOL_UNINSTALLED') 'uninstall refuses active protocols and returns a success marker'
$backupPrune = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\protocol-backup-prune.sh')
Assert-True ($backupPrune -match 'mxh-protocol-migration-rollback\.timer' -and $backupPrune -match 'protocol-lifecycle') 'backup cleanup protects active rollback and limits its remote scope'
$komariMaintenance = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\maintenance-komari.sh')
$agentUpgradeSection = [regex]::Match($komariMaintenance, '(?s)\n  AgentUpgrade\).*?\n    ;;').Value
Assert-True (-not [string]::IsNullOrWhiteSpace($agentUpgradeSection) -and $agentUpgradeSection -notmatch '--version') 'Agent upgrade never invokes the unsupported version interface'
Assert-True ([regex]::Matches($agentUpgradeSection, 'sha256sum --check --status').Count -eq 2 -and $komariMaintenance -match '"\$expected" "/proc/\$\{pid\}/exe"') 'Agent upgrade verifies downloaded, installed and running binary checksums'
Assert-True ($agentUpgradeSection -match 'verify_running_binary komari-agent.service' -and $komariMaintenance -match '"/proc/\$\{pid\}/exe" -ef "\$binary"') 'Agent upgrade checks the active service process uses the replaced binary'
Assert-True ($komariMaintenance -match 'for _ in \{1\.\.20\}' -and $agentUpgradeSection -match 'if \[\[ "\$was_active" == true \]\]') 'Agent process verification is bounded and never starts an inactive service'
Assert-True ($komariMaintenance -match 'tunnel_was_enabled=false; tunnel_was_active=false' -and $komariMaintenance -match '\[\[ "\$tunnel_was_active" == false \]\] \|\| systemctl start cloudflared\.service') 'Controller restore rollback returns cloudflared to its pre-restore enabled and active state'
Assert-True ($komariMaintenance -match 'for _ in \{1\.\.30\}; do grep -Fq "127\.0\.0\.1:\$\{controller_port\}"' -and $komariMaintenance -match "curl --silent --output /dev/null --write-out '%\{http_code\}'") 'Controller restore waits for the actual archived listener and validates loopback HTTP before committing'
$localHttpsSetup = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\local-https-target.sh')
Assert-True ($localHttpsSetup -match 'mask nginx\.service') 'nginx is masked while the package default site could start'
Assert-True ($localHttpsSetup -match 'unmask nginx\.service') 'nginx is unmasked only after package installation checks'
Assert-True ($localHttpsSetup -match 'listen 127\.0\.0\.1:\$\{VPS_PARAM_PORT\} ssl http2;' -and $localHttpsSetup -notmatch '(?m)^\s*http2 on;') 'local HTTPS target uses the nginx 1.22-compatible HTTP/2 syntax required by Debian 12'
$baseSystem = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\base-system.sh')
Assert-True ($baseSystem -match 'DPkg::Lock::Timeout=60' -and $baseSystem -match 'Waiting for apt/dpkg lock') 'remote apt operations wait and retry when apt/dpkg is locked'
$finalValidationSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\100-FinalValidation.ps1')
Assert-True ($coreSource -match 'Invoke-MxhSocks5UdpDnsTest' -and $coreSource -match '\[byte\[\]\]\(5, 3, 0, 1' -and $coreSource -match 'UDP DNS 事务校验失败') 'isolated Mihomo validation performs a real SOCKS5 UDP ASSOCIATE DNS round trip'
Assert-True ($finalValidationSource -match 'Invoke-MxhRealClientValidation' -and $coreSource -match "UdpDnsEndpoint =") 'Reality and AnyTLS final state records per-core HTTPS and UDP validation'
Assert-True ($coreSource -match 'SKIP-IPV6-VALIDATION' -and $coreSource -match 'Get-MxhIpv6ValidationSkipRecord' -and $coreSource -match 'Ipv6Skips') 'unavailable local IPv6 validation can only be skipped through an explicit reusable private record'
Assert-True ($coreSource -match '选择外部受管 VPS 执行 IPv6 验收（推荐）' -and $coreSource -match '明确跳过本次 IPv6 验收（记录为未验证）' -and $coreSource -match "Status = 'SkippedByUser'") 'interactive IPv6 path failure offers an external probe or a recorded non-passing skip'
Assert-True ($coreSource -match 'if \(\$Context\.NonInteractive\) \{ return \$null \}' -and $coreSource -match 'Resolve-MxhExternalValidationProbeContext') 'noninteractive validation cannot invent an IPv6 skip when no matching approval is pre-recorded'
Assert-True ($finalValidationSource -match '\$getEnabledPort' -and $finalValidationSource -match 'ANYTLS_PORT = & \$getEnabledPort ''AnyTlsPrimary''' -and $finalValidationSource -match 'LANDING_PORT = & \$getEnabledPort ''LandingShadowsocks''') 'final validation does not read optional protocol ports from disabled roles in legacy plans'
Assert-True ($coreSource -match 'vendor\\test-cores\\windows-amd64' -and $coreSource -match "Status = 'SkippedByUser'" -and $coreSource -match '非交互模式不能跳过') 'bundled cores are mandatory unless an interactive user explicitly records a skip'
Assert-True ($coreSource -match '\$stateKey=if\(\$Protocol -eq ''Reality''\)\{''ClientExports''\}' -and $coreSource -match '自动重新生成客户端导出后仍不可用') 'real validation regenerates legacy client export state before requiring per-family targets'
Assert-True ($coreSource -notmatch 'Clash Verge\\verge-mihomo' -and $coreSource -notmatch 'CurrentVersion\\Uninstall') 'core resolution does not inspect Clash Verge files or uninstall registry entries'
Assert-True ($coreSource -match 'function Set-VpsOpenSshPrivateKeyAccess' -and $coreSource -match "ssh-keygen\.exe" -and $coreSource -notmatch 'MXH_VPS_STRICT_LOCAL_ACL') 'local permission handling first delegates acceptance to OpenSSH in a dedicated private-key helper'
Assert-True ($coreSource -match "icacls\.exe" -and $coreSource -match "'/inheritance:r'" -and $coreSource -match "'/grant:r'" -and $coreSource -notmatch "'/T'") 'OpenSSH key ACL fallback targets one literal private-key file and never recurses into an archive'
Assert-True ($coreSource -notmatch 'Get-VpsOperationalSshKeyPath' -and $coreSource -notmatch '\.ssh\\mxh-vps-deploy') 'managed SSH keys run directly from the selected archive without a second operational copy'
$operationsSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'src\VpsDeploy.Operations.ps1')
Assert-True ($operationsSource -match 'Invoke-MxhRealClientValidation.+Reality' -and $operationsSource -match 'Invoke-MxhShadowsocksRealValidation' -and $operationsSource -match 'Invoke-MxhShadowsocksExternalValidation') 'controlled upgrades reuse full real-protocol validation'
Assert-True (([regex]::Matches($operationsSource, 'Invoke-MxhRealClientValidation -Context \$(?:candidate|Context) -Protocol (?:Reality|AnyTLS)')).Count -ge 4 -and ([regex]::Matches($operationsSource, 'Invoke-MxhShadowsocksRealValidation -Context \$(?:candidate|Context)')).Count -ge 2 -and ([regex]::Matches($operationsSource, 'Invoke-MxhShadowsocksExternalValidation -Context \$(?:candidate|Context)')).Count -ge 2) 'credential rotation and controlled upgrades require both local and trusted-entry Shadowsocks acceptance'
$migrationSourceText = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'src\VpsDeploy.Migration.ps1')
Assert-True ($migrationSourceText -match 'if \(\$module\.Id -in @\(\$Context\.Plan\.Migration\.ModuleIds\)\)') 'migration rollback resets every selected migration module before a retry'
Assert-True ($coreSource -match '默认值：\$Default（直接按 Enter/回车采用）' -and $coreSource -match '默认值：\{0\}（直接按 Enter/回车采用）' -and $coreSource -match '默认项：\{0\}（直接按 Enter/回车采用）' -and $coreSource -match "Read-Host '请输入'" -and $coreSource -match "Read-Host '请选择'") 'text, yes/no, and menu inputs render defaults on helper lines and keep the input line short'
Assert-True ($coreSource -notmatch 'b/back 均按普通内容处理') 'new-user navigation banner does not mention unsupported-looking b/back aliases'
Assert-True ($coreSource -match 'Wait-VpsReturnToMainMenu' -and $coreSource -match '当前操作失败；计划和状态已经保留，可从主菜单选择继续未完成部署') 'interactive operational failures pause and return to the main menu instead of exiting the process'
Assert-True ($coreSource -match 'DeploymentTransaction = \[ordered\]@' -and $coreSource -match "RollbackScope = 'ManagedStateWithRecoveryKey'") 'new plans carry a unique unified deployment transaction'
Assert-True ($coreSource -match '放弃未完成计划并回滚到部署前' -and $coreSource -match 'ABANDON-AND-ROLLBACK') 'resume menu exposes an explicit strongly confirmed abandon and rollback path'
Assert-True ($coreSource -match 'RolledBackAwaitingSnapshotCleanup' -and $coreSource -match 'SnapshotDeletedAwaitingLocalCleanup') 'abandon transaction can safely resume both remote snapshot deletion and local-only cleanup stages'
Assert-True ($coreSource -match 'BaselineCapturedBeforeMutations' -and $coreSource -match '该旧版协议变更没有') 'legacy protocol migrations without a verifiable pre-mutation baseline cannot claim a clean rollback'
Assert-True ($coreSource -match 'Xray 版本来源：XTLS/Xray-core 官方最新稳定版' -and $coreSource -match '本次实际\$\(\$Action\)版本：Xray \$ResolvedVersion' -and $coreSource -match '官方 latest 与项目固定验证版当前同为 Xray \$ResolvedVersion' -and $coreSource -match '官方 latest 为 Xray \$ResolvedVersion，项目固定验证版为 Xray \$FixedVersion') 'Xray selection dynamically compares latest and fixed versions while keeping the selected provenance clear'
Assert-True ($coreSource -notmatch '这里固定并校验的是 Xray 安装脚本来源' -and $operationsSource -notmatch '安装脚本固定校验不改变核心版本通道') 'Xray selection prompt does not mix installer pinning into core version wording'
$targetAuditModule = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\40-TargetAudit.ps1')
Assert-True ($targetAuditModule -match 'ACCEPT-TARGET-RISK' -and $targetAuditModule -match 'manual_override') 'failed target audits support an explicit recorded manual override'
Assert-True ($targetAuditModule -match 'NonInteractive.*禁止人工覆写') 'noninteractive target audit cannot silently bypass automatic requirements'
$targetAuditSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\target-audit.sh')
Assert-True ($targetAuditSource -match 'timeout 20 openssl s_client -4') 'target audit bounds the TLS probe and keeps it on the audited IPv4 address family'
Assert-True ($targetAuditSource -match '%\{time_namelookup\}.*%\{time_connect\}.*%\{time_appconnect\}') 'target audit captures DNS, TCP, and full TLS timing separately'
Assert-True ($targetAuditSource -match 'tcp_connected - name_lookup' -and $targetAuditSource -match 'tcp_median <= int\(max_median\)') 'target automatic latency gate uses TCP connect time excluding DNS'
Assert-True ($targetAuditModule -match 'TCP 建连（不含 DNS，自动门禁）' -and $targetAuditModule -match 'TLS 完成（含 DNS/TCP，仅供参考）') 'target audit UI identifies the gated and informational timing metrics'
$targetAuditPythonMatch = [regex]::Match($targetAuditSource, "(?s)<<'PY'\n(.+?)\nPY")
Assert-True $targetAuditPythonMatch.Success 'target audit Python payload is extractable'
$importAudit = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\existing-vps-import-audit.sh')
Assert-True ($importAudit -match 'IMPORT_PRIVATE' -and $importAudit -match 'RealityEntry') 'existing VPS import discovers supported protocol state and private configuration'
$importPythonMatch = [regex]::Match($importAudit, "(?s)python3 <<'PY'\n(.+?)\nPY")
Assert-True $importPythonMatch.Success 'existing import Python audit payload is extractable'
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $importPythonPath = Join-Path $ProjectRoot '.test-output\existing-import-audit.py'
    [IO.Directory]::CreateDirectory((Split-Path -Parent $importPythonPath)) | Out-Null
    [IO.File]::WriteAllText($importPythonPath, $importPythonMatch.Groups[1].Value, [Text.UTF8Encoding]::new($false))
    $pythonSyntax = Invoke-VpsProcess -FilePath $pythonCommand.Source -ArgumentList @(
        '-c', 'import pathlib,sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[1], "exec")', $importPythonPath
    ) -TimeoutSeconds 30
    Assert-True ($pythonSyntax.ExitCode -eq 0) 'existing import Python audit parses'
    [IO.File]::Delete($importPythonPath)

    $targetAuditFixtureRoot = Join-Path $ProjectRoot '.test-output\target-audit-metric'
    if (Test-Path -LiteralPath $targetAuditFixtureRoot) { [IO.Directory]::Delete($targetAuditFixtureRoot, $true) }
    [IO.Directory]::CreateDirectory($targetAuditFixtureRoot) | Out-Null
    $targetAuditPythonPath = Join-Path $targetAuditFixtureRoot 'target-audit.py'
    [IO.File]::WriteAllText($targetAuditPythonPath, $targetAuditPythonMatch.Groups[1].Value, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $targetAuditFixtureRoot 'timings.tsv'), @'
0.0030	0.0090	0.0730
0.0040	0.0110	0.0750
0.0035	0.0105	0.0710
0.0040	0.0120	0.0740
0.0030	0.0095	0.0680
'@.TrimStart(), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $targetAuditFixtureRoot 'http.txt'), "200`t2`t192.0.2.80`thttps://example.edu/`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $targetAuditFixtureRoot 'cname.txt'), '', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $targetAuditFixtureRoot 'headers.txt'), '', [Text.UTF8Encoding]::new($false))
    $targetMetricResult = Invoke-VpsProcess -FilePath $pythonCommand.Source -ArgumentList @(
        $targetAuditPythonPath, 'example.edu', '5', '0', '15', 'true', 'true', 'true', 'true', $targetAuditFixtureRoot
    ) -TimeoutSeconds 30
    Assert-True ($targetMetricResult.ExitCode -eq 0) 'target audit synthetic metric fixture executes'
    $targetMetricMatch = [regex]::Match($targetMetricResult.StdOut, 'VPSDEPLOY_TARGET_JSON_B64=([A-Za-z0-9+/=]+)')
    Assert-True $targetMetricMatch.Success 'target audit synthetic metric result is returned'
    $targetMetric = ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($targetMetricMatch.Groups[1].Value)) | ConvertFrom-Json -AsHashtable)
    Assert-True ([Math]::Abs([double]$targetMetric.tcp_connect_median_ms - 7.0) -lt 0.01) 'target audit computes TCP connect median after subtracting DNS'
    Assert-True ([Math]::Abs([double]$targetMetric.tls_appconnect_median_ms - 73.0) -lt 0.01) 'target audit retains full TLS completion time as a separate metric'
    Assert-True ([bool]$targetMetric.automatic_pass) 'slow TLS completion alone does not reject a nearby low-latency target'
    [IO.Directory]::Delete($targetAuditFixtureRoot, $true)
}
$importSsh = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\existing-vps-import-ssh-keyonly.sh')
Assert-True ($importSsh -match 'PasswordAuthentication no' -and $importSsh -match 'PubkeyAuthentication yes') 'optional existing-VPS key-only hardening remains available'
Assert-True ((Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'src\VpsDeploy.Import.ps1')) -match 'EnforceKeyOnlySsh') 'existing VPS import explicitly records whether SSH authentication is preserved or hardened'

Write-Host '== Supported operating systems and SSH port strategy ==' -ForegroundColor Cyan
Assert-True (Test-VpsSupportedOsRelease -Id debian -VersionId 12) 'Debian 12 is an explicitly supported release'
Assert-True (Test-VpsSupportedOsRelease -Id Debian -VersionId '13.1') 'Debian 13 point releases remain supported'
Assert-True (-not (Test-VpsSupportedOsRelease -Id ubuntu -VersionId 22.04)) 'Ubuntu is outside the formal VPS support contract'
Assert-True (-not (Test-VpsSupportedOsRelease -Id debian -VersionId 11)) 'Debian 11 is outside the verified contract'
Assert-True (-not (Test-VpsSupportedOsRelease -Id ubuntu -VersionId 20.04)) 'Ubuntu 20.04 is outside the verified contract'
Assert-True ((Get-VpsSupportedAssetArchitecture -Architecture x86_64) -eq 'amd64') 'x86_64 maps to the only supported VPS asset architecture'
$armRejected = $false
try { Get-VpsSupportedAssetArchitecture -Architecture arm64 | Out-Null } catch { $armRejected = $true }
Assert-True $armRejected 'arm64 is rejected by the formal VPS architecture gate'

$port22Selection = New-VpsSshPortSelection -BootstrapPort 22
Assert-True (-not [bool]$port22Selection.ReuseBootstrap) 'port 22 follows the replacement path'
Assert-True ([int]$port22Selection.Primary -ge 20000 -and [int]$port22Selection.Primary -le 59999) 'port 22 gets a high primary port'
Assert-True ([int]$port22Selection.Rescue -ge 20000 -and [int]$port22Selection.Rescue -le 59999) 'port 22 gets a high rescue port'
Assert-True ([int]$port22Selection.Primary -ne [int]$port22Selection.Rescue) 'generated primary and rescue ports differ'

$providerHighSelection = New-VpsSshPortSelection -BootstrapPort 45222
Assert-True ([bool]$providerHighSelection.ReuseBootstrap) 'provider high SSH port is reusable'
Assert-True ([int]$providerHighSelection.Primary -eq 45222) 'provider high SSH port becomes the primary'
Assert-True ([int]$providerHighSelection.Rescue -ne 45222) 'provider high SSH path adds only a distinct rescue port'
Assert-True (-not (Test-VpsReusableBootstrapSshPort -Port 8443)) 'loopback HTTPS target port is not reused for SSH'
$retainedPortPlan = [ordered]@{
    Server = [ordered]@{ BootstrapSshPort = 45222 }
    Ports = [ordered]@{ SshPrimary = 45222; SshRescue = [int]$providerHighSelection.Rescue }
}
Assert-True (Test-VpsBootstrapSshPortRetained -Plan $retainedPortPlan) 'plan records provider high port as a final SSH entry'
$sshTransition = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\ssh-transition.sh')
Assert-True ($sshTransition -match 'sort -n -u' -and $sshTransition -match 'ssh_ports') 'remote SSH transition de-duplicates a reused bootstrap port'
Assert-True ($sshTransition -match 'Primary and rescue SSH ports must be different') 'remote SSH transition rejects a duplicate rescue port'
$sshCutoverModule = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\110-SshCutover.ps1')
Assert-True ($sshCutoverModule -match 'BootstrapSshReused' -and $sshCutoverModule -match '未创建第三个 SSH 端口') 'final SSH module preserves a reused provider port without creating a third entry'
$ciText = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot '.github\workflows\ci.yml')
Assert-True ($ciText -match "debian: \['12', '13'\]" -and $ciText -match 'VPS remote contract') 'CI checks Debian 12 and 13 remote-script contracts while Windows remains the control-plane job'

Write-Host '== Bootstrap authentication arguments ==' -ForegroundColor Cyan
$sshArgumentContext = [pscustomobject]@{
    Plan = [ordered]@{
        Server = [ordered]@{ IPv4 = '192.0.2.10' }
        Paths = [ordered]@{ KeyDirectory = 'C:\fixture-key' }
    }
}
$providerKeyArgs = @(Get-VpsSshArguments -Context $sshArgumentContext -Port 22 -User root `
        -Interactive -IdentityFile 'C:\provider-existing-key')
Assert-True ('C:\provider-existing-key' -in $providerKeyArgs) 'existing provider key is passed to OpenSSH'
Assert-True ('IdentitiesOnly=yes' -in $providerKeyArgs) 'provider key uses IdentitiesOnly'
Assert-True ('PreferredAuthentications=publickey' -in $providerKeyArgs) 'provider key cannot silently fall back to password'
Assert-True ('BatchMode=yes' -notin $providerKeyArgs) 'interactive provider key permits passphrase prompt'
$passwordArgs = @(Get-VpsSshArguments -Context $sshArgumentContext -Port 22 -User root -Interactive)
Assert-True ('-i' -notin $passwordArgs) 'password bootstrap does not force an identity file'
Assert-True ('PubkeyAuthentication=no' -in $passwordArgs) 'password bootstrap does not accidentally reuse an agent key'
$managedKeyArgs = @(Get-VpsSshArguments -Context $sshArgumentContext -Port 22 -User root)
Assert-True ('IdentitiesOnly=yes' -in $managedKeyArgs -and 'PreferredAuthentications=publickey' -in $managedKeyArgs) 'managed-key verification explicitly uses only public-key authentication'
Assert-True ('PasswordAuthentication=no' -in $managedKeyArgs -and 'KbdInteractiveAuthentication=no' -in $managedKeyArgs) 'managed-key verification cannot fall back to password authentication'
Assert-True ($coreSource -match '密码及粘贴内容不会显示字符或星号' -and $coreSource -match '鼠标右键或 Ctrl\+Shift\+V 粘贴') 'password bootstrap explains hidden Windows Terminal paste behavior'
Assert-True ($coreSource -match '重新打开 SSH 密码提示' -and $coreSource -match '这不是初始密码错误') 'password bootstrap offers retry while distinguishing later public-key verification failures'
$importedAdminContext = [pscustomobject]@{ Secrets = [ordered]@{ AdminPassword = '<not-managed>' } }
$managedAdminContext = [pscustomobject]@{ Secrets = [ordered]@{ AdminPassword = 'fixture-managed-password' } }
Assert-True (-not (& $coreModule { param($Context) Test-VpsManagedAdminPassword -Context $Context } $importedAdminContext)) 'imported unknown admin password is never treated as a real sudo password'
Assert-True (& $coreModule { param($Context) Test-VpsManagedAdminPassword -Context $Context } $managedAdminContext) 'project-managed admin password keeps password-backed sudo validation'
$finalValidationSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'modules\100-FinalValidation.ps1')
Assert-True ($finalValidationSource -match 'Test-VpsImportedAdminSudoPolicy' -and $finalValidationSource -match '未验证未知密码本身') 'imported admin validation checks key login and sudo policy without claiming to know the password'
$bootstrapSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'assets\remote\bootstrap-access.sh')
Assert-True ($bootstrapSource -match '00-00-mxh-bootstrap-access\.conf' -and $bootstrapSource -match 'VPSDEPLOY_BOOTSTRAP_SSH_CONFIG=updated') 'password bootstrap can enable public-key authentication on provider images that disable it'
Assert-True ($bootstrapSource -match 'AuthorizedKeysFile \.ssh/authorized_keys' -and $bootstrapSource -match 'AuthenticationMethods any') 'bootstrap drop-in restores a standard root public-key authentication path'
Assert-True ($bootstrapSource -match 'restore_managed' -and $bootstrapSource -match 'sshd -t' -and $bootstrapSource -match 'systemctl reload ssh\.service') 'bootstrap SSH compatibility change validates and rolls back before continuing'
$bootstrapCommand = & $coreModule { New-VpsBootstrapAccessCommand -PublicKey 'ssh-ed25519 AAAA fixture' }
Assert-True ($bootstrapCommand -match "VPS_PARAM_PUBLIC_KEY='ssh-ed25519 AAAA fixture'" -and $bootstrapCommand -match 'base64 -d') 'bootstrap command generator safely injects the quoted public key and encoded script'

$keyReuseRoot = Join-Path $ProjectRoot '.test-output\ssh-key-reuse'
if (Test-Path -LiteralPath $keyReuseRoot) { [IO.Directory]::Delete($keyReuseRoot, $true) }
[IO.Directory]::CreateDirectory($keyReuseRoot) | Out-Null
$sourceKey = Join-Path $keyReuseRoot 'provider-original-key'
$keygenResult = Invoke-VpsProcess -FilePath (Get-Command ssh-keygen.exe -ErrorAction Stop).Source `
    -ArgumentList @('-t','ed25519','-N','','-C','provider-fixture','-f',$sourceKey) -TimeoutSeconds 60
Assert-True ($keygenResult.ExitCode -eq 0) 'fixture Ed25519 provider key generated'
$sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceKey).Hash
$sourceAclBefore = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { (Get-Acl -LiteralPath $sourceKey).Sddl } else { $null }
$managedDirectory = Join-Path $keyReuseRoot 'MXH-VPS-Deploy\ssh'
$reuseContext = [pscustomobject]@{ Plan = [ordered]@{
        NodeName='Example-Reused-Key';Server=[ordered]@{BootstrapKeyPath=$sourceKey}
        SshKey=[ordered]@{Mode='ReuseExisting';SourcePrivateKeyPath=$sourceKey;ManagedFileName='id_ed25519';PreserveSource=$true}
        Paths=[ordered]@{KeyDirectory=$managedDirectory}
    } }
& $coreModule { param($Context) Initialize-VpsSshKey -Context $Context } $reuseContext 6>$null
$managedKey = Join-Path $managedDirectory 'id_ed25519'
Assert-True (Test-Path -LiteralPath $managedKey -PathType Leaf) 'existing provider key is copied under a normalized managed filename'
Assert-True ((Get-FileHash -Algorithm SHA256 -LiteralPath $managedKey).Hash -eq $sourceHash) 'managed key copy preserves the provider private key instead of rotating it'
Assert-True ((Get-FileHash -Algorithm SHA256 -LiteralPath $sourceKey).Hash -eq $sourceHash) 'provider key source is never renamed or modified'
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $managedKeyProbe = Invoke-VpsProcess -FilePath (Get-Command ssh-keygen.exe -ErrorAction Stop).Source `
        -ArgumentList @('-y','-f',$managedKey) -TimeoutSeconds 60
    Assert-True ($managedKeyProbe.ExitCode -eq 0) 'managed private key satisfies the authoritative Windows OpenSSH access check'
    Assert-True ((Get-Acl -LiteralPath $sourceKey).Sddl -eq $sourceAclBefore) 'provider source-key ACL is not changed when the managed copy is sufficient'
}
Assert-True ((Get-Content -Raw -LiteralPath ($managedKey + '.pub')).Trim() -match '^ssh-ed25519\s+') 'public key is derived from the reused private key'
$keyCandidates = @(& $coreModule { param($Context) Get-VpsSshKeyCandidates -Context $Context } $reuseContext)
Assert-True ($keyCandidates.Count -eq 2 -and $keyCandidates[0] -eq $sourceKey -and $keyCandidates[1] -eq $managedKey) 'runtime SSH keeps both source and managed copies as ordered identity candidates'
Assert-True ((& $coreModule { param($Context) Get-VpsSshKeyPath -Context $Context } $reuseContext) -eq $sourceKey) 'runtime SSH retains source-key compatibility before a fallback is needed'
$sourceFallbackContext = [pscustomobject]@{ Plan = [ordered]@{
        SshKey=[ordered]@{Mode='ReuseExisting';SourcePrivateKeyPath=$sourceKey;ManagedFileName='id_ed25519'}
        Paths=[ordered]@{KeyDirectory=(Join-Path $keyReuseRoot 'missing-managed-key')}
    } }
Assert-True ((& $coreModule { param($Context) Get-VpsSshKeyPath -Context $Context } $sourceFallbackContext) -eq $sourceKey) 'runtime SSH falls back to the source key before a managed copy exists'
$badPermissionResult = [pscustomobject]@{ StdErr='WARNING: UNPROTECTED PRIVATE KEY FILE! Permission denied (publickey).'; StdOut='' }
$scpBadPermissionResult = [pscustomobject]@{ StdErr='Load key "<PRIVATE_KEY>": bad permissions'; StdOut='' }
$closedConnectionResult = [pscustomobject]@{ StdErr='scp.exe: Connection closed'; StdOut='' }
$remoteFailureResult = [pscustomobject]@{ StdErr='remote command returned status 1'; StdOut='' }
Assert-True (& $coreModule { param($Result) Test-VpsSshIdentityFailure -Result $Result } $badPermissionResult) 'SSH identity fallback recognizes a locally rejected private key'
Assert-True (& $coreModule { param($Result) Test-VpsSshIdentityFailure -Result $Result } $scpBadPermissionResult) 'SCP identity fallback recognizes the unsuppressed OpenSSH bad-permissions diagnostic'
Assert-True (-not (& $coreModule { param($Result) Test-VpsSshIdentityFailure -Result $Result } $closedConnectionResult)) 'a generic SCP connection close is never assumed to be an identity failure'
Assert-True (-not (& $coreModule { param($Result) Test-VpsSshIdentityFailure -Result $Result } $remoteFailureResult)) 'SSH identity fallback never repeats an unrelated remote command failure'
$scpUploadSource = [regex]::Match($coreSource, '(?s)function Invoke-VpsScpUpload \{.+?\n\}').Value
Assert-True ($scpUploadSource -notmatch "'-q'" -and $scpUploadSource -match "ProgressActivity '上传文件到 VPS'") 'SCP upload keeps identity diagnostics available for safe fallback and displays elapsed progress'

$rsaSourceKey = Join-Path $keyReuseRoot 'provider-rsa-pem-key'
$rsaKeygenResult = Invoke-VpsProcess -FilePath (Get-Command ssh-keygen.exe -ErrorAction Stop).Source `
    -ArgumentList @('-t','rsa','-b','2048','-m','PEM','-N','','-C','provider-rsa-fixture','-f',$rsaSourceKey) -TimeoutSeconds 60
Assert-True ($rsaKeygenResult.ExitCode -eq 0) 'fixture RSA PEM provider key generated'
$rsaManagedDirectory = Join-Path $keyReuseRoot 'MXH-VPS-Deploy-RSA\ssh'
$rsaReuseContext = [pscustomobject]@{ Plan = [ordered]@{
        NodeName='Example-Reused-RSA-Key';Server=[ordered]@{BootstrapKeyPath=$rsaSourceKey}
        SshKey=[ordered]@{Mode='ReuseExisting';SourcePrivateKeyPath=$rsaSourceKey;ManagedFileName='id_vps_management';PreserveSource=$true}
        Paths=[ordered]@{KeyDirectory=$rsaManagedDirectory}
    } }
& $coreModule { param($Context) Initialize-VpsSshKey -Context $Context } $rsaReuseContext 6>$null
$rsaManagedKey = Join-Path $rsaManagedDirectory 'id_vps_management'
$rsaPublicKey = (Get-Content -Raw -LiteralPath ($rsaManagedKey + '.pub')).Trim()
Assert-True ($rsaPublicKey -match '^ssh-rsa\s+') 'RSA PEM provider key is normalized without rotating it'
Assert-True (& $coreModule { param($PublicKey) Test-VpsSupportedSshPublicKey -PublicKey $PublicKey } $rsaPublicKey) 'bootstrap accepts a supported RSA SSH public key'
Assert-True (-not (& $coreModule { Test-VpsSupportedSshPublicKey -PublicKey 'not-an-ssh-key' })) 'bootstrap rejects malformed SSH public key text'
[IO.Directory]::Delete($keyReuseRoot, $true)

$oldLatest = [Environment]::GetEnvironmentVariable('MXH_VPS_TEST_XRAY_LATEST')
try {
    [Environment]::SetEnvironmentVariable('MXH_VPS_TEST_XRAY_LATEST','99.1.2')
    $resolvedLatest = & $coreModule { param($Root) Resolve-VpsXrayVersion -ProjectRoot $Root -Channel LatestStable } $ProjectRoot
    Assert-True ($resolvedLatest -eq '99.1.2') 'latest-stable Xray channel resolves and stores an exact version'
    $resolvedFixed = & $coreModule { param($Root) Resolve-VpsXrayVersion -ProjectRoot $Root -Channel FixedVerified } $ProjectRoot
    Assert-True ($resolvedFixed -eq '26.3.27') 'fixed verified Xray channel remains available'
}
finally { [Environment]::SetEnvironmentVariable('MXH_VPS_TEST_XRAY_LATEST',$oldLatest) }

Write-Host '== Client export fixture ==' -ForegroundColor Cyan
$singleStackNodeName = & $coreModule { Get-MxhAddressFamilyNodeName -BaseName 'Example-US.Entry' -AddressFamily IPv4 -DualStack $false }
$dualStackIpv4Name = & $coreModule { Get-MxhAddressFamilyNodeName -BaseName 'Example-US.Entry' -AddressFamily IPv4 -DualStack $true }
$dualStackIpv6Name = & $coreModule { Get-MxhAddressFamilyNodeName -BaseName 'Example-US.Entry' -AddressFamily IPv6 -DualStack $true }
Assert-True ($singleStackNodeName -eq 'Example-US.Entry') 'single-stack client node keeps the exact user-entered name'
Assert-True ($dualStackIpv4Name -eq 'Example-US.Entry-IPv4' -and $dualStackIpv6Name -eq 'Example-US.Entry-IPv6') 'dual-stack client nodes add explicit IPv4 and IPv6 suffixes'
$fixtureRoot = Join-Path $ProjectRoot '.test-output\client-export'
if (Test-Path -LiteralPath $fixtureRoot) {
    $resolved = [IO.Path]::GetFullPath($fixtureRoot)
    $expectedPrefix = [IO.Path]::GetFullPath((Join-Path $ProjectRoot '.test-output'))
    if (-not $resolved.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup path.' }
    [IO.Directory]::Delete($resolved, $true)
}
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$fixtureContext = [pscustomobject]@{
    ProjectRoot = $ProjectRoot
    ArchivePath = $fixtureRoot
    Plan = [ordered]@{
        NodeName = 'Example-US.Entry'
        Server = [ordered]@{ IPv4 = '192.0.2.10'; IPv6 = '2001:db8::10' }
        Ports = [ordered]@{ XrayPrimary = 443; XrayBackup = 32345 }
        Reality = [ordered]@{ Target = 'www.example.edu'; ForceIpv4Egress = $true }
    }
    Secrets = [ordered]@{
        AdminPassword = 'fixture-only-password'
        Xray = [ordered]@{
            Uuid = [guid]::Empty.ToString()
            RealityPrivateKey = 'fixture-private-key-not-used-by-client'
            RealityClientKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            ShortId = '0123456789abcdef'
        }
    }
    State = [ordered]@{ Modules = @{} }
    SecretsPath = (Join-Path $fixtureRoot 'secrets.json')
    StatePath = (Join-Path $fixtureRoot 'state.json')
    LogPath = (Join-Path $fixtureRoot 'test.log')
    DryRun = $false
}
$clientModule = $modules | Where-Object Id -eq 'client-export'
& $clientModule.Invoke $fixtureContext
$singBoxFixture = Get-Content -Raw -LiteralPath (Join-Path $fixtureRoot 'client-exports\sing-box-outbounds.private.json') | ConvertFrom-Json
Assert-True (@($singBoxFixture.outbounds).Count -eq 2) 'sing-box IPv4 and IPv6 outbounds generated'
Assert-True (@($singBoxFixture.outbounds.tag) -contains 'Example-US.Entry-IPv4' -and @($singBoxFixture.outbounds.tag) -contains 'Example-US.Entry-IPv6') 'dual-stack Reality outbound names expose both address-family suffixes'
Assert-True ((Get-Content -Raw -LiteralPath (Join-Path $fixtureRoot 'client-exports\mihomo-test-primary.yaml')) -match 'xtls-rprx-vision') 'Mihomo Vision profile generated'
Assert-True (@($fixtureContext.State.ClientExports.ValidationTargets).Count -eq 4) 'Reality exports cover primary/backup and IPv4/IPv6 independently'
Assert-True ($fixtureContext.State.ClientExports.CoreValidation.mihomo.Status -eq 'Ready' -and $fixtureContext.State.ClientExports.CoreValidation['sing-box'].Status -eq 'Ready') 'Reality export requires both bundled stable cores'
$serverConfig = New-MxhXrayServerConfig -Context $fixtureContext
$serverConfigRoundTrip = $serverConfig | ConvertTo-Json -Depth 30 | ConvertFrom-Json
Assert-True (@($serverConfigRoundTrip.inbounds).Count -eq 4) 'Reality server creates independent IPv4 and IPv6 listeners for both ports'
Assert-True ('0.0.0.0' -in @($serverConfigRoundTrip.inbounds.listen) -and '2001:db8::10' -in @($serverConfigRoundTrip.inbounds.listen)) 'Reality listener addresses include explicit IPv4 wildcard and configured IPv6 address'
Assert-True (@($serverConfigRoundTrip.routing.rules).Count -eq 1) 'Xray routing rules remain a JSON array with one rule'
Assert-True ($serverConfigRoundTrip.routing.rules[0].outboundTag -eq 'block') 'Xray IPv6 egress block rule preserved'
Assert-True ('::/0' -in @($serverConfigRoundTrip.routing.rules[0].ip)) 'Xray IPv6 destination block covers all IPv6 addresses'
$directOutbound = @($serverConfigRoundTrip.outbounds | Where-Object { $_.tag -eq 'direct' })[0]
Assert-True ($directOutbound.settings.domainStrategy -eq 'ForceIPv4') 'Reality ForceIpv4Egress forces IPv4 on the website outbound'
& $coreModule { param($Plan) Assert-MxhExpectedEgressFamily -Plan $Plan -Protocol Reality -Egress '192.0.2.20' -Label 'fixture' } $fixtureContext.Plan
Assert-True $true 'Reality IPv4 egress acceptance passes when enforced'
$ipv6EgressRejected = $false
try {
    & $coreModule { param($Plan) Assert-MxhExpectedEgressFamily -Plan $Plan -Protocol Reality -Egress '2001:db8::20' -Label 'fixture' } $fixtureContext.Plan
} catch { $ipv6EgressRejected = $true }
Assert-True $ipv6EgressRejected 'Reality validation rejects IPv6 egress when ForceIpv4Egress is enabled'
$optOutPlan = [ordered]@{ Reality = [ordered]@{ ForceIpv4Egress = $false } }
& $coreModule { param($Plan) Assert-MxhExpectedEgressFamily -Plan $Plan -Protocol Reality -Egress '2001:db8::20' -Label 'fixture' } $optOutPlan
Assert-True $true 'explicit IPv6 egress opt-out remains supported'
$localRealityPlan = [ordered]@{
    Reality = [ordered]@{
        Target = 'portal.example.invalid'
        TargetMode = 'LocalOwnedTls'
        ServerName = 'portal.example.invalid'
        TargetAddress = '127.0.0.1:8443'
    }
}
$localRealityTarget = Get-MxhRealityTargetSettings -Plan $localRealityPlan
Assert-True ($localRealityTarget.Mode -eq 'LocalOwnedTls') 'local Reality target mode is preserved'
Assert-True ($localRealityTarget.TargetAddress -eq '127.0.0.1:8443') 'local Reality target never loops to public 443'
Assert-True ($localRealityTarget.ServerName -eq 'portal.example.invalid') 'local Reality SNI uses owned domain'
$replacementRealityPlan = [ordered]@{
    Reality = [ordered]@{
        Target = 'old.example.invalid'
        TargetMode = 'ExternalAudited'
        ServerName = 'old.example.invalid'
        TargetAddress = 'old.example.invalid:443'
    }
}
Set-MxhRealityExternalTarget -Plan $replacementRealityPlan -Target 'new.example.invalid'
$replacementRealityTarget = Get-MxhRealityTargetSettings -Plan $replacementRealityPlan
Assert-True ($replacementRealityTarget.ServerName -eq 'new.example.invalid') 'replacement Reality target updates client server name'
Assert-True ($replacementRealityTarget.TargetAddress -eq 'new.example.invalid:443') 'replacement Reality target updates server destination'
$singleStackRealityContext = [pscustomobject]@{
    Plan = [ordered]@{
        NodeName = 'Example-US.Single'
        Server = [ordered]@{ IPv4 = '192.0.2.11'; IPv6 = $null }
        Ports = [ordered]@{ XrayPrimary = 443 }
        Reality = $fixtureContext.Plan.Reality
    }
    Secrets = $fixtureContext.Secrets
}
$singleStackRealityProfile = New-MxhMihomoProfileText -Context $singleStackRealityContext -ServerPort 443 -MixedPort 17890 -AddressFamily IPv4
Assert-True ($singleStackRealityProfile -match "name: 'Example-US.Single'" -and $singleStackRealityProfile -notmatch 'Example-US.Single-IPv4') 'single-stack Reality profile does not append an IPv4 suffix'
$legacyRealityPlan = [ordered]@{ Reality = [ordered]@{ Target = 'legacy.example.invalid' } }
Set-MxhRealityExternalTarget -Plan $legacyRealityPlan -Target 'legacy-new.example.invalid'
$legacyRealityTarget = Get-MxhRealityTargetSettings -Plan $legacyRealityPlan
Assert-True ($legacyRealityTarget.ServerName -eq 'legacy-new.example.invalid') 'legacy Reality replacement keeps client compatibility'
Assert-True ($legacyRealityTarget.TargetAddress -eq 'legacy-new.example.invalid:443') 'legacy Reality replacement keeps server compatibility'
[IO.Directory]::Delete($fixtureRoot, $true)

Write-Host '== Shadowsocks landing fixture ==' -ForegroundColor Cyan
$landingFixtureRoot = Join-Path $ProjectRoot '.test-output\landing-export'
if (Test-Path -LiteralPath $landingFixtureRoot) { [IO.Directory]::Delete($landingFixtureRoot, $true) }
[IO.Directory]::CreateDirectory($landingFixtureRoot) | Out-Null
$serverKey = [Convert]::ToBase64String([byte[]](1..16))
$primaryUserKey = [Convert]::ToBase64String([byte[]](17..32))
$secondaryUserKey = [Convert]::ToBase64String([byte[]](33..48))
$landingContext = [pscustomobject]@{
    ProjectRoot = $ProjectRoot
    ArchivePath = $landingFixtureRoot
    Plan = [ordered]@{
        NodeName = 'Example-US.Landing'
        Server = [ordered]@{ IPv4 = '192.0.2.20'; IPv6 = '2001:db8::20' }
        Ports = [ordered]@{ LandingShadowsocks = 33456 }
        Shadowsocks = [ordered]@{
            Method = '2022-blake3-aes-128-gcm'
            ClientTransitTag = 'US-West-LA Entry'
            SecondaryIpv6Enabled = $true
            SecondaryIpv6Address = '2001:db8::20'
            SecondaryBindInterface = 'eth0'
        }
    }
    Secrets = [ordered]@{
        AdminPassword = 'fixture-only-password'
        Shadowsocks = [ordered]@{
            ServerKey = $serverKey
            PrimaryUserKey = $primaryUserKey
            SecondaryUserKey = $secondaryUserKey
        }
    }
    State = [ordered]@{ Modules = @{} }
    SecretsPath = (Join-Path $landingFixtureRoot 'secrets.json')
    StatePath = (Join-Path $landingFixtureRoot 'state.json')
    LogPath = (Join-Path $landingFixtureRoot 'test.log')
    DryRun = $false
}
$serverConfig = New-MxhShadowsocksServerConfig -Context $landingContext
Assert-True (@($serverConfig.inbounds[0].users).Count -eq 2) 'SS2022 server has two users'
Assert-True (@($serverConfig.outbounds).Count -eq 2) 'landing server has IPv4 and IPv6 direct outbounds'
Assert-True ($serverConfig.outbounds[1].inet6_bind_address -eq '2001:db8::20') 'IPv6 outbound binds configured address'
Assert-True (@($serverConfig.route.rules).Count -eq 4) 'auth_user routing and opposite-family reject rules generated'
$landingExportModule = $modules | Where-Object Id -eq 'landing-client-export'
& $landingExportModule.Invoke $landingContext
$landingOutbounds = Get-Content -Raw -LiteralPath (Join-Path $landingFixtureRoot 'client-exports\sing-box-shadowsocks-outbounds.private.json') | ConvertFrom-Json
Assert-True (@($landingOutbounds.outbounds).Count -eq 2) 'two landing client outbounds generated'
Assert-True (@($landingOutbounds.outbounds.tag) -contains 'Example-US.Landing-IPv4' -and @($landingOutbounds.outbounds.tag) -contains 'Example-US.Landing-IPv6') 'dual-egress Shadowsocks nodes expose both address-family suffixes'
Assert-True (($landingOutbounds.outbounds[0].password -split ':').Count -eq 2) 'client password combines server and user keys'
Assert-True ($landingOutbounds.outbounds[0].detour -eq 'US-West-LA Entry') 'sing-box detour points to transit tag'
$landingContext.Plan.Shadowsocks.ClientPrimaryName = 'US-West-LA Exit A IPv4'
$landingContext.Plan.Shadowsocks.ClientSecondaryName = 'US-West-SF Exit A ATT IPv6'
$beforeLandingPassword = $landingOutbounds.outbounds[0].password
& $landingExportModule.Invoke $landingContext
$cityOutbounds = Get-Content -Raw -LiteralPath (Join-Path $landingFixtureRoot 'client-exports\sing-box-shadowsocks-outbounds.private.json') | ConvertFrom-Json
$cityMihomo = Get-Content -Raw -LiteralPath (Join-Path $landingFixtureRoot 'client-exports\mihomo-shadowsocks-test.yaml')
Assert-True ($cityOutbounds.outbounds[0].tag -eq 'US-West-LA Exit A IPv4' -and $cityOutbounds.outbounds[1].tag -eq 'US-West-SF Exit A ATT IPv6') 'CLI export preserves independent city labels for each egress'
Assert-True ($cityOutbounds.outbounds[0].password -eq $beforeLandingPassword -and $cityOutbounds.outbounds[1].detour -eq 'US-West-LA Entry') 'CLI city rename preserves credentials and entry detour'
Assert-True ($cityMihomo.Contains('US-West-LA Exit A IPv4') -and $cityMihomo.Contains('US-West-SF Exit A ATT IPv6')) 'both client exporters use the same egress city labels'
$landingContext.Plan.Shadowsocks.Remove('ClientPrimaryName'); $landingContext.Plan.Shadowsocks.Remove('ClientSecondaryName')
$singleStackLandingContext = [pscustomobject]@{
    Plan = [ordered]@{
        NodeName = 'Example-US.SingleLanding'
        Server = [ordered]@{ IPv4 = '192.0.2.21'; IPv6 = $null }
        Ports = $landingContext.Plan.Ports
        Shadowsocks = [ordered]@{
            Method = [string]$landingContext.Plan.Shadowsocks.Method
            ClientTransitTag = [string]$landingContext.Plan.Shadowsocks.ClientTransitTag
            SecondaryIpv6Enabled = $false
        }
    }
    Secrets = $landingContext.Secrets
}
$singleStackLandingProfile = New-MxhLandingMihomoProfileText -Context $singleStackLandingContext -MixedPort 17897
Assert-True ($singleStackLandingProfile -match "name: 'Example-US.SingleLanding'" -and $singleStackLandingProfile -notmatch 'Example-US.SingleLanding-IPv4') 'single-stack Shadowsocks profile does not append an IPv4 suffix'
[IO.Directory]::Delete($landingFixtureRoot, $true)

Write-Host '== AnyTLS trusted TLS and ECH fixture ==' -ForegroundColor Cyan
$generatedPadding = @(New-MxhAnyTlsPaddingScheme)
Assert-True ($generatedPadding.Count -eq 9) 'per-instance AnyTLS padding has stop plus packet 0-7 rules'
Assert-True ($generatedPadding[0] -eq 'stop=8') 'conservative AnyTLS padding stops after the initial packet window'
Assert-True (@($generatedPadding | Where-Object { $_ -notmatch '^(?:stop=8|[0-7]=[0-9,c-]+)$' }).Count -eq 0) 'generated AnyTLS padding uses valid restricted syntax'
$paddingNumbers = @([regex]::Matches(($generatedPadding -join ','), '\d+') | ForEach-Object { [int]$_.Value })
Assert-True (($paddingNumbers | Measure-Object -Maximum).Maximum -le 1100) 'generated AnyTLS padding stays below conservative plaintext maximum'
$legacyPadding = @(Get-MxhAnyTlsPaddingScheme -Plan ([ordered]@{ AnyTls = [ordered]@{} }))
Assert-True ($legacyPadding[2] -eq '1=100-400') 'legacy AnyTLS plans fall back to the official padding scheme'
$fakeEchConfig = "-----BEGIN ECH CONFIGS-----`nQUJDRA==`n-----END ECH CONFIGS-----`n"
$fakeEchKeys = "-----BEGIN ECH KEYS-----`nRUZHSA==`n-----END ECH KEYS-----`n"
$parsedEch = ConvertFrom-MxhEchKeyPairText -Text ($fakeEchConfig + $fakeEchKeys)
Assert-True ($parsedEch.ClientConfigBase64 -eq 'QUJDRA==') 'ECH client base64 is extracted without headers'
$anyTlsContext = [pscustomobject]@{
    Plan = [ordered]@{
        NodeName = 'Example-US.AnyTLS'
        Server = [ordered]@{ IPv4 = '192.0.2.40'; IPv6 = '2001:db8::40' }
        Ports = [ordered]@{ AnyTlsPrimary = 443 }
        AnyTls = [ordered]@{
            ServerName = 'edge.example.invalid'
            EchPublicName = 'www.example.invalid'
            ForceIpv4Egress = $true
            PaddingSchemeMode = 'PerInstanceConservativeV1'
            PaddingScheme = $generatedPadding
        }
    }
    Secrets = [ordered]@{
        AnyTls = [ordered]@{
            Password = [Convert]::ToBase64String([byte[]](49..80))
            EchServerKeyPem = $fakeEchKeys
            EchClientConfigPem = $fakeEchConfig
            EchClientConfigBase64 = $parsedEch.ClientConfigBase64
        }
    }
}
$anyTlsValidationMetadata = & $coreModule {
    param($target, $plan)
    Get-MxhValidationTargetMetadata -Target $target -Protocol AnyTLS -Plan $plan
} ([ordered]@{ AddressFamily = 'IPv4'; MixedPort = 17895 }) $anyTlsContext.Plan
Assert-True ($anyTlsValidationMetadata.Entry -eq 'primary' -and $anyTlsValidationMetadata.ServerPort -eq 443) 'AnyTLS real validation defaults missing Reality-only Entry and ServerPort fields safely'
$realityValidationPlan = [ordered]@{ Ports = [ordered]@{ XrayPrimary = 443; AnyTlsPrimary = 8443 } }
$realityValidationMetadata = & $coreModule {
    param($target, $plan)
    Get-MxhValidationTargetMetadata -Target $target -Protocol Reality -Plan $plan
} ([ordered]@{ Entry = 'backup'; AddressFamily = 'IPv6'; ServerPort = 30443 }) $realityValidationPlan
Assert-True ($realityValidationMetadata.Entry -eq 'backup' -and $realityValidationMetadata.ServerPort -eq 30443) 'Reality real validation preserves explicit entry and server port metadata'
$anyTlsServerConfig = New-MxhAnyTlsServerConfig -Context $anyTlsContext
$anyTlsRoundTrip = $anyTlsServerConfig | ConvertTo-Json -Depth 30 | ConvertFrom-Json
Assert-True ($anyTlsRoundTrip.inbounds[0].type -eq 'anytls') 'AnyTLS server inbound generated'
Assert-True ($anyTlsRoundTrip.inbounds[0].tls.min_version -eq '1.3') 'AnyTLS requires TLS 1.3'
Assert-True ($anyTlsRoundTrip.inbounds[0].tls.ech.enabled) 'AnyTLS server ECH enabled'
Assert-True ((@($anyTlsRoundTrip.inbounds[0].padding_scheme) -join "`n") -eq ($generatedPadding -join "`n")) 'AnyTLS server preserves the per-instance padding scheme'
Assert-True (@($anyTlsRoundTrip.route.rules).Count -eq 1) 'AnyTLS IPv4-only rule remains an array'
$anyTlsClient = New-MxhAnyTlsClientOutbound -Context $anyTlsContext -Server '192.0.2.40' -Tag 'anytls-out'
Assert-True ($anyTlsClient.tls.ech.enabled) 'sing-box AnyTLS client ECH enabled'
Assert-True (-not $anyTlsClient.tls.Contains('insecure')) 'sing-box AnyTLS client does not disable certificate verification'
$anyTlsMihomo = New-MxhAnyTlsMihomoProfileText -Context $anyTlsContext -MixedPort 17894
Assert-True ($anyTlsMihomo -match 'type: anytls') 'Mihomo AnyTLS profile generated'
Assert-True ($anyTlsMihomo -match "name: 'Example-US.AnyTLS-IPv4'" -and $anyTlsMihomo -notmatch 'Example-US.AnyTLS-AnyTLS') 'dual-stack AnyTLS name uses only the address-family suffix'
Assert-True ($anyTlsMihomo -match 'skip-cert-verify: false') 'Mihomo AnyTLS keeps certificate verification enabled'
Assert-True ($anyTlsMihomo -match 'ech-opts:') 'Mihomo AnyTLS profile includes ECH'
$singleStackAnyTlsContext = [pscustomobject]@{
    Plan = [ordered]@{
        NodeName = 'Example-US.Single'
        Server = [ordered]@{ IPv4 = '192.0.2.41'; IPv6 = $null }
        Ports = $anyTlsContext.Plan.Ports
        AnyTls = $anyTlsContext.Plan.AnyTls
    }
    Secrets = $anyTlsContext.Secrets
}
$singleStackAnyTlsProfile = New-MxhAnyTlsMihomoProfileText -Context $singleStackAnyTlsContext -MixedPort 17896 -AddressFamily IPv4
Assert-True ($singleStackAnyTlsProfile -match "name: 'Example-US.Single'" -and $singleStackAnyTlsProfile -notmatch 'Example-US.Single-(?:AnyTLS|IPv4)') 'single-stack AnyTLS profile keeps the exact user-entered name without protocol or IPv4 suffixes'

Write-Host '== Bidirectional protocol migration planning ==' -ForegroundColor Cyan
$realitySourcePath = Join-Path $ProjectRoot 'tests\fixtures\dry-run-plan.json'
$anyTlsSourcePath = Join-Path $ProjectRoot 'tests\fixtures\dry-run-anytls-plan.json'
$shadowsocksSourcePath = Join-Path $ProjectRoot 'tests\fixtures\dry-run-landing-plan.json'
$realitySource = Get-Content -Raw -LiteralPath $realitySourcePath | ConvertFrom-Json -AsHashtable
$anyTlsSource = Get-Content -Raw -LiteralPath $anyTlsSourcePath | ConvertFrom-Json -AsHashtable
$shadowsocksSource = Get-Content -Raw -LiteralPath $shadowsocksSourcePath | ConvertFrom-Json -AsHashtable
$migrationAllowlist = [ordered]@{ IPv4 = @('192.0.2.70'); IPv6 = @('2001:db8::70') }
$baselineTuning = [ordered]@{ Mode = 'BaselineOnly'; BandwidthMbps = $null; ReferenceRttMs = $null }
$migrationCases = @(
    @{ Source = $realitySource; Path = $realitySourcePath; Target = 'AnyTlsEntry'; Port = 443 },
    @{ Source = $realitySource; Path = $realitySourcePath; Target = 'ShadowsocksLanding'; Port = 34101 },
    @{ Source = $anyTlsSource; Path = $anyTlsSourcePath; Target = 'RealityEntry'; Port = 34102 },
    @{ Source = $anyTlsSource; Path = $anyTlsSourcePath; Target = 'ShadowsocksLanding'; Port = 34103 },
    @{ Source = $shadowsocksSource; Path = $shadowsocksSourcePath; Target = 'RealityEntry'; Port = 34104 },
    @{ Source = $shadowsocksSource; Path = $shadowsocksSourcePath; Target = 'AnyTlsEntry'; Port = 443 }
)
$migrationPlans = foreach ($case in $migrationCases) {
    New-MxhProtocolMigrationPlan -SourcePlan $case.Source -SourcePlanPath $case.Path `
        -TargetRole $case.Target -TargetServicePort $case.Port `
        -RealityTargetMode ExternalAudited -RealityTarget 'target.example.invalid' `
        -RealityServerName 'target.example.invalid' -RealityTargetAddress 'target.example.invalid:443' `
        -AnyTlsServerName 'edge.example.invalid' -EchPublicName 'www.example.invalid' `
        -SingBoxVersion '1.14.0' `
        -AnyTlsPaddingScheme @('stop=8', '0=10-20') -ForceIpv4Egress $true `
        -TrustedTlsEnabled ($case.Target -eq 'AnyTlsEntry') -CloudflareZoneName 'example.invalid' `
        -CertbotEmail 'fixture@example.invalid' -CloudflareTokenFile 'C:\fixture-token.private.txt' `
        -TrustedEntryIps $migrationAllowlist -ClientTransitTag 'US-West-LA Entry' `
        -ValidationEntryPlanPath 'C:\fixture-entry-plan.json' `
        -SecondaryIpv6Enabled $false -NetworkTuning $baselineTuning
}
Assert-True ($migrationPlans.Count -eq 6) 'all six directed protocol role conversions are generated'
$directionNames = @($migrationPlans | ForEach-Object { "$($_.Migration.SourceRole)->$($_.Migration.TargetRole)" })
Assert-True (($directionNames | Sort-Object -Unique).Count -eq 6) 'every Reality AnyTLS Shadowsocks direction is unique'
foreach ($plan in $migrationPlans) {
    Assert-True ($plan.Role -eq $plan.Migration.TargetRole) "migration target role is authoritative for $($plan.Migration.SourceRole)->$($plan.Role)"
    Assert-True ('migration-preflight' -in $plan.Migration.ModuleIds) 'migration plan includes fresh preflight'
    Assert-True ('migration-arm-rollback' -in $plan.Migration.ModuleIds) 'migration plan arms rollback before target switch'
    Assert-True ('migration-commit' -in $plan.Migration.ModuleIds) 'migration plan requires final commit'
    Assert-True ('final-validation' -in $plan.Migration.ModuleIds) 'migration plan includes target validation'
    $targetModule = switch ($plan.Role) {
        'RealityEntry' { 'xray-reality' }
        'AnyTlsEntry' { 'sing-box-anytls' }
        'ShadowsocksLanding' { 'sing-box-shadowsocks' }
    }
    Assert-True ($targetModule -in $plan.Migration.ModuleIds) "migration includes target module $targetModule"
}
Assert-True (($migrationPlans | Where-Object Role -eq 'RealityEntry').Count -eq 2) 'two sources can migrate to Reality'
Assert-True (($migrationPlans | Where-Object Role -eq 'AnyTlsEntry').Count -eq 2) 'two sources can migrate to AnyTLS'
Assert-True (($migrationPlans | Where-Object Role -eq 'ShadowsocksLanding').Count -eq 2) 'two sources can migrate to Shadowsocks'
Assert-True (@($migrationPlans | Where-Object Role -eq 'AnyTlsEntry' | Where-Object { [string]$_.AnyTls.SingBoxVersion -ne '1.14.0' }).Count -eq 0) 'AnyTLS migration replaces a legacy source version with the current pinned sing-box version'
Assert-True (@($migrationPlans | Where-Object Role -eq 'ShadowsocksLanding' | Where-Object { [string]$_.Shadowsocks.SingBoxVersion -ne '1.14.0' }).Count -eq 0) 'Shadowsocks migration replaces a legacy source version with the current pinned sing-box version'
Assert-True (@($migrationPlans | Where-Object Role -eq 'ShadowsocksLanding' | Where-Object { 'migration-shadowsocks-probe' -notin $_.Migration.ModuleIds }).Count -eq 0) 'every Shadowsocks migration requires a trusted-entry external probe'
$migrationSourceText = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'src\VpsDeploy.Migration.ps1')
Assert-True ($migrationSourceText -match '-SingBoxVersion \(\[string\]\$versions\.sing_box\.version\)') 'interactive migration planning always passes the pinned sing-box version into the new plan'
$localRealityMigrationIds = @(Get-MxhMigrationModuleIds -TargetRole RealityEntry -RealityTargetMode LocalOwnedTls)
Assert-True ('certbot-dns' -in $localRealityMigrationIds -and 'local-https-target' -in $localRealityMigrationIds) 'local Reality migration includes certificate and loopback HTTPS modules'
Assert-True ('target-audit' -notin $localRealityMigrationIds) 'local Reality migration excludes external target audit'

Write-Host '== Protocol lifecycle inventory and state transitions ==' -ForegroundColor Cyan
$standbyAnyTls = New-MxhProtocolMigrationPlan -SourcePlan $realitySource -SourcePlanPath $realitySourcePath `
    -TargetRole AnyTlsEntry -Operation InstallStandby -TargetServicePort 443 `
    -AnyTlsServerName 'edge.example.invalid' -EchPublicName 'www.example.invalid' `
    -SingBoxVersion '1.14.0' `
    -AnyTlsPaddingScheme @('stop=8', '0=10-20') -TrustedTlsEnabled $true `
    -CloudflareZoneName 'example.invalid' -CertbotEmail 'fixture@example.invalid' `
    -CloudflareTokenFile 'C:\fixture-token.private.txt' -NetworkTuning $baselineTuning
Assert-True ($standbyAnyTls.ProtocolInventory.RealityEntry.Installed -and $standbyAnyTls.ProtocolInventory.RealityEntry.Enabled) 'standby install keeps Reality installed and enabled'
Assert-True ($standbyAnyTls.ProtocolInventory.AnyTlsEntry.Installed -and -not $standbyAnyTls.ProtocolInventory.AnyTlsEntry.Enabled) 'standby install records AnyTLS as installed but disabled'
Assert-True ($standbyAnyTls.Migration.ValidationInventory.AnyTlsEntry.Enabled) 'standby protocol is temporarily enabled for real validation'
Assert-True ($standbyAnyTls.Migration.FinalRole -eq 'RealityEntry') 'standby install restores the original primary role'

$enableAnyTls = New-MxhProtocolLifecyclePlan -SourcePlan $standbyAnyTls -SourcePlanPath $realitySourcePath `
    -SourceInventory $standbyAnyTls.ProtocolInventory -TargetRole AnyTlsEntry -Operation Enable
Assert-True ($enableAnyTls.Migration.FinalInventory.AnyTlsEntry.Enabled) 'enabling installed AnyTLS marks it enabled'
Assert-True (-not $enableAnyTls.Migration.FinalInventory.RealityEntry.Enabled) 'enabling AnyTLS disables conflicting Reality without uninstalling it'
Assert-True ($enableAnyTls.Migration.FinalInventory.RealityEntry.Installed) 'entry switch preserves Reality installation'
Assert-True ('protocol-lifecycle-state' -in $enableAnyTls.Migration.ModuleIds -and 'sing-box-anytls' -notin $enableAnyTls.Migration.ModuleIds) 'switching installed protocols does not reinstall the target'

$uninstallReality = New-MxhProtocolLifecyclePlan -SourcePlan $enableAnyTls -SourcePlanPath $realitySourcePath `
    -SourceInventory $enableAnyTls.Migration.FinalInventory -TargetRole RealityEntry -Operation Uninstall
Assert-True (-not $uninstallReality.Migration.FinalInventory.RealityEntry.Installed) 'uninstall removes the disabled protocol from final inventory'
Assert-True ($uninstallReality.Migration.FinalInventory.AnyTlsEntry.Enabled) 'uninstall leaves the active peer entry enabled'
Assert-True ('protocol-lifecycle-uninstall' -in $uninstallReality.Migration.ModuleIds) 'uninstall plan uses the dedicated removal module'
Assert-True ('protocol-lifecycle-final-firewall' -in $uninstallReality.Migration.ModuleIds) 'uninstall plan performs final firewall convergence before commit'
$activeUninstallRejected = $false
try {
    New-MxhProtocolLifecyclePlan -SourcePlan $enableAnyTls -SourcePlanPath $realitySourcePath `
        -SourceInventory $enableAnyTls.Migration.FinalInventory -TargetRole AnyTlsEntry -Operation Uninstall | Out-Null
}
catch { $activeUninstallRejected = $_.Exception.Message -match '只能卸载' }
Assert-True $activeUninstallRejected 'active protocols cannot be uninstalled directly'

$realityToSs = @($migrationPlans | Where-Object { $_.Migration.SourceRole -eq 'RealityEntry' -and $_.Migration.TargetRole -eq 'ShadowsocksLanding' })[0]
Assert-True ($realityToSs.Migration.FinalInventory.RealityEntry.Enabled -and $realityToSs.Migration.FinalInventory.ShadowsocksLanding.Enabled) 'Shadowsocks can run concurrently with the entry protocol'
$firewallFixtureState = [ordered]@{ BootstrapSshRemoved = $true }
$firewallParameters = Get-MxhProtocolFirewallParameters -Plan $realityToSs -State $firewallFixtureState -Inventory $realityToSs.Migration.FinalInventory
Assert-True ([string]$firewallParameters.TCP_PORTS -match '443' -and [string]$firewallParameters.TCP_PORTS -match [string]$realityToSs.Ports.XrayBackup) 'concurrent firewall retains Reality primary and rescue ports'
Assert-True ([string]$firewallParameters.RESTRICTED_PORT -eq [string]$realityToSs.Ports.LandingShadowsocks) 'concurrent firewall keeps Shadowsocks as the restricted TCP and UDP port'
$standaloneBaseline = [ordered]@{ Mode = 'BaselineOnly'; BandwidthMbps = $null; ReferenceRttMs = $null }
$networkOnlyPlan = New-MxhNetworkTuningPlan -SourcePlan $realitySource -SourcePlanPath $realitySourcePath `
    -TuningRole RealityEntry -NetworkTuning $standaloneBaseline
Assert-True ($networkOnlyPlan.Migration.Operation -eq 'NetworkTune') 'standalone network tuning uses a dedicated lifecycle operation'
Assert-True ('network-tuning' -in $networkOnlyPlan.Migration.ModuleIds) 'standalone network tuning includes the tuning module'
Assert-True ('nftables-transition' -notin $networkOnlyPlan.Migration.ModuleIds -and 'protocol-lifecycle-final-firewall' -notin $networkOnlyPlan.Migration.ModuleIds) 'standalone network tuning does not rewrite the firewall'
Assert-True ($networkOnlyPlan.NetworkTuning.Mode -eq 'BaselineOnly' -and $null -eq $networkOnlyPlan.NetworkTuning.ReferenceRttMs) 'baseline network tuning requires no RTT'

$clearCommandResult = & (Get-Module VpsDeploy.Core) {
    [ordered]@{
        Clear = Test-VpsClearCommand ' clear '
        Cls = Test-VpsClearCommand 'CLS'
        BreadCloud = Test-VpsClearCommand 'BreadCloud'
        Clearwater = Test-VpsClearCommand 'Clearwater'
    }
}
Assert-True ($clearCommandResult.Clear -and $clearCommandResult.Cls) 'clear and cls are exact global clear commands'
Assert-True (-not $clearCommandResult.BreadCloud -and -not $clearCommandResult.Clearwater) 'clear command never uses prefix matching'
$helpCommandResult=&(Get-Module VpsDeploy.Core){[ordered]@{Help=Test-VpsHelpCommand ' help ';Short=Test-VpsHelpCommand 'H';Host=Test-VpsHelpCommand 'Hetzner'}}
Assert-True ($helpCommandResult.Help -and $helpCommandResult.Short -and -not $helpCommandResult.Host) 'help and h are exact global help commands'
$archiveRootValidation = & (Get-Module VpsDeploy.Core) {
    param($AbsolutePath, $DriveRoot)
    [ordered]@{
        Absolute = Test-VpsArchiveRoot $AbsolutePath
        Relative = Test-VpsArchiveRoot 'relative\archive'
        DriveRoot = Test-VpsArchiveRoot $DriveRoot
    }
} $ProjectRoot ([IO.Path]::GetPathRoot($ProjectRoot))
Assert-True ($archiveRootValidation.Absolute) 'archive root accepts a fully qualified non-root path'
Assert-True (-not $archiveRootValidation.Relative -and -not $archiveRootValidation.DriveRoot) 'archive root rejects relative paths and a bare drive root'

$backslashProjectRoot = $ProjectRoot.Replace('/', '\')
$forwardSlashProjectRoot = $ProjectRoot.Replace('\', '/')
$mixedProjectRoot = $backslashProjectRoot.Substring(0, 3) + $backslashProjectRoot.Substring(3).Replace('\', '/')
$pathSeparatorValidation = & (Get-Module VpsDeploy.Core) {
    param($BackslashPath, $ForwardSlashPath, $MixedPath)
    [pscustomobject]@{
        BackslashAccepted = Test-VpsPathSeparatorStyle -Value $BackslashPath
        ForwardSlashAccepted = Test-VpsPathSeparatorStyle -Value $ForwardSlashPath
        MixedRejected = -not (Test-VpsPathSeparatorStyle -Value $MixedPath)
        ForwardArchiveAccepted = Test-VpsArchiveRoot $ForwardSlashPath
        NormalizedForward = ConvertTo-VpsInputPath -Value $ForwardSlashPath
        ExistingForward = Test-VpsExistingInputPath -Value ($ForwardSlashPath.TrimEnd('/') + '/README.md') -PathType Leaf
        ExistingMixed = Test-VpsExistingInputPath -Value ($MixedPath.TrimEnd('/') + '/README.md') -PathType Leaf
    }
} $backslashProjectRoot $forwardSlashProjectRoot $mixedProjectRoot
Assert-True ($pathSeparatorValidation.BackslashAccepted -and $pathSeparatorValidation.ForwardSlashAccepted) 'path input accepts either slash style when used consistently'
Assert-True $pathSeparatorValidation.MixedRejected 'path input rejects mixed slash styles'
Assert-True $pathSeparatorValidation.ForwardArchiveAccepted 'archive root accepts a consistently forward-slashed absolute path'
Assert-True ($pathSeparatorValidation.NormalizedForward -eq [IO.Path]::GetFullPath($ProjectRoot)) 'forward-slash path input normalizes to the native platform separator'
Assert-True ($pathSeparatorValidation.ExistingForward -and -not $pathSeparatorValidation.ExistingMixed) 'existing-file validation accepts one separator style and rejects a mixed path'

$migrationFixtureRoot = Join-Path $ProjectRoot '.test-output\migration-context'
if (Test-Path -LiteralPath $migrationFixtureRoot) { [IO.Directory]::Delete($migrationFixtureRoot, $true) }
[IO.Directory]::CreateDirectory($migrationFixtureRoot) | Out-Null
$migrationSourcePlan = ($realitySource | ConvertTo-Json -Depth 40) | ConvertFrom-Json -AsHashtable
$migrationSourcePlan.Paths.Archive = $migrationFixtureRoot
$migrationSourcePlan.Paths.KeyDirectory = Join-Path $migrationFixtureRoot 'fixture-managed-key'
$migrationSourcePlan.SshKey = [ordered]@{ ManagedFileName = 'id_vps_management'; Mode = 'ReuseExisting' }
[IO.Directory]::CreateDirectory([string]$migrationSourcePlan.Paths.KeyDirectory) | Out-Null
[IO.File]::WriteAllText((Join-Path $migrationSourcePlan.Paths.KeyDirectory 'id_vps_management'), 'fixture-key')
[IO.File]::WriteAllText((Join-Path $migrationSourcePlan.Paths.KeyDirectory 'id_vps_management.pub'), 'fixture-public-key')
$migrationSourcePlanPath = Join-Path $migrationFixtureRoot 'deployment-plan.json'
$successState = { [ordered]@{ Status = 'Success'; UpdatedAt = '2026-01-01T00:00:00Z'; Message = 'fixture' } }
$migrationSourceState = [ordered]@{
    SchemaVersion = 1
    CurrentManagementPort = [int]$migrationSourcePlan.Ports.SshPrimary
    Modules = [ordered]@{
        'ssh-transition' = & $successState
        'xray-reality' = & $successState
        'nftables-transition' = & $successState
        'final-validation' = & $successState
        'ssh-cutover' = & $successState
        'private-archive' = & $successState
        'komari-agent' = & $successState
    }
}
$migrationSourceSecrets = [ordered]@{
    SchemaVersion = 1
    AdminPassword = 'fixture-admin-password'
    Xray = [ordered]@{ Uuid = 'fixture'; RealityPrivateKey = 'fixture'; RealityClientKey = 'fixture'; ShortId = 'fixture' }
}
Save-VpsJson -Value $migrationSourcePlan -Path $migrationSourcePlanPath -Private
Save-VpsJson -Value $migrationSourceState -Path (Join-Path $migrationFixtureRoot 'deployment-state.json') -Private
Save-VpsJson -Value $migrationSourceSecrets -Path (Join-Path $migrationFixtureRoot 'deployment-secrets.private.json') -Private
Assert-True (Test-MxhProtocolMigrationSource -PlanPath $migrationSourcePlanPath -Plan $migrationSourcePlan -State $migrationSourceState) 'completed script-managed source is accepted for migration'
$migrationTargetPlan = New-MxhProtocolMigrationPlan -SourcePlan $migrationSourcePlan -SourcePlanPath $migrationSourcePlanPath `
    -TargetRole ShadowsocksLanding -TargetServicePort 34201 -TrustedEntryIps $migrationAllowlist `
    -ClientTransitTag 'US-West-LA Entry' -SingBoxVersion '1.14.0' -NetworkTuning $baselineTuning
$migrationResultFixture = [pscustomobject]@{
    Plan = $migrationTargetPlan
    Source = [pscustomobject]@{ PlanPath = $migrationSourcePlanPath; Plan = $migrationSourcePlan; State = $migrationSourceState }
}
$migrationContext = & (Get-Module VpsDeploy.Core) {
    param($Root, $Result)
    Initialize-MxhProtocolMigrationContext -ProjectRoot $Root -MigrationResult $Result -NonInteractive
} $ProjectRoot $migrationResultFixture
Assert-True ($migrationContext.Plan.Role -eq 'ShadowsocksLanding') 'migration context writes the target role plan'
Assert-True (Test-Path -LiteralPath (Join-Path $migrationContext.Plan.Migration.LocalBackupDirectory 'deployment-plan.json')) 'migration context preserves the source plan before replacement'
Assert-True ($migrationContext.State.Modules.Contains('xray-reality')) 'migration context preserves source protocol history'
Assert-True (-not $migrationContext.State.Modules.Contains('nftables-transition') -and -not $migrationContext.State.Modules.Contains('final-validation')) 'migration context resets target validation and firewall modules'
Assert-True ($migrationContext.State.Migration.Status -eq 'Planned' -and -not $migrationContext.State.Migration.RollbackArmed) 'migration context starts before remote rollback is armed'
[IO.Directory]::Delete($migrationFixtureRoot, $true)

Write-Host '== Abandon incomplete deployment transaction ==' -ForegroundColor Cyan
$abandonLocalRoot = Join-Path $ProjectRoot '.test-output\abandon-local-plan'
if (Test-Path -LiteralPath $abandonLocalRoot) { [IO.Directory]::Delete($abandonLocalRoot, $true) }
[IO.Directory]::CreateDirectory((Join-Path $abandonLocalRoot 'ssh')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $abandonLocalRoot 'server-configs')) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $abandonLocalRoot 'client-exports')) | Out-Null
$abandonPlanPath = Join-Path $abandonLocalRoot 'deployment-plan.json'
$abandonStatePath = Join-Path $abandonLocalRoot 'deployment-state.json'
$abandonSecretsPath = Join-Path $abandonLocalRoot 'deployment-secrets.private.json'
$abandonTokenPath = Join-Path $abandonLocalRoot 'cloudflare-certbot-token.private.txt'
$abandonKeyPath = Join-Path $abandonLocalRoot 'ssh\id_vps_management'
$abandonPlan = [ordered]@{ Paths = [ordered]@{ Archive = $abandonLocalRoot } }
$abandonState = [ordered]@{ Modules = [ordered]@{} }
Save-VpsJson -Value $abandonPlan -Path $abandonPlanPath -Private
Save-VpsJson -Value $abandonState -Path $abandonStatePath -Private
Save-VpsJson -Value ([ordered]@{ Fixture = 'secret-placeholder' }) -Path $abandonSecretsPath -Private
[IO.File]::WriteAllText($abandonTokenPath, 'fixture-token-placeholder')
[IO.File]::WriteAllText($abandonKeyPath, 'fixture-key-placeholder')
[IO.File]::WriteAllText((Join-Path $abandonLocalRoot 'deployment.log'), 'fixture log')
& $coreModule { param($Root, $Path) Invoke-VpsAbandonIncompletePlan -ProjectRoot $Root -PlanPath $Path } $ProjectRoot $abandonPlanPath 6>$null
Assert-True (-not (Test-Path -LiteralPath $abandonPlanPath) -and -not (Test-Path -LiteralPath $abandonStatePath) -and -not (Test-Path -LiteralPath $abandonSecretsPath)) 'abandoning an unstarted plan removes only incomplete plan state and secrets'
Assert-True ((Test-Path -LiteralPath $abandonTokenPath) -and (Test-Path -LiteralPath $abandonKeyPath)) 'abandoning an unstarted plan preserves external token and SSH key files'
$abandonRecords = @(Get-ChildItem -LiteralPath (Join-Path $abandonLocalRoot 'abandoned-transactions') -Filter '*.json' -File)
Assert-True ($abandonRecords.Count -eq 1) 'abandoning an unstarted plan leaves one idempotent redacted audit record'
$abandonRecord = Get-Content -Raw -LiteralPath $abandonRecords[0].FullName | ConvertFrom-Json -AsHashtable
Assert-True (-not [bool]$abandonRecord.SnapshotDeleted -and [string]$abandonRecord.Kind -eq 'LocalPlanOnly') 'local-only abandon does not falsely claim a remote snapshot was deleted'
[IO.Directory]::Delete($abandonLocalRoot, $true)

$legacyAbandonRoot = Join-Path $ProjectRoot '.test-output\abandon-legacy-mutated-plan'
[IO.Directory]::CreateDirectory($legacyAbandonRoot) | Out-Null
$legacyAbandonPlanPath = Join-Path $legacyAbandonRoot 'deployment-plan.json'
$legacyAbandonStatePath = Join-Path $legacyAbandonRoot 'deployment-state.json'
Save-VpsJson -Value ([ordered]@{ Paths = [ordered]@{ Archive = $legacyAbandonRoot } }) -Path $legacyAbandonPlanPath -Private
Save-VpsJson -Value ([ordered]@{ Modules = [ordered]@{ audit = [ordered]@{ Status = 'Success' } } }) -Path $legacyAbandonStatePath -Private
$legacyAbandonRejected = $false
try { & $coreModule { param($Root, $Path) Invoke-VpsAbandonIncompletePlan -ProjectRoot $Root -PlanPath $Path } $ProjectRoot $legacyAbandonPlanPath 6>$null }
catch { $legacyAbandonRejected = $_.Exception.Message -match '尚无统一部署前快照' }
Assert-True $legacyAbandonRejected 'legacy remotely mutated plans without a unified baseline refuse fake clean rollback'
Assert-True ((Test-Path -LiteralPath $legacyAbandonPlanPath) -and (Test-Path -LiteralPath $legacyAbandonStatePath)) 'rejected legacy abandon preserves local recovery material'
[IO.Directory]::Delete($legacyAbandonRoot, $true)

Write-Host '== Conservative adaptive network planning ==' -ForegroundColor Cyan
$entrySmall = Get-VpsConservativeNetworkPlan -Role RealityEntry -MemoryKiB 1048576 `
    -Mode AdaptiveConservative -BandwidthMbps 1000 -ReferenceRttMs 160
Assert-True ($entrySmall.MemoryTier -eq 'small') '1 GiB entry uses small memory tier'
Assert-True ($entrySmall.BufferCapBytes -eq 8MB) '1 GiB entry buffer cap is 8 MiB'
Assert-True ($entrySmall.BufferTargetBytes -eq 8MB) 'high-BDP entry is capped by memory'
Assert-True ($entrySmall.QueueFloor -eq 2048) 'entry queue floor considers the nominal 1 Gbps plan conservatively'
$entryTiny = Get-VpsConservativeNetworkPlan -Role RealityEntry -MemoryKiB 524288 `
    -Mode AdaptiveConservative -BandwidthMbps 100 -ReferenceRttMs 160
Assert-True ($entryTiny.BufferTargetBytes -eq 4000000) '100 Mbps 160 ms entry uses two BDP below tiny cap'
Assert-True ($entryTiny.BufferTargetBytes -le $entryTiny.BufferCapBytes) 'tiny entry never exceeds memory cap'
$landingSmall = Get-VpsConservativeNetworkPlan -Role ShadowsocksLanding -MemoryKiB 1048576 `
    -Mode AdaptiveConservative -BandwidthMbps 1000 -ReferenceRttMs 5
Assert-True ($landingSmall.BufferTargetBytes -eq 1250000) 'nearby landing uses entry-to-landing RTT BDP'
Assert-True ($landingSmall.QueueFloor -eq 2048) 'landing queue floor reflects fan-in role'
$anyTlsSmall = Get-VpsConservativeNetworkPlan -Role AnyTlsEntry -MemoryKiB 1048576 `
    -Mode AdaptiveConservative -BandwidthMbps 1000 -ReferenceRttMs 160
Assert-True ($anyTlsSmall.Profile -eq 'entry-small-high-adaptive') 'AnyTLS profile records role, memory, nominal bandwidth and mode'
Assert-True ($anyTlsSmall.BufferCapBytes -eq 8MB) 'AnyTLS entry respects memory cap'
$monitor = Get-VpsConservativeNetworkPlan -Role MonitorOnly -MemoryKiB 1048576 -Mode BaselineOnly
Assert-True ($monitor.BufferTargetBytes -eq 0) 'monitor baseline does not tune buffers'
Assert-True ($monitor.QueueFloor -eq 0) 'monitor baseline does not pin proxy queues'
$baselineKnownBandwidth = Get-VpsConservativeNetworkPlan -Role RealityEntry -MemoryKiB 1048576 -Mode BaselineOnly -BandwidthMbps 500
Assert-True ($baselineKnownBandwidth.BandwidthMbps -eq 500 -and $baselineKnownBandwidth.ReferenceRttMs -eq $null) 'baseline records required nominal bandwidth without requiring RTT'
Assert-True ($baselineKnownBandwidth.BufferTargetBytes -eq 0 -and $baselineKnownBandwidth.QueueFloor -eq 1024) 'bandwidth-aware baseline remains conservative and does not tune buffers'
$invalidTuningRejected = $false
try {
    Get-VpsConservativeNetworkPlan -Role RealityEntry -MemoryKiB 1048576 `
        -Mode AdaptiveConservative -BandwidthMbps 0 -ReferenceRttMs 160 | Out-Null
}
catch { $invalidTuningRejected = $true }
Assert-True $invalidTuningRejected 'invalid adaptive bandwidth is rejected'

Write-Host '== Random port generator ==' -ForegroundColor Cyan
$ports = 1..200 | ForEach-Object { Get-VpsRandomPort -Exclude @(22, 443) }
Assert-True (@($ports | Where-Object { $_ -lt 20000 -or $_ -gt 59999 }).Count -eq 0) 'ports stay in 20000-59999'
Assert-True (@($ports | Where-Object { $_ -in @(22, 443) }).Count -eq 0) 'excluded ports not returned'

Write-Host '== Bash syntax and line endings ==' -ForegroundColor Cyan
$bashCandidates = @(
    'D:\Program Files\Git\bin\bash.exe',
    'C:\Program Files\Git\bin\bash.exe',
    '/usr/bin/bash',
    '/bin/bash'
)
$bash = $bashCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$shellFiles = @(Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'assets\remote') -Filter '*.sh' -File)
Assert-True ($shellFiles.Count -ge 10) 'remote shell module count'
$remotePayload = New-VpsRemoteScriptPayload `
    -Context ([pscustomobject]@{ ProjectRoot = $ProjectRoot }) `
    -Asset 'audit.sh' -Parameters ([ordered]@{ SAMPLE = 'value' })
Assert-True (-not $remotePayload.Contains("`r")) 'generated remote payload uses LF on Windows'
Assert-True ($remotePayload -match '(?m)^set -euo pipefail$') 'generated remote payload includes strict bash preamble'
foreach ($file in $shellFiles) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    Assert-True (-not $text.Contains("`r")) "$($file.Name) uses LF"
    Assert-True ($text -notmatch '(?m)^\s*set\s+-[^\n]*x') "$($file.Name) does not enable xtrace"
    Assert-True ($text -notmatch 'nft\s+list\s+ruleset\s*\|\s*grep\s+-[^\s]*q') "$($file.Name) avoids pipefail plus grep-q SIGPIPE checks"
    Assert-True ($text -notmatch '(?m)^[^#\n]+\|\s*grep\s+-[^\s]*q') "$($file.Name) avoids pipefail plus early-exit grep-q pipelines"
    if ($bash) {
        & $bash -n $file.FullName
        Assert-True ($LASTEXITCODE -eq 0) "$($file.Name) bash -n"
    }
}
if (-not $bash) { Write-Warning 'Bash not found; bash -n was skipped.' }

Write-Host '== Offline dry run ==' -ForegroundColor Cyan
$dryRunArchive = Join-Path $ProjectRoot 'DRY-RUN-SENTINEL-SHOULD-NOT-EXIST'
if (Test-Path -LiteralPath $dryRunArchive) { throw "Dry-run sentinel path already exists: $dryRunArchive" }
Push-Location $ProjectRoot
try {
    Start-VpsDeploy -ProjectRoot $ProjectRoot -Mode Resume `
        -PlanPath (Join-Path $ProjectRoot 'tests\fixtures\dry-run-plan.json') -DryRun -NonInteractive
}
finally {
    Pop-Location
}
Assert-True (-not (Test-Path -LiteralPath $dryRunArchive)) 'dry run creates no instance data'

$landingDryRunArchive = Join-Path $ProjectRoot 'DRY-RUN-LANDING-SENTINEL-SHOULD-NOT-EXIST'
if (Test-Path -LiteralPath $landingDryRunArchive) { throw "Dry-run sentinel path already exists: $landingDryRunArchive" }
Push-Location $ProjectRoot
try {
    Start-VpsDeploy -ProjectRoot $ProjectRoot -Mode Resume `
        -PlanPath (Join-Path $ProjectRoot 'tests\fixtures\dry-run-landing-plan.json') -DryRun -NonInteractive
}
finally {
    Pop-Location
}
Assert-True (-not (Test-Path -LiteralPath $landingDryRunArchive)) 'landing dry run creates no instance data'

foreach ($case in @(
        @{ Name = 'anytls'; Fixture = 'dry-run-anytls-plan.json'; Sentinel = 'DRY-RUN-ANYTLS-SENTINEL-SHOULD-NOT-EXIST' },
        @{ Name = 'local Reality'; Fixture = 'dry-run-local-reality-plan.json'; Sentinel = 'DRY-RUN-LOCAL-REALITY-SENTINEL-SHOULD-NOT-EXIST' }
    )) {
    $sentinel = Join-Path $ProjectRoot $case.Sentinel
    if (Test-Path -LiteralPath $sentinel) { throw "Dry-run sentinel path already exists: $sentinel" }
    Push-Location $ProjectRoot
    try {
        Start-VpsDeploy -ProjectRoot $ProjectRoot -Mode Resume `
            -PlanPath (Join-Path $ProjectRoot (Join-Path 'tests\fixtures' $case.Fixture)) -DryRun -NonInteractive
    }
    finally { Pop-Location }
    Assert-True (-not (Test-Path -LiteralPath $sentinel)) "$($case.Name) dry run creates no instance data"
}

Write-Host '== Interactive wizard back navigation ==' -ForegroundColor Cyan
$wizardInstanceRoot = Join-Path $ProjectRoot '.test-output\wizard-instance-root'
$wizardArchive = Join-Path $wizardInstanceRoot 'ExampleProvider\RevisedInstance'
if (Test-Path -LiteralPath $wizardArchive) { throw "Wizard dry-run archive already exists: $wizardArchive" }
$wizardInputLines = @(
    '',                  # accept the visible archive-root default
    'ExampleProvider',
    'OriginalInstance',
    '0',                 # return from node name to instance name
    'RevisedInstance',
    '',                  # accept regenerated node name
    '192.0.2.60',
    '',                  # no IPv6
    '',                  # default bootstrap SSH port
    '0',                 # return from authentication menu to SSH port
    '',
    '1',                 # password bootstrap
    '4',                 # MonitorOnly
    '',                  # default admin user
    'n',                 # automatic high ports
    'n',                 # no Komari
    '0',                 # summary: return to previous active item
    'n',
    '1'                  # confirm revised summary
)
$wizardInput = ($wizardInputLines -join [Environment]::NewLine) + [Environment]::NewLine
$pwshPath = (Get-Command pwsh -ErrorAction Stop).Source
$wizardResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile',
    '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),
    '-Mode', 'New',
    '-DryRun',
    '-InstanceRoot', $wizardInstanceRoot
) -InputText $wizardInput -TimeoutSeconds 60
Assert-True ($wizardResult.ExitCode -eq 0) 'interactive wizard completes after multiple back operations'
Assert-True ($wizardResult.StdOut -match 'RevisedInstance') 'back navigation replaces the earlier instance value'
Assert-True ($wizardResult.StdOut -match 'bootstrap-port' -and $wizardResult.StdOut -match 'komari-enabled') 'text, numbered menu, and summary back paths are exercised'
Assert-True (-not (Test-Path -LiteralPath $wizardArchive)) 'interactive wizard dry run writes no plan or archive'

$reuseWizardRoot = Join-Path $ProjectRoot '.test-output\wizard-existing-key-root'
$reuseWizardKey = Join-Path $ProjectRoot '.test-output\wizard-existing-provider-key'
if(Test-Path $reuseWizardRoot){[IO.Directory]::Delete($reuseWizardRoot,$true)}
foreach($item in @($reuseWizardKey,($reuseWizardKey+'.pub'))){if(Test-Path $item){Remove-Item $item -Force}}
$reuseKeygen=Invoke-VpsProcess (Get-Command ssh-keygen.exe).Source @('-t','ed25519','-N','','-C','provider-reuse-wizard','-f',$reuseWizardKey) -TimeoutSeconds 60
Assert-True ($reuseKeygen.ExitCode -eq 0) 'existing-key wizard fixture key generated'
$reuseWizardInput=(@('', 'ExampleProvider','ReuseExistingInstance','','192.0.2.63','','','2',$reuseWizardKey,'1','4','','n','n','1')-join[Environment]::NewLine)+[Environment]::NewLine
$reuseWizardResult=Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile','-File',(Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),'-Mode','New','-DryRun','-InstanceRoot',$reuseWizardRoot
) -InputText $reuseWizardInput -TimeoutSeconds 60
Assert-True ($reuseWizardResult.ExitCode -eq 0) 'new-deployment wizard accepts provider existing-key reuse without forcing a new public key'
Assert-True (-not(Test-Path $reuseWizardRoot)) 'existing-key New DryRun creates no instance archive'
foreach($item in @($reuseWizardKey,($reuseWizardKey+'.pub'))){if(Test-Path $item){Remove-Item $item -Force}}

$branchResetRoot = Join-Path $ProjectRoot '.test-output\wizard-branch-reset'
$branchDefaultRoot = Join-Path $ProjectRoot '.test-output\wizard-default-root'
$branchResetArchive = Join-Path $branchResetRoot 'ExampleProvider\BranchReset'
$branchInputs = @(
    $branchResetRoot, 'ExampleProvider', 'BranchReset', '', '192.0.2.61', '', '', '1', '1', '1', '', 'n',
    '1', 'target.example.com', 'y', 'y', 'n', '1000', 'n', '0',
    '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', # Komari -> role
    '4', '', 'n', 'n', '1'                   # switch to MonitorOnly and confirm
)
$branchQueue = [Collections.Generic.Queue[string]]::new()
$branchInputs | ForEach-Object { $branchQueue.Enqueue($_) }
$coreModule = Get-Module VpsDeploy.Core
$branchPlan = & $coreModule {
    param($InputQueue, $Root, $InstanceRoot)
    $script:WizardTestInputQueue = $InputQueue
    function Read-Host {
        param([string]$Prompt)
        if ($script:WizardTestInputQueue.Count -eq 0) { throw "Wizard test input exhausted at: $Prompt" }
        return $script:WizardTestInputQueue.Dequeue()
    }
    try { New-VpsInteractivePlan -ProjectRoot $Root -InstanceRoot $InstanceRoot }
    finally {
        Remove-Item Function:\Read-Host -ErrorAction SilentlyContinue
        Remove-Variable WizardTestInputQueue -Scope Script -ErrorAction SilentlyContinue
    }
} $branchQueue $ProjectRoot $branchDefaultRoot 6>$null
Assert-True ($branchPlan.Role -eq 'MonitorOnly') 'back navigation can replace a previously completed role branch'
Assert-True (-not $branchPlan.Reality.Target -and -not $branchPlan.TrustedTls.Enabled -and -not $branchPlan.AnyTls.Enabled) 'role change clears stale proxy and trusted TLS fields'
Assert-True ($branchPlan.NetworkTuning.Mode -eq 'BaselineOnly') 'role change clears stale adaptive tuning fields'
Assert-True ([string]$branchPlan.Paths.Archive -eq (Join-Path $branchResetArchive 'MXH-VPS-Deploy')) 'interactive archive root uses the instance managed-data subdirectory'
Assert-True ($branchQueue.Count -eq 0) 'branch-reset wizard consumed the expected navigation path'
Assert-True (-not (Test-Path -LiteralPath $branchResetArchive)) 'in-memory branch-reset test writes no plan or archive'

Write-Host '== Interactive navigation hierarchy ==' -ForegroundColor Cyan
$hierarchyInput = (@('clear', '1', '0', '2', '0', 'cls', '9') -join [Environment]::NewLine) + [Environment]::NewLine
$hierarchyResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'), '-Mode', 'Interactive', '-DryRun'
) -InputText $hierarchyInput -TimeoutSeconds 60
Assert-True ($hierarchyResult.ExitCode -eq 0) 'first new-deployment field and resume path both return to the main menu'
Assert-True ($hierarchyResult.StdOut -match 'MXH VPS Deploy' -and `
    [regex]::Matches($hierarchyResult.StdOut, '(?m)^0\r?$').Count -eq 2) 'interactive hierarchy consumed the sole back command in both child workflows'
Assert-True ($hierarchyResult.StdOut -notmatch '__MXH_VPS_WIZARD_' -and $hierarchyResult.StdErr -notmatch '__MXH_VPS_WIZARD_') 'navigation markers never leak to the console'
Assert-True ($hierarchyResult.StdOut -match '(?m)^clear\r?$' -and $hierarchyResult.StdOut -match '(?m)^cls\r?$') 'clear and cls are consumed by live menu navigation'

$literalProviderB = & $coreModule {
    function Read-Host { param([string]$Prompt); return 'b' }
    try { Read-VpsText '服务商名称' -AllowBack }
    finally { Remove-Item Function:\Read-Host -ErrorAction SilentlyContinue }
}
Assert-True ($literalProviderB -eq 'b') 'literal b is ordinary provider text and never a navigation alias'

$literalBackWord = & $coreModule {
    function Read-Host { param([string]$Prompt); return 'back' }
    try { Read-VpsText '普通文本' -AllowBack }
    finally { Remove-Item Function:\Read-Host -ErrorAction SilentlyContinue }
}
Assert-True ($literalBackWord -eq 'back') 'literal back is ordinary text and never a navigation alias'

$subMenuNavigation = & $coreModule {
    $script:NavigationQueue = [Collections.Generic.Queue[string]]::new()
    @('9', 'b', '0') | ForEach-Object { $script:NavigationQueue.Enqueue($_) }
    function Read-Host { param([string]$Prompt); return $script:NavigationQueue.Dequeue() }
    try { Read-VpsMenu '导航规范测试' @('执行') 1 -AllowBack }
    catch { return [pscustomobject]@{ Marker = $_.Exception.Message; Remaining = $script:NavigationQueue.Count } }
    finally {
        Remove-Item Function:\Read-Host -ErrorAction SilentlyContinue
        Remove-Variable NavigationQueue -Scope Script -ErrorAction SilentlyContinue
    }
}
Assert-True ($subMenuNavigation.Marker -eq '__MXH_VPS_WIZARD_BACK__' -and $subMenuNavigation.Remaining -eq 0) 'submenus reject 9 and b, then use only 0 to return'

$clientMenuReturnInput = (@('7', '0', '9') -join [Environment]::NewLine) + [Environment]::NewLine
$clientMenuReturnResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'), '-Mode', 'Interactive', '-DryRun'
) -InputText $clientMenuReturnInput -TimeoutSeconds 60
Assert-True ($clientMenuReturnResult.ExitCode -eq 0 -and $clientMenuReturnResult.StdOut -match '(?m)^9\r?$') 'client designer 0 returns to the main menu and only the following 9 exits'

$migrationDryRoot = Join-Path $ProjectRoot '.test-output\migration-dryrun-source'
$migrationEntryRoot = Join-Path $ProjectRoot '.test-output\migration-validation-entry'
if (Test-Path -LiteralPath $migrationDryRoot) { [IO.Directory]::Delete($migrationDryRoot, $true) }
if (Test-Path -LiteralPath $migrationEntryRoot) { [IO.Directory]::Delete($migrationEntryRoot, $true) }
[IO.Directory]::CreateDirectory($migrationDryRoot) | Out-Null
[IO.Directory]::CreateDirectory($migrationEntryRoot) | Out-Null
$migrationDryPlan = ($realitySource | ConvertTo-Json -Depth 40) | ConvertFrom-Json -AsHashtable
$migrationDryPlan.Paths.Archive = $migrationDryRoot
$migrationDryPlan.Paths.KeyDirectory = Join-Path $migrationDryRoot 'fixture-id_ed25519'
[IO.Directory]::CreateDirectory([string]$migrationDryPlan.Paths.KeyDirectory) | Out-Null
[IO.File]::WriteAllText((Join-Path $migrationDryPlan.Paths.KeyDirectory 'id_ed25519'), 'fixture-key')
[IO.File]::WriteAllText((Join-Path $migrationDryPlan.Paths.KeyDirectory 'id_ed25519.pub'), 'fixture-public-key')
$migrationDryPlanPath = Join-Path $migrationDryRoot 'deployment-plan.json'
$migrationDryState = [ordered]@{
    SchemaVersion = 1
    CurrentManagementPort = [int]$migrationDryPlan.Ports.SshPrimary
    Modules = [ordered]@{
        'ssh-transition' = & $successState
        'xray-reality' = & $successState
        'nftables-transition' = & $successState
        'final-validation' = & $successState
        'ssh-cutover' = & $successState
        'private-archive' = & $successState
    }
}
Save-VpsJson -Value $migrationDryPlan -Path $migrationDryPlanPath -Private
Save-VpsJson -Value $migrationDryState -Path (Join-Path $migrationDryRoot 'deployment-state.json') -Private
Save-VpsJson -Value $migrationSourceSecrets -Path (Join-Path $migrationDryRoot 'deployment-secrets.private.json') -Private
$migrationEntryPlan = ($realitySource | ConvertTo-Json -Depth 40) | ConvertFrom-Json -AsHashtable
$migrationEntryPlan.Server.IPv4 = '192.0.2.70'
$migrationEntryPlan.Paths.Archive = $migrationEntryRoot
$migrationEntryPlan.Paths.KeyDirectory = Join-Path $migrationEntryRoot 'fixture-managed-key'
$migrationEntryPlan.SshKey = [ordered]@{ ManagedFileName = 'id_vps_management'; Mode = 'ReuseExisting' }
[IO.Directory]::CreateDirectory([string]$migrationEntryPlan.Paths.KeyDirectory) | Out-Null
[IO.File]::WriteAllText((Join-Path $migrationEntryPlan.Paths.KeyDirectory 'id_vps_management'), 'fixture-key')
[IO.File]::WriteAllText((Join-Path $migrationEntryPlan.Paths.KeyDirectory 'id_vps_management.pub'), 'fixture-public-key')
$migrationEntryPlanPath = Join-Path $migrationEntryRoot 'deployment-plan.json'
$migrationEntryState = [ordered]@{
    SchemaVersion = 1
    CurrentManagementPort = [int]$migrationEntryPlan.Ports.SshPrimary
    Audit = [ordered]@{ Architecture = 'x86_64' }
    Modules = [ordered]@{
        'xray-reality' = & $successState
        'final-validation' = & $successState
        'ssh-cutover' = & $successState
    }
}
Save-VpsJson -Value $migrationEntryPlan -Path $migrationEntryPlanPath -Private
Save-VpsJson -Value $migrationEntryState -Path (Join-Path $migrationEntryRoot 'deployment-state.json') -Private
Save-VpsJson -Value $migrationSourceSecrets -Path (Join-Path $migrationEntryRoot 'deployment-secrets.private.json') -Private
$migrationDryInput = (@('1', '1', '2', '', '192.0.2.70', '', $migrationEntryPlanPath, 'n', 'n', '1') -join [Environment]::NewLine) + [Environment]::NewLine
$migrationDryResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),
    '-Mode', 'Migrate', '-DryRun', '-PlanPath', $migrationDryPlanPath
) -InputText $migrationDryInput -TimeoutSeconds 60
Assert-True ($migrationDryResult.ExitCode -eq 0) 'existing Reality plan can enter Shadowsocks migration DryRun'
foreach ($expectedId in @('migration-preflight', 'migration-arm-rollback', 'sing-box-shadowsocks', 'migration-shadowsocks-probe', 'migration-commit')) {
    Assert-True ($migrationDryResult.StdOut -match [regex]::Escape($expectedId)) "migration DryRun displays $expectedId"
}
Assert-True ($migrationDryResult.StdOut -notmatch '(?m)\sbootstrap-access\s' -and $migrationDryResult.StdOut -notmatch '(?m)\sxray-reality\s') 'migration DryRun excludes clean-install and source protocol modules'
[IO.Directory]::Delete($migrationDryRoot, $true)
[IO.Directory]::Delete($migrationEntryRoot, $true)

function New-TestMigrationSourceFixture {
    param(
        [Collections.IDictionary]$Template,
        [string]$Root,
        [string]$ProtocolModule
    )
    if (Test-Path -LiteralPath $Root) { [IO.Directory]::Delete($Root, $true) }
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $plan = ($Template | ConvertTo-Json -Depth 40) | ConvertFrom-Json -AsHashtable
    $plan.Paths.Archive = $Root
    $plan.Paths.KeyDirectory = Join-Path $Root 'fixture-id_ed25519'
    [IO.Directory]::CreateDirectory([string]$plan.Paths.KeyDirectory) | Out-Null
    [IO.File]::WriteAllText((Join-Path $plan.Paths.KeyDirectory 'id_ed25519'), 'fixture-key')
    [IO.File]::WriteAllText((Join-Path $plan.Paths.KeyDirectory 'id_ed25519.pub'), 'fixture-public-key')
    $planPath = Join-Path $Root 'deployment-plan.json'
    $state = [ordered]@{
        SchemaVersion = 1
        CurrentManagementPort = [int]$plan.Ports.SshPrimary
        Audit = [ordered]@{ OsId = 'debian'; OsVersion = '12'; Architecture = 'x86_64' }
        Modules = [ordered]@{
            'ssh-transition' = & $successState
            $ProtocolModule = & $successState
            'nftables-transition' = & $successState
            'final-validation' = & $successState
            'ssh-cutover' = & $successState
            'private-archive' = & $successState
        }
    }
    Save-VpsJson -Value $plan -Path $planPath -Private
    Save-VpsJson -Value $state -Path (Join-Path $Root 'deployment-state.json') -Private
    Save-VpsJson -Value $migrationSourceSecrets -Path (Join-Path $Root 'deployment-secrets.private.json') -Private
    return $planPath
}

Write-Host '== Maintenance center dry-run and client candidate engine ==' -ForegroundColor Cyan
$maintenanceFunctions = @(
    'Invoke-MxhMaintenanceCenter','Invoke-MxhManualRestoreCenter','Get-MxhHealthAudit','Invoke-MxhCredentialRotation',
    'Invoke-MxhSshMaintenance','Invoke-MxhFirewallMaintenance','Invoke-MxhControlledUpgrade',
    'Invoke-MxhClientCandidateMerge','Invoke-MxhKomariLifecycle','Invoke-MxhDecommission'
)
foreach ($name in $maintenanceFunctions) {
    $exists = & $coreModule { param($n) [bool](Get-Command $n -ErrorAction SilentlyContinue) } $name
    Assert-True $exists "maintenance function exists: $name"
}
$operationsSource = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'src\VpsDeploy.Operations.ps1')
Assert-True ($operationsSource -match '\$Context\.Plan\.AnyTls\.SingBoxVersion=\[string\]\$Context\.Versions\.sing_box\.version' -and $operationsSource -match '\$Context\.Plan\.Shadowsocks\.SingBoxVersion=\[string\]\$Context\.Versions\.sing_box\.version') 'controlled upgrades persist the exact sing-box version paired with the installed asset'
Assert-True ($operationsSource -match 'foreach\(\$directory in @\(''client-exports'',''server-configs''\)\)' -and $operationsSource -match 'Remove-Item \$current -Recurse -Force' -and $operationsSource -match 'Copy-Item \$source \$current -Recurse') 'failed maintenance rollback restores generated client and server configuration directories with the state files'
$healthAuditFixture = [ordered]@{
    SchemaVersion=1;CollectedAt='2026-01-01T00:00:00Z';Ssh=[ordered]@{Valid=$true;Ports=@([int]$realitySource.Ports.SshPrimary,[int]$realitySource.Ports.SshRescue);PasswordAuthentication='no';KbdInteractiveAuthentication='no';PubkeyAuthentication='yes';PermitRootLogin='prohibit-password'}
    Services=[ordered]@{
        RealityEntry=[ordered]@{Installed=$true;Enabled=$true;Active=$true}
        AnyTlsEntry=[ordered]@{Installed=$false;Enabled=$false;Active=$false}
        ShadowsocksLanding=[ordered]@{Installed=$false;Enabled=$false;Active=$false}
        KomariAgent=[ordered]@{Installed=$false;Enabled=$false;Active=$false}
        KomariController=[ordered]@{Installed=$false;Enabled=$false;Active=$false}
        Cloudflared=[ordered]@{Installed=$false;Enabled=$false;Active=$false}
    }
    Versions=[ordered]@{Xray='Xray 26.3.27';SingBoxAnyTls=$null;SingBox=$null;KomariAgent=$null}
    Hashes=[ordered]@{Xray=$null;Nftables='same'}
    Nftables=[ordered]@{Present=$true;Valid=$true};Certificate=[ordered]@{Present=$false;DaysRemaining=$null}
    Timers=[ordered]@{RollbackActive=$false;CertbotRenewEnabled=$false}
}
$healthPayload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($healthAuditFixture|ConvertTo-Json -Compress -Depth 20)))
$healthContext=[pscustomobject]@{Plan=$realitySource;State=[ordered]@{Modules=@{};KomariInstalled=$false;HealthBaseline=[ordered]@{Hashes=[ordered]@{Xray='old-hash';Nftables='same'}}};DryRun=$false}
$healthReport=& $coreModule {param($c,$payload) function Invoke-VpsRemoteScript{return [pscustomobject]@{StdOut="VPSDEPLOY_HEALTH_AUDIT_B64=$payload`nVPSDEPLOY_HEALTH_AUDIT_OK`n"}};try{Get-MxhHealthAudit $c}finally{Remove-Item Function:\Invoke-VpsRemoteScript -ErrorAction SilentlyContinue}} $healthContext $healthPayload
Assert-True ('CONFIG_HASH_DRIFT' -in @($healthReport.Findings.Code)) 'health drift detects deletion of a previously baselined managed file'
$healthAuditFixture.Timers.RollbackActive=$true
$activeRollbackPayload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($healthAuditFixture|ConvertTo-Json -Compress -Depth 20)))
$restoreAudit=& $coreModule {param($c,$payload) function Invoke-VpsRemoteScript{return [pscustomobject]@{StdOut="VPSDEPLOY_HEALTH_AUDIT_B64=$payload`nVPSDEPLOY_HEALTH_AUDIT_OK`n"}};try{Get-MxhHealthAudit $c -IgnoreActiveRollbackTimer}finally{Remove-Item Function:\Invoke-VpsRemoteScript -ErrorAction SilentlyContinue}} $healthContext $activeRollbackPayload
Assert-True ('ROLLBACK_TIMER_ACTIVE' -notin @($restoreAudit.Findings.Code)) 'manual restore validation can ignore its own expected rollback timer'
$healthAuditFixture.Timers.RollbackActive=$false
$healthPolicyResults=& $coreModule {
    param($c,$audit)
    $c.Plan=Copy-MxhHashtable $c.Plan
    $c.Plan.Import=@{SshAuthenticationPreserved=$true}
    $audit.Ssh.PasswordAuthentication='yes'
    function Invoke-VpsRemoteScript { [pscustomobject]@{StdOut=('VPSDEPLOY_HEALTH_AUDIT_B64='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($audit|ConvertTo-Json -Depth 20 -Compress))))} }
    $preserved=Get-MxhHealthAudit $c
    $c.Plan.Import.SshAuthenticationPreserved=$false
    $enforced=Get-MxhHealthAudit $c
    $c.Plan.Import.SshAuthenticationPreserved=$true
    $audit.Ssh.PubkeyAuthentication='no'
    $disabled=Get-MxhHealthAudit $c
    @('SSH_NOT_KEY_ONLY' -notin @($preserved.Findings.Code);'SSH_NOT_KEY_ONLY' -in @($enforced.Findings.Code);'SSH_PUBKEY_DISABLED' -in @($disabled.Findings.Code))
} ([pscustomobject]@{Plan=$realitySource;State=$healthContext.State;DryRun=$false}) ($healthAuditFixture|ConvertTo-Json -Depth 20|ConvertFrom-Json -AsHashtable)
foreach($result in $healthPolicyResults){Assert-True $result 'health audit respects preserved authentication but requires public-key access'}
$recoveryResults=& $coreModule {
    function Invoke-VpsRemoteScript {param($Context,$Asset,$Parameters)
        if(-not $Parameters.ContainsKey('EXPECTED_BACKUP')){throw 'Recovery lost the recorded backup identity'}
        [pscustomobject]@{StdOut='VPSDEPLOY_TRANSACTION_PHASE_B64=Um9sbGVkQmFjaw=='}
    }
    function Undo-MxhMaintenanceTransaction {param($Context,$Reason) $Context.State.Reconciled=$true}
    foreach($phase in @('LocalPrepared','Started')){
        $c=[pscustomobject]@{DryRun=$false;ArchivePath=(Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString()));State=@{MaintenanceTransaction=@{Phase=$phase;Committed=$false;RemoteBackup='/root/vps-deploy-backups/20260910-010101/protocol-lifecycle'}}}
        $blocked=$false
        try{Assert-MxhNoPendingLocalTransaction $c}catch{$blocked=$true}
        Invoke-MxhTransactionRecovery $c
        $blocked -and $c.State.Reconciled
    }
}
foreach($result in $recoveryResults){Assert-True $result 'automatic rollback reconciles local metadata and pending state blocks new maintenance'}
$restorePortResults=& $coreModule {
    param($plan)
    $plan=Copy-MxhHashtable $plan
    $c=[pscustomobject]@{Plan=$plan;State=@{Modules=@{}};Secrets=@{Xray=@{Fixture='secret'}}}
    $backup=Copy-MxhHashtable $plan
    $valid=New-MxhRestoreMetadata $c $backup $c.State $c.Secrets Full
    $backup.Ports.SshPrimary=34567
    $blocked=$false
    try{New-MxhRestoreMetadata $c $backup $c.State $c.Secrets Full|Out-Null}catch{$blocked=$_.Exception.Message -match '旧 SSH 端口'}
    @($valid.Plan.Ports.SshPrimary -eq $plan.Ports.SshPrimary;$blocked)
} $realitySource
foreach($result in $restorePortResults){Assert-True $result 'full restore accepts matching SSH ports and rejects historical firewall after port changes'}
$inactiveUpgradeBlocked=& $coreModule {
    function Get-MxhProtocolInventory { @{RealityEntry=@{Installed=$true;Active=$false};AnyTlsEntry=@{Installed=$false};ShadowsocksLanding=@{Installed=$false}} }
    function Read-VpsMenu {1}
    function Start-MxhMaintenanceTransaction {throw 'UNEXPECTED_REMOTE_MUTATION'}
    $c=[pscustomobject]@{Plan=@{};State=@{}}
    try{Invoke-MxhControlledUpgrade $c;return $false}catch{return $_.Exception.Message -match '停用备用状态'}
}
Assert-True $inactiveUpgradeBlocked 'inactive protocol upgrade is rejected before any transaction or remote mutation'
Assert-True ($operationsSource -match 'Get-MxhHealthAudit \$Context -IgnoreActiveRollbackTimer') 'manual restore validates against the selected restore-point context without flagging its own transaction timer'
Assert-True ($operationsSource -match '\$Context\.Plan=Read-VpsJsonHashtable \$Context\.PlanPath' -and $operationsSource -match '\$Context\.State=Read-VpsJsonHashtable \$Context\.StatePath') 'manual restore reloads in-memory plan and state after restoring local metadata'
Assert-True ($operationsSource -match 'foreach\(\$directory in @\(''client-exports'',''server-configs''\)\)') 'manual restore restores generated client and server directories together with metadata'
Assert-True ((Get-Content -Raw (Join-Path $ProjectRoot 'assets\remote\existing-vps-import-audit.sh')) -match 'Password.*PublicKey') 'existing import parser recognizes Xray 26.3.27 Password (PublicKey) label'
$maintenanceRoot = Join-Path $ProjectRoot '.test-output\maintenance-center-dryrun'
$maintenancePlan = New-TestMigrationSourceFixture -Template $realitySource -Root $maintenanceRoot -ProtocolModule 'xray-reality'
$maintenanceInput = (@('1','2','n') -join [Environment]::NewLine) + [Environment]::NewLine
$maintenanceResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile','-File',(Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),'-Mode','Maintain','-DryRun','-PlanPath',$maintenancePlan
) -InputText $maintenanceInput -TimeoutSeconds 60
Assert-True ($maintenanceResult.ExitCode -eq 0) 'maintenance center health audit DryRun exits cleanly'
Assert-True ($maintenanceResult.StdOut -match 'DryRun') 'maintenance center routes to read-only health audit'
$maintenanceBackInput = (@('1','9','0','0') -join [Environment]::NewLine) + [Environment]::NewLine
$maintenanceBackResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile','-File',(Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),'-Mode','Maintain','-DryRun','-PlanPath',$maintenancePlan
) -InputText $maintenanceBackInput -TimeoutSeconds 60
$maintenanceMenuCount = ([regex]::Matches($maintenanceBackResult.StdOut, '(?m)^\s*10\.')).Count
Assert-True ($maintenanceBackResult.ExitCode -eq 0) 'maintenance submenu back navigation exits cleanly after returning to the maintenance menu'
Assert-True ($maintenanceMenuCount -eq 2) 'maintenance submenu 0 redraws the maintenance center directly instead of reselecting the instance'

$candidateRoot = Join-Path $maintenanceRoot 'candidate-fixture'
$fragmentRoot = Join-Path $candidateRoot 'fragments'
$outputRoot = Join-Path $candidateRoot 'output'
[IO.Directory]::CreateDirectory($fragmentRoot) | Out-Null
$authorityYaml = Join-Path $candidateRoot 'authority.yaml'
$authorityJson = Join-Path $candidateRoot 'authority.json'
[IO.File]::WriteAllText($authorityYaml, @"
proxies:
  - name: Existing-IPv4
    type: vless
    server: 192.0.2.9
proxy-groups:
  - name: US-West-LA Entry
    type: select
    proxies:
      - Existing-IPv4
  - name: Europe Entry
    type: select
    proxies:
      - Existing-IPv4
rules:
  - MATCH,US-West-LA Entry
"@)
[IO.File]::WriteAllText((Join-Path $fragmentRoot 'mihomo-test-primary.yaml'), @"
proxies:
  - name: Candidate-IPv4
    type: vless
    server: 192.0.2.1
proxy-groups: []
rules: []
"@)
Save-VpsJson -Value ([ordered]@{ outbounds=@([ordered]@{type='vless';tag='Candidate-IPv4';server='192.0.2.1'}) }) -Path (Join-Path $fragmentRoot 'sing-box-outbounds.private.json')
Save-VpsJson -Value ([ordered]@{ outbounds=@(
        [ordered]@{type='vless';tag='Existing-IPv4';server='192.0.2.9'},[ordered]@{type='direct';tag='DIRECT'},[ordered]@{type='block';tag='BLOCK'},
        [ordered]@{type='selector';tag='US-West-LA Entry';outbounds=@('Existing-IPv4')},
        [ordered]@{type='selector';tag='Europe Entry';outbounds=@('Existing-IPv4')}
    ); route=[ordered]@{rules=@()} }) -Path $authorityJson
$pythonCommandForClient = Get-Command python.exe -ErrorAction SilentlyContinue
$clientBuilderAvailable = $false
if ($pythonCommandForClient) {
    $dependencyProbe = Invoke-VpsProcess -FilePath $pythonCommandForClient.Source -ArgumentList @('-c','import ruamel.yaml') -TimeoutSeconds 30
    $clientBuilderAvailable = $dependencyProbe.ExitCode -eq 0
}
if ($clientBuilderAvailable) {
$python = $pythonCommandForClient.Source
$merge = Invoke-VpsProcess -FilePath $python -ArgumentList @(
    (Join-Path $ProjectRoot 'scripts\merge_client_authority.py'),'--clash',$authorityYaml,'--sing-box',$authorityJson,
    '--fragments',$fragmentRoot,'--output',$outputRoot,'--roles','RealityEntry','--entry-group','US-West-LA Entry'
) -TimeoutSeconds 60
Assert-True ($merge.ExitCode -eq 0) 'client authority candidate merge fixture succeeds'
$mergedJson = Get-Content -Raw (Join-Path $outputRoot 'sing-box-general.candidate.json') | ConvertFrom-Json -AsHashtable
Assert-True ((Get-Item (Join-Path $outputRoot 'sing-box-general.candidate.json')).Length -lt 4MB) 'legacy candidate merger keeps runtime JSON below the desktop IPC ceiling'
Assert-True ('Candidate-IPv4' -in @($mergedJson.outbounds.tag)) 'candidate merge adds sing-box outbound'
Assert-True ('Candidate-IPv4' -in @((@($mergedJson.outbounds | Where-Object tag -eq 'US-West-LA Entry')[0]).outbounds)) 'candidate merge updates selected sing-box entry selector'
$removeRoot = Join-Path $candidateRoot 'remove-output'
$remove = Invoke-VpsProcess -FilePath $python -ArgumentList @(
    (Join-Path $ProjectRoot 'scripts\merge_client_authority.py'),'--clash',(Join-Path $outputRoot 'Clash_General.candidate.yaml'),
    '--sing-box',(Join-Path $outputRoot 'sing-box-general.candidate.json'),'--fragments',$fragmentRoot,'--output',$removeRoot,
    '--roles','','--remove-prefix','Candidate'
) -TimeoutSeconds 60
Assert-True ($remove.ExitCode -eq 0) 'decommission candidate removal fixture succeeds'
$removedJson = Get-Content -Raw (Join-Path $removeRoot 'sing-box-general.candidate.json') | ConvertFrom-Json -AsHashtable
Assert-True ('Candidate-IPv4' -notin @($removedJson.outbounds.tag)) 'decommission candidate removes matching sing-box outbound'

$designerOutput = Join-Path $candidateRoot 'designer-output'
$designerSpec = Join-Path $candidateRoot 'designer-spec.private.json'
$manualLanding = [ordered]@{
    name='Example Exit A IPv4';kind='landing';region_group=$null;transit_group='US-West-LA Entry'
    clash=[ordered]@{name='Example Exit A IPv4';type='ss';server='192.0.2.2';port=34567;cipher='2022-blake3-aes-128-gcm';password='fixture';udp=$true;'dialer-proxy'='US-West-LA Entry'}
    sing_box=[ordered]@{type='shadowsocks';tag='Example Exit A IPv4';server='192.0.2.2';server_port=34567;method='2022-blake3-aes-128-gcm';password='fixture';detour='US-West-LA Entry'}
}
$designerSpecValue = [ordered]@{
    schema_version=1
    fragment_sources=@([ordered]@{fragment_dir=$fragmentRoot;role='RealityEntry';node_names=@('Candidate-IPv4');region_group='US-West-LA Entry';transit_group=$null})
    manual_nodes=@($manualLanding)
    existing_node_refs=@([ordered]@{name='Existing-IPv4';kind='entry';region_group='US-West-LA Entry';transit_group=$null})
    groups=@(
        [ordered]@{name='US-West-LA Entry';members=@('Candidate-IPv4','Existing-IPv4')},
        [ordered]@{name='Default Exit';members=@('Example Exit A IPv4','US-West-LA Entry','DIRECT')},
        [ordered]@{name='Direct Route';members=@('DIRECT','Default Exit')},
        [ordered]@{name='AI Services';members=@('Default Exit','US-West-LA Entry','Example Exit A IPv4','Direct Route')}
    )
    remove_groups=@('Europe Entry')
    group_order=@('US-West-LA Entry','Default Exit','Direct Route','AI Services')
}
Save-VpsJson -Value $designerSpecValue -Path $designerSpec -Private
$designer = Invoke-VpsProcess -FilePath $python -ArgumentList @(
    (Join-Path $ProjectRoot 'scripts\build_client_authority.py'),'--clash',$authorityYaml,'--sing-box',$authorityJson,
    '--spec',$designerSpec,'--output',$designerOutput
) -TimeoutSeconds 60
Assert-True ($designer.ExitCode -eq 0) 'independent client authority designer builds a candidate from managed and manual nodes'
$designerJson = Get-Content -Raw (Join-Path $designerOutput 'sing-box-general.candidate.json') | ConvertFrom-Json -AsHashtable
Assert-True ((Get-Item (Join-Path $designerOutput 'sing-box-general.candidate.json')).Length -lt 4MB) 'independent designer emits compact sing-box runtime JSON'
$designerEntry = @($designerJson.outbounds | Where-Object tag -eq 'US-West-LA Entry')[0]
$designerLanding = @($designerJson.outbounds | Where-Object tag -eq 'Example Exit A IPv4')[0]
Assert-True (@($designerEntry.outbounds)[0] -eq 'Candidate-IPv4') 'regional entry order controls the selector first default'
Assert-True ('Existing-IPv4' -in @($designerEntry.outbounds)) 'existing authority node can be reused without re-entering credentials'
Assert-True ($designerLanding.detour -eq 'US-West-LA Entry') 'landing detour follows the chosen regional entry group'
Assert-True ((@($designerJson.outbounds | Where-Object tag -eq 'Default Exit')[0]).default -eq 'Example Exit A IPv4') 'default exit first member is written as sing-box selector default'
Assert-True (-not @($designerJson.outbounds | Where-Object tag -eq 'Europe Entry').Count) 'disabled default region group is removed from the candidate'
$designerYamlText = Get-Content -Raw (Join-Path $designerOutput 'Clash_General.candidate.yaml')
Assert-True ($designerYamlText -match 'dialer-proxy:\s+US-West-LA Entry') 'Clash landing node receives the matching dialer-proxy'
$genericOutput=Join-Path $candidateRoot 'generic-template-output'
$genericSpecPath=Join-Path $candidateRoot 'generic-template-spec.private.json'
$genericLayout=Get-Content -Raw (Join-Path $ProjectRoot 'config\client-layout.default.json')|ConvertFrom-Json -AsHashtable
$genericNode=[ordered]@{name='Portable-Entry';kind='entry';region_group='US-West-LA Entry';transit_group=$null;clash=[ordered]@{name='Portable-Entry';type='vless';server='192.0.2.80';port=443;uuid='fixture';network='tcp';tls=$true;servername='target.example.invalid';flow='xtls-rprx-vision';'client-fingerprint'='chrome';'reality-opts'=[ordered]@{'public-key'='fixture';'short-id'='0123456789abcdef'}};sing_box=[ordered]@{type='vless';tag='Portable-Entry';server='192.0.2.80';server_port=443;uuid='fixture';flow='xtls-rprx-vision';tls=[ordered]@{enabled=$true;server_name='target.example.invalid';reality=[ordered]@{enabled=$true;public_key='fixture';short_id='0123456789abcdef'}}}}
$genericGroups=[Collections.Generic.List[object]]::new();$genericGroups.Add([ordered]@{name='US-West-LA Entry';members=@('Portable-Entry')});$genericGroups.Add([ordered]@{name='Default Exit';members=@('US-West-LA Entry','DIRECT')});$genericGroups.Add([ordered]@{name='Direct Route';members=@('DIRECT','Default Exit')})
foreach($definition in $genericLayout.business_groups){$genericGroups.Add([ordered]@{name=[string]$definition.name;members=@([string]$definition.default,'US-West-LA Entry','Direct Route')|Select-Object -Unique})}
foreach($guard in $genericLayout.guard_groups){$genericGroups.Add([ordered]@{name=[string]$guard.name;members=@($guard.members|Where-Object{$_ -notin @('Hong Kong Entry','Europe Entry')})})}
$genericSpec=[ordered]@{schema_version=1;source_mode='GenericTemplate';output_mode='GenerateNew';fragment_sources=@();manual_nodes=@($genericNode);existing_node_refs=@();groups=@($genericGroups);remove_groups=@('US-West-SF Entry','Hong Kong Entry','Europe Entry');group_order=@('US-West-LA Entry','Default Exit','Direct Route')+@($genericLayout.business_groups.name)+@($genericLayout.guard_groups.name)}
Save-VpsJson -Value $genericSpec -Path $genericSpecPath -Private
$genericBuild=Invoke-VpsProcess -FilePath $python -ArgumentList @((Join-Path $ProjectRoot 'scripts\build_client_authority.py'),'--clash',(Join-Path $ProjectRoot 'templates\client\clash-general.template.yaml'),'--sing-box',(Join-Path $ProjectRoot 'templates\client\sing-box-general.template.json'),'--spec',$genericSpecPath,'--output',$genericOutput) -TimeoutSeconds 60
Assert-True ($genericBuild.ExitCode -eq 0) 'generic project templates build a complete candidate without personal authority files'
$genericManifest=Get-Content -Raw (Join-Path $genericOutput 'candidate-manifest.json')|ConvertFrom-Json -AsHashtable
Assert-True ([string]$genericManifest.source_mode -eq 'GenericTemplate' -and [string]$genericManifest.requested_output_mode -eq 'GenerateNew') 'candidate manifest records source and requested output modes'
$publishRoot=Join-Path $candidateRoot 'atomic-publish';[IO.Directory]::CreateDirectory($publishRoot)|Out-Null
$targetClash=Join-Path $publishRoot 'authority.yaml';$targetSing=Join-Path $publishRoot 'authority.json';[IO.File]::WriteAllText($targetClash,'old-clash');[IO.File]::WriteAllText($targetSing,'old-sing')
$backupRoot=Join-Path $publishRoot 'backups\fixture'
& $coreModule {param($cc,$cs,$tc,$ts,$br)Publish-MxhAuthorityPair -CandidateClash $cc -CandidateSingBox $cs -TargetClash $tc -TargetSingBox $ts -BackupRoot $br} (Join-Path $genericOutput 'Clash_General.candidate.yaml') (Join-Path $genericOutput 'sing-box-general.candidate.json') $targetClash $targetSing $backupRoot|Out-Null
Assert-True ((Get-Content -Raw $targetClash)-match 'Portable-Entry' -and (Get-Content -Raw $targetSing)-match 'Portable-Entry') 'validated authority pair publishes to both selected targets'
$publishJournal=Get-Content -Raw (Join-Path $backupRoot 'publish.private.json') | ConvertFrom-Json -AsHashtable
Assert-True ((Get-Content -Raw $publishJournal.ClashBackup)-eq'old-clash' -and (Get-Content -Raw $publishJournal.SingBackup)-eq'old-sing') 'authority overwrite preserves uniquely named rollback copies recorded in journal'
$cycleSpec = Get-Content -Raw -LiteralPath $designerSpec | ConvertFrom-Json -AsHashtable
$cycleSpec.groups = @([ordered]@{name='Cycle A';members=@('Cycle B')},[ordered]@{name='Cycle B';members=@('Cycle A')})
$cyclePath = Join-Path $candidateRoot 'cycle-spec.private.json'; Save-VpsJson -Value $cycleSpec -Path $cyclePath -Private
$cycle = Invoke-VpsProcess -FilePath $python -ArgumentList @(
    (Join-Path $ProjectRoot 'scripts\build_client_authority.py'),'--clash',$authorityYaml,'--sing-box',$authorityJson,
    '--spec',$cyclePath,'--output',(Join-Path $candidateRoot 'cycle-output')
) -TimeoutSeconds 60
Assert-True ($cycle.ExitCode -ne 0 -and $cycle.StdErr -match 'cycle') 'client authority designer rejects selector cycles before writing candidates'

$designerInstanceRoot = Join-Path $candidateRoot 'empty-instances'; [IO.Directory]::CreateDirectory($designerInstanceRoot)|Out-Null
$designerDryOutput = Join-Path $candidateRoot 'dry-output-root'
$designerDryInput = (@(
    '6','n','US-West-LA Entry','2',$authorityYaml,$authorityJson,'n','1','1','Existing-IPv4','US-West-LA Entry,DIRECT','n','2',$designerDryOutput,$designerDryOutput,'Clash_General.yaml','sing-box-general.json'
) -join [Environment]::NewLine) + [Environment]::NewLine
$designerDry = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile','-File',(Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),'-Mode','ClientConfig','-DryRun','-InstanceRoot',$designerInstanceRoot
) -InputText $designerDryInput -TimeoutSeconds 60
Assert-True ($designerDry.ExitCode -eq 0) 'independent ClientConfig mode completes a no-write DryRun without any managed VPS'
Assert-True ($designerDry.StdOut -match 'Existing-IPv4' -and $designerDry.StdOut -match 'DryRun') 'ClientConfig can optionally reuse an existing authority node without re-entering credentials'
Assert-True (-not(Test-Path -LiteralPath $designerDryOutput)) 'ClientConfig DryRun writes no candidate directory'
}
else {
    Write-Host 'Client authority engine tests skipped: optional pinned ruamel.yaml dependency is not installed.' -ForegroundColor Yellow
    Assert-True (Test-Path -LiteralPath (Join-Path $ProjectRoot 'requirements-client-merge.txt')) 'optional client designer dependency manifest exists'
    Assert-True (Test-Path -LiteralPath (Join-Path $ProjectRoot 'scripts\build_client_authority.py')) 'client designer remains discoverable when optional runtime is absent'
}
[IO.Directory]::Delete($maintenanceRoot, $true)

$backupCleanupRoot = Join-Path $ProjectRoot '.test-output\protocol-backup-cleanup-dryrun'
$backupCleanupPlan = New-TestMigrationSourceFixture -Template $realitySource -Root $backupCleanupRoot -ProtocolModule 'xray-reality'
$backupCleanupCandidate = Join-Path $backupCleanupRoot 'migration-backups\20260101-000000-Enable-RealityEntry'
[IO.Directory]::CreateDirectory($backupCleanupCandidate) | Out-Null
[IO.File]::WriteAllText((Join-Path $backupCleanupCandidate 'deployment-plan.json'), 'fixture')
$backupCleanupInput = (@('1', '5', '1', '0', 'DELETE-BACKUPS', '0', '2') -join [Environment]::NewLine) + [Environment]::NewLine
$backupCleanupResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),
    '-Mode', 'Migrate', '-DryRun', '-PlanPath', $backupCleanupPlan
) -InputText $backupCleanupInput -TimeoutSeconds 60
Assert-True ($backupCleanupResult.ExitCode -eq 0) 'protocol backup cleanup DryRun exits cleanly'
Assert-True ($backupCleanupResult.StdOut -match 'DryRun' -and $backupCleanupResult.StdOut -match 'migration-backups') 'backup cleanup DryRun reports its bounded local scope'
Assert-True (Test-Path -LiteralPath $backupCleanupCandidate -PathType Container) 'backup cleanup DryRun deletes no local backup'
[IO.Directory]::Delete($backupCleanupRoot, $true)

$anyToRealityRoot = Join-Path $ProjectRoot '.test-output\migration-anytls-to-reality'
$anyToRealityPlan = New-TestMigrationSourceFixture -Template $anyTlsSource -Root $anyToRealityRoot -ProtocolModule 'sing-box-anytls'
$anyToRealityInput = (@('1', '1', '1', '', '1', '1', 'target.example.invalid', 'y', 'y', 'n', '1') -join [Environment]::NewLine) + [Environment]::NewLine
$anyToRealityResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),
    '-Mode', 'Migrate', '-DryRun', '-PlanPath', $anyToRealityPlan
) -InputText $anyToRealityInput -TimeoutSeconds 60
Assert-True ($anyToRealityResult.ExitCode -eq 0) 'existing AnyTLS plan can enter external Reality migration DryRun'
Assert-True ($anyToRealityResult.StdOut -match 'target-audit' -and $anyToRealityResult.StdOut -match 'xray-reality') 'AnyTLS to Reality DryRun selects target audit and Xray modules'
Assert-True ($anyToRealityResult.StdOut -notmatch '(?m)\ssing-box-anytls\s') 'AnyTLS to Reality DryRun excludes the source service module'
$networkTuneInput = (@('1', '1000', '', '1') -join [Environment]::NewLine) + [Environment]::NewLine
$networkTuneResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),
    '-Mode', 'TuneNetwork', '-DryRun', '-PlanPath', $anyToRealityPlan
) -InputText $networkTuneInput -TimeoutSeconds 60
Assert-True ($networkTuneResult.ExitCode -eq 0) 'standalone network tuning enters DryRun on an existing managed VPS'
Assert-True ($networkTuneResult.StdOut -notmatch '(?m)\snftables-transition\s') 'standalone network tuning DryRun does not include firewall application'
[IO.Directory]::Delete($anyToRealityRoot, $true)

$ssToAnyRoot = Join-Path $ProjectRoot '.test-output\migration-ss-to-anytls'
$ssToAnyPlan = New-TestMigrationSourceFixture -Template $shadowsocksSource -Root $ssToAnyRoot -ProtocolModule 'sing-box-shadowsocks'
$ssTokenPath = Join-Path $ssToAnyRoot 'cloudflare-certbot-token.private.txt'
[IO.File]::WriteAllText($ssTokenPath, 'fixture-token-value')
$ssToAnyInput = (@(
    '1', '1', '2', 'edge.example.invalid', 'www.example.invalid', 'y', '', 'fixture@example.invalid', $ssTokenPath, 'n', '1'
) -join [Environment]::NewLine) + [Environment]::NewLine
$ssToAnyResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),
    '-Mode', 'Migrate', '-DryRun', '-PlanPath', $ssToAnyPlan
) -InputText $ssToAnyInput -TimeoutSeconds 60
Assert-True ($ssToAnyResult.ExitCode -eq 0) 'existing Shadowsocks plan can enter AnyTLS migration DryRun'
Assert-True ($ssToAnyResult.StdOut -match 'certbot-dns' -and $ssToAnyResult.StdOut -match 'sing-box-anytls') 'Shadowsocks to AnyTLS DryRun selects certificate and AnyTLS modules'
Assert-True ($ssToAnyResult.StdOut -notmatch '(?m)\ssing-box-shadowsocks\s') 'Shadowsocks to AnyTLS DryRun excludes the source service module'
[IO.Directory]::Delete($ssToAnyRoot, $true)

$importRoot = Join-Path $ProjectRoot '.test-output\existing-import-dryrun-root'
$importArchive = Join-Path $importRoot 'ExampleProvider\ExistingImport'
$importKey = Join-Path $ProjectRoot '.test-output\existing-import-provider-key'
if (Test-Path -LiteralPath $importRoot) { [IO.Directory]::Delete($importRoot, $true) }
[IO.File]::WriteAllText($importKey, 'fixture-existing-key')
$importInput = (@(
    '', 'ExampleProvider', 'ExistingImport', 'Example-US.Imported', '192.0.2.90', '', '', '1', $importKey,
    '1', '1', '1000', '1'
) -join [Environment]::NewLine) + [Environment]::NewLine
$importResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),
    '-Mode', 'Import', '-DryRun', '-InstanceRoot', $importRoot
) -InputText $importInput -TimeoutSeconds 60
Assert-True ($importResult.ExitCode -eq 0) 'existing VPS import wizard supports a no-write DryRun without deployment-plan.json'
Assert-True ($importResult.StdErr -notmatch 'Exception|Error') 'existing VPS import DryRun reports no execution error'
$importSourceText = Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'src\VpsDeploy.Import.ps1')
Assert-True ($importSourceText -match "SshKeyMode = 'ReuseExisting'" -and $importSourceText -match 'EnforceKeyOnlySsh = \$false') 'existing VPS import defaults to key reuse and preserves SSH authentication policy'
Assert-True ($importResult.StdOut -match '1000 Mbps' -and $importResult.StdOut -match 'MXH-VPS-Deploy') 'existing VPS import records nominal bandwidth and managed subdirectory layout'
Assert-True (-not (Test-Path -LiteralPath $importArchive)) 'existing VPS import DryRun creates no private archive or plan'
[IO.File]::Delete($importKey)

$directBackInput = '0' + [Environment]::NewLine
$directBackResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'), '-Mode', 'New', '-DryRun'
) -InputText $directBackInput -TimeoutSeconds 60
Assert-True ($directBackResult.ExitCode -eq 0) 'direct New mode exits cleanly when backing out of its first field'
Assert-True ($directBackResult.StdOut -notmatch '__MXH_VPS_WIZARD_' -and $directBackResult.StdErr -notmatch '__MXH_VPS_WIZARD_') 'direct-mode back remains an internal control signal'

$mainMenuExitResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'), '-Mode', 'Interactive', '-DryRun'
) -InputText ("9" + [Environment]::NewLine) -TimeoutSeconds 60
Assert-True ($mainMenuExitResult.ExitCode -eq 0) 'main menu exits cleanly with numbered option nine'
$mainMenuReservedResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'), '-Mode', 'Interactive', '-DryRun'
) -InputText ((@('0', 'b', '9') -join [Environment]::NewLine) + [Environment]::NewLine) -TimeoutSeconds 60
Assert-True ($mainMenuReservedResult.ExitCode -eq 0 -and $mainMenuReservedResult.StdOut -match '(?m)^b\r?$' -and $mainMenuReservedResult.StdOut -match '(?m)^9\r?$') 'main menu rejects 0 and b and exits only with 9'
$startVpsDeploySource = & $coreModule { (Get-Command Start-VpsDeploy).ScriptBlock.ToString() }
Assert-True ($startVpsDeploySource -match "'本地自检（不连接 VPS）',\s*'退出'") 'main menu exposes one numbered exit after offline validation'
Assert-True (([regex]::Matches($startVpsDeploySource, "'退出'")).Count -eq 1) 'main menu has no duplicate numbered exit option'
$mainHelpResult=Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @('-NoProfile','-File',(Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),'-Mode','Interactive','-DryRun') -InputText ((@('help','9')-join[Environment]::NewLine)+[Environment]::NewLine) -TimeoutSeconds 60
Assert-True ($mainHelpResult.ExitCode-eq 0 -and ([regex]::Matches($mainHelpResult.StdOut,'help / h')).Count-ge 2 -and $mainHelpResult.StdOut-match '(?m)^help\r?$') 'main menu help command explains current choices and returns to the menu'

$resumeFixture = (Join-Path $ProjectRoot 'tests\fixtures\dry-run-plan.json')
$resumeNavigationInput = (@('2', ('"' + $resumeFixture + '"'), '0', '0', '9') -join [Environment]::NewLine) + [Environment]::NewLine
$resumeNavigationResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'), '-Mode', 'Interactive', '-DryRun'
) -InputText $resumeNavigationInput -TimeoutSeconds 60
Assert-True ($resumeNavigationResult.ExitCode -eq 0) 'resume summary returns to quoted plan-path selection and then to the main menu'
Assert-True ($resumeNavigationResult.StdOut -match 'ExampleInstance') 'resume path with surrounding quotes is normalized and loaded'

$cancelInstanceRoot = Join-Path $ProjectRoot '.test-output\wizard-cancel-root'
$cancelArchive = Join-Path $cancelInstanceRoot 'ExampleProvider\CancelAtSummary'
$cancelInput = (@(
    '1', '', 'ExampleProvider', 'CancelAtSummary', '', '192.0.2.62', '', '', '1', '4', '', 'n', 'n', '2', '9'
) -join [Environment]::NewLine) + [Environment]::NewLine
$cancelResult = Invoke-VpsProcess -FilePath $pwshPath -ArgumentList @(
    '-NoProfile', '-File', (Join-Path $ProjectRoot 'Start-VPSDeploy.ps1'),
    '-Mode', 'Interactive', '-DryRun', '-InstanceRoot', $cancelInstanceRoot
) -InputText $cancelInput -TimeoutSeconds 60
Assert-True ($cancelResult.ExitCode -eq 0) 'summary cancellation returns to the main menu without an error pause'
Assert-True (-not (Test-Path -LiteralPath $cancelArchive)) 'summary cancellation writes no plan, credentials, or instance archive'
Assert-True ($cancelResult.StdOut -notmatch '__MXH_VPS_WIZARD_' -and $cancelResult.StdErr -notmatch '__MXH_VPS_WIZARD_') 'summary cancellation marker never leaks to the console'

$preExecutionContext = [pscustomobject]@{
    ProjectRoot = $ProjectRoot
    Plan = [ordered]@{ Role = 'AuditOnly' }
    State = [ordered]@{ Modules = @{} }
    DryRun = $false
    NonInteractive = $false
}
$preExecutionBack = & $coreModule {
    param($Context)
    function Read-Host { param([string]$Prompt); return '0' }
    try {
        Invoke-VpsModulePipeline -Context $Context -OnlyModule @('audit')
        return '<no-navigation-signal>'
    }
    catch { return $_.Exception.Message }
    finally { Remove-Item Function:\Read-Host -ErrorAction SilentlyContinue }
} $preExecutionContext 6>$null
Assert-True ($preExecutionBack -eq '__MXH_VPS_WIZARD_BACK__') 'final pre-execution confirmation can return before any remote module starts'
Assert-True ($preExecutionContext.State.Modules.Count -eq 0) 'pre-execution back leaves every module untouched'

$completedMigrationExplicitContext = [pscustomobject]@{
    ProjectRoot = $ProjectRoot
    Plan = [ordered]@{
        Role = 'AuditOnly'
        Migration = [ordered]@{ Enabled = $true; ModuleIds = @('private-archive'); Status = 'Completed' }
    }
    State = [ordered]@{ Modules = @{} }
    DryRun = $true
    NonInteractive = $true
}
$completedMigrationExplicitOutput = (& $coreModule {
        param($Context)
        Invoke-VpsModulePipeline -Context $Context -OnlyModule @('audit')
    } $completedMigrationExplicitContext 6>&1 | Out-String)
Assert-True ($completedMigrationExplicitOutput -match 'audit\s+只读审计系统') 'OnlyModule bypasses stale completed-migration ModuleIds and selects the explicitly requested eligible module'

Write-Host '== Final private archive checksum timing ==' -ForegroundColor Cyan
$checksumFixture = Join-Path $ProjectRoot '.test-output\private-archive-checksum'
[IO.Directory]::CreateDirectory($checksumFixture) | Out-Null
$checksumStatePath = Join-Path $checksumFixture 'deployment-state.json'
$checksumConfigPath = Join-Path $checksumFixture 'server-configs\fixture.json'
$checksumLiveLogPath = Join-Path $checksumFixture 'deployment.log'
[IO.Directory]::CreateDirectory((Split-Path -Parent $checksumConfigPath)) | Out-Null
[IO.File]::WriteAllText($checksumStatePath, '{"Modules":{"private-archive":{"Status":"Success"}}}', [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($checksumConfigPath, '{"fixture":true}', [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($checksumLiveLogPath, 'mutable audit log', [Text.UTF8Encoding]::new($false))
$checksumContext = [pscustomobject]@{ ArchivePath = $checksumFixture; DryRun = $false }
& $coreModule { param($Context) Update-VpsPrivateArchiveChecksums -Context $Context } $checksumContext
$checksumLines = @(Get-Content -LiteralPath (Join-Path $checksumFixture 'SHA256SUMS-private.txt'))
$checksumEntries = [ordered]@{}
foreach ($line in $checksumLines) {
    if ($line -match '^([0-9a-f]{64})  (.+)$') { $checksumEntries[$Matches[2]] = $Matches[1] }
}
Assert-True ($checksumEntries.Contains('deployment-state.json')) 'final checksum includes deployment state'
Assert-True ($checksumEntries['deployment-state.json'] -eq (Get-FileHash -LiteralPath $checksumStatePath -Algorithm SHA256).Hash.ToLowerInvariant()) 'final checksum matches persisted success state'
Assert-True (-not $checksumEntries.Contains('deployment.log')) 'final checksum excludes the append-only deployment log'
$pipelineSource = & $coreModule { (Get-Command Invoke-VpsModulePipeline).ScriptBlock.ToString() }
$successStateIndex = $pipelineSource.IndexOf("Set-VpsModuleState -Context `$Context -Id `$module.Id -Status Success")
$finalChecksumIndex = $pipelineSource.IndexOf('Update-VpsPrivateArchiveChecksums -Context $Context')
Assert-True ($successStateIndex -ge 0 -and $finalChecksumIndex -gt $successStateIndex) 'pipeline refreshes archive checksums after success state persistence'
$missingStateJson = & $coreModule { ConvertTo-VpsOptionalStateJson -State ([ordered]@{}) -Name 'RealityEgressTest' }
$presentStateJson = & $coreModule { ConvertTo-VpsOptionalStateJson -State ([ordered]@{ RealityEgressTest = [ordered]@{ Status = 'Passed' } }) -Name 'RealityEgressTest' }
Assert-True ($missingStateJson -eq '{"Status":"NotRecorded"}') 'legacy archive marks missing historical validation as not recorded'
Assert-True ($presentStateJson -eq '{"Status":"Passed"}') 'archive preserves recorded historical validation'
[IO.Directory]::Delete($checksumFixture, $true)

$testOutputRoot = Join-Path $ProjectRoot '.test-output'
if (Test-Path -LiteralPath $testOutputRoot) {
    $remainingTestOutput = @(Get-ChildItem -LiteralPath $testOutputRoot -Force)
    if ($remainingTestOutput.Count -eq 0) { [IO.Directory]::Delete($testOutputRoot, $false) }
}

Write-Host '== Secret scan ==' -ForegroundColor Cyan
& (Join-Path $ProjectRoot 'scripts\Test-NoSecrets.ps1') -ProjectRoot $ProjectRoot
Assert-True $true 'secret scan'

Write-Host "All tests passed: $passed assertions" -ForegroundColor Green
& (Join-Path $ProjectRoot 'tests/Test-Interaction.ps1') -ProjectRoot $ProjectRoot
& (Join-Path $ProjectRoot 'tests/Test-Workbench.ps1') -ProjectRoot $ProjectRoot
& (Join-Path $ProjectRoot 'tests/Test-SshKeyAccess.ps1') -ProjectRoot $ProjectRoot
& (Join-Path $ProjectRoot 'tests/Test-MenuCopy.ps1') -ProjectRoot $ProjectRoot
& (Join-Path $ProjectRoot 'tests/Test-AuditFixes.ps1') -ProjectRoot $ProjectRoot
& (Join-Path $ProjectRoot 'tests/Test-PowerShell74Bootstrap.ps1') -ProjectRoot $ProjectRoot
& (Join-Path $ProjectRoot 'tests/Test-AppUpdate.ps1') -ProjectRoot $ProjectRoot
if($IsWindows){& (Join-Path $ProjectRoot 'tests/Test-Gui.ps1') -ProjectRoot $ProjectRoot}
if($pythonCommandForClient){
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_certbot_source.py')
    if($LASTEXITCODE -ne 0){throw 'Certbot scoped DNS API source tests failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_client_compatibility.py')
    if($LASTEXITCODE -ne 0){throw 'Client template compatibility tests failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_google_client_policy.py')
    if($LASTEXITCODE -ne 0){throw 'Google client policy and authority ownership tests failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_health_audit.py')
    if($LASTEXITCODE -ne 0){throw 'Health audit behavior tests failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_network_runtime.py')
    if ($LASTEXITCODE -ne 0) { throw 'Network runtime tests failed.' }
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_network_audit.py')
    if($LASTEXITCODE -ne 0){throw 'Network runtime snapshot regressions failed.'}
    if($bash){ & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_review_repairs.py') --bash $bash }else{ & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_review_repairs.py') }
    if($LASTEXITCODE -ne 0){throw 'Cross-feature review repair regressions failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_bbr_kernel.py')
    if ($LASTEXITCODE -ne 0) { throw 'BBR fixed package contract failed.' }
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_kernel_prebuild.py')
    if ($LASTEXITCODE -ne 0) { throw 'BBR kernel contracts failed.' }
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_component_releases.py')
    if($LASTEXITCODE -ne 0){throw 'Official component release contracts failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_tunnel_public_access.py')
    if ($LASTEXITCODE -ne 0) { throw 'Tunnel public access probe regressions failed.' }
}
if($bash -and $pythonCommandForClient){
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_remote_transactions.py') --bash $bash
    if($LASTEXITCODE -ne 0){throw 'Remote transaction guard tests failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_scoped_rollback.py') --bash $bash
    if($LASTEXITCODE -ne 0){throw 'Scoped rollback behavior tests failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_component_installation.py') --bash $bash
    Assert-True ($LASTEXITCODE -eq 0) 'component installation and protocol coexistence boundaries'
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_import_contracts.py') --bash $bash
    if($LASTEXITCODE -ne 0){throw 'Import/SSH policy behavior tests failed.'}
    & $pythonCommandForClient.Source (Join-Path $ProjectRoot 'tests/test_komari_lifecycle.py') --bash $bash
    if($LASTEXITCODE -ne 0){throw 'Komari lifecycle compatibility tests failed.'}
}
