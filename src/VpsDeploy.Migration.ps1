function Get-MxhProtocolRoleLabel {
    param([Parameter(Mandatory)] [string]$Role)
    switch ($Role) {
        'RealityEntry' { 'Reality 入口' }
        'AnyTlsEntry' { 'AnyTLS + 可信 TLS + ECH 入口' }
        'ShadowsocksLanding' { 'Shadowsocks 2022 落地' }
        'MonitorOnly' { '仅管理/监控' }
        default { $Role }
    }
}

function Get-MxhProtocolServiceName {
    param([Parameter(Mandatory)] [string]$Role)
    switch ($Role) {
        'RealityEntry' { 'xray.service' }
        'AnyTlsEntry' { 'sing-box-anytls.service' }
        'ShadowsocksLanding' { 'sing-box.service' }
        default { throw "不支持的协议角色：$Role" }
    }
}

function Get-MxhManagedProtocolRoles {
    return @('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding')
}

function Copy-MxhHashtable {
    param([Parameter(Mandatory)] [Collections.IDictionary]$Value)
    return ($Value | ConvertTo-Json -Depth 40) | ConvertFrom-Json -AsHashtable
}

function Get-MxhProtocolInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [Collections.IDictionary]$Plan,
        [Collections.IDictionary]$State,
        [Collections.IDictionary]$RemoteInventory
    )

    if ($RemoteInventory) {
        $inventory = Copy-MxhHashtable -Value $RemoteInventory
    }
    elseif ($Plan.Contains('ProtocolInventory')) {
        $inventory = Copy-MxhHashtable -Value $Plan.ProtocolInventory
    }
    else {
        $inventory = [ordered]@{ SchemaVersion = 1 }
        $moduleForRole = @{
            RealityEntry = 'xray-reality'
            AnyTlsEntry = 'sing-box-anytls'
            ShadowsocksLanding = 'sing-box-shadowsocks'
        }
        foreach ($role in (Get-MxhManagedProtocolRoles)) {
            $installed = [string]$Plan.Role -eq $role
            if ($State -and (Test-MxhModuleSucceeded -State $State -Id $moduleForRole[$role])) { $installed = $true }
            $enabled = [string]$Plan.Role -eq $role
            $inventory[$role] = [ordered]@{
                Installed = $installed
                Enabled = $enabled
                Active = $enabled
                Partial = $false
                Service = Get-MxhProtocolServiceName -Role $role
            }
        }
    }

    foreach ($role in (Get-MxhManagedProtocolRoles)) {
        if (-not $inventory.Contains($role)) {
            $inventory[$role] = [ordered]@{
                Installed = $false; Enabled = $false; Active = $false; Partial = $false
                Service = Get-MxhProtocolServiceName -Role $role
            }
        }
        foreach ($field in @('Installed', 'Enabled', 'Active', 'Partial')) {
            if (-not $inventory[$role].Contains($field)) { $inventory[$role][$field] = $false }
            $inventory[$role][$field] = [bool]$inventory[$role][$field]
        }
        if (-not $inventory[$role].Contains('Service')) {
            $inventory[$role].Service = Get-MxhProtocolServiceName -Role $role
        }
        if ($inventory[$role].Partial) { throw "检测到不完整的协议安装：$(Get-MxhProtocolRoleLabel -Role $role)。请先人工修复或恢复备份。" }
        if (($inventory[$role].Enabled -or $inventory[$role].Active) -and -not $inventory[$role].Installed) {
            throw "协议状态不一致：未完整安装但处于启用/运行状态：$(Get-MxhProtocolRoleLabel -Role $role)。"
        }
    }
    if ($inventory.RealityEntry.Enabled -and $inventory.AnyTlsEntry.Enabled) {
        throw 'Reality 与 AnyTLS 共用 TCP 443，不能同时设为开机启用。'
    }
    if ($inventory.RealityEntry.Active -and $inventory.AnyTlsEntry.Active) {
        throw 'Reality 与 AnyTLS 共用 TCP 443，不能同时运行。'
    }
    return $inventory
}

function Get-MxhInventoryPrimaryRole {
    param([Parameter(Mandatory)] [Collections.IDictionary]$Inventory)
    foreach ($role in @('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding')) {
        if ([bool]$Inventory[$role].Enabled) { return $role }
    }
    return 'MonitorOnly'
}

function Test-MxhProtocolInstalled {
    param(
        [Parameter(Mandatory)] [Collections.IDictionary]$Plan,
        [Parameter(Mandatory)] [string]$Role
    )
    if ($Plan.Contains('ProtocolInventory') -and $Plan.ProtocolInventory.Contains($Role)) {
        return [bool]$Plan.ProtocolInventory[$Role].Installed
    }
    return [string]$Plan.Role -eq $Role
}

function Show-MxhProtocolInventory {
    param([Parameter(Mandatory)] [Collections.IDictionary]$Inventory)
    Write-Host ''
    Write-Host '协议安装与启用状态' -ForegroundColor White
    foreach ($role in (Get-MxhManagedProtocolRoles)) {
        $item = $Inventory[$role]
        $installed = if ($item.Installed) { '已安装' } else { '未安装' }
        $enabled = if ($item.Enabled) { '已启用' } else { '未启用' }
        $active = if ($item.Active) { '运行中' } else { '未运行' }
        Write-Host "  $(Get-MxhProtocolRoleLabel -Role $role)：$installed / $enabled / $active"
    }
    Write-VpsUi 'Reality 与 AnyTLS 可以同时保留在磁盘上，但因共用 TCP 443，只允许一个启用并运行；Shadowsocks 使用独立高位端口，可与入口协议同时运行。' Muted
}

function Get-MxhProtocolFirewallParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [Collections.IDictionary]$Plan,
        [Parameter(Mandatory)] [Collections.IDictionary]$State,
        [Parameter(Mandatory)] [Collections.IDictionary]$Inventory
    )

    $ports = @([int]$Plan.Ports.SshPrimary, [int]$Plan.Ports.SshRescue)
    $bootstrapRemoved = $State.Contains('BootstrapSshRemoved') -and [bool]$State.BootstrapSshRemoved
    if (-not $bootstrapRemoved) { $ports += [int]$Plan.Server.BootstrapSshPort }
    if ([bool]$Inventory.RealityEntry.Enabled) {
        $ports += [int]$Plan.Ports.XrayPrimary
        $ports += [int]$Plan.Ports.XrayBackup
    }
    if ([bool]$Inventory.AnyTlsEntry.Enabled) { $ports += [int]$Plan.Ports.AnyTlsPrimary }
    $ports = @($ports | Where-Object { $_ -gt 0 } | Sort-Object -Unique)

    $parameters = [ordered]@{
        TCP_PORTS = ($ports -join ',')
        RESTRICTED_PORT = ''
        ALLOWED_IPV4S = ''
        ALLOWED_IPV6S = ''
    }
    if ([bool]$Inventory.ShadowsocksLanding.Enabled) {
        $parameters.RESTRICTED_PORT = [string]$Plan.Ports.LandingShadowsocks
        $parameters.ALLOWED_IPV4S = (@($Plan.Shadowsocks.TrustedEntryIPv4s) -join ',')
        $parameters.ALLOWED_IPV6S = (@($Plan.Shadowsocks.TrustedEntryIPv6s) -join ',')
    }
    return $parameters
}

function Invoke-MxhProtocolFirewall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [Collections.IDictionary]$Inventory,
        [Parameter(Mandatory)] [string]$BackupStateName,
        [string]$ExpectedTransaction
    )
    $firewallMode = if ($Context.Plan.Contains('Firewall') -and $Context.Plan.Firewall.Contains('Mode')) {
        [string]$Context.Plan.Firewall.Mode
    } else { 'ManagedNftables' }
    if ($firewallMode -eq 'PreserveExisting') {
        if ($Context.Plan.Contains('Migration') -and $Context.Plan.Migration.Contains('InitialInventory') -and
            -not [bool]$Context.Plan.Migration.InitialInventory.ShadowsocksLanding.Installed -and
            [bool]$Inventory.ShadowsocksLanding.Enabled) {
            throw '导入实例使用“保留现有防火墙”模式；新增 Shadowsocks 高位端口需要单独审计并人工配置防火墙，脚本拒绝自动 flush/覆盖。'
        }
        $result = Invoke-VpsRemoteScript -Context $Context -Asset 'existing-firewall-validate.sh' -TimeoutSeconds 180
        if ($result.StdOut -notmatch 'VPSDEPLOY_EXISTING_FIREWALL_OK') { throw '现有防火墙语法检查未返回成功标记。' }
        if (-not $Context.State.Contains('BackupDirectories')) { $Context.State.BackupDirectories = @{} }
        $Context.State.BackupDirectories[$BackupStateName] = '<preserved-existing-firewall>'
        Save-VpsContext -Context $Context
        Write-VpsUi '已保留导入实例的现有防火墙，没有执行 flush ruleset 或端口重写。' Warning
        return
    }
    $parameters = Get-MxhProtocolFirewallParameters -Plan $Context.Plan -State $Context.State -Inventory $Inventory
    if ($ExpectedTransaction) { $parameters.EXPECTED_TRANSACTION = $ExpectedTransaction }
    $result = Invoke-VpsRemoteScript -Context $Context -Asset 'nftables-apply.sh' -Parameters $parameters
    $backup = Get-VpsMarkerValue $result.StdOut BACKUP_DIR -Required
    if (-not $Context.State.Contains('BackupDirectories')) { $Context.State.BackupDirectories = @{} }
    $Context.State.BackupDirectories[$BackupStateName] = $backup
    Save-VpsContext -Context $Context
}

function Test-MxhModuleSucceeded {
    param(
        [Parameter(Mandatory)] [Collections.IDictionary]$State,
        [Parameter(Mandatory)] [string]$Id
    )
    if (-not $State.Contains('Modules') -or -not $State.Modules.Contains($Id)) { return $false }
    return [string]$State.Modules[$Id].Status -eq 'Success'
}

function Get-MxhMigrationModuleIds {
    param(
        [Parameter(Mandatory)] [ValidateSet('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding', 'MonitorOnly')]
        [string]$TargetRole,
        [string]$RealityTargetMode = 'ExternalAudited',
        [ValidateSet('InstallActivate', 'InstallStandby', 'Enable', 'Disable', 'Uninstall', 'NetworkTune')]
        [string]$Operation = 'InstallActivate'
    )

    $ids = [Collections.Generic.List[string]]::new()
    $ids.Add('migration-preflight')
    if ($Operation -eq 'NetworkTune') {
        $ids.Add('migration-arm-rollback')
    }
    elseif ($Operation -in @('Enable', 'Disable')) {
        $ids.Add('migration-arm-rollback')
        $ids.Add('protocol-lifecycle-state')
        if ($Operation -eq 'Enable' -and $TargetRole -eq 'ShadowsocksLanding') {
            $ids.Add('migration-shadowsocks-probe')
        }
    }
    elseif ($Operation -eq 'Uninstall') {
        $ids.Add('migration-arm-rollback')
        $ids.Add('protocol-lifecycle-uninstall')
    }
    elseif ($TargetRole -eq 'RealityEntry') {
        if ($RealityTargetMode -eq 'LocalOwnedTls') {
            $ids.Add('certbot-dns')
            $ids.Add('local-https-target')
        }
        else { $ids.Add('target-audit') }
        $ids.Add('migration-arm-rollback')
        $ids.Add('xray-reality')
        $ids.Add('client-export')
    }
    elseif ($TargetRole -eq 'AnyTlsEntry') {
        $ids.Add('certbot-dns')
        $ids.Add('migration-arm-rollback')
        $ids.Add('sing-box-anytls')
        $ids.Add('anytls-client-export')
    }
    else {
        $ids.Add('migration-arm-rollback')
        $ids.Add('sing-box-shadowsocks')
        $ids.Add('landing-client-export')
        $ids.Add('migration-shadowsocks-probe')
    }
    if ($Operation -eq 'NetworkTune') { $ids.Add('network-tuning') }
    if ($Operation -ne 'NetworkTune') { $ids.Add('nftables-transition') }
    $ids.Add('final-validation')
    if ($Operation -ne 'NetworkTune') { $ids.Add('protocol-lifecycle-final-firewall') }
    $ids.Add('migration-commit')
    $ids.Add('private-archive')
    return $ids.ToArray()
}

function ConvertTo-MxhCompatiblePlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Collections.IDictionary]$Plan)
    $result=Copy-MxhHashtable -Value $Plan
    if(-not$result.Contains('NetworkTuning')){$result.NetworkTuning=[ordered]@{Mode='LegacyBaseline';BandwidthMbps=$null;ReferenceRttMs=$null}}
    if(-not$result.Contains('Komari')){$result.Komari=[ordered]@{Enabled=$false;Endpoint=$null;AgentVersion=$null}}
    if(-not$result.Contains('Firewall')){$result.Firewall=[ordered]@{Mode='PreserveExisting'}}
    if(-not$result.Paths.Contains('InstanceDirectory')){$result.Paths.InstanceDirectory=[string]$result.Paths.Archive}
    if(-not$result.Contains('Compatibility')){$result.Compatibility=[ordered]@{NormalizedBy='MXH-VPS-Deploy';OriginalSchema=if($result.Contains('SchemaVersion')){$result.SchemaVersion}else{$null};NormalizedAt=(Get-Date).ToString('o')}}
    return $result
}

function Test-MxhProtocolMigrationSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$PlanPath,
        [Parameter(Mandatory)] [Collections.IDictionary]$Plan,
        [Parameter(Mandatory)] [Collections.IDictionary]$State
    )

    $supported = @('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding', 'MonitorOnly')
    if ([string]$Plan.Role -notin $supported) {
        throw '协议管理只支持由本工具验收的 Reality、AnyTLS、Shadowsocks 或已停用全部协议的实例。'
    }
    foreach ($section in @('Server', 'Ports', 'Paths', 'NetworkTuning', 'Komari')) {
        if (-not $Plan.Contains($section)) { throw "部署计划缺少 $section 段。" }
    }
    $resolvedPlan = (Resolve-Path -LiteralPath $PlanPath).Path
    $planParent = [IO.Path]::GetFullPath((Split-Path -Parent $resolvedPlan)).TrimEnd('\', '/')
    $archive = [IO.Path]::GetFullPath([string]$Plan.Paths.Archive).TrimEnd('\', '/')
    if (-not $planParent.Equals($archive, [StringComparison]::OrdinalIgnoreCase)) {
        throw '计划文件不在其声明的实例私有归档根目录中，拒绝协议管理。'
    }
    $requiredModules = @('ssh-transition', 'nftables-transition', 'final-validation', 'ssh-cutover', 'private-archive')
    $inventory = Get-MxhProtocolInventory -Plan $Plan -State $State
    $moduleForRole = @{
        RealityEntry = 'xray-reality'
        AnyTlsEntry = 'sing-box-anytls'
        ShadowsocksLanding = 'sing-box-shadowsocks'
    }
    foreach ($role in (Get-MxhManagedProtocolRoles)) {
        if ([bool]$inventory[$role].Installed) { $requiredModules += $moduleForRole[$role] }
    }
    $missing = @($requiredModules | Where-Object { -not (Test-MxhModuleSucceeded -State $State -Id $_) })
    if ($missing.Count -gt 0) {
        throw "源计划尚未完整验收，缺少成功状态：$($missing -join ', ')。请先使用继续未完成部署。"
    }
    $managementPort = [int]$State.CurrentManagementPort
    if ($managementPort -notin @([int]$Plan.Ports.SshPrimary, [int]$Plan.Ports.SshRescue)) {
        throw '当前管理端口不是计划中的 SSH 主/救援端口，拒绝自动协议管理。'
    }
    $keyPath = Get-VpsSshKeyPath -Context ([pscustomobject]@{ Plan = $Plan })
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        throw '实例专用 SSH 私钥不存在，无法安全管理协议。'
    }
    foreach ($privateFile in @('deployment-state.json', 'deployment-secrets.private.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $archive $privateFile) -PathType Leaf)) {
            throw "实例私有归档缺少 $privateFile。"
        }
    }
    if ($Plan.Contains('Migration') -and [bool]$Plan.Migration.Enabled) {
        $status = [string]$Plan.Migration.Status
        if ($status -notin @('Completed', 'Committed')) {
            throw "已有未完成协议变更（状态 $status），请使用继续未完成部署，不要创建第二个操作。"
        }
    }
    return $true
}

function Test-MxhMigrationValidationEntryPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$PlanPath,
        [Parameter(Mandatory)] [string]$LandingServerIpv4,
        [Parameter(Mandatory)] [string[]]$AllowedEntryIpv4s
    )

    $resolved = (Resolve-Path -LiteralPath $PlanPath).Path
    $plan = Read-VpsJsonHashtable -Path $resolved
    if ([string]$plan.Role -notin @('RealityEntry', 'AnyTlsEntry')) {
        throw '外部链式探测必须选择一台已完成的 Reality 或 AnyTLS 入口计划。'
    }
    $entryIpv4 = [string]$plan.Server.IPv4
    if ($entryIpv4 -eq $LandingServerIpv4) { throw '验证入口不能就是正在转换为落地机的同一台 VPS。' }
    if ($entryIpv4 -notin $AllowedEntryIpv4s) {
        throw "验证入口 IPv4 未包含在 Shadowsocks 可信入口白名单中：$entryIpv4"
    }
    $archive = [string]$plan.Paths.Archive
    $planParent = [IO.Path]::GetFullPath((Split-Path -Parent $resolved)).TrimEnd('\', '/')
    $archiveFull = [IO.Path]::GetFullPath($archive).TrimEnd('\', '/')
    if (-not $planParent.Equals($archiveFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw '验证入口计划不在其声明的私有归档根目录中。'
    }
    $statePath = Join-Path $archive 'deployment-state.json'
    $secretsPath = Join-Path $archive 'deployment-secrets.private.json'
    $keyPath = Get-VpsSshKeyPath -Context ([pscustomobject]@{ Plan = $plan })
    foreach ($path in @($statePath, $secretsPath, $keyPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "验证入口归档缺少文件：$path" }
    }
    $state = Read-VpsJsonHashtable -Path $statePath
    if ([int]$state.CurrentManagementPort -notin @([int]$plan.Ports.SshPrimary, [int]$plan.Ports.SshRescue)) {
        throw '验证入口的当前管理端口不在 SSH 主/救援端口中。'
    }
    $protocolModule = if ($plan.Role -eq 'RealityEntry') { 'xray-reality' } else { 'sing-box-anytls' }
    foreach ($id in @('ssh-cutover', 'final-validation', $protocolModule)) {
        if (-not (Test-MxhModuleSucceeded -State $state -Id $id)) { throw "验证入口未完成模块：$id" }
    }
    return $true
}

function Get-MxhRemoteProtocolInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ProjectRoot,
        [Parameter(Mandatory)] [string]$PlanPath
    )

    $context = New-MxhReadonlyContextFromPlan -ProjectRoot $ProjectRoot -PlanPath $PlanPath
    Initialize-MxhPendingSshAccess $context
    $result = Invoke-VpsRemoteScript -Context $context -Asset 'protocol-lifecycle-status.sh' -TimeoutSeconds 180
    if ($result.StdOut -notmatch 'VPSDEPLOY_PROTOCOL_STATUS_OK') {
        throw '远端协议状态检查未返回成功标记。'
    }
    $json = Get-VpsMarkerValue $result.StdOut PROTOCOL_INVENTORY -Required
    $inventory = $json | ConvertFrom-Json -AsHashtable
    return Get-MxhProtocolInventory -Plan $context.Plan -State $context.State -RemoteInventory $inventory
}

function Read-MxhProtocolMigrationSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ProjectRoot,
        [string]$PlanPath,
        [switch]$DryRun
    )

    $candidatePath = $PlanPath
    while ($true) {
        if (-not $candidatePath) {
            $inputPath = Read-VpsText '现有 VPS 的 deployment-plan.json 完整路径' -AllowBack -Validate {
                param($v)
                Test-VpsExistingInputPath -Value $v -PathType Leaf
            } -ValidationMessage '找不到该计划文件，或路径混用了 / 与 \。可输入 0 返回主菜单。'
            $candidatePath = ConvertTo-VpsInputPath -Value $inputPath
        }
        try { $candidatePath = (Resolve-Path -LiteralPath (ConvertTo-VpsInputPath -Value $candidatePath)).Path }
        catch {
            Write-VpsUi $_.Exception.Message Warning
            $candidatePath = $null
            continue
        }
        try {
            $plan = ConvertTo-MxhCompatiblePlan -Plan (Read-VpsJsonHashtable -Path $candidatePath)
            $archive = [string]$plan.Paths.Archive
            $state = Read-VpsJsonHashtable -Path (Join-Path $archive 'deployment-state.json')
            Test-MxhProtocolMigrationSource -PlanPath $candidatePath -Plan $plan -State $state | Out-Null
            $inventory = if ($DryRun) {
                Get-MxhProtocolInventory -Plan $plan -State $state
            }
            else {
                Get-MxhRemoteProtocolInventory -ProjectRoot $ProjectRoot -PlanPath $candidatePath
            }
            Show-VpsPlanSummary -Plan $plan -ExistingInstance
            Show-MxhProtocolInventory -Inventory $inventory
        }
        catch {
            Write-VpsUi "不能进入协议管理：$($_.Exception.Message)" Warning
            $candidatePath = $null
            continue
        }
        try {
            $choice = Read-VpsMenu '确认要管理的 VPS' @(
                '确认，继续管理此 VPS',
                '取消并返回主菜单'
            ) 1 -AllowBack -HelpText @'
请核对上方的 VPS 信息和协议状态。
选择 1 进入下一步；选择 2 取消本次操作；输入 0 返回计划文件选择页。
'@
        }
        catch {
            if (-not (Test-VpsWizardBackError $_)) { throw }
            $choice = 0
        }
        if ($choice -eq 1) {
            return [pscustomobject]@{ PlanPath = $candidatePath; Plan = $plan; State = $state; Inventory = $inventory }
        }
        if ($choice -eq 2) { throw [OperationCanceledException]::new($script:VpsWizardCancelMarker) }
        $candidatePath = $null
    }
}

function New-MxhProtocolMigrationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [Collections.IDictionary]$SourcePlan,
        [Parameter(Mandatory)] [string]$SourcePlanPath,
        [Collections.IDictionary]$SourceState,
        [Collections.IDictionary]$SourceInventory,
        [Parameter(Mandatory)] [ValidateSet('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding')]
        [string]$TargetRole,
        [ValidateSet('InstallActivate', 'InstallStandby')]
        [string]$Operation = 'InstallActivate',
        [int]$TargetServicePort,
        [string]$RealityTargetMode = 'ExternalAudited',
        [string]$RealityTarget,
        [string]$RealityServerName,
        [string]$RealityTargetAddress,
        [int]$RealityLocalHttpsPort = 8443,
        [string]$XrayVersion,
        [ValidateSet('FixedVerified','LatestStable','ImportedOrLegacy')][string]$XrayVersionChannel = 'FixedVerified',
        [string]$AnyTlsServerName,
        [string]$EchPublicName,
        [string]$SingBoxVersion,
        [string[]]$AnyTlsPaddingScheme = @(),
        [bool]$ForceIpv4Egress = $true,
        [bool]$TrustedTlsEnabled = $false,
        [string]$CloudflareZoneName,
        [string]$CertbotEmail,
        [string]$CloudflareTokenFile,
        [Collections.IDictionary]$TrustedEntryIps = ([ordered]@{ IPv4 = @(); IPv6 = @() }),
        [string]$ClientTransitTag,
        [string]$ValidationEntryPlanPath,
        [bool]$SecondaryIpv6Enabled = $false,
        [string]$SecondaryIpv6Address,
        [string]$SecondaryBindInterface,
        [Collections.IDictionary]$NetworkTuning = ([ordered]@{ Mode = 'BaselineOnly'; BandwidthMbps = $null; ReferenceRttMs = $null })
    )

    $initialInventory = if ($SourceInventory) {
        Get-MxhProtocolInventory -Plan $SourcePlan -State $SourceState -RemoteInventory $SourceInventory
    } else {
        Get-MxhProtocolInventory -Plan $SourcePlan -State $SourceState
    }
    if ([bool]$initialInventory[$TargetRole].Installed) {
        throw '目标协议已经安装；请使用“切换/启停已安装协议”，如需重装请先停用并卸载。'
    }
    $sourceRole = Get-MxhInventoryPrimaryRole -Inventory $initialInventory
    $plan = ($SourcePlan | ConvertTo-Json -Depth 40) | ConvertFrom-Json -AsHashtable
    $plan.Role = $TargetRole
    $plan['UpdatedAt'] = (Get-Date).ToString('o')
    $plan.Ports.XrayPrimary = 443
    $plan.Ports.AnyTlsPrimary = 443
    if ($TargetRole -eq 'RealityEntry') { $plan.Ports.XrayBackup = $TargetServicePort }
    if ($TargetRole -eq 'ShadowsocksLanding') { $plan.Ports.LandingShadowsocks = $TargetServicePort }

    if (-not $plan.Contains('Reality')) { $plan.Reality = [ordered]@{} }
    if ($TargetRole -eq 'RealityEntry') {
        $plan.Reality.Target = $RealityTarget
        $plan.Reality.TargetMode = $RealityTargetMode
        $plan.Reality.ServerName = $RealityServerName
        $plan.Reality.TargetAddress = $RealityTargetAddress
        $plan.Reality.LocalHttpsPort = $RealityLocalHttpsPort
        $plan.Reality.ForceIpv4Egress = $ForceIpv4Egress
        if ($XrayVersion) { $plan.Reality.XrayVersion = $XrayVersion }
        $plan.Reality.XrayVersionChannel = $XrayVersionChannel
    }
    if (-not $plan.Contains('AnyTls')) { $plan.AnyTls = [ordered]@{} }
    $plan.AnyTls.Enabled = ($TargetRole -eq 'AnyTlsEntry') -or [bool]$initialInventory.AnyTlsEntry.Installed
    if ($TargetRole -eq 'AnyTlsEntry') {
        if($SingBoxVersion){$plan.AnyTls.SingBoxVersion=$SingBoxVersion}
        $plan.AnyTls.ServerName = $AnyTlsServerName
        $plan.AnyTls.EchPublicName = $EchPublicName
        $plan.AnyTls.ForceIpv4Egress = $ForceIpv4Egress
        $plan.AnyTls.PaddingSchemeMode = 'PerInstanceConservativeV1'
        $plan.AnyTls.PaddingScheme = @($AnyTlsPaddingScheme)
    }
    if (-not $plan.Contains('TrustedTls')) { $plan.TrustedTls = [ordered]@{} }
    $sourceUsesTrustedTls = [bool]$initialInventory.AnyTlsEntry.Installed -or
        ([bool]$initialInventory.RealityEntry.Installed -and $SourcePlan.Contains('Reality') -and
        $SourcePlan.Reality.Contains('TargetMode') -and $SourcePlan.Reality.TargetMode -eq 'LocalOwnedTls')
    $plan.TrustedTls.Enabled = $TrustedTlsEnabled -or $sourceUsesTrustedTls
    $plan.TrustedTls.ZoneName = $CloudflareZoneName
    $plan.TrustedTls.CertbotEmail = $CertbotEmail
    $plan.TrustedTls.CloudflareTokenFile = $CloudflareTokenFile
    if (-not $plan.TrustedTls.Contains('AnyTlsCertificateName')) { $plan.TrustedTls.AnyTlsCertificateName = 'mxh-anytls' }
    if (-not $plan.TrustedTls.Contains('RealityCertificateName')) { $plan.TrustedTls.RealityCertificateName = 'mxh-reality-target' }

    if (-not $plan.Contains('Shadowsocks')) { $plan.Shadowsocks = [ordered]@{} }
    if ($TargetRole -eq 'ShadowsocksLanding') {
        if($SingBoxVersion){$plan.Shadowsocks.SingBoxVersion=$SingBoxVersion}
        $plan.Shadowsocks.Method = '2022-blake3-aes-128-gcm'
        $plan.Shadowsocks.TrustedEntryIPv4s = @($TrustedEntryIps.IPv4)
        $plan.Shadowsocks.TrustedEntryIPv6s = @($TrustedEntryIps.IPv6)
        $plan.Shadowsocks.ClientTransitTag = $ClientTransitTag
        $plan.Shadowsocks['ValidationEntryPlanPath'] = $ValidationEntryPlanPath
        $plan.Shadowsocks.SecondaryIpv6Enabled = $SecondaryIpv6Enabled
        $plan.Shadowsocks.SecondaryIpv6Address = $SecondaryIpv6Address
        $plan.Shadowsocks.SecondaryBindInterface = $SecondaryBindInterface
    }
    $plan.NetworkTuning = $NetworkTuning

    $finalInventory = Copy-MxhHashtable -Value $initialInventory
    $finalInventory[$TargetRole].Installed = $true
    $finalInventory[$TargetRole].Partial = $false
    if ($Operation -eq 'InstallActivate') {
        $finalInventory[$TargetRole].Enabled = $true
        $finalInventory[$TargetRole].Active = $true
        if ($TargetRole -eq 'RealityEntry') {
            $finalInventory.AnyTlsEntry.Enabled = $false
            $finalInventory.AnyTlsEntry.Active = $false
        }
        elseif ($TargetRole -eq 'AnyTlsEntry') {
            $finalInventory.RealityEntry.Enabled = $false
            $finalInventory.RealityEntry.Active = $false
        }
    }
    else {
        $finalInventory[$TargetRole].Enabled = $false
        $finalInventory[$TargetRole].Active = $false
    }
    $validationInventory = Copy-MxhHashtable -Value $finalInventory
    $validationInventory[$TargetRole].Enabled = $true
    $validationInventory[$TargetRole].Active = $true
    if ($TargetRole -eq 'RealityEntry') {
        $validationInventory.AnyTlsEntry.Enabled = $false
        $validationInventory.AnyTlsEntry.Active = $false
    }
    elseif ($TargetRole -eq 'AnyTlsEntry') {
        $validationInventory.RealityEntry.Enabled = $false
        $validationInventory.RealityEntry.Active = $false
    }
    $plan['ProtocolInventory'] = $finalInventory
    $finalRole = Get-MxhInventoryPrimaryRole -Inventory $finalInventory

    $sourcePort = switch ($sourceRole) {
        'ShadowsocksLanding' { [int]$SourcePlan.Ports.LandingShadowsocks }
        default { 443 }
    }
    $targetPort = if ($TargetRole -eq 'ShadowsocksLanding') { $TargetServicePort } else { 443 }
    $moduleIds = @(Get-MxhMigrationModuleIds -TargetRole $TargetRole -RealityTargetMode $RealityTargetMode -Operation $Operation)
    $plan['Migration'] = [ordered]@{
        Enabled = $true
        SchemaVersion = 2
        Mode = 'ProtocolLifecycle'
        Operation = $Operation
        SourceRole = $sourceRole
        TargetRole = $TargetRole
        SourceService = if ($sourceRole -eq 'MonitorOnly') { $null } else { Get-MxhProtocolServiceName -Role $sourceRole }
        TargetService = Get-MxhProtocolServiceName -Role $TargetRole
        SourcePrimaryPort = $sourcePort
        TargetPrimaryPort = $targetPort
        ValidationEntryPlanPath = if ($TargetRole -eq 'ShadowsocksLanding') { $ValidationEntryPlanPath } else { $null }
        SourcePlanPath = (Resolve-Path -LiteralPath $SourcePlanPath).Path
        SourcePlanSha256 = (Get-FileHash -LiteralPath $SourcePlanPath -Algorithm SHA256).Hash
        RollbackTimeoutMinutes = 20
        ModuleIds = $moduleIds
        InitialInventory = $initialInventory
        ValidationInventory = $validationInventory
        FinalInventory = $finalInventory
        FinalRole = $finalRole
        KeepExistingProtocols = $true
        RemoveRole = $null
        Status = 'Planned'
        CreatedAt = (Get-Date).ToString('o')
        LocalBackupDirectory = $null
    }
    return $plan
}

function New-MxhProtocolLifecyclePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [Collections.IDictionary]$SourcePlan,
        [Parameter(Mandatory)] [string]$SourcePlanPath,
        [Collections.IDictionary]$SourceState,
        [Collections.IDictionary]$SourceInventory,
        [Parameter(Mandatory)] [ValidateSet('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding')]
        [string]$TargetRole,
        [Parameter(Mandatory)] [ValidateSet('Enable', 'Disable', 'Uninstall')]
        [string]$Operation
    )

    $initialInventory = if ($SourceInventory) {
        Get-MxhProtocolInventory -Plan $SourcePlan -State $SourceState -RemoteInventory $SourceInventory
    } else {
        Get-MxhProtocolInventory -Plan $SourcePlan -State $SourceState
    }
    $item = $initialInventory[$TargetRole]
    if (-not [bool]$item.Installed) { throw '该协议尚未安装；请使用“安装/补充协议”。' }
    if ($Operation -eq 'Enable' -and [bool]$item.Enabled) { throw '该协议已经启用。' }
    if ($Operation -eq 'Disable' -and -not [bool]$item.Enabled) { throw '该协议已经停用。' }
    if ($Operation -eq 'Uninstall' -and ([bool]$item.Enabled -or [bool]$item.Active)) {
        throw '安全限制：只能卸载已经停用且未运行的协议。请先单独停用或切换。'
    }

    $finalInventory = Copy-MxhHashtable -Value $initialInventory
    if ($Operation -eq 'Enable') {
        $finalInventory[$TargetRole].Enabled = $true
        $finalInventory[$TargetRole].Active = $true
        if ($TargetRole -eq 'RealityEntry') {
            $finalInventory.AnyTlsEntry.Enabled = $false
            $finalInventory.AnyTlsEntry.Active = $false
        }
        elseif ($TargetRole -eq 'AnyTlsEntry') {
            $finalInventory.RealityEntry.Enabled = $false
            $finalInventory.RealityEntry.Active = $false
        }
    }
    elseif ($Operation -eq 'Disable') {
        $finalInventory[$TargetRole].Enabled = $false
        $finalInventory[$TargetRole].Active = $false
    }
    else {
        $finalInventory[$TargetRole].Installed = $false
        $finalInventory[$TargetRole].Enabled = $false
        $finalInventory[$TargetRole].Active = $false
    }

    $sourceRole = Get-MxhInventoryPrimaryRole -Inventory $initialInventory
    $finalRole = Get-MxhInventoryPrimaryRole -Inventory $finalInventory
    $plan = Copy-MxhHashtable -Value $SourcePlan
    # Role is the execution role until commit; commit writes FinalRole.
    $plan.Role = $TargetRole
    $plan.UpdatedAt = (Get-Date).ToString('o')
    $plan['ProtocolInventory'] = $finalInventory
    if ($plan.Contains('AnyTls')) { $plan.AnyTls.Enabled = [bool]$finalInventory.AnyTlsEntry.Installed }

    $sourcePort = if ($sourceRole -eq 'ShadowsocksLanding') { [int]$SourcePlan.Ports.LandingShadowsocks } else { 443 }
    $targetPort = if ($TargetRole -eq 'ShadowsocksLanding') { [int]$SourcePlan.Ports.LandingShadowsocks } else { 443 }
    $moduleIds = @(Get-MxhMigrationModuleIds -TargetRole $TargetRole -Operation $Operation)
    $plan['Migration'] = [ordered]@{
        Enabled = $true
        SchemaVersion = 2
        Mode = 'ProtocolLifecycle'
        Operation = $Operation
        SourceRole = $sourceRole
        TargetRole = $TargetRole
        SourceService = if ($sourceRole -eq 'MonitorOnly') { $null } else { Get-MxhProtocolServiceName -Role $sourceRole }
        TargetService = Get-MxhProtocolServiceName -Role $TargetRole
        SourcePrimaryPort = $sourcePort
        TargetPrimaryPort = $targetPort
        ValidationEntryPlanPath = if ($TargetRole -eq 'ShadowsocksLanding') {
            if ($SourcePlan.Shadowsocks.Contains('ValidationEntryPlanPath') -and $SourcePlan.Shadowsocks.ValidationEntryPlanPath) {
                [string]$SourcePlan.Shadowsocks.ValidationEntryPlanPath
            }
            elseif ($SourcePlan.Contains('Migration') -and $SourcePlan.Migration.Contains('ValidationEntryPlanPath')) {
                [string]$SourcePlan.Migration.ValidationEntryPlanPath
            }
            else { $null }
        }
        else { $null }
        SourcePlanPath = (Resolve-Path -LiteralPath $SourcePlanPath).Path
        SourcePlanSha256 = (Get-FileHash -LiteralPath $SourcePlanPath -Algorithm SHA256).Hash
        RollbackTimeoutMinutes = 20
        ModuleIds = $moduleIds
        InitialInventory = $initialInventory
        ValidationInventory = $finalInventory
        FinalInventory = $finalInventory
        FinalRole = $finalRole
        KeepExistingProtocols = $true
        RemoveRole = if ($Operation -eq 'Uninstall') { $TargetRole } else { $null }
        Status = 'Planned'
        CreatedAt = (Get-Date).ToString('o')
        LocalBackupDirectory = $null
    }
    return $plan
}

function New-MxhNetworkTuningPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [Collections.IDictionary]$SourcePlan,
        [Parameter(Mandatory)] [string]$SourcePlanPath,
        [Collections.IDictionary]$SourceState,
        [Collections.IDictionary]$SourceInventory,
        [Parameter(Mandatory)] [ValidateSet('RealityEntry', 'AnyTlsEntry', 'ShadowsocksLanding', 'MonitorOnly')]
        [string]$TuningRole,
        [Parameter(Mandatory)] [Collections.IDictionary]$NetworkTuning
    )

    $inventory = if ($SourceInventory) {
        Get-MxhProtocolInventory -Plan $SourcePlan -State $SourceState -RemoteInventory $SourceInventory
    } else {
        Get-MxhProtocolInventory -Plan $SourcePlan -State $SourceState
    }
    if ($TuningRole -ne 'MonitorOnly' -and -not [bool]$inventory[$TuningRole].Installed) {
        throw '网络调优角色必须是该 VPS 已安装的协议角色。'
    }
    $plan = Copy-MxhHashtable -Value $SourcePlan
    $plan.Role = $TuningRole
    $plan.UpdatedAt = (Get-Date).ToString('o')
    $plan.NetworkTuning = Copy-MxhHashtable -Value $NetworkTuning
    $plan['ProtocolInventory'] = Copy-MxhHashtable -Value $inventory
    $primaryRole = Get-MxhInventoryPrimaryRole -Inventory $inventory
    $primaryPort = if ($primaryRole -eq 'ShadowsocksLanding') { [int]$plan.Ports.LandingShadowsocks } elseif ($primaryRole -eq 'MonitorOnly') { 0 } else { 443 }
    $plan['Migration'] = [ordered]@{
        Enabled = $true
        SchemaVersion = 2
        Mode = 'ProtocolLifecycle'
        Operation = 'NetworkTune'
        SourceRole = $primaryRole
        TargetRole = $TuningRole
        SourceService = if ($primaryRole -eq 'MonitorOnly') { $null } else { Get-MxhProtocolServiceName -Role $primaryRole }
        TargetService = if ($TuningRole -eq 'MonitorOnly') { $null } else { Get-MxhProtocolServiceName -Role $TuningRole }
        SourcePrimaryPort = $primaryPort
        TargetPrimaryPort = $primaryPort
        ValidationEntryPlanPath = $null
        SourcePlanPath = (Resolve-Path -LiteralPath $SourcePlanPath).Path
        SourcePlanSha256 = (Get-FileHash -LiteralPath $SourcePlanPath -Algorithm SHA256).Hash
        RollbackTimeoutMinutes = 20
        ModuleIds = @(Get-MxhMigrationModuleIds -TargetRole $TuningRole -Operation NetworkTune)
        InitialInventory = $inventory
        ValidationInventory = $inventory
        FinalInventory = $inventory
        FinalRole = $primaryRole
        KeepExistingProtocols = $true
        RemoveRole = $null
        Status = 'Planned'
        CreatedAt = (Get-Date).ToString('o')
        LocalBackupDirectory = $null
    }
    return $plan
}

function New-VpsNetworkTuningPlanInteractive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ProjectRoot,
        [string]$PlanPath,
        [switch]$DryRun
    )

    $source = Read-MxhProtocolMigrationSource -ProjectRoot $ProjectRoot -PlanPath $PlanPath -DryRun:$DryRun
    $inventory = Get-MxhProtocolInventory -Plan $source.Plan -State $source.State -RemoteInventory $source.Inventory
    $roles = @(Get-MxhManagedProtocolRoles | Where-Object { $inventory[$_].Installed })
    if ($roles.Count -eq 0) { $roles = @('MonitorOnly') }
    $defaultRole = Get-MxhInventoryPrimaryRole -Inventory $inventory
    if ($defaultRole -notin $roles) { $defaultRole = $roles[0] }
    if ($roles.Count -gt 1) {
        $labels = @($roles | ForEach-Object { Get-MxhProtocolRoleLabel -Role $_ })
        $default = [Array]::IndexOf($roles, $defaultRole) + 1
        $roleChoice = Read-VpsMenu '按哪个主要角色计算保守队列下限' $labels $default -AllowBack
        $tuningRole = $roles[$roleChoice - 1]
    }
    else { $tuningRole = $roles[0] }

    $settings = Read-VpsNetworkTuningSettings -Role $tuningRole -AllowBack
    $plan = New-MxhNetworkTuningPlan -SourcePlan $source.Plan -SourcePlanPath $source.PlanPath `
        -SourceState $source.State -SourceInventory $source.Inventory -TuningRole $tuningRole -NetworkTuning $settings
    Write-Host ''
    Write-Host '独立网络调优摘要' -ForegroundColor White
    Write-Host "  计算角色：$(Get-MxhProtocolRoleLabel -Role $tuningRole)"
    if ($settings.Mode -eq 'AdaptiveConservative') {
        Write-Host "  模式：已知带宽/RTT 自适应（$($settings.BandwidthMbps) Mbps / $($settings.ReferenceRttMs) ms）"
    }
    else {
        Write-Host '  模式：基础保守（无需 RTT，不调整 TCP 缓冲区上限）'
    }
    Write-Host '  协议、端口和防火墙：不改变'
    Write-Host '  回滚：应用前备份 sysctl，并启用 20 分钟服务端恢复保护'
    [void](Read-VpsMenu '请核对网络调优方案' @('确认并执行') 1 -AllowBack)
    return [pscustomobject]@{ Plan = $plan; Source = $source }
}

function New-MxhProtocolMigrationDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Source,
        [Parameter(Mandatory)] [string]$ProjectRoot,
        [ValidateSet('InstallActivate', 'InstallStandby')]
        [string]$Operation = 'InstallActivate'
    )

    $versions = Get-VpsVersions -ProjectRoot $ProjectRoot
    $defaultTransitTag = [string](Get-MxhClientLayoutTemplate -ProjectRoot $ProjectRoot).Value.region_groups[0]
    $sourcePlan = $Source.Plan
    $initialInventory = Get-MxhProtocolInventory -Plan $sourcePlan -State $Source.State -RemoteInventory $Source.Inventory
    $sourceRole = Get-MxhInventoryPrimaryRole -Inventory $initialInventory
    $allRoles = @(Get-MxhManagedProtocolRoles)
    $targetRoles = @($allRoles | Where-Object { -not [bool]$initialInventory[$_].Installed })
    if ($targetRoles.Count -eq 0) {
        Write-VpsUi '三种协议都已安装；请使用“切换/启停已安装协议”，或先卸载后重装。' Warning
        throw [InvalidOperationException]::new($script:VpsWizardBackMarker)
    }
    $preferredTarget = if ($sourceRole -eq 'RealityEntry') { 'AnyTlsEntry' } else { 'RealityEntry' }
    if ($preferredTarget -notin $targetRoles) { $preferredTarget = $targetRoles[0] }

    $sourceActivePorts = @([int]$sourcePlan.Ports.SshPrimary, [int]$sourcePlan.Ports.SshRescue)
    if ([bool]$initialInventory.RealityEntry.Installed -or [bool]$initialInventory.AnyTlsEntry.Installed) { $sourceActivePorts += 443 }
    if ([bool]$initialInventory.RealityEntry.Installed -and $sourcePlan.Ports.Contains('XrayBackup') -and $sourcePlan.Ports.XrayBackup) {
        $sourceActivePorts += [int]$sourcePlan.Ports.XrayBackup
    }
    if ([bool]$initialInventory.ShadowsocksLanding.Installed -and $sourcePlan.Ports.Contains('LandingShadowsocks') -and $sourcePlan.Ports.LandingShadowsocks) {
        $sourceActivePorts += [int]$sourcePlan.Ports.LandingShadowsocks
    }
    $sourceActivePorts = @($sourceActivePorts | Sort-Object -Unique)

    $priorXrayBackup = if ($sourcePlan.Ports.Contains('XrayBackup') -and $sourcePlan.Ports.XrayBackup) { [int]$sourcePlan.Ports.XrayBackup } else { 0 }
    $xrayBackup = if ($priorXrayBackup -ge 20000 -and $priorXrayBackup -le 59999 -and $priorXrayBackup -notin $sourceActivePorts) {
        $priorXrayBackup
    } else { Get-VpsRandomPort -Exclude $sourceActivePorts }
    $portExclusions = @($sourceActivePorts + $xrayBackup | Sort-Object -Unique)
    $priorLandingPort = if ($sourcePlan.Ports.Contains('LandingShadowsocks') -and $sourcePlan.Ports.LandingShadowsocks) { [int]$sourcePlan.Ports.LandingShadowsocks } else { 0 }
    $landingPort = if ($priorLandingPort -ge 20000 -and $priorLandingPort -le 59999 -and $priorLandingPort -notin $sourceActivePorts) {
        $priorLandingPort
    } else { Get-VpsRandomPort -Exclude $portExclusions }

    $realityMode = if ($sourcePlan.Contains('Reality') -and $sourcePlan.Reality.Contains('TargetMode')) {
        [string]$sourcePlan.Reality.TargetMode
    } else { 'ExternalAudited' }
    $realityTarget = if ($sourcePlan.Contains('Reality') -and $sourcePlan.Reality.Contains('Target')) { [string]$sourcePlan.Reality.Target } else { $null }
    $anyTlsPadding = if ($sourcePlan.Contains('AnyTls') -and $sourcePlan.AnyTls.Contains('PaddingScheme') -and @($sourcePlan.AnyTls.PaddingScheme).Count -gt 0) {
        @($sourcePlan.AnyTls.PaddingScheme)
    } else { @(New-MxhAnyTlsPaddingScheme) }
    $allowlistInput = if ($sourcePlan.Contains('Shadowsocks') -and
        $sourcePlan.Shadowsocks.Contains('TrustedEntryIPv4s') -and $sourcePlan.Shadowsocks.Contains('TrustedEntryIPv6s')) {
        (@($sourcePlan.Shadowsocks.TrustedEntryIPv4s) + @($sourcePlan.Shadowsocks.TrustedEntryIPv6s)) -join ','
    } else { $null }
    $trustedEntryIps = if ($allowlistInput) { ConvertTo-VpsIpAllowlist $allowlistInput } else { [ordered]@{ IPv4 = @(); IPv6 = @() } }
    $sourceAdaptive = $sourcePlan.Contains('NetworkTuning') -and $sourcePlan.NetworkTuning.Mode -eq 'AdaptiveConservative'

    $wizard = [ordered]@{
        TargetRole = $preferredTarget
        XrayBackup = $xrayBackup
        LandingPort = $landingPort
        RealityTargetMode = $realityMode
        RealityTarget = $realityTarget
        ForceIpv4 = if ($sourcePlan.Contains('Reality') -and $sourcePlan.Reality.Contains('ForceIpv4Egress')) { [bool]$sourcePlan.Reality.ForceIpv4Egress } elseif ($sourcePlan.Contains('AnyTls') -and $sourcePlan.AnyTls.Contains('ForceIpv4Egress')) { [bool]$sourcePlan.AnyTls.ForceIpv4Egress } else { $true }
        AnyTlsServerName = if ($sourcePlan.Contains('AnyTls') -and $sourcePlan.AnyTls.Contains('ServerName')) { [string]$sourcePlan.AnyTls.ServerName } else { $null }
        EchPublicName = if ($sourcePlan.Contains('AnyTls') -and $sourcePlan.AnyTls.Contains('EchPublicName')) { [string]$sourcePlan.AnyTls.EchPublicName } else { $null }
        AnyTlsPaddingScheme = $anyTlsPadding
        XrayVersionChannel = 'FixedVerified'
        XrayVersion = [string]$versions.xray.version
        CloudflareZoneName = if ($sourcePlan.Contains('TrustedTls') -and $sourcePlan.TrustedTls.Contains('ZoneName')) { [string]$sourcePlan.TrustedTls.ZoneName } else { $null }
        CertbotEmail = if ($sourcePlan.Contains('TrustedTls') -and $sourcePlan.TrustedTls.Contains('CertbotEmail')) { [string]$sourcePlan.TrustedTls.CertbotEmail } else { $null }
        CloudflareTokenFile = if ($sourcePlan.Contains('TrustedTls') -and $sourcePlan.TrustedTls.Contains('CloudflareTokenFile')) { [string]$sourcePlan.TrustedTls.CloudflareTokenFile } else { $null }
        AllowlistInput = $allowlistInput
        TrustedEntryIps = $trustedEntryIps
        ClientTransitTag = if ($sourcePlan.Contains('Shadowsocks') -and $sourcePlan.Shadowsocks.Contains('ClientTransitTag') -and $sourcePlan.Shadowsocks.ClientTransitTag) { [string]$sourcePlan.Shadowsocks.ClientTransitTag } else { $defaultTransitTag }
        ValidationEntryPlanPath = $null
        SecondaryIpv6Enabled = if ($sourcePlan.Contains('Shadowsocks') -and $sourcePlan.Shadowsocks.Contains('SecondaryIpv6Enabled')) { [bool]$sourcePlan.Shadowsocks.SecondaryIpv6Enabled } else { $false }
        SecondaryIpv6Address = if ($sourcePlan.Contains('Shadowsocks') -and $sourcePlan.Shadowsocks.Contains('SecondaryIpv6Address')) { [string]$sourcePlan.Shadowsocks.SecondaryIpv6Address } else { $null }
        SecondaryBindInterface = if ($sourcePlan.Contains('Shadowsocks') -and $sourcePlan.Shadowsocks.Contains('SecondaryBindInterface')) { [string]$sourcePlan.Shadowsocks.SecondaryBindInterface } else { $null }
        NetworkAdaptive = $sourceAdaptive
        BandwidthMbps = if ($sourceAdaptive) { [int]$sourcePlan.NetworkTuning.BandwidthMbps } else { $null }
        ReferenceRttMs = if ($sourceAdaptive) { [int]$sourcePlan.NetworkTuning.ReferenceRttMs } else { $null }
    }

    $steps = @(
        [pscustomobject]@{
            Id = 'target-role'; ShouldRun = { $true }; Run = {
                $labels = @($targetRoles | ForEach-Object { Get-MxhProtocolRoleLabel -Role $_ })
                $default = [Array]::IndexOf($targetRoles, [string]$wizard.TargetRole) + 1
                if ($default -lt 1) { $default = 1 }
                $choice = Read-VpsMenu '安装哪一种新协议' $labels $default -AllowBack
                $newRole = $targetRoles[$choice - 1]
                if ($wizard.TargetRole -ne $newRole) {
                    $wizard.TargetRole = $newRole
                    $wizard.NetworkAdaptive = $sourceAdaptive
                    $wizard.BandwidthMbps = if ($sourceAdaptive) { [int]$sourcePlan.NetworkTuning.BandwidthMbps } else { $null }
                    $wizard.ReferenceRttMs = if ($sourceAdaptive) { [int]$sourcePlan.NetworkTuning.ReferenceRttMs } else { $null }
                }
            }
        },
        [pscustomobject]@{
            Id = 'xray-backup'; ShouldRun = { $wizard.TargetRole -eq 'RealityEntry' }; Run = {
                $wizard.XrayBackup = [int](Read-VpsText '新的 Xray 救援端口' -Default ([string]$wizard.XrayBackup) -AllowBack -Validate {
                    param($v)
                    $n = 0
                    [int]::TryParse($v, [ref]$n) -and $n -ge 20000 -and $n -le 59999 -and $n -notin $sourceActivePorts
                } -ValidationMessage '端口必须在 20000–59999，且不能与当前仍在运行的服务或 SSH 端口冲突。')
            }
        },
        [pscustomobject]@{
            Id = 'xray-version'; ShouldRun = { $wizard.TargetRole -eq 'RealityEntry' }; Run = {
                $default = if ($wizard.XrayVersionChannel -eq 'LatestStable') { 2 } else { 1 }
                $choice = Read-VpsMenu 'Xray 版本通道' @(
                    "当前固定验证版（$($versions.xray.version)，推荐）",
                    'XTLS/Xray-core 官方最新稳定版'
                ) $default -AllowBack
                $wizard.XrayVersionChannel = if ($choice -eq 2) { 'LatestStable' } else { 'FixedVerified' }
                $wizard.XrayVersion = Resolve-VpsXrayVersion -ProjectRoot $ProjectRoot -Channel $wizard.XrayVersionChannel
                Show-VpsXrayVersionSelection -Channel $wizard.XrayVersionChannel `
                    -ResolvedVersion $wizard.XrayVersion -FixedVersion ([string]$versions.xray.version) -Action '部署'
            }
        },
        [pscustomobject]@{
            Id = 'reality-target-mode'; ShouldRun = { $wizard.TargetRole -eq 'RealityEntry' }; Run = {
                $default = if ($wizard.RealityTargetMode -eq 'LocalOwnedTls') { 2 } else { 1 }
                $choice = Read-VpsMenu 'REALITY target 模式' @(
                    '外部大学/机构/企业 target（严格审计）',
                    '自有域名 + 本机静态 HTTPS target'
                ) $default -AllowBack
                $newMode = if ($choice -eq 2) { 'LocalOwnedTls' } else { 'ExternalAudited' }
                if ($wizard.RealityTargetMode -ne $newMode) {
                    $wizard.RealityTargetMode = $newMode
                    $wizard.RealityTarget = $null
                    $wizard.CloudflareZoneName = $null
                    $wizard.CertbotEmail = $null
                    $wizard.CloudflareTokenFile = $null
                }
            }
        },
        [pscustomobject]@{
            Id = 'reality-target'; ShouldRun = { $wizard.TargetRole -eq 'RealityEntry' }; Run = {
                $prompt = if ($wizard.RealityTargetMode -eq 'LocalOwnedTls') { '本机 HTTPS target 域名' } else { 'REALITY 外部 target 域名' }
                $wizard.RealityTarget = Read-VpsText $prompt -Default ([string]$wizard.RealityTarget) -AllowBack `
                    -Validate ${function:Test-VpsHostName} -ValidationMessage '请输入不含协议、路径和端口的规范域名。'
            }
        },
        [pscustomobject]@{
            Id = 'reality-target-confirm'; ShouldRun = { $wizard.TargetRole -eq 'RealityEntry' -and $wizard.RealityTargetMode -eq 'ExternalAudited' }; Run = {
                if (-not (Read-VpsYesNo '确认该候选不是个人小站，并允许从 VPS 严格审计？' $true -AllowBack)) {
                    throw [InvalidOperationException]::new($script:VpsWizardBackMarker)
                }
            }
        },
        [pscustomobject]@{
            Id = 'anytls-server-name'; ShouldRun = { $wizard.TargetRole -eq 'AnyTlsEntry' }; Run = {
                $wizard.AnyTlsServerName = Read-VpsText 'AnyTLS 证书域名/内部 SNI' -Default ([string]$wizard.AnyTlsServerName) -AllowBack `
                    -Validate ${function:Test-VpsHostName} -ValidationMessage '请输入规范域名。'
            }
        },
        [pscustomobject]@{
            Id = 'ech-public-name'; ShouldRun = { $wizard.TargetRole -eq 'AnyTlsEntry' }; Run = {
                $wizard.EchPublicName = Read-VpsText 'ECH 对外 public name' -Default ([string]$wizard.EchPublicName) -AllowBack -Validate {
                    param($v) (Test-VpsHostName $v) -and $v -ne $wizard.AnyTlsServerName
                } -ValidationMessage '请输入与 AnyTLS 内部 SNI 不同的规范域名。'
            }
        },
        [pscustomobject]@{
            Id = 'force-ipv4'; ShouldRun = { $wizard.TargetRole -in @('RealityEntry', 'AnyTlsEntry') }; Run = {
                $wizard.ForceIpv4 = Read-VpsYesNo '是否强制代理网站流量从 VPS IPv4 出口？' ([bool]$wizard.ForceIpv4) -AllowBack
            }
        },
        [pscustomobject]@{
            Id = 'cloudflare-zone'; ShouldRun = {
                $wizard.TargetRole -eq 'AnyTlsEntry' -or ($wizard.TargetRole -eq 'RealityEntry' -and $wizard.RealityTargetMode -eq 'LocalOwnedTls')
            }; Run = {
                $domain = if ($wizard.TargetRole -eq 'AnyTlsEntry') { [string]$wizard.AnyTlsServerName } else { [string]$wizard.RealityTarget }
                $labels = @($domain -split '\.')
                $suggested = if ($labels.Count -ge 2) { ($labels[-2..-1] -join '.') } else { $domain }
                $default = if ($wizard.CloudflareZoneName) { [string]$wizard.CloudflareZoneName } else { $suggested }
                $wizard.CloudflareZoneName = Read-VpsText 'Cloudflare Zone 根域名' -Default $default -AllowBack `
                    -Validate ${function:Test-VpsHostName} -ValidationMessage '请输入 Cloudflare 中的完整根域名。'
            }
        },
        [pscustomobject]@{
            Id = 'certbot-email'; ShouldRun = {
                $wizard.TargetRole -eq 'AnyTlsEntry' -or ($wizard.TargetRole -eq 'RealityEntry' -and $wizard.RealityTargetMode -eq 'LocalOwnedTls')
            }; Run = {
                $wizard.CertbotEmail = Read-VpsText 'ACME/Let''s Encrypt 联系邮箱' -Default ([string]$wizard.CertbotEmail) -AllowBack -Validate {
                    param($v) $v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$'
                } -ValidationMessage '请输入有效邮箱地址。'
            }
        },
        [pscustomobject]@{
            Id = 'cloudflare-token'; ShouldRun = {
                $wizard.TargetRole -eq 'AnyTlsEntry' -or ($wizard.TargetRole -eq 'RealityEntry' -and $wizard.RealityTargetMode -eq 'LocalOwnedTls')
            }; Run = {
                $default = if ($wizard.CloudflareTokenFile) { [string]$wizard.CloudflareTokenFile } else {
                    $tokenRoot = if ($sourcePlan.Paths.Contains('InstanceDirectory')) { [string]$sourcePlan.Paths.InstanceDirectory } else { [string]$sourcePlan.Paths.Archive }
                    Join-Path $tokenRoot 'cloudflare-certbot-token.private.txt'
                }
                $value = Read-VpsText 'Cloudflare Certbot Token 本地私有文件' -Default $default -AllowBack `
                    -Validate { param($v) Test-VpsExistingInputPath -Value $v -PathType Leaf } `
                    -ValidationMessage '找不到 Token 文件，或路径混用了 / 与 \。'
                $wizard.CloudflareTokenFile = (Resolve-Path -LiteralPath (ConvertTo-VpsInputPath -Value $value)).Path
            }
        },
        [pscustomobject]@{
            Id = 'landing-port'; ShouldRun = { $wizard.TargetRole -eq 'ShadowsocksLanding' }; Run = {
                $wizard.LandingPort = [int](Read-VpsText 'Shadowsocks TCP/UDP 端口' -Default ([string]$wizard.LandingPort) -AllowBack -Validate {
                    param($v)
                    $n = 0
                    [int]::TryParse($v, [ref]$n) -and $n -ge 20000 -and $n -le 59999 -and $n -notin $sourceActivePorts
                } -ValidationMessage '端口必须在 20000–59999，且不能与当前仍在运行的服务或 SSH 端口冲突。')
            }
        },
        [pscustomobject]@{
            Id = 'landing-allowlist'; ShouldRun = { $wizard.TargetRole -eq 'ShadowsocksLanding' }; Run = {
                while ($true) {
                    try {
                        $value = Read-VpsText '允许连接落地端口的入口 VPS 公网 IP（多个用逗号分隔）' `
                            -Default ([string]$wizard.AllowlistInput) -AllowBack
                        $wizard.TrustedEntryIps = ConvertTo-VpsIpAllowlist $value
                        $wizard.AllowlistInput = $value
                        break
                    }
                    catch {
                        if (Test-VpsWizardBackError $_) { throw }
                        Write-VpsUi $_.Exception.Message Warning
                    }
                }
            }
        },
        [pscustomobject]@{
            Id = 'landing-transit-tag'; ShouldRun = { $wizard.TargetRole -eq 'ShadowsocksLanding' }; Run = {
                $wizard.ClientTransitTag = Read-VpsText '客户端链式连接使用的入口组/tag' -Default ([string]$wizard.ClientTransitTag) -AllowBack -Validate {
                    param($v) -not [string]::IsNullOrWhiteSpace($v) -and $v -notin @('Proxy', "$($sourcePlan.NodeName)-IPv4", "$($sourcePlan.NodeName)-IPv6")
                } -ValidationMessage '入口组/tag 不能与生成的落地节点名称重复。'
            }
        },
        [pscustomobject]@{
            Id = 'landing-validation-entry'; ShouldRun = { $wizard.TargetRole -eq 'ShadowsocksLanding' }; Run = {
                while ($true) {
                    try {
                        $value = Read-VpsText '用于链式实测的入口 VPS deployment-plan.json' `
                            -Default ([string]$wizard.ValidationEntryPlanPath) -AllowBack -Validate {
                                param($v) Test-VpsExistingInputPath -Value $v -PathType Leaf
                            } -ValidationMessage '找不到该入口计划文件，或路径混用了 / 与 \。'
                        $resolved = (Resolve-Path -LiteralPath (ConvertTo-VpsInputPath -Value $value)).Path
                        Test-MxhMigrationValidationEntryPlan -PlanPath $resolved `
                            -LandingServerIpv4 ([string]$sourcePlan.Server.IPv4) `
                            -AllowedEntryIpv4s @($wizard.TrustedEntryIps.IPv4) | Out-Null
                        $wizard.ValidationEntryPlanPath = $resolved
                        break
                    }
                    catch {
                        if (Test-VpsWizardBackError $_) { throw }
                        Write-VpsUi $_.Exception.Message Warning
                    }
                }
            }
        },
        [pscustomobject]@{
            Id = 'secondary-ipv6-enabled'; ShouldRun = { $wizard.TargetRole -eq 'ShadowsocksLanding' -and [bool]$sourcePlan.Server.IPv6 }; Run = {
                $wizard.SecondaryIpv6Enabled = Read-VpsYesNo '是否增加独立 IPv6 出口用户？' ([bool]$wizard.SecondaryIpv6Enabled) -AllowBack
                if (-not $wizard.SecondaryIpv6Enabled) {
                    $wizard.SecondaryIpv6Address = $null
                    $wizard.SecondaryBindInterface = $null
                }
            }
        },
        [pscustomobject]@{
            Id = 'secondary-ipv6-address'; ShouldRun = { $wizard.TargetRole -eq 'ShadowsocksLanding' -and [bool]$sourcePlan.Server.IPv6 -and [bool]$wizard.SecondaryIpv6Enabled }; Run = {
                $default = if ($wizard.SecondaryIpv6Address) { [string]$wizard.SecondaryIpv6Address } else { [string]$sourcePlan.Server.IPv6 }
                $wizard.SecondaryIpv6Address = Read-VpsText 'IPv6 出口源地址' -Default $default -AllowBack `
                    -Validate { param($v) Test-VpsIpAddress $v IPv6 } -ValidationMessage '请输入本机实际配置的 IPv6 地址。'
            }
        },
        [pscustomobject]@{
            Id = 'secondary-bind-interface'; ShouldRun = { $wizard.TargetRole -eq 'ShadowsocksLanding' -and [bool]$sourcePlan.Server.IPv6 -and [bool]$wizard.SecondaryIpv6Enabled }; Run = {
                $value = Read-VpsText 'IPv6 出口接口（一般留空）' -Default ([string]$wizard.SecondaryBindInterface) -AllowEmpty -AllowBack `
                    -Validate { param($v) -not $v -or $v -match '^[A-Za-z0-9_.:-]{1,32}$' }
                $wizard.SecondaryBindInterface = if ($value) { $value } else { $null }
            }
        },
        [pscustomobject]@{
            Id = 'network-adaptive'; ShouldRun = { $false }; Run = {
                $wizard.NetworkAdaptive = Read-VpsYesNo '是否为目标角色重新应用保守自适应网络调优？' ([bool]$wizard.NetworkAdaptive) -AllowBack
                if (-not $wizard.NetworkAdaptive) {
                    $wizard.BandwidthMbps = $null
                    $wizard.ReferenceRttMs = $null
                }
            }
        },
        [pscustomobject]@{
            Id = 'network-bandwidth'; ShouldRun = { $false }; Run = {
                $wizard.BandwidthMbps = [int](Read-VpsText '套餐标称带宽（Mbps）' -Default ([string]$wizard.BandwidthMbps) -AllowBack -Validate {
                    param($v) $n = 0; [int]::TryParse($v, [ref]$n) -and $n -ge 1 -and $n -le 100000
                } -ValidationMessage '请输入 1–100000 之间的整数 Mbps。')
            }
        },
        [pscustomobject]@{
            Id = 'network-rtt'; ShouldRun = { $false }; Run = {
                $prompt = if ($wizard.TargetRole -in @('RealityEntry', 'AnyTlsEntry')) { '主要使用地到该入口 VPS 的典型 RTT（ms）' } else { '常用入口 VPS 到该落地机的典型 RTT（ms）' }
                $wizard.ReferenceRttMs = [int](Read-VpsText $prompt -Default ([string]$wizard.ReferenceRttMs) -AllowBack -Validate {
                    param($v) $n = 0; [int]::TryParse($v, [ref]$n) -and $n -ge 1 -and $n -le 2000
                } -ValidationMessage '请输入 1–2000 之间的整数毫秒值。')
            }
        }
    )

    $buildPlan = {
        $trustedTls = $wizard.TargetRole -eq 'AnyTlsEntry' -or `
            ($wizard.TargetRole -eq 'RealityEntry' -and $wizard.RealityTargetMode -eq 'LocalOwnedTls')
        $network = Copy-MxhHashtable -Value $sourcePlan.NetworkTuning
        $targetPort = if ($wizard.TargetRole -eq 'RealityEntry') { [int]$wizard.XrayBackup } elseif ($wizard.TargetRole -eq 'ShadowsocksLanding') { [int]$wizard.LandingPort } else { 443 }
        $realityServerName = if ($wizard.TargetRole -eq 'RealityEntry') { [string]$wizard.RealityTarget } else { $null }
        $realityAddress = if ($wizard.TargetRole -eq 'RealityEntry' -and $wizard.RealityTargetMode -eq 'LocalOwnedTls') {
            '127.0.0.1:8443'
        } elseif ($wizard.TargetRole -eq 'RealityEntry') { "$($wizard.RealityTarget):443" } else { $null }
        New-MxhProtocolMigrationPlan -SourcePlan $sourcePlan -SourcePlanPath $Source.PlanPath `
            -SourceState $Source.State -SourceInventory $Source.Inventory `
            -TargetRole $wizard.TargetRole -Operation $Operation -TargetServicePort $targetPort `
            -RealityTargetMode $wizard.RealityTargetMode -RealityTarget $wizard.RealityTarget `
            -RealityServerName $realityServerName -RealityTargetAddress $realityAddress `
            -XrayVersion $wizard.XrayVersion -XrayVersionChannel $wizard.XrayVersionChannel `
            -AnyTlsServerName $wizard.AnyTlsServerName -EchPublicName $wizard.EchPublicName `
            -SingBoxVersion ([string]$versions.sing_box.version) `
            -AnyTlsPaddingScheme @($wizard.AnyTlsPaddingScheme) -ForceIpv4Egress ([bool]$wizard.ForceIpv4) `
            -TrustedTlsEnabled $trustedTls -CloudflareZoneName $wizard.CloudflareZoneName `
            -CertbotEmail $wizard.CertbotEmail -CloudflareTokenFile $wizard.CloudflareTokenFile `
            -TrustedEntryIps $wizard.TrustedEntryIps -ClientTransitTag $wizard.ClientTransitTag `
            -ValidationEntryPlanPath $wizard.ValidationEntryPlanPath `
            -SecondaryIpv6Enabled ([bool]$wizard.SecondaryIpv6Enabled) `
            -SecondaryIpv6Address $wizard.SecondaryIpv6Address -SecondaryBindInterface $wizard.SecondaryBindInterface `
            -NetworkTuning $network
    }

    $index = 0
    while ($true) {
        while ($index -lt $steps.Count) {
            $step = $steps[$index]
            if (-not (& $step.ShouldRun)) { $index++; continue }
            try { & $step.Run; $index++ }
            catch {
                if (-not (Test-VpsWizardBackError $_)) { throw }
                $previous = -1
                for ($candidate = $index - 1; $candidate -ge 0; $candidate--) {
                    if (& $steps[$candidate].ShouldRun) { $previous = $candidate; break }
                }
                if ($previous -lt 0) { throw }
                $index = $previous
                Write-VpsUi "返回协议安装上一项：$($steps[$previous].Id)" Muted
            }
        }

        $plan = & $buildPlan
        Write-Host ''
        Write-Host '协议安装摘要' -ForegroundColor White
        Write-Host "  实例：$($plan.Provider) / $($plan.Instance)"
        Write-Host "  当前主角色：$(Get-MxhProtocolRoleLabel -Role $sourceRole)"
        Write-Host "  新安装协议：$(Get-MxhProtocolRoleLabel -Role ([string]$plan.Role))"
        $installStateText = if ($Operation -eq 'InstallStandby') {
            '新协议保留为已安装但停用；恢复当前运行状态'
        }
        elseif ([string]$plan.Role -eq 'ShadowsocksLanding') {
            '启用新的落地协议；现有 Reality/AnyTLS 入口状态保持不变'
        }
        else {
            '启用新入口协议；冲突的 TCP 443 入口保留安装文件但停用'
        }
        Write-Host "  安装后状态：$installStateText"
        Write-Host '  网络参数：保持现状；如需调整请从主菜单进入“调整网络参数”'
        Write-Host "  SSH：保留 $($plan.Ports.SshPrimary) + $($plan.Ports.SshRescue)"
        Write-Host "  自动回滚：切换后 20 分钟内未完成验收则恢复源服务和旧 nftables"
        Show-VpsPlanSummary -Plan $plan
        try {
            $choice = Read-VpsMenu '请核对协议安装方案' @(
                '确认并进入协议安装模块计划',
                '取消并返回主菜单'
            ) 1 -AllowBack
        }
        catch {
            if (-not (Test-VpsWizardBackError $_)) { throw }
            $choice = 0
        }
        if ($choice -eq 1) { return [pscustomobject]@{ Plan = $plan; Source = $Source } }
        if ($choice -eq 2) { throw [OperationCanceledException]::new($script:VpsWizardCancelMarker) }
        for ($candidate = $steps.Count - 1; $candidate -ge 0; $candidate--) {
            if (& $steps[$candidate].ShouldRun) { $index = $candidate; break }
        }
    }
}

function New-MxhProtocolStateDetails {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Source)

    $inventory = Get-MxhProtocolInventory -Plan $Source.Plan -State $Source.State -RemoteInventory $Source.Inventory
    while ($true) {
    $actionChoice = Read-VpsMenu '启用或停用协议' @(
        '启用协议（如端口冲突，会停用另一入口协议）',
        '停用协议（保留安装文件）'
    ) 1 -AllowBack
    try {
    $operation = if ($actionChoice -eq 1) { 'Enable' } else { 'Disable' }
    $candidates = @(if ($operation -eq 'Enable') {
            Get-MxhManagedProtocolRoles | Where-Object { $inventory[$_].Installed -and -not $inventory[$_].Enabled }
        } else {
            Get-MxhManagedProtocolRoles | Where-Object { $inventory[$_].Installed -and $inventory[$_].Enabled }
        })
    if ($candidates.Count -eq 0) {
        Write-VpsUi "没有可执行“$operation”的协议。" Warning
        throw [InvalidOperationException]::new($script:VpsWizardBackMarker)
    }
    $labels = @($candidates | ForEach-Object { Get-MxhProtocolRoleLabel -Role $_ })
    while ($true) {
    $choice = Read-VpsMenu '选择协议' $labels 1 -AllowBack
    try {
    $role = $candidates[$choice - 1]
    $plan = New-MxhProtocolLifecyclePlan -SourcePlan $Source.Plan -SourcePlanPath $Source.PlanPath `
        -SourceState $Source.State -SourceInventory $Source.Inventory -TargetRole $role -Operation $operation

    Write-Host ''
    Write-Host '协议状态变更摘要' -ForegroundColor White
    Write-Host "  操作：$(if ($operation -eq 'Enable') { '启用/切换到' } else { '停用' }) $(Get-MxhProtocolRoleLabel -Role $role)"
    if ($operation -eq 'Enable' -and $role -in @('RealityEntry', 'AnyTlsEntry')) {
        Write-Host '  TCP 443：另一个入口协议将保留安装文件，但会停止并取消开机启用'
    }
    if ($operation -eq 'Disable' -and $role -in @('RealityEntry', 'AnyTlsEntry') -and
        (Get-MxhInventoryPrimaryRole -Inventory $plan.Migration.FinalInventory) -eq 'MonitorOnly') {
        Write-VpsUi '执行后不会有入口协议监听 TCP 443；SSH 与其他服务不受影响。' Warning
    }
    Show-MxhProtocolInventory -Inventory $plan.Migration.FinalInventory
    [void](Read-VpsMenu '请核对状态变更' @('确认并执行') 1 -AllowBack)
    return [pscustomobject]@{ Plan = $plan; Source = $Source }
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function New-MxhProtocolUninstallDetails {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Source)

    $inventory = Get-MxhProtocolInventory -Plan $Source.Plan -State $Source.State -RemoteInventory $Source.Inventory
    $candidates = @(Get-MxhManagedProtocolRoles | Where-Object {
            $inventory[$_].Installed -and -not $inventory[$_].Enabled -and -not $inventory[$_].Active
        })
    if ($candidates.Count -eq 0) {
        Write-VpsUi '没有可安全卸载的协议。运行中或已启用的协议必须先通过“切换/启停”停用。' Warning
        throw [InvalidOperationException]::new($script:VpsWizardBackMarker)
    }
    $labels = @($candidates | ForEach-Object { Get-MxhProtocolRoleLabel -Role $_ })
    while ($true) {
    $choice = Read-VpsMenu '选择要卸载的已停用协议' $labels 1 -AllowBack
    try {
    $role = $candidates[$choice - 1]
    $plan = New-MxhProtocolLifecyclePlan -SourcePlan $Source.Plan -SourcePlanPath $Source.PlanPath `
        -SourceState $Source.State -SourceInventory $Source.Inventory -TargetRole $role -Operation Uninstall

    Write-Host ''
    Write-Host '协议卸载摘要' -ForegroundColor White
    Write-Host "  卸载：$(Get-MxhProtocolRoleLabel -Role $role)"
    Write-Host '  删除：该协议的运行时、systemd 单元和服务端配置'
    Write-Host '  保留：共享 Certbot/ACME 环境、历史归档以及本次变更的本地和远端回滚备份'
    Write-Host '  保护：20 分钟自动回滚；活动协议不能直接卸载'
    Show-MxhProtocolInventory -Inventory $plan.Migration.FinalInventory
    $phrase = Read-VpsText '输入 UNINSTALL 确认卸载' -AllowBack
    if ($phrase -cne 'UNINSTALL') {
        Write-VpsUi '确认短语不匹配，未创建卸载计划。' Warning
        throw [InvalidOperationException]::new($script:VpsWizardBackMarker)
    }
    return [pscustomobject]@{ Plan = $plan; Source = $Source }
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function Invoke-MxhProtocolBackupCleanup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Source,
        [Parameter(Mandatory)] [string]$ProjectRoot,
        [switch]$DryRun
    )

    if ($Source.Plan.Contains('Migration') -and [bool]$Source.Plan.Migration.Enabled -and
        [string]$Source.Plan.Migration.Status -notin @('Completed', 'Committed')) {
        throw '存在未完成协议变更，拒绝清理任何备份。'
    }
    $scope = Read-VpsMenu '清理哪些协议变更备份' @(
        '只清理本机备份',
        '只清理 VPS 上的备份',
        '同时清理两处备份'
    ) 1 -AllowBack -HelpText '只清理本工具生成的协议变更备份，不是删除服务。下一步可设置保留份数；删除前会列出范围并要求确认。'
    $keep = [int](Read-VpsText '保留最近几份（0 表示全部删除）' -Default '3' -AllowBack -ZeroIsValue -Validate {
            param($v) $n = 0; [int]::TryParse($v, [ref]$n) -and $n -ge 0 -and $n -le 100
        } -ValidationMessage '请输入 0–100 之间的整数。')

    $archive = [IO.Path]::GetFullPath([string]$Source.Plan.Paths.Archive).TrimEnd('\', '/')
    $localRoot = [IO.Path]::GetFullPath((Join-Path $archive 'migration-backups')).TrimEnd('\', '/')
    $archivePrefix = $archive + [IO.Path]::DirectorySeparatorChar
    if (-not $localRoot.StartsWith($archivePrefix, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $localRoot) -ne 'migration-backups') {
        throw '本地备份根目录校验失败，拒绝清理。'
    }
    $localCandidates = @(if (Test-Path -LiteralPath $localRoot -PathType Container) {
        Get-ChildItem -LiteralPath $localRoot -Directory -Force | Where-Object {
                -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                $_.Name -match '^\d{8}-\d{6}-(?:(?:RealityEntry|AnyTlsEntry|ShadowsocksLanding)-to-(?:RealityEntry|AnyTlsEntry|ShadowsocksLanding)|(?:InstallActivate|InstallStandby|Enable|Disable|Uninstall|Convert)-(?:RealityEntry|AnyTlsEntry|ShadowsocksLanding))$'
            } | Sort-Object LastWriteTimeUtc -Descending
    })
    $localRemove = @($localCandidates | Select-Object -Skip $keep)

    Write-Host ''
    Write-Host '备份清理摘要' -ForegroundColor White
    Write-Host "  保留最近：$keep 份"
    if ($scope -in @(1, 3)) { Write-Host "  本地将删除：$($localRemove.Count) 份（限定于 $localRoot）" }
    if ($scope -in @(2, 3)) { Write-Host '  远端：仅匹配 /root/vps-deploy-backups/<时间戳>/protocol-lifecycle 或旧 protocol-migration' }
    Write-VpsUi '备份清理不可由自动回滚恢复；远端存在活动回滚计时器时会强制拒绝。' Warning
    $phrase = Read-VpsText '输入 DELETE-BACKUPS 确认' -AllowBack
    if ($phrase -cne 'DELETE-BACKUPS') {
        Write-VpsUi '确认短语不匹配，未删除任何备份。' Warning
        return
    }
    if ($DryRun) {
        Write-VpsUi 'DryRun：已完成范围与数量计算，不删除本地或远端备份。' Success
        return
    }

    if ($scope -in @(1, 2, 3)) {
        $context = New-MxhReadonlyContextFromPlan -ProjectRoot $ProjectRoot -PlanPath $Source.PlanPath
        $result = Invoke-VpsRemoteScript -Context $context -Asset 'protocol-backup-prune.sh' -Parameters @{
            KEEP_LATEST = [string]$keep
            CHECK_ONLY = ($scope -eq 1).ToString().ToLowerInvariant()
        } -TimeoutSeconds 300
        if ($result.StdOut -notmatch 'VPSDEPLOY_PROTOCOL_BACKUP_PRUNE_OK') { throw '远端备份清理未返回成功标记。' }
        $removed = Get-VpsMarkerValue $result.StdOut REMOTE_BACKUPS_REMOVED -Required
        if ($scope -in @(2, 3)) { Write-VpsUi "远端已删除 $removed 份协议变更备份。" Success }
    }
    if ($scope -in @(1, 3)) {
        foreach ($directory in $localRemove) {
            $resolved = [IO.Path]::GetFullPath($directory.FullName).TrimEnd('\', '/')
            $rootPrefix = $localRoot + [IO.Path]::DirectorySeparatorChar
            if (-not $resolved.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw '候选备份越出 migration-backups，已停止清理。'
            }
            [IO.Directory]::Delete($resolved, $true)
        }
        Write-VpsUi "本地已删除 $($localRemove.Count) 份协议变更备份。" Success
    }
}

function New-VpsProtocolMigrationPlanInteractive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ProjectRoot,
        [string]$PlanPath,
        [switch]$DryRun
    )

    $candidatePath = $PlanPath
    while ($true) {
        $source = Read-MxhProtocolMigrationSource -ProjectRoot $ProjectRoot -PlanPath $candidatePath -DryRun:$DryRun
        $returnToSource = $false
        while ($true) {
            try {
                $choice = Read-VpsMenu '代理协议管理' @(
                    '安装并启用新协议',
                    '安装备用协议（验证后停用）',
                    '启用或停用已有协议',
                    '卸载已停用协议',
                    '清理旧备份（协议变更）',
                    '更换 VPS'
                ) 1 -AllowBack -HelpText @'
1 安装并启用：安装所选协议并投入使用。Reality 与 AnyTLS 共用 443，启用一个会停用另一个，但不卸载。
2 安装备用：安装并临时启动验证，结束后保留新协议但不启用，恢复原有服务状态；验证期间可能短暂切换服务。
3 启用或停用：只调整已安装协议，不重新安装。Shadowsocks 使用独立端口，可与入口协议同时运行。
4 卸载：仅允许卸载已停用协议；删除该协议的程序和配置，保留回滚备份。
5 清理旧备份：按保留份数删除协议变更备份；从备份恢复请进入运维中心。
6 更换 VPS：重新选择部署计划文件。输入 0 返回当前 VPS 的确认页。
'@
            }
            catch {
                if (-not (Test-VpsWizardBackError $_)) { throw }
                $candidatePath = $source.PlanPath
                $returnToSource = $true
                break
            }
            try {
                switch ($choice) {
                    1 { return New-MxhProtocolMigrationDetails -Source $source -ProjectRoot $ProjectRoot -Operation InstallActivate }
                    2 { return New-MxhProtocolMigrationDetails -Source $source -ProjectRoot $ProjectRoot -Operation InstallStandby }
                    3 { return New-MxhProtocolStateDetails -Source $source }
                    4 { return New-MxhProtocolUninstallDetails -Source $source }
                    5 {
                        Invoke-MxhProtocolBackupCleanup -Source $source -ProjectRoot $ProjectRoot -DryRun:$DryRun
                        continue
                    }
                    6 {
                        $candidatePath = $null
                        $returnToSource = $true
                        break
                    }
                }
                if ($returnToSource) { break }
            }
            catch {
                if (-not (Test-VpsWizardBackError $_)) { throw }
                Write-VpsUi '已返回协议管理操作选择。' Info
                continue
            }
        }
        if ($returnToSource) {
            if ($candidatePath) { Write-VpsUi '已返回实例核对。' Info }
            else { Write-VpsUi '请重新选择实例。' Info }
            continue
        }
    }
}

function Initialize-MxhProtocolMigrationContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ProjectRoot,
        [Parameter(Mandatory)] $MigrationResult,
        [switch]$DryRun,
        [switch]$NonInteractive
    )

    $plan = $MigrationResult.Plan
    $source = $MigrationResult.Source
    $archive = [IO.Path]::GetFullPath([string]$plan.Paths.Archive)
    if ($DryRun) {
        $context = Initialize-VpsContext -ProjectRoot $ProjectRoot -Plan $plan -DryRun -NonInteractive:$NonInteractive
        $context.State = ($source.State | ConvertTo-Json -Depth 40) | ConvertFrom-Json -AsHashtable
        $context.State['Migration'] = [ordered]@{
            Status = 'DryRun'
            RollbackArmed = $false
            Committed = $false
        }
        return $context
    }

    $statePath = Join-Path $archive 'deployment-state.json'
    $secretsPath = Join-Path $archive 'deployment-secrets.private.json'
    $freshSourcePlan = Read-VpsJsonHashtable -Path $source.PlanPath
    $state = Read-VpsJsonHashtable -Path $statePath
    Test-MxhProtocolMigrationSource -PlanPath $source.PlanPath -Plan $freshSourcePlan -State $state | Out-Null
    $freshHash = (Get-FileHash -LiteralPath $source.PlanPath -Algorithm SHA256).Hash
    if ($freshHash -ne [string]$plan.Migration.SourcePlanSha256) {
        throw '部署计划在协议管理向导确认后发生变化，拒绝覆盖；请重新进入向导。'
    }
    $secrets = Read-VpsJsonHashtable -Path $secretsPath
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $backupRoot = Join-Path $archive 'migration-backups'
    $operationName = if ($plan.Migration.Contains('Operation')) { [string]$plan.Migration.Operation } else { 'Convert' }
    $backupDirectory = Join-Path $backupRoot ("$stamp-$operationName-$($plan.Migration.TargetRole)")
    $resolvedBackup = [IO.Path]::GetFullPath($backupDirectory)
    $archivePrefix = $archive.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedBackup.StartsWith($archivePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw '协议变更备份目录越出实例私有归档，拒绝继续。'
    }
    [IO.Directory]::CreateDirectory($resolvedBackup) | Out-Null
    foreach ($name in @('deployment-plan.json', 'deployment-state.json', 'deployment-secrets.private.json')) {
        $sourceFile = Join-Path $archive $name
        if (Test-Path -LiteralPath $sourceFile -PathType Leaf) {
            $destination = Join-Path $resolvedBackup $name
            Copy-Item -LiteralPath $sourceFile -Destination $destination
            Protect-VpsPrivateFile -Path $destination
        }
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $archive -Filter '*-final-archive.txt' -File -ErrorAction SilentlyContinue)) {
        $destination = Join-Path $resolvedBackup $file.Name
        Copy-Item -LiteralPath $file.FullName -Destination $destination
        Protect-VpsPrivateFile -Path $destination
    }
    foreach ($directoryName in @('server-configs', 'client-exports')) {
        $sourceDirectory = Join-Path $archive $directoryName
        if (Test-Path -LiteralPath $sourceDirectory -PathType Container) {
            Copy-Item -LiteralPath $sourceDirectory -Destination (Join-Path $resolvedBackup $directoryName) -Recurse
        }
    }

    $plan.Migration.LocalBackupDirectory = $resolvedBackup
    $state['Migration'] = [ordered]@{
        Status = 'Planned'
        SourceRole = [string]$plan.Migration.SourceRole
        TargetRole = [string]$plan.Migration.TargetRole
        Operation = $operationName
        LocalBackupDirectory = $resolvedBackup
        RollbackArmed = $false
        Committed = $false
        StartedAt = (Get-Date).ToString('o')
    }
    foreach ($id in @($plan.Migration.ModuleIds)) {
        if ($state.Modules.Contains([string]$id)) { $state.Modules.Remove([string]$id) }
    }
    Save-VpsJson -Value $plan -Path (Join-Path $archive 'deployment-plan.json') -Private
    Save-VpsJson -Value $state -Path $statePath -Private
    Save-VpsJson -Value $secrets -Path $secretsPath -Private
    return Initialize-VpsContext -ProjectRoot $ProjectRoot -Plan $plan -NonInteractive:$NonInteractive
}

function New-MxhReadonlyContextFromPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ProjectRoot,
        [Parameter(Mandatory)] [string]$PlanPath
    )

    $plan = ConvertTo-MxhCompatiblePlan -Plan (Read-VpsJsonHashtable -Path $PlanPath)
    $archive = [string]$plan.Paths.Archive
    $state = Read-VpsJsonHashtable -Path (Join-Path $archive 'deployment-state.json')
    $secrets = Read-VpsJsonHashtable -Path (Join-Path $archive 'deployment-secrets.private.json')
    return [pscustomobject]@{
        ProjectRoot = $ProjectRoot
        Plan = $plan
        ArchivePath = $archive
        PlanPath = $PlanPath
        SecretsPath = (Join-Path $archive 'deployment-secrets.private.json')
        StatePath = (Join-Path $archive 'deployment-state.json')
        LogPath = (Join-Path $archive 'deployment.log')
        Secrets = $secrets
        State = $state
        DryRun = $true
        NonInteractive = $true
        Versions = (Get-VpsVersions -ProjectRoot $ProjectRoot)
    }
}

function Invoke-MxhProtocolMigrationRollback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)] [string]$Reason
    )

    if (-not $Context.Plan.Contains('Migration') -or -not [bool]$Context.Plan.Migration.Enabled) { return }
    if (-not $Context.State.Contains('Migration')) { return }
    if (-not [bool]$Context.State.Migration.RollbackArmed -or [bool]$Context.State.Migration.Committed) { return }

    Write-VpsUi '协议变更失败，正在立即恢复变更前的协议文件、启用状态与 nftables；若 SSH 暂时不可达，服务器端计时器仍会自动执行。' Warning
    try {
        $result = Invoke-VpsRemoteScript -Context $Context -Asset 'protocol-migration-trigger-rollback.sh' -Parameters @{
            EXPECTED_BACKUP = [string]$Context.State.Migration.RemoteBackupDirectory
            SOURCE_ROLE = [string]$Context.Plan.Migration.SourceRole
        } -TimeoutSeconds 180
        if ($result.StdOut -notmatch 'VPSDEPLOY_MIGRATION_ROLLBACK_OK') { throw '远端未返回回滚成功标记。' }
        $Context.State.Migration.Status = 'RolledBack'
        $Context.State.Migration.RollbackArmed = $false
        $Context.State.Migration.RolledBackAt = (Get-Date).ToString('o')
        $Context.State.Migration.LastError = $Reason
        $Context.Plan.Migration.Status = 'RolledBack'
        Write-VpsUi '变更前的协议状态和旧防火墙已恢复。修复原因后可选择【继续未完成部署】重试。' Success
    }
    catch {
        $Context.State.Migration.Status = 'RollbackPending'
        $Context.State.Migration.LastError = $Reason
        $Context.State.Migration.RollbackError = $_.Exception.Message
        $Context.Plan.Migration.Status = 'RollbackPending'
        Write-VpsUi '立即回滚未能确认；请等待最多 20 分钟让 VPS 端独立计时器恢复源协议。' Error
    }
    finally {
        $modules = @(Get-VpsModules -ProjectRoot $Context.ProjectRoot)
        foreach ($module in $modules) {
            if ($module.Id -in @($Context.Plan.Migration.ModuleIds)) {
                if ($Context.State.Modules.Contains([string]$module.Id)) { $Context.State.Modules.Remove([string]$module.Id) }
            }
        }
        Save-VpsJson -Value $Context.Plan -Path $Context.PlanPath -Private
        Save-VpsContext -Context $Context
    }
}
