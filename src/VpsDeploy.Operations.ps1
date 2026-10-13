function Get-MxhMaintenanceContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ProjectRoot, [Parameter(Mandatory)] $Source, [switch]$DryRun)
    $context = New-MxhReadonlyContextFromPlan -ProjectRoot $ProjectRoot -PlanPath $Source.PlanPath
    $context.DryRun = [bool]$DryRun
    $context.NonInteractive = $false
    if(-not $DryRun){Initialize-MxhPendingSshAccess $context}
    $journalPath=Join-Path $context.ArchivePath 'restore-pending.private.json'
    if(Test-Path -LiteralPath $journalPath){
        $journal=Read-VpsJsonHashtable $journalPath
        if($journal.Phase -notin @('Committed','RolledBack')){Write-VpsUi '发现未完成的恢复记录，请先进入“处理未完成的维护操作”。' Warning}
    }
    Assert-VpsSupportedTarget -OsId ([string]$context.State.Audit.OsId) -OsVersion ([string]$context.State.Audit.OsVersion) `
        -Architecture ([string]$context.State.Audit.Architecture) | Out-Null
    return $context
}

function Initialize-MxhPendingSshAccess {
    param($Context)
    $path=Join-Path $Context.ArchivePath 'ssh-maintenance-pending.private.json'
    if(-not(Test-Path -LiteralPath $path)){return}
    $journal=Read-VpsJsonHashtable $path
    if($journal.Phase -in @('Committed','RolledBack')){return}
    Write-VpsUi '发现中断的 SSH 维护，正在只读核实新旧入口；未改变任何服务器设置。' Warning
    $keys=@(Get-VpsSshKeyCandidates $Context)+@([string]$journal.KeyBackup)
    if($journal.OldPlan.SshKey.Contains('SourcePrivateKeyPath')){$keys+=@([string]$journal.OldPlan.SshKey.SourcePrivateKeyPath)}
    $ports=@([int]$Context.State.CurrentManagementPort,[int]$journal.OldPlan.Ports.SshPrimary,[int]$journal.OldPlan.Ports.SshRescue)|Select-Object -Unique
    $ssh=Get-VpsCommandPath 'ssh.exe'
    foreach($key in @($keys|Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Leaf)}|Select-Object -Unique)){
        foreach($port in $ports){
            $arguments=@('-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=accept-new','-o','ConnectTimeout=5','-i',$key,'-p',[string]$port,"root@$($Context.Plan.Server.IPv4)",'printf MXH_RECOVERY_ACCESS_OK')
            $result=Invoke-VpsProcess $ssh $arguments -TimeoutSeconds 12
            if($result.ExitCode -eq 0 -and $result.StdOut -eq 'MXH_RECOVERY_ACCESS_OK'){
                Set-VpsActiveSshKeyPath $Context $key;$Context.State.CurrentManagementPort=$port;return
            }
        }
    }
    throw '新旧 SSH 入口均未确认可用。请使用服务商恢复控制台核实回滚，密钥备份未删除。'
}

function Save-MxhMaintenanceContext {
    param([Parameter(Mandatory)] $Context)
    if ($Context.DryRun) { return }
    Save-VpsJson -Value $Context.Plan -Path $Context.PlanPath -Private
    Save-VpsContext -Context $Context
}

function Assert-MxhNoPendingLocalTransaction {
    param($Context)
    if($Context.State.Contains('MaintenanceTransaction') -and -not [bool]$Context.State.MaintenanceTransaction.Committed){
        throw '本地仍有未完成的维护记录，请先进入“处理未完成的维护操作”核对服务器并恢复本地状态。'
    }
    foreach($name in @('restore-pending.private.json','ssh-maintenance-pending.private.json')){
        $path=Join-Path $Context.ArchivePath $name
        if(Test-Path -LiteralPath $path){if((Read-VpsJsonHashtable $path).Phase -notin @('Committed','RolledBack')){throw '请先在遗留事务入口处理未完成的本地恢复/SSH 记录，不能开始新操作。'}}
    }
}

function Start-MxhMaintenanceTransaction {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [string]$Label, [switch]$QuiesceKomariController,
        [ValidateSet('Protocols','Network','Firewall','KomariAgent','KomariController','Cloudflared')][string[]]$Components=@('Protocols','Network','Firewall'))
    if ($Context.DryRun) { return [ordered]@{ DryRun = $true; Label = $Label } }
    if ($Label -notmatch '^[A-Za-z0-9-]{1,48}$') { throw '维护事务标签无效。' }
    Assert-MxhNoPendingLocalTransaction $Context
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N')
    $local = Join-Path $Context.ArchivePath "maintenance-backups\$stamp-$Label"
    [IO.Directory]::CreateDirectory($local) | Out-Null
    foreach ($name in @('deployment-plan.json','deployment-state.json','deployment-secrets.private.json')) {
        $path = Join-Path $Context.ArchivePath $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { Copy-Item -LiteralPath $path -Destination (Join-Path $local $name); Protect-VpsPrivateFile (Join-Path $local $name) }
    }
    foreach ($directory in @('client-exports','server-configs')) {
        $path = Join-Path $Context.ArchivePath $directory
        if (Test-Path -LiteralPath $path -PathType Container) { Copy-Item -LiteralPath $path -Destination (Join-Path $local $directory) -Recurse }
    }
    $role = Get-MxhInventoryPrimaryRole -Inventory (Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State)
    if ($QuiesceKomariController -and 'KomariController' -notin $Components) { $Components += 'KomariController' }
    $result = Invoke-VpsRemoteScript -Context $Context -Asset 'protocol-migration-arm-rollback.sh' -Parameters @{
        SOURCE_ROLE = $role; TARGET_ROLE = $role; TIMEOUT_MINUTES = '20'
        QUIESCE_KOMARI_CONTROLLER = ([bool]$QuiesceKomariController).ToString().ToLowerInvariant()
        COMPONENTS = ($Components | Sort-Object -Unique) -join ','
    } -TimeoutSeconds 300
    $remote = Get-VpsMarkerValue $result.StdOut BACKUP_DIR -Required
    $transaction = [ordered]@{ Label=$Label; Components=@($Components); LocalBackup=$local; RemoteBackup=$remote; StartedAt=(Get-Date).ToString('o'); Committed=$false }
    Save-VpsJson -Value $transaction -Path (Join-Path $local 'maintenance-transaction.json') -Private
    $Context.State.MaintenanceTransaction = $transaction
    Save-MxhMaintenanceContext $Context
    return $transaction
}

function Complete-MxhMaintenanceTransaction {
    param([Parameter(Mandatory)] $Context)
    if ($Context.DryRun) { return }
    $Context.State.MaintenanceTransaction.Phase='LocalPrepared'
    Save-MxhMaintenanceContext $Context
    $result = Invoke-VpsRemoteScript -Context $Context -Asset 'maintenance-transaction-commit.sh' -Parameters @{EXPECTED_BACKUP=[string]$Context.State.MaintenanceTransaction.RemoteBackup}
    if ($result.StdOut -notmatch 'VPSDEPLOY_MAINTENANCE_COMMITTED') { throw '维护事务提交未确认。' }
    $Context.State.MaintenanceTransaction.Committed = $true
    $Context.State.MaintenanceTransaction.Phase='Committed'
    $Context.State.MaintenanceTransaction.CommittedAt = (Get-Date).ToString('o')
    Save-MxhMaintenanceContext $Context
}

function Undo-MxhMaintenanceTransaction {
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] [string]$Reason)
    if ($Context.DryRun) { return }
    try {
        if($Context.State.MaintenanceTransaction.Contains('Committed') -and $Context.State.MaintenanceTransaction.Committed){throw '该操作已完成，不能按中断操作自动撤销；请使用“从备份恢复”。'}
        $result = Invoke-VpsRemoteScript -Context $Context -Asset 'protocol-migration-trigger-rollback.sh' -Parameters @{ EXPECTED_BACKUP=[string]$Context.State.MaintenanceTransaction.RemoteBackup; SOURCE_ROLE = (Get-MxhInventoryPrimaryRole -Inventory (Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State)) } -TimeoutSeconds 300
        if ($result.StdOut -notmatch 'VPSDEPLOY_MIGRATION_ROLLBACK_OK') { throw '服务器未确认回滚。' }
        $backup=[string]$Context.State.MaintenanceTransaction.LocalBackup
        if($backup -and (Test-Path $backup -PathType Container)){
            foreach($name in @('deployment-plan.json','deployment-state.json','deployment-secrets.private.json')){
                $source=Join-Path $backup $name;if(Test-Path $source){Copy-Item $source (Join-Path $Context.ArchivePath $name) -Force;Protect-VpsPrivateFile (Join-Path $Context.ArchivePath $name)}
            }
            foreach($directory in @('client-exports','server-configs')){
                $current=Join-Path $Context.ArchivePath $directory
                $source=Join-Path $backup $directory
                if(Test-Path $current -PathType Container){Remove-Item $current -Recurse -Force}
                if(Test-Path $source -PathType Container){Copy-Item $source $current -Recurse}
            }
            $Context.Plan=Read-VpsJsonHashtable $Context.PlanPath
            $Context.State=Read-VpsJsonHashtable $Context.StatePath
            $Context.Secrets=Read-VpsJsonHashtable $Context.SecretsPath
        }
        $Context.State.LastMaintenanceRollback=[ordered]@{At=(Get-Date).ToString('o');Reason=$Reason;RemoteConfirmed=$true}
        Save-MxhMaintenanceContext $Context
    }
    catch { Write-VpsUi '立即回滚未确认；请检查遗留事务状态，不能假定回滚计时器仍然有效。备份保留。' Error; throw }
}

function Invoke-MxhTransactionRecovery {
    param($Context)
    if ($Context.DryRun) { Write-VpsUi 'DryRun：只读检查遗留事务；不会连接或解除锁。' Info; return }
    $sshJournalPath=Join-Path $Context.ArchivePath 'ssh-maintenance-pending.private.json'
    if(Test-Path -LiteralPath $sshJournalPath){
        $sshJournal=Read-VpsJsonHashtable $sshJournalPath
        if($sshJournal.Phase -notin @('Committed','RolledBack')){
            $status=Invoke-VpsRemoteScript $Context 'maintenance-transaction-status.sh' @{ACTION='Status';EXPECTED_BACKUP=[string]$sshJournal.Backup}
            $phase=Get-VpsMarkerValue $status.StdOut TRANSACTION_PHASE -Required
            if($phase -eq 'Committed'){
                if($sshJournal.Phase -ne 'LocalPrepared'){throw 'SSH 远端提交与本地阶段不一致，请保留密钥备份人工核对。'}
                $sshJournal.Phase='Committed';Save-VpsJson $sshJournal $sshJournalPath -Private
                Write-VpsUi 'SSH 远端提交已核实。' Success;return
            }
            if(-not(Read-VpsYesNo '恢复中断的 SSH 维护及本地管理密钥？' $false -AllowBack)){return}
            if($phase -ne 'RolledBack'){Invoke-VpsRemoteScript $Context 'maintenance-ssh-rollback.sh' @{EXPECTED_BACKUP=[string]$sshJournal.Backup}|Out-Null}
            foreach($item in @(@{Target=$sshJournal.ManagedKey;Backup=$sshJournal.KeyBackup;Existed=$sshJournal.KeyExisted},@{Target=$sshJournal.ManagedPublic;Backup=$sshJournal.PublicBackup;Existed=$sshJournal.PublicExisted})){
                if($item.Existed -and -not(Test-Path -LiteralPath $item.Backup -PathType Leaf)){throw 'SSH 本地恢复备份缺失，停止替换密钥。'}
            }
            foreach($item in @(@{Target=$sshJournal.ManagedKey;Backup=$sshJournal.KeyBackup;Existed=$sshJournal.KeyExisted},@{Target=$sshJournal.ManagedPublic;Backup=$sshJournal.PublicBackup;Existed=$sshJournal.PublicExisted})){
                if($item.Existed){Copy-Item -LiteralPath $item.Backup -Destination $item.Target -Force}
                elseif([IO.File]::Exists($item.Target)){[IO.File]::Delete($item.Target)}
            }
            $Context.Plan=$sshJournal.OldPlan;$Context.State=$sshJournal.OldState
            if(Test-Path -LiteralPath $sshJournal.ManagedKey){Set-VpsOpenSshPrivateKeyAccess $sshJournal.ManagedKey}
            Save-MxhMaintenanceContext $Context;$sshJournal.Phase='RolledBack';Save-VpsJson $sshJournal $sshJournalPath -Private
            Write-VpsUi 'SSH 维护已恢复，旧密钥备份保留。' Success;return
        }
    }
    $journalPath=Join-Path $Context.ArchivePath 'restore-pending.private.json'
    if(Test-Path -LiteralPath $journalPath){
        $journal=Read-VpsJsonHashtable $journalPath
        if($journal.Phase -notin @('Committed','RolledBack')){
            $status=Invoke-VpsRemoteScript $Context 'maintenance-transaction-status.sh' @{ACTION='Status';EXPECTED_BACKUP=[string]$journal.Transaction.RemoteBackup}
            $phase=Get-VpsMarkerValue $status.StdOut TRANSACTION_PHASE -Required
            if($phase -eq 'Committed'){
                if($journal.Phase -ne 'LocalApplied'){throw '远端已提交，但本地阶段记录异常；保留暂存与备份，不能自动推断恢复。'}
                $Context.State.MaintenanceTransaction=$journal.Transaction;$Context.State.MaintenanceTransaction.Committed=$true
                Save-MxhMaintenanceContext $Context;$journal.Phase='Committed';Save-VpsJson $journal $journalPath -Private
                Write-VpsUi '已核实远端提交，补全本地恢复记录。' Success;return
            }
            if(-not(Read-VpsYesNo '发现中断的恢复操作，是否恢复该操作开始前的状态？' $false -AllowBack)){return}
            $Context.State.MaintenanceTransaction=$journal.Transaction
            Undo-MxhMaintenanceTransaction $Context 'Recover interrupted manual restore'
            $journal.Phase='RolledBack';Save-VpsJson $journal $journalPath -Private
            Write-VpsUi '中断的恢复操作已回滚。' Success;return
        }
    }
    if($Context.State.Contains('MaintenanceTransaction')){
        $local=$Context.State.MaintenanceTransaction
        if(-not [bool]$local.Committed){
            $status=Invoke-VpsRemoteScript $Context 'maintenance-transaction-status.sh' @{ACTION='Status';EXPECTED_BACKUP=[string]$local.RemoteBackup}
            if((Get-VpsMarkerValue $status.StdOut TRANSACTION_PHASE -Required) -eq 'RolledBack'){
                Undo-MxhMaintenanceTransaction $Context 'Reconcile confirmed automatic rollback'
                Write-VpsUi '服务器已自动回滚，对应本地计划、凭据和配置也已恢复。' Success
                return
            }
        }
        if($local.Contains('Phase') -and $local.Phase -eq 'LocalPrepared'){
            $status=Invoke-VpsRemoteScript $Context 'maintenance-transaction-status.sh' @{ACTION='Status';EXPECTED_BACKUP=[string]$local.RemoteBackup}
            if((Get-VpsMarkerValue $status.StdOut TRANSACTION_PHASE -Required) -eq 'Committed'){
                $local.Committed=$true;$local.Phase='Committed';Save-MxhMaintenanceContext $Context
                Write-VpsUi '已核实远端提交结果，补全本地记录。' Success;return
            }
        }
    }
    $result=Invoke-VpsRemoteScript $Context 'maintenance-transaction-status.sh' @{ACTION='Status'}
    $phase=Get-VpsMarkerValue $result.StdOut TRANSACTION_PHASE -Required
    $remote=Get-VpsMarkerValue $result.StdOut TRANSACTION_BACKUP
    Write-VpsUi "远端事务状态：$phase" Info
    if (-not $remote) { return }
    $choice=Read-VpsMenu '处理未完成的维护操作' @('只查看，暂不处理','恢复到本次操作前','清除未开始操作的占用标记') 1 -AllowBack -HelpText '第 2 项会恢复匹配的远端和本地备份。第 3 项仅适用于准备阶段：服务和回滚计时器都没有运行时才允许清除；不会强行终止正在执行的操作。'
    if($choice -eq 1){return}
    if($choice -eq 3){
        if($phase -ne 'Preparing'){throw '只有尚未启用回滚的准备阶段可以解除；已启用事务必须恢复。'}
        if(-not(Read-VpsYesNo '确认解除准备锁？服务器还会复查计时器与服务未运行。' $false -AllowBack)){return}
        Invoke-VpsRemoteScript $Context 'maintenance-transaction-status.sh' @{ACTION='ReleaseUnarmed';EXPECTED_BACKUP=$remote}|Out-Null
        Write-VpsUi '准备锁已解除，快照文件保留。' Success;return
    }
    $metadata=@(Get-ChildItem -LiteralPath (Join-Path $Context.ArchivePath 'maintenance-backups') -Filter maintenance-transaction.json -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $value=Read-VpsJsonHashtable $_.FullName
        if([string]$value.RemoteBackup -eq $remote){$value}
    })
    if($metadata.Count -ne 1){throw '未找到唯一匹配的本地维护备份；请在原操作计划中恢复协议迁移，不能猜测本地恢复点。'}
    if(-not(Read-VpsYesNo '确认恢复该事务开始前的远端与本地状态？' $false -AllowBack)){return}
    $Context.State.MaintenanceTransaction=$metadata[0]
    Undo-MxhMaintenanceTransaction $Context 'Explicit recovery of unfinished transaction'
    Write-VpsUi '事务已恢复，本地备份保留。' Success
}

function Get-MxhHealthAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [switch]$Persist,
        [switch]$InitializeBaseline,
        [switch]$IgnoreActiveRollbackTimer
    )
    if ($Context.DryRun) {
        return [ordered]@{ SchemaVersion=1; DryRun=$true; Findings=@(); Status='DryRun' }
    }
    $agentReleases = @{}
    if ($Context.PSObject.Properties['Versions'] -and $Context.Versions.komari_agent) {
        foreach ($asset in $Context.Versions.komari_agent.assets.PSObject.Properties) {
            $agentReleases[[string]$asset.Value.sha256] = [string]$Context.Versions.komari_agent.version
        }
    }
    $result = Invoke-VpsRemoteScript -Context $Context -Asset 'maintenance-health-audit.sh' -Parameters @{AGENT_RELEASES_JSON=($agentReleases|ConvertTo-Json -Compress)} -TimeoutSeconds 300
    $audit = (Get-VpsMarkerValue $result.StdOut HEALTH_AUDIT -Required) | ConvertFrom-Json -AsHashtable
    $findings = [Collections.Generic.List[object]]::new()
    $add = { param($severity,$code,$message) $findings.Add([ordered]@{ Severity=$severity; Code=$code; Message=$message }) }
    if (-not $audit.Ssh.Valid) { & $add Critical 'SSH_CONFIG_INVALID' 'sshd -T 未通过。' }
    $preserveSsh = $Context.Plan.Contains('Import') -and $Context.Plan.Import.Contains('SshAuthenticationPreserved') -and [bool]$Context.Plan.Import.SshAuthenticationPreserved
    if ($audit.Ssh.PubkeyAuthentication -ne 'yes') {
        & $add Critical 'SSH_PUBKEY_DISABLED' 'SSH 公钥认证已关闭，不能保证受管密钥入口可用。'
    } elseif (-not $preserveSsh -and ($audit.Ssh.PasswordAuthentication -ne 'no' -or $audit.Ssh.KbdInteractiveAuthentication -ne 'no')) {
        & $add Critical 'SSH_NOT_KEY_ONLY' 'SSH 有效配置不是公钥独占登录。'
    }
    $expectedPorts = @([int]$Context.Plan.Ports.SshPrimary,[int]$Context.Plan.Ports.SshRescue) | Sort-Object -Unique
    foreach ($port in $expectedPorts) { if ($port -notin @($audit.Ssh.Ports | ForEach-Object {[int]$_})) { & $add Critical 'SSH_PORT_DRIFT' '一个计划内 SSH 入口没有出现在有效配置中。' } }
    $inventory = Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State
    foreach ($role in Get-MxhManagedProtocolRoles) {
        $expected = $inventory[$role]; $actual = $audit.Services[$role]
        foreach ($field in @('Installed','Enabled','Active')) {
            if ([bool]$expected[$field] -ne [bool]$actual[$field]) { & $add Critical 'PROTOCOL_STATE_DRIFT' "$role 的 $field 与本地清单不一致。" }
        }
        if ($expected.Active -and $actual.Contains('ProcessMatchesBinary') -and $actual.ProcessMatchesBinary -eq $false) {
            & $add Critical 'RUNNING_BINARY_MISMATCH' "$role 的运行进程未使用受管程序。"
        }
    }
    $requireListener = {
        param([int]$port,[string]$transport,[string]$label)
        if ($port -lt 1) { & $add Critical 'LISTENER_PLAN_MISSING' "$label 缺少有效监听端口。"; return }
        if ($audit.Contains('Listeners')) {
            if ($port -notin @($audit.Listeners[$transport])) { & $add Critical 'REQUIRED_LISTENER_MISSING' "$label 缺少计划内 $transport 监听。" }
        } elseif ($audit.Contains('ListenerPorts')) {
            if ($port -notin @($audit.ListenerPorts)) { & $add Critical 'REQUIRED_LISTENER_MISSING' "$label 缺少计划内监听。" }
            if ($transport -eq 'Udp') { & $add Warning 'LISTENER_CHECK_INCOMPLETE' '旧审计快照没有独立 UDP 监听证据。' }
        } else { & $add Warning 'LISTENER_CHECK_INCOMPLETE' '审计快照没有监听证据，不能确认为健康。' }
    }
    foreach ($port in $expectedPorts) { & $requireListener $port Tcp 'SSH' }
    if ($inventory.RealityEntry.Active) {
        & $requireListener ([int]$Context.Plan.Ports.XrayPrimary) Tcp 'Reality'
        if ($Context.Plan.Ports.XrayBackup) { & $requireListener ([int]$Context.Plan.Ports.XrayBackup) Tcp 'Reality 备用入口' }
        if ($Context.Plan.Reality.Contains('TargetMode') -and $Context.Plan.Reality.TargetMode -eq 'LocalOwnedTls') { & $requireListener ([int]$Context.Plan.Reality.LocalHttpsPort) Tcp 'Reality 本机 HTTPS 目标' }
    }
    if ($inventory.AnyTlsEntry.Active) { & $requireListener ([int]$Context.Plan.Ports.AnyTlsPrimary) Tcp 'AnyTLS' }
    if ($inventory.ShadowsocksLanding.Active) {
        & $requireListener ([int]$Context.Plan.Ports.LandingShadowsocks) Tcp 'Shadowsocks'
        & $requireListener ([int]$Context.Plan.Ports.LandingShadowsocks) Udp 'Shadowsocks'
    }
    if ($audit.Nftables.Present -and -not $audit.Nftables.Valid) { & $add Critical 'NFTABLES_INVALID' 'nftables 持久化配置语法无效。' }
    $certificateRoles = @()
    if ($inventory.AnyTlsEntry.Installed) { $certificateRoles += 'AnyTls' }
    if ($inventory.RealityEntry.Installed -and $Context.Plan.Reality.Contains('TargetMode') -and $Context.Plan.Reality.TargetMode -eq 'LocalOwnedTls') { $certificateRoles += 'Reality' }
    foreach ($certificateRole in $certificateRoles) {
        $cert = if ($audit.Contains('Certificates')) { $audit.Certificates[$certificateRole] } elseif ($certificateRole -eq 'AnyTls') { $audit.Certificate } else { $null }
        if (-not $cert -or -not $cert.Present -or $null -eq $cert.DaysRemaining -or [int]$cert.DaysRemaining -lt 0) { & $add Critical 'TLS_CERT_INVALID' "$certificateRole 的受管证书缺失、不可解析或已过期。" }
        elseif ([int]$cert.DaysRemaining -lt 21) { & $add Warning 'TLS_CERT_EXPIRY' "$certificateRole 证书剩余不足 21 天。" }
    }
    if ($certificateRoles.Count -and (-not $audit.Timers.CertbotRenewEnabled -or ($audit.Timers.Contains('CertbotRenewActive') -and -not $audit.Timers.CertbotRenewActive))) {
        & $add Warning 'CERTBOT_RENEW_UNAVAILABLE' '受管证书的自动续期计时器未启用或未运行。'
    }
    if ($audit.Timers.RollbackActive -and -not $IgnoreActiveRollbackTimer) { & $add Warning 'ROLLBACK_TIMER_ACTIVE' '存在尚未提交的自动回滚计时器。' }
    if ($Context.State.Contains('HealthBaseline')) {
        foreach ($key in $Context.State.HealthBaseline.Hashes.Keys) {
            $old=[string]$Context.State.HealthBaseline.Hashes[$key]; $now=[string]$audit.Hashes[$key]
            if (($old -or $now) -and $old -ne $now) { & $add Warning 'CONFIG_HASH_DRIFT' "$key 的 SHA-256 与已确认基线不同。" }
        }
    }
    $expectedAgentInstalled=$Context.State.Contains('KomariInstalled') -and [bool]$Context.State.KomariInstalled
    if($expectedAgentInstalled -ne [bool]$audit.Services.KomariAgent.Installed){& $add Warning 'KOMARI_AGENT_DRIFT' 'Komari Agent 安装状态与本地清单不一致。'}
    if([bool]$Context.Plan.Komari.Enabled -ne [bool]$audit.Services.KomariAgent.Active){& $add Warning 'KOMARI_AGENT_STATE_DRIFT' 'Komari Agent 运行状态与本地计划不一致。'}
    if ($expectedAgentInstalled -and -not $audit.Versions.KomariAgent) { & $add Warning 'KOMARI_AGENT_VERSION_UNKNOWN' 'Agent 文件哈希不属于当前已知资产，未执行 Agent 查询版本。' }
    foreach ($component in @('KomariAgent','KomariController','Cloudflared')) {
        $actual=$audit.Services[$component]
        if ($actual.Active -and $actual.Contains('ProcessMatchesBinary') -and $actual.ProcessMatchesBinary -eq $false) { & $add Critical 'RUNNING_BINARY_MISMATCH' "$component 的运行进程与受管程序不一致。" }
        if ($component -ne 'KomariAgent' -and $Context.State.Contains($component)) {
            $expected=$Context.State[$component]
            foreach ($field in @('Installed','Enabled','Active')) {
                if ($expected.Contains($field) -and [bool]$expected[$field] -ne [bool]$actual[$field]) { & $add Warning 'KOMARI_SERVICE_STATE_DRIFT' "$component 的 $field 与本地记录不同。" }
            }
        }
    }
    if ($audit.Services.KomariController.Active) { & $requireListener 25774 Tcp 'Komari Controller' }
    if ($audit.Contains('ChecksIncomplete') -and @($audit.ChecksIncomplete).Count) { & $add Warning 'AUDIT_CHECK_INCOMPLETE' '部分只读检查超时或不可用，不能确认为健康。' }
    if($inventory.RealityEntry.Installed -and [string]$audit.Versions.Xray -notmatch [regex]::Escape([string]$Context.Plan.Reality.XrayVersion)){& $add Warning 'XRAY_VERSION_DRIFT' 'Xray 版本与固定计划不一致。'}
    if($inventory.AnyTlsEntry.Installed -and [string]$audit.Versions.SingBoxAnyTls -notmatch [regex]::Escape([string]$Context.Plan.AnyTls.SingBoxVersion)){& $add Warning 'SINGBOX_VERSION_DRIFT' 'AnyTLS sing-box 版本与固定计划不一致。'}
    if($inventory.ShadowsocksLanding.Installed -and [string]$audit.Versions.SingBox -notmatch [regex]::Escape([string]$Context.Plan.Shadowsocks.SingBoxVersion)){& $add Warning 'SINGBOX_VERSION_DRIFT' 'Shadowsocks sing-box 版本与固定计划不一致。'}
    if($Context.State.Contains('KomariController') -and [bool]$Context.State.KomariController.Installed){
        $expectedControllerVersion=if($Context.Plan.Komari.Contains('ControllerVersion')){[string]$Context.Plan.Komari.ControllerVersion}else{''}
        if(-not $audit.Versions.KomariController){& $add Warning 'KOMARI_CONTROLLER_VERSION_UNKNOWN' '无法确认 Controller 服务实际使用的程序版本。'}
        elseif($expectedControllerVersion -and [string]$audit.Versions.KomariController -notmatch [regex]::Escape($expectedControllerVersion)){& $add Warning 'KOMARI_CONTROLLER_VERSION_DRIFT' 'Komari Controller 版本与实例计划不一致。'}
    }
    $status = if (@($findings | Where-Object Severity -eq Critical).Count) {'Critical'} elseif ($findings.Count) {'Warning'} else {'Healthy'}
    if ($InitializeBaseline -and $status -eq 'Healthy') {
        $Context.State.HealthBaseline = [ordered]@{ EstablishedAt=(Get-Date).ToString('o'); Hashes=Copy-MxhHashtable $audit.Hashes }
    }
    $report=[ordered]@{ SchemaVersion=1; Status=$status; CollectedAt=$audit.CollectedAt; Findings=$findings.ToArray(); Snapshot=$audit }
    if ($Persist) {
        $dir=Join-Path $Context.ArchivePath 'health-audits'; [IO.Directory]::CreateDirectory($dir)|Out-Null
        $path=Join-Path $dir ((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')+'.json')
        Save-VpsJson $report $path -Private; $Context.State.LastHealthAudit=$path; Save-MxhMaintenanceContext $Context
    }
    return $report
}

function Show-MxhHealthAudit {
    param([Parameter(Mandatory)] $Report)
    Write-Host ''; Write-Host "健康审计：$($Report.Status)" -ForegroundColor White
    if (-not @($Report.Findings).Count) { Write-VpsUi '未发现服务状态、SSH、防火墙、证书或配置哈希异常。' Success; return }
    foreach ($finding in $Report.Findings) { Write-VpsUi "[$($finding.Code)] $($finding.Message)" $(if($finding.Severity -eq 'Critical'){'Error'}else{'Warning'}) }
}

function Invoke-MxhHealthAuditInteractive {
    param($Context)
    $initialize = -not $Context.State.Contains('HealthBaseline')
    $report=Get-MxhHealthAudit $Context -Persist -InitializeBaseline:$initialize
    Show-MxhHealthAudit $report
    if ($initialize -and $report.Status -eq 'Healthy') { Write-VpsUi '已把本次脱敏哈希快照建立为配置漂移基线。' Success }
    elseif (-not $initialize -and $report.Status -ne 'Critical' -and @($report.Findings).Count -gt 0 -and
        @($report.Findings | Where-Object Code -ne 'CONFIG_HASH_DRIFT').Count -eq 0 -and
        (Read-VpsYesNo '这些哈希变化是否为已确认维护结果，并更新为新基线？' $false -AllowBack)) {
        $Context.State.HealthBaseline = [ordered]@{ EstablishedAt=(Get-Date).ToString('o'); Hashes=Copy-MxhHashtable $report.Snapshot.Hashes }
        Save-MxhMaintenanceContext $Context
        Write-VpsUi '配置漂移基线已更新；远端没有因此被修改。' Success
    }
}

function New-MxhRestoreMetadata {
    param($Context, $Plan, $State, $Secrets, [ValidateSet('Full','ConfigOnly')][string]$Scope)
    if([string]$Plan.Server.IPv4 -ne [string]$Context.Plan.Server.IPv4){throw '恢复点不属于当前服务器。'}
    $oldInventory=Get-MxhProtocolInventory -Plan $Plan -State $State
    $currentInventory=Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State
    if($Scope -eq 'ConfigOnly'){
        foreach($role in Get-MxhManagedProtocolRoles){
            if([bool]$oldInventory[$role].Installed -ne [bool]$currentInventory[$role].Installed){throw '协议安装集合已变化，不能仅恢复配置；请选择完整恢复。'}
        }
        foreach($key in @('XrayPrimary','XrayBackup','AnyTlsPrimary','LandingShadowsocks')){
            if([string]$Plan.Ports[$key] -ne [string]$Context.Plan.Ports[$key]){throw '协议端口已变化，仅恢复配置会与当前防火墙冲突；请选择完整恢复。'}
        }
        if(($Plan.TrustedTls | ConvertTo-Json -Depth 15 -Compress) -ne ($Context.Plan.TrustedTls | ConvertTo-Json -Depth 15 -Compress)){throw '证书设置已变化，不能仅恢复配置。'}
        $newPlan=Copy-MxhHashtable $Context.Plan;$newState=Copy-MxhHashtable $Context.State;$newSecrets=Copy-MxhHashtable $Context.Secrets
        foreach($section in @('Reality','AnyTls','Shadowsocks')){
            $newPlan[$section]=Copy-MxhHashtable $Plan[$section]
            foreach($key in @('Enabled','XrayVersion','XrayVersionChannel','SingBoxVersion','TrustedEntryIPv4s','TrustedEntryIPv6s')){
                if($Context.Plan[$section].Contains($key)){$newPlan[$section][$key]=$Context.Plan[$section][$key]}
            }
        }
    }else{
        $oldSshPorts=@([int]$Plan.Ports.SshPrimary,[int]$Plan.Ports.SshRescue)|Sort-Object -Unique
        $currentSshPorts=@([int]$Context.Plan.Ports.SshPrimary,[int]$Context.Plan.Ports.SshRescue)|Sort-Object -Unique
        if(($oldSshPorts -join ',') -ne ($currentSshPorts -join ',')){
            throw '恢复点使用旧 SSH 端口，完整恢复其防火墙可能切断当前连接。请选择“只恢复代理配置和密钥／密码”，或使用 SSH 端口变更后的备份。未修改服务器。'
        }
        $newPlan=Copy-MxhHashtable $Plan;$newState=Copy-MxhHashtable $State;$newSecrets=Copy-MxhHashtable $Secrets
        # Monitoring is only restored through its own quiesced workflow.
        $newPlan.Komari=Copy-MxhHashtable $Context.Plan.Komari
        foreach($key in @($newState.Keys|Where-Object{$_ -like 'Komari*' -or $_ -like 'Cloudflared*'})){$newState.Remove($key)|Out-Null}
        foreach($key in @($Context.State.Keys|Where-Object{$_ -like 'Komari*' -or $_ -like 'Cloudflared*'})){$newState[$key]=$Context.State[$key]}
        foreach($key in @($newSecrets.Keys|Where-Object{$_ -like 'Komari*' -or $_ -like 'Cloudflared*'})){$newSecrets.Remove($key)|Out-Null}
        foreach($key in @($Context.Secrets.Keys|Where-Object{$_ -like 'Komari*' -or $_ -like 'Cloudflared*'})){$newSecrets[$key]=$Context.Secrets[$key]}
        # The protocol snapshot does not restore SSH identity, server identity or local paths.
        foreach($key in @('Server','Paths','Bootstrap','SshKey','AdminUser','Provider','Instance','NodeName','Import')){
            if($Context.Plan.Contains($key)){$newPlan[$key]=$Context.Plan[$key]}
        }
        foreach($key in @('SshPrimary','SshRescue')){$newPlan.Ports[$key]=$Context.Plan.Ports[$key]}
        foreach($key in @('CurrentManagementPort','BootstrapAccess','SshCutover')){
            if($Context.State.Contains($key)){$newState[$key]=$Context.State[$key]}
        }
    }
    foreach($pair in @(@('RealityEntry','Xray'),@('AnyTlsEntry','AnyTls'),@('ShadowsocksLanding','Shadowsocks'))){
        if([bool]$oldInventory[$pair[0]].Installed){
            if(-not $Secrets.Contains($pair[1])){throw '恢复点缺少已安装协议的凭据，停止恢复。'}
            $newSecrets[$pair[1]]=Copy-MxhHashtable $Secrets[$pair[1]]
        }
    }
    return @{Plan=$newPlan;State=$newState;Secrets=$newSecrets}
}

function Invoke-MxhManualRestoreCenter {
    param($Context)
    if ($Context.DryRun) { Write-VpsUi 'DryRun：将枚举本地/远端成对备份，恢复前再建立当前状态快照。' Success; return }
    $candidates=@()
    $migrationRoot=Join-Path $Context.ArchivePath 'migration-backups'
    $candidates+=@(Get-ChildItem $migrationRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $statePath=Join-Path $_.FullName 'deployment-state.json'; if(Test-Path $statePath){$s=Read-VpsJsonHashtable $statePath;$remote=$null;if($s.Contains('Migration') -and $s.Migration.Contains('RemoteBackupDirectory')){$remote=[string]$s.Migration.RemoteBackupDirectory};if($remote){[pscustomobject]@{Directory=$_.FullName;Remote=$remote;Name=$_.Name;Time=$_.LastWriteTimeUtc}}}
    })
    $maintenanceRoot=Join-Path $Context.ArchivePath 'maintenance-backups'
    $candidates+=@(Get-ChildItem $maintenanceRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $metadata=Join-Path $_.FullName 'maintenance-transaction.json';if(Test-Path $metadata){$m=Read-VpsJsonHashtable $metadata;if($m.RemoteBackup -and (-not $m.Contains('Components') -or 'Protocols' -in $m.Components)){[pscustomobject]@{Directory=$_.FullName;Remote=[string]$m.RemoteBackup;Name=$_.Name;Time=$_.LastWriteTimeUtc}}}
    })
    $candidates=@($candidates|Sort-Object Time -Descending)
    if(-not $candidates.Count){Write-VpsUi '没有找到可验证的本地/远端成对协议备份。' Warning; return}
    while ($true) {
    $choice=Read-VpsMenu '选择恢复点' @($candidates|ForEach-Object{$_.Name}) 1 -AllowBack
    try {
    $selected=$candidates[$choice-1]
    while ($true) {
    $scopeChoice=Read-VpsMenu '选择恢复范围' @('只恢复代理配置和密钥／密码','恢复协议相关文件和运行设置') 1 -AllowBack -HelpText @'
1 只恢复配置：保留当前服务启停、防火墙和程序版本；若安装的协议、端口或证书设置不兼容，会停止恢复。
2 恢复协议相关文件和设置：恢复代理程序、配置、服务启停、防火墙和网络参数；即使旧备份包含 Komari，也不会恢复监控数据。Komari 请使用专用恢复入口。备份与当前 SSH 端口不同会拒绝恢复。
两项都不是系统重装，不恢复 SSH 登录身份；执行前会备份当前状态。
'@
    try {
    $scope=if($scopeChoice -eq 1){'ConfigOnly'}else{'Full'}
    if((Read-VpsText '输入 RESTORE 确认' -AllowBack) -cne 'RESTORE'){Write-VpsUi '未恢复。' Warning;return}
    $restorePlanPath=Join-Path $selected.Directory 'deployment-plan.json'
    $restoreStatePath=Join-Path $selected.Directory 'deployment-state.json'
    $restoreSecretsPath=Join-Path $selected.Directory 'deployment-secrets.private.json'
    if(-not(Test-Path -LiteralPath $restorePlanPath -PathType Leaf) -or -not(Test-Path -LiteralPath $restoreStatePath -PathType Leaf)){
        throw '所选恢复点缺少部署计划或状态元数据，已停止恢复。'
    }
    $restorePlan=Read-VpsJsonHashtable $restorePlanPath
    $restoreState=Read-VpsJsonHashtable $restoreStatePath
    if(-not(Test-Path -LiteralPath $restoreSecretsPath -PathType Leaf)){throw '恢复点缺少私有凭据元数据，未执行恢复。'}
    $restoreSecrets=Read-VpsJsonHashtable $restoreSecretsPath
    $prepared=New-MxhRestoreMetadata $Context $restorePlan $restoreState $restoreSecrets $scope
    $restorePlan=$prepared.Plan;$restoreState=$prepared.State;$restoreSecrets=$prepared.Secrets
    $stage=Join-Path $Context.ArchivePath ('restore-staging-'+[Guid]::NewGuid().ToString('N'))
    Save-VpsJson $restorePlan (Join-Path $stage 'deployment-plan.json') -Private
    Save-VpsJson $restoreState (Join-Path $stage 'deployment-state.json') -Private
    Save-VpsJson $restoreSecrets (Join-Path $stage 'deployment-secrets.private.json') -Private
    foreach($directory in @('client-exports','server-configs')){
        $source=Join-Path $selected.Directory $directory
        if(Test-Path -LiteralPath $source -PathType Container){Copy-Item -LiteralPath $source -Destination (Join-Path $stage $directory) -Recurse}
    }
    $transaction=Start-MxhMaintenanceTransaction $Context 'ManualRestore'
    $journalPath=Join-Path $Context.ArchivePath 'restore-pending.private.json'
    $journal=@{Phase='Prepared';Stage=$stage;Transaction=$transaction;Scope=$scope}
    Save-VpsJson $journal $journalPath -Private
    $remoteCommitted=$false
    try {
        $r=Invoke-VpsRemoteScript $Context 'maintenance-restore-apply.sh' @{BACKUP_PATH=$selected.Remote;SCOPE=$scope} -TimeoutSeconds 600
        if($r.StdOut -notmatch 'VPSDEPLOY_MANUAL_RESTORE_APPLIED'){throw '恢复脚本未确认完成。'}
        foreach($port in @([int]$Context.Plan.Ports.SshPrimary,[int]$Context.Plan.Ports.SshRescue)|Sort-Object -Unique){
            if(-not(Test-VpsSshConnection $Context root $port)){throw '恢复后 SSH 管理入口复验失败，停止提交并恢复操作前状态。'}
        }
        $currentPlan=$Context.Plan;$currentState=$Context.State;$currentSecrets=$Context.Secrets
        try{
            $Context.Plan=$restorePlan;$Context.State=$restoreState;$Context.Secrets=$restoreSecrets
            $report=Get-MxhHealthAudit $Context -IgnoreActiveRollbackTimer
        }finally{
            $Context.Plan=$currentPlan;$Context.State=$currentState;$Context.Secrets=$currentSecrets
        }
        Show-MxhHealthAudit $report
        if($report.Status -eq 'Critical'){throw '恢复后的服务器状态与所选恢复点清单不一致。'}
        if(-not(Read-VpsYesNo '保留此次恢复结果？' $true)){throw '用户选择恢复到操作前状态。'}
        $journal.Phase='RemoteApplied';Save-VpsJson $journal $journalPath -Private
        foreach($name in @('deployment-plan.json','deployment-state.json','deployment-secrets.private.json')){
            $source=Join-Path $stage $name
            Save-VpsJson (Read-VpsJsonHashtable $source) (Join-Path $Context.ArchivePath $name) -Private
        }
        foreach($directory in @('client-exports','server-configs')){
            $current=Join-Path $Context.ArchivePath $directory
            $source=Join-Path $stage $directory
            if(Test-Path -LiteralPath $current -PathType Container){Move-Item -LiteralPath $current -Destination (Join-Path $stage ($directory+'.before'))}
            if(Test-Path -LiteralPath $source -PathType Container){Copy-Item -LiteralPath $source -Destination $current -Recurse}
        }
        $Context.Plan=Read-VpsJsonHashtable $Context.PlanPath
        $Context.State=Read-VpsJsonHashtable $Context.StatePath
        $Context.Secrets=Read-VpsJsonHashtable $Context.SecretsPath
        $Context.State.MaintenanceTransaction=$transaction
        $Context.State.LastManualRestore=[ordered]@{At=(Get-Date).ToString('o');RestorePoint=$selected.Name;Scope=$scope}
        Save-MxhMaintenanceContext $Context
        $journal.Phase='LocalApplied';Save-VpsJson $journal $journalPath -Private
        Complete-MxhMaintenanceTransaction $Context
        $remoteCommitted=$true
        $journal.Phase='Committed';Save-VpsJson $journal $journalPath -Private
        Write-VpsUi '远端恢复与对应本地元数据恢复已提交。建议立即再运行一次健康审计并建立新基线。' Success
    } catch {
        if(-not $remoteCommitted){
            $Context.State.MaintenanceTransaction=$transaction
            Undo-MxhMaintenanceTransaction $Context $_.Exception.Message
            $journal.Phase='RolledBack';Save-VpsJson $journal $journalPath -Private
        }
        throw
    }
    return
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function New-MxhRotatedProtocolConfig {
    param([Parameter(Mandatory)][Collections.IDictionary]$Config,[Parameter(Mandatory)]$OldSecrets,
        [Parameter(Mandatory)]$NewSecrets,[ValidateSet('RealityEntry','AnyTlsEntry','ShadowsocksLanding')][string]$Role)
    $result=Copy-MxhHashtable $Config
    if($Role -eq 'RealityEntry'){
        $inbounds=@($result.inbounds|Where-Object{$_.protocol -eq 'vless' -and $_.streamSettings.security -eq 'reality'})
        if(-not $inbounds.Count){throw '现有 Reality 配置布局无法安全轮换。'}
        foreach($inbound in $inbounds){
            $clients=@($inbound.settings.clients)
            if($clients.Count -ne 1 -or $clients[0].id -ne $OldSecrets.Xray.Uuid -or $inbound.streamSettings.realitySettings.privateKey -ne $OldSecrets.Xray.RealityPrivateKey){throw 'Reality 用户或密钥已变化，停止轮换；先重新核对实例。'}
            $clients[0].id=[string]$NewSecrets.Xray.Uuid
            $inbound.streamSettings.realitySettings.privateKey=[string]$NewSecrets.Xray.RealityPrivateKey
            $ids=@($inbound.streamSettings.realitySettings.shortIds)
            if([string]$OldSecrets.Xray.ShortId -notin $ids){throw 'Reality shortId 已变化，停止轮换。'}
            $inbound.streamSettings.realitySettings.shortIds=@($ids|ForEach-Object{if($_ -eq $OldSecrets.Xray.ShortId){[string]$NewSecrets.Xray.ShortId}else{$_}})
        }
    }elseif($Role -eq 'AnyTlsEntry'){
        $inbounds=@($result.inbounds|Where-Object{$_.type -eq 'anytls'})
        if($inbounds.Count -ne 1 -or @($inbounds[0].users).Count -ne 1 -or $inbounds[0].users[0].password -ne $OldSecrets.AnyTls.Password){throw 'AnyTLS 用户布局或密码已变化，停止轮换。'}
        $inbounds[0].users[0].password=[string]$NewSecrets.AnyTls.Password
    }else{
        $inbounds=@($result.inbounds|Where-Object{$_.type -eq 'shadowsocks'})
        if($inbounds.Count -ne 1 -or $inbounds[0].password -ne $OldSecrets.Shadowsocks.ServerKey){throw 'Shadowsocks 服务端密钥或布局已变化，停止轮换。'}
        $names=@($inbounds[0].users|ForEach-Object{$_.name})
        if('ipv4-client' -notin $names -or @($names|Sort-Object -Unique).Count -ne $names.Count -or @($names|Where-Object{$_ -notin @('ipv4-client','ipv6-client')}).Count){throw 'Shadowsocks 包含未识别或重复用户，停止轮换。'}
        foreach($user in $inbounds[0].users){
            $key=if($user.name -eq 'ipv4-client'){'PrimaryUserKey'}else{'SecondaryUserKey'}
            if(-not $NewSecrets.Shadowsocks[$key] -or $user.password -ne $OldSecrets.Shadowsocks[$key]){throw 'Shadowsocks 用户凭据已变化，停止轮换。'}
            $user.password=[string]$NewSecrets.Shadowsocks[$key]
        }
    }
    return $result
}

function Invoke-MxhCredentialRotation {
    param($Context)
    while ($true) {
    $inventory=Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State
    $roles=@(Get-MxhManagedProtocolRoles|Where-Object{[bool]$inventory[$_].Installed})
    if(-not $roles.Count){Write-VpsUi '没有可轮换的受管代理协议。' Warning;return}
    $choice=Read-VpsMenu '选择要更换密钥／密码的协议' @($roles|ForEach-Object{Get-MxhProtocolRoleLabel $_}) 1 -AllowBack
    try {
    $role=$roles[$choice-1]
    if(-not [bool]$inventory[$role].Active){throw '为避免备用协议被意外激活，当前只允许轮换正在运行的协议。请先切换到该协议。'}
    if($Context.DryRun){Write-VpsUi "DryRun：将为 $role 生成候选凭据、功能测试后再替换。" Success;return}
    if (-not (Read-VpsYesNo '轮换后旧客户端凭据将失效，确认继续？' $false -AllowBack)) { continue }
    $candidateSecrets=Copy-MxhHashtable $Context.Secrets
    if($role -eq 'RealityEntry'){
        $r=Invoke-VpsRemoteScript $Context 'xray-generate-credentials.sh' @{} -SensitiveOutput
        $encoded=[regex]::Match($r.StdOut,'(?m)^VPSDEPLOY_XRAY_SECRET_B64=([A-Za-z0-9+/=]+)$')
        if(-not $encoded.Success){throw '无法解析新 Reality 凭据。'}
        $candidateSecrets.Xray=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded.Groups[1].Value))|ConvertFrom-Json -AsHashtable)
    } elseif($role -eq 'AnyTlsEntry'){
        $candidateSecrets.AnyTls.Password=New-VpsRandomString 32
    } else {
        $keyBytes=switch([string]$Context.Plan.Shadowsocks.Method){'2022-blake3-aes-128-gcm'{16};'2022-blake3-aes-256-gcm'{32};'2022-blake3-chacha20-poly1305'{32};default{throw 'Shadowsocks 加密方法不支持安全轮换。'}}
        $candidateSecrets.Shadowsocks.PrimaryUserKey=New-MxhRandomBase64Key $keyBytes
        if([bool]$Context.Plan.Shadowsocks.SecondaryIpv6Enabled){$candidateSecrets.Shadowsocks.SecondaryUserKey=New-MxhRandomBase64Key $keyBytes}
    }
    $candidate=[pscustomobject]@{ProjectRoot=$Context.ProjectRoot;Plan=$Context.Plan;ArchivePath=$Context.ArchivePath;PlanPath=$Context.PlanPath;SecretsPath=$Context.SecretsPath;StatePath=$Context.StatePath;LogPath=$Context.LogPath;Secrets=$candidateSecrets;State=$Context.State;DryRun=$false;NonInteractive=$false;Versions=$Context.Versions}
    $current=Invoke-VpsRemoteScript $Context 'maintenance-protocol-config-read.sh' @{ROLE=$role} -TimeoutSeconds 60 -SensitiveOutput
    $original=(Get-VpsMarkerValue $current.StdOut SERVER_CONFIG -Required)|ConvertFrom-Json -AsHashtable
    $originalHash=Get-VpsMarkerValue $current.StdOut SERVER_CONFIG_SHA256 -Required
    $config=New-MxhRotatedProtocolConfig $original $Context.Secrets $candidateSecrets $role
    Start-MxhMaintenanceTransaction $Context 'CredentialRotation'|Out-Null
    try {
        $r=Invoke-VpsRemoteScript $Context 'maintenance-protocol-config-apply.sh' @{ROLE=$role;CONFIG_JSON=($config|ConvertTo-Json -Depth 40);EXPECTED_CONFIG_SHA256=$originalHash;WAS_ACTIVE='true'} -TimeoutSeconds 300 -SensitiveOutput
        if($r.StdOut -notmatch 'VPSDEPLOY_CREDENTIAL_CONFIG_APPLIED'){throw '远端未确认候选凭据配置。'}
        $modulePath=if($role -eq 'RealityEntry'){'modules\90-ClientExport.ps1'}elseif($role -eq 'AnyTlsEntry'){'modules\91-AnyTlsClientExport.ps1'}else{'modules\92-LandingClientExport.ps1'}
        $module=&(Join-Path $Context.ProjectRoot $modulePath); & $module.Invoke $candidate
        if($role -eq 'RealityEntry'){
            Invoke-MxhRealClientValidation -Context $candidate -Protocol Reality|Out-Null
        } elseif($role -eq 'AnyTlsEntry'){
            Invoke-MxhRealClientValidation -Context $candidate -Protocol AnyTLS|Out-Null
        } else {
            Invoke-MxhShadowsocksRealValidation -Context $candidate|Out-Null
            Invoke-MxhShadowsocksExternalValidation -Context $candidate|Out-Null
        }
        $Context.Secrets=$candidateSecrets; $Context.State=$candidate.State
        $Context.State.CredentialRotation=[ordered]@{Role=$role;RotatedAt=(Get-Date).ToString('o');Mode=if($role -eq 'RealityEntry'){'AtomicCutover'}else{'CandidateValidated'} }
        Save-MxhMaintenanceContext $Context
        $serverDir=Join-Path $Context.ArchivePath 'server-configs'
        if($role -eq 'RealityEntry'){Invoke-VpsScpDownload $Context '/usr/local/etc/xray/config.json' (Join-Path $serverDir 'xray-config.json')}
        elseif($role -eq 'AnyTlsEntry'){Invoke-VpsScpDownload $Context '/etc/sing-box-anytls/config.json' (Join-Path $serverDir 'sing-box-anytls-config.private.json')}
        else{Invoke-VpsScpDownload $Context '/etc/sing-box/config.json' (Join-Path $serverDir 'sing-box-config.private.json')}
        Complete-MxhMaintenanceTransaction $Context
        Write-VpsUi '凭据已轮换并完成功能测试；旧值只保留在受保护的维护备份中。' Success
    }catch{Undo-MxhMaintenanceTransaction $Context $_.Exception.Message;throw}
    return
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function Test-MxhSshIdentityConnection {
    param($Context,[string]$Identity,[int]$Port,[string]$User)
    $ssh=Get-VpsCommandPath 'ssh.exe'; $args=@('-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=accept-new','-o','ConnectTimeout=6','-i',$Identity,'-p',[string]$Port,"$User@$($Context.Plan.Server.IPv4)",'printf VPSDEPLOY_NEW_KEY_OK')
    $last=$null
    foreach($attempt in 1..5){
        $last=Invoke-VpsProcess $ssh $args -TimeoutSeconds 20
        if($last.ExitCode -eq 0 -and $last.StdOut -match 'VPSDEPLOY_NEW_KEY_OK'){return $true}
        if($attempt -lt 5){Start-Sleep -Seconds 2}
    }
    Write-VpsLog -Context $Context -Level ERROR -Message "SSH candidate validation failed: user=$User port=$Port exit=$($last.ExitCode) detail=$($last.StdErr.Trim())"
    return $false
}

function Invoke-MxhSshMaintenance {
    param($Context)
    while ($true) {
    $action=Read-VpsMenu 'SSH 登录设置' @('检查登录与服务状态（不改服务器）','更换 SSH 登录密钥','更换 SSH 主／备用端口和密钥') 1 -AllowBack -HelpText '更换密钥或端口时，先保留旧入口并验证新入口，成功后再移除旧公钥和旧端口。第 3 项会同时更换两个端口及密钥，不是只改端口。'
    try {
    if($action -eq 1){Show-MxhHealthAudit (Get-MxhHealthAudit $Context -Persist);return}
    $changePorts=$action -eq 3
    if($changePorts -and [string]$Context.Plan.Firewall.Mode -eq 'PreserveExisting'){throw '保留现有防火墙模式下脚本拒绝自动换端口；请先人工审计并转为受管防火墙。'}
    $primary=if($changePorts){Get-VpsRandomPort}else{[int]$Context.Plan.Ports.SshPrimary}
    $rescue=if($changePorts){Get-VpsRandomPort -Exclude @($primary)}else{[int]$Context.Plan.Ports.SshRescue}
    if($Context.DryRun){Write-VpsUi 'DryRun：将并行保留旧/新入口，验证新密钥后再移除旧入口和旧公钥。' Success;return}
    Write-VpsUi "SSH 候选主/救援端口：$primary / $rescue；验证通过后将替换旧管理密钥。" Warning
    if (-not (Read-VpsYesNo '确认开始 SSH 维护？请保留当前恢复入口。' $false -AllowBack)) { continue }
    Assert-MxhNoPendingLocalTransaction $Context
    $activeKey=Get-VpsSshKeyPath $Context
    $managedKey=Get-VpsManagedSshKeyPath $Context
    $managedPublic=Get-VpsSshPublicKeyPath $Context
    $keygen=Get-VpsCommandPath 'ssh-keygen.exe'
    $oldPublic=if(Test-Path -LiteralPath $managedPublic -PathType Leaf){(Get-Content -Raw -LiteralPath $managedPublic).Trim()}else{
        $derived=Invoke-VpsProcess $keygen @('-y','-f',$activeKey) -TimeoutSeconds 60
        if($derived.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($derived.StdOut)){throw '无法从当前活动私钥派生旧公钥，已停止轮换。'}
        $derived.StdOut.Trim()
    }
    $temp=$managedKey+'.rotation-'+(Get-Date -Format yyyyMMddHHmmss)
    $r=Invoke-VpsProcess $keygen @('-t','ed25519','-a','64','-N','','-C',$Context.Plan.NodeName,'-f',$temp) -TimeoutSeconds 60
    if($r.ExitCode -ne 0){throw '生成候选 SSH 密钥失败。'}; Set-VpsOpenSshPrivateKeyAccess $temp
    $newPublic=(Get-Content -Raw ($temp+'.pub')).Trim(); $oldPorts=@([int]$Context.Plan.Ports.SshPrimary,[int]$Context.Plan.Ports.SshRescue)|Sort-Object -Unique
    $rotationStamp=Get-Date -Format yyyyMMddHHmmss
    $keyBackup=$managedKey+'.bak-'+$rotationStamp
    $publicBackup=$managedPublic+'.bak-'+$rotationStamp
    $managedKeyExisted=Test-Path -LiteralPath $managedKey -PathType Leaf
    $managedPublicExisted=Test-Path -LiteralPath $managedPublic -PathType Leaf
    $oldSshKeyPlan=Copy-MxhHashtable $Context.Plan.SshKey
    $oldPlan=Copy-MxhHashtable $Context.Plan;$oldState=Copy-MxhHashtable $Context.State
    $sshBackup=$null
    $sshJournal=$null;$sshJournalPath=Join-Path $Context.ArchivePath 'ssh-maintenance-pending.private.json'
    $localMutationStarted=$false
    try{
        $sshParameters=@{OLD_PORTS=$oldPorts-join',';NEW_PRIMARY=[string]$primary;NEW_RESCUE=[string]$rescue;NEW_PUBLIC_KEY=$newPublic;ADMIN_USER=[string]$Context.Plan.AdminUser;FIREWALL_REQUIRED=$changePorts.ToString().ToLowerInvariant()}
        if($changePorts){
            $oldFirewall=Get-MxhProtocolFirewallParameters $Context.Plan $Context.State (Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State)
            foreach($key in $oldFirewall.Keys){$sshParameters[$key]=$oldFirewall[$key]}
        }
        $r=Invoke-VpsRemoteScript $Context 'maintenance-ssh-apply.sh' $sshParameters -TimeoutSeconds 180
        if($r.StdOut -notmatch 'VPSDEPLOY_SSH_MAINTENANCE_STAGED'){throw 'SSH 候选入口未确认。'}
        $sshBackup=Get-VpsMarkerValue $r.StdOut BACKUP_DIR -Required
        if($changePorts){
            $tempPlan=Copy-MxhHashtable $Context.Plan; $tempPlan.Ports.SshPrimary=$primary;$tempPlan.Ports.SshRescue=$rescue
            $parameters=Get-MxhProtocolFirewallParameters $tempPlan $Context.State (Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State)
            $parameters.TCP_PORTS=(@($oldPorts+$primary+$rescue+($parameters.TCP_PORTS-split','|ForEach-Object{[int]$_}))|Sort-Object -Unique)-join','
            $parameters.EXPECTED_TRANSACTION=$sshBackup
            Invoke-VpsRemoteScript $Context 'nftables-apply.sh' $parameters -TimeoutSeconds 180|Out-Null
        }
        $portChecks=@([pscustomobject]@{Label='Primary';Port=$primary},[pscustomobject]@{Label='Rescue';Port=$rescue})|Sort-Object Port -Unique
        foreach($check in $portChecks){foreach($user in @('root',[string]$Context.Plan.AdminUser)|Sort-Object -Unique){if(-not(Test-MxhSshIdentityConnection $Context $temp $check.Port $user)){throw "候选 SSH 密钥复验失败：$user / $($check.Label)。"}}}
        if($managedKeyExisted){Copy-Item -LiteralPath $managedKey -Destination $keyBackup -Force;Set-VpsOpenSshPrivateKeyAccess $keyBackup}
        if($managedPublicExisted){Copy-Item -LiteralPath $managedPublic -Destination $publicBackup -Force}
        $sshJournal=@{Phase='RemoteStaged';Backup=$sshBackup;OldPlan=$oldPlan;OldState=$oldState;ManagedKey=$managedKey;ManagedPublic=$managedPublic;KeyBackup=$keyBackup;PublicBackup=$publicBackup;KeyExisted=$managedKeyExisted;PublicExisted=$managedPublicExisted}
        Save-VpsJson $sshJournal $sshJournalPath -Private
        $localMutationStarted=$true
        Copy-Item -LiteralPath $temp -Destination $managedKey -Force
        Copy-Item -LiteralPath ($temp+'.pub') -Destination $managedPublic -Force
        Set-VpsOpenSshPrivateKeyAccess $managedKey
        $Context.Plan.SshKey.Mode='GenerateManaged'
        $Context.Plan.SshKey.RotatedFromMode=[string]$oldSshKeyPlan.Mode
        $Context.Plan.SshKey.RotatedAt=(Get-Date).ToString('o')
        foreach($check in $portChecks){foreach($user in @('root',[string]$Context.Plan.AdminUser)|Sort-Object -Unique){if(-not(Test-VpsSshConnection $Context $user $check.Port)){throw "本地密钥切换后复验失败：$user / $($check.Label)。"}}}
        $r=Invoke-VpsRemoteScript $Context 'maintenance-ssh-commit.sh' @{EXPECTED_BACKUP=$sshBackup;NEW_PRIMARY=[string]$primary;NEW_RESCUE=[string]$rescue;NEW_PUBLIC_KEY=$newPublic;OLD_PUBLIC_KEY=$oldPublic;ADMIN_USER=[string]$Context.Plan.AdminUser} -TimeoutSeconds 180
        if($r.StdOut -notmatch 'VPSDEPLOY_SSH_MAINTENANCE_COMMITTED'){throw 'SSH 维护提交失败。'}
        $Context.Plan.Ports.SshPrimary=$primary;$Context.Plan.Ports.SshRescue=$rescue;$Context.State.CurrentManagementPort=$primary
        if($changePorts){Invoke-MxhProtocolFirewall $Context (Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State) 'SshMaintenanceFinalFirewall' -ExpectedTransaction $sshBackup}
        Save-MxhMaintenanceContext $Context
        $sshJournal.Phase='LocalPrepared';Save-VpsJson $sshJournal $sshJournalPath -Private
        $finalized=Invoke-VpsRemoteScript $Context 'maintenance-ssh-finalize.sh' @{EXPECTED_BACKUP=$sshBackup}
        if($finalized.StdOut -notmatch 'VPSDEPLOY_SSH_MAINTENANCE_FINALIZED'){throw 'SSH 最终提交未确认，请检查恢复记录。'}
        $sshJournal.Phase='Committed';Save-VpsJson $sshJournal $sshJournalPath -Private
        Write-VpsUi '新密钥已在 root/admin 与双端口验证，旧公钥和旧端口已移除。' Success
    }catch{
        if($sshBackup){try { Invoke-VpsRemoteScript $Context 'maintenance-ssh-rollback.sh' @{EXPECTED_BACKUP=$sshBackup}|Out-Null } catch { Write-VpsUi 'SSH 立即恢复未确认，保留密钥备份并检查远端事务状态。' Error;throw }}
        if($localMutationStarted){
            $Context.Plan.SshKey=$oldSshKeyPlan
            if($managedKeyExisted -and (Test-Path -LiteralPath $keyBackup)){Copy-Item -LiteralPath $keyBackup -Destination $managedKey -Force}elseif(Test-Path -LiteralPath $managedKey){Remove-Item -LiteralPath $managedKey -Force}
            if($managedPublicExisted -and (Test-Path -LiteralPath $publicBackup)){Copy-Item -LiteralPath $publicBackup -Destination $managedPublic -Force}elseif(Test-Path -LiteralPath $managedPublic){Remove-Item -LiteralPath $managedPublic -Force}
            if(Test-Path -LiteralPath $managedKey){Set-VpsOpenSshPrivateKeyAccess $managedKey}
        }
        $Context.Plan=$oldPlan;$Context.State=$oldState
        if($sshBackup){Save-MxhMaintenanceContext $Context}
        if($sshJournal){$sshJournal.Phase='RolledBack';Save-VpsJson $sshJournal $sshJournalPath -Private}
        throw
    }finally{foreach($p in @($temp,$temp+'.pub')){if(Test-Path $p){Remove-Item $p -Force}}}
    return
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function Invoke-MxhFirewallMaintenance {
    param($Context)
    while ($true) {
    $mode=[string]$Context.Plan.Firewall.Mode
    $options=if($mode -eq 'PreserveExisting'){@('检查规则与服务状态（不改服务器）','改由本工具管理（替换现有规则）')}else{@('检查规则与服务状态（不改服务器）','按当前协议重新生成规则','修改 Shadowsocks 允许连接的 IP')}
    $modeLabel=if($mode -eq 'PreserveExisting'){'保留原有规则'}else{'本工具管理规则'}
    $choice=Read-VpsMenu "防火墙规则（$modeLabel）" $options 1 -AllowBack -HelpText '检查只读取服务器状态。接管或重新生成会替换 nftables 规则；修改允许连接的 IP 会重新应用规则。执行时保留 SSH 恢复保护，不能代替服务商控制台的安全组设置。'
    try {
    if($choice -eq 1){Show-MxhHealthAudit (Get-MxhHealthAudit $Context -Persist);return}
    if($Context.DryRun){Write-VpsUi 'DryRun：将先预检候选规则，再事务化应用和复验 SSH/协议监听。' Success;return}
    $new4=@($Context.Plan.Shadowsocks.TrustedEntryIPv4s);$new6=@($Context.Plan.Shadowsocks.TrustedEntryIPv6s)
    if($mode -eq 'PreserveExisting'){
        if((Read-VpsText '输入 ADOPT-MANAGED-NFT 确认替换现有规则' -AllowBack)-cne 'ADOPT-MANAGED-NFT'){throw '确认短语不匹配，未接管防火墙。'}
    }
    if($choice -eq 3){
        $new4=ConvertTo-VpsIpAllowlist (Read-VpsText '可信入口 IPv4，逗号分隔' -Default ($new4-join',') -AllowEmpty -AllowBack) IPv4
        $new6=ConvertTo-VpsIpAllowlist (Read-VpsText '可信入口 IPv6，逗号分隔' -Default ($new6-join',') -AllowEmpty -AllowBack) IPv6
        if(-not $new4.Count -and -not $new6.Count){throw 'Shadowsocks 白名单不能同时为空。'}
    }
    Start-MxhMaintenanceTransaction $Context 'FirewallMaintenance' -Components Firewall|Out-Null
    try{
        if($mode -eq 'PreserveExisting'){$Context.Plan.Firewall.Mode='ManagedNftables'}
        $Context.Plan.Shadowsocks.TrustedEntryIPv4s=@($new4);$Context.Plan.Shadowsocks.TrustedEntryIPv6s=@($new6)
        Invoke-MxhProtocolFirewall $Context (Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State) 'IndependentFirewall'
        foreach($port in @([int]$Context.Plan.Ports.SshPrimary,[int]$Context.Plan.Ports.SshRescue)|Sort-Object -Unique){if(-not(Test-VpsSshConnection $Context root $port)){throw '防火墙应用后 SSH 复验失败。'}}
        $report=Get-MxhHealthAudit $Context; if($report.Status -eq 'Critical'){throw '防火墙应用后的健康审计出现严重项。'}
        Complete-MxhMaintenanceTransaction $Context;Save-MxhMaintenanceContext $Context;Write-VpsUi '防火墙候选已通过语法、双 SSH 和服务状态复验。' Success
    }catch{Undo-MxhMaintenanceTransaction $Context $_.Exception.Message;throw}
    return
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function Update-MxhKomariServiceState {
    param([Parameter(Mandatory)]$Context)
    $result=Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='Status'} -TimeoutSeconds 60
    foreach($item in @(@{Unit='komari-agent.service';Key='KomariAgent'},@{Unit='komari.service';Key='KomariController'},@{Unit='cloudflared.service';Key='Cloudflared'})) {
        $match=[regex]::Match($result.StdOut,'(?m)^'+[regex]::Escape($item.Unit)+'=(true|false),(true|false),(true|false)\r?$')
        if(-not $match.Success){throw '无法同步 Komari 实际服务状态，尚未提交。'}
        $state=@{Installed=$match.Groups[1].Value -eq 'true';Enabled=$match.Groups[2].Value -eq 'true';Active=$match.Groups[3].Value -eq 'true'}
        if($item.Key -eq 'KomariAgent'){$Context.State.KomariInstalled=$state.Installed;$Context.Plan.Komari.Enabled=$state.Active}
        else{$Context.State[$item.Key]=$state}
    }
}

function Invoke-MxhKomariUpgrade {
    param([Parameter(Mandatory)]$Context,[ValidateSet('KomariAgent','KomariController')][string]$Component)
    if($Context.DryRun){Write-VpsUi "DryRun：$Component 共用升级预检、备份、迁移确认与回滚流程。" Info;return}
    if($Component -eq 'KomariController'){Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='ControllerPreflight'} -TimeoutSeconds 60|Out-Null}
    Start-MxhMaintenanceTransaction $Context 'KomariUpgrade' -Components $Component -QuiesceKomariController:($Component -eq 'KomariController')|Out-Null
    try {
        $arch=Get-VpsSupportedAssetArchitecture -Architecture ([string]$Context.State.Audit.Architecture)
        $catalog=if($Component -eq 'KomariAgent'){$Context.Versions.komari_agent}else{$Context.Versions.komari_controller}
        $asset=$catalog.assets.$arch
        $parameters=@{ACTION=if($Component -eq 'KomariAgent'){'AgentUpgrade'}else{'ControllerUpgrade'};VERSION=[string]$catalog.version;ASSET_NAME=[string]$asset.name;SHA256=[string]$asset.sha256}
        if($Component -eq 'KomariController'){
            $backup=Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='ControllerBackup';INCLUDE_TUNNEL='false'} -TimeoutSeconds 600
            $remote=Get-VpsMarkerValue $backup.StdOut KOMARI_BACKUP -Required
            $directory=Join-Path $Context.ArchivePath 'komari-backups';[IO.Directory]::CreateDirectory($directory)|Out-Null
            $local=Join-Path $directory (Split-Path -Leaf $remote);Invoke-VpsScpDownload $Context $remote $local
            $parameters.BACKUP_FILE=$remote
        }
        $result=Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' $parameters -TimeoutSeconds 1200
        if($result.StdOut -notmatch 'VPSDEPLOY_KOMARI_LIFECYCLE_OK'){throw 'Komari 程序更新未确认。'}
        if($Component -eq 'KomariController'){
            $migration=Get-VpsMarkerValue $result.StdOut KOMARI_MIGRATION_REQUIRED -Required
            while($migration -eq 'true'){
                Write-VpsUi '请在面板 /admin/database-migration 完成迁移，再返回复验。20 分钟回滚保护仍有效；取消或超时会恢复升级前数据。' Warning
                $choice=Read-VpsMenu '等待面板数据库迁移' @('已在面板完成，重新检查','取消升级并回滚') 1 -AllowBack -HelpText '不会自动迁移或删除历史数据。超过保护期限时，后续命令会拒绝写入。'
                if($choice -eq 2){throw '用户取消 Komari 数据库迁移。'}
                $verification=Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='ControllerVerify';VERSION=[string]$catalog.version} -TimeoutSeconds 120
                $migration=Get-VpsMarkerValue $verification.StdOut KOMARI_MIGRATION_REQUIRED -Required
            }
            if($migration -eq 'deferred'){Write-VpsUi '原服务未运行，数据库迁移将在下次启动后人工完成。' Warning}
            elseif($migration -ne 'false'){throw '无法确认数据库迁移状态，未提交。'}
            $Context.Plan.Komari.ControllerVersion=[string]$catalog.version
            Write-VpsUi "升级前一致性备份已下载：$local" Success
        }else{$Context.Plan.Komari.AgentVersion=[string]$catalog.version}
        Update-MxhKomariServiceState $Context
        $report=Get-MxhHealthAudit $Context -IgnoreActiveRollbackTimer
        if($report.Status -eq 'Critical'){throw 'Komari 升级后健康检查存在严重异常。'}
        Complete-MxhMaintenanceTransaction $Context
        $Context.State.LastControlledUpgrade=@{Component=$Component;At=(Get-Date).ToString('o');Catalog='versions.json'}
        Save-MxhMaintenanceContext $Context
        Write-VpsUi '程序、实际运行状态和本地记录已核对；浏览器登录与主题仍需人工确认。' Success
    }catch{Undo-MxhMaintenanceTransaction $Context $_.Exception.Message;throw}
}

function Invoke-MxhControlledUpgrade {
    param($Context)
    while ($true) {
    $inventory=Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State
    $roles=@(Get-MxhManagedProtocolRoles|Where-Object{[bool]$inventory[$_].Installed})
    if($Context.State.Contains('KomariInstalled') -and [bool]$Context.State.KomariInstalled){$roles+='KomariAgent'}
    if($Context.State.Contains('KomariController') -and [bool]$Context.State.KomariController.Installed){$roles+='KomariController'}
    if(-not $roles.Count){Write-VpsUi '没有可升级的受管组件。' Warning;return}
    $choice=Read-VpsMenu '选择要更新的服务' @($roles|ForEach-Object{if($_ -eq 'KomariAgent'){'Komari Agent'}elseif($_ -eq 'KomariController'){'Komari Controller'}else{Get-MxhProtocolRoleLabel $_}}) 1 -AllowBack -HelpText '默认使用项目记录的版本和下载校验值，不代表官方最新版。Xray 可进一步选择版本来源。更新前备份，更新后检查服务和连接。'
    try {
    $role=$roles[$choice-1]
    $targetVersion=$null;$targetChannel=$null
    if($role -in @(Get-MxhManagedProtocolRoles) -and -not [bool]$inventory[$role].Active){
        throw '该协议当前处于停用备用状态，不能直接更新并进行真实连接验收。请先在“管理代理协议”中启用或切换到该协议，再执行更新；未修改服务器。'
    }
    if($role -eq 'RealityEntry'){
        $channelChoice=Read-VpsMenu 'Xray 升级目标' @(
            "保持计划版本（$($Context.Plan.Reality.XrayVersion)）",
            "切换到当前固定验证版（$($Context.Versions.xray.version)）",
            '解析并切换到 XTLS/Xray-core 官方最新稳定版'
        ) 1 -AllowBack
        $targetVersion=if($channelChoice -eq 1){[string]$Context.Plan.Reality.XrayVersion}elseif($channelChoice -eq 2){[string]$Context.Versions.xray.version}else{Resolve-VpsXrayVersion -ProjectRoot $Context.ProjectRoot -Channel LatestStable}
        $targetChannel=if($channelChoice -eq 3){'LatestStable'}elseif($channelChoice -eq 2){'FixedVerified'}elseif($Context.Plan.Reality.Contains('XrayVersionChannel')){[string]$Context.Plan.Reality.XrayVersionChannel}else{'ImportedOrLegacy'}
        if($targetChannel -in @('FixedVerified','LatestStable')){
            Show-VpsXrayVersionSelection -Channel $targetChannel -ResolvedVersion $targetVersion `
                -FixedVersion ([string]$Context.Versions.xray.version) -Action '升级'
        }else{
            Write-VpsUi "Xray 版本来源：保持现有部署计划（$targetChannel）。" Info
            Write-VpsUi "本次实际升级版本：Xray $targetVersion。" Success
        }
    }
    if($Context.DryRun){Write-VpsUi "DryRun：将下载并校验固定资产、配置检查、同版本可重复安装、失败自动回滚：$role" Success;return}
    if($role -in @('KomariAgent','KomariController')){Invoke-MxhKomariUpgrade $Context $role;return}
    Start-MxhMaintenanceTransaction $Context 'ControlledUpgrade'|Out-Null
    try{
        $arch=Get-VpsSupportedAssetArchitecture -Architecture ([string]$Context.State.Audit.Architecture)
        if($role -eq 'RealityEntry'){
            Invoke-VpsRemoteScript $Context 'xray-install.sh' @{VERSION=$targetVersion;INSTALLER_URL=[string]$Context.Versions.xray.installer_url;INSTALLER_SHA256=[string]$Context.Versions.xray.installer_sha256} -TimeoutSeconds 1200|Out-Null
            $Context.Plan.Reality.XrayVersion=$targetVersion;$Context.Plan.Reality.XrayVersionChannel=$targetChannel
            # Binary-only upgrade: preserve all existing users, routing and dialer fields.
        }elseif($role -in @('AnyTlsEntry','ShadowsocksLanding')){
            $asset=$Context.Versions.sing_box.assets.$arch; $script=if($role -eq 'AnyTlsEntry'){'sing-box-anytls-install.sh'}else{'sing-box-install.sh'}
            $params=@{VERSION=[string]$Context.Versions.sing_box.version;ASSET_NAME=[string]$asset.name;SHA256=[string]$asset.sha256}
            if($role -eq 'ShadowsocksLanding'){$params.NEED_BIND_INTERFACE=([bool]$Context.Plan.Shadowsocks.SecondaryBindInterface).ToString().ToLowerInvariant()}
            Invoke-VpsRemoteScript $Context $script $params -TimeoutSeconds 1200|Out-Null
            if($role -eq 'AnyTlsEntry'){$Context.Plan.AnyTls.SingBoxVersion=[string]$Context.Versions.sing_box.version}
            else{$Context.Plan.Shadowsocks.SingBoxVersion=[string]$Context.Versions.sing_box.version}
        }
        if($role -notin @('KomariAgent','KomariController')){
            $stateResult=Invoke-VpsRemoteScript $Context 'protocol-lifecycle-apply-state.sh' @{
                REALITY_ENABLED=([bool]$inventory.RealityEntry.Enabled).ToString().ToLowerInvariant()
                ANYTLS_ENABLED=([bool]$inventory.AnyTlsEntry.Enabled).ToString().ToLowerInvariant()
                SHADOWSOCKS_ENABLED=([bool]$inventory.ShadowsocksLanding.Enabled).ToString().ToLowerInvariant()
                RESTART_ROLE=$role
            } -TimeoutSeconds 300
            if($stateResult.StdOut -notmatch 'VPSDEPLOY_PROTOCOL_STATE_APPLIED'){throw '升级后原服务启停状态恢复未确认。'}
        }
        $protocolValidations=@()
        if($role -eq 'RealityEntry'){
            $clientModule=& (Join-Path $Context.ProjectRoot 'modules\90-ClientExport.ps1')
            & $clientModule.Invoke $Context
            $protocolValidations+=Invoke-MxhRealClientValidation -Context $Context -Protocol Reality
        }elseif($role -eq 'AnyTlsEntry'){
            $clientModule=& (Join-Path $Context.ProjectRoot 'modules\91-AnyTlsClientExport.ps1')
            & $clientModule.Invoke $Context
            $protocolValidations+=Invoke-MxhRealClientValidation -Context $Context -Protocol AnyTLS
        }elseif($role -eq 'ShadowsocksLanding'){
            $protocolValidations+=Invoke-MxhShadowsocksRealValidation -Context $Context
            $protocolValidations+=Invoke-MxhShadowsocksExternalValidation -Context $Context
        }
        $report=Get-MxhHealthAudit $Context -IgnoreActiveRollbackTimer;if($report.Status -eq 'Critical'){throw '升级后健康审计出现严重项。'}
        $validationStatus=if($protocolValidations.Count -gt 0 -and -not @($protocolValidations|Where-Object Status -ne 'Passed').Count){'Passed'}else{'Incomplete'}
        Complete-MxhMaintenanceTransaction $Context;$Context.State.LastControlledUpgrade=[ordered]@{Component=$role;At=(Get-Date).ToString('o');Catalog='versions.json';ValidationStatus=$validationStatus};Save-MxhMaintenanceContext $Context
        if($validationStatus -eq 'Passed'){
            Write-VpsUi '固定资产校验、安装、配置检查、服务复验和真实协议验收均已完成。' Success
        }else{
            Write-VpsUi '更新已完成，但部分协议验收未通过完整执行；跳过项已记入私有记录，不计为验收通过。' Warning
        }
    }catch{Undo-MxhMaintenanceTransaction $Context $_.Exception.Message;throw}
    return
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function Invoke-MxhClientCandidateMerge {
    param($Context)
    $instanceDirectory=[string]$Context.Plan.Paths.InstanceDirectory
    $providerDirectory=Split-Path -Parent $instanceDirectory
    $instanceRoot=Split-Path -Parent $providerDirectory
    Write-VpsUi "将打开独立客户端配置设计器；当前实例可从受管计划列表提取：$($Context.Plan.NodeName)" Info
    Invoke-MxhClientAuthorityDesigner -ProjectRoot $Context.ProjectRoot -InstanceRoot $instanceRoot -DryRun:$Context.DryRun
}

function Get-MxhKomariBackupComponents {
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.Formats.Tar
    $stream=[IO.File]::OpenRead($Path)
    $gzip=[IO.Compression.GZipStream]::new($stream,[IO.Compression.CompressionMode]::Decompress)
    $reader=[System.Formats.Tar.TarReader]::new($gzip,$true)
    $tunnelNames=@('etc/systemd/system/cloudflared.service','usr/local/bin/cloudflared','usr/bin/cloudflared')
    $found=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    try{
        while($null -ne ($entry=$reader.GetNextEntry())){
            $name=$entry.Name
            while($name.StartsWith('./',[StringComparison]::Ordinal)){$name=$name.Substring(2)}
            if($name -in $tunnelNames){$found.Add($name)|Out-Null}
        }
    }finally{$reader.Dispose();$gzip.Dispose();$stream.Dispose()}
    if($found.Count -gt 0){
        if(-not $found.Contains($tunnelNames[0]) -or (-not $found.Contains($tunnelNames[1]) -and -not $found.Contains($tunnelNames[2]))){
            throw '备份中的隧道文件不完整，已停止恢复；请选择同时包含隧道服务和程序的备份。'
        }
        return @('KomariController','Cloudflared')
    }
    return @('KomariController')
}

function Invoke-MxhKomariLifecycle {
    param($Context)
    while ($true) {
    $choice=Read-VpsMenu 'Komari 监控管理' @('检查监控服务状态','安装或修复 Agent／更换 Token','更新 Agent（保留 Token）','卸载 Agent','备份监控面板（Controller）','从备份恢复监控面板','更换 Cloudflare Tunnel Token','更新监控面板（自动备份）','卸载监控面板和 Tunnel 连接器') 1 -AllowBack -HelpText @'
Agent 是 VPS 上的监控采集端；Controller 是监控面板；Tunnel 连接器用于通过 Cloudflare 访问面板。
第 2 项会要求站点地址和 Agent Token；第 3、8 项使用项目记录的固定版本，不一定是官方最新版。
状态审计只读；安装、轮换、升级和卸载会修改当前 VPS。
Controller 升级会停服务创建完整数据备份与一致性事务快照；失败同时恢复数据库、插件/主题数据和旧二进制。
若 1.5 出现数据库迁移引导，须在面板手动完成后返回复验；取消会回滚，不把迁移页面能打开当成升级已完成。
脚本验证版本、回环监听、HTTP、服务状态与 Tunnel 服务；登录、TOTP 和主题视觉效果仍需用户在浏览器最终确认。
'@
    try {
    if($Context.DryRun){Write-VpsUi 'DryRun：只显示 Komari 生命周期动作，不读取 Token、不连接服务器。' Success;return}
    $endpoint=$null
    $token=$null
    if($choice -eq 2){
        $endpointDefault=if($Context.Plan.Komari.Endpoint){[string]$Context.Plan.Komari.Endpoint}else{[string]$Context.Versions.komari_agent.endpoint_default}
        $inputValues=Read-VpsForm -Values @{endpoint=$endpointDefault} -Steps @(
            @{Key='endpoint';Read={param($v) Read-VpsText 'Komari 站点 HTTPS 地址' -Default $v.endpoint -AllowBack -Validate{param($value)$uri=$null;[Uri]::TryCreate($value,'Absolute',[ref]$uri)-and$uri.Scheme-eq'https'}}}
            @{Key='token';Read={param($v) Read-MxhSecretText 'Komari Agent Token' -AllowBack}}
        )
        $endpoint=$inputValues.endpoint;$token=$inputValues.token;$inputValues.Clear()
    }
    if($choice -eq 7){$token=Read-MxhSecretText 'Cloudflare Tunnel Token' -AllowBack}
    if($choice -eq 1){$r=Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='Status'};Write-VpsUi 'Komari 服务状态审计完成（详细结果只写入私有日志）。' Success;return}
    if($choice -eq 9 -and (Read-VpsText '输入 REMOVE-KOMARI-CONTROLLER 确认' -AllowBack)-cne 'REMOVE-KOMARI-CONTROLLER'){
        Write-VpsUi '确认短语不匹配，未卸载。' Warning
        continue
    }
    if($choice -in @(3,8)){Invoke-MxhKomariUpgrade $Context $(if($choice -eq 3){'KomariAgent'}else{'KomariController'});return}
    if($choice -eq 6){
        $file=Read-VpsText 'Controller 备份 tar.gz 完整路径' -AllowBack -Validate{param($v)Test-VpsExistingInputPath -Value $v -PathType Leaf} -ValidationMessage '找不到备份文件，或路径混用了 / 与 \。'
        $file=ConvertTo-VpsInputPath -Value $file
        if((Split-Path -Leaf $file) -notmatch '^komari-controller-\d{8}-\d{6}\.tar\.gz$'){throw '请选择本工具生成的 komari-controller-日期-时间.tar.gz 备份。'}
        $backupHash=Get-MxhFileFingerprint $file
        $restoreComponents=@(Get-MxhKomariBackupComponents -Path $file)
        Write-VpsUi $(if('Cloudflared' -in $restoreComponents){'恢复范围：主控及备份内的隧道文件；恢复期间隧道可能短暂中断。'}else{'恢复范围：仅主控；当前隧道文件及运行状态保持不变。'}) Info
        $activate=Read-VpsYesNo '恢复后启用 Controller？（同机验证可选否）' $false -AllowBack
        if((Get-MxhFileFingerprint $file) -ne $backupHash){throw '备份在读取或确认期间发生变化，已停止恢复；请重新选择备份。'}
        $remote='/root/'+(Split-Path -Leaf $file)
        Invoke-VpsScpUpload $Context $file $remote
    }
    if($choice -in @(2,4,6,7,9)){
        $components=if($choice -in @(2,4)){@('KomariAgent')}elseif($choice -eq 7){@('Cloudflared')}elseif($choice -eq 6){$restoreComponents}else{@('KomariController','Cloudflared')}
        Start-MxhMaintenanceTransaction $Context 'KomariLifecycle' -Components $components -QuiesceKomariController:($choice -in @(6,9))|Out-Null
    }
    try{
        if($choice -eq 2){
            try{$arch=Get-VpsSupportedAssetArchitecture -Architecture ([string]$Context.State.Audit.Architecture);$asset=$Context.Versions.komari_agent.assets.$arch
                $r=Invoke-VpsRemoteScript $Context 'komari-agent.sh' @{ENDPOINT=$endpoint;TOKEN=$token;NODE_NAME=[string]$Context.Plan.NodeName;VERSION=[string]$Context.Versions.komari_agent.version;ASSET_NAME=[string]$asset.name;SHA256=[string]$asset.sha256} -TimeoutSeconds 1200 -SensitiveOutput
            }finally{$token=$null};$Context.Plan.Komari.Endpoint=$endpoint;$Context.Plan.Komari.Enabled=$true;$Context.Plan.Komari.AgentVersion=[string]$Context.Versions.komari_agent.version;$Context.State.KomariInstalled=$true
        }elseif($choice -eq 4){Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='AgentUninstall'}|Out-Null;$Context.Plan.Komari.Enabled=$false;$Context.State.KomariInstalled=$false;$Context.Plan.Komari.Remove('AgentVersion')|Out-Null
        }elseif($choice -eq 5){
            $r=Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='ControllerBackup'} -TimeoutSeconds 600;$remote=Get-VpsMarkerValue $r.StdOut KOMARI_BACKUP -Required
            $dir=Join-Path $Context.ArchivePath 'komari-backups';[IO.Directory]::CreateDirectory($dir)|Out-Null;$local=Join-Path $dir (Split-Path -Leaf $remote);Invoke-VpsScpDownload $Context $remote $local;Write-VpsUi "Controller 备份已下载：$local" Success;return
        }elseif($choice -eq 6){
            $restore=Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='ControllerRestore';BACKUP_FILE=$remote;BACKUP_SHA256=$backupHash;FINAL_ACTIVE=$activate.ToString().ToLowerInvariant()} -TimeoutSeconds 600
            if($restore.StdOut -notmatch 'VPSDEPLOY_KOMARI_LIFECYCLE_OK'){throw 'Controller 恢复未确认。'}
            $Context.Plan.Komari.ControllerVersion=Get-VpsMarkerValue $restore.StdOut KOMARI_RESTORED_VERSION -Required
            Write-VpsUi '数据已隔离还原，服务已完成启动检查；隧道仅在备份包含时还原，否则保留现状。浏览器登录与历史数据仍需确认。' Success
        }elseif($choice -eq 7){
            try{Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='TunnelRotate';TUNNEL_TOKEN=$token} -TimeoutSeconds 300 -SensitiveOutput|Out-Null}finally{$token=$null}
        }else{
            Invoke-VpsRemoteScript $Context 'maintenance-komari.sh' @{ACTION='ControllerUninstall'} -TimeoutSeconds 300|Out-Null
            $Context.Plan.Komari.Remove('ControllerVersion')|Out-Null
        }
        if($choice -in @(2,4,6,7,9)){
            Update-MxhKomariServiceState $Context
            Complete-MxhMaintenanceTransaction $Context;Save-MxhMaintenanceContext $Context
        }
        Write-VpsUi 'Komari 生命周期操作已提交。' Success
    }catch{if($choice -in @(2,4,6,7,9)){Undo-MxhMaintenanceTransaction $Context $_.Exception.Message};throw}
    return
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function Invoke-MxhDecommission {
    param($Context)
    while ($true) {
    $choice=Read-VpsMenu '停用或卸载服务（保留 SSH 和系统）' @('只检查并生成报告','停用代理和监控 Agent（保留文件）','卸载代理和 Agent（保留远端备份）','卸载代理和 Agent，并删除远端备份','卸载以上服务及监控面板／Tunnel，并删除远端备份') 1 -AllowBack -HelpText @'
只处理本工具管理的组件，不删除 VPS、不重装系统，也不移除 SSH。
第 2 项停止服务并关闭开机启动。第 3 项先备份再删除程序和配置，保留远端恢复点。
第 4、5 项在完成本地备份后删除远端恢复点；第 5 项还卸载 Komari 面板和 Cloudflare Tunnel 连接器。
涉及卸载或删除备份时会再次要求确认，请先确认本地备份可用。
'@
    try {
    $report=Get-MxhHealthAudit $Context -Persist;Show-MxhHealthAudit $report
    if($choice -eq 1){Write-VpsUi '退役预检已完成，没有修改 VPS。' Success;return}
    $scope=if($choice -eq 2){'Disable'}else{'RemoveManaged'};$wipeBackups=$choice -in @(4,5);$removeController=$choice -eq 5
    if((Read-VpsText '输入 DECOMMISSION 确认' -AllowBack)-cne 'DECOMMISSION'){Write-VpsUi '未退役。' Warning;return}
    if($removeController -and (Read-VpsText '再次输入 DECOMMISSION-ALL 确认移除 Controller/Connector' -AllowBack)-cne 'DECOMMISSION-ALL'){Write-VpsUi '未执行整机退役。' Warning;return}
    if($Context.DryRun){Write-VpsUi "DryRun：将执行 $scope；SSH 和系统文件保留。" Success;return}
    $layout=(Get-MxhClientLayoutTemplate -ProjectRoot $Context.ProjectRoot).Value
    $clash=[string]$layout.authority_defaults.clash;$sing=[string]$layout.authority_defaults.sing_box
    if((Test-Path $clash) -and (Test-Path $sing)){
        $out=Join-Path $Context.ArchivePath ('decommission-client-candidate\'+(Get-Date -Format yyyyMMdd-HHmmss));[IO.Directory]::CreateDirectory($out)|Out-Null
        $python=Get-VpsCommandPath 'python.exe';$script=Join-Path $Context.ProjectRoot 'scripts\merge_client_authority.py'
        $r=Invoke-VpsProcess $python @($script,'--clash',$clash,'--sing-box',$sing,'--fragments',(Join-Path $Context.ArchivePath 'client-exports'),'--output',$out,'--roles','','--remove-prefix',[string]$Context.Plan.NodeName) -TimeoutSeconds 300
        if($r.ExitCode -ne 0){throw '无法生成退役节点删除候选，已停止远端退役。'}
        $clashCandidate=Join-Path $out 'Clash_General.candidate.yaml';$testData=Join-Path $out 'mihomo-test-data';[IO.Directory]::CreateDirectory($testData)|Out-Null
        foreach($core in @(Get-VpsMihomoCorePaths -ProjectRoot $Context.ProjectRoot)){if(Test-Path $core){$test=Invoke-VpsProcess $core @('-t','-d',$testData,'-f',$clashCandidate) -TimeoutSeconds 180;if($test.ExitCode -ne 0){throw '退役删除候选未通过 Mihomo 双核心语法测试。'}}}
        $singCandidate=Join-Path $out 'sing-box-general.candidate.json';Get-Content -Raw $singCandidate|ConvertFrom-Json|Out-Null
        if((Get-Item $singCandidate).Length-ge 4MB){throw '退役 sing-box 候选超过 4 MiB 桌面端安全上限。'}
        Protect-VpsPrivateFile $clashCandidate;Protect-VpsPrivateFile (Join-Path $out 'sing-box-general.candidate.json')
        Write-VpsUi "已先生成客户端节点删除候选：$out" Success
    }
    $components=@('Protocols','Network','Firewall','KomariAgent')
    if($removeController){$components+=@('KomariController','Cloudflared')}
    $transaction=Start-MxhMaintenanceTransaction $Context 'DecommissionFinal' -Components $components -QuiesceKomariController:$removeController
    $agentWasInstalled=$Context.State.Contains('KomariInstalled') -and [bool]$Context.State.KomariInstalled
    $decommissionCommitted=$false
    try{
        $backupDir=Join-Path $Context.ArchivePath 'decommission-backup';[IO.Directory]::CreateDirectory($backupDir)|Out-Null
        Invoke-VpsScpDownload $Context ($transaction.RemoteBackup+'/protocol-files.tar.gz') (Join-Path $backupDir ((Get-Date -Format yyyyMMdd-HHmmss)+'-managed-files.tar.gz'))
        $r=Invoke-VpsRemoteScript $Context 'maintenance-decommission.sh' @{SCOPE=$scope;REMOVE_CONTROLLER=$removeController.ToString().ToLowerInvariant()} -TimeoutSeconds 300
        if($r.StdOut -notmatch 'VPSDEPLOY_DECOMMISSION_OK'){throw '退役动作未确认。'}
        foreach($role in Get-MxhManagedProtocolRoles){$Context.Plan.ProtocolInventory[$role].Enabled=$false;$Context.Plan.ProtocolInventory[$role].Active=$false;if($scope -eq 'RemoveManaged'){$Context.Plan.ProtocolInventory[$role].Installed=$false}}
        $Context.Plan.Role=Get-MxhInventoryPrimaryRole $Context.Plan.ProtocolInventory
        $Context.State.ProtocolInventory=Copy-MxhHashtable $Context.Plan.ProtocolInventory
        $Context.Plan.Komari.Enabled=$false;$Context.State.KomariInstalled=if($scope -eq 'RemoveManaged'){$false}else{$agentWasInstalled}
        if([string]$Context.Plan.Firewall.Mode -ne 'PreserveExisting'){Invoke-MxhProtocolFirewall $Context (Get-MxhProtocolInventory -Plan $Context.Plan -State $Context.State) 'DecommissionFinalFirewall'}
        foreach($port in @([int]$Context.Plan.Ports.SshPrimary,[int]$Context.Plan.Ports.SshRescue)|Sort-Object -Unique){if(-not(Test-VpsSshConnection $Context root $port)){throw '退役后 SSH 复验失败。'}}
        Complete-MxhMaintenanceTransaction $Context
        $decommissionCommitted=$true
        if($wipeBackups){$final=Invoke-VpsRemoteScript $Context 'maintenance-decommission-finalize.sh' @{CONFIRM='WIPE-REMOTE-BACKUPS'} -TimeoutSeconds 180;if($final.StdOut -notmatch 'VPSDEPLOY_DECOMMISSION_FINALIZED'){throw '远端恢复点清理未确认。'}}
        $Context.State.Decommission=[ordered]@{Scope=$scope;ControllerRemoved=$removeController;RemoteBackupsWiped=$wipeBackups;At=(Get-Date).ToString('o');FinalBackup=$backupDir}
        Save-MxhMaintenanceContext $Context;Write-VpsUi '退役完成；SSH 与系统保留，最终受管文件备份已下载。' Success
    }catch{if(-not $decommissionCommitted){Undo-MxhMaintenanceTransaction $Context $_.Exception.Message};throw}
    return
    } catch { if (Test-VpsWizardBackError $_) { continue }; throw }
    }
}

function Invoke-MxhMaintenanceCenter {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectRoot,[string]$PlanPath,[switch]$DryRun)
    $candidate=$PlanPath
    while($true){
        $source=Read-MxhProtocolMigrationSource -ProjectRoot $ProjectRoot -PlanPath $candidate -DryRun:$DryRun
        $context=Get-MxhMaintenanceContext $ProjectRoot $source -DryRun:$DryRun
        $reselectInstance=$false
        while(-not $reselectInstance){
            try{
                $choice=Read-VpsMenu 'VPS 运维中心' @(
                    '从备份恢复',
                    '检查服务和配置（不改服务器）',
                    '更换代理密钥／密码',
                    'SSH 登录设置（密钥、端口）',
                    '管理防火墙规则',
                    '更新服务版本',
                    '客户端配置（Clash / sing-box）',
                    'Komari 监控管理',
                    '停用或卸载服务',
                    '更换 VPS',
                    '处理未完成的维护操作'
                ) 2 -AllowBack -HelpText @'
1 从备份恢复：选择恢复点和范围，不是恢复整个操作系统。
2 检查服务和配置：检查 SSH、服务、端口及配置是否与记录一致；不改服务器，报告保存在本机。
3 更换代理密钥／密码：替换客户端连接所需的认证信息，原客户端配置需要更新；不更换 SSH 登录密钥。
4、5 管理 SSH 登录和服务器防火墙；不代替服务商控制台的安全组设置。
6 更新服务版本：选择组件和支持的版本来源，并在更新后验证。
7 客户端配置：打开本地方案工作台；生成候选与发布分开确认。
8 Komari 监控管理：管理 Agent、监控面板和 Cloudflare Tunnel 连接器。
9 停用或卸载服务：可选择仅停用、卸载或删除备份，始终保留 SSH 和系统。
10 更换 VPS：重新选择部署计划文件。
11 处理未完成操作：检查中断的维护，核实已完成结果或恢复操作前状态；不会强行清除正在运行的保护。
'@
            }catch{
                if(Test-VpsWizardBackError $_){throw}
                throw
            }
            try{
                switch($choice){
                    1{Invoke-MxhManualRestoreCenter $context}
                    2{Invoke-MxhHealthAuditInteractive $context}
                    3{Invoke-MxhCredentialRotation $context}
                    4{Invoke-MxhSshMaintenance $context}
                    5{Invoke-MxhFirewallMaintenance $context}
                    6{Invoke-MxhControlledUpgrade $context}
                    7{Invoke-MxhClientCandidateMerge $context}
                    8{Invoke-MxhKomariLifecycle $context}
                    9{Invoke-MxhDecommission $context}
                    10{$reselectInstance=$true}
                    11{Invoke-MxhTransactionRecovery $context}
                }
                if($reselectInstance){break}
                if(Read-VpsYesNo '继续维护当前实例？' $true){continue}
                return
            }catch{
                if(Test-VpsWizardBackError $_){
                    Write-VpsUi '已返回 VPS 运维中心。' Info
                    continue
                }
                throw
            }
        }
        if($reselectInstance){$candidate=$null;continue}
    }
}
