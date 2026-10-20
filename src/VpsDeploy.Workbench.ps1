function Get-MxhFileFingerprint {
    param([string]$Path)
    if (-not [IO.File]::Exists($Path)) { return 'Missing' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function New-MxhClientScheme {
    param([string]$ProjectRoot)
    $sources=Get-MxhClientTemplatePaths $ProjectRoot
    return @{
        SchemaVersion=1; Id=[Guid]::NewGuid().ToString('N'); Name='新方案'; Entries=@()
        Layout=Copy-MxhHashtable (Get-MxhClientLayoutTemplate $ProjectRoot).Value
        Clash=$sources.Clash; SingBox=$sources.SingBox; SourceMode='GenericTemplate'
        Sources=@{}; Candidate=$null; Dirty=$true; Targets=@{Clash='';SingBox=''}
    }
}

function Get-MxhSchemeSpec {
    param($Scheme)
    $layout=$Scheme.Layout
    $nodes=@($Scheme.Entries | ForEach-Object { $_.Node })
    if(-not $nodes.Count){throw '请先添加至少一个入口节点。'}
    if(@($nodes | Group-Object name | Where-Object Count -gt 1).Count){throw '节点名称重复，请先重命名或删除重复项。'}
    $groups=[Collections.Generic.List[object]]::new()
    $active=@($layout.region_groups | Where-Object { $region=$_; @($nodes | Where-Object { $_.kind -eq 'entry' -and $_.region_group -eq $region }).Count })
    if(-not $active.Count){throw '至少需要一个入口节点及有效的地区组。'}
    foreach($node in $nodes){
        if($node.kind -eq 'landing' -and $node.transit_group -notin $active){throw "落地节点 $($node.name) 的入口组没有可用节点，请修改连接关系。"}
    }
    foreach($region in $active){$groups.Add(@{name=$region;members=@($nodes | Where-Object {$_.kind -eq 'entry' -and $_.region_group -eq $region} | ForEach-Object {$_.name})})}
    $exit=[string]$layout.default_exit_group;$direct=[string]$layout.direct_group
    $allowed=@($active)+@($nodes | Where-Object kind -eq landing | ForEach-Object name)+@('DIRECT')
    $members=@($layout.default_exit_members | Where-Object {$_ -in $allowed})+@($allowed | Where-Object {$_ -notin $layout.default_exit_members})
    $groups.Add(@{name=$exit;members=$members});$groups.Add(@{name=$direct;members=@('DIRECT',$exit)})
    $businessAllowed=@($exit,$direct)+@($active)+@($nodes | Where-Object kind -eq landing | ForEach-Object name)
    foreach($definition in $layout.business_groups){
        $first=if($definition.default -in $businessAllowed){$definition.default}else{$exit}
        $order=@($first)+@($definition.order | Where-Object {$_ -in $businessAllowed -and $_ -ne $first})+@($businessAllowed | Where-Object {$_ -ne $first -and $_ -notin $definition.order})
        if($definition.Contains('include_block') -and $definition.include_block){$order+=@('BLOCK')}
        $groups.Add(@{name=$definition.name;members=@($order | Select-Object -Unique)})
    }
    foreach($guard in $layout.guard_groups){$groups.Add(@{name=$guard.name;members=@($guard.members)})}
    return @{schema_version=1;source_mode=$Scheme.SourceMode;output_mode='CandidateOnly';manual_nodes=$nodes;fragment_sources=@();existing_node_refs=@();groups=@($groups);group_order=@($groups | ForEach-Object name);remove_groups=@($layout.region_groups | Where-Object {$_ -notin $active})}
}

function Save-MxhClientScheme {
    param($Scheme,[string]$ProjectRoot)
    if($Scheme.Id -notmatch '^[a-f0-9]{32}$'){throw '方案标识无效。'}
    $path=Join-Path $ProjectRoot ('private/client-schemes/'+$Scheme.Id+'.private.json')
    # Preserve the project's inherited-ACL policy; encrypt drafts for the current Windows user.
    $copy=Copy-MxhHashtable $Scheme;$copy.Dirty=$false;$copy.Candidate=$null
    if(-not $IsWindows){throw '方案草稿加密仅支持当前 Windows 用户。'}
    $secure=ConvertTo-SecureString ($copy | ConvertTo-Json -Depth 60 -Compress) -AsPlainText -Force
    try{$payload=ConvertFrom-SecureString $secure}finally{$secure.Dispose()}
    Save-VpsJson @{SchemaVersion=1;Protection='WindowsCurrentUser';Name=$Scheme.Name;Id=$Scheme.Id;Payload=$payload} $path -Private
    $Scheme.Dirty=$false
    Write-VpsUi '方案草稿已按当前 Windows 用户加密保存；跨账号不可直接打开，重新打开后必须重新校验。' Success
}

function Read-MxhSchemeSources {
    param([string]$ProjectRoot,[string]$Clash,[string]$SingBox)
    $python=Test-MxhClientBuilderRuntime $ProjectRoot
    $result=Invoke-VpsProcess $python @((Join-Path $ProjectRoot 'scripts/inspect_client_sources.py'),'--clash',$Clash,'--sing-box',$SingBox) -TimeoutSeconds 60
    if($result.ExitCode -ne 0){throw '无法读取成对客户端节点，请检查两份来源文件。'}
    return @($result.StdOut | ConvertFrom-Json -AsHashtable)
}

function Open-MxhClientScheme {
    param([string]$ProjectRoot)
    $root=Join-Path $ProjectRoot 'private/client-schemes'
    $files=@(Get-ChildItem -LiteralPath $root -Filter '*.private.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if(-not $files.Count){throw '尚未保存草稿，请先快速创建方案。'}
    $labels=@($files | ForEach-Object {
        try{$item=Read-VpsJsonHashtable $_.FullName;$label=if($item.Contains('Name')){[string]$item.Name}else{$_.BaseName}}catch{$label=$_.BaseName}
        $label+' / '+$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
    })
    $index=(Read-VpsMenu '选择私有草稿' $labels 1 -AllowBack)-1
    $envelope=Read-VpsJsonHashtable $files[$index].FullName
    if(-not $envelope.Contains('Protection') -or $envelope.Protection -ne 'WindowsCurrentUser'){throw '不支持的草稿保护格式，原文件未修改。'}
    try{$secure=ConvertTo-SecureString $envelope.Payload;try{$scheme=(ConvertFrom-VpsSecureString $secure)|ConvertFrom-Json -AsHashtable}finally{$secure.Dispose()}}catch{throw '草稿无法解密，请使用创建草稿的 Windows 账号和设备。'}
    if(-not $scheme.Contains('SchemaVersion') -or $scheme.SchemaVersion -ne 1){throw '不支持的方案格式，原文件未修改。'}
    foreach($key in @('Id','Name','Entries','Layout','Clash','SingBox','SourceMode','Sources','Targets')){if(-not $scheme.Contains($key)){throw "草稿缺少字段：$key"}}
    $scheme.Candidate=$null;$scheme.Dirty=$false
    foreach($path in $scheme.Sources.Keys){if((Get-MxhFileFingerprint $path) -ne $scheme.Sources[$path]){Write-VpsUi '草稿来源已变化或缺失；请先刷新来源。' Warning;break}}
    return $scheme
}

function Add-MxhSchemeSourceNodes {
    param($Scheme,[string]$ProjectRoot,[string]$InstanceRoot)
    $original=$Scheme;$Scheme=Copy-MxhHashtable $Scheme
    while($true){
    $mode=Read-VpsMenu '添加节点' @('从已纳管实例选择','手动添加','从方案的现有配置来源选择') 1 -AllowBack
    try{
    if($mode -eq 2){
        $node=New-MxhManualClientNode -RegionGroups @($Scheme.Layout.region_groups) -LandingTransitDefaults $Scheme.Layout.landing_transit_defaults
        $Scheme.Entries+=@(@{Id=[Guid]::NewGuid().ToString('N');Node=$node;Source=@{Kind='Manual'}})
    }else{
        $plans=if($mode -eq 1){@(Get-MxhManagedClientPlans $InstanceRoot)}else{@()}
        if($mode -eq 1 -and -not $plans.Count){Write-VpsUi '没有受管实例，可选择手动添加。' Info;continue}
        $pairs=@{RealityEntry=@('mihomo-test-primary.yaml','sing-box-outbounds.private.json');AnyTlsEntry=@('mihomo-anytls-test.yaml','sing-box-anytls-outbounds.private.json');ShadowsocksLanding=@('mihomo-shadowsocks-test.yaml','sing-box-shadowsocks-outbounds.private.json')}
        $values=Read-VpsForm -Values @{clash=$Scheme.Clash;sing=$Scheme.SingBox;catalog=@();roles=@()} -Steps @(
            @{Key='plan';When={param($v)$mode -eq 1};Read={param($v)
                $plan=$plans[(Read-VpsMenu '选择实例' @($plans | ForEach-Object {$_.Plan.NodeName}) 1 -AllowBack)-1].Plan
                $directory=Join-Path $plan.Paths.Archive 'client-exports'
                $v.roles=@(@('RealityEntry','AnyTlsEntry','ShadowsocksLanding') | Where-Object {(Test-Path -LiteralPath (Join-Path $directory $pairs[$_][0]) -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $directory $pairs[$_][1]) -PathType Leaf)})
                if(-not $v.roles.Count){throw '该实例尚无成对客户端片段，请先生成导出或选择其他实例。'}
                $v.role=$null;return $plan
            }}
            @{Key='role';When={param($v)$mode -eq 1 -and $v.roles.Count -gt 1};Read={param($v)
                $v.roles[(Read-VpsMenu '选择协议片段' @($v.roles | ForEach-Object {Get-MxhProtocolRoleLabel $_}) 1 -AllowBack)-1]
            }}
            @{Key='selected';Read={param($v)
                if($mode -eq 1){
                    $role=if($v.roles.Count -eq 1){$v.roles[0]}else{$v.role};$pair=$pairs[$role]
                    $directory=Join-Path $v.plan.Paths.Archive 'client-exports';$v.clash=Join-Path $directory $pair[0];$v.sing=Join-Path $directory $pair[1]
                }
                foreach($path in @($v.clash,$v.sing)){if($Scheme.Sources.Contains($path) -and $Scheme.Sources[$path] -ne (Get-MxhFileFingerprint $path)){throw '已有来源已变化，请先刷新来源，再添加节点。'}}
                $v.catalog=@(Read-MxhSchemeSources $ProjectRoot $v.clash $v.sing)
                if(-not $v.catalog.Count){throw '来源中没有可管理的成对节点。'}
                for($i=0;$i -lt $v.catalog.Count;$i++){Write-Host ("  {0}. {1}" -f ($i+1),$v.catalog[$i].name)}
                @(Read-MxhIndexSelection '选择节点编号（逗号分隔）' $v.catalog.Count -Options @($v.catalog|ForEach-Object name) -GuiPrompt '选择要加入方案的节点')
            }}
            @{Key='group';Read={param($v)
                if($Scheme.Layout.region_groups.Count -eq 1){return $Scheme.Layout.region_groups[0]}
                $Scheme.Layout.region_groups[(Read-VpsMenu '所选节点使用哪个地区入口组？之后可逐个修改。' @($Scheme.Layout.region_groups) 1 -AllowBack)-1]
            }}
        )
        $clash=$values.clash;$sing=$values.sing
        foreach($index in @($values.selected)){
            $node=$values.catalog[$index]
            $group=$values.group
            if($node.kind -eq 'entry'){$node.region_group=$group}else{$node.transit_group=$group}
            $Scheme.Entries+=@(@{Id=[Guid]::NewGuid().ToString('N');Node=$node;Source=@{Kind='Pair';Clash=$clash;SingBox=$sing;Name=$node.name}})
        }
        $Scheme.Sources[$clash]=Get-MxhFileFingerprint $clash;$Scheme.Sources[$sing]=Get-MxhFileFingerprint $sing
    }
    $Scheme.Dirty=$true;$Scheme.Candidate=$null
    $original.Entries=$Scheme.Entries;$original.Sources=$Scheme.Sources;$original.Dirty=$true;$original.Candidate=$null
    return
    }catch{if(Test-VpsWizardBackError $_){continue};throw}
    }
}

function Update-MxhSchemeSources {
    param($Scheme,[string]$ProjectRoot)
    $updated=Copy-MxhHashtable $Scheme
    foreach($entry in $updated.Entries){
        if($entry.Source.Kind -ne 'Pair'){continue}
        $nodes=@(Read-MxhSchemeSources $ProjectRoot $entry.Source.Clash $entry.Source.SingBox | Where-Object name -eq $entry.Source.Name)
        if($nodes.Count -ne 1){throw '来源节点已删除或重名，请先移除该引用，再重新选择来源。'}
        $node=$nodes[0];$node.name=$entry.Node.name;$node.clash.name=$node.name;$node.sing_box.tag=$node.name
        $node.region_group=$entry.Node.region_group;$node.transit_group=$entry.Node.transit_group;$entry.Node=$node
    }
    foreach($path in @($updated.Sources.Keys)){$updated.Sources[$path]=Get-MxhFileFingerprint $path}
    $Scheme.Entries=$updated.Entries;$Scheme.Sources=$updated.Sources;$Scheme.Candidate=$null;$Scheme.Dirty=$true
}

function Invoke-MxhSchemeBuild {
    param($Scheme,[string]$ProjectRoot,[switch]$DryRun,[string]$OutputRoot)
    $spec=Get-MxhSchemeSpec $Scheme
    foreach($path in $Scheme.Sources.Keys){if((Get-MxhFileFingerprint $path) -ne $Scheme.Sources[$path]){throw '节点来源已变化，请先选择“刷新来源”，核对后重新生成。'}}
    if($DryRun){Write-VpsUi "DryRun：方案包含 $($Scheme.Entries.Count) 个节点，未写文件或校验核心。" Success;return}
    $Scheme.Candidate=$null
    if(-not $OutputRoot){$OutputRoot=Join-Path $ProjectRoot 'private/client-candidates'}
    $output=Join-Path $OutputRoot ([Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($output)|Out-Null;Protect-VpsPrivateFile $output
    $specPath=Join-Path $output 'client-layout-spec.private.json';Save-VpsJson $spec $specPath -Private
    $fingerprints=@{};foreach($path in @($Scheme.Clash,$Scheme.SingBox)+@($Scheme.Sources.Keys)){$fingerprints[$path]=Get-MxhFileFingerprint $path}
    $python=Test-MxhClientBuilderRuntime $ProjectRoot
    $result=Invoke-VpsProcess $python @((Join-Path $ProjectRoot 'scripts/build_client_authority.py'),'--clash',$Scheme.Clash,'--sing-box',$Scheme.SingBox,'--spec',$specPath,'--output',$output) -TimeoutSeconds 300
    if($result.ExitCode -ne 0){throw '候选生成失败：请检查节点名称、引用关系和来源结构。私有候选目录已保留。'}
    $clash=Join-Path $output 'Clash_General.candidate.yaml';$sing=Join-Path $output 'sing-box-general.candidate.json'
    if((Get-Item -LiteralPath $sing).Length -ge 4MB){throw 'sing-box 候选超过 4 MiB，请减少规则或节点。'}
    $states=Test-MxhClientAuthorityPair $ProjectRoot $clash $sing
    foreach($path in $fingerprints.Keys){if((Get-MxhFileFingerprint $path) -ne $fingerprints[$path]){throw '生成期间来源发生变化，候选失效。'}}
    $Scheme.Candidate=@{Clash=$clash;SingBox=$sing;Sources=$fingerprints;ClashHash=Get-MxhFileFingerprint $clash;SingHash=Get-MxhFileFingerprint $sing;States=$states;SpecHash=Get-MxhSchemeHash $Scheme}
    Write-VpsUi "候选已生成。Mihomo=$($states.mihomo.Status)，sing-box=$($states['sing-box'].Status)。尚未发布。" Success
}

function Get-MxhSchemeHash {
    param($Scheme)
    function Canonical($value){
        if($value -is [Collections.IDictionary]){$sorted=[ordered]@{};foreach($key in @($value.Keys | Sort-Object)){$sorted[$key]=Canonical $value[$key]};return $sorted}
        if($value -is [array]){return ,@($value | ForEach-Object {Canonical $_})}
        return $value
    }
    $json=(Canonical (Get-MxhSchemeSpec $Scheme))|ConvertTo-Json -Depth 60 -Compress
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($json)))
}

function Invoke-MxhSchemePublish {
    param($Scheme,[string]$ProjectRoot,[switch]$DryRun)
    if(-not $Scheme.Candidate){throw '请先生成并校验候选。'}
    $candidate=$Scheme.Candidate
    if($candidate.SpecHash -ne (Get-MxhSchemeHash $Scheme)){throw '方案已修改，请重新生成。'}
    foreach($path in $candidate.Sources.Keys){if((Get-MxhFileFingerprint $path) -ne $candidate.Sources[$path]){throw '来源文件已变化，请重新生成。'}}
    if((Get-MxhFileFingerprint $candidate.Clash) -ne $candidate.ClashHash -or (Get-MxhFileFingerprint $candidate.SingBox) -ne $candidate.SingHash){throw '候选文件发生变化，请重新生成。'}
    if($candidate.States.mihomo.Status -ne 'Ready' -or $candidate.States['sing-box'].Status -ne 'Ready'){throw '存在跳过的核心校验，仅保留候选，不允许发布。'}
    $paths=Read-VpsForm -Values @{clash=$Scheme.Targets.Clash;sing=$Scheme.Targets.SingBox} -Steps @(
        @{Key='clash';Read={param($v) Read-VpsText 'Clash 发布目标完整路径' -Default $v.clash -AllowBack}}
        @{Key='sing';Read={param($v) Read-VpsText 'sing-box 发布目标完整路径' -Default $v.sing -AllowBack}}
    )
    $targetClash=ConvertTo-VpsInputPath $paths.clash;$targetSing=ConvertTo-VpsInputPath $paths.sing
    $expected=@{Clash=Get-MxhFileFingerprint $targetClash;SingBox=Get-MxhFileFingerprint $targetSing}
    Write-Host "Clash：$targetClash（$(if($expected.Clash -eq 'Missing'){'新建'}else{'替换并备份'})）"
    Write-Host "sing-box：$targetSing（$(if($expected.SingBox -eq 'Missing'){'新建'}else{'替换并备份'})）"
    Write-Host "方案节点：$(@($Scheme.Entries | ForEach-Object {$_.Node.name}) -join ', ')；凭据内容不展示。"
    $python=Test-MxhClientBuilderRuntime $ProjectRoot
    $diff=Invoke-VpsProcess $python @((Join-Path $ProjectRoot 'scripts/summarize_client_change.py'),'--old-clash',$targetClash,'--old-sing',$targetSing,'--new-clash',$candidate.Clash,'--new-sing',$candidate.SingBox) -TimeoutSeconds 30
    if($diff.ExitCode -ne 0){throw '无法生成脱敏差异摘要，未发布。'}
    $summary=$diff.StdOut | ConvertFrom-Json -AsHashtable
    foreach($name in @('Clash','SingBox')){
        $item=$summary[$name]
        Write-Host "$name：原文件=$($item.PreviousState)；新增 $($item.Added.Count)，移除 $($item.Removed.Count)，修改 $($item.Changed.Count) 个节点/出站。"
        if($item.Changed.Count){Write-Host ('  修改项：'+($item.Changed -join ', '))}
        if($item.Removed.Count){Write-Host ('  移除项：'+($item.Removed -join ', '))}
        if($item.OtherSections.Count){Write-Host ('  其他变化区块：'+($item.OtherSections -join ', '))}
    }
    if(-not(Read-VpsYesNo '确认发布这两份已校验候选？' $false -AllowBack)){return}
    if($DryRun){Write-VpsUi 'DryRun：未发布。' Info;return}
    foreach($path in $candidate.Sources.Keys){if((Get-MxhFileFingerprint $path) -ne $candidate.Sources[$path]){throw '确认期间来源发生变化，请重新生成。'}}
    $backup=Join-Path $ProjectRoot ('private/client-publish/'+[Guid]::NewGuid().ToString('N'))
    Publish-MxhCheckedAuthorityPair $candidate.Clash $candidate.SingBox $targetClash $targetSing $backup -States $candidate.States -Sources $candidate.Sources -Expected $expected -ExpectedCandidates @{Clash=$candidate.ClashHash;SingBox=$candidate.SingHash} | Out-Null
    $Scheme.Targets=@{Clash=$targetClash;SingBox=$targetSing};$Scheme.Dirty=$true
    Write-VpsUi "发布完成；备份与事务记录：$backup" Success
}

function Invoke-MxhClientWorkbench {
    param([string]$ProjectRoot,[string]$InstanceRoot,$Scheme,[switch]$DryRun)
    try {
    while($true){
        Write-Host "`n方案：$($Scheme.Name) | 节点：$($Scheme.Entries.Count) | 未保存：$($Scheme.Dirty) | 候选：$([bool]$Scheme.Candidate)"
        foreach($entry in $Scheme.Entries){Write-Host "  $($entry.Node.name) [$($entry.Node.kind)] → $($entry.Node.region_group)$($entry.Node.transit_group)"}
        try{$choice=Read-VpsMenu '方案工作台' @('添加节点','修改或删除节点／连接关系','分组与业务默认项','刷新来源节点','生成并校验候选','查看发布摘要并发布','保存草稿','修改方案名称') $(if($Scheme.Entries.Count){5}else{1}) -AllowBack}
        catch{
            if(-not(Test-VpsWizardBackError $_)){throw}
            if($Scheme.Dirty -and -not $DryRun){
                try{$leave=Read-VpsMenu '离开前处理草稿' @('保存并返回','放弃本次未保存修改并返回','继续编辑') 3 -AllowBack}catch{if(Test-VpsWizardBackError $_){continue};throw}
                if($leave -eq 3){continue};if($leave -eq 1){Save-MxhClientScheme $Scheme $ProjectRoot}
            }
            return
        }
        try{
            switch($choice){
                1 { Add-MxhSchemeSourceNodes $Scheme $ProjectRoot $InstanceRoot }
                2 { Edit-MxhSchemeEntry $Scheme }
                3 { Edit-MxhSchemeGroups $Scheme }
                4 { Update-MxhSchemeSources $Scheme $ProjectRoot }
                5 { Invoke-MxhSchemeBuild $Scheme $ProjectRoot -DryRun:$DryRun }
                6 { Invoke-MxhSchemePublish $Scheme $ProjectRoot -DryRun:$DryRun }
                7 { if($DryRun){Write-VpsUi 'DryRun：未保存草稿。' Info}else{Save-MxhClientScheme $Scheme $ProjectRoot} }
                8 { $Scheme.Name=Read-VpsText '方案名称' -Default $Scheme.Name -AllowBack;$Scheme.Dirty=$true }
            }
        }catch{
            if(Test-VpsWizardBackError $_){continue}
            if(Test-VpsNavigationError $_){throw}
            Write-VpsUi $_.Exception.Message Warning
        }
    }
    } finally {
        if($null -ne $script:VpsInteractionSession -and $script:VpsInteractionSession.CancelRequested -and $Scheme.Dirty -and -not $DryRun){
            Save-MxhClientScheme $Scheme $ProjectRoot
            Write-VpsUi '当前配置方案已保存为私人草稿，可从客户端页面重新打开。' Info
        }
    }
}

function Restore-MxhPendingPublication {
    param([string]$JournalPath)
    $journal=Read-VpsJsonHashtable $JournalPath
    if($journal.Phase -in @('Committed','RolledBack')){return}
    $locks=[Collections.Generic.List[object]]::new()
    try{
        foreach($target in @($journal.Clash,$journal.SingBox) | Sort-Object){$locks.Add([IO.File]::Open($target+'.may-publish.lock','OpenOrCreate','ReadWrite','None'))}
        foreach($key in @('Clash','SingBox')){
            $current=Get-MxhFileFingerprint $journal[$key]
            $candidate=if($journal.Contains('Candidates')){[string]$journal.Candidates[$key]}else{''}
            if($current -ne $journal.Before[$key] -and $current -ne $candidate){throw '目标包含事务记录之外的外部修改，拒绝自动恢复。'}
            $backup=if($key -eq 'Clash'){$journal.ClashBackup}else{$journal.SingBackup}
            if($journal.Before[$key] -ne 'Missing' -and (Get-MxhFileFingerprint $backup) -ne $journal.Before[$key]){throw '原文件备份缺失或校验不匹配，拒绝恢复。'}
        }
        $journal.Phase='Recovering';Save-VpsJson $journal $JournalPath -Private
        foreach($key in @('Clash','SingBox')){
            $target=[string]$journal[$key]
            if($journal.Before[$key] -eq 'Missing'){if([IO.File]::Exists($target)){[IO.File]::Delete($target)}}
            else{
                $backup=if($key -eq 'Clash'){$journal.ClashBackup}else{$journal.SingBackup}
                $temporary=$target+'.restore-'+[Guid]::NewGuid().ToString('N')
                try{Copy-Item -LiteralPath $backup -Destination $temporary;[IO.File]::Move($temporary,$target,$true)}finally{if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
            }
        }
        $journal.Phase='RolledBack';Save-VpsJson $journal $JournalPath -Private
    }finally{foreach($lock in $locks){$lock.Dispose()}}
}

function Invoke-MxhPublicationRecovery {
    param([string]$ProjectRoot,[switch]$DryRun)
    $root=Join-Path $ProjectRoot 'private/client-publish'
    $pending=@(Get-ChildItem -LiteralPath $root -Filter publish.private.json -Recurse -File -ErrorAction SilentlyContinue | Where-Object {(Read-VpsJsonHashtable $_.FullName).Phase -notin @('Committed','RolledBack')})
    if(-not $pending.Count){Write-VpsUi '没有未完成的配置发布记录。' Info;return}
    $file=$pending[(Read-VpsMenu '选择未完成发布' @($pending | ForEach-Object {$_.Directory.Name}) 1 -AllowBack)-1]
    $journal=Read-VpsJsonHashtable $file.FullName
    Write-VpsUi "状态：$($journal.Phase)；Clash：$($journal.Clash)；sing-box：$($journal.SingBox)" Warning
    if(-not(Read-VpsYesNo '恢复该次发布前的两份文件？外部修改或备份损坏时会拒绝。' $false -AllowBack)){return}
    if($DryRun){Write-VpsUi 'DryRun：未恢复文件。' Info;return}
    Restore-MxhPendingPublication $file.FullName
    Write-VpsUi '发布前文件已恢复，事务备份保留。' Success
}

function Edit-MxhSchemeEntry {
    param($Scheme)
    if(-not $Scheme.Entries.Count){return}
    while($true){
        $index=(Read-VpsMenu '选择节点' @($Scheme.Entries | ForEach-Object {$_.Node.name}) 1 -AllowBack)-1
        $entry=$Scheme.Entries[$index];$node=$entry.Node
        try{
            while($true){
            $action=Read-VpsMenu '节点编辑' @('名称','入口组／落地经由的入口组','服务器地址','端口','删除节点','修改敏感凭据') 2 -AllowBack
            try{
            switch($action){
                1 {
                    if($Scheme.SourceMode -eq 'ExistingAuthority'){throw '导入模式先保留原节点名称，避免破坏来源中的自定义引用。可修改分组关系。'}
                    $name=Read-VpsText '新节点名' -Default $node.name -AllowBack -Validate ${function:Test-VpsNodeName}
                    if(@($Scheme.Entries | Where-Object {$_.Id -ne $entry.Id -and $_.Node.name -eq $name}).Count){throw '节点名称重复。'}
                    $old=$node.name;$node.name=$name;$node.clash.name=$name;$node.sing_box.tag=$name
                    $Scheme.Layout.default_exit_members=@($Scheme.Layout.default_exit_members | ForEach-Object {if($_ -eq $old){$name}else{$_}})
                    foreach($definition in $Scheme.Layout.business_groups){
                        if($definition.default -eq $old){$definition.default=$name}
                        if($definition.Contains('order')){$definition.order=@($definition.order | ForEach-Object {if($_ -eq $old){$name}else{$_}})}
                    }
                }
                2 {$group=$Scheme.Layout.region_groups[(Read-VpsMenu '选择地区入口组' @($Scheme.Layout.region_groups) 1 -AllowBack)-1];if($node.kind -eq 'entry'){$node.region_group=$group}else{$node.transit_group=$group}}
                3 {if($entry.Source.Kind -ne 'Manual'){throw '来源引用节点请先修改源配置，再刷新来源。'};$server=Read-VpsText '服务器地址' -Default $node.sing_box.server -AllowBack -Validate {param($v)$ip=$null;[Net.IPAddress]::TryParse($v,[ref]$ip) -or (Test-VpsHostName $v)};$node.clash.server=$server;$node.sing_box.server=$server}
                4 {if($entry.Source.Kind -ne 'Manual'){throw '来源引用节点请先修改源配置，再刷新来源。'};$port=[int](Read-VpsText '服务端口' -Default ([string]$node.sing_box.server_port) -AllowBack -Validate {param($v)$n=0;[int]::TryParse($v,[ref]$n)-and$n -ge 1-and$n -le 65535});$node.clash.port=$port;$node.sing_box.server_port=$port}
                5 {
                    if($Scheme.SourceMode -eq 'ExistingAuthority'){Write-VpsUi '导入基础中已有的节点仍会保留；本操作只移除方案对它的管理，不从来源中删除。' Warning}
                    if(Read-VpsYesNo '从方案删除该节点？不会修改来源或服务器。' $false -AllowBack){$Scheme.Entries=@($Scheme.Entries | Where-Object Id -ne $entry.Id)}else{continue}
                }
                6 {
                    if($entry.Source.Kind -ne 'Manual'){throw '来源引用节点请修改原配置并刷新，避免下次刷新覆盖手动凭据。'}
                    $fields=if($node.sing_box.type -eq 'vless'){@('UUID','Reality PublicKey','Reality short-id')}elseif($node.sing_box.type -eq 'anytls'){@('密码','ECH client config Base64')}else{@('密码')}
                    $value=Read-VpsForm -Steps @(
                        @{Key='field';Read={param($v)(Read-VpsMenu '选择凭据字段' $fields 1 -AllowBack)-1}}
                        @{Key='secret';Read={param($v)Read-MxhSecretText $fields[$v.field] -AllowBack}}
                    )
                    if($node.sing_box.type -eq 'vless'){
                        switch($value.field){
                            0 {$node.clash.uuid=$value.secret;$node.sing_box.uuid=$value.secret}
                            1 {$node.clash['reality-opts']['public-key']=$value.secret;$node.sing_box.tls.reality.public_key=$value.secret}
                            2 {$node.clash['reality-opts']['short-id']=$value.secret;$node.sing_box.tls.reality.short_id=$value.secret}
                        }
                    }elseif($node.sing_box.type -eq 'anytls' -and $value.field -eq 1){
                        try{[Convert]::FromBase64String($value.secret)|Out-Null}catch{throw 'ECH 输入不是有效 Base64，原凭据未改变。'}
                        $node.clash['ech-opts'].config=$value.secret;$node.sing_box.tls.ech.config=@('-----BEGIN ECH CONFIGS-----',$value.secret,'-----END ECH CONFIGS-----')
                    }else{$node.clash.password=$value.secret;$node.sing_box.password=$value.secret}
                }
            }
            $Scheme.Dirty=$true;$Scheme.Candidate=$null;return
            }catch{if(Test-VpsWizardBackError $_){continue};throw}
            }
        }catch{if(Test-VpsWizardBackError $_){continue};throw}
    }
}

function Edit-MxhSchemeGroups {
    param($Scheme)
    while($true){
    $choice=Read-VpsMenu '分组设置' @('编辑地区组列表','调整节点显示／优先顺序','业务组默认出口') 1 -AllowBack
    try{
    if($choice -eq 1){
        $regions=@(Read-MxhRegionGroups -Defaults @($Scheme.Layout.region_groups))
        $used=@($Scheme.Entries | ForEach-Object {if($_.Node.kind -eq 'entry'){$_.Node.region_group}else{$_.Node.transit_group}})
        if(@($used | Where-Object {$_ -notin $regions}).Count){throw '不能删除仍被节点使用的地区组。请先修改节点连接关系。'}
        $Scheme.Layout.region_groups=$regions
    }elseif($choice -eq 2){
        $names=@($Scheme.Entries | ForEach-Object {$_.Node.name});if(-not $names.Count){return}
        $ordered=@(Read-MxhOrderedNames '节点顺序' -Allowed $names -Default $names)
        $Scheme.Entries=@($ordered | ForEach-Object {$name=$_;$Scheme.Entries | Where-Object {$_.Node.name -eq $name}})
    }else{
        $definitions=@($Scheme.Layout.business_groups)
        $values=Read-VpsForm -Steps @(
            @{Key='index';Read={param($v)(Read-VpsMenu '选择业务组' @($definitions | ForEach-Object name) 1 -AllowBack)-1}}
            @{Key='value';Read={param($v)$allowed=@($Scheme.Layout.default_exit_group,$Scheme.Layout.direct_group)+@($Scheme.Layout.region_groups);$allowed[(Read-VpsMenu '默认出口' $allowed 1 -AllowBack)-1]}}
        )
        $definitions[$values.index].default=$values.value
    }
    $Scheme.Dirty=$true;$Scheme.Candidate=$null
    return
    }catch{if(Test-VpsWizardBackError $_){continue};throw}
    }
}
