function Get-MxhClientLayoutTemplate {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $genericPath = Join-Path $ProjectRoot 'config\client-layout.default.json'
    $local = Join-Path $ProjectRoot 'config\client-layout.local.json'
    $generic = Read-VpsJsonHashtable -Path $genericPath
    $value = if (Test-Path -LiteralPath $local -PathType Leaf) {
        Merge-VpsHashtable -Base $generic -Overlay (Read-VpsJsonHashtable -Path $local)
    } else { $generic }
    return [pscustomobject]@{ Path = $(if (Test-Path -LiteralPath $local -PathType Leaf) { $local } else { $genericPath }); GenericPath=$genericPath; LocalPath=$local; Value=$value }
}

function Get-MxhClientTemplatePaths {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $clash = Join-Path $ProjectRoot 'templates\client\clash-general.template.yaml'
    $sing = Join-Path $ProjectRoot 'templates\client\sing-box-general.template.json'
    if (-not (Test-Path -LiteralPath $clash -PathType Leaf) -or -not (Test-Path -LiteralPath $sing -PathType Leaf)) {
        throw '项目通用客户端模板缺失，请先运行项目离线自检。'
    }
    return [pscustomobject]@{ Clash=$clash; SingBox=$sing }
}

function Get-MxhClientDefaultPath {
    param([Parameter(Mandatory)][string]$ProjectRoot,[AllowEmptyString()][string]$CommandLine,[AllowEmptyString()][string]$Environment,[AllowEmptyString()][string]$LocalOrGeneric)
    $value = if (-not [string]::IsNullOrWhiteSpace($CommandLine)) { $CommandLine } elseif (-not [string]::IsNullOrWhiteSpace($Environment)) { $Environment } else { $LocalOrGeneric }
    return Resolve-VpsPortablePath -ProjectRoot $ProjectRoot -Path $value
}

function Show-MxhClientLayoutDefaults {
    param([Parameter(Mandatory)][hashtable]$Layout,[Parameter(Mandatory)][string]$SourcePath)
    Write-Host ''
    Write-Host '当前客户端布局默认值' -ForegroundColor Cyan
    Write-Host "  来源：$SourcePath"
    Write-Host "  地区入口组：$(@($Layout.region_groups) -join ' -> ')"
    Write-Host "  默认出口组：$($Layout.default_exit_group)"
    Write-Host "  直连组：$($Layout.direct_group)"
    Write-Host "  默认出口优先：$(@($Layout.default_exit_members) -join ' -> ')"
    Write-Host "  业务组：$(@($Layout.business_groups.name) -join ' -> ')"
    Write-Host "  基础来源：$($Layout.authority_defaults.source_mode)"
    Write-Host "  默认输出：$($Layout.authority_defaults.output_root)"
}

function ConvertTo-MxhPreferenceMap {
    param([AllowEmptyString()][string]$Text,[Parameter(Mandatory)][string[]]$AllowedValues)
    $map = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return $map }
    foreach ($pair in $Text -split '[;；]+') {
        $parts = @($pair -split '=',2)
        if ($parts.Count -ne 2) { throw "映射格式无效：$pair" }
        $name=$parts[0].Trim();$value=$parts[1].Trim()
        if (-not $name -or $value -notin $AllowedValues) { throw "映射值无效：$pair" }
        $map[$name]=$value
    }
    return $map
}

function Invoke-MxhEditClientLayoutDefaults {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    while ($true) {
        $template = Get-MxhClientLayoutTemplate -ProjectRoot $ProjectRoot
        $layout = $template.Value
        $choice = $null
        try {
            $choice = Read-VpsMenu '客户端布局默认值' @(
                '查看当前默认值',
                '修改地区入口组及显示顺序',
                '修改地区组内节点优先顺序',
                '修改落地节点默认入口映射',
                '修改默认出口与直连组',
                '修改业务组名称、顺序和默认项',
                '修改基础来源与输出默认值',
                '恢复项目通用默认值'
            ) 1 -AllowBack -HelpText @'
这里修改的是以后运行设计器时采用的本机默认值，不会立刻生成配置或连接 VPS。
个人默认写入 config/client-layout.local.json，该文件被 Git 忽略；恢复通用默认值时会先保留时间戳备份。
'@
            if ($choice -eq 1) { Show-MxhClientLayoutDefaults -Layout $layout -SourcePath $template.Path; continue }
            if ($choice -eq 2) {
                $layout.region_groups = @(Read-MxhRegionGroups -Defaults @($layout.region_groups))
            }
            elseif ($choice -eq 3) {
                $map=[ordered]@{}
                foreach($region in @($layout.region_groups)){
                    $existing=if($layout.region_member_defaults.Contains($region)){@($layout.region_member_defaults[$region])}else{@()}
                    $raw=Read-VpsText "$region 默认节点顺序（节点名逗号分隔；可留空）" -Default ($existing -join ', ') -AllowEmpty -AllowBack
                    $map[$region]=@($raw -split '[,;，]+'|ForEach-Object{$_.Trim()}|Where-Object{$_}|Select-Object -Unique)
                }
                $layout.region_member_defaults=$map
            }
            elseif ($choice -eq 4) {
                $current=@($layout.landing_transit_defaults.Keys|ForEach-Object{"$_=$($layout.landing_transit_defaults[$_])"}) -join '; '
                while($true){try{$raw=Read-VpsText '落地节点=地区入口组（多项用分号；可留空）' -Default $current -AllowEmpty -AllowBack;$layout.landing_transit_defaults=ConvertTo-MxhPreferenceMap -Text $raw -AllowedValues @($layout.region_groups);break}catch{if(Test-VpsWizardBackError $_){throw};Write-VpsUi $_.Exception.Message Warning}}
            }
            elseif ($choice -eq 5) {
                $oldExit=[string]$layout.default_exit_group;$oldDirect=[string]$layout.direct_group
                $layout.default_exit_group=Read-VpsText '默认出口组名称' -Default $oldExit -AllowBack -Validate ${function:Test-VpsNodeName}
                $layout.direct_group=Read-VpsText '直连策略组名称' -Default $oldDirect -AllowBack -Validate ${function:Test-VpsNodeName}
                foreach($definition in $layout.business_groups){if([string]$definition.default-eq$oldExit){$definition.default=[string]$layout.default_exit_group}elseif([string]$definition.default-eq$oldDirect){$definition.default=[string]$layout.direct_group};if($definition.Contains('order')){$definition.order=@($definition.order|ForEach-Object{if($_-eq$oldExit){[string]$layout.default_exit_group}elseif($_-eq$oldDirect){[string]$layout.direct_group}else{$_}}|Select-Object -Unique)}}
                foreach($guard in $layout.guard_groups){$guard.members=@($guard.members|ForEach-Object{if($_-eq$oldExit){[string]$layout.default_exit_group}elseif($_-eq$oldDirect){[string]$layout.direct_group}else{$_}}|Select-Object -Unique)}
                $allowed=@($layout.region_groups)+@('DIRECT')
                $layout.default_exit_members=@(Read-MxhOrderedNames '默认出口候选优先顺序' -Allowed $allowed -Default @($layout.default_exit_members|Where-Object{$_ -in $allowed}))
            }
            elseif ($choice -eq 6) {
                $names=@($layout.business_groups.name)
                $ordered=Read-MxhOrderedNames '业务组显示顺序' -Allowed $names -Default $names
                $byName=@{};foreach($item in $layout.business_groups){$byName[[string]$item.name]=$item}
                $new=[Collections.Generic.List[object]]::new()
                $allowed=@([string]$layout.default_exit_group,[string]$layout.direct_group)+@($layout.region_groups)
                foreach($name in $ordered){
                    $item=$byName[$name];$default=Read-VpsText "$name 默认出口" -Default ([string]$item.default) -AllowBack -Validate{param($v)$v -in $allowed} -ValidationMessage ('可选项：'+($allowed -join ', '))
                    $order=@($default)+@($allowed|Where-Object{$_ -ne $default});$item.default=$default;$item.order=$order;$new.Add($item)
                }
                $layout.business_groups=@($new)
            }
            elseif ($choice -eq 7) {
                $mode=Read-VpsMenu '默认基础来源' @('项目通用模板','导入现有 Clash/sing-box 配置') $(if([string]$layout.authority_defaults.source_mode -eq 'ExistingAuthority'){2}else{1}) -AllowBack
                $layout.authority_defaults.source_mode=if($mode -eq 2){'ExistingAuthority'}else{'GenericTemplate'}
                if($mode -eq 2){
                    $value=Read-VpsText '默认 Clash 配置路径（可留空，运行时再填）' -Default ([string]$layout.authority_defaults.clash) -AllowEmpty -AllowBack -Validate{param($v)Test-VpsPathSeparatorStyle -Value $v -AllowEmpty} -ValidationMessage '路径可全用 / 或全用 \，但不能混用。'
                    $layout.authority_defaults.clash=ConvertTo-VpsInputPath -Value $value -AllowEmpty
                    $value=Read-VpsText '默认 sing-box 配置路径（可留空，运行时再填）' -Default ([string]$layout.authority_defaults.sing_box) -AllowEmpty -AllowBack -Validate{param($v)Test-VpsPathSeparatorStyle -Value $v -AllowEmpty} -ValidationMessage '路径可全用 / 或全用 \，但不能混用。'
                    $layout.authority_defaults.sing_box=ConvertTo-VpsInputPath -Value $value -AllowEmpty
                }
                $value=Read-VpsText '默认输出目录（可用相对项目路径）' -Default ([string]$layout.authority_defaults.output_root) -AllowBack -Validate ${function:Test-VpsPathSeparatorStyle} -ValidationMessage '路径可全用 / 或全用 \，但不能混用。'
                $layout.authority_defaults.output_root=ConvertTo-VpsInputPath -Value $value
            }
            else {
                if(-not(Read-VpsYesNo '恢复项目通用默认值？当前个人默认会改名保留。' $false -AllowBack)){continue}
                if(Test-Path -LiteralPath $template.LocalPath){Move-Item -LiteralPath $template.LocalPath -Destination ($template.LocalPath+'.backup.'+(Get-Date -Format yyyyMMdd-HHmmss))}
                Write-VpsUi '已恢复项目通用默认值。' Success
                continue
            }
            Save-VpsJson -Value $layout -Path $template.LocalPath -Private
            Write-VpsUi '本机客户端布局默认值已保存。' Success
        }
        catch {
            if (Test-VpsWizardBackError $_) {
                if ($null -eq $choice) { return }
                continue
            }
            throw
        }
    }
}

function Read-MxhOrderedNames {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Allowed,
        [string[]]$Default = @(),
        [switch]$AllowEmpty
    )
    $defaultText = @($Default | Where-Object { $_ -in $Allowed }) -join ', '
    while ($true) {
        $text = Read-VpsText $Prompt -Default $defaultText -AllowEmpty:$AllowEmpty -AllowBack
        $items = @($text -split '[,;，]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $duplicates = @($items | Group-Object | Where-Object Count -gt 1)
        $unknown = @($items | Where-Object { $_ -notin $Allowed })
        if ($duplicates) { Write-VpsUi '列表中不能出现重复项。' Warning; continue }
        if ($unknown) { Write-VpsUi "列表包含未知项：$($unknown -join ', ')" Warning; continue }
        if (-not $items.Count -and -not $AllowEmpty) { Write-VpsUi '至少选择一项。' Warning; continue }
        return $items
    }
}

function Read-MxhRegionGroups {
    param([Parameter(Mandatory)][string[]]$Defaults)
    if (-not (Read-VpsYesNo '是否新增、重命名或彻底重排地区入口组？' $false -AllowBack)) {
        return Read-MxhOrderedNames '本次启用哪些默认地区入口组（逗号分隔并按显示顺序排列）' -Allowed $Defaults -Default $Defaults
    }
    while ($true) {
        $raw = Read-VpsText '地区入口组名称（逗号分隔，例如 US-West-LA Entry, Hong Kong Entry）' -Default ($Defaults -join ', ') -AllowBack
        $items = @($raw -split '[,;，]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($items.Count -lt 1 -or $items.Count -gt 12) { Write-VpsUi '地区入口组数量必须在 1–12 之间。' Warning; continue }
        if (@($items | Group-Object | Where-Object Count -gt 1)) { Write-VpsUi '地区入口组不能重名。' Warning; continue }
        if (@($items | Where-Object { $_.Length -gt 80 -or $_ -match '[\r\n]' -or $_ -in @('DIRECT','REJECT','BLOCK') })) {
            Write-VpsUi '地区入口组名称无效或与保留 tag 冲突。' Warning; continue
        }
        return $items
    }
}

function Read-MxhSecretText {
    param([Parameter(Mandatory)][string]$Prompt,[switch]$AllowBack)
    while ($true) {
        $hint = if($AllowBack){'（隐藏输入；输入 0 返回上一级）'}else{'（隐藏输入）'}
        $secure = if ($null -ne $script:VpsInteractionSession) {
            $script:VpsInteractionSession.ReadSecret($Prompt, [bool]$AllowBack)
        } else { Read-Host ($Prompt+$hint) -AsSecureString }
        if ($null -eq $secure) { throw [OperationCanceledException]::new($script:VpsWizardCancelMarker) }
        try { $value = ConvertFrom-VpsSecureString $secure }
        finally { $secure.Dispose() }
        if(Test-VpsClearCommand $value){Clear-VpsScreen;continue}
        if(Test-VpsHelpCommand $value){Show-VpsHelp '敏感值不会显示；输入 0 返回上一级，输入 clear 清屏。';continue}
        if($AllowBack -and $value.Trim() -eq '0'){throw [InvalidOperationException]::new($script:VpsWizardBackMarker)}
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
        Write-VpsUi '该敏感项不能为空。' Warning
    }
}

function Read-MxhIndexSelection {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][int]$Count,
        [switch]$AllowEmpty,
        [string[]]$Options=@(),
        [string]$GuiPrompt='选择项目'
    )
    while ($true) {
        if($null -ne $script:VpsInteractionSession -and $Options.Count -eq $Count){
            $raw=$script:VpsInteractionSession.ReadMultiple($GuiPrompt,$Options,[bool]$AllowEmpty)
            if($null -eq $raw){throw [OperationCanceledException]::new($script:VpsWizardCancelMarker)}
            if($raw -eq '0'){throw [InvalidOperationException]::new($script:VpsWizardBackMarker)}
        }else{$raw = Read-VpsText $Prompt -AllowEmpty:$AllowEmpty -AllowBack}
        if (-not $raw -and $AllowEmpty) { return @() }
        try {
            return @($raw -split '[,;，\s]+' | Where-Object { $_ } | ForEach-Object {
                    $number = 0
                    if (-not [int]::TryParse($_, [ref]$number) -or $number -lt 1 -or $number -gt $Count) {
                        throw "编号不在 1–$Count 范围内：$_"
                    }
                    $number - 1
                } | Sort-Object -Unique)
        }
        catch { Write-VpsUi $_.Exception.Message Warning }
    }
}

function Get-MxhManagedClientPlans {
    param([Parameter(Mandatory)][string]$InstanceRoot)
    if (-not (Test-Path -LiteralPath $InstanceRoot -PathType Container)) { return @() }
    $result = [Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $InstanceRoot -Filter deployment-plan.json -File -Recurse -ErrorAction SilentlyContinue) {
        if ($file.FullName -match '[\\/](maintenance-backups|migration-backups|client-candidates|decommission-client-candidate)[\\/]') { continue }
        try {
            $plan = Read-VpsJsonHashtable -Path $file.FullName
            if (-not $plan.Contains('NodeName') -or -not $plan.Contains('Paths')) { continue }
            $result.Add([pscustomobject]@{ Path = $file.FullName; Plan = $plan })
        }
        catch { Write-VpsUi "跳过无法解析的计划：$($file.FullName)" Warning }
    }
    return @($result | Sort-Object { $_.Plan.Provider }, { $_.Plan.Instance })
}

function Read-MxhPlanSelection {
    param([object[]]$Plans)
    if (-not $Plans.Count) { Write-VpsUi '没有发现已纳管计划；仍可手动添加节点。' Info; return @() }
    Write-Host ''
    Write-Host '可提取的已纳管 VPS：' -ForegroundColor Cyan
    for ($i = 0; $i -lt $Plans.Count; $i++) {
        Write-Host ("  {0}. {1} / {2} / {3}" -f ($i + 1), $Plans[$i].Plan.Provider, $Plans[$i].Plan.Instance, $Plans[$i].Plan.NodeName)
    }
    $indexes = @(Read-MxhIndexSelection '输入要提取的编号（逗号分隔；留空跳过）' $Plans.Count -AllowEmpty -Options @($Plans|ForEach-Object{"$($_.Plan.Provider) · $($_.Plan.Instance) · $($_.Plan.NodeName)"}) -GuiPrompt '选择要提取节点的受管实例')
    return @($indexes | ForEach-Object { $Plans[$_] })
}

function Get-MxhFragmentNodeNames {
    param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$Role)
    $name = switch ($Role) {
        RealityEntry { 'sing-box-outbounds.private.json' }
        AnyTlsEntry { 'sing-box-anytls-outbounds.private.json' }
        ShadowsocksLanding { 'sing-box-shadowsocks-outbounds.private.json' }
    }
    $path = Join-Path $Directory $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    $json = Read-VpsJsonHashtable -Path $path
    return @($json.outbounds | ForEach-Object { [string]$_.tag } | Where-Object { $_ })
}

function New-MxhManualClientNode {
    param([Parameter(Mandatory)][string[]]$RegionGroups,[hashtable]$LandingTransitDefaults)
    $draft = Read-VpsForm -Steps @(
        @{Key='kind';Read={param($v)
            $selected=Read-VpsMenu '手动节点协议' @('VLESS + Reality + Vision 入口','AnyTLS + TLS/ECH 入口','Shadowsocks 2022 落地') $(if($v.kind){[int]$v.kind}else{1}) -AllowBack
            if($v.kind -and $v.kind -ne $selected){foreach($key in @('port','uuid','publicKey','shortId','password','serverName','echConfig','method')){$v[$key]=$null}}
            return $selected
        }}
        @{Key='name';Read={param($v) Read-VpsText '节点名称/tag' -Default $v.name -AllowBack -Validate ${function:Test-VpsNodeName}}}
        @{Key='server';Read={param($v) Read-VpsText '服务器地址（IPv4、IPv6 或域名）' -Default $v.server -AllowBack -Validate {
            param($value) $ip=$null; [Net.IPAddress]::TryParse($value,[ref]$ip) -or (Test-VpsHostName $value)
        } -ValidationMessage '请输入 IP 或域名，不要包含协议、端口或路径。'}}
        @{Key='port';Read={param($v) [int](Read-VpsText '服务端口' -Default $(if($v.port){[string]$v.port}elseif($v.kind -eq 3){'46936'}else{'443'}) -AllowBack -Validate {
            param($value) $n=0; [int]::TryParse($value,[ref]$n) -and $n -ge 1 -and $n -le 65535
        })}}
        @{Key='uuid';When={param($v)$v.kind -eq 1};Read={param($v) Read-MxhSecretText 'UUID' -AllowBack}}
        @{Key='publicKey';When={param($v)$v.kind -eq 1};Read={param($v) Read-MxhSecretText 'Reality PublicKey' -AllowBack}}
        @{Key='shortId';When={param($v)$v.kind -eq 1};Read={param($v) Read-MxhSecretText 'Reality short-id' -AllowBack}}
        @{Key='method';When={param($v)$v.kind -eq 3};Read={param($v) Read-VpsText 'Shadowsocks 方法' -Default $(if($v.method){$v.method}else{'2022-blake3-aes-128-gcm'}) -AllowBack}}
        @{Key='password';When={param($v)$v.kind -ne 1};Read={param($v) Read-MxhSecretText '协议密码（Shadowsocks 使用客户端组合密码）' -AllowBack}}
        @{Key='serverName';When={param($v)$v.kind -ne 3};Read={param($v) Read-VpsText '服务端 SNI / servername' -Default $v.serverName -AllowBack -Validate ${function:Test-VpsHostName}}}
        @{Key='echConfig';When={param($v)$v.kind -eq 2};Read={param($v)
            while($true){
                $value=Read-MxhSecretText 'ECH client config Base64' -AllowBack
                try { $decoded=[Convert]::FromBase64String($value); if($decoded.Length -gt 0){return $value} } catch [FormatException] {}
                Write-VpsUi 'ECH client config 不是有效 Base64，请重新输入。' Warning
            }
        }}
        @{Key='group';Read={param($v)
            $preferred=if($v.group){[string]$v.group}elseif($LandingTransitDefaults -and $LandingTransitDefaults.Contains($v.name)){[string]$LandingTransitDefaults[$v.name]}else{''}
            $defaultIndex=[Array]::IndexOf($RegionGroups,$preferred)+1;if($defaultIndex -lt 1){$defaultIndex=1}
            $title=if($v.kind -eq 3){'该落地节点经由哪个地区入口组连接'}else{'该入口属于哪个地区入口组'}
            $RegionGroups[(Read-VpsMenu $title $RegionGroups $defaultIndex -AllowBack)-1]
        }}
    )
    $kind=$draft.kind;$name=$draft.name;$server=$draft.server;$port=[int]$draft.port
    if ($kind -eq 1) {
        $uuid=$draft.uuid;$publicKey=$draft.publicKey;$shortId=$draft.shortId;$serverName=$draft.serverName
        $clash = [ordered]@{ name=$name;type='vless';server=$server;port=$port;uuid=$uuid;network='tcp';tls=$true;udp=$true;servername=$serverName;flow='xtls-rprx-vision';'client-fingerprint'='chrome';'reality-opts'=[ordered]@{'public-key'=$publicKey;'short-id'=$shortId} }
        $sing = [ordered]@{ type='vless';tag=$name;server=$server;server_port=$port;uuid=$uuid;flow='xtls-rprx-vision';packet_encoding='xudp';tls=[ordered]@{enabled=$true;server_name=$serverName;utls=[ordered]@{enabled=$true;fingerprint='chrome'};reality=[ordered]@{enabled=$true;public_key=$publicKey;short_id=$shortId}} }
        $region = $draft.group
        return [ordered]@{name=$name;kind='entry';region_group=$region;transit_group=$null;clash=$clash;sing_box=$sing}
    }
    if ($kind -eq 2) {
        $password=$draft.password;$serverName=$draft.serverName;$echConfig=$draft.echConfig
        if ($echConfig -notmatch '^[A-Za-z0-9+/=]+$') { throw 'ECH client config 不是规范 Base64。' }
        $pem = @('-----BEGIN ECH CONFIGS-----',$echConfig,'-----END ECH CONFIGS-----')
        $clash = [ordered]@{name=$name;type='anytls';server=$server;port=$port;password=$password;udp=$true;sni=$serverName;'skip-cert-verify'=$false;'ech-opts'=[ordered]@{enable=$true;config=$echConfig}}
        $sing = [ordered]@{type='anytls';tag=$name;server=$server;server_port=$port;password=$password;tls=[ordered]@{enabled=$true;server_name=$serverName;min_version='1.3';ech=[ordered]@{enabled=$true;config=$pem}}}
        $region = $draft.group
        return [ordered]@{name=$name;kind='entry';region_group=$region;transit_group=$null;clash=$clash;sing_box=$sing}
    }
    $method=$draft.method;$password=$draft.password;$transit=$draft.group
    $clash = [ordered]@{name=$name;type='ss';server=$server;port=$port;cipher=$method;password=$password;udp=$true;'dialer-proxy'=$transit}
    $sing = [ordered]@{type='shadowsocks';tag=$name;server=$server;server_port=$port;method=$method;password=$password;detour=$transit}
    return [ordered]@{name=$name;kind='landing';region_group=$null;transit_group=$transit;clash=$clash;sing_box=$sing}
}

function Test-MxhClientBuilderRuntime {
    param([Parameter(Mandatory)][string]$ProjectRoot)
    $python = Get-VpsCommandPath 'python.exe'
    $versionProbe = Invoke-VpsProcess $python @('-c','import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 9)') -TimeoutSeconds 30
    if ($versionProbe.ExitCode -ne 0) { throw '客户端权威配置设计器需要 Python 3.9 或更高版本。' }
    $probe = Invoke-VpsProcess $python @('-c','import ruamel.yaml') -TimeoutSeconds 30
    if ($probe.ExitCode -eq 0) { return $python }
    Write-VpsUi '客户端配置设计器缺少固定依赖 ruamel.yaml。部署/纳管功能不受影响。' Warning
    if (-not (Read-VpsYesNo '现在使用当前 Python 安装 requirements-client-merge.txt？' $true -AllowBack)) {
        throw '未安装客户端配置设计器依赖。'
    }
    $install = Invoke-VpsProcess $python @('-m','pip','install','--disable-pip-version-check','-r',(Join-Path $ProjectRoot 'requirements-client-merge.txt')) -TimeoutSeconds 600
    if ($install.ExitCode -ne 0) { throw 'Python 依赖安装失败，请检查网络或手动运行 requirements-client-merge.txt。' }
    return $python
}

function Get-MxhClientCoreFailureText {
    param([Parameter(Mandatory)]$Result)
    $parts = [Collections.Generic.List[string]]::new()
    foreach ($value in @([string]$Result.StdErr, [string]$Result.StdOut)) {
        $trimmed = $value.Trim()
        if (-not [string]::IsNullOrWhiteSpace($trimmed) -and $trimmed -notin $parts) {
            $parts.Add($trimmed)
        }
    }
    if (-not $parts.Count) { return "核心退出码 $($Result.ExitCode)，没有提供诊断输出。" }
    return ($parts -join "`n")
}

function Invoke-MxhMihomoCandidateCheck {
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$CorePath,
        [Parameter(Mandatory)][string]$DataDirectory,
        [Parameter(Mandatory)][string]$ConfigPath
    )
    Copy-VpsBundledMihomoGeodata -ProjectRoot $ProjectRoot -DestinationDirectory $DataDirectory | Out-Null
    $result = $null
    foreach ($attempt in 1..2) {
        $result = Invoke-VpsProcess $CorePath @('-t', '-d', $DataDirectory, '-f', $ConfigPath) -TimeoutSeconds 180
        if ($result.ExitCode -eq 0) { return $result }
        if ($attempt -eq 1) {
            Write-VpsUi 'Mihomo 首次校验失败；保留隔离数据目录并自动重试一次，以排除 GeoData/规则集首次获取的瞬时失败。' Warning
            Start-Sleep -Seconds 1
        }
    }
    return $result
}

function New-MxhSingBoxValidationConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$DataDirectory
    )
    # Never put vendor/cache absolute paths into the portable candidate itself.
    $config = Read-VpsJsonHashtable -Path $ConfigPath
    if ($config.Contains('route') -and $config.route.Contains('rule_set')) {
        $vendorRoot = [IO.Path]::GetFullPath((Join-Path $ProjectRoot 'vendor/test-cores/windows-amd64'))
        $manifest = Read-VpsJsonHashtable -Path (Join-Path $vendorRoot 'checksums.json')
        $entries = @($manifest.data_files | Where-Object { [string]$_.consumer -eq 'sing-box' })
        if ($entries.Count -ne 5) { throw 'MXH Route 离线公共规则清单必须包含五个规则集。' }
        foreach ($rule in @($config.route.rule_set)) {
            if ([string]$rule.type -ne 'remote') { continue }
            $matched = @($entries | Where-Object {
                [string]$_.tag -eq [string]$rule.tag -and [string]$_.source -eq [string]$rule.url -and [string]$rule.format -eq 'binary'
            })
            if (-not $matched.Count) { continue } # Custom rule sources keep their original semantics.
            if ($matched.Count -ne 1) { throw '离线公共规则标签重复。' }
            $entry = $matched[0]
            $relative = [string]$entry.file
            if ($relative -ne "mxh-route-public-rules/$([string]$entry.tag).srs") { throw '离线公共规则路径不在白名单。' }
            $source = [IO.Path]::GetFullPath((Join-Path $vendorRoot $relative))
            if (-not $source.StartsWith($vendorRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-Path -LiteralPath $source -PathType Leaf) -or [string]$entry.sha256 -notmatch '^[0-9a-f]{64}$' -or
                (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$entry.sha256) {
                throw '离线公共规则文件缺失、越界或 SHA-256 不匹配。'
            }
            # Official 1.14.2 check reads the same SRS bytes that MXH Route seeds offline.
            $rule.type = 'local'
            $rule.path = $source
            foreach ($key in @('url', 'download_detour', 'update_interval', 'initial_path')) { $null = $rule.Remove($key) }
        }
    }
    [IO.Directory]::CreateDirectory($DataDirectory) | Out-Null
    $path = Join-Path $DataDirectory 'validation.private.json'
    Save-VpsJson -Value $config -Path $path -Private
    return $path
}

function Invoke-MxhSingBoxCandidateCheck {
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$CorePath,
        [Parameter(Mandatory)][string]$ConfigPath
    )
    $data = Join-Path ([IO.Path]::GetTempPath()) ('mxh-sing-box-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($data) | Out-Null
    try {
        $validationPath = New-MxhSingBoxValidationConfig -ProjectRoot $ProjectRoot -ConfigPath $ConfigPath -DataDirectory $data
        return Invoke-VpsProcess $CorePath @('check', '-D', $data, '-c', $validationPath) -TimeoutSeconds 180
    }
    finally { Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue }
}

function Test-MxhClientAuthorityPair {
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$ClashPath,
        [Parameter(Mandatory)][string]$SingBoxPath
    )
    $context = [pscustomobject]@{ ProjectRoot = $ProjectRoot; NonInteractive = $false }
    $states = [ordered]@{}
    $mihomo = Resolve-VpsClientValidationCore -Context $context -Core mihomo
    $states.mihomo = $mihomo
    if ($mihomo.Status -eq 'Ready') {
        $data = Join-Path ([IO.Path]::GetTempPath()) ('mxh-mihomo-' + [guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($data) | Out-Null
        try {
            $test = Invoke-MxhMihomoCandidateCheck -ProjectRoot $ProjectRoot -CorePath $mihomo.Path -DataDirectory $data -ConfigPath $ClashPath
            if ($test.ExitCode -ne 0) { throw "Clash 候选未通过内置稳定 Mihomo：$(Get-MxhClientCoreFailureText $test)" }
        }
        finally { Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $singBox = Resolve-VpsClientValidationCore -Context $context -Core 'sing-box'
    $states['sing-box'] = $singBox
    if ($singBox.Status -eq 'Ready') {
        $test = Invoke-MxhSingBoxCandidateCheck -ProjectRoot $ProjectRoot -CorePath $singBox.Path -ConfigPath $SingBoxPath
        if ($test.ExitCode -ne 0) { throw "sing-box 候选未通过内置稳定核心：$(Get-MxhClientCoreFailureText $test)" }
    }
    foreach ($alpha in @(Get-VpsMihomoCorePaths -ProjectRoot $ProjectRoot | Where-Object { $_ -ne $mihomo.Path })) {
        $data = Join-Path ([IO.Path]::GetTempPath()) ('mxh-mihomo-alpha-' + [guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($data) | Out-Null
        try {
            $test = Invoke-MxhMihomoCandidateCheck -ProjectRoot $ProjectRoot -CorePath $alpha -DataDirectory $data -ConfigPath $ClashPath
            if ($test.ExitCode -ne 0) { throw "Clash 候选未通过可选 Mihomo alpha：$(Get-MxhClientCoreFailureText $test)" }
        }
        finally { Remove-Item -LiteralPath $data -Recurse -Force -ErrorAction SilentlyContinue }
    }
    return $states
}

function Test-MxhForbiddenAuthorityPath {
    param([Parameter(Mandatory)][string]$Path)
    $full=[IO.Path]::GetFullPath($Path)
    return $full -match '(?i)[\\/]AppData[\\/].*clash-verge|io\.github\.clash-verge'
}

function Get-MxhClientSourceFingerprints {
    param([string[]]$BasePaths,[object[]]$FragmentSources=@())
    $paths=@($BasePaths)
    foreach($fragment in $FragmentSources){
        if($fragment -isnot [Collections.IDictionary] -or -not $fragment.Contains('fragment_dir') -or [string]::IsNullOrWhiteSpace([string]$fragment.fragment_dir)){
            throw '受管片段缺少来源目录，请重新选择来源。'
        }
        $paths+=([string]$fragment.fragment_dir)
    }
    $fingerprints=@{}
    foreach($path in $paths | Sort-Object -Unique){
        if(Test-Path -LiteralPath $path -PathType Leaf){$fingerprints[$path]=Get-MxhFileFingerprint $path}
        elseif(Test-Path -LiteralPath $path -PathType Container){
            foreach($file in Get-ChildItem -LiteralPath $path -File -Recurse){$fingerprints[$file.FullName]=Get-MxhFileFingerprint $file.FullName}
        }else{throw '配置来源已经不存在，请重新读取来源后生成候选。'}
    }
    return $fingerprints
}

function Publish-MxhCheckedAuthorityPair {
    param([Parameter(Mandatory)][string]$CandidateClash,[Parameter(Mandatory)][string]$CandidateSingBox,
        [Parameter(Mandatory)][string]$TargetClash,[Parameter(Mandatory)][string]$TargetSingBox,
        [Parameter(Mandatory)][string]$BackupRoot,[Parameter(Mandatory)]$States,
        [Parameter(Mandatory)][hashtable]$Expected,[Parameter(Mandatory)][hashtable]$ExpectedCandidates,
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable]$Sources)
    if($States.mihomo.Status -ne 'Ready' -or $States['sing-box'].Status -ne 'Ready'){throw '存在跳过的核心校验，仅保留候选，不允许发布。'}
    foreach($source in $Sources.Keys){if((Get-MxhFileFingerprint $source) -ne $Sources[$source]){throw '来源文件已变化，未发布，请重新生成。'}}
    Publish-MxhAuthorityPair $CandidateClash $CandidateSingBox $TargetClash $TargetSingBox $BackupRoot -Expected $Expected -ExpectedCandidates $ExpectedCandidates
}

function Publish-MxhAuthorityPair {
    param(
        [Parameter(Mandatory)][string]$CandidateClash,
        [Parameter(Mandatory)][string]$CandidateSingBox,
        [Parameter(Mandatory)][string]$TargetClash,
        [Parameter(Mandatory)][string]$TargetSingBox,
        [Parameter(Mandatory)][string]$BackupRoot,
        [hashtable]$Expected,
        [hashtable]$ExpectedCandidates
    )
    if((Test-MxhForbiddenAuthorityPath $TargetClash) -or (Test-MxhForbiddenAuthorityPath $TargetSingBox)){throw '拒绝写入 Clash Verge AppData/profile 副本；请选择独立权威文件。'}
    $TargetClash=[IO.Path]::GetFullPath($TargetClash);$TargetSingBox=[IO.Path]::GetFullPath($TargetSingBox)
    if($TargetClash -eq $TargetSingBox){throw '两份配置不能指向同一个目标文件。'}
    if($TargetClash -in @([IO.Path]::GetFullPath($CandidateClash),[IO.Path]::GetFullPath($CandidateSingBox)) -or $TargetSingBox -in @([IO.Path]::GetFullPath($CandidateClash),[IO.Path]::GetFullPath($CandidateSingBox))){throw '发布目标不能覆盖候选文件本身。'}
    foreach($target in @($TargetClash,$TargetSingBox)){
        $parent=Split-Path -Parent $target
        if([string]::IsNullOrWhiteSpace($parent)){throw "目标必须是完整路径：$target"}
        [IO.Directory]::CreateDirectory($parent)|Out-Null
    }
    [IO.Directory]::CreateDirectory($BackupRoot)|Out-Null
    Protect-VpsPrivateFile $BackupRoot
    $stamp=[Guid]::NewGuid().ToString('N')
    $clashBackup=Join-Path $BackupRoot ('clash-'+$stamp+'.backup');$singBackup=Join-Path $BackupRoot ('sing-box-'+$stamp+'.backup')
    $clashTemp=$TargetClash+'.mxh-new-'+$stamp;$singTemp=$TargetSingBox+'.mxh-new-'+$stamp
    $locks=[Collections.Generic.List[object]]::new()
    $journalPath=Join-Path $BackupRoot 'publish.private.json'
    $singChanged=$false
    try{
        foreach($target in @($TargetClash,$TargetSingBox) | Sort-Object){
            $locks.Add([IO.File]::Open($target+'.mxh-publish.lock',[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None))
        }
        $before=@{Clash=Get-MxhFileFingerprint $TargetClash;SingBox=Get-MxhFileFingerprint $TargetSingBox}
        if($Expected -and ($Expected.Clash -ne $before.Clash -or $Expected.SingBox -ne $before.SingBox)){throw '确认后目标文件已经变化，未覆盖，请重新查看发布摘要。'}
        if($before.Clash -ne 'Missing'){Copy-Item -LiteralPath $TargetClash -Destination $clashBackup}
        if($before.SingBox -ne 'Missing'){Copy-Item -LiteralPath $TargetSingBox -Destination $singBackup}
        $journal=@{Phase='Prepared';Clash=$TargetClash;SingBox=$TargetSingBox;ClashBackup=$clashBackup;SingBackup=$singBackup;Before=$before}
        Save-VpsJson $journal $journalPath -Private
        [IO.File]::WriteAllText($clashTemp,'');Protect-VpsPrivateFile $clashTemp
        [IO.File]::WriteAllText($singTemp,'');Protect-VpsPrivateFile $singTemp
        Copy-Item -LiteralPath $CandidateClash -Destination $clashTemp -Force
        Copy-Item -LiteralPath $CandidateSingBox -Destination $singTemp -Force
        $candidateHashes=@{Clash=Get-MxhFileFingerprint $clashTemp;SingBox=Get-MxhFileFingerprint $singTemp}
        if($ExpectedCandidates -and ($candidateHashes.Clash -ne $ExpectedCandidates.Clash -or $candidateHashes.SingBox -ne $ExpectedCandidates.SingBox)){throw '候选文件与已校验版本不同，未发布。'}
        $journal.Candidates=$candidateHashes;Save-VpsJson $journal $journalPath -Private
        if((Get-MxhFileFingerprint $TargetClash) -ne $before.Clash -or (Get-MxhFileFingerprint $TargetSingBox) -ne $before.SingBox){throw '目标文件被外部程序修改，发布已停止。'}
        [IO.File]::Move($clashTemp,$TargetClash,$true)
        try{
            $journal.Phase='ClashApplied';Save-VpsJson $journal $journalPath -Private
            if((Get-MxhFileFingerprint $TargetSingBox) -ne $before.SingBox){throw 'sing-box 目标被外部修改，停止第二份替换。'}
            [IO.File]::Move($singTemp,$TargetSingBox,$true)
            $singChanged=$true
            $journal.Phase='Committed';Save-VpsJson $journal $journalPath -Private
        }catch{
            if((Get-MxhFileFingerprint $TargetClash) -ne $candidateHashes.Clash){throw '发布期间 Clash 目标被外部修改，拒绝覆盖外部变更；请从发布记录人工恢复。'}
            if(Test-Path -LiteralPath $clashBackup){Copy-Item -LiteralPath $clashBackup -Destination $TargetClash -Force}else{Remove-Item -LiteralPath $TargetClash -ErrorAction SilentlyContinue}
            if($singChanged){
                if((Get-MxhFileFingerprint $TargetSingBox) -ne $candidateHashes.SingBox){throw '发布期间 sing-box 目标被外部修改，保留备份供人工恢复。'}
                if(Test-Path -LiteralPath $singBackup){Copy-Item -LiteralPath $singBackup -Destination $TargetSingBox -Force}elseif($before.SingBox -eq 'Missing' -and [IO.File]::Exists($TargetSingBox)){[IO.File]::Delete($TargetSingBox)}
            }
            $journal.Phase='RolledBack';Save-VpsJson $journal $journalPath -Private
            throw
        }
    }
    finally{
        foreach($lock in $locks){$lock.Dispose()}
        Remove-Item -LiteralPath $clashTemp,$singTemp -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{Clash=$TargetClash;SingBox=$TargetSingBox;BackupRoot=$BackupRoot}
}

function Invoke-MxhBuildClientAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$InstanceRoot,
        [string]$ClashAuthorityPath,
        [string]$SingBoxAuthorityPath,
        [string]$ClientOutputRoot,
        [switch]$DryRun
    )
    $templateResult = Get-MxhClientLayoutTemplate -ProjectRoot $ProjectRoot
    $layout = $templateResult.Value
    Write-VpsUi "布局默认值：$($templateResult.Path)" Info
    $originalRegions = @($layout.region_groups)
    $regions = @(Read-MxhRegionGroups -Defaults $originalRegions)
    $customRegions = (($regions -join "`n") -ne ($originalRegions -join "`n"))
    $defaultSource = if ([string]$layout.authority_defaults.source_mode -eq 'ExistingAuthority') { 2 } else { 1 }
    $sourceChoice = Read-VpsMenu '选择基础配置来源' @(
        '项目通用模板（推荐；不依赖任何个人配置）',
        '导入一对现有 Clash/sing-box 配置作为基础（只读）'
    ) $defaultSource -AllowBack -HelpText @'
通用模板适合新人或全新环境；它提供最小可用的 DNS、mixed 入站、规则和业务组骨架，不含任何节点或个人路径。
导入现有配置会保留其高级 DNS/TUN/规则，并允许复用已有节点；源文件始终只读。
'@
    if ($sourceChoice -eq 1) {
        $sources = Get-MxhClientTemplatePaths -ProjectRoot $ProjectRoot
        $clash = $sources.Clash
        $sing = $sources.SingBox
        $sourceMode = 'GenericTemplate'
    }
    else {
        $clashDefault = Get-MxhClientDefaultPath -ProjectRoot $ProjectRoot -CommandLine $ClashAuthorityPath -Environment $env:MXH_VPS_CLASH_AUTHORITY -LocalOrGeneric ([string]$layout.authority_defaults.clash)
        $singDefault = Get-MxhClientDefaultPath -ProjectRoot $ProjectRoot -CommandLine $SingBoxAuthorityPath -Environment $env:MXH_VPS_SINGBOX_AUTHORITY -LocalOrGeneric ([string]$layout.authority_defaults.sing_box)
        $clash = Read-VpsText '现有 Clash YAML（只读源）' -Default $clashDefault -AllowBack -Validate { param($v) Test-VpsExistingInputPath -Value $v -PathType Leaf } -ValidationMessage '找不到文件，或路径混用了 / 与 \。'
        $sing = Read-VpsText '现有 sing-box JSON（只读源）' -Default $singDefault -AllowBack -Validate { param($v) Test-VpsExistingInputPath -Value $v -PathType Leaf } -ValidationMessage '找不到文件，或路径混用了 / 与 \。'
        $clash = ConvertTo-VpsInputPath -Value $clash
        $sing = ConvertTo-VpsInputPath -Value $sing
        $sourceMode = 'ExistingAuthority'
    }
    $authoritySing = Get-Content -Raw -LiteralPath $sing.Trim('"') | ConvertFrom-Json -AsHashtable
    $fragmentSources = [Collections.Generic.List[object]]::new()
    $manualNodes = [Collections.Generic.List[object]]::new()
    $existingNodeRefs = [Collections.Generic.List[object]]::new()
    $entryMembers = [ordered]@{}; foreach ($region in $regions) { $entryMembers[$region] = [Collections.Generic.List[string]]::new() }
    $landingNames = [Collections.Generic.List[string]]::new()

    $plans = @(Get-MxhManagedClientPlans -InstanceRoot $InstanceRoot)
    foreach ($selected in @(Read-MxhPlanSelection -Plans $plans)) {
        $inventory = Get-MxhProtocolInventory -Plan $selected.Plan
        $exports = Join-Path ([string]$selected.Plan.Paths.Archive) 'client-exports'
        foreach ($role in Get-MxhManagedProtocolRoles) {
            if (-not [bool]$inventory[$role].Installed) { continue }
            $names = @(Get-MxhFragmentNodeNames -Directory $exports -Role $role)
            if (-not $names.Count) { Write-VpsUi "$($selected.Plan.NodeName) 缺少 $role 客户端片段，已跳过。" Warning; continue }
            if (-not (Read-VpsYesNo "提取 $($selected.Plan.NodeName) 的 $(Get-MxhProtocolRoleLabel $role) 节点？" ([bool]$inventory[$role].Enabled) -AllowBack)) { continue }
            if ($role -eq 'ShadowsocksLanding') {
                $preferred=@($names|ForEach-Object{if($layout.landing_transit_defaults.Contains($_)){[string]$layout.landing_transit_defaults[$_]}}|Where-Object{$_ -in $regions}|Select-Object -First 1)
                $defaultIndex=if($preferred.Count){[Array]::IndexOf($regions,$preferred[0])+1}else{1}
                $transit = $regions[(Read-VpsMenu '该落地节点使用哪个地区入口组作为 transit/detour' $regions $defaultIndex -AllowBack)-1]
                $fragmentSources.Add([ordered]@{fragment_dir=$exports;role=$role;node_names=$names;region_group=$null;transit_group=$transit})
                foreach ($name in $names) { $landingNames.Add($name) }
            }
            else {
                $region = $regions[(Read-VpsMenu "$($selected.Plan.NodeName) 加入哪个地区入口组" $regions 1 -AllowBack)-1]
                $fragmentSources.Add([ordered]@{fragment_dir=$exports;role=$role;node_names=$names;region_group=$region;transit_group=$null})
                foreach ($name in $names) { $entryMembers[$region].Add($name) }
            }
        }
    }
    while (Read-VpsYesNo '是否手动添加一台未纳管 VPS 的节点？' $false -AllowBack) {
        $node = New-MxhManualClientNode -RegionGroups $regions -LandingTransitDefaults $layout.landing_transit_defaults
        $manualNodes.Add($node)
        if ($node.kind -eq 'entry') { $entryMembers[[string]$node.region_group].Add([string]$node.name) }
        else { $landingNames.Add([string]$node.name) }
    }
    $selectedNames = @($fragmentSources | ForEach-Object { @($_.node_names) }) + @($manualNodes | ForEach-Object { [string]$_.name })
    $existingCandidates = @($authoritySing.outbounds | Where-Object {
            [string]$_.type -in @('vless','anytls','shadowsocks') -and [string]$_.tag -notin $selectedNames
        })
    if ($existingCandidates.Count) {
        Write-Host ''
        Write-Host '权威文件中尚未由受管计划/手动输入选中的现有节点：' -ForegroundColor Cyan
        for ($i = 0; $i -lt $existingCandidates.Count; $i++) {
            Write-Host ("  {0}. {1} ({2})" -f ($i + 1), $existingCandidates[$i].tag, $existingCandidates[$i].type)
        }
        $indexes=@(Read-MxhIndexSelection '直接复用哪些现有节点（逗号分隔；留空跳过，无需重新输入凭据）' $existingCandidates.Count -AllowEmpty -Options @($existingCandidates|ForEach-Object{"$($_.tag) · $($_.type)"}) -GuiPrompt '选择要复用的现有节点')
        if($indexes.Count){
            $selectors = @($authoritySing.outbounds | Where-Object { [string]$_.type -eq 'selector' })
            foreach ($index in $indexes) {
                $outbound = $existingCandidates[$index]
                $name = [string]$outbound.tag
                if ([string]$outbound.type -eq 'shadowsocks') {
                    $suggested = [string]$outbound.detour
                    if($layout.landing_transit_defaults.Contains($name)){$suggested=[string]$layout.landing_transit_defaults[$name]}
                    $default = [Array]::IndexOf($regions,$suggested) + 1
                    if ($default -lt 1) { $default = 1 }
                    $transit = $regions[(Read-VpsMenu "$name 使用哪个地区入口组作为 transit/detour" $regions $default -AllowBack) - 1]
                    $existingNodeRefs.Add([ordered]@{name=$name;kind='landing';region_group=$null;transit_group=$transit})
                    $landingNames.Add($name)
                }
                else {
                    $matches = @($selectors | Where-Object { [string]$_.tag -in $regions -and $name -in @($_.outbounds) } | ForEach-Object { [string]$_.tag })
                    $default = if ($matches.Count) { [Array]::IndexOf($regions,$matches[0]) + 1 } else { 1 }
                    if ($default -lt 1) { $default = 1 }
                    $region = $regions[(Read-VpsMenu "$name 加入哪个地区入口组" $regions $default -AllowBack) - 1]
                    $existingNodeRefs.Add([ordered]@{name=$name;kind='entry';region_group=$region;transit_group=$null})
                    $entryMembers[$region].Add($name)
                }
            }
        }
    }
    $allNodeCount = @($fragmentSources | ForEach-Object { @($_.node_names) }).Count + $manualNodes.Count + $existingNodeRefs.Count
    if ($allNodeCount -eq 0) { throw '没有选择或手动添加任何节点。' }

    $groups = [Collections.Generic.List[object]]::new(); $activeRegions = [Collections.Generic.List[string]]::new()
    foreach ($region in $regions) {
        $allowed = @($entryMembers[$region] | Sort-Object -Unique)
        if (-not $allowed.Count) { Write-VpsUi "$region 没有节点，本次候选不创建该组。" Warning; continue }
        $preferred=if($layout.region_member_defaults.Contains($region)){@($layout.region_member_defaults[$region]|Where-Object{$_ -in $allowed})}else{@()}
        $defaultOrder=@($preferred)+@($allowed|Where-Object{$_ -notin $preferred})
        $ordered = @(Read-MxhOrderedNames "$region 内节点顺序（第一项是首次默认）" -Allowed $allowed -Default $defaultOrder)
        $groups.Add([ordered]@{name=$region;members=$ordered}); $activeRegions.Add($region)
    }
    if (-not $activeRegions.Count) { throw '至少需要一个包含入口节点的地区入口组。' }
    $defaultExitName = [string]$layout.default_exit_group
    $directName = [string]$layout.direct_group
    $exitAllowed = @($activeRegions) + @($landingNames | Sort-Object -Unique) + @('DIRECT')
    $preferredExit=@($layout.default_exit_members|Where-Object{$_ -in $exitAllowed})
    $exitDefault=@($preferredExit)+@($exitAllowed|Where-Object{$_ -notin $preferredExit})
    $exitMembers = @(Read-MxhOrderedNames "$defaultExitName 选项顺序（第一项是首次默认）" -Allowed $exitAllowed -Default $exitDefault)
    $groups.Add([ordered]@{name=$defaultExitName;members=$exitMembers})
    $groups.Add([ordered]@{name=$directName;members=@('DIRECT',$defaultExitName)})
    $businessAllowed = @($defaultExitName) + @($activeRegions) + @($landingNames | Sort-Object -Unique) + @($directName)
    $customBusiness = Read-VpsYesNo '是否逐个调整业务组的默认项和完整顺序？' $false -AllowBack
    foreach ($definition in $layout.business_groups) {
        $default = if ([string]$definition.default -in $businessAllowed) { [string]$definition.default } else { $businessAllowed[0] }
        $preferredOrder=if($definition.Contains('order')){@($definition.order|Where-Object{$_ -in $businessAllowed})}else{@()}
        $members = @($default) + @($preferredOrder|Where-Object{$_ -ne $default}) + @($businessAllowed | Where-Object { $_ -ne $default -and $_ -notin $preferredOrder })
        if ($definition.Contains('include_block') -and [bool]$definition.include_block) { $members += 'BLOCK' }
        if ($customBusiness) {
            $members = @(Read-MxhOrderedNames "$($definition.name) 选项顺序（第一项是首次默认）" -Allowed $members -Default $members)
            $definition.default = $members[0]
        }
        $groups.Add([ordered]@{name=[string]$definition.name;members=$members})
    }
    foreach ($guard in $layout.guard_groups) { $groups.Add([ordered]@{name=[string]$guard.name;members=@($guard.members)}) }
    $groupOrder = @($activeRegions) + @($defaultExitName,$directName) + @($layout.business_groups.name) + @($layout.guard_groups.name)

    $outputMode=Read-VpsMenu '配置保存方式' @(
        '覆盖指定的当前权威配置（验证、时间戳备份、原子替换）',
        '生成一对新配置文件（不覆盖现有文件）'
    ) 2 -AllowBack -HelpText @'
覆盖权威配置：先在暂存目录生成并完成 Mihomo/sing-box 校验，再备份原文件并原子替换；拒绝写入 Clash Verge AppData。
生成新配置：写入全新目录和文件名，任何目标文件已存在都会停止，不改当前权威配置。
'@
    $outputDefault=Get-MxhClientDefaultPath -ProjectRoot $ProjectRoot -CommandLine $ClientOutputRoot -Environment $env:MXH_VPS_CLIENT_OUTPUT_ROOT -LocalOrGeneric ([string]$layout.authority_defaults.output_root)
    $outputRoot = Read-VpsText '暂存与报告输出根目录' -Default $outputDefault -AllowBack -Validate ${function:Test-VpsArchiveRoot} -ValidationMessage '请输入完整绝对路径；可全用 / 或全用 \，但不能混用。'
    $outputRoot = ConvertTo-VpsInputPath -Value $outputRoot
    $stamp=Get-Date -Format yyyyMMdd-HHmmss
    $output = Join-Path $outputRoot ('staging-'+$stamp)
    $targetClash=$null;$targetSing=$null
    if($outputMode -eq 1){
        $targetClashDefault=Get-MxhClientDefaultPath -ProjectRoot $ProjectRoot -CommandLine $ClashAuthorityPath -Environment $env:MXH_VPS_CLASH_AUTHORITY -LocalOrGeneric ([string]$layout.authority_defaults.clash)
        $targetSingDefault=Get-MxhClientDefaultPath -ProjectRoot $ProjectRoot -CommandLine $SingBoxAuthorityPath -Environment $env:MXH_VPS_SINGBOX_AUTHORITY -LocalOrGeneric ([string]$layout.authority_defaults.sing_box)
        $targetClash=Read-VpsText '要覆盖的 Clash 权威 YAML 完整路径' -Default $targetClashDefault -AllowBack -Validate{param($v)(Test-VpsPathSeparatorStyle -Value $v) -and -not(Test-MxhForbiddenAuthorityPath (ConvertTo-VpsInputPath -Value $v))} -ValidationMessage '路径可全用 / 或全用 \，但不能混用；且不能指向 Clash Verge AppData。'
        $targetSing=Read-VpsText '要覆盖的 sing-box 权威 JSON 完整路径' -Default $targetSingDefault -AllowBack -Validate{param($v)(Test-VpsPathSeparatorStyle -Value $v) -and -not(Test-MxhForbiddenAuthorityPath (ConvertTo-VpsInputPath -Value $v))} -ValidationMessage '路径可全用 / 或全用 \，但不能混用；且不能指向 Clash Verge AppData。'
        $targetClash=ConvertTo-VpsInputPath -Value $targetClash;$targetSing=ConvertTo-VpsInputPath -Value $targetSing
    }else{
        $newDir=Read-VpsText '新配置保存目录' -Default (Join-Path $outputRoot ('generated-'+$stamp)) -AllowBack -Validate ${function:Test-VpsArchiveRoot} -ValidationMessage '请输入完整绝对路径；可全用 / 或全用 \，但不能混用。'
        $newDir=ConvertTo-VpsInputPath -Value $newDir
        $newClashName=Read-VpsText '新 Clash 文件名' -Default ([string]$layout.authority_defaults.new_clash_name) -AllowBack -Validate{param($v)$v -match '\.(yaml|yml)$' -and $v -notmatch '[\\/]'}
        $newSingName=Read-VpsText '新 sing-box 文件名' -Default ([string]$layout.authority_defaults.new_sing_box_name) -AllowBack -Validate{param($v)$v -match '\.json$' -and $v -notmatch '[\\/]'}
        $targetClash=Join-Path $newDir $newClashName;$targetSing=Join-Path $newDir $newSingName
        if((Test-Path -LiteralPath $targetClash) -or (Test-Path -LiteralPath $targetSing)){throw '生成新配置模式不会覆盖现有文件；请更换目录或文件名。'}
    }
    if ($DryRun) { Write-VpsUi "DryRun：将从 $($fragmentSources.Count) 个受管片段、$($manualNodes.Count) 个手动节点和 $($existingNodeRefs.Count) 个现有节点生成、验证并写入 $targetClash 与 $targetSing。" Success; return }
    $expectedTargets=@{Clash=Get-MxhFileFingerprint $targetClash;SingBox=Get-MxhFileFingerprint $targetSing}
    $expectedSources=Get-MxhClientSourceFingerprints -BasePaths @($clash,$sing) -FragmentSources @($fragmentSources)
    [IO.Directory]::CreateDirectory($output) | Out-Null
    $removeGroups = @($originalRegions | Where-Object { $_ -notin @($activeRegions) })
    $spec = [ordered]@{schema_version=1;source_mode=$sourceMode;output_mode=$(if($outputMode-eq 1){'OverwriteAuthority'}else{'GenerateNew'});fragment_sources=@($fragmentSources);manual_nodes=@($manualNodes);existing_node_refs=@($existingNodeRefs);groups=@($groups);remove_groups=$removeGroups;group_order=$groupOrder}
    $specPath = Join-Path $output 'client-layout-spec.private.json'; Save-VpsJson -Value $spec -Path $specPath -Private
    $python = Test-MxhClientBuilderRuntime -ProjectRoot $ProjectRoot
    $builder = Join-Path $ProjectRoot 'scripts\build_client_authority.py'
    $result = Invoke-VpsProcess $python @($builder,'--clash',$clash.Trim('"'),'--sing-box',$sing.Trim('"'),'--spec',$specPath,'--output',$output) -TimeoutSeconds 300
    if ($result.ExitCode -ne 0) { throw "客户端候选生成失败：$($result.StdErr.Trim())" }
    $candidate = Join-Path $output 'Clash_General.candidate.yaml'
    $singCandidate = Join-Path $output 'sing-box-general.candidate.json'
    Get-Content -Raw $singCandidate | ConvertFrom-Json | Out-Null
    $singBytes = (Get-Item -LiteralPath $singCandidate).Length
    if ($singBytes -ge 4MB) { throw "sing-box 候选为 $singBytes 字节，超过桌面端 4 MiB 安全上限；请减少内联规则或节点。" }
    $expectedCandidates=@{Clash=Get-MxhFileFingerprint $candidate;SingBox=Get-MxhFileFingerprint $singCandidate}
    $coreStates = Test-MxhClientAuthorityPair -ProjectRoot $ProjectRoot -ClashPath $candidate -SingBoxPath $singCandidate
    if($coreStates.mihomo.Status -ne 'Ready' -or $coreStates['sing-box'].Status -ne 'Ready'){throw '存在跳过的核心校验，仅保留候选，不允许发布。'}
    Write-VpsUi "Clash：$targetClash；sing-box：$targetSing。双核心已校验；指纹、备份和恢复与工作台一致。生成记录保留在：$output" Info
    if(-not(Read-VpsYesNo '确认发布这两份已完成双核心校验的配置？' $false -AllowBack)){return}
    $backupRoot=Join-Path $ProjectRoot ('private/client-publish/'+[Guid]::NewGuid().ToString('N'))
    $published=Publish-MxhCheckedAuthorityPair -CandidateClash $candidate -CandidateSingBox $singCandidate -TargetClash $targetClash.Trim('"') -TargetSingBox $targetSing.Trim('"') -BackupRoot $backupRoot -Expected $expectedTargets -ExpectedCandidates $expectedCandidates -Sources $expectedSources -States $coreStates
    $layout.region_groups=@($regions);$layout.default_exit_members=@($exitMembers);$layout.authority_defaults.source_mode=$sourceMode
    if($sourceMode -eq 'ExistingAuthority'){$layout.authority_defaults.clash=$clash.Trim('"');$layout.authority_defaults.sing_box=$sing.Trim('"')}
    if($outputMode -eq 1){$layout.authority_defaults.clash=$targetClash.Trim('"');$layout.authority_defaults.sing_box=$targetSing.Trim('"')}
    $layout.authority_defaults.output_root=$outputRoot
    if(Read-VpsYesNo '将本次来源、地区、组顺序和输出路径保存为本机默认？' $false -AllowBack){Save-VpsJson -Value $layout -Path (Join-Path $ProjectRoot 'config\client-layout.local.json') -Private}
    Write-VpsUi "配置已写入：$targetClash；$targetSing" Success
    Write-VpsUi "Mihomo=$($coreStates.mihomo.Status)，sing-box=$($coreStates['sing-box'].Status)；sing-box 体积 $singBytes 字节（低于 4 MiB）。$(if($outputMode -eq 1){'原文件备份：'+$backupRoot}else{'当前权威配置未修改。'})" Info
}

function Invoke-MxhClientAuthorityDesigner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$InstanceRoot,
        [string]$ClashAuthorityPath,
        [string]$SingBoxAuthorityPath,
        [string]$ClientOutputRoot,
        [switch]$DryRun
    )
    while($true){
        try{
            $choice=Read-VpsMenu 'Clash/sing-box 客户端权威配置设计器' @(
                '快速创建方案',
                '打开已有方案／恢复草稿',
                '导入现有配置到方案',
                '校验一对现有 Clash/sing-box 配置',
                '高级默认设置',
                '旧版高级生成流程（兼容入口）',
                '查看可用节点数据源',
                '检查／恢复未完成的配置发布'
            ) 1 -AllowBack -HelpText @'
快速创建：选择节点与连接关系，进入可随时修改的方案工作台；生成候选与发布分离。
已有方案：打开私有草稿，敏感值不显示；重新打开必须重新校验。
默认值：只维护被 Git 忽略的本机偏好，可恢复项目通用默认。
数据源：只读扫描已纳管计划；未纳管节点可在生成流程中隐藏输入。
校验配置：不改文件，执行可用 Mihomo 核心、严格 JSON 和 4 MiB 检查。
'@
        }catch{
            if(Test-VpsWizardBackError $_){throw}
            throw
        }
        try{
            if($choice -in @(1,2,3)){
                $scheme=if($choice -eq 2){Open-MxhClientScheme $ProjectRoot}else{New-MxhClientScheme $ProjectRoot}
                if($choice -eq 3){
                    $paths=Read-VpsForm -Steps @(
                        @{Key='clash';Read={param($v)Read-VpsText '现有 Clash YAML（只读）' -Default $ClashAuthorityPath -AllowBack -Validate{param($p)Test-VpsExistingInputPath $p -PathType Leaf}}}
                        @{Key='sing';Read={param($v)Read-VpsText '现有 sing-box JSON（只读）' -Default $SingBoxAuthorityPath -AllowBack -Validate{param($p)Test-VpsExistingInputPath $p -PathType Leaf}}}
                    )
                    $scheme.Clash=ConvertTo-VpsInputPath $paths.clash;$scheme.SingBox=ConvertTo-VpsInputPath $paths.sing;$scheme.SourceMode='ExistingAuthority'
                    $scheme.Sources[$scheme.Clash]=Get-MxhFileFingerprint $scheme.Clash;$scheme.Sources[$scheme.SingBox]=Get-MxhFileFingerprint $scheme.SingBox
                }
                Invoke-MxhClientWorkbench $ProjectRoot $InstanceRoot $scheme -DryRun:$DryRun
            }
            elseif($choice -eq 5){Invoke-MxhEditClientLayoutDefaults -ProjectRoot $ProjectRoot}
            elseif($choice -eq 6){Invoke-MxhBuildClientAuthority -ProjectRoot $ProjectRoot -InstanceRoot $InstanceRoot -ClashAuthorityPath $ClashAuthorityPath -SingBoxAuthorityPath $SingBoxAuthorityPath -ClientOutputRoot $ClientOutputRoot -DryRun:$DryRun;return}
            elseif($choice -eq 8){Invoke-MxhPublicationRecovery $ProjectRoot -DryRun:$DryRun}
            elseif($choice -eq 7){
                $plans=@(Get-MxhManagedClientPlans -InstanceRoot $InstanceRoot);Write-VpsUi "已扫描 $InstanceRoot，发现 $($plans.Count) 个可读取的受管计划。" Info
                foreach($item in $plans){Write-Host ("  - {0} / {1} / {2}" -f $item.Plan.Provider,$item.Plan.Instance,$item.Plan.NodeName)}
                Write-VpsUi '此外可在生成流程中手动添加未纳管 VLESS Reality、AnyTLS 或 Shadowsocks 节点；敏感输入不会显示。' Info
            }else{
                $layout=(Get-MxhClientLayoutTemplate -ProjectRoot $ProjectRoot).Value
                $clashDefault=Get-MxhClientDefaultPath -ProjectRoot $ProjectRoot -CommandLine $ClashAuthorityPath -Environment $env:MXH_VPS_CLASH_AUTHORITY -LocalOrGeneric ([string]$layout.authority_defaults.clash)
                $singDefault=Get-MxhClientDefaultPath -ProjectRoot $ProjectRoot -CommandLine $SingBoxAuthorityPath -Environment $env:MXH_VPS_SINGBOX_AUTHORITY -LocalOrGeneric ([string]$layout.authority_defaults.sing_box)
                $clash=Read-VpsText 'Clash YAML' -Default $clashDefault -AllowBack -Validate{param($v)Test-VpsExistingInputPath -Value $v -PathType Leaf} -ValidationMessage '找不到文件，或路径混用了 / 与 \。'
                $sing=Read-VpsText 'sing-box JSON' -Default $singDefault -AllowBack -Validate{param($v)Test-VpsExistingInputPath -Value $v -PathType Leaf} -ValidationMessage '找不到文件，或路径混用了 / 与 \。'
                $clash=ConvertTo-VpsInputPath -Value $clash;$sing=ConvertTo-VpsInputPath -Value $sing
                Get-Content -Raw -LiteralPath $sing.Trim('"')|ConvertFrom-Json|Out-Null;$bytes=(Get-Item -LiteralPath $sing.Trim('"')).Length;if($bytes-ge 4MB){throw "sing-box 文件为 $bytes 字节，达到或超过 4 MiB。"}
                $states=Test-MxhClientAuthorityPair -ProjectRoot $ProjectRoot -ClashPath $clash.Trim('"') -SingBoxPath $sing.Trim('"')
                Write-VpsUi "两份配置已校验：Mihomo=$($states.mihomo.Status)，sing-box=$($states['sing-box'].Status)。" Success
            }
        }catch{if(Test-VpsWizardBackError $_){Write-VpsUi '已返回客户端配置设计器。' Info;continue};if(Test-VpsNavigationError $_){Write-VpsUi (Get-VpsNavigationMessage $_) Info;continue};throw}
    }
}
