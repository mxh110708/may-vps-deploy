[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ApplicationDirectory,
    [Parameter(Mandatory)][string]$FixtureRoot,
    [Parameter(Mandatory)][string]$ProjectRoot,
    [string]$PythonRuntimeDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ApplicationDirectory=[IO.Path]::GetFullPath($ApplicationDirectory)
$FixtureRoot=[IO.Path]::GetFullPath($FixtureRoot)
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$invoke = Join-Path $ProjectRoot 'scripts/Invoke-VpsBackgroundTest.ps1'
$started = & (Join-Path $ProjectRoot 'scripts/Start-VpsBackgroundTest.ps1') -ApplicationDirectory $ApplicationDirectory -FixtureRoot $FixtureRoot -PublicAssetRoot $ProjectRoot -SyntheticFixture
$session = $started.SessionManifest; $cases = [Collections.Generic.List[object]]::new()
function Send([string]$command,[hashtable]$arguments=@{}) { & $invoke -SessionManifest $session -Command $command -Arguments $arguments }
function Read-Ui {
    $ui=Send 'ui.read'
    $unguarded=@($ui.elements | Where-Object { $_.kind -eq 'ComboBox' -and -not $_.wheel_selection_blocked })
    if($unguarded.Count){throw ('Native selector allows wheel selection: ' + ($unguarded.name -join ', '))}
    $ui
}
function Control([string]$name,[string]$kind='') {
    $matches = @((Read-Ui).elements | Where-Object { $_.name -eq $name -and (-not $kind -or $_.kind -eq $kind) })
    if ($matches.Count -ne 1) { throw "No unique native control: $name ($kind)." }; $matches[0]
}
function Click([string]$name) { Send 'ui.invoke' @{id=(Control $name 'Button').id} | Out-Null }
function Set-Text([string]$name,[string]$value) { Send 'ui.set' @{id=(Control $name 'TextBox').id;value=$value} | Out-Null }
function Choose([string]$name,[string]$value) { Send 'ui.choose' @{name=$name;value=$value} | Out-Null }
function Toggle([string]$name,[bool]$value) { Send 'ui.toggle' @{name=$name;value=$value} | Out-Null }
function Wait-Ui([scriptblock]$condition,[int]$seconds=15) {
    $until=[DateTimeOffset]::UtcNow.AddSeconds($seconds)
    do { $ui=Read-Ui; if (& $condition $ui) { return $ui }; Start-Sleep -Milliseconds 100 } while ([DateTimeOffset]::UtcNow -lt $until)
    throw 'Native UI did not reach the expected state.'
}
function Check([bool]$success,[string]$name) { if(-not $success){throw $name};$cases.Add(@{name=$name;state='passed';layer='native_ui'}) }
try {
    $nativeRequest=Join-Path $FixtureRoot 'test-artifacts/native-client-request.json'
    $nativeResponse=Join-Path $FixtureRoot 'test-artifacts/native-client-response.json'
    @{command='ui.read';arguments=@{}} | ConvertTo-Json | Set-Content -LiteralPath $nativeRequest -Encoding utf8
    $clientStart=[Diagnostics.ProcessStartInfo]::new((Join-Path $ApplicationDirectory 'May-VPS-Deploy.exe'))
    $clientStart.UseShellExecute=$false; $clientStart.CreateNoWindow=$true; $clientStart.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    foreach($argument in @('--test-command',$session,$nativeRequest,$nativeResponse)) { $clientStart.ArgumentList.Add($argument) }
    $clientProcess=[Diagnostics.Process]::Start($clientStart)
    try { if(-not $clientProcess.WaitForExit(25000) -or $clientProcess.ExitCode -ne 0) { throw 'Native test-command client failed.' } } finally { $clientProcess.Dispose() }
    $nativeResult=Get-Content -Raw -LiteralPath $nativeResponse | ConvertFrom-Json
    Check ($nativeResult.ok -and $nativeResult.result.page -eq 'overview') 'native command client before WinUI startup'
    $firstRead=@(Read-Ui)
    Check ($firstRead.Count -eq 1 -and $firstRead[0].page -eq 'overview' -and @($firstRead[0].elements).Count -gt 0) 'strict PowerShell client returns one UI result without async task objects'
    if ($PythonRuntimeDirectory) { [IO.Directory]::CreateDirectory((Join-Path $FixtureRoot 'runtime')) | Out-Null; Copy-Item -LiteralPath $PythonRuntimeDirectory -Destination (Join-Path $FixtureRoot 'runtime/python') -Recurse -Force }
    Click 'deploy'; Set-Text '服务商' 'Example'; Set-Text '实例名称' 'Native Flow'
    $null=Wait-Ui {param($ui) @($ui.elements|Where-Object { $_.name -eq '节点名称' -and $_.value -eq 'Example-Native-Flow' }).Count -eq 1 }
    Check $true 'generated node name through TextChanged'
    Set-Text '节点名称' 'personal-name'; Set-Text '服务商' 'Another'
    Check ((Control '节点名称' 'TextBox').value -eq 'personal-name') 'custom name survives provider change'
    Click '审阅计划'; $ui=Read-Ui
    Check (-not $ui.busy -and -not $ui.dialog -and $ui.notice) 'invalid deployment stops before connection'
    Toggle 'Komari 监控 Agent' $true
    Check ((Control 'Komari 主控地址' 'TextBox').enabled) 'monitor field appears after purpose selection'
    Toggle 'Komari 监控 Agent' $false
    Check (@((Read-Ui).elements|Where-Object name -eq 'Komari 主控地址').Count -eq 0) 'monitor field hides when disabled'
    Click '已有实例追加安装'; $null=Wait-Ui {param($ui) $ui.dialog -eq '在已有实例追加安装'}
    Click '选择组件'; $null=Wait-Ui {param($ui) $ui.dialog -eq '追加安装组件'}
    Check (-not (Control 'Reality 入口' 'CheckBox').enabled -and -not (Control '填写参数' 'Button').enabled) 'installed component disabled and empty batch blocked'
    Toggle 'Shadowsocks 落地' $true; Toggle 'Komari 主控' $true
    Click '填写参数'; $null=Wait-Ui {param($ui) $ui.dialog -eq '填写追加安装参数'}
    Set-Text '可信入口 IP（逗号分隔）' '192.0.2.30'
    Check ((Control '主控本机 HTTP 端口' 'TextBox').enabled -and (Control '新落地 TCP / UDP 端口' 'TextBox').enabled) 'combined append shows both components parameters'
    Click '审阅安装'; $null=Wait-Ui {param($ui) $ui.dialog -eq '审阅追加安装计划'}
    Check ((@((Read-Ui).elements|Where-Object { $_.name -match '本轮新增|统一验收|安装 Shadowsocks|安装 Komari' }).Count -ge 3)) 'one append review lists components order and shared rollback'
    Send 'ui.capture' @{name='batch-installation-review.png'} | Out-Null; Click '返回'; $null=Wait-Ui {param($ui) -not $ui.dialog}
    Click 'settings'; Toggle '最小到托盘' $true
    Send 'window.close' | Out-Null; $ui=Wait-Ui {param($ui) $ui.window.minimized_to_tray -and $ui.window.tray_registered}
    Check (-not $ui.busy) 'close registers real shell tray icon and keeps process alive'
    Send 'window.restore' | Out-Null; $ui=Wait-Ui {param($ui) -not $ui.window.minimized_to_tray -and -not $ui.window.tray_registered}
    Toggle '关闭应用' $true
    Check ((Get-Content -Raw -LiteralPath (Join-Path $FixtureRoot 'private/desktop-settings.json')|ConvertFrom-Json).CloseBehavior -eq 'Exit') 'mutually exclusive close choice persists'
    Click 'clients'; Click '创建方案'; $null=Wait-Ui {param($ui) $ui.dialog -eq '创建配置方案'}
    Toggle 'sing-box 生成目标' $false; Toggle 'Clash 生成目标' $false
    Check (-not (Control '开始设计' 'Button').enabled) 'no output disables primary button'
    try { Click '开始设计'; throw 'Disabled primary executed.' } catch { Check ($_.Exception.Message -match '不可用') 'disabled native invoke refused' }
    Toggle 'sing-box 生成目标' $true; Toggle 'Clash 生成目标' $true; Set-Text '方案名称' 'background-native'
    Send 'ui.capture' @{name='create-scheme.png'} | Out-Null
    Click '开始设计'; $null=Wait-Ui {param($ui) -not $ui.dialog -and @($ui.elements|Where-Object name -eq '手动添加').Count -eq 1}
    Click '手动添加'; $null=Wait-Ui {param($ui) $ui.dialog -eq '添加节点'}
    Choose '协议' 'ShadowsocksLanding'; Set-Text '节点名称' 'synthetic-exit'; Set-Text '服务器地址' '192.0.2.12'; Set-Text 'Shadowsocks 方法' 'aes-128-gcm'
    $secret='synthetic-private-value'; [IO.File]::WriteAllText((Join-Path $FixtureRoot 'test-secrets/ss.txt'),$secret)
    Send 'ui.secret' @{name='密码 / SS2022 组合密钥';reference='ss.txt'} | Out-Null
    $ui=Read-Ui
    Check (($ui|ConvertTo-Json -Depth 20) -notmatch $secret -and (Control '密码 / SS2022 组合密钥' 'PasswordBox').filled) 'password set through private reference and redacted from snapshot'
    Click '保存'; $null=Wait-Ui {param($ui) -not $ui.dialog -and @($ui.elements|Where-Object name -eq 'synthetic-exit').Count -eq 1}
    Click '手动添加'; $null=Wait-Ui {param($ui) $ui.dialog -eq '添加节点'}
    Set-Text '节点名称' 'synthetic-entry'; Set-Text '服务器地址' '192.0.2.13'; Set-Text 'SNI' 'example.com'
    Set-Text 'Reality 公钥' ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).Replace('+','-').Replace('/','_').TrimEnd('='))
    Set-Text 'short-id' 'a1b2c3d4'
    [IO.File]::WriteAllText((Join-Path $FixtureRoot 'test-secrets/uuid.txt'),[guid]::NewGuid().ToString())
    Send 'ui.secret' @{name='UUID';reference='uuid.txt'} | Out-Null
    Click '保存'; $null=Wait-Ui {param($ui) -not $ui.dialog -and @($ui.elements|Where-Object name -eq 'synthetic-entry').Count -eq 1}
    Send 'window.close' | Out-Null; $null=Wait-Ui {param($ui) $ui.dialog -eq '保存方案修改？'}
    Click '继续编辑'; $null=Wait-Ui {param($ui) -not $ui.dialog}
    Check ((Control '拖动排序 synthetic-entry' 'NodeReorderHandle').enabled) 'direct close asks about unsaved scheme and cancel preserves editor'
    $nodeScroll=@((Read-Ui).elements | Where-Object kind -eq 'ScrollViewer')
    Check ($nodeScroll.Count -eq 1) 'node list has one actual scroll viewport'
    Send 'ui.scroll' @{id=$nodeScroll[0].id;offset=100000} | Out-Null
    $null=Wait-Ui {param($ui) $scroll=@($ui.elements|Where-Object kind -eq 'ScrollViewer');$scroll.Count -eq 1 -and [Math]::Abs($scroll[0].offset-$scroll[0].extent) -lt 2}
    $startedDrag=Send 'ui.drag' @{id=(Control '拖动排序 synthetic-entry' 'NodeReorderHandle').id;phase='begin'}
    $movingDrag=Send 'ui.drag' @{phase='move';insertion=0}
    Send 'ui.capture' @{name='native-drag-preview.png'} | Out-Null
    $cancelledDrag=Send 'ui.drag' @{phase='cancel'}
    Check ($startedDrag.started -and $movingDrag.preview -and $movingDrag.indicator -and $cancelledDrag.cancelled) 'incremental handle gesture renders row preview and cancellation preserves order'
    $moved=Send 'ui.drag' @{id=(Control '拖动排序 synthetic-entry' 'NodeReorderHandle').id;insertion=0}
    Check ($moved.moved -and $moved.indicator -and $moved.preview) 'drag press move release follows application pointer handlers'
    Click '3 · 连接与分组'; Click '设置'; $ui=Wait-Ui {param($ui) $ui.dialog -eq '业务默认出口'}
    $business=@($ui.elements | Where-Object { $_.kind -like '*ComboBox' } | ForEach-Object name)
    Check ([Array]::IndexOf($business,'Academic Research')+1 -eq [Array]::IndexOf($business,'Google Services') -and [Array]::IndexOf($business,'Google Services')+1 -eq [Array]::IndexOf($business,'Microsoft Services')) 'Google business selector is between Academic and Microsoft'
    $google=Control 'Google Services' 'ComboBox'
    Check (@($google.choices | Where-Object { $_.value -eq 'synthetic-exit' }).Count -eq 1) 'Google selector can choose a landing exit'
    Send 'ui.choose' @{id=$google.id;value='synthetic-exit'} | Out-Null; Click '保存'; $null=Wait-Ui {param($ui) -not $ui.dialog}
    Click '4 · 生成与导出'; $ui=Read-Ui
    Check (-not (Control '审阅并导出' 'Button').enabled -and ($ui.elements.name -join ' ') -match '生成') 'export prerequisites visible and enforced'
    $export=Join-Path $FixtureRoot 'test-artifacts'
    Set-Text 'Clash YAML 文件' (Join-Path $export 'test.yaml'); Set-Text 'sing-box JSON 文件' (Join-Path $export 'test.json')
    if ($PythonRuntimeDirectory) {
        Click '生成配置'; $null=Wait-Ui {param($ui) -not $ui.busy -and @($ui.elements|Where-Object { $_.name -eq '校验配置' -and $_.enabled }).Count -eq 1} 60
        Click '校验配置'; $null=Wait-Ui {param($ui) -not $ui.busy -and @($ui.elements|Where-Object { $_.name -eq '审阅并导出' -and $_.enabled }).Count -eq 1} 60
        Click '审阅并导出'; $null=Wait-Ui {param($ui) [bool]$ui.dialog}; Send 'ui.capture' @{name='export-review.png'} | Out-Null
        $primary=@((Read-Ui).elements|Where-Object { $_.kind -eq 'Button' -and $_.name -notin @('取消','返回') })
        Check ($primary.Count -eq 1) 'export has one explicit confirmation'
        Send 'ui.invoke' @{id=$primary[0].id} | Out-Null; $null=Wait-Ui {param($ui) -not $ui.busy -and -not $ui.dialog} 60
        Check ((Test-Path -LiteralPath (Join-Path $export 'test.yaml')) -and (Test-Path -LiteralPath (Join-Path $export 'test.json'))) 'two real core-validated configs exported through normal UI'
    } else { $cases.Add(@{name='real core generation validation export';state='skipped';reason='No bundled Python runtime supplied.'}) }
    Click '保存方案'; Click '退出编辑'; $null=Wait-Ui {param($ui) -not $ui.dialog}
    $peerDirectory=Join-Path $FixtureRoot 'private/instances/Example/Native-Landing/May-VPS-Deploy'
    [IO.Directory]::CreateDirectory($peerDirectory) | Out-Null
    @{Provider='Example';Instance='Native-Landing';NodeName='原生合成落地';Role='ShadowsocksLanding';Roles=@('ShadowsocksLanding');Server=@{IPv4='192.0.2.20';IPv6='2001:db8::20'};Ports=@{SshPrimary=22022;SshRescue=33022;LandingShadowsocks=4000};Import=@{Status='Completed'};Shadowsocks=@{Method='2022-blake3-aes-128-gcm';SecondaryIpv6Enabled=$true;SecondaryIpv6Address='2001:db8:1::20'};ProtocolInventory=@{ShadowsocksLanding=@{Installed=$true;Enabled=$true}}} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $peerDirectory 'deployment-plan.json') -Encoding utf8
    @{Engine='dotnet-v1';CurrentManagementPort=22022} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $peerDirectory 'deployment-state.json') -Encoding utf8
    Click 'network'; Choose '目标实例' 'Example/Managed-Demo/May-VPS-Deploy'
    $canonical=Join-Path $FixtureRoot 'private/instances/Example/Managed-Demo/May-VPS-Deploy'
    $backup=Join-Path $canonical 'ip-change-example'
    [IO.Directory]::CreateDirectory($backup) | Out-Null
    Copy-Item -LiteralPath (Join-Path $canonical 'deployment-plan.json') -Destination (Join-Path $backup 'deployment-plan.json')
    Click 'instances'
    Check (@((Control '选择实例').choices|Where-Object value -eq 'Example/Managed-Demo/May-VPS-Deploy').Count -eq 1 -and @((Control '选择实例').choices|Where-Object value -Like '*ip-change-example*').Count -eq 0) 'nested IP-change backup is not a duplicate native instance choice'
    Choose '选择实例' 'Example/Managed-Demo/May-VPS-Deploy'; Click '删除实例'; $null=Wait-Ui {param($ui) $ui.dialog -eq '删除本地实例'}
    Check (((Read-Ui).elements.name -join ' ') -match '删除范围' -and (Test-Path -LiteralPath (Join-Path $backup 'deployment-plan.json'))) 'canonical instance deletion review opens while backup data is preserved'
    Click '返回'; $null=Wait-Ui {param($ui) -not $ui.dialog}; Click 'network'; Choose '目标实例' 'Example/Managed-Demo/May-VPS-Deploy'
    Check ((Control '优化偏好').value -eq 'Balanced') 'balanced diagnostics is the normal default'
    Choose '入口连接地址族' 'Both'
    Check (((Read-Ui).elements.name -join ' ') -match '每条路径有效载荷最多 204 MiB') 'dual stack shares one total payload budget'
    Choose '调优总流量预算' 'Custom'; Set-Text '自定义总预算（MiB，64–20480）' '20481'; Click '采集并生成建议'
    Check (-not (Read-Ui).dialog -and (Read-Ui).notice) 'over 20 GiB is rejected before any review or connection'
    Set-Text '自定义总预算（MiB，64–20480）' '20480'; Choose '调优总流量预算' 'Maximum'
    Choose 'TCP 角色与测试路径' 'Relay'; Choose '优化偏好' 'Upload'
    Check ((Control '中转后的已有落地（仅读取归档）').value -eq 'Example/Native-Landing/May-VPS-Deploy') 'relay selector discovers managed landing and preserves source instance'
    Choose '入口 → 落地连接地址族' 'IPv6'; Choose '落地访问网站使用的 IP' 'IPv6'
    Choose '落地访问网站使用的 IP' 'Both'
    Check (((Read-Ui).elements.name -join ' ') -match '共 4 条路径') 'both exit families refresh the shared budget without rebuilding the page'
    Click '采集并生成建议'; $ui=Wait-Ui {param($ui) [bool]$ui.dialog}
    Check (($ui.elements.name -join ' ') -match '上传优先' -and ($ui.elements.name -join ' ') -match 'Native-Landing' -and ($ui.elements.name -join ' ') -match '20 GiB' -and ($ui.elements.name -join ' ') -match '连接 VPS：IPv4' -and ($ui.elements.name -join ' ') -match '连接 VPS：IPv6' -and ($ui.elements.name -join ' ') -match '落地→网站：IPv4' -and ($ui.elements.name -join ' ') -match '落地→网站：IPv6') 'normal network review includes entry connection and both exit families with a shared flow budget'
    Click '返回'; $null=Wait-Ui {param($ui) -not $ui.dialog}
    Choose 'TCP 角色与测试路径' 'Entry'
    Check (@((Read-Ui).elements|Where-Object name -eq '中转后的已有落地（仅读取归档）').Count -eq 0) 'single-hop path hides unused relay fields'
    Choose 'TCP 角色与测试路径' 'ForwardOnly'; Click '采集并生成建议'; $ui=Wait-Ui {param($ui) [bool]$ui.dialog}
    Check (($ui.elements.name -join ' ') -match '不发起公网吞吐测试') 'forward-only review does not promise irrelevant throughput tests'
    Click '返回'; $null=Wait-Ui {param($ui) -not $ui.dialog}
    Choose '目标实例' 'Example/Native-Landing/May-VPS-Deploy'
    Check ((Control 'TCP 角色与测试路径').value -eq 'Landing' -and @((Read-Ui).elements|Where-Object name -eq '审阅并应用建议').Count -eq 0) 'landing offers diagnostics and only basic fq BBR tuning'
    Check ((Control '落地访问网站使用的 IP').value -eq 'Both') 'dual-exit landing defaults to testing both exits'
    Choose '入口连接地址族' 'Both'; Choose '落地访问网站使用的 IP' 'IPv6'; Choose '落地访问网站使用的 IP' 'Both'
    Check (((Read-Ui).elements.name -join ' ') -match '共 4 条路径') 'landing distinguishes connection and exit families and divides the budget across four paths'
    Click '采集并生成建议'; $ui=Wait-Ui {param($ui) [bool]$ui.dialog}
    Check (($ui.elements.name -join ' ') -match '落地→网站：IPv4' -and ($ui.elements.name -join ' ') -match '落地→网站：IPv6') 'landing review includes both deployed exits'
    Click '返回'; $null=Wait-Ui {param($ui) -not $ui.dialog}
    Send 'ui.capture' @{name='native-network-path.png'} | Out-Null
    $kernelStateFile=Join-Path $canonical 'deployment-state.json'
    $kernelState=Get-Content -Raw -LiteralPath $kernelStateFile | ConvertFrom-Json -AsHashtable
    $kernelState.LastKernelCheck=@{Compatible=$true;Kernel='6.12.1-amd64';BbrVersion='VersionUnverified';Reasons=@();At=[DateTimeOffset]::UtcNow.ToString('O')}
    $kernelState | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $kernelStateFile -Encoding utf8
    Click 'instances'; Click 'network'; Choose '目标实例' 'Example/Managed-Demo/May-VPS-Deploy'
    Check ((Control 'BBR 版本').value -eq 'Current') 'kernel replacement remains opt-in'
    Choose 'BBR 版本' 'v3'; $ui=Read-Ui
    Check (@($ui.elements | Where-Object name -eq 'BBR v3 内核来源').Count -eq 0 -and ($ui.elements.name -join ' ') -match '固定预编译' -and ($ui.elements.name -join ' ') -notmatch '最新提交|VPS 源码构建') 'BBR v3 exposes only the embedded precompiled package'
    Click '审阅安装 BBR v3 内核'
    $ui=Wait-Ui {param($ui) [bool]$ui.dialog}; $kernelCatalogText=Get-Content -Raw -LiteralPath (Join-Path $ProjectRoot 'config/kernel-catalog.json'); $kernelCatalog=$kernelCatalogText | ConvertFrom-Json
    $kernelSourceDate=([System.Text.Json.JsonDocument]::Parse($kernelCatalogText)).RootElement.GetProperty('SourceDate').GetString()
    Check (($ui.elements.name -join ' ').Contains($kernelCatalog.Commit) -and ($ui.elements.name -join ' ').Contains($kernelCatalog.Sha256) -and ($ui.elements.name -join ' ').Contains($kernelSourceDate) -and ($ui.elements.name -join ' ').Contains($kernelCatalog.BaseKernel) -and ($ui.elements.name -join ' ') -match '非 root|不等于 LTS') 'kernel review binds full official commit, date, base version and source digest with build boundaries'
    Check (($ui.elements.name -join ' ').Contains($kernelCatalog.Prebuilt.Sha256) -and ($ui.elements.name -join ' ') -match '应用内置预编译包' -and ($ui.elements.name -join ' ') -match '不安装编译依赖') 'native review shows embedded package digest and no VPS compilation'
    Send 'ui.capture' @{name='native-google-kernel-review.png'} | Out-Null
    Click '返回'; $null=Wait-Ui {param($ui) -not $ui.dialog}; Choose 'BBR 版本' 'Current'
    Send 'suite.run' | Out-Null
    $until=[DateTimeOffset]::UtcNow.AddSeconds(75)
    do { $suite=Send 'suite.status'; if($suite.state -ne 'running'){break};Start-Sleep -Milliseconds 200 } while([DateTimeOffset]::UtcNow -lt $until)
    Check ($suite.state -eq 'passed') 'deployment maintenance additions native regression suites'
    $ui=Read-Ui
    Check ($ui.window.window_activations -eq 0 -and $ui.window.foreground_samples -eq 0 -and $ui.window.offscreen -and -not $ui.window.shown_in_switchers) 'test instance never activated or appeared in switcher'
    $audit=Get-Content -Raw -LiteralPath (Join-Path $export 'commands.jsonl')
    Check ($audit -notmatch $secret -and $audit -notmatch '"token"') 'command audit omits input values and credentials'
    $cases.Add(@{name='physical pointer capture tray menu wheel system picker UAC';state='unverified';reason='Application drag path and real tray lifecycle tested; no global mouse injection or OS dialog control.'})
    @{schema_version=1;state='passed';cases=$cases;window=$ui.window;production_connections=0} | ConvertTo-Json -Depth 25 | Set-Content -LiteralPath (Join-Path $export 'native-flow.json') -Encoding utf8
    'PASS: native UI command flow, dialogs, independent storage, no foreground activation.'
} catch {
    try { Send 'ui.capture' @{name='failure.png'} | Out-Null } catch { }
    @{schema_version=1;state='failed';safe_error=$_.Exception.Message;cases=$cases} | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $FixtureRoot 'test-artifacts/native-flow.json') -Encoding utf8
    throw
} finally { try { Send 'session.stop' | Out-Null } catch { } }
