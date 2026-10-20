#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(DontShow)][string]$InstanceRoot,
    [string]$PlanPath,
    [Parameter(DontShow)][string]$PreviewPath,
    [Parameter(DontShow)][switch]$NoShow
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw '图形界面需要 Windows 10/11。' }
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { throw '请用 pwsh -STA 启动图形界面。' }
$script:GuiProjectRoot = $PSScriptRoot
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
trap {
    if ($NoShow -or $PreviewPath) { break }
    [void][Windows.MessageBox]::Show("应用无法继续：$($_.Exception.Message)",'May VPS Deploy','OK','Error')
    exit 1
}
if (-not ('May.VpsDeploy.Gui.Session' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'src/gui/VpsDeploy.GuiHost.cs')
}
Import-Module (Join-Path $PSScriptRoot 'src/VpsDeploy.Core.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src/VpsDeploy.GuiData.psm1') -Force
$script:GuiModule = Get-Module VpsDeploy.Core
$script:GuiDataPaths = Get-VpsGuiDataPaths $PSScriptRoot
if ($InstanceRoot -and ($NoShow -or $PreviewPath)) {
    $script:GuiDataPaths.Settings = Join-Path $InstanceRoot 'gui-settings.json'
    $script:GuiDataPaths.History = Join-Path $InstanceRoot 'task-history.json'
}
$application = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'config/application.json') | ConvertFrom-Json
$script:GuiPreferences = @{ automatic_update_check = $false; scale = 1.0 }
$preferencesPath = $script:GuiDataPaths.Settings
if (Test-Path -LiteralPath $preferencesPath) {
    $saved = Get-Content -Raw -LiteralPath $preferencesPath | ConvertFrom-Json -AsHashtable
    if ($saved.ContainsKey('automatic_update_check')) { $script:GuiPreferences.automatic_update_check = [bool]$saved.automatic_update_check }
    if ($saved.ContainsKey('scale') -and [double]$saved.scale -in @(1.0, 1.12)) { $script:GuiPreferences.scale = [double]$saved.scale }
}
if ($InstanceRoot -and -not ($NoShow -or $PreviewPath)) { throw '图形界面统一使用应用 private/instances 目录。' }
if (-not $InstanceRoot) { $InstanceRoot = $script:GuiDataPaths.Instances }
if ($PlanPath -and -not (Test-VpsGuiPlanPath $InstanceRoot $PlanPath)) { throw '此计划不属于应用实例目录，请先转换旧归档。' }
[xml]$layout = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'assets/gui/MainWindow.xaml')
$script:GuiWindow = [Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($layout))
$script:GuiControls = @{}
foreach ($match in [regex]::Matches($layout.OuterXml, 'x:Name="([^"]+)"')) {
    $script:GuiControls[$match.Groups[1].Value] = $script:GuiWindow.FindName($match.Groups[1].Value)
}
$fontDirectory = [uri]::new((Join-Path $PSScriptRoot 'assets/gui/fonts') + [IO.Path]::DirectorySeparatorChar)
$body = [Windows.Media.FontFamily]::new()
$body.FamilyMaps.Clear()
$body.FamilyMaps.Add([Windows.Media.FontFamilyMap]@{Unicode='2e80-9fff,f900-faff,ff00-ffef';Target='Microsoft YaHei UI'})
$body.FamilyMaps.Add([Windows.Media.FontFamilyMap]@{Target=$fontDirectory.AbsoluteUri + '#Schibsted Grotesk'})
$script:GuiWindow.FontFamily = $body
$script:GuiControls.Brand.FontFamily = [Windows.Media.FontFamily]::new($fontDirectory, './#Source Serif 4 14pt')
$script:GuiControls.RuntimeLabel.Text = if(Test-Path -LiteralPath (Join-Path $PSScriptRoot 'desktop-runtime.json')){'内置环境就绪'}else{"PowerShell $($PSVersionTable.PSVersion)"}
$icon=Join-Path $PSScriptRoot 'assets/gui/app.ico'
if(Test-Path -LiteralPath $icon){$script:GuiWindow.Icon=[Windows.Media.Imaging.BitmapFrame]::Create([uri]$icon)}
$script:GuiControls.VersionLabel.Text = $application.version + $(if ($application.channel -eq 'development') { ' · UI 预览' } else { '' })
$script:GuiControls.UpdateVersion.Text = "当前版本 $($application.version)"
$script:GuiControls.AutoUpdateCheck.IsChecked = $script:GuiPreferences.automatic_update_check
$script:GuiWindow.Content.LayoutTransform = [Windows.Media.ScaleTransform]::new($script:GuiPreferences.scale,$script:GuiPreferences.scale)
$chrome = [Windows.Shell.WindowChrome]::new()
$chrome.CaptionHeight = 54; $chrome.ResizeBorderThickness = [Windows.Thickness]::new(6)
$chrome.GlassFrameThickness = [Windows.Thickness]::new(0)
[Windows.Shell.WindowChrome]::SetWindowChrome($script:GuiWindow, $chrome)
foreach ($name in @('MinimizeWindow','MaximizeWindow','CloseWindow')) {
    [Windows.Shell.WindowChrome]::SetIsHitTestVisibleInChrome($script:GuiControls[$name], $true)
}
$script:GuiState = @{
    Session = $null; Request = $null; Mode = ''; Title = ''; Root = $InstanceRoot
    PlanPath = $PlanPath; Catalog = @(); Journal = [Collections.Generic.List[string]]::new()
    Context = [Collections.Generic.List[string]]::new(); Update = $null; Closing = $false; PendingTask = $null; FormMode='New'
    History=@(); HistoryWritable=$true; StartedAt=''
}
if(Test-Path -LiteralPath $script:GuiDataPaths.History){
    try{
        $savedHistory=Get-Content -Raw -LiteralPath $script:GuiDataPaths.History|ConvertFrom-Json -AsHashtable
        if($savedHistory.schema_version -ne 1 -or -not $savedHistory.ContainsKey('tasks')){throw 'Unsupported task history.'}
        $script:GuiState.History=@($savedHistory.tasks)
    }
    catch{$script:GuiState.HistoryWritable=$false}
}
$script:GuiTimer = [Windows.Threading.DispatcherTimer]::new()
$script:GuiTimer.Interval = [TimeSpan]::FromMilliseconds(100)

function Save-VpsGuiPreferences {
    try { Save-VpsJson -Path $script:GuiDataPaths.Settings -Value $script:GuiPreferences -Private }
    catch { $script:GuiControls.FooterStatus.Text='界面设置未保存，请检查应用目录的写入权限。' }
}
function Show-VpsGuiPage {
    param([string]$Page, [string]$Title)
    $navigation=@{OverviewPage='NavOverview';DeploymentPage='NavDeploy';ClientsPage='NavClients';InstancesPage='NavInstances';RecordsPage='NavRecords';SettingsPage='NavSettings'}
    if($navigation.ContainsKey($Page)){$script:GuiControls[$navigation[$Page]].IsChecked=$true}
    foreach ($name in @('OverviewPage','DeploymentPage','ClientsPage','InstancesPage','WorkflowPage','RecordsPage','SettingsPage')) {
        $script:GuiControls[$name].Visibility = if ($name -eq $Page) { 'Visible' } else { 'Collapsed' }
    }
    $script:GuiControls.PageTitle.Text = $Title
    $script:GuiControls.MainScroll.ScrollToTop()
}
function Update-VpsGuiHistory {
    $script:GuiControls.TaskHistory.Items.Clear()
    $labels=@{Completed='已完成';Warning='已结束，有提示';Failed='未完成';Canceled='已取消'}
    foreach($record in @($script:GuiState.History|Select-Object -Last 120|Sort-Object EndedAt -Descending)){
        try{
            $label=$labels[[string]$record.Status]
            $line="$(([datetime]$record.EndedAt).ToLocalTime().ToString('MM-dd HH:mm')) · $($record.Title) · $label"
            [void]$script:GuiControls.TaskHistory.Items.Add($line)
        }catch{continue}
    }
    $script:GuiControls.NoTaskHistory.Visibility=if($script:GuiControls.TaskHistory.Items.Count){'Collapsed'}else{'Visible'}
}
function Save-VpsGuiTaskRecord {
    param([May.VpsDeploy.Gui.Session]$Session)
    if($script:GuiState.Mode -in @('CheckUpdate','ApplyUpdate')){return}
    $status=if($Session.Failed){'Failed'}elseif($Session.CancelRequested -or $Session.NavigatedBack){'Canceled'}elseif($Session.HasWarnings){'Warning'}else{'Completed'}
    $script:GuiState.History+=@{Mode=$script:GuiState.Mode;Title=$script:GuiState.Title;Status=$status;StartedAt=$script:GuiState.StartedAt;EndedAt=(Get-Date).ToUniversalTime().ToString('o')}
    $script:GuiState.History=@($script:GuiState.History|Select-Object -Last 120)
    if($script:GuiState.HistoryWritable){
        try{Save-VpsJson -Path $script:GuiDataPaths.History -Value @{schema_version=1;tasks=$script:GuiState.History} -Private}
        catch{$script:GuiControls.FooterStatus.Text='任务状态已保留在当前窗口，历史记录文件未能保存。'}
    }
    Update-VpsGuiHistory
}
function Get-VpsGuiCatalog {
    param([string]$Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return }
    $queue = [Collections.Generic.Queue[string]]::new(); $queue.Enqueue($Root)
    $visited = 0
    while ($queue.Count -and $visited -lt 5000) {
        $directory = $queue.Dequeue(); $visited++
        $file = Join-Path $directory 'deployment-plan.json'
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            try {
                $plan = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable
                if ($plan.ContainsKey('Provider') -and $plan.ContainsKey('Instance') -and $plan.ContainsKey('Role') -and (Test-VpsGuiPlanPath $Root $file)) {
                    [pscustomobject]@{ Label = "$($plan.Provider) · $($plan.Instance)"; Role = [string]$plan.Role; PlanPath = $file }
                }
            } catch { }
        }
        foreach ($child in Get-ChildItem -LiteralPath $directory -Directory -ErrorAction SilentlyContinue) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($child.Name -in @('.git','.tmp','.cache','private','migration-backups','maintenance-backups','health-audits','abandoned-transactions','server-configs','client-exports')) { continue }
            $queue.Enqueue($child.FullName)
        }
    }
}
function Get-VpsGuiRoleLabel {
    param([string]$Role)
    $names=@{RealityEntry='Reality 入口';AnyTlsEntry='AnyTLS + ECH 入口';ShadowsocksLanding='Shadowsocks 2022 落地';MonitorOnly='监控与基础管理';AuditOnly='仅审计'}
    if($names.ContainsKey($Role)){return $names[$Role]};return $Role
}
function Update-VpsGuiCatalog {
    $selected = if ($script:GuiControls.InstanceList.SelectedItem) { [string]$script:GuiControls.InstanceList.SelectedItem.Tag } else { $script:GuiState.PlanPath }
    $script:GuiState.Catalog = @(Get-VpsGuiCatalog -Root $script:GuiState.Root)
    $script:GuiControls.InstanceCount.Text = [string]$script:GuiState.Catalog.Count
    $script:GuiControls.DataLocation.Text = $script:GuiDataPaths.Root
    $script:GuiControls.InstanceList.Items.Clear()
    foreach ($instance in $script:GuiState.Catalog) {
        $entry = [Windows.Controls.ListBoxItem]::new()
        $entry.Tag = $instance.PlanPath
        $content = [Windows.Controls.StackPanel]::new()
        $label = [Windows.Controls.TextBlock]::new(); $label.Text = $instance.Label; $label.FontWeight = 'SemiBold'
        $role = [Windows.Controls.TextBlock]::new(); $role.Text = Get-VpsGuiRoleLabel $instance.Role; $role.Foreground = '#999999'; $role.Margin = '0,6,0,0'
        [void]$content.Children.Add($label); [void]$content.Children.Add($role)
        $entry.Content = $content; [void]$script:GuiControls.InstanceList.Items.Add($entry)
        if ($instance.PlanPath -eq $selected) { $entry.IsSelected = $true }
    }
    $script:GuiControls.NoInstancesLabel.Visibility = if ($script:GuiState.Catalog.Count) { 'Collapsed' } else { 'Visible' }
}
function Show-VpsGuiInstanceDetails {
    $selected=$script:GuiControls.InstanceList.SelectedItem
    if(-not $selected){$script:GuiControls.SelectedInstanceLabel.Text='尚未选择实例';$script:GuiControls.SelectedInstanceDetails.Text='选中实例后查看归档信息。';return}
    try {
        $plan=Get-Content -Raw -LiteralPath $selected.Tag|ConvertFrom-Json -AsHashtable
        $script:GuiControls.SelectedInstanceLabel.Text="$($plan.Provider) · $($plan.Instance)"
        $detail="用途：$(Get-VpsGuiRoleLabel $plan.Role)"
        if($plan.ContainsKey('NodeName')){$detail+="`n节点：$($plan.NodeName)"}
        $statePath=Join-Path (Split-Path -Parent $selected.Tag) 'deployment-state.json'
        if(Test-Path -LiteralPath $statePath){
            $state=Get-Content -Raw -LiteralPath $statePath|ConvertFrom-Json -AsHashtable
            if($state.ContainsKey('Modules')){
                $counts=@($state.Modules.Values|ForEach-Object Status|Group-Object|ForEach-Object{"$($_.Name) $($_.Count)"})
                $detail+="`n本地部署记录：$($counts -join ' · ')"
            }
        }
        $script:GuiControls.SelectedInstanceDetails.Text=$detail
    }catch{$script:GuiControls.SelectedInstanceDetails.Text='归档信息无法读取，请核对本地文件。'}
}
function Show-VpsGuiDeploymentForm {
    param([ValidateSet('New','Import')][string]$Mode='New')
    $script:GuiState.FormMode=$Mode
    $script:GuiControls.DeploymentCaption.Text=if($Mode -eq 'New'){'部署新 VPS'}else{'接入已有 VPS'}
    $script:GuiControls.NewRoleFields.Visibility=if($Mode -eq 'New'){'Visible'}else{'Collapsed'}
    $script:GuiControls.NewFormError.Visibility='Collapsed'
    $script:GuiControls.NavDeploy.IsChecked=$true
    Show-VpsGuiPage 'DeploymentPage' $script:GuiControls.DeploymentCaption.Text
}
function Submit-VpsGuiDeploymentForm {
    $form=@{}
    foreach($key in @('Provider','Instance','NodeName','IPv4','IPv6','SshPort','KeyPath','Admin')){$form[$key]=$script:GuiControls["New$key"].Text.Trim()}
    $form.Auth=$script:GuiControls.NewAuthType.SelectedIndex
    $form.KeyMode=$script:GuiControls.NewKeyMode.SelectedIndex+1
    $form.Role=$script:GuiControls.NewRole.SelectedIndex+1
    $mode=$script:GuiState.FormMode
    $errors=& $script:GuiModule {
        param($Form,$Mode,$Root)
        if(-not(Test-VpsSafePathSegment $Form.Provider)){'请填写有效的服务商名称。'}
        if(-not(Test-VpsSafePathSegment $Form.Instance)){'请填写有效的实例名称。'}
        if($Form.Provider -and $Form.Instance -and (Get-VpsExistingPlanPath (Join-Path (Join-Path $Root $Form.Provider) $Form.Instance))){'此实例已有计划，请在实例页管理。'}
        if($Form.NodeName -and -not(Test-VpsNodeName $Form.NodeName)){'节点名称格式无效。'}
        if(-not(Test-VpsIpAddress $Form.IPv4 IPv4)){'请填写有效的服务器 IPv4。'}
        if($Form.IPv6 -and -not(Test-VpsIpAddress $Form.IPv6 IPv6)){'服务器 IPv6 格式无效。'}
        $port=0;if(-not[int]::TryParse($Form.SshPort,[ref]$port) -or $port -lt 1 -or $port -gt 65535){'SSH 端口应为 1–65535。'}
        if($Form.Auth -eq 0 -and -not(Test-VpsExistingInputPath $Form.KeyPath -PathType Leaf)){'请选择现有 OpenSSH 私钥文件。'}
        if($Mode -eq 'New' -and ($Form.Admin -notmatch '^[a-z_][a-z0-9_-]{0,30}$' -or $Form.Admin -eq 'root')){'日常管理用户不能是 root，应使用有效的 Linux 用户名。'}
    } $form $mode $script:GuiState.Root
    if($errors){$script:GuiControls.NewFormError.Text=@($errors)-join "`n";$script:GuiControls.NewFormError.Visibility='Visible';return}
    $node=if($form.NodeName){$form.NodeName}else{(($form.Provider+'-'+$form.Instance)-replace '[^A-Za-z0-9._-]','-')-replace '-+','-'}
    $initial=@{'服务商名称'=$form.Provider;'实例名称'=$form.Instance}
    if($mode -eq 'New'){
        $initial['客户端节点名称']=$node;$initial['服务器 IPv4']=$form.IPv4;$initial['服务器 IPv6（未填写时可直接回车）']=$form.IPv6
        $initial['服务商当前 SSH 端口']=$form.SshPort;$initial['日常管理用户']=$form.Admin
        $initial['服务商初始 root 登录方式']=if($form.Auth -eq 0){'2'}else{'1'}
        $initial['现有服务商私钥文件的完整路径']=$form.KeyPath;$initial['SSH 管理密钥策略']=[string]$form.KeyMode
        $initial['这台 VPS 的部署角色']=[string]$form.Role
    }else{
        $initial['客户端节点基础名称']=$node;$initial['VPS IPv4']=$form.IPv4;$initial['VPS IPv6（没有可留空）']=$form.IPv6
        $initial['当前可用 root SSH 端口']=$form.SshPort;$initial['当前 root SSH 认证方式']=if($form.Auth -eq 0){'1'}else{'2'}
        $initial['当前 root OpenSSH 私钥完整路径']=$form.KeyPath;$initial['纳管后的 SSH 管理密钥']=[string]$form.KeyMode
    }
    Start-VpsGuiTask $mode $script:GuiControls.DeploymentCaption.Text -InitialAnswers $initial
}
function Start-VpsGuiClientAction {
    param([int]$Choice)
    $title='Clash/sing-box 客户端权威配置设计器'
    if($script:GuiState.Request -and $script:GuiState.Request.Title -eq $title){
        [void]$script:GuiState.Request.Respond([string]$Choice);$script:GuiState.Request=$null
        $script:GuiControls.CloseClientWorkspace.Visibility='Collapsed'
        Set-VpsGuiTaskAvailability $true;Show-VpsGuiPage 'WorkflowPage' '客户端配置'
    }else{Start-VpsGuiTask 'ClientConfig' '客户端配置' -InitialAnswers @{$title=[string]$Choice}}
}
function Set-VpsGuiTaskAvailability {
    param([bool]$Busy)
    foreach ($name in @('TaskNew','TaskImport','TaskProtocols','TaskMaintain','TaskResume','TaskClients','TaskNetwork','TaskValidate','InstanceMaintain','InstanceProtocols','InstanceResume','InstanceNetwork','ContinueSelected','StartNewForm','ClientCreate','ClientOpen','ClientFromConfig','ClientValidate','ClientDefaults','ClientRecover','CheckUpdate','ApplyUpdate')) {
        $script:GuiControls[$name].IsEnabled = -not $Busy
    }
    $script:GuiControls.ActiveTask.Visibility = if ($Busy) { 'Visible' } else { 'Collapsed' }
}
function Add-VpsGuiJournal {
    param([string]$Text, [string]$Kind = 'Info')
    $plain = [regex]::Replace($Text, '\x1b\[[0-9;]*m', '').Trim()
    if (-not $plain) { return }
    $line = "[$((Get-Date).ToString('HH:mm:ss'))] $plain"
    $script:GuiState.Journal.Add($line)
    while ($script:GuiState.Journal.Count -gt 600) { $script:GuiState.Journal.RemoveAt(0) }
    $joined = $script:GuiState.Journal -join [Environment]::NewLine
    $script:GuiControls.WorkflowLog.Text = $joined; $script:GuiControls.RecordsLog.Text = $joined
    $script:GuiControls.WorkflowLog.ScrollToEnd()
    if ($Kind -in @('Output','Warning','Error','Info','Step')) {
        $script:GuiState.Context.Add($plain)
        while ($script:GuiState.Context.Count -gt 200) { $script:GuiState.Context.RemoveAt(0) }
    }
    if ($Kind -in @('Warning','Error')) { $script:GuiControls.WorkflowStatus.Text = $plain }
    elseif ($Kind -eq 'Step') { $script:GuiControls.WorkflowStatus.Text = $plain; $script:GuiControls.FooterStatus.Text = $plain }
}
function Start-VpsGuiTask {
    param([string]$Mode, [string]$Title,[hashtable]$InitialAnswers=@{})
    if ($script:GuiState.Session -and $script:GuiState.Session.Running) { return }
    if ($script:GuiState.Session) { $script:GuiState.Session.Dispose() }
    $script:GuiState.Mode = $Mode; $script:GuiState.Title = $Title
    $script:GuiState.Request = $null; $script:GuiState.Context.Clear()
    $script:GuiState.Session = [May.VpsDeploy.Gui.Session]::new()
    $selectedPlan = $script:GuiState.PlanPath
    if ($script:GuiControls.InstanceList.SelectedItem) { $selectedPlan = [string]$script:GuiControls.InstanceList.SelectedItem.Tag }
    if ($Mode -in @('Maintain','Migrate','Resume','TuneNetwork')) {
        if (-not $selectedPlan -or -not (Test-VpsGuiPlanPath $script:GuiState.Root $selectedPlan)) {
            $script:GuiState.PendingTask = @{ Mode=$Mode; Title=$Title }
            $script:GuiControls.ContinueSelected.Visibility = 'Visible'
            $script:GuiControls.ContinueSelected.Content = "选择实例并继续 · $Title"
            $script:GuiControls.NavInstances.IsChecked = $true
            Show-VpsGuiPage 'InstancesPage' '实例'; Update-VpsGuiCatalog
            $script:GuiControls.FooterStatus.Text = '请先选择要管理的实例。'
            return
        }
    }
    $script:GuiState.PendingTask = $null; $script:GuiControls.ContinueSelected.Visibility = 'Collapsed'
    $script:GuiControls.WorkflowStage.Text='配置选项 → 审阅 → 执行'
    $initial=[Collections.Generic.Dictionary[string,string]]::new()
    foreach($pair in $InitialAnswers.GetEnumerator()){$initial[$pair.Key]=[string]$pair.Value}
    $script:GuiState.Session.SetInitialAnswers($initial)
    $script:GuiState.StartedAt=(Get-Date).ToUniversalTime().ToString('o')
    $script:GuiState.Session.StartWorkflow($script:GuiProjectRoot, $Mode, $script:GuiState.Root, $selectedPlan, $script:GuiControls.UpdateProxy.Text)
    $script:GuiControls.WorkflowTitle.Text = $Title
    $targetLabel=''
    if($Mode -in @('New','Import') -and $InitialAnswers.ContainsKey('实例名称')){$targetLabel="$($InitialAnswers['服务商名称']) · $($InitialAnswers['实例名称'])"}
    elseif($Mode -in @('Maintain','Migrate','Resume','TuneNetwork')){
        $targetLabel=[string]($script:GuiState.Catalog|Where-Object PlanPath -eq $selectedPlan|Select-Object -First 1).Label
    }
    $script:GuiControls.WorkflowTarget.Text="当前实例：$targetLabel"
    $script:GuiControls.WorkflowTarget.Visibility=if($targetLabel){'Visible'}else{'Collapsed'}
    $script:GuiControls.WorkflowStatus.Text = '正在准备…'
    $script:GuiControls.WorkflowStage.Visibility=if($Mode -in @('New','Import')){'Visible'}else{'Collapsed'}
    $script:GuiControls.InputCard.Visibility = 'Collapsed'
    $script:GuiControls.CompletedActions.Visibility = 'Collapsed'
    $script:GuiControls.CancelTask.Visibility = 'Visible'
    $script:GuiControls.TaskProgress.Visibility = 'Visible'
    $script:GuiControls.TaskProgress.IsIndeterminate = $true
    $script:GuiControls.SidebarStatus.Text = '任务进行中'
    $script:GuiControls.FooterStatus.Text = $Title
    if ($Mode -notin @('CheckUpdate','ApplyUpdate')) { Show-VpsGuiPage 'WorkflowPage' $Title }
    else { $script:GuiControls.UpdateStatus.Text = $(if ($Mode -eq 'CheckUpdate') { '正在检查…' } else { '正在下载和校验…' }) }
    Set-VpsGuiTaskAvailability $true
}
function Show-VpsGuiInput {
    param([May.VpsDeploy.Gui.InputRequest]$Request)
    $script:GuiState.Request = $Request
    if($Request.Title -match '核对.*摘要'){$script:GuiControls.WorkflowStage.Text='审阅方案 → 确认执行'}
    elseif($Request.Title -match '确认按以上顺序'){$script:GuiControls.WorkflowStage.Text='即将执行 · 最后确认'}
    if($script:GuiState.Mode -eq 'ClientConfig' -and $Request.Title -eq 'Clash/sing-box 客户端权威配置设计器'){
        foreach($name in @('ClientCreate','ClientOpen','ClientFromConfig','ClientValidate','ClientDefaults','ClientRecover')){$script:GuiControls[$name].IsEnabled=$true}
        $script:GuiControls.InputCard.Visibility='Collapsed';$script:GuiControls.CloseClientWorkspace.Visibility='Visible'
        Show-VpsGuiPage 'ClientsPage' '客户端配置';return
    }
    $script:GuiControls.QuestionLabel.Text = $Request.Title
    $script:GuiControls.QuestionContext.Text = $script:GuiState.Context -join [Environment]::NewLine
    $script:GuiState.Context.Clear()
    $script:GuiControls.InputCard.Visibility = 'Visible'
    $script:GuiControls.WorkflowStatus.Text = '等待填写此步骤'
    $script:GuiControls.TaskProgress.IsIndeterminate = $false
    foreach ($name in @('ChoiceList','ChoiceActions','TextInput','SecretInput','PickInputPath','ClearInput')) { $script:GuiControls[$name].Visibility = 'Collapsed' }
    $script:GuiControls.SubmitInput.Visibility='Visible'
    $script:GuiControls.SecretInput.Clear()
    $script:GuiControls.BackInput.Visibility = if ($Request.AllowBack) { 'Visible' } else { 'Collapsed' }
    $script:GuiControls.HelpText.Text = $Request.HelpText
    $script:GuiControls.InputHelp.Visibility = if ($Request.HelpText) { 'Visible' } else { 'Collapsed' }
    if ($Request.Kind -in @('menu','yesno','multiple')) {
        $script:GuiControls.ChoiceList.Items.Clear()
        foreach ($option in $Request.Options) {
            $item = [Windows.Controls.ListBoxItem]::new()
            $label = [Windows.Controls.TextBlock]::new(); $label.Text = $option; $label.TextWrapping = 'Wrap'
            $item.Content = $label; [void]$script:GuiControls.ChoiceList.Items.Add($item)
        }
        $script:GuiControls.ChoiceList.SelectedIndex = $Request.DefaultIndex
        $script:GuiControls.ChoiceList.SelectionMode=if($Request.Kind -eq 'multiple'){'Multiple'}else{'Single'}
        $script:GuiControls.ChoiceList.Visibility = 'Visible'
        $script:GuiControls.InputHint.Text = if($Request.Kind -eq 'multiple'){'点击所需项目，可同时选择多个。'}else{'选择一项，再点击继续。'}
        if($Request.Kind -eq 'multiple'){
            $script:GuiControls.ClearInput.Visibility=if($Request.CanClear){'Visible'}else{'Collapsed'}
            $script:GuiControls.ClearInput.Content='跳过选择'
        }elseif($Request.Kind -eq 'menu' -and $Request.Options.Count -le 12){
            $script:GuiControls.ChoiceActions.Children.Clear()
            for($i=0;$i -lt $Request.Options.Count;$i++){
                $button=[Windows.Controls.Button]::new();$button.Content=$Request.Options[$i];$button.Tag=$i
                $button.HorizontalContentAlignment='Left';$button.Margin='0,0,0,8'
                $button.Add_Click({param($sender,$eventArgs)$script:GuiControls.ChoiceList.SelectedIndex=[int]$sender.Tag;Submit-VpsGuiInput})
                [void]$script:GuiControls.ChoiceActions.Children.Add($button)
            }
            $script:GuiControls.ChoiceActions.Visibility='Visible';$script:GuiControls.ChoiceList.Visibility='Collapsed'
            $script:GuiControls.SubmitInput.Visibility='Collapsed';$script:GuiControls.InputHint.Text='点击要进行的操作。'
        }
    } elseif ($Request.Kind -eq 'secret') {
        $script:GuiControls.SecretInput.Visibility = 'Visible'
        $script:GuiControls.InputHint.Text = '此项使用隐藏输入。'
        [void]$script:GuiControls.SecretInput.Focus()
    } else {
        $script:GuiControls.TextInput.Text = $Request.DefaultValue
        $script:GuiControls.TextInput.Visibility = 'Visible'
        $script:GuiControls.ClearInput.Visibility = if ($Request.CanClear) { 'Visible' } else { 'Collapsed' }
        $script:GuiControls.ClearInput.Content='清空此项'
        $script:GuiControls.InputHint.Text = if ($Request.DefaultValue) { '已填写默认值，可以直接继续或修改。' } else { '填写完成后点击继续。' }
        if ($Request.Title -match '路径|目录|文件') { $script:GuiControls.PickInputPath.Visibility = 'Visible' }
        [void]$script:GuiControls.TextInput.Focus(); $script:GuiControls.TextInput.SelectAll()
    }
    Show-VpsGuiPage 'WorkflowPage' $script:GuiState.Title
}
function Submit-VpsGuiInput {
    $request = $script:GuiState.Request
    if (-not $request -or $request.IsCompleted) { return }
    if ($request.Kind -eq 'secret') {
        $secret = $script:GuiControls.SecretInput.SecurePassword
        if (-not $request.RespondSecret($secret)) { $secret.Dispose() }
        $script:GuiControls.SecretInput.Clear()
    } elseif($request.Kind -eq 'multiple'){
        $indexes=@($script:GuiControls.ChoiceList.SelectedItems|ForEach-Object{$script:GuiControls.ChoiceList.Items.IndexOf($_)+1}|Sort-Object)
        if(-not $indexes.Count -and -not $request.CanClear){return}
        [void]$request.Respond($indexes -join ',')
    } elseif ($request.Kind -in @('menu','yesno')) {
        $index = $script:GuiControls.ChoiceList.SelectedIndex
        if ($index -lt 0) { return }
        $value = if ($request.Kind -eq 'yesno') { @('y','n')[$index] } else { [string]($index + 1) }
        [void]$request.Respond($value)
    } else { [void]$request.Respond($script:GuiControls.TextInput.Text) }
    $script:GuiState.Request = $null
    $script:GuiControls.InputCard.Visibility = 'Collapsed'
    $script:GuiControls.WorkflowStatus.Text = '正在继续…'
    $script:GuiControls.TaskProgress.IsIndeterminate = $true
}
function Receive-VpsGuiEvents {
    $session = $script:GuiState.Session
    if (-not $session) { return }
    $notice = $null; $count = 0
    while ($count -lt 100 -and $session.Notices.TryDequeue([ref]$notice)) {
        if ($notice.Kind -eq 'Progress') {
            $script:GuiControls.FooterStatus.Text = $notice.Text
            if ($notice.Percent -ge 0) { $script:GuiControls.TaskProgress.IsIndeterminate = $false; $script:GuiControls.TaskProgress.Value = $notice.Percent }
        } else { Add-VpsGuiJournal $notice.Text $notice.Kind }
        $count++
    }
    $request = $null
    if (-not $script:GuiState.Request -and $session.Requests.TryDequeue([ref]$request)) {
        if (-not $request.IsCompleted) { Show-VpsGuiInput $request }
    }
    if ($session.Running -and $session.Poll()) {
        $script:GuiControls.InputCard.Visibility = 'Collapsed'
        $script:GuiControls.TaskProgress.Visibility = 'Collapsed'
        $script:GuiControls.CancelTask.Visibility = 'Collapsed'
        $script:GuiControls.CompletedActions.Visibility = 'Visible'
        Set-VpsGuiTaskAvailability $false
        $script:GuiControls.CloseClientWorkspace.Visibility='Collapsed'
        $message = if ($session.Failed) { '操作未完成，请查看执行详情。' } elseif ($session.CancelRequested -or $session.NavigatedBack) { '当前任务已取消，已完成的操作和归档保留。' } elseif ($session.HasWarnings) { '当前操作已结束，请查看详情中的提示。' } else { '当前操作已完成。' }
        $script:GuiControls.WorkflowStatus.Text = $message; $script:GuiControls.FooterStatus.Text = $message
        $script:GuiControls.SidebarStatus.Text = '准备就绪'
        if ($session.Failed -or $session.HasWarnings) { $script:GuiControls.TaskDetails.IsExpanded = $true }
        Update-VpsGuiCatalog
        Save-VpsGuiTaskRecord $session
        if ($script:GuiState.Mode -eq 'CheckUpdate') {
            if ($session.Failed) { $script:GuiControls.UpdateStatus.Text = '检查失败，请稍后重试或填写网络代理。' }
            elseif ($session.Result.Count) {
                $info = $session.Result[$session.Result.Count - 1].BaseObject
                $script:GuiState.Update = $info
                $script:GuiControls.UpdateStatus.Text = if ($info.Available) { "可更新至 $($info.Version)" } else { '当前已是最新正式版本。' }
                $script:GuiControls.ReleaseNotesText.Text = $info.Notes
                $script:GuiControls.ReleaseNotes.Visibility = if ($info.Available) { 'Visible' } else { 'Collapsed' }
                $script:GuiControls.ApplyUpdate.Visibility = if ($info.Available) { 'Visible' } else { 'Collapsed' }
            }
        }
        if ($script:GuiState.Mode -eq 'ApplyUpdate') {
            if ($session.Failed) { $script:GuiControls.UpdateStatus.Text = '更新未开始，当前版本保留。请查看执行记录。' }
            elseif ($session.Result.Count -and $session.Result[$session.Result.Count - 1].BaseObject.RestartRequired) {
                $script:GuiState.Closing = $true; $script:GuiWindow.Close()
            }
        }
        if ($script:GuiState.Closing -and -not $session.Running) { $script:GuiWindow.Close() }
    }
}
$script:GuiTimer.Add_Tick({ Receive-VpsGuiEvents })
$script:GuiControls.SubmitInput.Add_Click({ Submit-VpsGuiInput })
$script:GuiControls.TextInput.Add_KeyDown({ param($sender,$eventArgs) if ($eventArgs.Key -eq 'Return') { Submit-VpsGuiInput; $eventArgs.Handled = $true } })
$script:GuiControls.SecretInput.Add_KeyDown({ param($sender,$eventArgs) if ($eventArgs.Key -eq 'Return') { Submit-VpsGuiInput; $eventArgs.Handled = $true } })
$script:GuiControls.BackInput.Add_Click({
    if ($script:GuiState.Request) {
        $request = $script:GuiState.Request
        if ($request.Kind -eq 'secret') {
            $back = [Security.SecureString]::new(); $back.AppendChar('0'); [void]$request.RespondSecret($back)
        } else { [void]$request.Respond($request.BackValue) }
        $script:GuiControls.SecretInput.Clear(); $script:GuiState.Request = $null; $script:GuiControls.InputCard.Visibility = 'Collapsed'
    }
})
$script:GuiControls.ClearInput.Add_Click({ if ($script:GuiState.Request) { [void]$script:GuiState.Request.Respond($(if($script:GuiState.Request.Kind -eq 'multiple'){''}else{'!empty'})); $script:GuiState.Request = $null; $script:GuiControls.InputCard.Visibility = 'Collapsed' } })
$script:GuiControls.CancelTask.Add_Click({ if ($script:GuiState.Session) { $script:GuiState.Session.Cancel(); $script:GuiState.Request = $null; $script:GuiControls.SecretInput.Clear(); $script:GuiControls.InputCard.Visibility = 'Collapsed' } })
$script:GuiControls.ReturnOverview.Add_Click({ $script:GuiControls.NavOverview.IsChecked = $true; Show-VpsGuiPage 'OverviewPage' '概述'; Update-VpsGuiCatalog })
$script:GuiControls.NavOverview.Add_Click({ Show-VpsGuiPage 'OverviewPage' '概述' })
$script:GuiControls.NavInstances.Add_Click({ Show-VpsGuiPage 'InstancesPage' '实例'; Update-VpsGuiCatalog })
$script:GuiControls.NavDeploy.Add_Click({ Show-VpsGuiDeploymentForm })
$script:GuiControls.NavClients.Add_Click({ Show-VpsGuiPage 'ClientsPage' '客户端配置' })
$script:GuiControls.NavRecords.Add_Click({ Show-VpsGuiPage 'RecordsPage' '记录' })
$script:GuiControls.NavSettings.Add_Click({ Show-VpsGuiPage 'SettingsPage' '设置' })
$script:GuiControls.ActiveTask.Add_Click({
    if($script:GuiState.Request -and $script:GuiState.Request.Title -eq 'Clash/sing-box 客户端权威配置设计器'){Show-VpsGuiPage 'ClientsPage' '客户端配置'}
    else{Show-VpsGuiPage 'WorkflowPage' $script:GuiState.Title}
})
$script:GuiControls.ContinueSelected.Add_Click({
    if ($script:GuiState.PendingTask) { Start-VpsGuiTask $script:GuiState.PendingTask.Mode $script:GuiState.PendingTask.Title }
})
$script:GuiControls.TaskNew.Add_Click({ Show-VpsGuiDeploymentForm 'New' })
$script:GuiControls.TaskImport.Add_Click({ Show-VpsGuiDeploymentForm 'Import' })
$script:GuiControls.TaskProtocols.Add_Click({ Start-VpsGuiTask 'Migrate' '代理协议' })
$script:GuiControls.TaskMaintain.Add_Click({ Start-VpsGuiTask 'Maintain' '运维中心' })
$script:GuiControls.TaskResume.Add_Click({ Start-VpsGuiTask 'Resume' '继续未完成部署' })
$script:GuiControls.TaskClients.Add_Click({ $script:GuiControls.NavClients.IsChecked=$true;Show-VpsGuiPage 'ClientsPage' '客户端配置' })
$script:GuiControls.TaskNetwork.Add_Click({ Start-VpsGuiTask 'TuneNetwork' '调整网络参数' })
$script:GuiControls.TaskValidate.Add_Click({ Start-VpsGuiTask 'ValidateProject' '本地自检' })
$script:GuiControls.InstanceMaintain.Add_Click({ Start-VpsGuiTask 'Maintain' '运维中心' })
$script:GuiControls.InstanceProtocols.Add_Click({ Start-VpsGuiTask 'Migrate' '代理协议' })
$script:GuiControls.InstanceResume.Add_Click({ Start-VpsGuiTask 'Resume' '继续未完成部署' })
$script:GuiControls.InstanceNetwork.Add_Click({ Start-VpsGuiTask 'TuneNetwork' '网络参数' })
$script:GuiControls.InstanceList.Add_SelectionChanged({Show-VpsGuiInstanceDetails})
$script:GuiControls.StartNewForm.Add_Click({Submit-VpsGuiDeploymentForm})
$script:GuiControls.NewAuthType.Add_SelectionChanged({
    $script:GuiControls.NewKeyFields.Visibility=if($script:GuiControls.NewAuthType.SelectedIndex -eq 0){'Visible'}else{'Collapsed'}
    $script:GuiControls.NewAuthNote.Visibility=if($script:GuiControls.NewAuthType.SelectedIndex -eq 0){'Collapsed'}else{'Visible'}
})
$script:GuiControls.BrowseNewKey.Add_Click({$dialog=[Microsoft.Win32.OpenFileDialog]::new();$dialog.Title='选择现有 OpenSSH 私钥';if($dialog.ShowDialog($script:GuiWindow)){$script:GuiControls.NewKeyPath.Text=$dialog.FileName}})
$script:GuiControls.ClientCreate.Add_Click({Start-VpsGuiClientAction 1})
$script:GuiControls.ClientOpen.Add_Click({Start-VpsGuiClientAction 2})
$script:GuiControls.ClientFromConfig.Add_Click({Start-VpsGuiClientAction 3})
$script:GuiControls.ClientValidate.Add_Click({Start-VpsGuiClientAction 4})
$script:GuiControls.ClientDefaults.Add_Click({Start-VpsGuiClientAction 5})
$script:GuiControls.ClientRecover.Add_Click({Start-VpsGuiClientAction 8})
$script:GuiControls.CloseClientWorkspace.Add_Click({if($script:GuiState.Session){$script:GuiState.Session.Cancel();$script:GuiState.Request=$null}})
$script:GuiControls.CheckUpdate.Add_Click({ Start-VpsGuiTask 'CheckUpdate' '检查应用更新' })
$script:GuiControls.ApplyUpdate.Add_Click({
    if ([Windows.MessageBox]::Show($script:GuiWindow,'将下载并校验新版，关闭当前窗口后更新并重新启动。是否继续？','更新应用','YesNo','Question','No') -eq 'Yes') {
        Start-VpsGuiTask 'ApplyUpdate' '更新应用'
    }
})
$script:GuiControls.AutoUpdateCheck.Add_Click({ $script:GuiPreferences.automatic_update_check = [bool]$script:GuiControls.AutoUpdateCheck.IsChecked; Save-VpsGuiPreferences })
$script:GuiControls.ScaleNormal.Add_Click({ $script:GuiPreferences.scale = 1.0; $script:GuiWindow.Content.LayoutTransform=[Windows.Media.ScaleTransform]::new(1,1); Save-VpsGuiPreferences })
$script:GuiControls.ScaleLarge.Add_Click({ $script:GuiPreferences.scale = 1.12; $script:GuiWindow.Content.LayoutTransform=[Windows.Media.ScaleTransform]::new(1.12,1.12); Save-VpsGuiPreferences })
$script:GuiControls.PickInputPath.Add_Click({
    if (-not $script:GuiState.Request) { return }
    if ($script:GuiState.Request.Title -match '目录|根路径') { $dialog = [Microsoft.Win32.OpenFolderDialog]::new(); $dialog.Title = '选择目录'; if ($dialog.ShowDialog($script:GuiWindow)) { $script:GuiControls.TextInput.Text = $dialog.FolderName } }
    else { $dialog = [Microsoft.Win32.OpenFileDialog]::new(); $dialog.Title = '选择文件'; if ($dialog.ShowDialog($script:GuiWindow)) { $script:GuiControls.TextInput.Text = $dialog.FileName } }
})
$script:GuiControls.MinimizeWindow.Add_Click({ $script:GuiWindow.WindowState = 'Minimized' })
$script:GuiControls.MaximizeWindow.Add_Click({ $script:GuiWindow.WindowState = if ($script:GuiWindow.WindowState -eq 'Maximized') { 'Normal' } else { 'Maximized' } })
$script:GuiControls.CloseWindow.Add_Click({ $script:GuiWindow.Close() })
$script:GuiWindow.Add_Closing({
    param($sender,$eventArgs)
    if ($script:GuiState.Session -and $script:GuiState.Session.Running) {
        $eventArgs.Cancel = $true
        $script:GuiState.Closing = $true
        $script:GuiState.Session.Cancel()
        $script:GuiControls.FooterStatus.Text = '等待当前操作到达可返回的位置后关闭。'
    }
})
Update-VpsGuiCatalog
Update-VpsGuiHistory
if ($PreviewPath) {
    $previewRoot = $script:GuiWindow.Content
    $previewRoot.Measure([Windows.Size]::new(1180,820))
    $previewRoot.Arrange([Windows.Rect]::new(0,0,1180,820))
    $previewRoot.UpdateLayout()
    $bitmap = [Windows.Media.Imaging.RenderTargetBitmap]::new(1180,820,96,96,[Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($previewRoot)
    $encoder = [Windows.Media.Imaging.PngBitmapEncoder]::new(); $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream = [IO.File]::Create($PreviewPath); try { $encoder.Save($stream) } finally { $stream.Dispose() }
    return
}
if ($NoShow) { return }
$mutexName='Local\mxh-vps-deploy-'+[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($script:GuiProjectRoot.ToLowerInvariant()))).Substring(0,24)
$instanceMutex=[Threading.Mutex]::new($false,$mutexName)
$mutexHeld=$false
try {$mutexHeld=$instanceMutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$mutexHeld=$true}
if(-not $mutexHeld){[void][Windows.MessageBox]::Show('此目录中的应用已在运行，请使用已有窗口。','May VPS Deploy','OK','Information');$instanceMutex.Dispose();return}
$script:GuiTimer.Start()
$script:GuiWindow.Add_ContentRendered({
    if ($script:GuiPreferences.automatic_update_check) { Start-VpsGuiTask 'CheckUpdate' '检查应用更新' }
})
try { [void]$script:GuiWindow.ShowDialog() }
finally {
    $script:GuiTimer.Stop()
    if ($script:GuiState.Session -and -not $script:GuiState.Session.Running) { $script:GuiState.Session.Dispose() }
    if($mutexHeld){$instanceMutex.ReleaseMutex()};$instanceMutex.Dispose()
}
