#requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ProjectRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $IsWindows) { throw 'GUI behavior checks require Windows.' }
$passed=0
function Assert-Gui { param([bool]$Condition,[string]$Message) if(-not $Condition){throw "GUI ASSERT: $Message"}; $script:passed++ }
function Wait-GuiRequest {
    param([May.VpsDeploy.Gui.Session]$Session)
    $watch=[Diagnostics.Stopwatch]::StartNew(); $request=$null
    while($watch.ElapsedMilliseconds -lt 10000) {
        if($Session.Requests.TryDequeue([ref]$request)){return $request}
        if($Session.Poll()){throw "Worker ended before expected input: $($Session.ErrorMessage)"}
        [Threading.Thread]::Sleep(10)
    }
    $notice=$null;$reason='';while($Session.Notices.TryDequeue([ref]$notice)){$reason+=$notice.Text}
    throw "GUI input timed out. $reason"
}
function Wait-GuiDone {
    param([May.VpsDeploy.Gui.Session]$Session,[switch]$Ui)
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.ElapsedMilliseconds -lt 10000) {
        if($Ui){Receive-VpsGuiEvents}else{[void]$Session.Poll()}
        if(-not $Session.Running){if($Ui){Receive-VpsGuiEvents};return}
        [Threading.Thread]::Sleep(10)
    }
    throw 'GUI task timed out.'
}
$fixture=Join-Path $ProjectRoot ('.test-output/gui-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture)|Out-Null
try {
    . (Join-Path $ProjectRoot 'Start-VPSDeploy.Gui.ps1') -NoShow -InstanceRoot $fixture
    $paths=Get-VpsGuiDataPaths $ProjectRoot
    Assert-Gui ($paths.Instances -eq (Join-Path $ProjectRoot 'private/instances')) 'desktop archives are application-local'
    Assert-Gui ($paths.Settings -eq (Join-Path $ProjectRoot 'private/gui-settings.json')) 'preferences share private data boundary'
    Assert-Gui (-not $GuiControls.ContainsKey('BrowseInstances') -and -not $GuiControls.ContainsKey('BrowsePlan')) 'no legacy archive import or external root chooser'
    Assert-Gui ($GuiWindow.FontFamily.FamilyMaps.Count -eq 2) 'consistent Latin and Chinese font mapping'
    Assert-Gui (-not $GuiControls.AutoUpdateCheck.IsChecked) 'update checks opt in'
    $session=[May.VpsDeploy.Gui.Session]::new()
    $worker=@'
param($Root,$Session)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $Root 'src/VpsDeploy.Core.psm1') -Force
Set-VpsInteractionSession $Session
$module=Get-Module VpsDeploy.Core
& $module {
$text=Read-VpsText 'text' -Default 'default' -Validate {param($v)$v -eq 'default'}
$zero=Read-VpsText 'zero' -AllowBack -ZeroIsValue
$empty=Read-VpsText 'clear' -Default 'old' -AllowEmpty -AllowClear
$menu=Read-VpsMenu 'menu' @('first','second') 2 -AllowBack
$yes=Read-VpsYesNo 'yesno' $false -AllowBack
$matched=(Read-MxhSecretText 'secret') -eq 'fixture-hidden-only'
[pscustomobject]@{Text=$text;Zero=$zero;Empty=$empty;Menu=$menu;Yes=$yes;SecretMatched=$matched}
}
'@
    $bindings=[Collections.Generic.Dictionary[string,object]]::new();$bindings['Root']=$ProjectRoot;$bindings['Session']=$session
    $session.StartScript($worker,$bindings)
    $q=Wait-GuiRequest $session; Assert-Gui ($q.DefaultValue -eq 'default') 'default exposed as field'; [void]$q.Respond('invalid')
    $q=Wait-GuiRequest $session; [void]$q.Respond('')
    $q=Wait-GuiRequest $session; Assert-Gui ($q.BackValue -eq '/back') 'numeric zero keeps explicit back'; [void]$q.Respond('0')
    $q=Wait-GuiRequest $session; Assert-Gui $q.CanClear 'clear is explicit'; [void]$q.Respond('!empty')
    $q=Wait-GuiRequest $session; Assert-Gui ($q.DefaultIndex -eq 1 -and $q.Options.Count -eq 2) 'real choices and default'; [void]$q.Respond('2')
    $q=Wait-GuiRequest $session; Assert-Gui ($q.Kind -eq 'yesno' -and $q.DefaultIndex -eq 1) 'confirmation respects backend default'; [void]$q.Respond('n')
    $q=Wait-GuiRequest $session; Assert-Gui ($q.Kind -eq 'secret') 'secret uses protected input'; [void]$q.RespondSecret(('fixture-hidden-only'|ConvertTo-SecureString -AsPlainText -Force))
    Wait-GuiDone $session
    Assert-Gui (-not $session.Failed) 'worker completes without terminal'
    $result=$session.Result[0]
    Assert-Gui ($result.Text -eq 'default' -and $result.Zero -eq '0' -and $result.Empty -eq '' -and $result.Menu -eq 2 -and -not $result.Yes -and $result.SecretMatched) 'backend parsing is preserved'
    $notice=$null;$log=''
    while($session.Notices.TryDequeue([ref]$notice)){$log+=$notice.Text}
    Assert-Gui ($log -notmatch 'fixture-hidden-only' -and $session.HasWarnings) 'validation warning preserved without secret echo'
    $session.Dispose()

    $session=[May.VpsDeploy.Gui.Session]::new()
    $cancelModules=@'
param($Root,$Session)
Import-Module (Join-Path $Root 'src/VpsDeploy.Core.psm1') -Force
Set-VpsInteractionSession $Session
& (Get-Module VpsDeploy.Core) {
    param($Root,$Session)
    function Get-VpsModules {
        @(@{Id='first';Name='first';Order=1;Requires=@();Roles=@('AuditOnly');IsEnabled={param($c)$true};Invoke={param($c)$c.Session.Cancel()}},
          @{Id='second';Name='second';Order=2;Requires=@('first');Roles=@('AuditOnly');IsEnabled={param($c)$true};Invoke={throw 'Second module must never start.'}})
    }
    function Set-VpsModuleState {param($Context,$Id,$Status,$Message)$Context.State.Modules[$Id]=@{Status=$Status}}
    $context=[pscustomobject]@{ProjectRoot=$Root;Plan=@{Role='AuditOnly'};State=@{Modules=@{}};Session=$Session;DryRun=$false;NonInteractive=$true}
    try {Invoke-VpsModulePipeline $context}catch{if(-not(Test-VpsNavigationError $_)){throw}}
    [pscustomobject]@{Count=$context.State.Modules.Count;Status=$context.State.Modules.first.Status}
} $Root $Session
'@
    $bindings=[Collections.Generic.Dictionary[string,object]]::new();$bindings['Root']=$ProjectRoot;$bindings['Session']=$session
    $session.StartScript($cancelModules,$bindings);Wait-GuiDone $session
    if($session.Failed){throw "Module cancellation fixture failed: $($session.ErrorMessage)"}
    Assert-Gui (-not $session.Failed -and $session.Result[0].Count -eq 1 -and $session.Result[0].Status -eq 'Success') 'cancel stops between modules after persisting completed step'
    $session.Dispose()

    $GuiControls.TaskMaintain.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    Assert-Gui ($GuiControls.InstancesPage.Visibility -eq 'Visible' -and $GuiState.PendingTask.Mode -eq 'Maintain') 'instance chosen before maintenance'
    Assert-Gui (-not $GuiState.Session.Running) 'no remote job from empty selection'
    $GuiControls.TaskNew.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    Assert-Gui ($GuiControls.DeploymentPage.Visibility -eq 'Visible' -and -not $GuiState.Session.Running) 'deployment opens a form without starting a worker'
    $GuiControls.StartNewForm.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    Assert-Gui ($GuiControls.NewFormError.Visibility -eq 'Visible' -and -not $GuiState.Session.Running) 'form validates inline before configuration'
    $GuiControls.NewProvider.Text='FixtureProvider';$GuiControls.NewInstance.Text='FixtureInstance'
    $GuiControls.NewIPv4.Text='192.0.2.15';$GuiControls.NewAuthType.SelectedIndex=1;$GuiControls.NewRole.SelectedIndex=4
    $GuiControls.StartNewForm.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not $GuiState.Request -and $watch.ElapsedMilliseconds -lt 10000){Receive-VpsGuiEvents;[Threading.Thread]::Sleep(10)}
    Assert-Gui ($null -ne $GuiState.Request -and $GuiState.Session.Running) 'real workflow uses GUI input broker'
    Assert-Gui (-not $GuiControls.TaskNew.IsEnabled -and $GuiControls.ActiveTask.Visibility -eq 'Visible') 'one active task with return entry'
    Assert-Gui ($GuiState.Request.Title -notmatch '私有归档根目录') 'desktop skips CLI archive root question'
    Assert-Gui ($GuiState.Request.Title -notmatch '服务商名称|实例名称|服务器 IPv4|登录方式|部署角色') 'form values go through backend validation without CLI input sequence'
    $GuiControls.NavSettings.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    Assert-Gui ($GuiControls.SettingsPage.Visibility -eq 'Visible') 'navigation remains responsive during worker input'
    $GuiControls.ActiveTask.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    Assert-Gui ($GuiControls.WorkflowPage.Visibility -eq 'Visible') 'returns to current task'
    $GuiControls.CancelTask.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    Wait-GuiDone $GuiState.Session -Ui
    Assert-Gui (-not $GuiState.Session.Failed -and $GuiControls.WorkflowStatus.Text -match '取消') 'cancel reports cancellation rather than success'
    Assert-Gui (@(Get-ChildItem -LiteralPath $fixture -File -Recurse|Where-Object Name -like 'deployment-*').Count -eq 0) 'cancel before confirmation creates no archive or server job'
    $history=Get-Content -Raw -LiteralPath (Join-Path $fixture 'task-history.json')|ConvertFrom-Json -AsHashtable
    Assert-Gui ($history.schema_version -eq 1 -and @($history.tasks)[-1].Status -eq 'Canceled') 'desktop task outcome is persisted separately from sensitive logs'
    Assert-Gui ($GuiControls.TaskNew.IsEnabled) 'task controls restored after cancel'

    $session=[May.VpsDeploy.Gui.Session]::new()
    $multiple=@'
param($Root,$Session)
Import-Module (Join-Path $Root 'src/VpsDeploy.Core.psm1') -Force
Set-VpsInteractionSession $Session
& (Get-Module VpsDeploy.Core) { @(Read-MxhIndexSelection 'legacy numbering' 3 -Options @('Alpha','Beta','Gamma')) -join ',' }
'@
    $bindings=[Collections.Generic.Dictionary[string,object]]::new();$bindings['Root']=$ProjectRoot;$bindings['Session']=$session
    $session.StartScript($multiple,$bindings);$q=Wait-GuiRequest $session
    Assert-Gui ($q.Kind -eq 'multiple' -and $q.Options.Count -eq 3) 'node multi-selection is graphical'
    [void]$q.Respond('1,3');Wait-GuiDone $session
    Assert-Gui (-not $session.Failed -and $session.Result[0].ToString() -eq '0,2') 'multi-select preserves exact backend indexes'
    $session.Dispose()

    $session=[May.VpsDeploy.Gui.Session]::new()
    $broker=[May.VpsDeploy.Gui.SshSecretBroker]::new($session)
    try {
        $helper=& $GuiModule {param($Root)Get-VpsGuiAskPassPath $Root} $ProjectRoot
        $start=[Diagnostics.ProcessStartInfo]::new($helper);$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $start.Environment['MXH_VPS_GUI_ASKPASS_PIPE']=$broker.PipeName;$start.ArgumentList.Add('fixture SSH password')
        $child=[Diagnostics.Process]::Start($start)
        try {
            try{$q=Wait-GuiRequest $session}catch{if($child.HasExited){throw ("Credential helper exited: "+$child.ExitCode+' '+$child.StandardError.ReadToEnd())};throw}
            Assert-Gui ($q.Kind -eq 'secret') 'OpenSSH helper requests a GUI credential'
            [void]$q.RespondSecret(('fixture-hidden-only'|ConvertTo-SecureString -AsPlainText -Force))
            Assert-Gui ($child.WaitForExit(10000) -and $child.ExitCode -eq 0) 'askpass helper completes'
            Assert-Gui ($child.StandardOutput.ReadToEnd().Trim() -eq 'fixture-hidden-only') 'credential passed only through in-memory pipe'
            $notice=$null;$log='';while($session.Notices.TryDequeue([ref]$notice)){$log+=$notice.Text}
            Assert-Gui ($log -notmatch 'fixture-hidden-only') 'SSH credential never enters GUI log'
        }finally{$child.Dispose()}
    }finally{$broker.Dispose();$session.Dispose()}

    $session=[May.VpsDeploy.Gui.Session]::new()
    $saveCanceledDraft=@'
param($Root,$Fixture,$Session)
Import-Module (Join-Path $Root 'src/VpsDeploy.Core.psm1') -Force
Set-VpsInteractionSession $Session
& (Get-Module VpsDeploy.Core) {
    param($Fixture)
    $scheme=@{Id=[guid]::NewGuid().ToString('N');Name='GUI cancellation fixture';Entries=@();Dirty=$true;Candidate=$null;Secret='fixture-hidden-only'}
    try{Invoke-MxhClientWorkbench $Fixture $Fixture $scheme}catch{if(-not(Test-VpsNavigationError $_)){throw}}
    $file=Join-Path $Fixture ('private/client-schemes/'+$scheme.Id+'.private.json')
    $text=Get-Content -Raw -LiteralPath $file
    [pscustomobject]@{Saved=(Test-Path $file);Encrypted=($text -notmatch 'fixture-hidden-only');Dirty=$scheme.Dirty}
} $Fixture
'@
    $bindings=[Collections.Generic.Dictionary[string,object]]::new();$bindings['Root']=$ProjectRoot;$bindings['Fixture']=$fixture;$bindings['Session']=$session
    $session.Cancel();$session.StartScript($saveCanceledDraft,$bindings);Wait-GuiDone $session
    Assert-Gui (-not $session.Failed -and $session.Result[0].Saved -and $session.Result[0].Encrypted -and -not $session.Result[0].Dirty) 'desktop cancellation saves encrypted dirty draft'
    $session.Dispose()

    $archive=Join-Path $fixture 'FixtureProvider/FixtureInstance/May-VPS-Deploy'
    [IO.Directory]::CreateDirectory($archive)|Out-Null
    $plan=Join-Path $archive 'deployment-plan.json'
    @{Provider='FixtureProvider';Instance='FixtureInstance';Role='AuditOnly';Paths=@{Archive=$archive;InstanceDirectory=(Split-Path -Parent $archive);KeyDirectory=(Join-Path $archive 'ssh')}}|ConvertTo-Json -Depth 5|Set-Content $plan
    Assert-Gui (Test-VpsGuiPlanPath $fixture $plan) 'canonical application archive accepted'
    Assert-Gui (-not (Test-VpsGuiPlanPath (Join-Path $fixture 'other') $plan)) 'outside archive rejected'
    Update-VpsGuiCatalog
    Assert-Gui ($GuiControls.InstanceList.Items.Count -eq 1) 'catalog shows current local plan'
    $GuiState.Session.Dispose();$GuiState.Session=[May.VpsDeploy.Gui.Session]::new()
    $GuiState.Mode='New'
    $GuiState.Session.StartScript("throw 'fixture failure'",[Collections.Generic.Dictionary[string,object]]::new())
    Wait-GuiDone $GuiState.Session -Ui
    Assert-Gui ($GuiState.Session.Failed -and $GuiControls.TaskDetails.IsExpanded) 'failure opens details'
    Assert-Gui ($GuiControls.FooterStatus.Text -match '未完成') 'failure is never displayed as success'
    $rootMenu=[May.VpsDeploy.Gui.InputRequest]::new();$rootMenu.Title='Clash/sing-box 客户端权威配置设计器';$rootMenu.Kind='menu';$rootMenu.Options=@('create','open')
    $GuiState.Mode='ClientConfig';Show-VpsGuiInput $rootMenu
    Assert-Gui ($GuiControls.ClientsPage.Visibility -eq 'Visible' -and $GuiControls.InputCard.Visibility -eq 'Collapsed') 'client root uses desktop page without stale workflow input'
    Show-VpsGuiPage 'OverviewPage' '概述'
    $GuiControls.ActiveTask.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    Assert-Gui ($GuiControls.ClientsPage.Visibility -eq 'Visible') 'return to active client root restores correct actions'
    $rootMenu.Cancel();$GuiState.Request=$null
    $GuiState.Session.Dispose();$GuiState.Session=$null
    Write-Host "GUI behavior passed: $passed assertions" -ForegroundColor Green
} finally {
    if($GuiState.Session -and $GuiState.Session.Running){$GuiState.Session.Cancel();Wait-GuiDone $GuiState.Session}
    if($GuiState.Session){$GuiState.Session.Dispose()}
    $prefix=[IO.Path]::GetFullPath((Join-Path $ProjectRoot '.test-output'))+[IO.Path]::DirectorySeparatorChar
    if(-not [IO.Path]::GetFullPath($fixture).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe GUI fixture cleanup.'}
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
