using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Automation;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow : Window, IUserInteraction
{
    private readonly AppPaths paths;
    private readonly ArchiveStore store;
    private readonly TaskCoordinator coordinator;
    private readonly ClientWorkbench workbench;
    private readonly ClientRouteDiagnostics clientDiagnostics;
    private readonly Dictionary<string, Button> navigation = new();
    private readonly Grid shell = new();
    private readonly Dictionary<Button, UIElement> disclosures = new();
    private readonly StackPanel page = new() { Spacing = 20, MaxWidth = 1120, HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly UserControl pageHost = new();
    private readonly UserControl pageAction = new();
    private readonly TextBlock heading = new() { FontSize = 27, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold };
    private readonly TextBlock caption = new() { FontSize = 13, Foreground = Brush(Paint.Muted), TextWrapping = TextWrapping.Wrap };
    private readonly InlineNotice notice = new();
    private readonly TextBlock taskText = new() { Text = "就绪", FontSize = 13, Foreground = Brush(Paint.Muted), TextWrapping = TextWrapping.Wrap };
    private readonly TransferProgressBar taskProgress = new() { Name = "TaskProgress", Height = 4, IsIndeterminate = false, Foreground = Brush(Paint.Accent), Background = Brush(Paint.Button), Visibility = Visibility.Collapsed };
    private readonly Button cancel = new() { Content = "取消任务", Visibility = Visibility.Collapsed };
    private readonly SemaphoreSlim dialogs = new(1);
    private readonly JsonObject settings;
    private readonly JsonObject deploymentForm = new() { ["Provider"] = "", ["Instance"] = "", ["NodeName"] = "", ["SshPort"] = 22, ["Role"] = "RealityEntry" };
    private JsonObject? scheme;
    private string? selectedInstance;
    private CancellationTokenSource? taskCancellation;
    private bool closing;
    private bool updateTask;
    private string currentPage = "overview";
    private readonly string[] launchArguments;

    public MainWindow(AppPaths paths, string[] arguments, BackgroundTestSession? session = null)
    {
        this.paths = paths; launchArguments = arguments; testSession = session; store = new(paths, new WindowsSecretProtector());
        var assets = new ValidationAssets(paths, "windows-amd64"); var tools = new ExternalToolRunner();
        IRemoteSessionFactory remote = new SshSessionFactory(store); if (session != null) remote = session.Restrict(remote);
        coordinator = new(store, new WorkflowEngine(store, remote, new ManagedKeys(new WindowsManagedKeyAccess()), this, new ProtocolValidation(assets, tools, store), new NetworkMeasurement(assets, tools), new TcpForwardValidation(store, new ClientRouteDiagnostics(assets, tools)), new UdpForwardValidation(store, assets, tools), new MonitorReadClient(), new TcpChainValidation(new ClientRouteDiagnostics(assets, tools)), new InboundValidation(store, new ClientRouteDiagnostics(assets, tools))));
        workbench = new(store, tools, assets, paths.Resolve("runtime/python/python.exe"));
        clientDiagnostics = new(assets, tools);
        var preference = paths.Resolve("private/desktop-settings.json"); settings = File.Exists(preference) ? ArchiveStore.ReadJson(preference) : new JsonObject { ["AutoCheckUpdates"] = false, ["UpdateProxy"] = "http://127.0.0.1:2080" };
        fonts = new(paths);
        DesktopTypography.Load(settings); DesktopTypography.Mark(heading, TypeRole.Title, 27); DesktopTypography.Mark(caption, TypeRole.Note, 13); DesktopTypography.Mark(taskText, TypeRole.Note, 13);
        try { SetFont(settings.Text("FontId", "Route")); }
        catch (OperationException) { SetFont("Route"); fontFallback = true; }
        Title = "May VPS Deploy"; ExtendsContentIntoTitleBar = true;
        AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "assets", "gui", "app.ico"));
        AppWindow.TitleBar.ButtonForegroundColor = ColorHelper.FromArgb(255, 230, 233, 238); AppWindow.TitleBar.ButtonBackgroundColor = ColorHelper.FromArgb(0, 0, 0, 0); AppWindow.TitleBar.ButtonInactiveBackgroundColor = ColorHelper.FromArgb(0, 0, 0, 0);
        Application.Current.Resources["ContentDialogMaxWidth"] = 760d; Application.Current.Resources["ContentDialogMinWidth"] = 400d; Application.Current.Resources["ContentDialogCornerRadius"] = new CornerRadius(12);
        Application.Current.Resources["ContentControlThemeFontFamily"] = InterfaceFont;
        var root = new UserControl { FontFamily = InterfaceFont, FontSize = 14, RequestedTheme = ElementTheme.Dark, Background = Brush(Paint.Canvas), Content = shell }; Content = root;
        shell.Background = Brush(Paint.Canvas); shell.RowDefinitions.Add(new() { Height = new GridLength(40) }); shell.RowDefinitions.Add(new() { Height = new GridLength(1, GridUnitType.Star) }); shell.RowDefinitions.Add(new() { Height = GridLength.Auto });
        var title = new Grid { Background = Brush(Paint.Title), Margin = new Thickness(20, 0, 145, 0) }; title.Children.Add(new TextBlock { Text = "May VPS Deploy", VerticalAlignment = VerticalAlignment.Center, FontSize = 13, Foreground = Brush(Paint.Muted) }); shell.Children.Add(title); SetTitleBar(title);
        var body = new Grid(); body.ColumnDefinitions.Add(new() { Width = new GridLength(220) }); body.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        var sidebar = new StackPanel { Padding = new Thickness(14, 22, 14, 18), Spacing = 5 };
        sidebar.Children.Add(new StackPanel { Margin = new Thickness(12, 0, 0, 26), Spacing = 8, Children = { new TextBlock { Text = "May Deploy", FontSize = 26, Foreground = Brush(Paint.SidebarText), FontFamily = new FontFamily("ms-appx:///Fonts/SourceSerif4-600.ttf#Source Serif 4"), FontWeight = Microsoft.UI.Text.FontWeights.SemiBold }, new TextBlock { Text = "VPS 部署与维护", FontSize = 12, Foreground = Brush(Paint.SidebarMuted) } } });
        foreach (var (id, label, icon) in new[] { ("overview", "概述", Symbol.Home), ("instances", "实例", Symbol.World), ("monitoring", "监测", Symbol.View), ("deploy", "部署", Symbol.Add), ("clients", "配置设计", Symbol.Link), ("network", "网络调优", Symbol.Globe), ("records", "记录", Symbol.Clock), ("settings", "设置", Symbol.Setting) })
        { var labelText = Text(label, 14); labelText.Foreground = Brush(Paint.SidebarText); var button = new Button { Content = Row(new SymbolIcon(icon) { Width = 18, Height = 18, Foreground = Brush(Paint.SidebarIcon) }, labelText), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left, Padding = new Thickness(14, 11, 14, 11), Background = Brush(Paint.Sidebar), BorderThickness = new Thickness(0), CornerRadius = new CornerRadius(7) }; button.Click += (_, _) => SelectPage(id); navigation[id] = button; sidebar.Children.Add(button); }
        body.Children.Add(new Border { Background = Brush(Paint.Sidebar), BorderBrush = Brush(Paint.SidebarBorder), BorderThickness = new Thickness(0, 0, 1, 0), Child = sidebar });
        pageHost.Content = page;
        var content = new ScrollViewer { Content = new StackPanel { Spacing = 22, Margin = new Thickness(36, 24, 36, 28), Children = { new StackPanel { Spacing = 7, Children = { heading, caption } }, notice, pageHost } }, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled }; Grid.SetColumn(content, 1); body.Children.Add(content);
        mainScroll = content;
        Grid.SetRow(body, 1); shell.Children.Add(body);
        var taskBar = new Grid { Padding = new Thickness(20, 9, 20, 9), Background = Brush(Paint.Footer), ColumnSpacing = 16 };
        taskBar.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) }); taskBar.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); taskBar.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        taskBar.Children.Add(new StackPanel { Spacing = 6, VerticalAlignment = VerticalAlignment.Center, Children = { taskText, taskProgress } }); Grid.SetColumn(pageAction, 1); taskBar.Children.Add(pageAction); Grid.SetColumn(cancel, 2); taskBar.Children.Add(cancel);
        DesktopTypography.Mark(cancel, TypeRole.Body, 13); cancel.Padding = new Thickness(16, 8, 16, 8); cancel.CornerRadius = new CornerRadius(6); cancel.Background = Brush(Paint.Button); cancel.BorderBrush = Brush(Paint.ButtonBorder);
        cancel.Click += (_, _) => { taskCancellation?.Cancel(); taskText.Text = updateTask ? "正在取消应用更新…" : "正在等待安全边界；远端步骤完成后再处理取消。"; cancel.IsEnabled = false; };
        Grid.SetRow(taskBar, 2); shell.Children.Add(taskBar);
        AppWindow.Closing += async (_, e) =>
        {
            SaveWindowPlacementForClose();
            if (!closing && !exitFromTray && settings.Text("CloseBehavior", "Exit") == "Tray") { e.Cancel = true; MinimizeToTray(); return; }
            exitFromTray = false;
            if (taskCancellation != null) { e.Cancel = true; closing = true; taskCancellation.Cancel(); taskText.Text = "正在安全结束任务，完成后关闭窗口。"; }
            else if (!closing && SchemeChanged)
            {
                e.Cancel = true;
                try { if (await ExitScheme(false)) { closing = true; Close(); } }
                catch (Exception error) { Show(error is OperationException safe ? safe.Message : "方案未能保存，窗口保持打开。", InfoBarSeverity.Error); }
            }
        };
        Closed += (_, _) => { CancelNodeReorder(); StopNetworkScheduler(); StopMonitoring(); trayIcon?.Dispose(); trayIcon = null; };
        SetAppearance(settings.Text("Appearance", "Dark"));
        InitializeMonitoring();
        InitializeWindowPlacement();
        root.Loaded += (_, _) => { Program.Trace(arguments, "Root Loaded"); StartNetworkScheduler(); };
        root.Loaded += async (_, _) => { SelectPage("overview"); if (fontFallback) Show("所选字体暂时不可用，已使用内置原版字体。可在设置中重新选择或导入。", InfoBarSeverity.Warning); if (testSession != null) { StartTestSession(); return; } if (arguments.Contains("--verify-installed-update")) { await InstalledUpdateSmoke(); return; } if (arguments.Contains("--ui-smoke") || arguments.Contains("--verify-runtime")) { await UiSmoke(); return; } if (settings.Flag("AutoCheckUpdates")) await CheckUpdates(true); };
    }
    private static SolidColorBrush Brush(Paint role) => DesktopTheme.Brush(role);
    private static TextBlock Text(string value, int size = 14, bool muted = false) => DesktopTypography.Mark(new TextBlock { Text = value, FontFamily = InterfaceFont, TextWrapping = TextWrapping.Wrap, Foreground = Brush(muted ? Paint.Muted : Paint.Text) }, size >= 30 ? TypeRole.Metric : size >= 16 ? TypeRole.Title : muted ? TypeRole.Note : TypeRole.Body, size);
    private static StackPanel Column(params UIElement[] children) { var panel = new StackPanel { Spacing = 14 }; foreach (var child in children) panel.Children.Add(child); return panel; }
    private static Border Card(UIElement content) => new() { Background = Brush(Paint.Surface), BorderBrush = Brush(Paint.Border), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(22), Child = content };
    private Button Action(string title, Func<Task> handler, bool accent = false, bool allowDuringTask = false)
    {
        var button = new Button { Content = title, MinHeight = 36, FontSize = 13, Padding = new Thickness(16, 8, 16, 8), CornerRadius = new CornerRadius(6), BorderThickness = new Thickness(1), BorderBrush = Brush(accent ? Paint.Accent : Paint.ButtonBorder), Background = Brush(accent ? Paint.Accent : Paint.Button), Foreground = Brush(accent ? Paint.AccentText : Paint.Text) }; AutomationProperties.SetName(button, title);
        DesktopTypography.Mark(button, TypeRole.Body, 13);
        button.Click += async (_, _) => { try { if (taskCancellation != null && !allowDuringTask) throw new OperationException("已有任务运行，请等待结束。"); await handler(); } catch (OperationCanceledException) { Show("已取消。"); } catch (Exception error) { var safe = SafeFailures.Describe(error); Show(safe.Message + (safe.NextAction == null ? "" : "\n" + safe.NextAction), InfoBarSeverity.Error); } }; return button;
    }
    private static StackPanel Row(params UIElement[] children) { var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, VerticalAlignment = VerticalAlignment.Center }; foreach (var child in children) panel.Children.Add(child); return panel; }
    private static Grid Fields(params FrameworkElement[] children)
    {
        var grid = new Grid { ColumnSpacing = 20, RowSpacing = 16 }; grid.ColumnDefinitions.Add(new()); grid.ColumnDefinitions.Add(new());
        foreach (var child in children) grid.Children.Add(child);
        var columns = 0;
        void Arrange(int count) { if (columns == count) return; columns = count; grid.RowDefinitions.Clear(); grid.ColumnDefinitions[1].Width = count == 2 ? new GridLength(1, GridUnitType.Star) : new GridLength(0); for (var i = 0; i < children.Length; i++) { if (i % count == 0) grid.RowDefinitions.Add(new() { Height = GridLength.Auto }); Grid.SetColumn(children[i], i % count); Grid.SetRow(children[i], i / count); } }
        Arrange(2); grid.SizeChanged += (_, _) => Arrange(grid.ActualWidth < 560 ? 1 : 2); return grid;
    }
    private CheckBox Flag(string label, JsonObject model, string key)
    {
        var box = DesktopTypography.Mark(new CheckBox { Content = label, IsChecked = model.Flag(key) }, TypeRole.Body, 14); box.Checked += (_, _) => model[key] = true; box.Unchecked += (_, _) => model[key] = false; return box;
    }
    private UIElement Details(string label, UIElement content)
    {
        content.Visibility = Visibility.Collapsed;
        var arrow = new TextBlock { Text = "\uE70D", FontFamily = new FontFamily("Segoe Fluent Icons"), FontSize = 11, Foreground = Brush(Paint.Icon), VerticalAlignment = VerticalAlignment.Center };
        var button = Action(label, () => { var open = content.Visibility != Visibility.Visible; content.Visibility = open ? Visibility.Visible : Visibility.Collapsed; arrow.Text = open ? "\uE70E" : "\uE70D"; return Task.CompletedTask; }, allowDuringTask: true);
        var header = new Grid { ColumnSpacing = 16 }; header.ColumnDefinitions.Add(new()); header.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); header.Children.Add(Text(label, 13)); Grid.SetColumn(arrow, 1); header.Children.Add(arrow);
        button.Content = header; button.HorizontalAlignment = HorizontalAlignment.Stretch; button.HorizontalContentAlignment = HorizontalAlignment.Stretch; button.Padding = new Thickness(16, 12, 16, 12); button.Background = Brush(Paint.Surface);
        if (launchArguments.Contains("--review-screenshots")) disclosures[button] = content; return new StackPanel { Spacing = 14, Children = { button, content } };
    }
    private void Show(string message, InfoBarSeverity severity = InfoBarSeverity.Informational) { notice.Message = message; notice.Severity = severity; notice.IsOpen = true; }
    private void Navigate(string id)
    {
        CancelNodeReorder();
        StopMonitoring();
        ClearExecution();
        currentPage = id; page.Children.Clear(); disclosures.Clear(); pageAction.Content = null; notice.IsOpen = false; heading.Text = id switch { "overview" => "概述", "instances" => "实例", "monitoring" => "持续监测", "deploy" => "部署", "clients" => "配置设计", "network" => "网络调优", "records" => "任务记录", _ => "设置" }; caption.Text = id switch { "overview" => "集中管理你的 VPS 与连接配置。", "instances" => "选择实例，查看归档并进行维护。", "monitoring" => "读取 May Monitor 授权节点的最近状态。", "deploy" => "组合选择用途，审阅计划，然后执行。", "clients" => "选择目标，设计连接，校验后导出配置。", "network" => "部署完成后，按需要单独审阅并调整网络参数。", "records" => "查看任务结果和需要处理的恢复记录。", _ => "应用更新、外观设置与私人数据。" };
        try { switch (id) { case "overview": Overview(); break; case "instances": Instances(); break; case "monitoring": MonitoringPage(); break; case "deploy": Deployment(); break; case "clients": Clients(); break; case "network": NetworkPage(); break; case "records": Records(); break; default: Settings(); break; } } catch (Exception error) { Show(error is OperationException safe ? safe.Message : "本地记录暂时无法读取，请核对数据目录。", InfoBarSeverity.Error); }
        if (Content is DependencyObject root) ApplyFont(root);
    }
    private void SelectPage(string id)
    {
        if (taskCancellation != null) return;
        foreach (var pair in navigation)
        {
            var active = pair.Key == id; pair.Value.Background = Brush(active ? Paint.SidebarSelected : Paint.Sidebar);
            if (pair.Value.Content is StackPanel items) { ((SymbolIcon)items.Children[0]).Foreground = Brush(active ? Paint.SidebarSelectedIcon : Paint.SidebarIcon); var label = (TextBlock)items.Children[1]; label.Foreground = Brush(active ? Paint.SidebarSelectedText : Paint.SidebarText); label.FontWeight = active ? Microsoft.UI.Text.FontWeights.SemiBold : Microsoft.UI.Text.FontWeights.Normal; }
        }
        Navigate(id);
    }
    private void Overview()
    {
        var grid = new Grid { ColumnSpacing = 16 }; grid.ColumnDefinitions.Add(new()); grid.ColumnDefinitions.Add(new());
        grid.Children.Add(Card(Column(Row(new SymbolIcon(Symbol.World) { Foreground = Brush(Paint.Accent) }, Text("受管实例", 15)), Row(Text(store.ListInstances().Count().ToString(), 32), Text("个实例", 12, true)), Action("查看实例", () => { SelectPage("instances"); return Task.CompletedTask; }))));
        var right = Card(Column(Row(new SymbolIcon(Symbol.Link) { Foreground = Brush(Paint.Accent) }, Text("配置方案", 15)), Row(Text(workbench.List().Count().ToString(), 32), Text("个方案", 12, true)), Action("打开配置设计", () => { SelectPage("clients"); return Task.CompletedTask; }))); Grid.SetColumn(right, 1); grid.Children.Add(right); page.Children.Add(grid);
        page.Children.Add(Card(Trailing(Column(Text("开始新的部署", 18), Text("部署新的 VPS，或接入已经配置好的实例。", 13, true)), Row(Action("新建部署", () => { deploymentForm["Existing"] = false; SelectPage("deploy"); return Task.CompletedTask; }, true), Action("接入已有 VPS", () => { deploymentForm["Existing"] = true; SelectPage("deploy"); return Task.CompletedTask; })) )));
        page.Children.Add(Card(Trailing(Column(Text("持续监测", 18), Text("连接 May Monitor，按实例查看在线状态和最近指标。", 13, true)), Action("查看监测", () => { SelectPage("monitoring"); return Task.CompletedTask; }))));
        var last = new TaskHistory(store).Read().LastOrDefault();
        page.Children.Add(Card(Column(Text("最近任务", 18), Text(last == null ? "暂时还没有任务记录" : OutcomeLabel((TaskOutcome)last.Number("Outcome")), 14, last == null), Text(last == null ? "完成部署、维护或配置导出后，可在记录页查看结果。" : last.Text("Stage"), 13, true), Action("查看记录", () => { SelectPage("records"); return Task.CompletedTask; }))));
    }
    private void Instances()
    {
        var instances = store.ListInstances().ToArray(); if (instances.Length == 0) { page.Children.Add(Card(Column(Text("还没有受管实例", 22), Text("从部署页创建，或接入已有 VPS。", 14, true), Action("开始", () => { SelectPage("deploy"); return Task.CompletedTask; }, true)))); return; }
        var selection = new JsonObject(); var picker = Choice("选择实例", selection, "Instance", instances.Select(instance => (instance.RelativePath, instance.Plan.Text("Provider") + " / " + instance.Plan.Text("Instance"))));
        var details = new StackPanel { Spacing = 20 }; page.Children.Add(picker); page.Children.Add(details);
        picker.SelectionChanged += (_, _) =>
        {
            if (picker.SelectedItem is not ComboBoxItem item) return;
            selectedInstance = (string)item.Tag; details.Children.Clear(); var plan = instances.First(x => x.RelativePath == selectedInstance).Plan;
            var relative = selectedInstance; var status = InstanceLifecycle.Read(store, relative, plan);
            details.Children.Add(Card(Column(SectionHeading(plan.Text("NodeName"), Symbol.World, string.Join(" + ", DeploymentPlans.Purposes(plan).Select(RoleLabel))), Text(plan.Text("Server.IPv4") + (plan.Text("Server.IPv6") == "" ? "" : " / " + plan.Text("Server.IPv6")), 14, true), Text(status.Label, 14, true))));
            if (!status.Managed || status.NeedsRecovery)
            {
                var followup = Column(Text(status.NeedsRecovery ? "先核对未完成事务" : "继续未完成草稿", 18),
                    Text(status.LastError == "" ? "该归档还不代表已部署完成。" : status.LastError),
                    Text(status.NextAction == "" ? status.NeedsRecovery ? "先取得真实事务状态，不能直接重放部署。" : "继续使用已保存的计划；如要重建，可删除下面的本地归档。" : status.NextAction, 14, true));
                if (status.CanContinue) followup.Children.Add(Action(status.ContinueKind == OperationKind.ResumeImport ? "继续接入" : "继续部署", () => Submit(new(status.ContinueKind, relative, new())), true));
                if (status.NeedsRecovery) followup.Children.Add(Action("核对恢复状态", () => Submit(new(OperationKind.Recover, relative, new())), true));
                details.Children.Add(Card(followup));
            }
            if (status.Managed && !status.NeedsRecovery)
            {
            details.Children.Add(GroupLabel("日常维护"));
            var forwarding = TcpForwarding.Rules(plan["TcpForwarding"] as JsonObject).ToArray();
            details.Children.Add(SettingsGroup(SettingRow("独立 TCP 端口转发", forwarding.Length == 0 ? "按需激活、来源白名单与实际转发验收" : forwarding.Count(r => r.Flag("Enabled")) + " 条已启用 · " + forwarding.Length + " 条已保存；实际状态需核对", Symbol.Forward, Action("管理转发", () => TcpForwardSheet(relative, plan)))));
            details.Children.Add(SettingsGroup(SettingRow("跨实例 TCP 编排", "前置 → 中转 → 落地 · 统一依赖、验收与恢复", Symbol.Link, Action("管理线路", () => TcpChainSheet(relative, plan)))));
            details.Children.Add(SettingsGroup(SettingRow("通用多入站", "独立身份、监听、用户、证书、出站与恢复范围", Symbol.AllApps, Action("管理入站", () => InboundsSheet(relative, plan)))));
            var udpForwarding = UdpForwarding.Rules(plan["UdpForwarding"] as JsonObject).ToArray();
            details.Children.Add(SettingsGroup(SettingRow("独立 UDP 端口转发", udpForwarding.Length == 0 ? "独立会话、来源白名单与真实 UDP 往返验收" : udpForwarding.Count(r => r.Flag("Enabled")) + " 条已启用 · " + udpForwarding.Length + " 条已保存；实际状态需核对", Symbol.Forward, Action("管理 UDP 转发", () => UdpForwardSheet(relative, plan)))));
            details.Children.Add(SettingsGroup(
                SettingRow("健康检查", "读取服务、监听与管理入口的当前状态", Symbol.Sync, Action("检查", () => Submit(new(OperationKind.HealthAudit, selectedInstance, new())))),
                SettingRow("代理协议", "管理已安装协议的启用、停用、切换与卸载", Symbol.Setting, Action("协议管理", () => OperationSheet(OperationKind.ProtocolState, plan))),
                SettingRow("追加代理协议", "在此实例安装尚未安装的协议，保留已有服务", Symbol.Add, Action("添加协议", () => ChooseInstallation(plan))),
                SettingRow("代理核心", "升级此 VPS 上的 Xray 或 sing-box；审阅时显示对象与版本", Symbol.Download, Action("升级核心", () => OperationSheet(OperationKind.Upgrade, plan))),
                SettingRow("协议凭据", "轮换正在运行的协议凭据", Symbol.Permissions, Action("凭据轮换", () => OperationSheet(OperationKind.RotateCredentials, plan)))));
            foreach (var role in ServerOutboundRouting.Roles.Where(role => plan.Flag("ProtocolInventory." + role + ".Installed", DeploymentPlans.Uses(plan, role))))
            {
                var route = plan.At("ServerOutbound." + role) as JsonObject;
                var description = route == null ? "指定 Shadowsocks 落地，执行前审阅并备份" : route.Text("Name") + " · " + route.Text("EgressFamily") + "\n" + ServerOutboundRouting.SourcesSummary(store, route);
                details.Children.Add(SettingsGroup(SettingRow(ServerOutboundRouting.Label(role) + " · 固定下一跳", description, Symbol.Forward, Action("配置出站", () => ServerOutboundSheet(relative, plan, role)))));
            }
            var health = InstanceState(relative)["HealthReport"] as JsonObject;
            if (health?["Checks"] is JsonArray checks)
            {
                var report = Column(Text(health.Text("Status") == "Passed" ? "最近健康检查 · 核对通过" : "最近健康检查 · 有待处理项", 18));
                foreach (var check in checks.Where(c => health.Text("Status") == "Passed" || c!.Text("Status") != "Passed")) report.Children.Add(Trailing(Text(check!.Text("Name") + " · " + check.Text("Message"), 13, true), Text(check.Text("Status") == "Passed" ? "通过" : "需核对", 13)));
                if (health.Text("Status") == "Passed") details.Children.Add(Details("健康检查结果", Card(report)));
                else
                {
                    var passed = checks.Where(c => c!.Text("Status") == "Passed").ToArray();
                    if (passed.Length > 0) report.Children.Add(Details("已通过的检查", Column(passed.Select(c => (UIElement)Text(c!.Text("Name") + " · 核对通过", 13, true)).ToArray())));
                    details.Children.Insert(1, Card(report));
                }
            }
            details.Children.Add(GroupLabel("监控与访问")); details.Children.Add(MonitoringControls(plan, InstanceState(relative)));
            details.Children.Add(Details("恢复与后续操作", SettingsGroup(
                SettingRow("未完成任务", "核对事务状态，再选择恢复操作", Symbol.Sync, Action("核对", () => Submit(new(OperationKind.Recover, selectedInstance, new())))),
                SettingRow("协议备份", "从明确选择的协议备份恢复", Symbol.Library, Action("从备份恢复", () => OperationSheet(OperationKind.Restore, plan))),
                SettingRow("实例退役", "停用或移除受管协议与 Agent", Symbol.Delete, Action("审阅退役", () => OperationSheet(OperationKind.Decommission, plan))))));
            }
            var delete = Action("删除实例", () => DeleteInstance(relative)); delete.IsEnabled = !status.NeedsRecovery;
            details.Children.Add(SettingsGroup(SettingRow("删除本地实例", status.NeedsRecovery ? "先处理未确认事务，之后可删除本地归档" : "删除此实例的全部本地受管文件；审阅后执行", Symbol.Delete, delete)));
        };
        var selectionIndex = Math.Max(0, Array.FindIndex(instances, x => x.RelativePath == selectedInstance)); if (picker.SelectedIndex == selectionIndex) picker.SelectedIndex = -1; picker.SelectedIndex = selectionIndex;
    }
    private static string RoleLabel(string role) => role switch { "RealityEntry" => "Reality 入口", "AnyTlsEntry" => "AnyTLS / ECH 入口", "ShadowsocksLanding" => "Shadowsocks 落地", _ => "监控或基础维护" };
    private TextBox Field(string label, JsonObject model, string key, string defaultValue = "", bool numeric = false)
    {
        var box = new TextBox { Header = label, Text = model.Text(key, defaultValue), HorizontalAlignment = HorizontalAlignment.Stretch, MinWidth = 180, FontSize = 13, MinHeight = 38, Padding = new Thickness(12, 9, 12, 9), CornerRadius = new CornerRadius(6), BorderThickness = new Thickness(1), BorderBrush = Brush(Paint.InputBorder), Background = Brush(Paint.Input), Foreground = Brush(Paint.Text) }; AutomationProperties.SetName(box, label);
        DesktopTypography.Mark(box, TypeRole.Body, 14);
        box.TextChanged += (_, _) => { model[key] = numeric && int.TryParse(box.Text, out var number) ? JsonValue.Create(number) : JsonValue.Create(box.Text.Trim()); }; return box;
    }
    private UIElement FileField(string label, JsonObject model, string key, bool save = false)
    {
        var grid = new Grid { ColumnSpacing = 10 }; grid.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) }); grid.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); var field = Field(label, model, key); grid.Children.Add(field);
        var browse = Action("浏览", async () => { var result = await PickFile(save, key.Contains("Clash") ? ".yaml" : ".json"); if (result != null) field.Text = result; }); browse.VerticalAlignment = VerticalAlignment.Bottom; Grid.SetColumn(browse, 1); grid.Children.Add(browse); return grid;
    }
    private async Task<string?> PickFile(bool save, string extension)
    {
        if (backgroundTest) throw new OperationException("后台测试不打开系统选择器；请通过表单填入测试工作区中的路径。");
        var handle = WinRT.Interop.WindowNative.GetWindowHandle(this);
        if (save)
        {
            // Selecting a destination must not create an empty file before review.
            return WindowsSavePathPicker.Select(handle, extension);
        }
        var picker = new global::Windows.Storage.Pickers.FileOpenPicker(); picker.FileTypeFilter.Add("*"); WinRT.Interop.InitializeWithWindow.Initialize(picker, handle); return (await picker.PickSingleFileAsync())?.Path;
    }
    private async Task<bool> Submit(OperationRequest request)
    {
        if (taskCancellation != null) throw new OperationException("已有任务运行，请等待结束。");
        var prepared = await ResolveExistingDraft(request); if (prepared == null) return false; request = prepared;
        var review = coordinator.Review(request);
        if (!await ReviewOperation(review)) return false;
        activeOperation = request;
        if (OperationSteps.HasDeploymentProgress(request.Kind)) ShowExecution(request);
        var completed = false;
        try { await RunBackground("准备任务", async token => { var progress = new Progress<TaskProgress>(ExecutionProgress); var record = await Task.Run(() => coordinator.ExecuteAsync(review, request, progress, token)); completed = record.Outcome is TaskOutcome.Completed or TaskOutcome.CompletedWithWarnings; taskText.Text = OutcomeLabel(record.Outcome) + " · " + StageLabel(record.Stage); if (ShowingExecution) FinishExecution(record); Show(TaskMessage(record), record.Outcome is TaskOutcome.Failed or TaskOutcome.NeedsRecovery ? InfoBarSeverity.Error : record.Outcome == TaskOutcome.Completed ? InfoBarSeverity.Success : InfoBarSeverity.Warning); }); }
        catch (Exception error)
        {
            if (ShowingExecution && executionResult == null)
            {
                var safe = error is OperationCanceledException ? null : SafeFailures.Describe(error);
                FinishExecution(new TaskRecord("ui-" + Guid.NewGuid().ToString("N"), request.Kind, executionStarted, DateTimeOffset.UtcNow,
                    error is OperationCanceledException ? TaskOutcome.Cancelled : TaskOutcome.Failed, "preflight", safe?.Message, safe?.Code, safe?.NextAction, request.InstanceRelativePath));
            }
            throw;
        }
        finally { activeOperation = null; RefreshTaskResultPage(); }
        return completed;
    }
    private void RefreshTaskResultPage()
    {
        if (ShowingExecution) return;
        if (currentPage is not ("instances" or "records" or "overview" or "network")) return;
        var shown = notice.IsOpen; var message = notice.Message; var severity = notice.Severity;
        SelectPage(currentPage); if (shown) Show(message, severity);
    }
    private async Task RunBackground(string label, Func<CancellationToken, Task> action)
    {
        if (taskCancellation != null) throw new OperationException("已有任务运行，请等待结束。");
        taskCancellation = new(); cancel.Visibility = Visibility.Visible; cancel.IsEnabled = true; taskProgress.Value = 0; taskProgress.IsIndeterminate = true; taskProgress.Visibility = Visibility.Visible; taskText.Text = label; pageHost.IsEnabled = ShowingExecution && executionResult == null; pageAction.IsEnabled = false; foreach (var button in navigation.Values) button.IsEnabled = false;
        try { await action(taskCancellation.Token); if (taskText.Text == label) taskText.Text = "已完成"; }
        catch (OperationCanceledException) { taskText.Text = "已取消"; throw; }
        catch { taskText.Text = "任务未完成"; throw; }
        finally { taskCancellation.Dispose(); taskCancellation = null; pageHost.IsEnabled = true; pageAction.IsEnabled = true; foreach (var button in navigation.Values) button.IsEnabled = true; cancel.Visibility = Visibility.Collapsed; taskProgress.Visibility = Visibility.Collapsed; if (closing) { SaveDraft(); Close(); } }
    }
    private static string OutcomeLabel(TaskOutcome outcome) => outcome switch { TaskOutcome.Completed => "已完成", TaskOutcome.CompletedWithWarnings => "已完成，含提示", TaskOutcome.Cancelled => "已取消", TaskOutcome.NeedsRecovery => "待恢复", TaskOutcome.Failed => "失败", _ => "上次任务未确认结束" };
    private void SaveDraft() => SaveScheme();
    public Task<bool> ConfirmHostAsync(HostIdentity identity, CancellationToken cancellationToken) => activeOperation?.Options.Flag("Scheduled") == true ? Task.FromResult(false) : ConfirmHostIdentity(identity, cancellationToken);
    public async Task<bool> ConfirmAsync(UserDecision decision, CancellationToken cancellationToken) => await OnUi(async () =>
    {
        if (activeOperation?.Options.Flag("Scheduled") == true) return false;
        var phrase = new TextBox { Header = decision.RequiredPhrase == null ? "" : "输入 " + decision.RequiredPhrase + " 确认", Visibility = decision.RequiredPhrase == null ? Visibility.Collapsed : Visibility.Visible }; var dialog = OperationDialog(decision.Title, Column(Text(decision.Description), phrase), "确认");
        if (decision.RequiredPhrase != null) { dialog.IsPrimaryButtonEnabled = false; phrase.TextChanged += (_, _) => dialog.IsPrimaryButtonEnabled = phrase.Text == decision.RequiredPhrase; } using var registration = cancellationToken.Register(() => DispatcherQueue.TryEnqueue(dialog.Hide)); return await ShowDialog(dialog) == ContentDialogResult.Primary;
    }, cancellationToken);
    public async Task<string?> SecretAsync(string title, CancellationToken cancellationToken) => await OnUi(async () =>
    {
        if (activeOperation?.Options.Flag("Scheduled") == true) return null;
        var box = SecretField(title); var dialog = OperationDialog("输入凭据", box, "继续"); using var registration = cancellationToken.Register(() => DispatcherQueue.TryEnqueue(dialog.Hide)); var result = await ShowDialog(dialog); var value = result == ContentDialogResult.Primary ? box.Password : null; box.Password = ""; return value;
    }, cancellationToken);
    private async Task<T> OnUi<T>(Func<Task<T>> action, CancellationToken cancellationToken)
    {
        await dialogs.WaitAsync(cancellationToken); try { var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously); if (!DispatcherQueue.TryEnqueue(async () => { try { completion.SetResult(await action()); } catch (Exception error) { completion.TrySetException(error); } })) throw new OperationCanceledException(); return await completion.Task; } finally { dialogs.Release(); }
    }
}
