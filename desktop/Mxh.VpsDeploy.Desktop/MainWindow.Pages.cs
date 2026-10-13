using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private ComboBox Choice(string label, JsonObject model, string key, IEnumerable<(string Value, string Label)> choices, bool preserveMissing = false, bool preventWheelSelection = false)
    {
        ComboBox box = preventWheelSelection ? new InstanceSelector() : new ComboBox();
        box.Header = label; box.HorizontalAlignment = HorizontalAlignment.Stretch; box.MinHeight = 38; box.FontSize = 13;
        box.CornerRadius = new CornerRadius(6); box.BorderThickness = new Thickness(1); box.BorderBrush = Brush(Paint.InputBorder); box.Background = Brush(Paint.Input); box.Foreground = Brush(Paint.Text);
        DesktopTypography.Mark(box, TypeRole.Body, 14);
        foreach (var (value, title) in choices) box.Items.Add(new ComboBoxItem { Content = title, Tag = value });
        var selectedIndex = box.Items.Cast<ComboBoxItem>().ToList().FindIndex(i => (string)i.Tag == model.Text(key));
        box.SelectedIndex = preserveMissing ? selectedIndex : Math.Max(0, selectedIndex);
        if (preserveMissing && selectedIndex < 0) box.PlaceholderText = "请选择有效的入口组";
        if (box.SelectedItem is ComboBoxItem first) model[key] = (string)first.Tag;
        box.SelectionChanged += (_, _) => { if (box.SelectedItem is ComboBoxItem item) model[key] = (string)item.Tag; }; return box;
    }
    private async Task OperationSheet(OperationKind kind, JsonObject plan)
    {
        if (kind == OperationKind.Upgrade) { await UpgradeCore(plan); return; }
        if (kind == OperationKind.TuneNetwork) { SelectPage("network"); return; }
        if (kind == OperationKind.Komari) throw new OperationException("请从实例页选择具体的监控或访问组件。");
        var options = new JsonObject { ["Scope"] = kind == OperationKind.TuneNetwork ? "Network" : kind == OperationKind.Decommission ? "ManagedInstance" : "Protocol" };
        var panel = Column(Text("选择本次操作范围，再审阅执行。", 14, true));
        if (kind is OperationKind.ProtocolState or OperationKind.RotateCredentials) panel.Children.Add(Choice("协议", options, "Protocol", DeploymentPlans.Roles[..3].Where(role => plan.Flag("ProtocolInventory." + role + ".Installed", plan.Text("Role") == role)).Select(role => (role, RoleLabel(role)))));
        if (kind == OperationKind.ProtocolState) panel.Children.Add(Choice("操作", options, "Action", [("Switch", "切换到此入口"), ("Enable", "启用"), ("Disable", "停用备用"), ("Uninstall", "卸载此协议")]));
        if (kind == OperationKind.Restore)
        {
            var directory = SafePath.Resolve(paths.Instance(selectedInstance!), "maintenance-backups");
            var backups = Directory.Exists(directory) ? Directory.EnumerateFiles(directory, "restore-metadata.json", SearchOption.AllDirectories).Select(ArchiveStore.ReadJson).Where(b => ProtocolRestores.Compatible(b, plan)).ToArray() : [];
            if (backups.Length == 0) throw new OperationException("没有兼容当前管理入口的协议专用恢复点。网络、主控和追加安装备份请从各自的恢复入口处理。");
            panel.Children.Add(Choice("恢复点", options, "Backup", backups.Select(b => (b.Text("RemoteBackup"), b.Text("CreatedAt")))));
            panel.Children.Add(Choice("恢复范围", options, "RestoreMode", [("ConfigOnly", "仅恢复协议配置"), ("Full", "恢复协议程序、文件与服务")])); panel.Children.Add(Text("仅限协议范围；SSH、网络、防火墙和监控保持当前配置。", 13, true));
        }
        if (kind == OperationKind.Decommission) { panel.Children.Add(Choice("退役级别", options, "Action", [("Disable", "停用受管协议与 Agent"), ("RemoveManaged", "卸载受管协议与 Agent")])); panel.Children.Add(Text("保留 SSH 和基础系统；主控与 Tunnel 不包含在此范围。", 13, true)); }
        var dialog = OperationDialog(kind switch { OperationKind.ProtocolState => "协议管理", OperationKind.RotateCredentials => "凭据轮换", OperationKind.TuneNetwork => "网络参数", OperationKind.Restore => "从备份恢复", _ => "实例退役" }, panel, "审阅");
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        await Submit(new(kind, selectedInstance!, options));
    }
    private async Task AddManagedNodes()
    {
        var all = new List<(ClientProfiles.NodePair Node, JsonObject Plan, string Relative)>();
        foreach (var instance in store.ListInstances())
        {
            var status = InstanceLifecycle.Read(store, instance.RelativePath, instance.Plan); if (!status.Managed || status.NeedsRecovery) continue;
            var secretFile = SafePath.Resolve(paths.Instance(instance.RelativePath), "secrets.dotnet.private.json"); if (!File.Exists(secretFile)) continue;
            var secrets = store.ReadSecret(secretFile); all.AddRange(ClientProfiles.Nodes(instance.Plan, secrets).Select(n => (n, instance.Plan, instance.RelativePath))); secrets.Clear();
        }
        var candidates = all.DistinctBy(i => i.Node.Name).ToArray();
        var picker = new ManagedNodePicker(candidates.Select(i => i.Node), scheme!["Nodes"]!.AsArray().Select(n => n!.Text("name")).ToHashSet(StringComparer.Ordinal));
        var dialog = OperationDialog("选择节点", picker.Content, "添加 / 更新");
        dialog.IsPrimaryButtonEnabled = picker.Selected.Count != 0;
        picker.SelectionChanged += () => dialog.IsPrimaryButtonEnabled = picker.Selected.Count != 0;
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        foreach (var item in candidates.Where(s => picker.Selected.Contains(s.Node.Name)))
        {
            var nodes = scheme!["Nodes"]!.AsArray();
            var index = nodes.ToList().FindIndex(n => n != null && (n.Text("name") == item.Node.Name || n["ManagedOrigin"] is JsonObject origin && origin.Text("Instance") == item.Relative && origin.Text("Role") == item.Node.Role && origin.Text("Family") == item.Node.Family && origin.Text("EgressFamily") == item.Node.EgressFamily && origin.Flag("Backup") == item.Node.IsBackup));
            var previous = index < 0 ? null : nodes[index];
            var node = new JsonObject { ["name"] = item.Node.Name, ["kind"] = item.Node.Role == "ShadowsocksLanding" ? "landing" : "entry", ["region_group"] = previous?.Text("region_group", "US-West Entry") ?? "US-West Entry", ["transit_group"] = previous?.Text("transit_group", item.Plan.Text("Shadowsocks.ClientTransitTag", "US-West Entry")) ?? item.Plan.Text("Shadowsocks.ClientTransitTag", "US-West Entry"), ["clash"] = item.Node.Clash.DeepClone(), ["sing_box"] = item.Node.SingBox.DeepClone(), ["ManagedOrigin"] = ManagedNodeSources.Origin(item.Relative, item.Node) };
            if (previous?["AuthorityName"] != null) node["AuthorityName"] = previous["AuthorityName"]!.DeepClone();
            if (index < 0) nodes.Add(node); else nodes[index] = node;
        }
        DirtyScheme();
    }
    private async Task ReadClientSources()
    {
        var selected = scheme ?? throw new OperationException("请先选择方案。"); var sources = new JsonObject { ["Clash"] = "", ["SingBox"] = "" }; var panel = new StackPanel { Spacing = 14 };
        foreach (var format in ClientSchemes.Formats(selected)) panel.Children.Add(FileField(format == "Clash" ? "Clash 来源文件" : "sing-box 来源文件", sources, format));
        panel.Children.Add(Text("读取节点，并沿用来源的规则、DNS 与高级设置。来源文件只读，导出位置在最后一步选择。", 14, true));
        var dialog = new ContentDialog { XamlRoot = shell.XamlRoot, RequestedTheme = ElementTheme.Dark, Title = "读取现有配置", Content = panel, PrimaryButtonText = "读取", CloseButtonText = "取消" };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        var fingerprints = new JsonObject(); foreach (var format in ClientSchemes.Formats(selected)) { if (!File.Exists(sources.Text(format))) throw new OperationException("请选择存在的来源文件。"); fingerprints[format] = ClientSchemes.SourceFingerprint(sources.Text(format)); }
        JsonArray nodes = new(); await RunBackground("读取来源配置", async token => nodes = await workbench.ReadSourcesAsync(sources.Text("Clash"), sources.Text("SingBox"), token));
        if (nodes.Count == 0) throw new OperationException("来源中未找到受支持的 Reality、AnyTLS 或 Shadowsocks 节点。");
        foreach (var format in ClientSchemes.Formats(selected)) { if (fingerprints.Text(format) != ClientSchemes.SourceFingerprint(sources.Text(format))) throw new OperationException("读取期间来源发生变化。"); selected[format] = sources.Text(format); }
        selected["SourceMode"] = "ExistingAuthority"; selected["SourceFingerprints"] = fingerprints;
        selected["AuthorityNodes"] = new JsonArray(nodes.Select(n => (JsonNode?)JsonValue.Create(n!.Text("name"))).ToArray());
        var names = selected["Nodes"]!.AsArray().Select(n => n!.Text("name")).ToHashSet();
        foreach (var node in nodes)
        {
            if (!names.Add(node!.Text("name")))
            {
                var retained = selected["Nodes"]!.AsArray().Single(n => n!.Text("name") == node.Text("name"))!; retained["AuthorityName"] = node.Text("name"); continue;
            }
            var copy = node!.DeepClone(); copy["region_group"] = "US-West Entry"; copy["AuthorityName"] = copy.Text("name");
            if (!selected["Layout"]!.Strings("region_groups").Contains(copy.Text("transit_group"))) copy["transit_group"] = "US-West Entry";
            selected["Nodes"]!.AsArray().Add(copy);
        }
        DirtyScheme();
    }
    private async Task EditNode(int? index)
    {
        var activeScheme = scheme ?? throw new OperationException("请先选择方案。");
        var existing = index.HasValue ? activeScheme["Nodes"]!.AsArray()[index.Value]!.AsObject() : null;
        string Read(string primary, string fallback, string defaultValue = "") => existing == null ? defaultValue : existing.Text(primary, existing.Text(fallback, defaultValue));
        var echLines = existing?.At("sing_box.tls.ech.config") as JsonArray;
        var model = new JsonObject { ["Name"] = existing?.Text("name") ?? "", ["Role"] = Read("clash.type", "sing_box.type") switch { "ss" or "shadowsocks" => "ShadowsocksLanding", "anytls" => "AnyTlsEntry", _ => "RealityEntry" }, ["Address"] = Read("clash.server", "sing_box.server"), ["Port"] = existing?.Number("clash.port", existing.Number("sing_box.server_port", 443)) ?? 443, ["Region"] = existing?.Text("region_group", "US-West Entry") ?? "US-West Entry", ["Transit"] = existing?.Text("transit_group", "US-West Entry") ?? "US-West Entry", ["Sni"] = Read("clash.servername", "clash.sni", Read("sing_box.tls.server_name", "sing_box.tls.server_name")), ["Uuid"] = Read("clash.uuid", "sing_box.uuid"), ["PublicKey"] = Read("clash.reality-opts.public-key", "sing_box.tls.reality.public_key"), ["ShortId"] = Read("clash.reality-opts.short-id", "sing_box.tls.reality.short_id"), ["Ech"] = existing?.Text("clash.ech-opts.config", echLines == null ? "" : string.Join("", echLines.Select(l => l!.ToString()).Where(l => !l.StartsWith("-----")))) ?? "", ["Method"] = Read("clash.cipher", "sing_box.method", "2022-blake3-aes-128-gcm") };
        var password = SecretField("密码 / SS2022 组合密钥", Read("clash.password", "sing_box.password"));
        var uuid = SecretField("UUID", model.Text("Uuid"));
        var role = Choice("协议", model, "Role", DeploymentPlans.Roles[..3].Select(value => (value, RoleLabel(value)))); if (existing != null) role.IsEnabled = false;
        var specifics = new StackPanel { Spacing = 16 }; var panel = Column(Fields(Field("节点名称", model, "Name"), role, Field("服务器地址", model, "Address"), Field("端口", model, "Port", numeric: true)), specifics); panel.MinWidth = 380;
        void Refresh()
        {
            specifics.Children.Clear();
            if (model.Text("Role") == "ShadowsocksLanding") { specifics.Children.Add(Fields(Choice("连接的入口组", model, "Transit", activeScheme["Layout"]!.Strings("region_groups").Select(r => (r, r))), Field("Shadowsocks 方法", model, "Method"))); specifics.Children.Add(password); }
            else { specifics.Children.Add(Fields(Choice("入口地区", model, "Region", activeScheme["Layout"]!.Strings("region_groups").Select(r => (r, r))), Field("SNI", model, "Sni"))); if (model.Text("Role") == "RealityEntry") { specifics.Children.Add(uuid); specifics.Children.Add(Fields(Field("Reality 公钥", model, "PublicKey"), Field("short-id", model, "ShortId"))); } else { specifics.Children.Add(password); specifics.Children.Add(Field("ECH 客户端配置", model, "Ech")); } }
        }
        role.SelectionChanged += (_, _) => Refresh(); Refresh();
        var dialog = new ContentDialog { XamlRoot = shell.XamlRoot, RequestedTheme = ElementTheme.Dark, Title = existing == null ? "添加节点" : "编辑节点", Content = new ScrollViewer { Content = panel, MaxHeight = 500 }, PrimaryButtonText = "保存", CloseButtonText = "取消" };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) { password.Password = ""; uuid.Password = ""; return; }
        model["Uuid"] = uuid.Password.Trim(); uuid.Password = "";
        if (model.Text("Name").Length is < 1 or > 120 || model.Text("Name").Any(char.IsControl) || model.Text("Address") == "" || model.Number("Port") is < 1 or > 65535) { password.Password = ""; throw new OperationException("请填写有效的名称、服务器地址和 1–65535 的端口。"); }
        if (activeScheme["Nodes"]!.AsArray().Where((_, i) => i != index).Any(n => n!.Text("name") == model.Text("Name"))) { password.Password = ""; throw new OperationException("节点名称已存在。"); }
        var fakePlan = new JsonObject { ["NodeName"] = model.Text("Name"), ["Role"] = model.Text("Role"), ["Server"] = new JsonObject { ["IPv4"] = model.Text("Address"), ["IPv6"] = "" }, ["Ports"] = new JsonObject { ["XrayPrimary"] = model.Number("Port"), ["AnyTlsPrimary"] = model.Number("Port"), ["LandingShadowsocks"] = model.Number("Port") }, ["Reality"] = new JsonObject { ["ServerName"] = model.Text("Sni") }, ["AnyTls"] = new JsonObject { ["ServerName"] = model.Text("Sni") }, ["Shadowsocks"] = new JsonObject { ["Method"] = model.Text("Method") } };
        var fakeSecrets = new JsonObject { ["Xray"] = new JsonObject { ["Uuid"] = model.Text("Uuid"), ["RealityClientKey"] = model.Text("PublicKey"), ["ShortId"] = model.Text("ShortId") }, ["AnyTls"] = new JsonObject { ["Password"] = password.Password, ["EchClientConfigPem"] = "-----BEGIN ECH CONFIGS-----\n" + model.Text("Ech") + "\n-----END ECH CONFIGS-----\n" }, ["Shadowsocks"] = new JsonObject { ["ServerKey"] = password.Password.Split(':')[0], ["PrimaryUserKey"] = password.Password.Contains(':') ? password.Password[(password.Password.IndexOf(':') + 1)..] : "" } };
        var pair = ClientProfiles.Nodes(fakePlan, fakeSecrets).First();
        pair.Clash["name"] = model.Text("Name"); pair.SingBox["tag"] = model.Text("Name");
        if (model.Text("Role") == "ShadowsocksLanding") { pair.Clash["password"] = password.Password; pair.SingBox["password"] = password.Password; }
        // Preserve legitimate advanced node settings when editing the fields exposed by this form.
        var clash = existing?["clash"]?.DeepClone().AsObject() ?? pair.Clash.DeepClone().AsObject(); var sing = existing?["sing_box"]?.DeepClone().AsObject() ?? pair.SingBox.DeepClone().AsObject();
        if (existing != null)
        {
            foreach (var field in new[] { "name", "server", "port", "uuid", "servername", "sni", "password", "cipher", "reality-opts.public-key", "reality-opts.short-id", "ech-opts.config" }) if (pair.Clash.At(field) is JsonNode value) clash.Put(field, value.DeepClone());
            foreach (var field in new[] { "tag", "server", "server_port", "uuid", "password", "method", "tls.server_name", "tls.reality.public_key", "tls.reality.short_id", "tls.ech.config" }) if (pair.SingBox.At(field) is JsonNode value) sing.Put(field, value.DeepClone());
        }
        var node = new JsonObject { ["name"] = model.Text("Name"), ["kind"] = model.Text("Role") == "ShadowsocksLanding" ? "landing" : "entry", ["region_group"] = model.Text("Region"), ["transit_group"] = model.Text("Transit"), ["clash"] = clash, ["sing_box"] = sing };
        if (existing?["AuthorityName"] != null) node["AuthorityName"] = existing["AuthorityName"]!.DeepClone();
        if (index.HasValue) activeScheme["Nodes"]!.AsArray()[index.Value] = node; else activeScheme["Nodes"]!.AsArray().Add(node); password.Password = ""; fakeSecrets.Clear(); DirtyScheme();
    }
    private async Task EditBusinessGroups()
    {
        var definitions = scheme!["Layout"]!["business_groups"]!.DeepClone().AsArray(); var panel = new StackPanel { Spacing = 14 }; var choices = new[] { scheme.Text("Layout.default_exit_group"), scheme.Text("Layout.direct_group") }.Concat(scheme["Layout"]!.Strings("region_groups")).Concat(scheme["Nodes"]!.AsArray().Where(n => n!.Text("kind") == "landing").Select(n => n!.Text("name"))).ToArray();
        foreach (var definition in definitions.OfType<JsonObject>()) panel.Children.Add(Choice(definition.Text("name"), definition, "default", choices.Select(c => (c, c))));
        var dialog = new ContentDialog { XamlRoot = shell.XamlRoot, RequestedTheme = ElementTheme.Dark, Title = "业务默认出口", Content = new ScrollViewer { Content = panel, MaxHeight = 480 }, PrimaryButtonText = "保存", CloseButtonText = "取消" };
        if (await ShowDialog(dialog) == ContentDialogResult.Primary) { scheme["Layout"]!["business_groups"] = definitions; DirtyScheme(); }
    }
    private async Task EditExitOrder()
    {
        var members = scheme!["Layout"]!.Strings("default_exit_members").ToList(); var panel = new StackPanel { Spacing = 8 }; var list = new ListView { SelectionMode = ListViewSelectionMode.Single, ItemsSource = members.ToArray() }; panel.Children.Add(list);
        panel.Children.Add(Row(Action("上移", () => { var index = list.SelectedIndex; if (index > 0) { (members[index - 1], members[index]) = (members[index], members[index - 1]); list.ItemsSource = members.ToArray(); list.SelectedIndex = index - 1; } return Task.CompletedTask; }), Action("下移", () => { var index = list.SelectedIndex; if (index >= 0 && index < members.Count - 1) { (members[index + 1], members[index]) = (members[index], members[index + 1]); list.ItemsSource = members.ToArray(); list.SelectedIndex = index + 1; } return Task.CompletedTask; })));
        var dialog = new ContentDialog { XamlRoot = shell.XamlRoot, RequestedTheme = ElementTheme.Dark, Title = "默认出口顺序", Content = panel, PrimaryButtonText = "保存", CloseButtonText = "取消" };
        if (await ShowDialog(dialog) == ContentDialogResult.Primary) { scheme["Layout"]!["default_exit_members"] = new JsonArray(members.Select(m => (JsonNode?)JsonValue.Create(m)).ToArray()); DirtyScheme(); }
    }
    private async Task PublishClients()
    {
        var selected = scheme ?? throw new OperationException("请先选择方案。"); var clash = selected.Text("Targets.Clash"); var sing = selected.Text("Targets.SingBox"); workbench.PreparePublish(selected, clash, sing);
        RememberScheme();
        if (!await ConfirmAsync(new("审阅配置导出", ClientSchemes.OutputLabel(selected) + " 的候选已校验。将导出到以下文件，已有文件会先备份：\n" + string.Join("\n", ClientSchemes.SelectedTargets(selected, clash, sing).Select(t => t.Path)) + "\n导出后由你自行导入客户端。"), CancellationToken.None)) return;
        await RunBackground("导出配置文件", token => { token.ThrowIfCancellationRequested(); workbench.Publish(selected, clash, sing); Show("所选配置已导出，恢复副本与事务记录已保存。", InfoBarSeverity.Success); return Task.CompletedTask; });
    }
    private void Settings()
    {
        page.Children.Add(GroupLabel("外观"));
        var appearance = Choice("", settings, "Appearance", [("Dark", "深色"), ("Light", "浅色")]); appearance.MinWidth = 150; appearance.Tag = "Appearance"; Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(appearance, "颜色模式");
        appearance.SelectionChanged += (_, _) => SetAppearance(settings.Text("Appearance"), true);
        page.Children.Add(SettingsGroup(SettingRow("颜色模式", "切换深色与浅色界面", Symbol.Setting, appearance), FontSetting()));
        page.Children.Add(GroupLabel("文字大小")); page.Children.Add(TypographySettings());
        page.Children.Add(GroupLabel("窗口启动")); page.Children.Add(WindowPlacementSetting());
        page.Children.Add(GroupLabel("关闭设置")); page.Children.Add(CloseBehaviorSetting());
        var check = new ToggleSwitch { Tag = "AutoCheckUpdates", IsOn = settings.Flag("AutoCheckUpdates"), OnContent = "", OffContent = "", MinWidth = 0, Width = 48 }; check.Toggled += (_, _) => { settings["AutoCheckUpdates"] = check.IsOn; SaveSettings(); };
        page.Children.Add(GroupLabel("更新"));
        page.Children.Add(SettingsGroup(
            SettingRow("自动检查更新", "在启动应用时检查正式版本", Symbol.Sync, check),
            SettingRow("检查更新", "安装新版后自动重新打开应用", Symbol.Download, Action("检查更新", () => CheckUpdates(false)))));
        var proxy = Field("代理地址（可留空）", settings, "UpdateProxy"); proxy.LostFocus += (_, _) => SaveSettings();
        page.Children.Add(Details("更新连接", Card(Column(proxy, Text("此地址仅供应用下载更新使用。", 12, true)))));
        page.Children.Add(GroupLabel("数据与配置"));
        page.Children.Add(SettingsGroup(
            PrivateDirectorySetting(),
            SettingRow("卸载数据处理", "卸载时可选择保留归档和本地配置，或彻底删除应用数据", Symbol.Delete, Text("卸载时选择", 12, true))));
        var version = ArchiveStore.ReadJson(paths.Resolve("config/application.json")).Text("version");
        page.Children.Add(GroupLabel("关于"));
        var appIcon = new Image { Name = "AboutApplicationIcon", Width = 32, Height = 32, Source = new Microsoft.UI.Xaml.Media.Imaging.SvgImageSource(new Uri("ms-appx:///assets/gui/app.svg")) };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(appIcon, "MXH VPS Deploy 应用图标");
        page.Children.Add(SettingsGroup(SettingRow("MXH VPS Deploy", "Windows 桌面应用", appIcon, Text("v" + version, 13, true))));
    }
    private void SaveSettings() => ArchiveStore.WriteJson(paths.Resolve("private/desktop-settings.json"), settings);
}
