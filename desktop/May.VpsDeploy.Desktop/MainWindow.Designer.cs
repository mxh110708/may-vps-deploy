#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Automation;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private int designerStep;
    private string schemeBaseline = "";
    private bool SchemeChanged => scheme != null && ArchiveStore.Fingerprint(scheme) != schemeBaseline;
    private void RememberScheme() { schemeBaseline = scheme == null ? "" : ArchiveStore.Fingerprint(scheme); }
    private void SaveScheme() { if (scheme == null) return; workbench.Save(scheme); RememberScheme(); }
    private void OpenScheme(JsonObject saved)
    {
        scheme = saved; designerStep = 0;
        if (scheme["Candidate"] is JsonObject candidate) { candidate["ValidationStatus"] = "Pending"; candidate["Targets"] = new JsonObject(); }
        RememberScheme(); Navigate("clients");
    }
    private async Task CreateScheme()
    {
        var draft = ClientSchemes.New(paths);
        var dialog = new ContentDialog { XamlRoot = shell.XamlRoot, Title = "创建配置方案", PrimaryButtonText = "开始设计", CloseButtonText = "取消" };
        dialog.Content = Column(Field("方案名称", draft, "Name"), Text("生成目标", 16), OutputSelection(draft, () => dialog.IsPrimaryButtonEnabled = HasOutput(draft)), Text("点亮需要的目标，两个都点亮就分别生成两份配置。", 14, true));
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        if (!HasOutput(draft)) throw new OperationException("请至少选择一个生成目标。");
        if (draft.Text("Name").Length is < 1 or > 100 || draft.Text("Name").Any(char.IsControl)) throw new OperationException("方案名称应为 1–100 个可打印字符。");
        scheme = draft; schemeBaseline = ""; designerStep = 1; Navigate("clients");
    }
    private async Task<bool> ExitScheme(bool navigate = true)
    {
        if (SchemeChanged)
        {
            var dialog = new ContentDialog { XamlRoot = shell.XamlRoot, Title = "保存方案修改？", Content = Text("此方案还有未保存的修改。"), PrimaryButtonText = "保存并退出", SecondaryButtonText = "放弃修改", CloseButtonText = "继续编辑" };
            var result = await ShowDialog(dialog); if (result == ContentDialogResult.None) return false; if (result == ContentDialogResult.Primary) SaveScheme();
        }
        scheme = null; schemeBaseline = ""; designerStep = 0; if (navigate) Navigate("clients"); return true;
    }
    private async Task DeleteScheme(JsonObject saved)
    {
        if (!await ConfirmAsync(new("删除配置方案", "删除“" + saved.Text("Name") + "”及其本地候选文件。已导出的配置文件和导出恢复记录保留。"), CancellationToken.None)) return;
        workbench.Delete(saved); Navigate("clients"); Show("方案已删除。", InfoBarSeverity.Success);
    }
    private void DirtyScheme() { scheme!.Remove("Candidate"); Navigate("clients"); }
    private void Clients()
    {
        if (scheme == null)
        {
            page.Children.Add(Card(Trailing(SectionHeading("连接配置设计", Symbol.Link, "点亮需要的配置目标，设计节点、连接与分组。"), Action("创建方案", CreateScheme, true))));
            var saved = workbench.List().ToArray();
            if (saved.Length == 0) page.Children.Add(Card(Column(Text("从一个方案开始", 18), Text("选择生成目标，添加节点，再直观地组织入口与落地。", 14, true))));
            else
            {
                page.Children.Add(GroupLabel("已保存的方案"));
                page.Children.Add(SettingsGroup(saved.Select(s => (UIElement)SettingRow(s.Text("Name"), ClientSchemes.OutputLabel(s) + " · " + s["Nodes"]!.AsArray().Count + " 个节点", Symbol.Link, Row(Action("打开", () => { OpenScheme(s); return Task.CompletedTask; }), Action("删除", () => DeleteScheme(s))))).ToArray()));
            }
            return;
        }
        var name = Field("方案名称", scheme, "Name"); name.MaxWidth = 450; name.HorizontalAlignment = HorizontalAlignment.Left;
        page.Children.Add(Trailing(Column(name, Text(ClientSchemes.OutputLabel(scheme) + (SchemeChanged ? " · 有未保存的修改" : " · 已保存"), 14, true)), Row(Action("保存方案", () => { SaveScheme(); Navigate("clients"); Show("方案已保存。", InfoBarSeverity.Success); return Task.CompletedTask; }), Action("退出编辑", async () => { await ExitScheme(); }))));
        var steps = new Grid { ColumnSpacing = 8, RowSpacing = 8 };
        foreach (var _ in Enumerable.Range(0, 4)) steps.ColumnDefinitions.Add(new());
        foreach (var (label, index) in new[] { "目标", "节点", "连接与分组", "生成与导出" }.Select((label, index) => (label, index)))
        {
            var button = Action((index + 1) + " · " + label, () => { designerStep = index; Navigate("clients"); return Task.CompletedTask; });
            button.Content = Text((index + 1) + " · " + label); button.Tag = "DesignerStep." + index; button.HorizontalAlignment = HorizontalAlignment.Stretch; button.Padding = new Thickness(8, 12, 8, 12);
            button.IsEnabled = index == 0 || HasOutput(scheme);
            if (designerStep == index) { button.Background = Brush(Paint.Info); button.BorderBrush = Brush(Paint.Accent); button.Foreground = Brush(Paint.Text); }
            Grid.SetColumn(button, index); steps.Children.Add(button);
        }
        page.Children.Add(steps);
        switch (designerStep) { case 0: DesignerTargets(); break; case 1: DesignerNodes(); break; case 2: DesignerConnections(); break; default: DesignerExport(); break; }
        if (designerStep < 3) { var next = Action("下一步：" + new[] { "添加节点", "连接与分组", "生成与导出" }[designerStep], () => { designerStep++; Navigate("clients"); return Task.CompletedTask; }, true); next.IsEnabled = HasOutput(scheme); pageAction.Content = next; }
    }
    private static bool HasOutput(JsonObject model) => model.Text("OutputClients", "Both") is "SingBox" or "Clash" or "Both";
    private static Grid OutputSelection(JsonObject model, System.Action? changed = null)
    {
        var grid = new Grid { ColumnSpacing = 12, RowSpacing = 12 };
        grid.ColumnDefinitions.Add(new()); grid.ColumnDefinitions.Add(new());
        var options = new List<ToggleButton>();
        foreach (var (value, label, description) in new[] { ("SingBox", "sing-box", "JSON 配置"), ("Clash", "Clash", "Mihomo / Clash YAML") })
        {
            var selected = model.Text("OutputClients", "Both") is "Both" || model.Text("OutputClients") == value;
            var mark = new SymbolIcon(Symbol.Accept) { Width = 16, Height = 16, Foreground = Brush(Paint.Accent), Visibility = selected ? Visibility.Visible : Visibility.Collapsed };
            var status = Text(selected ? "已选择" : "点击选择", 14, true);
            var header = new Grid { ColumnSpacing = 12 }; header.ColumnDefinitions.Add(new()); header.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); header.Children.Add(Text(label, 18)); Grid.SetColumn(mark, 1); header.Children.Add(mark);
            var option = new ToggleButton { Tag = "OutputClients." + value, IsChecked = selected, Content = Column(header, Text(description, 14, true), status), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch, Padding = new Thickness(18), MinHeight = 116, CornerRadius = new CornerRadius(10), BorderThickness = new Thickness(1), Foreground = Brush(Paint.Text), FontFamily = InterfaceFont };
            foreach (var state in new[] { "", "PointerOver", "Pressed" }) { option.Resources["ToggleButtonBackgroundChecked" + state] = Brush(Paint.Info); option.Resources["ToggleButtonForegroundChecked" + state] = Brush(Paint.Text); option.Resources["ToggleButtonBorderBrushChecked" + state] = Brush(Paint.Accent); }
            AutomationProperties.SetName(option, label + " 生成目标");
            void PaintSelection() { var on = option.IsChecked == true; option.Background = Brush(on ? Paint.Info : Paint.Surface); option.BorderBrush = Brush(on ? Paint.Accent : Paint.Border); status.Text = on ? "已选择" : "点击选择"; mark.Visibility = on ? Visibility.Visible : Visibility.Collapsed; }
            PaintSelection(); options.Add(option); Grid.SetColumn(option, options.Count - 1); grid.Children.Add(option);
            void ChangeSelection(object sender, RoutedEventArgs args)
            {
                model["OutputClients"] = options.All(b => b.IsChecked == true) ? "Both" : options[0].IsChecked == true ? "SingBox" : options[1].IsChecked == true ? "Clash" : "None";
                PaintSelection(); changed?.Invoke();
            }
            option.Checked += ChangeSelection; option.Unchecked += ChangeSelection;
        }
        return grid;
    }
    private void DesignerTargets()
    {
        var selected = scheme!;
        page.Children.Add(SectionHeading("生成哪些配置", Symbol.Document, "点亮 sing-box 或 Clash；两个都点亮就分别生成两份配置。")); page.Children.Add(OutputSelection(selected, DirtyScheme));
        if (!HasOutput(selected)) page.Children.Add(Text("请至少点亮一个生成目标。", 14, true));
        var read = Action("读取现有配置", ReadClientSources); read.IsEnabled = HasOutput(selected);
        page.Children.Add(Card(Column(SectionHeading("基础配置", Symbol.Library, selected.Text("SourceMode") == "ExistingAuthority" ? "沿用读取来源中的规则、DNS 及未编辑的高级配置。" : "使用内置基础模板，自动生成节点和业务分组。"), Row(read, Action("恢复内置模板", () => { var template = ClientSchemes.New(paths); selected["Clash"] = template["Clash"]!.DeepClone(); selected["SingBox"] = template["SingBox"]!.DeepClone(); selected["SourceMode"] = "GenericTemplate"; selected.Remove("SourceFingerprints"); DirtyScheme(); return Task.CompletedTask; })), Text("sing-box 配置可用于兼容的下游客户端，包括 May Route。", 14, true))));
    }
    private void DesignerNodes()
    {
        var nodes = scheme!["Nodes"]!.AsArray();
        page.Children.Add(SectionHeading("添加连接节点", Symbol.Link, "拖动左侧手柄调整顺序；也可使用上下按钮。保存方案和导出的配置沿用此顺序。"));
        var import = Action("导入分享链接", ImportClientLinks); import.Tag = "ClientLinks.Import";
        page.Children.Add(Row(Action("添加受管节点", AddManagedNodes), Action("手动添加", () => EditNode(null)), import));
        var forwarded = Action("添加转发节点", AddForwardedClientNodes); forwarded.Tag = "ClientForwarded.Add"; page.Children.Add(forwarded);
        var inboundNodes = Action("添加独立入站节点", AddInboundClientNodes); inboundNodes.Tag = "ClientInbounds.Add"; page.Children.Add(inboundNodes);
        var subscription = Action("添加订阅来源", AddClientSubscription); subscription.Tag = "ClientSources.Add"; page.Children.Add(subscription); DesignerClientSources();
        DesignerNodeGroups();
        if (nodes.Count == 0) { page.Children.Add(Card(Column(Text("还没有节点", 18), Text("先添加至少一个入口节点。使用落地时，再添加落地节点并选择它连接的入口组。", 14, true)))); return; }
        var rows = new List<UIElement>();
        CancelNodeReorder(); nodeDropRows.Clear(); nodeDragSession = Guid.NewGuid().ToString("N");
        for (var i = 0; i < nodes.Count; i++)
        {
            var index = i; var node = nodes[i]!;
            var up = Action("↑", () => { if (index > 0 && ClientSchemes.MoveNode(scheme!, index, index - 1)) RefreshNodeOrder(); return Task.CompletedTask; }); AutomationProperties.SetName(up, "上移节点"); up.IsEnabled = i > 0;
            var down = Action("↓", () => { if (index < nodes.Count - 1 && ClientSchemes.MoveNode(scheme!, index, index + 2)) RefreshNodeOrder(); return Task.CompletedTask; }); AutomationProperties.SetName(down, "下移节点"); down.IsEnabled = i < nodes.Count - 1;
            var actions = Row(up, down, Action("编辑", () => EditNode(index)), Action("移除", () => RemoveClientNode(index)));
            if (node.Text("Source.Kind") == "Subscription") actions.Children.Add(Action("转为手动", () => DetachClientSourceNode(node.AsObject())));
            rows.Add(ReorderableNodeRow(scheme!, nodes, index, actions));
        }
        page.Children.Add(SettingsGroup(rows.ToArray()));
    }
    private void DesignerConnections()
    {
        var nodes = scheme!["Nodes"]!.AsArray(); var regions = scheme["Layout"]!.Strings("region_groups").Where(r => nodes.Any(n => n!.Text("kind") == "entry" && n.Text("region_group") == r)).ToArray();
        page.Children.Add(SectionHeading("连接关系", Symbol.Link, "以下为方案中的候选路径；客户端决定实际选择。连接地址族与网站出口地址族分别标注。"));
        if (scheme.Flag("OutputRules.Enabled")) page.Children.Add(Text("此处展示源节点关系；导出时另应用筛选、命名和排序，最终节点及顺序请查看生成预览。", 14, true));
        if (regions.Length == 0) page.Children.Add(Card(Column(Text("先添加入口节点", 18), Action("返回节点", () => { designerStep = 1; Navigate("clients"); return Task.CompletedTask; }, true))));
        DesignerTopology();
        var unconnected = nodes.OfType<JsonObject>().Where(n => n.Text("kind") == "landing" && !regions.Contains(n.Text("transit_group"))).Select(n => n.Text("name")).ToArray();
        if (unconnected.Length != 0) page.Children.Add(Card(Column(Text("需要补全连接", 18), Text(string.Join("、", unconnected) + " 尚未连接到有效入口组，请在下方调整连接。", 14, true))));
        var connections = new List<UIElement>();
        foreach (var node in nodes.OfType<JsonObject>())
        {
            var key = node.Text("kind") == "landing" ? "transit_group" : "region_group";
            var choices = node.Text("kind") == "landing" ? regions : scheme["Layout"]!.Strings("region_groups");
            if (choices.Length == 0) continue;
            var choice = Choice("", node, key, choices.Select(r => (r, r)), preserveMissing: true); choice.MinWidth = 180; choice.Tag = "NodeGroup." + node.Text("name");
            choice.SelectionChanged += (_, _) => DirtyScheme(); connections.Add(SettingRow(node.Text("name"), node.Text("kind") == "landing" ? "选择连接的入口组" : "选择归属的入口地区", Symbol.Link, choice));
        }
        if (connections.Count != 0) page.Children.Add(Details("调整连接", SettingsGroup(connections.ToArray())));
        page.Children.Add(SettingsGroup(SettingRow("业务分组", "选择各业务的默认出口", Symbol.List, Action("设置", EditBusinessGroups)), SettingRow("默认出口顺序", "选择优先使用的地区组或落地", Symbol.Sort, Action("调整", EditExitOrder))));
    }
    private void DesignerExport()
    {
        var selected = scheme!; var validated = selected.Text("Candidate.ValidationStatus") == "Passed"; var targets = selected["Targets"]!.AsObject();
        if (!HasOutput(selected)) { page.Children.Add(Text("请先在目标页点亮需要生成的配置。", 14, true)); return; }
        page.Children.Add(Card(SectionHeading("生成与校验", Symbol.Document, ClientSchemes.OutputLabel(selected) + " · " + selected["Nodes"]!.AsArray().Count + " 个节点 · " + (validated ? "已通过核心校验" : selected["Candidate"] == null ? "尚未生成" : selected.Text("Candidate.ValidationStatus") == "Failed" ? "校验未通过" : "待校验"))));
        page.Children.Add(Text("操作顺序：生成配置 → 校验配置 → 通过后审阅并导出。", 16));
        var rules = Action("筛选与命名", EditClientOutputRules); rules.Tag = "ClientOutput.Rules";
        var previewButton = Action("预览与能力报告", PreviewClientOutput); previewButton.Tag = "ClientOutput.Preview";
        var share = Action("分享节点链接", () => ShareClientLinks(selected)); share.Tag = "ClientShare.Open";
        var output = ClientOutputRules.Preview(selected);
        page.Children.Add(Card(Column(Text("输出处理 · " + (selected.Flag("OutputRules.Enabled") ? "已启用" : "沿用源节点"), 17), Row(rules, previewButton, share))));
        foreach (var issue in output.Issues.Where(i => i.Severity == "Error")) page.Children.Add(Text(issue.Message, 14));
        var generate = Action("生成配置", async () => { try { await RunBackground("正在生成配置", async token => await workbench.BuildAsync(selected, token)); RememberScheme(); } finally { Navigate("clients"); } Show("配置已生成，方案已保存。", InfoBarSeverity.Success); }, selected["Candidate"] == null); generate.IsEnabled = selected["Nodes"]!.AsArray().Count > 0 && output.Ready;
        var validate = Action("校验配置", async () => { try { await RunBackground("正在校验配置", async token => await workbench.ValidateAsync(selected, token)); RememberScheme(); } finally { Navigate("clients"); } Show("所选客户端的核心校验通过。", InfoBarSeverity.Success); }, selected["Candidate"] != null && !validated); validate.IsEnabled = selected["Candidate"] != null;
        page.Children.Add(Row(generate, validate)); page.Children.Add(GroupLabel("导出位置"));
        var hint = Text(ClientSchemes.ExportHint(selected), 14); hint.Tag = "ExportPrerequisiteHint";
        var export = Action("审阅并导出", PublishClients, true); export.IsEnabled = ClientSchemes.CanExport(selected);
        foreach (var format in ClientSchemes.Formats(selected))
        {
            var fileField = (Grid)FileField(format == "Clash" ? "Clash YAML 文件" : "sing-box JSON 文件", targets, format, true);
            ((TextBox)fileField.Children[0]).TextChanged += (_, _) => { hint.Text = ClientSchemes.ExportHint(selected); export.IsEnabled = ClientSchemes.CanExport(selected); };
            page.Children.Add(Card(fileField));
        }
        page.Children.Add(Card(hint));
        page.Children.Add(Text("可新建配置文件，或选择已有的独立权威文件。替换前审阅并保留恢复副本，导出后由你自行导入客户端。", 14, true));
        pageAction.Content = export;
    }
}
