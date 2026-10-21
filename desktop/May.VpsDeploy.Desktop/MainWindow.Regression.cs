using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> DesktopRegression(string outputDirectory)
    {
        if (!launchArguments.Contains("--app-root") || !File.Exists(paths.Resolve("qa-ui-review.fixture.json"))) throw new OperationException("交互回归需要显式的隔离工作区。");
        var proof = new JsonObject(); var oldSettings = settings.DeepClone().AsObject(); var oldForm = deploymentForm.DeepClone().AsObject();
        static void Invoke(Button button) => ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke();
        static void Toggle(ToggleButton button) => ((IToggleProvider)new ToggleButtonAutomationPeer(button).GetPattern(PatternInterface.Toggle)).Toggle();
        static void Require(bool passed, string message) { if (!passed) throw new OperationException(message); }
        async Task Respond(Func<Task> action, string buttonName, System.Action<ContentDialog>? inspect = null)
        {
            var pending = action(); ContentDialog? dialog = null;
            for (var i = 0; i < 30 && dialog == null; i++) { await Task.Delay(40); dialog = VisualTreeHelper.GetOpenPopupsForXamlRoot(shell.XamlRoot).SelectMany(p => Find<ContentDialog>(p.Child)).FirstOrDefault(); }
            if (dialog == null) throw new OperationException("隔离对话框未打开。");
            shell.UpdateLayout(); inspect?.Invoke(dialog); Invoke(Find<Button>(dialog).Single(b => b.Name == buttonName)); await pending;
        }
        async Task Shot(string name) { shell.UpdateLayout(); await Task.Delay(120); await Capture(SafePath.Resolve(outputDirectory, name + ".png")); }
        try
        {
            scheme = null; SelectPage("settings"); var toggle = Find<ToggleSwitch>(shell).Single(item => item.Tag as string == "AutoCheckUpdates"); toggle.IsOn = true;
            var appearance = Find<ComboBox>(shell).Single(c => c.Tag as string == "Appearance"); var colors = new JsonArray();
            foreach (var mode in new[] { "Light", "Dark", "Light", "Dark" })
            {
                appearance.SelectedItem = appearance.Items.OfType<ComboBoxItem>().Single(item => item.Tag as string == mode); await Task.Delay(120); shell.UpdateLayout();
                var track = Find<Rectangle>(toggle).Single(r => r.Name == "SwitchKnobBounds");
                Require(track.Fill is SolidColorBrush brush && brush.Color.Equals(DesktopTheme.Color(Paint.Accent)), "开关未随颜色模式往返切换。");
                colors.Add(new JsonObject { ["theme"] = mode, ["rendered_color"] = ((SolidColorBrush)track.Fill).Color.ToString() });
            }
            proof["theme_cycles"] = colors;
            var scroll = Find<ScrollViewer>(shell).First(v => v.Content is StackPanel panel && panel.Children.Contains(pageHost));
            scroll.ChangeView(null, toggle.TransformToVisual((UIElement)scroll.Content).TransformPoint(new(0, 0)).Y - 220, null, true); await Shot("theme-dark-return"); scroll.ChangeView(null, 0, null, true);
            foreach (var role in Enum.GetValues<TypeRole>())
            {
                var choice = Find<ComboBox>(shell).Single(c => c.Tag as string == "FontSize." + role);
                foreach (var size in new[] { "Small", "Medium", "Large" })
                {
                    var beforeTitle = heading.FontSize; var beforeNote = caption.FontSize;
                    choice.SelectedItem = choice.Items.OfType<ComboBoxItem>().Single(item => item.Tag as string == size);
                    Require(ArchiveStore.ReadJson(paths.Resolve("private/desktop-settings.json")).Text("FontSizes." + role) == size, "字号偏好未保存。");
                    if (role == TypeRole.Title) Require(heading.FontSize == DesktopTypography.Size(role, 27) && caption.FontSize == beforeNote, "标题字号影响说明字号。");
                    if (role == TypeRole.Note) Require(caption.FontSize == DesktopTypography.Size(role, 13) && heading.FontSize == beforeTitle, "说明字号影响标题。");
                    if (role == TypeRole.Body) Require(Find<Button>(shell).Single(b => b.Content as string == "检查更新").FontSize == DesktopTypography.Size(role, 13), "功能字号未即时应用。");
                }
            }
            proof["typography_options"] = 12; await Shot("settings-large-text");
            SelectPage("overview"); shell.UpdateLayout(); Require(Find<TextBlock>(shell).Count(t => t.FontSize == DesktopTypography.Size(TypeRole.Metric, 32)) == 2, "统计数字未采用数值字号。");
            SelectPage("settings");
            foreach (var role in Enum.GetValues<TypeRole>()) SetTextSize(role, "Medium");
            var count = workbench.List().Count(); await Respond(CreateScheme, "CloseButton", dialog =>
            {
                var choices = Find<ToggleButton>(dialog).Where(b => (b.Tag as string)?.StartsWith("OutputClients.") == true).ToArray(); Require(choices.Length == 2 && choices.All(b => b.IsChecked == true), "新建方案缺少两个独立生成目标。");
                Toggle(choices[0]); Toggle(choices[1]); Require(!dialog.IsPrimaryButtonEnabled, "未选择生成目标仍允许开始。"); Toggle(choices[1]); Require(dialog.IsPrimaryButtonEnabled, "选择一个生成目标无法开始。");
            }); Require(scheme == null && workbench.List().Count() == count, "取消创建留下空方案。");
            await Respond(CreateScheme, "PrimaryButton"); Require(scheme != null && SchemeChanged && workbench.List().Count() == count, "新建方案未进入可取消的编辑状态。");
            Require(Find<Button>(shell).Any(b => b.Content as string == "退出编辑"), "方案缺少退出入口。");
            await Respond(async () => { await ExitScheme(); }, "CloseButton"); Require(scheme != null, "继续编辑丢失方案。");
            await Respond(async () => { await ExitScheme(); }, "SecondaryButton"); Require(scheme == null && workbench.List().Count() == count, "放弃修改写入了空方案。");
            await Respond(CreateScheme, "PrimaryButton"); scheme!["Name"] = "隔离回归方案"; SaveScheme(); var id = scheme.Text("Id"); await ExitScheme();
            var saved = workbench.List().Single(s => s.Text("Id") == id); Require(Find<Button>(shell).Any(b => b.Content as string == "删除"), "方案列表缺少删除入口。");
            await Respond(() => DeleteScheme(saved), "PrimaryButton"); Require(!workbench.List().Any(s => s.Text("Id") == id), "删除方案未生效。"); proof["scheme_lifecycle"] = true;
            scheme = ClientSchemes.New(paths); scheme["Name"] = "隔离目标选择"; designerStep = 0; SelectPage("clients");
            void ChangeTarget(string format) { designerStep = 0; SelectPage("clients"); Toggle(Find<ToggleButton>(shell).Single(b => b.Tag as string == "OutputClients." + format)); }
            ChangeTarget("Clash"); Require(scheme.Text("OutputClients") == "SingBox", "只点亮 sing-box 未生成单端选择。"); await Shot("designer-target-singbox");
            foreach (var mode in new[] { "SingBox", "None", "Clash", "Both" })
            {
                if (mode == "None")
                {
                    ChangeTarget("SingBox"); Require(!HasOutput(scheme) && pageAction.Content is Button next && !next.IsEnabled && Find<ToggleButton>(shell).Count(b => (b.Tag as string)?.StartsWith("OutputClients.") == true) == 2, "未选目标的边界或卡片数量错误。"); continue;
                }
                if (mode == "Clash") ChangeTarget("Clash"); if (mode == "Both") ChangeTarget("SingBox"); Require(scheme.Text("OutputClients") == mode, "点亮目标的组合不正确。");
                designerStep = 3; SelectPage("clients"); var fields = Find<TextBox>(shell).Select(b => b.Header as string).ToArray();
                Require(fields.Contains("sing-box JSON 文件") == (mode != "Clash") && fields.Contains("Clash YAML 文件") == (mode != "SingBox"), "导出路径未按所选客户端收缩。"); await Shot("designer-export-" + mode.ToLowerInvariant());
            }
            proof["selected_export_fields"] = new JsonArray("SingBox", "Clash", "Both"); proof["independent_output_toggles"] = true; proof["no_output_blocked"] = true;
            scheme["Nodes"] = new JsonArray(new JsonObject { ["name"] = "未连接的落地", ["kind"] = "landing", ["transit_group"] = "无效入口" }); var fingerprint = ArchiveStore.Fingerprint(scheme); designerStep = 2; SelectPage("clients");
            Require(ArchiveStore.Fingerprint(scheme) == fingerprint && Find<TextBlock>(shell).Any(t => t.Text == "需要补全连接"), "显示连接页面时静默改写了落地关系。"); proof["connection_render_readonly"] = true; scheme = null;
            proof["save_path_picker"] = await SavePathPickerRegression();
            proof["client_routes"] = await ClientRoutesRegression(outputDirectory);
            proof["client_output"] = await ClientOutputRegression(outputDirectory);
            proof["server_outbound"] = await ServerOutboundRegression(outputDirectory);
            deploymentForm.Remove("Roles"); deploymentForm["Role"] = "RealityEntry"; deploymentForm["Existing"] = false; SelectPage("deploy");
            Find<CheckBox>(shell).Single(b => b.Tag as string == "Purpose.AnyTlsEntry").IsChecked = true; await Task.Delay(80);
            Find<CheckBox>(shell).Single(b => b.Tag as string == "Purpose.ShadowsocksLanding").IsChecked = true; await Task.Delay(80);
            Require(deploymentForm.Strings("Roles").Length == 3 && Find<ComboBox>(shell).Any(c => c.Header as string == "默认启用的入口"), "多用途选择未保留默认入口。");
            Require(!Find<TextBox>(shell).Any(b => b.Header as string is "套餐标称带宽（Mbps）" or "参考 RTT（ms，可选）"), "新机部署仍要求调优参数。");
            var check = Find<CheckBox>(shell).Single(b => b.Tag as string == "Purpose.RealityEntry"); var fill = Find<Rectangle>(check).Single(r => r.Name == "NormalRectangle").Fill as SolidColorBrush;
            Require(fill != null && fill.Color.Equals(DesktopTheme.Color(Paint.Accent)), "用途选框未使用当前主题色。"); await Shot("deploy-multiple-purposes");
            SelectPage("network"); Require(page.Children.Count > 0 && heading.Text == "网络调优", "网络调优入口不可用。"); await Shot("network-independent"); proof["manual_network_boundary"] = true; proof["multiple_purposes"] = true;
            proof["deployment_experience"] = await DeploymentRegression(outputDirectory);
            proof["window_placement"] = await WindowPlacementRegression(outputDirectory);
            return proof;
        }
        finally
        {
            scheme = null; schemeBaseline = ""; settings.Clear(); foreach (var item in oldSettings) settings[item.Key] = item.Value?.DeepClone(); DesktopTypography.Load(settings); SetAppearance(settings.Text("Appearance", "Dark")); SaveSettings();
            deploymentForm.Clear(); foreach (var item in oldForm) deploymentForm[item.Key] = item.Value?.DeepClone();
        }
    }
}
