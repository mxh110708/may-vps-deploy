using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> UdpForwardRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("转发界面回归只允许合成工作区。");
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        async Task Press(ContentDialog dialog, string name)
        {
            var clicked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            void OnClick(ContentDialog sender, ContentDialogButtonClickEventArgs args) => clicked.TrySetResult();
            if (name == "PrimaryButton") dialog.PrimaryButtonClick += OnClick; else dialog.CloseButtonClick += OnClick;
            try
            {
                var button = Find<Button>(dialog).Single(b => b.Name == name);
                ((IInvokeProvider)(FrameworkElementAutomationPeer.CreatePeerForElement(button) ?? new ButtonAutomationPeer(button)).GetPattern(PatternInterface.Invoke)).Invoke();
                await clicked.Task.WaitAsync(TimeSpan.FromSeconds(3));
            }
            finally { if (name == "PrimaryButton") dialog.PrimaryButtonClick -= OnClick; else dialog.CloseButtonClick -= OnClick; }
        }
        async Task Invoke(ContentDialog dialog, string tag)
        {
            var button = Find<Button>(dialog).Single(b => b.Tag as string == tag);
            var clicked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            void OnClick(object sender, RoutedEventArgs args) => clicked.TrySetResult();
            button.Click += OnClick;
            try
            {
                ((IInvokeProvider)(FrameworkElementAutomationPeer.CreatePeerForElement(button) ?? new ButtonAutomationPeer(button)).GetPattern(PatternInterface.Invoke)).Invoke();
                await clicked.Task.WaitAsync(TimeSpan.FromSeconds(3));
            }
            finally { button.Click -= OnClick; }
        }
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            for (var i = 0; i < 100; i++) { await Task.Delay(25); if (activeTestDialog != null && activeTestDialog != old) { await Task.Delay(70); return activeTestDialog; } }
            throw new OperationException("未收到 UDP 转发对话框。");
        }
        static TextBox Input(ContentDialog dialog, string tag) => Find<TextBox>(dialog).Single(c => c.Tag as string == tag);
        static async Task Fill(TextBox input, string value)
        {
            if (input.Text == value) return;
            var changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            void OnChange(object sender, TextChangedEventArgs args) => changed.TrySetResult();
            input.TextChanged += OnChange;
            try { input.Text = value; await changed.Task.WaitAsync(TimeSpan.FromSeconds(3)); }
            finally { input.TextChanged -= OnChange; }
        }
        async Task Rejected(ContentDialog dialog, string expected, string message)
        {
            var error = Find<TextBlock>(dialog).Single(t => t.Tag as string == "UdpForward.Error");
            bool Responded() => expected == "" ? error.Text.Length > 0 : error.Text.Contains(expected);
            for (var i = 0; i < 100 && activeTestDialog == dialog && !Responded(); i++) await Task.Delay(25);
            Require(activeTestDialog == dialog && Responded(), message);
        }
        var previous = selectedInstance; var template = store.ListInstances().First(); var plan = template.Plan.DeepClone().AsObject();
        plan["Provider"] = "Example"; plan["Instance"] = "Round9-" + Guid.NewGuid().ToString("N")[..8]; plan.Remove("UdpForwarding");
        var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative); plan.Put("Paths.Archive", JsonValue.Create(directory));
        var state = InstanceState(template.RelativePath).DeepClone().AsObject(); state.Remove("UdpForwarding");
        var file = SafePath.Resolve(directory, "deployment-plan.json"); ArchiveStore.WriteJson(file, plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), new JsonObject());
        var history = new TaskHistory(store).Read().Count; Task? pending = null; JsonObject? proxyScheme = null; var initial = ClientSchemes.SourceFingerprint(file); var originalSize = AppWindow.Size;
        try
        {
            var scale = shell.XamlRoot?.RasterizationScale ?? 1; AppWindow.Resize(new((int)(992 * scale), (int)(688 * scale))); await Task.Delay(100); shell.UpdateLayout();
            selectedInstance = relative; SelectPage("instances"); Require(Find<Button>(shell).Any(b => b.Content as string == "管理 UDP 转发"), "实例页缺少转发入口。");
            pending = UdpForwardSheet(relative, plan); var form = await Dialog(); await Invoke(form, "UdpForward.Add"); await Task.Delay(50);
            Require(Input(form, "UdpForward.Sources.0").AcceptsReturn && Find<ComboBox>(form).Any(b => b.Tag as string == "UdpForward.Validation.0"), "白名单或实际验收控件缺失。");
            await Press(form, "PrimaryButton"); await Rejected(form, "", "非法转发未保留表单。");
            await Fill(Input(form, "UdpForward.Port.0"), "55001"); await Fill(Input(form, "UdpForward.Target.0"), "192.0.2.20"); await Fill(Input(form, "UdpForward.TargetPort.0"), "53"); await Fill(Input(form, "UdpForward.Sources.0"), "198.51.100.88/24"); await Fill(Input(form, "UdpForward.Query.0"), "example.test");
            Require(Input(form, "UdpForward.Timeout.0").Text == "120" && Input(form, "UdpForward.Maximum.0").Text == "256", "UDP 会话限制未正确回填。");
            await Fill(Input(form, "UdpForward.Timeout.0"), "5"); await Press(form, "PrimaryButton"); await Rejected(form, "会话", "非法会话限制未保留表单。"); await Fill(Input(form, "UdpForward.Timeout.0"), "120");
            await Invoke(form, "UdpForward.Add"); await Task.Delay(50); Require(Find<Button>(form).Count(b => (b.Tag as string)?.StartsWith("UdpForward.Remove.") == true) == 2, "规则没有竖向增加。");
            await Invoke(form, "UdpForward.Remove.1"); await Task.Delay(50); Require(Input(form, "UdpForward.Port.0").Text == "55001", "移除另一规则丢失已有草稿。");
            var visual = Find<Border>(form).Where(b => b.ActualWidth > 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)form;
            await Capture(SafePath.Resolve(output, "udp-forward-form.png"), visual);
            await Press(form, "PrimaryButton"); var review = await Dialog(form);
            ArchiveStore.WriteJson(SafePath.Resolve(output, "udp-forward-review.json"), new JsonObject { ["Title"] = review.Title?.ToString(), ["Text"] = new JsonArray(Find<TextBlock>(review).Select(t => (JsonNode?)JsonValue.Create(t.Text)).ToArray()) });
            Require(Find<TextBlock>(review).Any(t => t.Text == "审阅 UDP 转发变更") && Find<TextBlock>(review).Any(t => t.Text.Contains("198.51.100.0/24") && t.Text.Contains("55001") && t.Text.Contains("清空原会话")), "最终审阅缺少规范来源或中断范围。");
            await Press(review, "CloseButton"); await pending; Require(ClientSchemes.SourceFingerprint(file) == initial && new TaskHistory(store).Read().Count == history, "取消审阅仍启动转发任务。");
            pending = UdpForwardSheet(relative, plan); form = await Dialog(); Find<ComboBox>(form).Single(c => c.Tag as string == "UdpForward.Action").SelectedIndex = 1; await Press(form, "PrimaryButton"); await Task.Delay(80);
            Require(activeTestDialog == form && Find<TextBlock>(form).Any(t => t.Text.Contains("尚未配置")), "空实例检查未明确阻止。"); await Press(form, "CloseButton"); await pending;
            var rule = UdpForwarding.NewRule(); rule["ListenPort"] = 55001; rule["TargetAddress"] = "192.0.2.20"; rule["TargetPort"] = 22; rule["AllowedSources"] = new JsonArray("198.51.100.0/24"); rule["Validation"] = new JsonObject { ["Type"] = "Echo" };
            var saved = UdpForwarding.Empty(); saved["Rules"]!.AsArray().Add(rule); plan["UdpForwarding"] = saved; state["UdpForwarding"] = new JsonObject { ["RemoteHash"] = new string('a', 64) };
            ArchiveStore.WriteJson(file, plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); var savedHash = ClientSchemes.SourceFingerprint(file);
            pending = UdpForwardSheet(relative, plan); form = await Dialog(); Require(Input(form, "UdpForward.Port.0").Text == "55001" && Find<ComboBox>(form).Single(c => c.Tag as string == "UdpForward.Validation.0").SelectedIndex == 1, "已保存规则未正确回填。");
            Find<ComboBox>(form).Single(c => c.Tag as string == "UdpForward.Action").SelectedIndex = 2; await Press(form, "PrimaryButton"); review = await Dialog(form);
            Require(Find<TextBlock>(review).Any(t => t.Text.Contains("移除全部受管 UDP 转发")), "移除审阅未明确组件范围。"); await Press(review, "CloseButton"); await pending;
            Require(ClientSchemes.SourceFingerprint(file) == savedHash && taskCancellation == null && new TaskHistory(store).Read().Count == history, "移除审阅取消仍改变配置。");
            proxyScheme = ClientSchemes.New(paths); proxyScheme["Name"] = "UDP 专项合成来源";
            ClientNodeImport.Apply(proxyScheme, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-ui-udp-secret@192.0.2.20:8443#UDP-Proxy-Fixture", proxyScheme, proxyScheme["Layout"]!.Strings("region_groups")[0])); workbench.Save(proxyScheme);
            var proxyPlan = plan.DeepClone().AsObject(); proxyPlan.Remove("UdpForwarding"); pending = UdpForwardSheet(relative, proxyPlan); form = await Dialog(); await Invoke(form, "UdpForward.Add");
            Find<ComboBox>(form).Single(c => c.Tag as string == "UdpForward.Validation.0").SelectedIndex = 2; await Task.Delay(80);
            Require(Input(form, "UdpForward.Resolver.0").Text == "1.1.1.1" && Input(form, "UdpForward.ResolverPort.0").Text == "53" && Input(form, "UdpForward.Query.0").Text == "example.com", "UDP 代理 DNS 默认值未显示。");
            await Fill(Input(form, "UdpForward.Port.0"), "55104"); await Fill(Input(form, "UdpForward.Sources.0"), "198.51.100.88/24");
            await Press(form, "PrimaryButton"); await Rejected(form, "UDP 代理来源", "未选来源仍进入 UDP 代理审阅。");
            var sourceChoice = Find<ComboBox>(form).Single(c => c.Tag as string == "UdpForward.Proxy.0");
            sourceChoice.SelectedIndex = sourceChoice.Items.Cast<ComboBoxItem>().ToList().FindIndex(item => item.Content?.ToString()?.Contains("UDP-Proxy-Fixture") == true); await Task.Delay(50);
            Require(Input(form, "UdpForward.Target.0").Text == "192.0.2.20" && Input(form, "UdpForward.TargetPort.0").Text == "8443", "UDP 代理来源没有填入真实目标。");
            var controls = Find<TextBox>(form).Select(t => t.Text).Concat(Find<TextBlock>(form).Select(t => t.Text)); Require(!controls.Any(t => t.Contains("synthetic-ui-udp-secret")), "UDP 代理凭据进入普通控件。");
            await Fill(Input(form, "UdpForward.Resolver.0"), "224.0.0.1"); await Press(form, "PrimaryButton"); await Rejected(form, "单播", "非法出口 DNS 未留在表单。"); await Fill(Input(form, "UdpForward.Resolver.0"), "1.1.1.1");
            visual = Find<Border>(form).Where(b => b.ActualWidth > 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)form; await Capture(SafePath.Resolve(output, "udp-proxy-form.png"), visual);
            var scroll = Find<ScrollViewer>(form).Where(s => s.IsLoaded && s.ActualWidth > 250 && s.ActualHeight > 100 && s.ScrollableHeight > 0).OrderByDescending(s => s.ActualWidth * s.ActualHeight).First();
            scroll.ChangeView(null, scroll.ScrollableHeight, null, true); await Task.Delay(100); Require(scroll.VerticalOffset > 0, "UDP 代理参数区域无法滚动显示。");
            await Press(form, "PrimaryButton"); review = await Dialog(form);
            Require(Find<TextBlock>(review).Any(t => t.Text.Contains("Shadowsocks UDP") && t.Text.Contains("1.1.1.1:53") && t.Text.Contains("不使用 TCP")) && !Find<TextBlock>(review).Any(t => t.Text.Contains("synthetic-ui-udp-secret")), "UDP 代理审阅丢失实际范围或泄露凭据。");
            ArchiveStore.WriteJson(SafePath.Resolve(output, "udp-proxy-review.json"), new JsonObject { ["Title"] = review.Title?.ToString(), ["Text"] = new JsonArray(Find<TextBlock>(review).Select(t => (JsonNode?)JsonValue.Create(t.Text)).ToArray()) });
            await Press(review, "CloseButton"); await pending;
            Require(ClientSchemes.SourceFingerprint(file) == savedHash && taskCancellation == null && new TaskHistory(store).Read().Count == history, "UDP 代理审阅取消仍保存或执行。");
            var selectedNode = proxyScheme["Nodes"]![0]!.AsObject(); var savedProxy = UdpForwarding.NewRule(); savedProxy["ListenPort"] = 55104; savedProxy["TargetAddress"] = "192.0.2.20"; savedProxy["TargetPort"] = 8443; savedProxy["AllowedSources"] = new JsonArray("198.51.100.0/24");
            savedProxy["Validation"] = new JsonObject { ["Type"] = "Shadowsocks", ["SchemeId"] = proxyScheme.Text("Id"), ["NodeId"] = selectedNode.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(selectedNode), ["ResolverAddress"] = "1.1.1.1", ["ResolverPort"] = 53, ["QueryName"] = "example.com", ["QueryType"] = "A" };
            var savedConfiguration = UdpForwarding.Empty(); savedConfiguration["Rules"]!.AsArray().Add(savedProxy); plan["UdpForwarding"] = savedConfiguration; ArchiveStore.WriteJson(file, plan);
            pending = UdpForwardSheet(relative, plan); form = await Dialog();
            Require(Find<ComboBox>(form).Single(c => c.Tag as string == "UdpForward.Validation.0").SelectedIndex == 2 && Find<ComboBox>(form).Single(c => c.Tag as string == "UdpForward.Proxy.0").SelectedIndex >= 0 && Input(form, "UdpForward.Resolver.0").Text == "1.1.1.1" && Input(form, "UdpForward.TargetPort.0").Text == "8443", "保存的 UDP 代理参数或来源未回填。");
            await Press(form, "CloseButton"); await pending;
            return new() { ["session_limits"] = true, ["invalid_timeout_keeps_form"] = true, ["instance_entry"] = true, ["whitelist_application_controls"] = true, ["invalid_keeps_form"] = true, ["vertical_add_remove"] = true, ["draft_preserved"] = true, ["normalized_scoped_review"] = true, ["cancel_no_task"] = true, ["absent_check_guard"] = true, ["saved_rule_refill"] = true, ["remove_review_cancel"] = true, ["proxy_defaults"] = true, ["proxy_requires_source"] = true, ["proxy_source_target"] = true, ["proxy_no_credential_display"] = true, ["proxy_dns_guard"] = true, ["proxy_scoped_review"] = true, ["proxy_cancel_preserves_archive"] = true, ["proxy_saved_refill"] = true };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(80); }
            if (pending != null) { try { await pending.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationException) { } }
            if (proxyScheme != null) workbench.Delete(proxyScheme);
            var deletion = new InstanceDeletion(store); deletion.Delete(deletion.Review(relative)); selectedInstance = previous; AppWindow.Resize(originalSize); SelectPage("instances");
        }
    }
}
