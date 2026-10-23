using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> TcpForwardRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("转发界面回归只允许合成工作区。");
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        Task Press(ContentDialog dialog, string name) => RegressionPress(dialog, name);
        Task Invoke(ContentDialog dialog, string tag) => RegressionInvoke(Find<Button>(dialog).Single(b => b.Tag as string == tag));
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            for (var i = 0; i < 100; i++) { await Task.Delay(25); if (activeTestDialog != null && activeTestDialog != old) { await Task.Delay(70); return activeTestDialog; } }
            throw new OperationException("未收到 TCP 转发对话框。");
        }
        static TextBox Input(ContentDialog dialog, string tag) => Find<TextBox>(dialog).Single(c => c.Tag as string == tag);
        var previous = selectedInstance; var template = store.ListInstances().First(); var plan = template.Plan.DeepClone().AsObject();
        plan["Provider"] = "Example"; plan["Instance"] = "Round8-" + Guid.NewGuid().ToString("N")[..8]; plan.Remove("TcpForwarding");
        var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative); plan.Put("Paths.Archive", JsonValue.Create(directory));
        var state = InstanceState(template.RelativePath).DeepClone().AsObject(); state.Remove("TcpForwarding");
        var file = SafePath.Resolve(directory, "deployment-plan.json"); ArchiveStore.WriteJson(file, plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), new JsonObject());
        var history = new TaskHistory(store).Read().Count; Task? pending = null; var initial = ClientSchemes.SourceFingerprint(file); var originalSize = AppWindow.Size;
        try
        {
            var scale = shell.XamlRoot?.RasterizationScale ?? 1; AppWindow.Resize(new((int)(992 * scale), (int)(688 * scale))); await Task.Delay(100); shell.UpdateLayout();
            selectedInstance = relative; SelectPage("instances"); Require(Find<Button>(shell).Any(b => b.Content as string == "管理转发"), "实例页缺少转发入口。");
            pending = TcpForwardSheet(relative, plan); var form = await Dialog(); await Invoke(form, "TcpForward.Add"); await Task.Delay(50);
            Require(Input(form, "TcpForward.Sources.0").AcceptsReturn && Find<ComboBox>(form).Any(b => b.Tag as string == "TcpForward.Validation.0"), "白名单或实际验收控件缺失。");
            await Press(form, "PrimaryButton"); await Task.Delay(80); Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "TcpForward.Error").Text.Length > 0, "非法转发未保留表单。");
            await RegressionFill(Input(form, "TcpForward.Port.0"), "55001"); await RegressionFill(Input(form, "TcpForward.Target.0"), "192.0.2.20"); await RegressionFill(Input(form, "TcpForward.TargetPort.0"), "443"); await RegressionFill(Input(form, "TcpForward.Sources.0"), "198.51.100.88/24"); await RegressionFill(Input(form, "TcpForward.Sni.0"), "target.example.test");
            await Invoke(form, "TcpForward.Add"); await Task.Delay(50); Require(Find<Button>(form).Count(b => (b.Tag as string)?.StartsWith("TcpForward.Remove.") == true) == 2, "规则没有竖向增加。");
            await Invoke(form, "TcpForward.Remove.1"); await Task.Delay(50); Require(Input(form, "TcpForward.Port.0").Text == "55001", "移除另一规则丢失已有草稿。");
            var visual = Find<Border>(form).Where(b => b.ActualWidth > 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)form;
            await Capture(SafePath.Resolve(output, "tcp-forward-form.png"), visual);
            await Press(form, "PrimaryButton"); var review = await Dialog(form);
            ArchiveStore.WriteJson(SafePath.Resolve(output, "tcp-forward-review.json"), new JsonObject { ["Title"] = review.Title?.ToString(), ["Text"] = new JsonArray(Find<TextBlock>(review).Select(t => (JsonNode?)JsonValue.Create(t.Text)).ToArray()) });
            Require(Find<TextBlock>(review).Any(t => t.Text == "审阅 TCP 转发变更") && Find<TextBlock>(review).Any(t => t.Text.Contains("198.51.100.0/24") && t.Text.Contains("55001") && t.Text.Contains("已有转发连接中断")), "最终审阅缺少规范来源或中断范围。");
            await Press(review, "CloseButton"); await pending; Require(ClientSchemes.SourceFingerprint(file) == initial && new TaskHistory(store).Read().Count == history, "取消审阅仍启动转发任务。");
            pending = TcpForwardSheet(relative, plan); form = await Dialog(); await RegressionSelect(Find<ComboBox>(form).Single(c => c.Tag as string == "TcpForward.Action"), 1); await Press(form, "PrimaryButton"); await Task.Delay(80);
            Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "TcpForward.Error").Text.Contains("尚未配置"), "空实例检查未明确阻止。"); await Press(form, "CloseButton"); await pending;
            var rule = TcpForwarding.NewRule(); rule["ListenPort"] = 55001; rule["TargetAddress"] = "192.0.2.20"; rule["TargetPort"] = 22; rule["AllowedSources"] = new JsonArray("198.51.100.0/24"); rule["Validation"] = new JsonObject { ["Type"] = "Ssh" };
            var saved = TcpForwarding.Empty(); saved["Rules"]!.AsArray().Add(rule); plan["TcpForwarding"] = saved; state["TcpForwarding"] = new JsonObject { ["RemoteHash"] = new string('a', 64) };
            ArchiveStore.WriteJson(file, plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); var savedHash = ClientSchemes.SourceFingerprint(file);
            pending = TcpForwardSheet(relative, plan); form = await Dialog(); Require(Input(form, "TcpForward.Port.0").Text == "55001" && Find<ComboBox>(form).Single(c => c.Tag as string == "TcpForward.Validation.0").SelectedIndex == 1, "已保存规则未正确回填。");
            await RegressionSelect(Find<ComboBox>(form).Single(c => c.Tag as string == "TcpForward.Action"), 2); await Press(form, "PrimaryButton"); review = await Dialog(form);
            Require(Find<TextBlock>(review).Any(t => t.Text.Contains("移除当前实例全部受管 TCP 转发")), "移除审阅未明确组件范围。"); await Press(review, "CloseButton"); await pending;
            Require(ClientSchemes.SourceFingerprint(file) == savedHash && taskCancellation == null && new TaskHistory(store).Read().Count == history, "移除审阅取消仍改变配置。");
            return new() { ["instance_entry"] = true, ["whitelist_application_controls"] = true, ["invalid_keeps_form"] = true, ["vertical_add_remove"] = true, ["draft_preserved"] = true, ["normalized_scoped_review"] = true, ["cancel_no_task"] = true, ["absent_check_guard"] = true, ["saved_rule_refill"] = true, ["remove_review_cancel"] = true };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(80); }
            if (pending != null) { try { await pending.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationException) { } }
            var deletion = new InstanceDeletion(store); deletion.Delete(deletion.Review(relative)); selectedInstance = previous; AppWindow.Resize(originalSize); SelectPage("instances");
        }
    }
}
