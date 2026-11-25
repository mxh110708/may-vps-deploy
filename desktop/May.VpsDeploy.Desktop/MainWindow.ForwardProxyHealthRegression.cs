using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ForwardProxyHealthRegression(string output)
    {
        if (testSession == null || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("协议健康界面检查仅限后台合成归档。");
        static void Require(bool condition, string text) { if (!condition) throw new OperationException(text); }
        var rule = UdpForwarding.NewRule(); rule["ListenPort"] = 25440; rule["TargetAddress"] = "192.0.2.40"; rule["TargetPort"] = 443; rule["AllowedSources"] = new JsonArray("198.51.100.0/24");
        rule["Validation"] = new JsonObject { ["Type"] = "Shadowsocks", ["SchemeId"] = new string('a', 32), ["NodeId"] = new string('b', 32), ["NodeFingerprint"] = new string('c', 64), ["QueryName"] = "example.com", ["QueryType"] = "A", ["ResolverAddress"] = "1.1.1.1", ["ResolverPort"] = 53 };
        rule["TargetGroup"] = ForwardTargetGroups.New(rule); rule["TargetGroup"]!["BackupAddress"] = "2001:db8::40";
        var config = new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(rule) }; var error = Text("", 13);
        var dialog = OperationDialog("协议健康合成检查", DialogScroll(Column(ForwardGroupEditor(rule, "ProxyHealth40", 0), error)), "检查并审阅");
        dialog.PrimaryButtonClick += (_, args) => { try { UdpForwarding.Normalize(config); } catch (OperationException e) { args.Cancel = true; error.Text = e.Message; } };
        var pending = ShowDialog(dialog); var until = DateTimeOffset.UtcNow.AddSeconds(8);
        while ((activeTestDialog != dialog || !Find<Button>(dialog).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
        var consent = Find<CheckBox>(dialog).Single(c => c.Tag as string == "ProxyHealth40.ProxyHealth.0"); var proof = new JsonObject();
        Require(consent.IsChecked == false, "未取得授权却默认启用凭据探测。"); proof["consent_defaults_off"] = true;
        await RegressionPress(dialog, "PrimaryButton"); Require(activeTestDialog == dialog && error.Text != "", "未授权的加密 UDP 主备未保留表单。"); proof["unauthorized_retains_form"] = true;
        await RegressionToggle(consent, true); Require(rule.Flag("TargetGroup.Health.Consent"), "授权控件未更新实际规则。"); proof["explicit_consent_updates_rule"] = true;
        var exit = Find<TextBox>(dialog).Single(t => t.Header?.ToString()?.StartsWith("主目标预期出口") == true);
        await RegressionFill(exit, "not-an-ip"); await RegressionPress(dialog, "PrimaryButton"); Require(activeTestDialog == dialog && exit.Text == "not-an-ip", "非法出口未保留原输入。"); proof["invalid_exit_retains_input"] = true;
        await RegressionFill(exit, "198.51.100.40");
        await Capture(SafePath.Resolve(output, "proxy-health-form.png"), dialog);
        await RegressionPress(dialog, "PrimaryButton"); Require(await pending == ContentDialogResult.Primary, "修正后未通过真实模型检查。"); proof["corrected_form_validates"] = true;
        var summary = ForwardTargetGroups.Summary(rule);
        Require(summary.Contains("私有保存") && summary.Contains("加密 UDP") && summary.Contains("不回退"), "审阅缺少凭据、实际回程或失败关闭范围。");
        var review = OperationDialog("审阅协议健康范围", DialogScroll(Text(summary, 14, true)), "确认"); var reviewTask = ShowDialog(review);
        until = DateTimeOffset.UtcNow.AddSeconds(8);
        while ((activeTestDialog != review || !Find<Button>(review).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
        await Task.Delay(80);
        await Capture(SafePath.Resolve(output, "proxy-health-review.png"), review);
        await RegressionPress(review, "CloseButton"); Require(await reviewTask != ContentDialogResult.Primary, "取消审阅触发了确认。"); proof["review_and_cancel"] = true;
        Require(testActivations == 0 && testForegroundSamples == 0, "后台检查激活了前台。"); proof["zero_foreground_activity"] = true;
        return proof;
    }
}
