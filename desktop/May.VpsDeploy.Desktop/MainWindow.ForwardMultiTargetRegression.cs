using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ForwardMultiTargetRegression(string output)
    {
        if (testSession == null || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("多目标表单检查仅限隔离合成归档。");
        var proof = new JsonObject();
        void Require(bool condition, string name) { if (!condition) throw new OperationException("多目标表单：" + name); proof[name] = true; }
        foreach (var udp in new[] { false, true })
        {
            var rule = udp ? UdpForwarding.NewRule() : TcpForwarding.NewRule(); var label = udp ? "udp" : "tcp";
            rule["ListenPort"] = 25441; rule["TargetAddress"] = "192.0.2.20"; rule["TargetPort"] = 443; rule["AllowedSources"] = new JsonArray("198.51.100.0/24"); rule["Validation"] = new JsonObject { ["Type"] = udp ? "Echo" : "Ssh" };
            var config = new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(rule) }; var error = Text("", 13);
            var dialog = OperationDialog("多目标合成表单检查", DialogScroll(Column(ForwardGroupEditor(rule, "Multi41", 0), error)), "检查并审阅");
            dialog.PrimaryButtonClick += (_, args) => { try { if (udp) UdpForwarding.Normalize(config); else TcpForwarding.Normalize(config); } catch (OperationException e) { args.Cancel = true; error.Text = e.Message; } };
            var pending = ShowDialog(dialog); var until = DateTimeOffset.UtcNow.AddSeconds(8);
            while ((activeTestDialog != dialog || !Find<Button>(dialog).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
            ComboBox Strategy() => Find<ComboBox>(dialog).Single(c => c.Tag as string == "Multi41.GroupStrategy.0");
            TextBox Address(int target) => Find<TextBox>(dialog).Single(t => t.Tag as string == "Multi41.GroupTargetAddress.0." + target);
            CheckBox Enabled() => Find<CheckBox>(dialog).Single(c => c.Tag as string == "Multi41.Group.0");
            await RegressionSelect(Strategy(), 1); shell.UpdateLayout(); await Task.Delay(40);
            await RegressionFill(Address(2), "192.0.2.21");
            await RegressionInvoke(Find<Button>(dialog).Single(b => b.Content?.ToString() == "添加目标（总计最多 8 个）")); shell.UpdateLayout(); await Task.Delay(40);
            await RegressionFill(Address(3), "2001:db8::22");
            var identities = ForwardTargetGroups.TargetIds(rule).ToArray();
            Require(identities.Length == 3 && rule.Text("TargetGroup.Strategy") == "RoundRobin", label + "_add_three_targets");
            await RegressionSelect(Strategy(), 2); shell.UpdateLayout(); await Task.Delay(40);
            Require(rule.Text("TargetGroup.Strategy") == "SourceIpHash" && identities.SequenceEqual(ForwardTargetGroups.TargetIds(rule)), label + "_policy_preserves_identities");
            await RegressionSelect(Strategy(), 0); shell.UpdateLayout(); await Task.Delay(40);
            Require(Strategy().SelectedIndex == 2 && ForwardTargetGroups.Targets(rule).Count() == 3, label + "_failover_does_not_drop_targets");
            await RegressionFill(Address(3), "bad-ip"); await RegressionPress(dialog, "PrimaryButton");
            Require(activeTestDialog == dialog && Address(3).Text == "bad-ip" && error.Text != "", label + "_invalid_retains_form");
            await RegressionFill(Address(3), "2001:db8::22");
            await RegressionToggle(Enabled(), false); Require(rule["TargetGroup"] == null, label + "_disable_removes_group");
            await RegressionToggle(Enabled(), true); Require(identities.SequenceEqual(ForwardTargetGroups.TargetIds(rule)), label + "_toggle_preserves_draft");
            await RegressionToggle(Enabled(), false); await RegressionSelect(Strategy(), 1); shell.UpdateLayout(); await Task.Delay(40);
            Require(identities.SequenceEqual(ForwardTargetGroups.TargetIds(rule)) && rule.Text("TargetGroup.Strategy") == "RoundRobin", label + "_disabled_policy_switch_preserves_draft");
            await RegressionInvoke(Find<Button>(dialog).Where(b => b.Content?.ToString() == "移除此目标").Last()); shell.UpdateLayout(); await Task.Delay(40);
            Require(ForwardTargetGroups.Targets(rule).Count() == 2 && ForwardTargetGroups.TargetIds(rule).Last() == identities[1], label + "_remove_one_target");
            await RegressionPress(dialog, "PrimaryButton"); Require(await pending == ContentDialogResult.Primary, label + "_corrected_form_validates");
            Require(ForwardTargetGroups.Summary(rule).Contains("不回退直连"), label + "_review_has_failure_boundary");
        }
        Require(testActivations == 0 && testForegroundSamples == 0, "zero_foreground_activity");
        // Deliberately no screen capture, global input or external application controls.
        return proof;
    }
}
