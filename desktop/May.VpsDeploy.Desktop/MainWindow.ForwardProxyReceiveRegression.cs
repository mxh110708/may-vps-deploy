using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ForwardProxyReceiveRegression(string output)
    {
        if (testSession == null || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("可信 PROXY 表单检查仅限隔离合成归档。");
        var proof = new JsonObject();
        void Require(bool condition, string name) { if (!condition) throw new OperationException("可信 PROXY 表单：" + name); proof[name] = true; }
        var rule = TcpForwarding.NewRule(); rule["ListenPort"] = 25442; rule["TargetAddress"] = "192.0.2.20"; rule["TargetPort"] = 443;
        rule["AllowedSources"] = new JsonArray("198.51.100.0/24"); rule["Validation"]!["ServerName"] = "target.example.test"; rule["ProxyProtocol"] = "v2";
        var config = new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(rule) }; var drafts = new Dictionary<string, JsonObject>();
        var plan = new JsonObject { ["Server"] = new JsonObject { ["IPv4"] = "203.0.113.9" } }; var error = Text("", 13);
        var dialog = OperationDialog("可信 PROXY 合成表单检查", DialogScroll(Column(ForwardProxyReceiveEditor(rule, 0, drafts, plan), error)), "检查并审阅");
        dialog.PrimaryButtonClick += (_, args) => { try { TcpForwarding.Normalize(config); } catch (OperationException failure) { error.Text = failure.Message; args.Cancel = true; } };
        var pending = ShowDialog(dialog); var until = DateTimeOffset.UtcNow.AddSeconds(8);
        while ((activeTestDialog != dialog || !Find<Button>(dialog).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
        TextBox Input(string key) => Find<TextBox>(dialog).Single(t => t.Tag as string == "TcpForward.Receive." + key + ".0");
        var enabled = Find<CheckBox>(dialog).Single(c => c.Tag as string == "TcpForward.Receive.Enabled.0");
        Require(rule["ProxyReceive"] == null, "receive_off_by_default");
        await RegressionToggle(enabled, true); Require(rule.Text("ProxyReceive.Protocol") == "Auto" && !rule.Strings("ProxyReceive.TrustedSources").Any(), "enable_has_no_implicit_trusted_relays");
        await RegressionFill(Input("TrustedSources"), "0.0.0.0/0"); await RegressionFill(Input("ClientSources"), "192.0.2.0/24"); await RegressionFill(Input("ProbeSource"), "192.0.2.9");
        await RegressionPress(dialog, "PrimaryButton"); Require(activeTestDialog == dialog && Input("TrustedSources").Text == "0.0.0.0/0" && error.Text != "", "global_trust_refused_without_losing_form");
        await RegressionFill(Input("TrustedSources"), "198.51.100.1/32");
        await RegressionFill(Input("ProbeSource"), "203.0.113.1"); await RegressionPress(dialog, "PrimaryButton"); Require(activeTestDialog == dialog && Input("ProbeSource").Text == "203.0.113.1", "probe_must_match_client_network");
        await RegressionFill(Input("ProbeSource"), "192.0.2.9");
        await RegressionFill(Input("TimeoutSeconds"), "11"); await RegressionPress(dialog, "PrimaryButton"); Require(activeTestDialog == dialog && Input("TimeoutSeconds").Text == "11", "deadline_bound_retains_input");
        await RegressionFill(Input("TimeoutSeconds"), "3");
        var protocol = Find<ComboBox>(dialog).Single(c => c.Tag as string == "TcpForward.Receive.Protocol.0"); await RegressionSelect(protocol, 1);
        Require(rule.Text("ProxyReceive.Protocol") == "v1", "explicit_receive_protocol");
        var draft = rule["ProxyReceive"]!.ToJsonString(); await RegressionToggle(enabled, false); Require(rule["ProxyReceive"] == null, "disable_removes_policy");
        await RegressionToggle(enabled, true); Require(rule["ProxyReceive"]!.ToJsonString() == draft, "toggle_preserves_reviewed_draft");
        var duplicate = ForwardTargetGroups.CopyRule(rule); Require(duplicate.Text("Id") != rule.Text("Id") && JsonNode.DeepEquals(duplicate["ProxyReceive"], rule["ProxyReceive"]), "copy_preserves_policy_and_changes_rule_identity");
        Require(ForwardProxyReceive.Summary(rule).Contains("可信") && ForwardProxyReceive.Summary(rule).Contains("不接受无头直连"), "review_explains_trust_and_direct_rejection");
        await RegressionPress(dialog, "PrimaryButton"); Require(await pending == ContentDialogResult.Primary, "corrected_policy_validates");
        Require(testActivations == 0 && testForegroundSamples == 0, "zero_foreground_activity");
        return proof;
    }
}
