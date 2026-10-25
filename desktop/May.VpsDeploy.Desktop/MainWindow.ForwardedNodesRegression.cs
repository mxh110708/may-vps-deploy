using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ForwardedNodesRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("转发节点回归只允许合成工作区。");
        static void Require(bool condition, string message) { if (!condition) throw new OperationException(message); }
        async Task<ContentDialog> Dialog(ContentDialog? previous = null)
        {
            for (var i = 0; i < 100; i++) { await Task.Delay(25); if (activeTestDialog != null && activeTestDialog != previous && Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) return activeTestDialog; }
            throw new OperationException("未收到转发节点对话框。");
        }
        var originalScheme = scheme; var originalStep = designerStep;
        var template = store.ListInstances().First(); var plan = template.Plan.DeepClone().AsObject();
        plan["Provider"] = "Example"; plan["Instance"] = "Round11-" + Guid.NewGuid().ToString("N")[..8]; plan["NodeName"] = "测试转发实例";
        plan.Remove("TcpForwarding"); plan.Remove("UdpForwarding");
        var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative);
        plan.Put("Paths.Archive", JsonValue.Create(directory)); plan.Put("Import.Status", JsonValue.Create("Completed"));
        var source = ClientSchemes.New(paths); source["Name"] = "测试转发目标";
        ClientNodeImport.Apply(source, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-forwarded-password@192.0.2.20:443#Target", source, "US-West-LA Entry", "entry")); workbench.Save(source);
        var target = source["Nodes"]![0]!; var configuration = TcpForwarding.Empty(); var rule = TcpForwarding.NewRule();
        rule["ListenPort"] = 55001; rule["TargetAddress"] = "192.0.2.20"; rule["TargetPort"] = 443; rule["AllowedSources"] = new JsonArray("198.51.100.0/24");
        rule["Validation"] = new JsonObject { ["Type"] = "Proxy", ["SchemeId"] = source.Text("Id"), ["NodeId"] = target.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(target) };
        configuration["Rules"]!.AsArray().Add(rule); plan["TcpForwarding"] = configuration;
        var state = new JsonObject { ["Engine"] = "dotnet-v1", ["CurrentManagementPort"] = 22022, ["TcpForwarding"] = new JsonObject { ["RemoteHash"] = new string('a', 64), ["Validation"] = new JsonObject { ["Status"] = "Passed", ["Items"] = new JsonArray(new JsonObject { ["Id"] = rule.Text("Id"), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "ForwardedApplication", ["Checks"] = new JsonArray(new JsonObject { ["Address"] = plan.Text("Server.IPv4"), ["Type"] = "Proxy", ["Status"] = "Passed" }) }) } } };
        void Save() { state["TcpForwarding"]!["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(configuration); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); }
        Save(); store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), new JsonObject());
        var history = new TaskHistory(store).Read().Count; Task? pending = null;
        try
        {
            scheme = ClientSchemes.New(paths); designerStep = 1; Navigate("clients");
            Require(Find<Button>(shell).Any(b => b.Tag as string == "ClientForwarded.Add"), "节点页缺少转发节点入口。");
            pending = AddForwardedClientNodes(); var form = await Dialog();
            var choice = Find<CheckBox>(form).Single(b => (b.Tag as string)?.StartsWith("ClientForwarded.Choice.") == true);
            Require(choice.IsEnabled && !form.IsPrimaryButtonEnabled && !Find<TextBlock>(form).Any(t => t.Text.Contains("synthetic-forwarded-password")), "选择状态或凭据显示边界错误。");
            await Capture(SafePath.Resolve(output, "forwarded-node-picker.png"), form);
            await RegressionPress(form, "CloseButton"); await pending;
            Require(scheme["Nodes"]!.AsArray().Count == 0, "取消转发节点选择仍修改了方案。");
            pending = AddForwardedClientNodes(); form = await Dialog(); choice = Find<CheckBox>(form).Single(b => b.IsEnabled); choice.IsChecked = true;
            await RegressionPress(form, "PrimaryButton"); await pending;
            var node = scheme["Nodes"]![0]!.AsObject(); var id = node.Text("Id");
            Require(!node.Flag("clash.udp", true) && node.Text("sing_box.network") == "tcp" && node.Text("ForwardedOrigin.RuleId") == rule.Text("Id"), "保存丢失来源或错误声明 UDP。");
            pending = EditForwardedClientNode(node); form = await Dialog();
            await RegressionFill(Find<TextBox>(form).Single(t => t.Header as string == "节点名称"), "我的转发");
            Require(!Find<PasswordBox>(form).Any() && !Find<TextBox>(form).Any(t => t.Text == "synthetic-forwarded-password"), "转发节点编辑暴露或重建凭据。");
            await RegressionPress(form, "PrimaryButton"); await pending;
            Require(node.Text("name") == "我的转发" && node.Text("Id") == id, "重命名失去节点身份。");
            rule["ListenPort"] = 55003; Save();
            pending = AddForwardedClientNodes(); form = await Dialog(); Find<CheckBox>(form).Single(b => b.IsEnabled).IsChecked = true;
            await RegressionPress(form, "PrimaryButton"); await pending;
            Require(scheme["Nodes"]!.AsArray().Count == 1 && scheme["Nodes"]![0]!.Text("Id") == id && scheme["Nodes"]![0]!.Text("name") == "我的转发" && scheme["Nodes"]![0]!.Number("sing_box.server_port") == 55003, "更新转发丢失名称或创建了重复节点。");
            var unchanged = ArchiveStore.Fingerprint(scheme);
            pending = AddForwardedClientNodes(); form = await Dialog(); Find<CheckBox>(form).Single(b => b.IsEnabled).IsChecked = true;
            rule["ListenPort"] = 55004; Save(); await RegressionPress(form, "PrimaryButton");
            Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "ClientForwarded.Error").Text.Length > 0 && ArchiveStore.Fingerprint(scheme) == unchanged, "过期选择没有被阻止或部分修改方案。");
            await RegressionPress(form, "CloseButton"); await pending;
            rule["Enabled"] = false; Save(); pending = AddForwardedClientNodes(); form = await Dialog();
            Require(Find<CheckBox>(form).All(b => !b.IsEnabled) && !form.IsPrimaryButtonEnabled, "停用转发仍可选择。");
            await RegressionPress(form, "CloseButton"); await pending;
            Require(new TaskHistory(store).Read().Count == history && taskCancellation == null, "本地节点操作创建了服务器任务。");
            return new() { ["designer_entry"] = true, ["no_credentials"] = true, ["cancel_unchanged"] = true, ["tcp_capability"] = true, ["rename_keeps_identity"] = true, ["update_keeps_name"] = true, ["stale_selection_guard"] = true, ["disabled_unselectable"] = true, ["no_remote_task"] = true };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(80); }
            if (pending != null) { try { await pending.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationException) { } }
            workbench.Delete(source); var deletion = new InstanceDeletion(store); deletion.Delete(deletion.Review(relative));
            scheme = originalScheme; designerStep = originalStep; Navigate("clients");
        }
    }
}
