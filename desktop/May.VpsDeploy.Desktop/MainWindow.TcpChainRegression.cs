using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> TcpChainRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("线路界面回归只允许合成工作区。");
        static void Require(bool ok, string message) { if (!ok) throw new OperationException(message); }
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            for (var i = 0; i < 120; i++) { await Task.Delay(25); if (activeTestDialog != null && activeTestDialog != old) { activeTestDialog.UpdateLayout(); if (Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) { await Task.Delay(150); return activeTestDialog; } } }
            throw new OperationException("未收到跨实例线路界面。");
        }
        static TextBox Input(ContentDialog dialog, string tag) => Find<TextBox>(dialog).Single(t => t.Tag as string == "TcpChain." + tag);
        static ComboBox Choice(ContentDialog dialog, string tag) => Find<ComboBox>(dialog).Single(t => t.Tag as string == "TcpChain." + tag);
        static int Index(ComboBox box, string value) => box.Items.Cast<ComboBoxItem>().ToList().FindIndex(i => i.Tag as string == value);
        var originalSelected = selectedInstance; var template = store.ListInstances().First(); var plans = new List<JsonObject>(); var relatives = new List<string>(); var history = new TaskHistory(store).Read().Count; Task? pending = null;
        var sourceScheme = ClientSchemes.New(paths); sourceScheme["Name"] = "Chain UI fixture"; string? chainFile = null; var originalSize = AppWindow.Size;
        try
        {
            for (var i = 0; i < 3; i++)
            {
                var p = template.Plan.DeepClone().AsObject(); p["Provider"] = "Example"; p["Instance"] = "ChainUI-" + i + "-" + Guid.NewGuid().ToString("N")[..6]; p["NodeName"] = "线路测试 " + i; p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Server.IPv4", JsonValue.Create("192.0.2." + (100 + i))); p.Put("Server.IPv6", JsonValue.Create("2001:db8::" + (100 + i))); p.Remove("TcpForwarding"); p.Remove("TcpChain");
                var relative = p.Text("Provider") + "/" + p.Text("Instance") + "/May-VPS-Deploy"; relatives.Add(relative); plans.Add(p); p.Put("Paths.Archive", JsonValue.Create(paths.Instance(relative)));
                ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relative), "deployment-plan.json"), p); ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relative), "deployment-state.json"), new JsonObject { ["Engine"] = "dotnet-v1", ["CurrentManagementPort"] = p.Number("Ports.SshPrimary") });
                store.WriteSecret(SafePath.Resolve(paths.Instance(relative), "secrets.dotnet.private.json"), new JsonObject { ["Xray"] = new JsonObject { ["Uuid"] = Guid.NewGuid().ToString(), ["RealityClientKey"] = ServerConfigurations.RandomKey(32), ["ShortId"] = "abcd1234" } });
            }
            var secret = store.ReadSecret(SafePath.Resolve(paths.Instance(relatives[2]), "secrets.dotnet.private.json")); var pair = ClientProfiles.Nodes(plans[2], secret).First(); secret.Clear();
            var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Chain UI target", ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = pair.Clash.DeepClone(), ["sing_box"] = pair.SingBox.DeepClone(), ["ManagedOrigin"] = ManagedNodeSources.Origin(relatives[2], pair) }; node["clash"]!["name"] = node.Text("name"); node["sing_box"]!["tag"] = node.Text("name"); sourceScheme["Nodes"]!.AsArray().Add(node); workbench.Save(sourceScheme);
            selectedInstance = relatives[0]; SelectPage("instances"); Require(Find<Button>(shell).Any(b => b.Content as string == "管理线路"), "实例页缺少跨实例入口。");
            var scale = shell.XamlRoot?.RasterizationScale ?? 1; AppWindow.Resize(new((int)(1000 * scale), (int)(720 * scale)));
            pending = TcpChainSheet(relatives[0], plans[0]); var form = await Dialog();
            Require((Choice(form,"Family").SelectedItem as ComboBoxItem)?.Tag as string == "IPv4" && (Choice(form,"Transport").SelectedItem as ComboBoxItem)?.Tag as string == "TCP","新建线路默认地址族或传输错误。");
            await RegressionFill(Input(form,"Name"),"保留草稿"); await RegressionSelect(Choice(form,"Family"),1);
            Require(Input(form,"Name").Text=="保留草稿"&&Input(form,"SourceAddress").Text==plans[0].Text("Server.IPv6"),"切换地址族丢失草稿或保留错误前置出口。");
            await RegressionSelect(Choice(form,"Transport"),1);
            Require(!Choice(form,"Landing").Items.Cast<ComboBoxItem>().Any(i=>i.Tag as string==sourceScheme.Text("Id")+":"+node.Text("Id"))&&Find<TextBlock>(form).Any(t=>t.Text.Contains("Hysteria2／TUIC")),"UDP 选择仍包含不适用的 TCP 来源或未说明边界。");
            await Capture(SafePath.Resolve(output,"chain21-udp-form.png"),form);
            await RegressionSelect(Choice(form,"Family"),0);await RegressionSelect(Choice(form,"Transport"),0);
            await RegressionPress(form, "PrimaryButton"); await Task.Delay(100); Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "TcpChain.Error").Text != "", "缺少参与实例仍通过审阅。");
            var relay = Choice(form, "Relay"); await RegressionSelect(relay, Index(relay, relatives[1]));
            var landing = Choice(form, "Landing"); await RegressionSelect(landing, Index(landing, sourceScheme.Text("Id") + ":" + node.Text("Id")));
            await RegressionFill(Input(form, "Name"), "三台实例测试线路"); await RegressionFill(Input(form, "Sources"), "198.51.100.88/24"); await RegressionFill(Input(form, "FrontPort"), "18443"); await RegressionFill(Input(form, "RelayPort"), "18444");
            Require(Input(form, "SourceAddress").Text == plans[0].Text("Server.IPv4") && Find<TextBlock>(form).Any(t => t.Text.Contains(relatives[2]) && t.Text.Contains("落地")), "落地或前置出口没有正确回填。");
            await Capture(SafePath.Resolve(output, "tcp-chain-form.png"), form);
            await RegressionPress(form, "PrimaryButton"); var review = await Dialog(form); var texts = string.Join("\n", Find<TextBlock>(review).Select(t => t.Text));
            Require(texts.Contains("审阅跨实例线路") && relatives.All(texts.Contains) && texts.Contains("198.51.100.0/24") && texts.Contains("/32") && texts.Contains("18443") && texts.Contains("18444") && !texts.Contains(node.Text("sing_box.uuid")), "审阅缺少依赖、端口、规范白名单或泄露凭据。");
            await Capture(SafePath.Resolve(output, "tcp-chain-review.png"), review); await RegressionPress(review, "CloseButton"); await pending;
            Require(new TaskHistory(store).Read().Count == history && relatives.All(r => TcpChains.Plan(store, r)["TcpChain"] == null), "取消线路审阅仍执行或保存依赖。");
            var c = TcpChains.New(relatives[0]); c["Name"] = "已保存线路"; c["RelayInstance"] = relatives[1]; c["LandingInstance"] = relatives[2]; c["FrontSources"] = new JsonArray("198.51.100.0/24"); c["FrontSourceAddress"] = plans[0].Text("Server.IPv4"); c["Landing"] = new JsonObject { ["SchemeId"] = sourceScheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
            for (var i = 0; i < 3; i++)
            {
                var p = plans[i]; p["TcpChain"] = new JsonObject { ["Id"] = c.Text("Id"), ["FrontInstance"] = relatives[0] };
                var state = new JsonObject { ["Engine"] = "dotnet-v1" };
                if (i < 2) { p["TcpForwarding"] = new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(TcpChains.Rule(c, i == 0, plans[i + 1].Text("Server.IPv4"), i == 0 ? c.Number("RelayPort") : node.Number("sing_box.server_port"))) }; state["TcpForwarding"] = new JsonObject { ["RemoteHash"] = new string(i == 0 ? 'a' : 'b', 64), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(p["TcpForwarding"]!) }; }
                ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relatives[i]), "deployment-plan.json"), p); ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relatives[i]), "deployment-state.json"), state);
            }
            var saved = new JsonObject { ["Version"] = 1, ["Configuration"] = c.DeepClone(), ["Phase"] = "Active", ["FrontHash"] = new string('a', 64), ["RelayHash"] = new string('b', 64) }; chainFile = TcpChains.FileName(paths, c.Text("Id")); ArchiveStore.WriteJson(chainFile, saved);
            pending = TcpChainSheet(relatives[1], plans[1]); form = await Dialog(); Require(Choice(form, "Selection").SelectedIndex == 1 && Find<TextBlock>(form).Any(t => t.Text.Contains(relatives[0]) && t.Text.Contains(relatives[2])), "从中转未显示同一条线路。");
            await RegressionSelect(Choice(form, "Selection"), 0); await RegressionFill(Input(form, "Name"), "保留的新建草稿"); var draftLanding = Choice(form, "Landing"); await RegressionSelect(draftLanding, Index(draftLanding, sourceScheme.Text("Id") + ":" + node.Text("Id")));
            await RegressionSelect(Choice(form, "Selection"), 1); await RegressionSelect(Choice(form, "Selection"), 0);
            Require(Input(form, "Name").Text == "保留的新建草稿" && (Choice(form, "Landing").SelectedItem as ComboBoxItem)?.Tag as string == sourceScheme.Text("Id") + ":" + node.Text("Id"), "切换查看线路丢失或隐藏新建草稿的落地选择。");
            await RegressionSelect(Choice(form, "Selection"), 1);
            await RegressionSelect(Choice(form, "Action"), 1); await RegressionPress(form, "PrimaryButton"); review = await Dialog(form); Require(Find<TextBlock>(review).Any(t => t.Text.Contains("移除线路") && t.Text.Contains(relatives[0])), "移除审阅未显示完整线路。"); await RegressionPress(review, "CloseButton"); await pending;
            saved["Phase"] = "NeedsRecovery"; saved["Transaction"] = new JsonObject { ["TaskId"] = Guid.NewGuid().ToString("N") }; ArchiveStore.WriteJson(chainFile, saved);
            pending = TcpChainSheet(relatives[2], plans[2]); form = await Dialog(); Require(Choice(form, "Action").Items.Count == 1 && (Choice(form, "Action").SelectedItem as ComboBoxItem)?.Tag as string == "Recover", "待恢复线路没有统一恢复入口。"); await RegressionPress(form, "PrimaryButton"); review = await Dialog(form); await RegressionPress(review, "CloseButton"); await pending;
            Require(new TaskHistory(store).Read().Count == history && taskCancellation == null, "检查、移除或恢复的取消仍启动了远端任务。");
            var executionRequest = new OperationRequest(OperationKind.TcpChain, relatives[0], new JsonObject { ["Action"] = "Apply", ["Configuration"] = c.DeepClone() });
            ShowExecution(executionRequest); Require(executionRows.Count == 5 && heading.Text == "跨实例线路任务" && Find<TextBlock>(page).Any(t => relatives.All(t.Text.Contains)), "执行页没有完整阶段或三台依赖。");
            var testTask = Guid.NewGuid().ToString("N"); ExecutionProgress(new(testTask, "chain-preflight", 0, 5, "合成进度", "chain-preflight", TaskStepState.Running)); ExecutionProgress(new(testTask, "chain-preflight", 1, 5, "合成进度", "chain-preflight", TaskStepState.Completed)); ExecutionProgress(new(testTask, "chain-backup", 1, 5, "合成失败", "chain-backup", TaskStepState.Failed));
            Require(executionRows["chain-preflight"].State == TaskStepState.Completed && executionRows["chain-backup"].State == TaskStepState.Failed, "执行阶段未显示实际完成及失败状态。");
            FinishExecution(new TaskRecord(testTask, OperationKind.TcpChain, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, TaskOutcome.NeedsRecovery, "chain-backup", "合成恢复提示", InstanceRelativePath: relatives[0])); Require(heading.Text == "跨实例线路结果" && StageLabel("chain-backup") == "建立两台恢复点", "跨实例结果或阶段名称显示错误。");
            await Capture(SafePath.Resolve(output, "tcp-chain-progress.png"), page);
            return new JsonObject { ["entry"] = true, ["required_participants"] = true, ["managed_landing_refill"] = true, ["source_refill"] = true, ["all_dependencies_reviewed"] = true, ["canonical_whitelist"] = true, ["no_auth_in_review"] = true, ["cancel_no_task"] = true, ["shared_route_from_relay"] = true, ["remove_review"] = true, ["recovery_entry"] = true, ["staged_progress"] = true, ["failed_stage_visible"] = true, ["draft_preserved"] = true };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(100); } if (pending != null) try { await pending.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationException) { }
            if (chainFile != null && File.Exists(chainFile)) File.Delete(chainFile);
            foreach (var relative in relatives) { var p = TcpChains.Plan(store, relative); p.Remove("TcpChain"); ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relative), "deployment-plan.json"), p); var deletion = new InstanceDeletion(store); deletion.Delete(deletion.Review(relative)); }
            var schemeFile = ServerOutboundRouting.SchemeFile(paths, sourceScheme.Text("Id")); if (File.Exists(schemeFile)) File.Delete(schemeFile);
            ClearExecution(); selectedInstance = originalSelected; AppWindow.Resize(originalSize); SelectPage("instances");
        }
    }
}
