using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> WireGuardRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("隧道界面回归只允许合成工作区。");
        static void Require(bool ok, string message) { if (!ok) throw new OperationException(message); }
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            for (var i = 0; i < 120; i++) { await Task.Delay(25); if (activeTestDialog != null && activeTestDialog != old) { activeTestDialog.UpdateLayout(); if (Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) { await Task.Delay(150); return activeTestDialog; } } }
            throw new OperationException("未收到隧道界面。");
        }
        static TextBox Input(ContentDialog dialog, string tag) => Find<TextBox>(dialog).Single(t => t.Tag as string == "WireGuard." + tag);
        static ComboBox Box(ContentDialog dialog, string tag) => Find<ComboBox>(dialog).Single(t => t.Tag as string == "WireGuard." + tag);
        var template = store.ListInstances().First(); var plans = new List<JsonObject>(); var relatives = new List<string>();
        var original = selectedInstance; Task? pending = null; string? recordFile = null; var history = new TaskHistory(store).Read().Count;
        try
        {
            for (var i = 0; i < 2; i++)
            {
                var p = template.Plan.DeepClone().AsObject(); p["Provider"] = "Example"; p["Instance"] = "WireGuardUI-" + i + "-" + Guid.NewGuid().ToString("N")[..6]; p["NodeName"] = "隧道测试 " + i;
                foreach (var key in new[] { "TcpChain", "WireGuardTunnel", "TcpForwarding", "UdpForwarding", "InboundModel" }) p.Remove(key);
                p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Server.IPv4", JsonValue.Create("192.0.2." + (140 + i))); p.Put("Server.IPv6", JsonValue.Create("2001:db8::" + (140 + i)));
                var relative = p.Text("Provider") + "/" + p.Text("Instance") + "/May-VPS-Deploy"; relatives.Add(relative); plans.Add(p); p.Put("Paths.Archive", JsonValue.Create(paths.Instance(relative)));
                ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relative), "deployment-plan.json"), p); ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relative), "deployment-state.json"), new JsonObject { ["Engine"] = "dotnet-v1" });
            }
            selectedInstance = relatives[0]; SelectPage("instances"); Require(Find<Button>(shell).Any(b => b.Content as string == "管理隧道"), "实例页缺少隧道入口。");
            pending = WireGuardSheet(relatives[0], plans[0]); var form = await Dialog(); await RegressionPress(form, "PrimaryButton");
            Require(activeTestDialog == form && Find<TextBlock>(form).Any(t => t.Tag as string == "WireGuard.Error" && t.Text.Length > 0), "缺少第二台时没有阻止审阅。");
            await RegressionFill(Input(form, "Name"), "保留隧道草稿"); await RegressionSelect(Box(form, "Family"), 1);
            Require(Input(form, "Name").Text == "保留隧道草稿", "切换外层地址族丢失草稿。");
            var peer = Box(form, "Peer"); var index = peer.Items.Cast<ComboBoxItem>().ToList().FindIndex(i => i.Tag as string == relatives[1]); await RegressionSelect(peer, index);
            await RegressionPress(form, "PrimaryButton"); var review = await Dialog(form);
            Require(Find<TextBlock>(review).Any(t => relatives.All(t.Text.Contains) && t.Text.Contains("IPv6") && t.Text.Contains("默认路由") && t.Text.Contains("MTU")), "审阅未展示两端和完整范围。");
            await RegressionPress(review, "CloseButton"); await pending;
            Require(new TaskHistory(store).Read().Count == history && taskCancellation == null, "取消审阅仍启动远端任务。");
            var c = WireGuardTunnels.New(relatives[0]); c["SecondInstance"] = relatives[1]; c["Family"] = "IPv6";
            for (var i = 0; i < 2; i++)
            {
                plans[i]["WireGuardTunnel"] = WireGuardTunnels.Peer(c, plans[i], plans[1-i], i == 0); plans[i]["WireGuardTunnel"]!["PublicKey"] = Convert.ToBase64String(Enumerable.Repeat((byte)(i+1),32).ToArray()); plans[i]["WireGuardTunnel"]!["PeerPublicKey"] = Convert.ToBase64String(Enumerable.Repeat((byte)(2-i),32).ToArray());
                ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relatives[i]), "deployment-plan.json"), plans[i]); ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relatives[i]), "deployment-state.json"), new JsonObject { ["Engine"] = "dotnet-v1", ["WireGuardTunnel"] = new JsonObject { ["RemoteHash"] = new string('a', 64) } });
            }
            var saved = new JsonObject { ["Version"] = 1, ["Configuration"] = c.DeepClone(), ["Phase"] = "Active", ["Validation"] = new JsonObject { ["Status"] = "Passed" } }; recordFile = WireGuardTunnels.FileName(paths, c.Text("Id")); ArchiveStore.WriteJson(recordFile, saved);
            pending = WireGuardSheet(relatives[1], plans[1]); form = await Dialog(); Require(Box(form,"Selection").SelectedIndex == 1 && Find<TextBlock>(form).Any(t => relatives.All(t.Text.Contains)), "从第二台没有显示同一隧道。");
            await RegressionSelect(Box(form,"Action"), 1); await RegressionPress(form,"PrimaryButton"); review = await Dialog(form); Require(Find<TextBlock>(review).Any(t => t.Text.Contains("Remove")), "移除未单独审阅。"); await RegressionPress(review,"CloseButton"); await pending;
            saved["Phase"] = "NeedsRecovery"; saved["Transaction"] = new JsonObject { ["TaskId"] = Guid.NewGuid().ToString("N") }; ArchiveStore.WriteJson(recordFile, saved);
            var pendingState = ArchiveStore.ReadJson(SafePath.Resolve(paths.Instance(relatives[1]), "deployment-state.json")); pendingState["WireGuardTunnelTransaction"] = new JsonObject { ["TaskId"] = saved.Text("Transaction.TaskId") }; ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relatives[1]), "deployment-state.json"), pendingState);
            selectedInstance = relatives[1]; SelectPage("instances"); Require(Find<Button>(shell).Any(b => b.Content as string == "恢复两端隧道"), "实例待恢复状态隐藏了双端恢复入口。");
            pending = WireGuardSheet(relatives[1], plans[1]); form = await Dialog(); Require(Box(form,"Action").Items.Count == 1 && (Box(form,"Action").SelectedItem as ComboBoxItem)?.Tag as string == "Recover", "待恢复隧道缺少统一恢复入口。"); await RegressionPress(form,"PrimaryButton"); review = await Dialog(form); await RegressionPress(review,"CloseButton"); await pending;
            var request = new OperationRequest(OperationKind.WireGuardTunnel, relatives[0], new() { ["Action"] = "Apply", ["Configuration"] = c.DeepClone() }); ShowExecution(request);
            Require(executionRows.Count == 5 && heading.Text == "WireGuard 隧道任务" && Find<TextBlock>(page).Any(t => relatives.All(t.Text.Contains)), "隧道执行页丢失阶段或双端范围。");
            Require(new TaskHistory(store).Read().Count == history && taskCancellation == null, "回归意外执行远端操作。");
            await Capture(SafePath.Resolve(output, "wireguard-progress.png"), page);
            return new() { ["entry"] = true, ["required_peer"] = true, ["draft_preserved"] = true, ["both_hosts_reviewed"] = true, ["scope_reviewed"] = true, ["cancel_no_task"] = true, ["shared_record"] = true, ["remove_review"] = true, ["recovery_entry"] = true, ["staged_progress"] = true };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(100); } if (pending != null) try { await pending.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationException) { }
            if (recordFile != null && File.Exists(recordFile)) File.Delete(recordFile);
            foreach (var relative in relatives) { var p = TcpChains.Plan(store,relative); p.Remove("WireGuardTunnel"); ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relative),"deployment-plan.json"),p); var stateFile = SafePath.Resolve(paths.Instance(relative), "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile); state.Remove("WireGuardTunnelTransaction"); ArchiveStore.WriteJson(stateFile, state); var deletion = new InstanceDeletion(store); deletion.Delete(deletion.Review(relative)); }
            ClearExecution(); selectedInstance = original; SelectPage("instances");
        }
    }
}
