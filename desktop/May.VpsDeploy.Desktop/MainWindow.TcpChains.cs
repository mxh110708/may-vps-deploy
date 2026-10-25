using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task TcpChainSheet(string relative, JsonObject plan)
    {
        var records = TcpChains.List(store).Where(r => TcpChains.Instances(r["Configuration"]!.AsObject()).Contains(relative))
            .OrderBy(r => TcpChains.Pending(r) ? 0 : r.Text("Phase") == "Active" ? 1 : 2).ThenByDescending(r => r.Text("UpdatedAt"), StringComparer.Ordinal).ToArray();
        var instances = store.ListInstances().Where(i => InstanceLifecycle.Read(store, i.RelativePath, i.Plan).Managed).ToArray();
        var sources = workbench.List().SelectMany(s => (s["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(n => n["ManagedOrigin"] is JsonObject && n.Text("ManagedOrigin.Family") == "IPv4" && n["TcpChainOrigin"] == null && n["ForwardedOrigin"] == null).Select(n => (Scheme: s, Node: n)) ?? []).ToArray();
        var fresh = TcpChains.New(relative); fresh["FrontSourceAddress"] = plan.Text("Server.IPv4");
        var model = new JsonObject { ["Selected"] = records.FirstOrDefault(r => TcpChains.Pending(r) || r.Text("Phase") == "Active")?.Text("Configuration.Id") ?? "New", ["Action"] = "Apply" };
        var selected = Choice("线路", model, "Selected", new[] { ("New", "新建线路（以此实例为前置）") }.Concat(records.Select(r => (r.Text("Configuration.Id"), r.Text("Configuration.Name") + " · " + TcpChains.PhaseLabel(r))))); selected.Tag = "TcpChain.Selection";
        var content = new StackPanel { Spacing = 16 }; var error = Text("", 14, true); error.Tag = "TcpChain.Error";
        JsonObject current = fresh; JsonObject? options = null;
        void Refresh()
        {
            content.Children.Clear(); error.Text = "";
            var record = records.SingleOrDefault(r => r.Text("Configuration.Id") == model.Text("Selected"));
            current = record == null ? fresh : record["Configuration"]!.DeepClone().AsObject();
            model["Action"] = record == null ? "Apply" : TcpChains.Pending(record) ? "Recover" : "Check";
            var operations = record == null ? new[] { ("Apply", "新建并验收线路") } : TcpChains.Pending(record) ? [("Recover", "恢复本次整条线路")] : record.Text("Phase") == "Active" ? [("Check", "只读检查整条线路"), ("Remove", "移除这条线路")] : [("Check", "已结束；请新建线路")];
            var operation = Choice("操作", model, "Action", operations); operation.Tag = "TcpChain.Action"; content.Children.Add(operation);
            if (record != null)
            {
                content.Children.Add(Text(current.Text("FrontInstance") + ":" + current.Number("FrontPort") + "\n↓ TCP\n" + current.Text("RelayInstance") + ":" + current.Number("RelayPort") + "\n↓ TCP\n" + current.Text("LandingInstance"), 16));
                content.Children.Add(Text("前置允许来源：" + string.Join("，", current.Strings("FrontSources")) + "\n中转仅允许：" + current.Text("FrontSourceAddress") + "/32\n最后检查：" + record.Text("LastCheckedAt", record.Text("UpdatedAt")), 14, true));
                content.Children.Add(Text("上次整链代理与 HTTPS 验收：" + (record.Text("Validation.Status") == "Passed" ? "通过" : "尚未通过") + (record.Text("LastCheck.Status") == "Failed" ? "\n最近检查未通过，请重新检查后生成客户端节点。" : ""), 15));
                if (record.At("Validation.Segments") is JsonArray segments)
                    foreach (var segment in segments) content.Children.Add(Text((segment.Text("FromInstance") == current.Text("FrontInstance") ? "前置 → 中转" : "中转 → 落地") + " · TCP " + (segment.Text("Status") == "Connected" ? "已连接" : "未确认") + "（独立于整链代理验收）", 14, true));
                return;
            }
            var name = Field("线路名称", current, "Name"); name.Tag = "TcpChain.Name"; content.Children.Add(name);
            content.Children.Add(Text("前置：" + relative, 15));
            var relay = Choice("中转实例", current, "RelayInstance", instances.Where(i => i.RelativePath != relative).Select(i => (i.RelativePath, i.Plan.Text("NodeName") + " · " + i.RelativePath)), true); relay.Tag = "TcpChain.Relay"; content.Children.Add(relay);
            var landingModel = new JsonObject { ["Node"] = current.Text("Landing.SchemeId") + ":" + current.Text("Landing.NodeId") }; var landingText = Text(current.Text("LandingInstance") == "" ? "请选择落地节点，沿用其鉴权、SNI 与预期出口。" : "落地：" + current.Text("LandingInstance"), 14, true);
            var landing = Choice("落地实例的已有代理节点", landingModel, "Node", sources.Select(s => (s.Scheme.Text("Id") + ":" + s.Node.Text("Id"), s.Node.Text("name") + " · " + s.Node.Text("ManagedOrigin.Instance"))), true); landing.Tag = "TcpChain.Landing";
            landing.SelectionChanged += (_, _) =>
            {
                var source = sources.FirstOrDefault(s => s.Scheme.Text("Id") + ":" + s.Node.Text("Id") == landingModel.Text("Node")); if (source.Node == null) return;
                current["LandingInstance"] = source.Node.Text("ManagedOrigin.Instance"); current["Landing"] = new JsonObject { ["SchemeId"] = source.Scheme.Text("Id"), ["NodeId"] = source.Node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(source.Node) };
                landingText.Text = "落地：" + current.Text("LandingInstance") + " · IPv4:" + source.Node.Number("sing_box.server_port");
            };
            content.Children.Add(landing); content.Children.Add(landingText);
            var frontPort = Field("前置 TCP 端口", current, "FrontPort", numeric: true); frontPort.Tag = "TcpChain.FrontPort";
            var relayPort = Field("中转 TCP 端口", current, "RelayPort", numeric: true); relayPort.Tag = "TcpChain.RelayPort"; content.Children.Add(Fields(frontPort, relayPort));
            var allowed = new TextBox { Header = "前置允许来源（IP / CIDR，每行一个，须包含验收电脑的公网地址）", AcceptsReturn = true, MinHeight = 80, Text = string.Join("\n", current.Strings("FrontSources")), Tag = "TcpChain.Sources" };
            allowed.TextChanged += (_, _) => current["FrontSources"] = new JsonArray(allowed.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()); content.Children.Add(allowed);
            var egress = Field("前置连接中转时的真实 IPv4 出口", current, "FrontSourceAddress"); egress.Tag = "TcpChain.SourceAddress"; content.Children.Add(egress);
            content.Children.Add(Text("中转只允许上述前置出口。仅三台不同的受管实例、IPv4 TCP；落地不安装新协议。外部防火墙须放行相应端口。每台实例限参与一条线路。", 14, true));
        }
        selected.SelectionChanged += (_, _) => Refresh(); Refresh();
        var dialog = OperationDialog("跨实例 TCP 编排", DialogScroll(Column(selected, content, error)), "审阅");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                if (model.Text("Action") == "Apply")
                {
                    var rule = TcpChains.Rule(current, true, "192.0.2.2", 443);
                    var normalized = TcpForwarding.Normalize(new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(rule) }); current["FrontSources"] = normalized["Rules"]![0]!["AllowedSources"]!.DeepClone();
                }
                options = new JsonObject { ["Action"] = model.Text("Action"), ["Configuration"] = current.DeepClone() };
                TcpChains.Prepare(store, new(OperationKind.TcpChain, current.Text("FrontInstance"), options));
            }
            catch (OperationException failure) { error.Text = failure.Message; args.Cancel = true; }
        };
        try { if (await ShowDialog(dialog) == ContentDialogResult.Primary) await Submit(new(OperationKind.TcpChain, current.Text("FrontInstance"), options!)); }
        finally { foreach (var source in sources.Select(s => s.Scheme).Distinct()) source.Clear(); }
    }
}
