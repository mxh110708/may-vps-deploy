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
        var sources = workbench.List().SelectMany(s => (s["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(n => TcpChains.SourceOrigin(n) != null && n["TcpChainOrigin"] == null && n["ForwardedOrigin"] == null).Select(n => (Scheme: s, Node: n)) ?? []).ToArray();
        var fresh = TcpChains.New(relative); fresh["FrontSourceAddress"] = plan.Text("Server.IPv4");
        var model = new JsonObject { ["Selected"] = records.FirstOrDefault(r => TcpChains.Pending(r) || r.Text("Phase") == "Active")?.Text("Configuration.Id") ?? "New", ["Action"] = "Apply" };
        var selected = Choice("线路", model, "Selected", new[] { ("New", "新建线路（以此实例为前置）") }.Concat(records.Select(r => (r.Text("Configuration.Id"), r.Text("Configuration.Name") + " · " + TcpChains.Transport(r["Configuration"]!.AsObject()) + " · " + TcpChains.PhaseLabel(r))))); selected.Tag = "TcpChain.Selection";
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
                content.Children.Add(Text(TcpChains.Family(current) + " · " + TcpChains.Transport(current) + "\n" + current.Text("FrontInstance") + ":" + current.Number("FrontPort") + "\n↓\n" + current.Text("RelayInstance") + ":" + current.Number("RelayPort") + "\n↓\n" + current.Text("LandingInstance"), 16));
                content.Children.Add(Text("前置允许来源：" + string.Join("，", current.Strings("FrontSources")) + "\n中转仅允许：" + TcpChainUnderlay.RelaySourceDescription(current) + "\n最后检查：" + record.Text("LastCheckedAt", record.Text("UpdatedAt")), 14, true));
                content.Children.Add(Text("上次整链代理与 HTTPS 验收：" + (record.Text("Validation.Status") == "Passed" ? "通过" : "尚未通过") + (record.Text("LastCheck.Status") == "Failed" ? "\n最近检查未通过，请重新检查后生成客户端节点。" : ""), 15));
                content.Children.Add(Text(TcpChainUnderlay.Summary(current), 14, true));
                var shared = TcpChains.Preserved(store, current);
                content.Children.Add(Text(shared.Length == 0 ? "没有其他线路使用本线路的前置／中转实例。" : "共享实例的其他线路：\n" + string.Join("\n", shared.Select(r => r.Text("Configuration.Name") + " · " + TcpChains.Transport(r["Configuration"]!.AsObject()) + " · " + TcpChains.PhaseLabel(r))) + "\n移除本线路保留其他线路及其依赖；修改共享组件前会审阅并复验受影响线路。", 14, true));
                if (record.At("Validation.Segments") is JsonArray segments)
                    foreach (var segment in segments) content.Children.Add(Text((segment.Text("FromInstance") == current.Text("FrontInstance") ? "前置 → 中转" : "中转 → 落地") + (segment.Text("Scope") == "UdpRouteOnly" ? " · UDP 路由可用（不证明回程）" : " · TCP " + (segment.Text("Status") == "Connected" ? "已连接" : "未确认")) + "；整链应用验收单独记录。", 14, true));
                return;
            }
            var name = Field("线路名称", current, "Name"); name.Tag = "TcpChain.Name"; content.Children.Add(name);
            content.Children.Add(Text("前置：" + relative, 15));
            var previousFamily = TcpChains.Family(current);
            var family = Choice("线路地址族", current, "Family", [("IPv4", "IPv4"), ("IPv6", "IPv6")]); family.Tag = "TcpChain.Family";
            var transport = Choice("转发传输", current, "Transport", [("TCP", "TCP · 原生 TCP 代理"), ("UDP", "UDP · Hysteria2 / TUIC 固定端口")]); transport.Tag = "TcpChain.Transport";
            void Changed()
            {
                if (current.Text("FrontSourceAddress") == plan.Text("Server." + previousFamily)) current["FrontSourceAddress"] = plan.Text("Server." + TcpChains.Family(current));
                current["Landing"] = new JsonObject(); current["LandingInstance"] = ""; current.Remove("WireGuard"); Refresh();
            }
            family.SelectionChanged += (_, _) => Changed(); transport.SelectionChanged += (_, _) => Changed(); content.Children.Add(Fields(family, transport));
            var relay = Choice("中转实例", current, "RelayInstance", instances.Where(i => i.RelativePath != relative).Select(i => (i.RelativePath, i.Plan.Text("NodeName") + " · " + i.RelativePath)), true); relay.Tag = "TcpChain.Relay"; content.Children.Add(relay);
            relay.PlaceholderText = "请选择中转实例";
            relay.SelectionChanged += (_, _) => { current.Remove("WireGuard"); Refresh(); };
            var landingModel = new JsonObject { ["Node"] = current.Text("Landing.SchemeId") + ":" + current.Text("Landing.NodeId") }; var landingText = Text(current.Text("LandingInstance") == "" ? "请选择落地节点，沿用其鉴权、SNI 与预期出口。" : "落地：" + current.Text("LandingInstance"), 14, true);
            var available = sources.Where(s => TcpChains.Supports(s.Node, TcpChains.Transport(current), TcpChains.Family(current))).ToArray();
            var landing = Choice("落地实例的已有代理节点", landingModel, "Node", available.Select(s => (s.Scheme.Text("Id") + ":" + s.Node.Text("Id"), s.Node.Text("name") + " · " + TcpChains.SourceOrigin(s.Node)!.Text("Instance"))), true); landing.Tag = "TcpChain.Landing";
            landing.PlaceholderText = available.Length == 0 ? "当前地址族和传输没有可用落地节点" : "请选择已保存的落地节点";
            landing.SelectionChanged += (_, _) =>
            {
                var source = available.FirstOrDefault(s => s.Scheme.Text("Id") + ":" + s.Node.Text("Id") == landingModel.Text("Node")); if (source.Node == null) return;
                current["LandingInstance"] = TcpChains.SourceOrigin(source.Node)!.Text("Instance"); current["Landing"] = new JsonObject { ["SchemeId"] = source.Scheme.Text("Id"), ["NodeId"] = source.Node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(source.Node) };
                landingText.Text = "落地：" + current.Text("LandingInstance") + " · " + TcpChains.Family(current) + ":" + source.Node.Number("sing_box.server_port");
                current.Remove("WireGuard"); Refresh();
            };
            content.Children.Add(landing); content.Children.Add(landingText);
            var underlays = TcpChainUnderlay.Choices(store, current).ToArray();
            var underlayKey = current.Text("WireGuard.Id") + ":" + current.Text("WireGuard.Segment");
            var staleUnderlay = TcpChainUnderlay.Selected(current) && !underlays.Any(u => u.Key == underlayKey && JsonNode.DeepEquals(u.Reference,current["WireGuard"]));
            var underlayModel = new JsonObject { ["Selected"] = staleUnderlay ? "Stale" : TcpChainUnderlay.Selected(current) ? underlayKey : "Direct" };
            var underlayOptions = new[] { ("Direct", "原生直连（现有方式）") }.Concat(staleUnderlay ? [("Stale", "先前选择已变化或不可用，请重新选择")] : Array.Empty<(string,string)>()).Concat(underlays.Select(u => (u.Key, u.Label)));
            var underlay = Choice("实例间连接", underlayModel, "Selected", underlayOptions); underlay.Tag = "TcpChain.Underlay";
            underlay.SelectionChanged += (_, _) =>
            {
                if(underlayModel.Text("Selected")=="Stale")return;
                var choice = underlays.SingleOrDefault(u => u.Key == underlayModel.Text("Selected"));
                if (choice == null) current.Remove("WireGuard"); else current["WireGuard"] = choice.Reference.DeepClone();
                Refresh();
            };
            content.Children.Add(underlay);
            content.Children.Add(Text(underlays.Length == 0 ? "选择相邻实例后，可复用它们之间已验收的 WireGuard 隧道；请先在实例页创建并检查隧道。" : TcpChainUnderlay.Summary(current), 14, true));
            var frontPort = Field("前置 " + TcpChains.Transport(current) + " 端口", current, "FrontPort", numeric: true); frontPort.Tag = "TcpChain.FrontPort";
            var relayPort = Field("中转 " + TcpChains.Transport(current) + " 端口", current, "RelayPort", numeric: true); relayPort.Tag = "TcpChain.RelayPort"; content.Children.Add(Fields(frontPort, relayPort));
            var allowed = new TextBox { Header = "前置允许来源（IP / CIDR，每行一个，须包含验收电脑的公网地址）", AcceptsReturn = true, MinHeight = 80, Text = string.Join("\n", current.Strings("FrontSources")), Tag = "TcpChain.Sources" };
            allowed.TextChanged += (_, _) => current["FrontSources"] = new JsonArray(allowed.Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()); content.Children.Add(allowed);
            var egress = Field("前置连接中转时的真实 " + TcpChains.Family(current) + " 出口", current, "FrontSourceAddress"); egress.Tag = "TcpChain.SourceAddress"; egress.IsEnabled = current.Text("WireGuard.Segment") != "FrontRelay"; content.Children.Add(egress);
            content.Children.Add(Text("中转仅允许：" + TcpChainUnderlay.RelaySourceDescription(current) + "。原生连接段使用所选地址族，WireGuard 段使用隧道内 IPv4；落地须监听该连接地址。落地不安装新协议；UDP 限固定端口 Hysteria2／TUIC，每规则会话上限 256、超时 120 秒，必须验收 HTTPS 和应用 UDP 回程。可复用实例，须使用独立监听端口；修改共享转发组件时既有连接可能短暂重连，并复验受影响线路。", 14, true));
        }
        selected.SelectionChanged += (_, _) => Refresh(); Refresh();
        var dialog = OperationDialog("跨实例线路编排", DialogScroll(Column(selected, content, error)), "审阅");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                if (model.Text("Action") == "Apply")
                {
                    var rule = TcpChains.Rule(current, true, TcpChains.Family(current) == "IPv6" ? "2001:db8::2" : "192.0.2.2", 443);
                    var normalized = TcpChains.NormalizeForwarding(current, new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(rule) }); current["FrontSources"] = normalized["Rules"]![0]!["AllowedSources"]!.DeepClone();
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
