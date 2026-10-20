using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private UIElement NetworkPathFields(string relative, JsonObject options, bool entry, Action pathsChanged)
    {
        var peers = store.ListInstances().Where(i => i.RelativePath != relative && i.Plan.Flag("ProtocolInventory.ShadowsocksLanding.Enabled", DeploymentPlans.InitiallyEnabled(i.Plan, "ShadowsocksLanding")) && InstanceLifecycle.Read(store, i.RelativePath, i.Plan).Managed && !InstanceLifecycle.Read(store, i.RelativePath, i.Plan).NeedsRecovery).ToArray();
        if (!entry) options["Topology"] = "Landing";
        else if (NetworkTuning.Topology(options) == "Landing" || NetworkTuning.Topology(options) == "Relay" && peers.Length == 0) options["Topology"] = "Entry";
        var choices = entry ? new List<(string, string)> { ("Entry", "入口代理 · 用户到目标"), ("ForwardOnly", "纯 TCP/IP 转发 · 仅观察") } : [("Landing", "落地代理 · 出站诊断")];
        if (entry && peers.Length > 0) choices.Insert(1, ("Relay", "中转代理 · 经已有落地"));
        var topology = Choice("TCP 角色与测试路径", options, "Topology", choices);
        var description = Text(NetworkTuning.PathDescription(options), 13, true);
        var egressHint = Text("落地访问网站使用的 IP 控制“落地→网站”；下方入口连接地址族控制“本机→VPS”。两项都选双栈时分别测试 4 种组合，共用一份流量预算。", 13, true);
        ComboBox EgressChoice(JsonObject plan)
        {
            if (!NetworkTuning.HasIpv6LandingEgress(plan)) options["PeerEgress"] = "IPv4";
            var choice = Choice("落地访问网站使用的 IP", options, "PeerEgress", NetworkTuning.HasIpv6LandingEgress(plan)
                ? [("Both", "IPv4 和 IPv6 都测"), ("IPv4", "仅 IPv4"), ("IPv6", "仅 IPv6")]
                : [("IPv4", "仅 IPv4")]);
            choice.SelectionChanged += (_, _) => pathsChanged(); return choice;
        }
        var peerPanel = new StackPanel { Spacing = 12 };
        if (entry && peers.Length > 0)
        {
            if (!peers.Any(p => p.RelativePath == options.Text("PeerInstance"))) options["PeerInstance"] = peers[0].RelativePath;
            var peer = Choice("中转后的已有落地（仅读取归档）", options, "PeerInstance", peers.Select(i => (i.RelativePath, i.Plan.Text("Provider") + " / " + i.Plan.Text("Instance"))));
            var families = new StackPanel();
            void RefreshPeer()
            {
                var plan = peers.First(p => p.RelativePath == options.Text("PeerInstance")).Plan;
                if (plan.Text("Server.IPv6") == "") options["PeerFamily"] = "IPv4";
                families.Children.Clear(); families.Children.Add(Fields(
                    Choice("入口 → 落地连接地址族", options, "PeerFamily", plan.Text("Server.IPv6") == "" ? [("IPv4", "IPv4")] : [("IPv4", "IPv4"), ("IPv6", "IPv6")]),
                    EgressChoice(plan)));
                pathsChanged();
            }
            peer.SelectionChanged += (_, _) => RefreshPeer(); RefreshPeer(); peerPanel.Children.Add(peer); peerPanel.Children.Add(families);
        }
        void RefreshPath()
        {
            peerPanel.Visibility = NetworkTuning.Topology(options) == "Relay" ? Visibility.Visible : Visibility.Collapsed;
            egressHint.Visibility = NetworkTuning.Topology(options) is "Landing" or "Relay" ? Visibility.Visible : Visibility.Collapsed;
            description.Text = NetworkTuning.PathDescription(options); pathsChanged();
        }
        topology.SelectionChanged += (_, _) => RefreshPath(); RefreshPath();
        UIElement landingEgress = new StackPanel();
        if (!entry)
        {
            var plan = store.ListInstances().First(i => i.RelativePath == relative).Plan;
            landingEgress = EgressChoice(plan);
        }
        return Card(Column(SectionHeading("优化目标与 TCP 边界", Symbol.Globe, "先降低关键方向重传，再在接近时比较持续吞吐；网页、视频起步与排队延迟同时验收。"),
            Fields(topology, Choice("优化偏好", options, "PriorityDirection", [("Balanced", "双向均衡（默认）"), ("Download", "下载优先 · 同时保护上传"), ("Upload", "上传优先 · 同时保护下载")])), peerPanel, landingEgress, egressHint, description,
            Text("三种模式均测量上传和下载，并分别检查重传和速度；任何方向明显退化均不保留参数。", 13, true),
            Text("中转不能用本机直出推断整条链路；纯转发流量不受本机 TCP 拥塞窗口控制。落地保持 fq + BBR，出站诊断用于定位问题。", 13, true)));
    }
    private (FrameworkElement Content, Action Refresh) NetworkBudgetFields(JsonObject options, ComboBox family)
    {
        if (options.Text("TestSize") is "Light" or "Full") options["TestSize"] = options.Text("TestSize") == "Light" ? "Quick" : "Standard";
        var size = Choice("调优总流量预算", options, "TestSize", [("Quick", "快速 · 128 MiB"), ("Standard", "标准 · 1 GiB（默认）"), ("Deep", "深入 · 4 GiB"), ("Extended", "扩展 · 10 GiB"), ("Maximum", "最大 · 20 GiB"), ("Custom", "自定义 · 不超过 20 GiB")]);
        var custom = Field("自定义总预算（MiB，64–20480）", options, "TrafficBudgetMiB", numeric: true);
        var description = Text("", 13, true);
        void Refresh()
        {
            custom.Visibility = options.Text("TestSize") == "Custom" ? Visibility.Visible : Visibility.Collapsed;
            description.Text = options.Text("TestSize") == "Custom" && (!int.TryParse(options.Text("TrafficBudgetMiB"), out var amount) || amount is < 64 or > NetworkTuning.MaximumFlowBudgetMiB)
                ? "请输入 64–20480 MiB。20 GiB 是整个流程的总预算，双栈与前后复测不能各自再用一份。"
                : NetworkTuning.BudgetDescription(options) + " 本轮所选路径合计时限约 " + NetworkTuning.DurationSeconds(options) * NetworkTuning.SelectedPathCount(options) + " 秒，另加有限 SSH 采集。预算或时间不足时会明确记录覆盖不足。";
        }
        size.SelectionChanged += (_, _) => Refresh(); family.SelectionChanged += (_, _) => Refresh(); custom.TextChanged += (_, _) => Refresh(); Refresh();
        return (Column(size, custom, description), Refresh);
    }
}
