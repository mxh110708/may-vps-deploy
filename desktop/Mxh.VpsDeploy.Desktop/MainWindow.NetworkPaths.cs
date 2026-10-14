using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private UIElement NetworkPathFields(string relative, JsonObject options, bool entry)
    {
        var peers = store.ListInstances().Where(i => i.RelativePath != relative && i.Plan.Flag("ProtocolInventory.ShadowsocksLanding.Enabled", DeploymentPlans.InitiallyEnabled(i.Plan, "ShadowsocksLanding")) && InstanceLifecycle.Read(store, i.RelativePath, i.Plan).Managed && !InstanceLifecycle.Read(store, i.RelativePath, i.Plan).NeedsRecovery).ToArray();
        if (!entry) options["Topology"] = "Landing";
        else if (NetworkTuning.Topology(options) == "Landing" || NetworkTuning.Topology(options) == "Relay" && peers.Length == 0) options["Topology"] = "Entry";
        var choices = entry ? new List<(string, string)> { ("Entry", "入口代理 · 用户到目标"), ("ForwardOnly", "纯 TCP/IP 转发 · 仅观察") } : [("Landing", "落地代理 · 出站诊断")];
        if (entry && peers.Length > 0) choices.Insert(1, ("Relay", "中转代理 · 经已有落地"));
        var topology = Choice("TCP 角色与测试路径", options, "Topology", choices, preventWheelSelection: true);
        var description = Text(NetworkTuning.PathDescription(options), 13, true);
        var peerPanel = new StackPanel { Spacing = 12 };
        if (peers.Length > 0)
        {
            if (!peers.Any(p => p.RelativePath == options.Text("PeerInstance"))) options["PeerInstance"] = peers[0].RelativePath;
            var peer = Choice("中转后的已有落地（仅读取归档）", options, "PeerInstance", peers.Select(i => (i.RelativePath, i.Plan.Text("Provider") + " / " + i.Plan.Text("Instance"))), preventWheelSelection: true);
            var families = new StackPanel();
            void RefreshPeer()
            {
                var plan = peers.First(p => p.RelativePath == options.Text("PeerInstance")).Plan;
                if (plan.Text("Server.IPv6") == "") options["PeerFamily"] = "IPv4";
                if (!plan.Flag("Shadowsocks.SecondaryIpv6Enabled")) options["PeerEgress"] = "IPv4";
                families.Children.Clear(); families.Children.Add(Fields(
                    Choice("入口 → 落地连接地址族", options, "PeerFamily", plan.Text("Server.IPv6") == "" ? [("IPv4", "IPv4")] : [("IPv4", "IPv4"), ("IPv6", "IPv6")]),
                    Choice("落地访问目标的出口", options, "PeerEgress", plan.Flag("Shadowsocks.SecondaryIpv6Enabled") && plan.Text("Shadowsocks.SecondaryIpv6Address") != "" ? [("IPv4", "IPv4"), ("IPv6", "IPv6")] : [("IPv4", "IPv4")])));
            }
            peer.SelectionChanged += (_, _) => RefreshPeer(); RefreshPeer(); peerPanel.Children.Add(peer); peerPanel.Children.Add(families);
        }
        void RefreshPath() { peerPanel.Visibility = NetworkTuning.Topology(options) == "Relay" ? Visibility.Visible : Visibility.Collapsed; description.Text = NetworkTuning.PathDescription(options); }
        topology.SelectionChanged += (_, _) => RefreshPath(); RefreshPath();
        UIElement landingEgress = new StackPanel();
        if (!entry)
        {
            var plan = store.ListInstances().First(i => i.RelativePath == relative).Plan;
            if (!plan.Flag("Shadowsocks.SecondaryIpv6Enabled") || plan.Text("Shadowsocks.SecondaryIpv6Address") == "") options["PeerEgress"] = "IPv4";
            landingEgress = Choice("落地访问目标的出口", options, "PeerEgress", plan.Flag("Shadowsocks.SecondaryIpv6Enabled") && plan.Text("Shadowsocks.SecondaryIpv6Address") != "" ? [("IPv4", "IPv4"), ("IPv6", "IPv6")] : [("IPv4", "IPv4")]);
        }
        return Card(Column(SectionHeading("优化目标与 TCP 边界", Symbol.Globe, "先降低关键方向重传，再在接近时比较持续吞吐；网页、视频起步与排队延迟同时验收。"),
            Fields(topology, Choice("关键业务方向", options, "PriorityDirection", [("Download", "用户下载 · VPS 向用户发送"), ("Upload", "用户上传 · VPS 向下一跳发送")])), peerPanel, landingEgress, description,
            Text("中转不能用本机直出推断整条链路；纯转发流量不受本机 TCP 拥塞窗口控制。落地保持 fq + BBR，出站诊断用于定位问题。", 13, true)));
    }
}
