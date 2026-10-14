using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private readonly Dictionary<string, JsonObject> networkForms = new();
    private void NetworkPage()
    {
        var instances = store.ListInstances().Where(instance => { var status = InstanceLifecycle.Read(store, instance.RelativePath, instance.Plan); return status.Managed; }).ToArray();
        if (instances.Length == 0) { page.Children.Add(Card(Column(SectionHeading("选择已部署的实例", Symbol.Globe, "部署完成或接入已有 VPS 后，可以单独进行网络配置。"), Action("查看实例", () => { SelectPage("instances"); return Task.CompletedTask; })))); return; }
        var selection = new JsonObject { ["Instance"] = instances.Any(i => i.RelativePath == selectedInstance) ? selectedInstance : instances[0].RelativePath };
        var picker = Choice("目标实例", selection, "Instance", instances.Select(i => (i.RelativePath, i.Plan.Text("Provider") + " / " + i.Plan.Text("Instance"))), preventWheelSelection: true);
        page.Children.Add(picker); var panel = new StackPanel { Spacing = 20 }; page.Children.Add(panel);
        void Refresh()
        {
            selectedInstance = selection.Text("Instance"); var relative = selectedInstance; var plan = instances.First(i => i.RelativePath == relative).Plan;
            var directory = paths.Instance(relative); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); panel.Children.Clear();
            var entry = NetworkTuning.IsEntry(plan);
            panel.Children.Add(Card(SectionHeading(plan.Text("NodeName"), Symbol.World, entry ? "入口 / 中转：按关键方向采集路径与 TCP 证据，保护短连接起步，应用后复测。" : "落地机：只启用 fq 与可用 BBR，可额外只读诊断出站稳定性。")));
            var runtime = state.At("LastNetworkComparison.VerifiedRuntime") as JsonObject ?? state.At("NetworkTuning.AppliedRuntime") as JsonObject;
            if (runtime != null) panel.Children.Add(Card(Column(Text("上次已核验的运行配置", 17), Text("拥塞控制：" + NetworkTuning.Sysctl(runtime, "net.ipv4.tcp_congestion_control") + " · BBR 版本：" + (runtime.Text("BbrVersion") == "VersionUnverified" ? "未确认" : runtime.Text("BbrVersion"))), Text("记录时间：" + NetworkTime(state.Text("LastNetworkComparison.At", state.Text("NetworkTuning.At"))) + "；当前状态可通过重新采集核对。", 13, true))));
            KernelPanel(panel, relative, state);
            if (InstanceLifecycle.Read(store, relative, plan).NeedsRecovery) { pageAction.Content = null; return; }
            if (!entry && !plan.Flag("ProtocolInventory.ShadowsocksLanding.Enabled", DeploymentPlans.InitiallyEnabled(plan, "ShadowsocksLanding")))
            {
                panel.Children.Add(Card(Column(SectionHeading("基础网络配置", Symbol.Setting), Text("启用 fq 与可用 BBR，核验真实接口队列，并保留恢复点。缓冲区、TFO 等参数沿用当前值。", 14, true))));
                pageAction.Content = Action("审阅并启用 fq + BBR", () => Submit(new(OperationKind.TuneNetwork, relative, new JsonObject { ["Scope"] = "Network", ["Profile"] = "LandingBasic", ["BbrVersion"] = BbrChoice(relative) })), true); return;
            }
            if (!networkForms.TryGetValue(relative, out var options)) networkForms[relative] = options = NetworkTuning.Defaults(plan);
            var protocols = (entry ? DeploymentPlans.Roles[..2] : ["ShadowsocksLanding"]).Where(role => plan.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.InitiallyEnabled(plan, role))).Select(role => (role, RoleLabel(role))).ToArray();
            if (!protocols.Any(pair => pair.role == options.Text("Protocol"))) options["Protocol"] = protocols.First().role;
            panel.Children.Add(NetworkPathFields(relative, options, entry));
            var family = Choice("入口连接地址族", options, "Family", plan.Text("Server.IPv6") == "" ? [("IPv4", "IPv4")] : [("Both", "IPv4 + IPv6 · 分别测量和验收"), ("IPv4", "仅 IPv4"), ("IPv6", "仅 IPv6")]);
            panel.Children.Add(Card(Column(SectionHeading("套餐与测试路径", Symbol.Link, "只填写套餐信息。RTT、吞吐和资源状况由应用采集；标称带宽不会用测速结果替代。"),
                Fields(Field("标称下载带宽（Mbps，未知留空）", options, "BandwidthMbps", numeric: true), Field("标称上传带宽（Mbps，未知留空）", options, "UploadMbps", numeric: true)),
                Fields(Choice("带宽类型", options, "CapacityType", [("Unknown", "未知"), ("Shared", "共享"), ("Dedicated", "独享"), ("Burst", "突发")]), Choice("所选入口协议", options, "Protocol", protocols)),
                Fields(family, NetworkBudgetFields(options, family)))));
            panel.Children.Add(NetworkTimeFields(options));
            panel.Children.Add(Row(Action("采集并生成建议", () => Submit(new(OperationKind.MeasureNetwork, relative, options)), true), Action("审阅晚高峰补测", () => ScheduleNetwork(relative, options))));
            panel.Children.Add(Text(NetworkTuning.ComparisonPolicyDescription, 14, true));
            panel.Children.Add(Text("测速走隔离代理，不占用鼠标、不切换系统代理。下载与短连接覆盖 Cloudflare / Hetzner，上传公共端点覆盖有限时只给基础建议。有效载荷受预算限制，TLS、协议及重传流量另计；UDP 只取 5 个可用性样本。", 14, true));
            ShowNetworkSchedule(panel, directory);
            JsonObject? report = null;
            if (state.Text("LastNetworkMeasurement.Id") != "")
            {
                report = NetworkTuning.ReadReport(directory, state.Text("LastNetworkMeasurement.Id"));
                report["Analysis"] = NetworkTuning.Analyze(report, NetworkTuning.History(directory));
            }
            if (report != null) panel.Children.Add(NetworkReportCard(report));
            var kernelChanged = report != null && state.Text("KernelUpgrade.Runtime.Kernel") != "" && state.Text("KernelUpgrade.Runtime.Kernel") != report.Text("ServerAfter.Kernel");
            var oldObservation = report != null && (report.Text("ServerAfter.BootId") == "" || report.Text("Client.EvidencePolicy") != NetworkTuning.EvidencePolicy);
            if (kernelChanged) panel.Children.Add(Text("内核已经更换，此记录不能继续用于精细建议。请重新采集；现在仍可审阅 fq + BBR 基础配置。", 14, true));
            if (oldObservation) panel.Children.Add(Text("此测量来自旧版采集，缺少新版方向和短连接证据。请重新采集；基础 fq + BBR 仍可单独应用。", 14, true));
            var apply = new JsonObject { ["Scope"] = "Network", ["Profile"] = entry ? "EntryBasic" : "LandingBasic" };
            if (report != null && !kernelChanged && !oldObservation && report.Text("Analysis.Profile") == "EntryMeasured")
            {
                apply["Profile"] = "EntryMeasured"; apply["MeasurementId"] = report.Text("Id");
                apply["MeasurementSha256"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "network-measurements/" + report.Text("Id") + ".json"));
            }
            panel.Children.Add(Text(apply.Text("Profile") == "EntryMeasured" ? "已有自动采集建议。审阅后应用，并以同一路径复测；没有明确收益则恢复原值。建议超过 24 小时或协议变化后需重新采集。" : "未取得足够依据时可先使用 fq + BBR 基础配置；不会猜测 RTT 或盲目扩大缓冲。", 14, true));
            var comparison = state.At("LastNetworkComparison") as JsonObject;
            if (comparison?.Text("BeforeId") is { Length: > 0 } beforeId && comparison.Text("AfterId") is { Length: > 0 } afterId)
            {
                var before = NetworkTuning.ReadReport(directory, beforeId); var after = NetworkTuning.ReadReport(directory, afterId);
                panel.Children.Add(Card(Column(Text("应用前后对比", 17), NetworkMetrics(before, after), Text(ComparisonLabel(comparison.Text("Result")) + (comparison.Flag("RestoredOriginal") ? "；已恢复原运行值与队列。" : "；已保留本次配置。"), 14), Text(comparison.Text("Decision.Reason", "此记录来自旧版判定；新复测会显示丢包参考与速度的具体取舍。"), 13, true))));
            }
            if (apply.Text("Profile") == "EntryMeasured") panel.Children.Add(Action("只应用 fq + BBR 基础配置", () => Submit(new(OperationKind.TuneNetwork, relative, new JsonObject { ["Scope"] = "Network", ["Profile"] = "EntryBasic", ["BbrVersion"] = BbrChoice(relative) }))));
            pageAction.Content = Action(apply.Text("Profile") == "EntryMeasured" ? "审阅并应用建议" : "审阅基础配置", () => { apply["BbrVersion"] = BbrChoice(relative); return Submit(new(OperationKind.TuneNetwork, relative, apply)); }, true);
        }
        picker.SelectionChanged += (_, _) => Refresh(); Refresh();
    }
    private static string NetworkTime(string text) => DateTimeOffset.TryParse(text, out var time) ? time.ToLocalTime().ToString("yyyy-MM-dd HH:mm") : "未知";
    private static string ComparisonLabel(string value) => value switch { "Improved" => "本次路径测得收益", "Regression" => "丢包参考或传输性能退化", "Tradeoff" => "改善伴随其他指标代价", "NoClearGain" => "未测得明确收益", "Inconclusive" => "复测信息不足", _ => "基础配置已核验" };
    private UIElement NetworkReportCard(JsonObject report)
    {
        if (report["Paths"] is JsonArray)
        {
            var group = Column(Text("双栈测量 · " + NetworkTime(report.Text("At")), 17), Text("IPv4 / IPv6 独立结果；共享参数只应用一次，所有选中路径复测通过后才保留。", 13, true));
            foreach (var path in NetworkTuning.PathReports(report)) group.Children.Add(NetworkReportCard(path));
            foreach (var note in report.Strings("Analysis.Notes")) group.Children.Add(Text(note, 13, true));
            return Card(group);
        }
        var capacity = report.Text("Options.CapacityType") switch { "Shared" => "共享", "Dedicated" => "独享", "Burst" => "突发", _ => "未知" };
        var content = Column(Text("最近一次测量 · " + NetworkTime(report.Text("At")), 17), NetworkMetrics(report), Text("协议：" + RoleLabel(report.Text("Options.Protocol")) + " · " + report.Text("Options.Family") + " · 套餐类型：" + capacity, 13, true), Text("关键方向：" + NetworkTuning.DirectionLabel(report["Options"]!.AsObject()), 13, true), Text(NetworkTuning.PathDescription(report["Options"]!.AsObject()), 13, true));
        content.Children.Add(Text("CPU：" + NetworkTuning.Value(report, "ServerAfter.Cpu.BusyPercent").ToString("0.0") + "% · steal：" + NetworkTuning.Value(report, "ServerAfter.Cpu.StealPercent").ToString("0.0") + "% · 内存：" + report.Long("ServerAfter.MemoryKiB") / 1024 + " MiB"));
        foreach (var direction in new[] { "Download", "Upload" })
        {
            var loss = NetworkTuning.DirectionEvidence(report, direction);
            content.Children.Add(Text((direction == "Download" ? "下载" : "上传") + " TCP 重传参考：" + (loss.Flag("Eligible") ? NetworkTuning.Value(loss, "Percent").ToString("0.00", CultureInfo.InvariantCulture) + "%" : "样本不足或计数未确认") + " · 重传 " + loss.Long("RetransmittedSegments") + " / 发送 " + loss.Long("SentSegments") + " 段；匹配 TCP 连接差量，同对端其他业务仍可能干扰。", 13, true));
        }
        if (report.Flag("Analysis.SendBufferLimited")) content.Children.Add(Text("多数样本确认发送缓冲限制；仅考虑发送上限候选，接收缓冲和初始默认内存保持原值。", 13, true));
        content.Children.Add(Text("UDP 小样本：" + report.Number("Client.Udp.Received") + "/" + report.Number("Client.Udp.Sent") + " 收到响应；超时单列，不用于判定整条线路丢包率。", 13, true));
        content.Children.Add(Text("VPS→Cloudflare IPv4 补充测速：" + NetworkTuning.Value(report, "VpsOutbound.Outbound.Mbps").ToString("0.0") + " Mbps · " + (report.Text("VpsOutbound.Outbound.Status") == "Complete" ? "已完成" : "未取得") + "；此值不代替实际入口路径吞吐。", 13, true));
        foreach (var target in (report.At("VpsOutbound.OutboundStability.Targets") as JsonArray ?? []).OfType<JsonObject>())
        {
            var attempts = (target["Attempts"] as JsonArray ?? []).OfType<JsonObject>().ToArray(); var complete = attempts.Where(t => t.Flag("Complete")).ToArray();
            content.Children.Add(Text("VPS 出站 HTTPS · " + target.Text("Endpoint") + "：" + complete.Length + "/" + attempts.Length + " 响应；启动 p95 " + (complete.Length > 0 ? NetworkTuning.Percentile(complete.Select(t => NetworkTuning.Value(t, "Milliseconds")), .95).ToString("0.0") + " ms" : "未取得") + "。仅诊断目标路径，不能据此设全局限速。", 13, true));
        }
        content.Children.Add(Text(report.Text("Client.Status") == "Measured" ? "测量完成；建议未自动应用。" : "测量未完整完成：" + report.Text("Client.SafeFailure", report.Text("Client.LimitReached", "部分传输未完成")), 14));
        foreach (var note in report.Strings("Analysis.Notes")) content.Children.Add(Text(note, 13, true));
        return Card(content);
    }
    private UIElement NetworkMetrics(JsonObject before, JsonObject? after = null)
    {
        if (before["Paths"] is JsonArray)
        {
            var paths = new StackPanel { Spacing = 12 };
            foreach (var path in NetworkTuning.PathReports(before))
            {
                var matched = after == null ? null : NetworkTuning.PathReports(after).SingleOrDefault(p => p.Text("Options.Family") == path.Text("Options.Family"));
                paths.Children.Add(Text(path.Text("Options.Family"), 15)); paths.Children.Add(NetworkMetrics(path, matched));
            }
            return paths;
        }
        var grid = new Grid { ColumnSpacing = 20, RowSpacing = 9 }; grid.ColumnDefinitions.Add(new()); grid.ColumnDefinitions.Add(new()); if (after != null) grid.ColumnDefinitions.Add(new());
        var rows = new[] { ("指标", "", ""), ("下载 TCP 重传参考", "DownloadTcpRetransmitPercent", "%"), ("上传 TCP 重传参考", "UploadTcpRetransmitPercent", "%"), ("下载 · 单连接", "DownloadSingleMbps", " Mbps"), ("下载 · 4 个连接", "DownloadMultiMbps", " Mbps"), ("上传 · 单连接", "UploadSingleMbps", " Mbps"), ("上传 · 4 个连接", "UploadMultiMbps", " Mbps"), ("匹配 TCP RTT", "TcpRttMs", " ms"), ("短连接启动 p95", "StartupP95Ms", " ms"), ("空闲响应 p95", "IdleP95Ms", " ms"), ("传输中响应 p95", "LoadedP95Ms", " ms"), ("响应抖动", "JitterMs", " ms") };
        for (var i = 0; i < rows.Length; i++)
        {
            grid.RowDefinitions.Add(new() { Height = GridLength.Auto });
            var label = Text(rows[i].Item1, 14, i > 0); Grid.SetRow(label, i); grid.Children.Add(label);
            foreach (var (report, column) in after == null ? new[] { (before, 1) } : new[] { (before, 1), (after, 2) })
            {
                var value = i == 0 ? column == 1 ? after == null ? "本次实测" : "应用前" : "应用后" : NetworkTuning.Value(report, "Analysis." + rows[i].Item2) > 0 ? NetworkTuning.Value(report, "Analysis." + rows[i].Item2).ToString("0.0", CultureInfo.InvariantCulture) + rows[i].Item3 : "未取得";
                if (rows[i].Item2.EndsWith("TcpRetransmitPercent", StringComparison.Ordinal)) { var loss = NetworkTuning.DirectionEvidence(report, rows[i].Item2.StartsWith("Upload", StringComparison.Ordinal) ? "Upload" : "Download"); value = loss.Flag("Eligible") ? NetworkTuning.Value(loss, "Percent").ToString("0.00", CultureInfo.InvariantCulture) + "%" : "未取得足够依据"; }
                var text = Text(value); Grid.SetColumn(text, column); Grid.SetRow(text, i); grid.Children.Add(text);
            }
        }
        return grid;
    }
}
