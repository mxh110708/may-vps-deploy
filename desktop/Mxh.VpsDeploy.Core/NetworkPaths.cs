using System.Globalization;
using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed record NetworkMeasurementPath(ClientProfiles.NodePair Node, ClientProfiles.NodePair? Entry, string ExpectedEgress, string Fingerprint) : IDisposable
{
    public string ObservedInboundAddress { get; set; } = "";
    public void Dispose() { Node.Clash.Clear(); Node.SingBox.Clear(); Entry?.Clash.Clear(); Entry?.SingBox.Clear(); }
}

public static partial class NetworkTuning
{
    public const string EvidencePolicy = "Directional.v2";
    public static string Topology(JsonObject options) => options.Text("Topology", "Entry");
    public static string Priority(JsonObject options) => options.Text("PriorityDirection", "Balanced");
    public static string DirectionLabel(JsonObject options) => Priority(options) switch { "Upload" => "上传优先 · 双向测量并保护下载", "Download" => "下载优先 · 双向测量并保护上传", _ => "双向均衡 · 上传和下载分别验收" };
    public static string PathDescription(JsonObject options) => Topology(options) switch
    {
        "Relay" => "本机 → 所选入口 → 已纳管 Shadowsocks 落地 → 测试目标；只调整入口，不修改落地。",
        "Landing" => "本机 → Shadowsocks 落地 → 测试目标；只读诊断出站稳定性，配置仍限于 fq + BBR。",
        "ForwardOnly" => "纯 TCP/IP 转发：本机拥塞控制不代表转发流量；只读观察，不推导精细参数。",
        _ => "本机 → 所选入口 → 测试目标；VPS 自身出口另列，不能代替实际用户路径。"
    };
    public static string MeasurementSummary(JsonObject options) => "只读采集 VPS 状态。" + PathDescription(options) + "\n关键方向：" + DirectionLabel(options)
        + (Topology(options) == "Relay" ? "\n落地归档：" + options.Text("PeerInstance") : "")
        + (Topology(options) == "ForwardOnly" ? "\n本次只观察转发和本机状态，不发起公网吞吐测试，不推导 TCP 缓冲参数。" : "\n通过隔离代理测试 Cloudflare 与 Hetzner 的有限下载和重复短连接启动；独立目标不足的方向不宣称全局优化通过。不修改系统代理或对端 VPS。\n" + BudgetDescription(options) + "\n地址族：" + string.Join("、", Families(options)) + "；每条路径最长 " + DurationSeconds(options) + " 秒，另加有限 SSH 状态采集。")
        + "\n标称下载/上传：" + options.Number("BandwidthMbps") + "/" + options.Number("UploadMbps") + " Mbps（0 表示未知）；套餐类型：" + options.Text("CapacityType")
        + "。\n使用地时区：" + options.Text("TimeZoneId") + "；高峰：" + options.Number("PeakStartHour") + "–" + options.Number("PeakEndHour") + " 时。结果只代表所选路径与时段。";
    public static string PeerArchiveFingerprint(ArchiveStore store, JsonObject options)
    {
        if (Topology(options) != "Relay") return "";
        var directory = store.Paths.Instance(options.Text("PeerInstance")); var files = new JsonObject();
        foreach (var name in new[] { "deployment-plan.json", "deployment-state.json", "secrets.dotnet.private.json", "deployment-secrets.private.json", "operation-pending.dotnet.json" }) files[name] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, name));
        return ArchiveStore.Fingerprint(files);
    }
    public static NetworkMeasurementPath ResolvePath(ArchiveStore store, JsonObject plan, JsonObject secrets, JsonObject options, string currentInstance)
    {
        ValidateMeasurement(options);
        var node = ClientProfiles.Nodes(plan, secrets, true).SingleOrDefault(n => n.Role == options.Text("Protocol") && n.Family == options.Text("Family") && !n.IsBackup && n.EgressFamily == (Topology(options) == "Landing" ? options.Text("PeerEgress", "IPv4") : "IPv4"))
            ?? throw new OperationException("所选协议或地址族未启用，请重新读取实例。");
        var source = SourceFingerprint(plan, secrets);
        if (Topology(options) != "Relay") return new(node, null, node.EgressFamily == "IPv6" ? plan.Text("Shadowsocks.SecondaryIpv6Address") : plan.Text("Server.IPv4"), source);
        var relative = options.Text("PeerInstance");
        if (relative == currentInstance) throw new OperationException("中转落地不能选择当前实例自身。");
        var directory = store.Paths.Instance(relative);
        var peer = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"));
        if (relative != peer.Text("Provider") + "/" + peer.Text("Instance") + "/MXH-VPS-Deploy" || !InstanceLifecycle.Read(store, relative, peer).Managed || InstanceLifecycle.Read(store, relative, peer).NeedsRecovery || peer.Text("Server.IPv4") == plan.Text("Server.IPv4"))
            throw new OperationException("落地实例身份或受管状态变化，请先核对归档。");
        var secretFile = SafePath.Resolve(directory, "secrets.dotnet.private.json");
        var peerSecrets = File.Exists(secretFile) ? store.ReadSecret(secretFile) : ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-secrets.private.json"));
        try
        {
            var exit = ClientProfiles.Nodes(peer, peerSecrets, true).SingleOrDefault(n => n.Role == "ShadowsocksLanding" && n.Family == options.Text("PeerFamily", "IPv4") && n.EgressFamily == options.Text("PeerEgress", "IPv4"))
                ?? throw new OperationException("所选落地协议、连接地址族或出口地址族未启用。");
            var fingerprint = ArchiveStore.Fingerprint(new JsonObject { ["Entry"] = source, ["Landing"] = SourceFingerprint(peer, peerSecrets), ["Peer"] = relative });
            return new(exit, node, peer.Text(exit.EgressFamily == "IPv6" ? "Shadowsocks.SecondaryIpv6Address" : "Server.IPv4"), fingerprint);
        }
        finally { peerSecrets.Clear(); }
    }

    // No socket that disappears between snapshots is assumed to have zero retransmissions.
    // Only monotonically increasing samples from the same boot and socket cookie are paired.
    public static JsonObject SocketEvidence(IEnumerable<JsonObject> observations, string leg)
    {
        var points = observations.ToArray(); var boot = points.FirstOrDefault()?.Text("BootId") ?? "";
        var valid = boot != "" && points.All(p => p.Text("BootId") == boot && !p.Flag("Tcp.Truncated"));
        var pairs = new List<(JsonObject First, JsonObject Last)>();
        if (valid)
        {
            var sockets = points.SelectMany(p => (p.At("Tcp.Sockets") as JsonArray ?? []).OfType<JsonObject>().Where(s => s.Text("Leg") == leg));
            foreach (var group in sockets.Where(s => s.Text("Identity") != "").GroupBy(s => s.Text("Identity")))
            {
                var values = group.ToArray(); if (values.Length < 2) continue;
                if (values.Any(s => !s.ContainsKey("DataSegmentsOut") || !s.ContainsKey("TotalRetrans"))) continue;
                if (values.Zip(values.Skip(1), (a, b) => b.Long("DataSegmentsOut") >= a.Long("DataSegmentsOut") && b.Long("TotalRetrans") >= a.Long("TotalRetrans")).Any(ok => !ok)) { valid = false; break; }
                if (values[^1].Long("DataSegmentsOut") > values[0].Long("DataSegmentsOut") || values[^1].Long("TotalRetrans") > values[0].Long("TotalRetrans")) pairs.Add((values[0], values[^1]));
            }
        }
        var sent = valid ? pairs.Sum(p => p.Last.Long("DataSegmentsOut") - p.First.Long("DataSegmentsOut")) : 0;
        var retrans = valid ? pairs.Sum(p => p.Last.Long("TotalRetrans") - p.First.Long("TotalRetrans")) : 0;
        return new JsonObject { ["Leg"] = leg, ["BootId"] = boot, ["CountersValid"] = valid && pairs.Count > 0, ["SentSegments"] = sent, ["RetransmittedSegments"] = retrans,
            ["SocketPairs"] = pairs.Count, ["Percent"] = valid && sent > 0 ? 100d * retrans / sent : null,
            ["ByteCoverageKnown"] = valid && pairs.Count > 0 && pairs.All(p => p.First.ContainsKey("BytesSent") && p.Last.ContainsKey("BytesSent") && p.Last.Long("BytesSent") >= p.First.Long("BytesSent")),
            ["BytesSent"] = valid ? pairs.Sum(p => Math.Max(0, p.Last.Long("BytesSent") - p.First.Long("BytesSent"))) : 0,
            ["RttMs"] = Percentile(pairs.Select(p => Value(p.Last, "RttMs")).Where(x => x > 0), .2),
            ["SendBufferLimitedPercent"] = Percentile(pairs.Where(p => p.First.ContainsKey("BusyMs") && p.Last.ContainsKey("BusyMs") && p.First.ContainsKey("SendBufferLimitedMs") && p.Last.ContainsKey("SendBufferLimitedMs") && Value(p.Last, "BusyMs") > Value(p.First, "BusyMs") && Value(p.Last, "SendBufferLimitedMs") >= Value(p.First, "SendBufferLimitedMs")).Select(p => 100 * (Value(p.Last, "SendBufferLimitedMs") - Value(p.First, "SendBufferLimitedMs")) / (Value(p.Last, "BusyMs") - Value(p.First, "BusyMs"))), .5) };
    }
    public static JsonObject DirectionEvidence(JsonObject report, string? selectedDirection = null)
    {
        var direction = selectedDirection ?? Priority(report["Options"] as JsonObject ?? new());
        var transfers = (report.At("Client.Transfers") as JsonArray ?? []).OfType<JsonObject>().Where(t => t.Text("Direction") == direction && t.Flag("Complete") && Value(t, "Seconds") >= MinimumTransferSeconds && t.Flag("TcpEvidence.CountersValid") && t.Flag("TcpEvidence.PayloadMatched")).ToArray();
        var unique = transfers.Select(t => t.Text("Endpoint") + ":" + t.Number("Streams") + ":" + t.Number("Round")).Distinct().Count() == transfers.Length;
        var boot = report.Text("ServerAfter.BootId");
        var valid = report.Text("Client.EvidencePolicy") == EvidencePolicy && unique && transfers.Length >= 4 && boot != "" && report.Text("ServerBefore.BootId") == boot && transfers.All(t => t.Text("TcpEvidence.BootId") == boot);
        var sent = valid ? transfers.Sum(t => t.Long("TcpEvidence.SentSegments")) : 0;
        var retrans = valid ? transfers.Sum(t => t.Long("TcpEvidence.RetransmittedSegments")) : 0;
        return new JsonObject { ["Scope"] = "MatchedTcpSockets", ["Direction"] = direction, ["CountersValid"] = valid,
            ["Eligible"] = valid && sent >= MinimumLossSegments, ["SentSegments"] = sent, ["RetransmittedSegments"] = retrans,
            ["Percent"] = valid && sent > 0 ? 100d * retrans / sent : null, ["Rounds"] = transfers.Length,
            ["Endpoints"] = new JsonArray(transfers.Select(t => t.Text("Endpoint")).Distinct().Order().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
            ["Status"] = !valid ? "ScopedSamplesUnavailable" : sent < MinimumLossSegments ? "InsufficientSegments" : "Available" };
    }
}
