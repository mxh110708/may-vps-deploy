using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Mxh.VpsDeploy.Core;

public interface INetworkMeasurement
{
    Task<JsonObject> MeasureAsync(NetworkMeasurementPath path, JsonObject options, string directory,
        Func<CancellationToken, Task<JsonObject>> observe, IProgress<string> progress, CancellationToken cancellationToken);
}

public static partial class NetworkTuning
{
    public static bool IsEntry(JsonObject plan) => DeploymentPlans.Roles[..2].Any(role =>
        plan.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.InitiallyEnabled(plan, role)));
    public static string Profile(JsonObject plan) => IsEntry(plan) ? "EntryBasic" : "LandingBasic";
    public static string Id(string value) => Regex.IsMatch(value, "^[a-f0-9]{32}$") ? value : throw new OperationException("网络测量记录身份无效。");
    public static double Value(JsonNode? node, string path) => double.TryParse(node.Text(path), NumberStyles.Float, CultureInfo.InvariantCulture, out var value) && double.IsFinite(value) ? value : 0;
    public static double Percentile(IEnumerable<double> samples, double percentile)
    {
        var values = samples.Where(x => double.IsFinite(x) && x >= 0).Order().ToArray();
        if (values.Length == 0) return 0;
        var position = (values.Length - 1) * percentile; var low = (int)position; var high = (int)Math.Ceiling(position);
        return values[low] + (values[high] - values[low]) * (position - low);
    }
    public static JsonObject Defaults(JsonObject plan) => new()
    {
        ["BandwidthMbps"] = plan.Number("NetworkPreferences.BandwidthMbps", plan.Number("NetworkTuning.BandwidthMbps")),
        ["UploadMbps"] = plan.Number("NetworkPreferences.UploadMbps"),
        ["CapacityType"] = plan.Text("NetworkPreferences.CapacityType", "Unknown"),
        ["Protocol"] = !IsEntry(plan) ? "ShadowsocksLanding" : plan.Text("ActiveEntry", plan.Text("Role")) is "AnyTlsEntry" ? "AnyTlsEntry" : "RealityEntry",
        ["Topology"] = plan.Text("NetworkPreferences.Topology", IsEntry(plan) ? "Entry" : "Landing"),
        ["PriorityDirection"] = plan.Text("NetworkPreferences.EvidencePolicy") == EvidencePolicy ? plan.Text("NetworkPreferences.PriorityDirection", "Balanced") : "Balanced",
        ["PeerInstance"] = plan.Text("NetworkPreferences.PeerInstance"), ["PeerFamily"] = plan.Text("NetworkPreferences.PeerFamily", "IPv4"), ["PeerEgress"] = plan.Text("NetworkPreferences.PeerEgress", !IsEntry(plan) && HasIpv6LandingEgress(plan) ? "Both" : "IPv4"),
        ["Family"] = plan.Text("NetworkPreferences.Family", "IPv4"), ["TestSize"] = plan.Text("NetworkPreferences.TestSize", "Standard"), ["TrafficBudgetMiB"] = plan.Number("NetworkPreferences.TrafficBudgetMiB", 1024),
        ["TimeZoneId"] = plan.Text("NetworkPreferences.TimeZoneId", TimeZoneInfo.Local.Id),
        ["PeakStartHour"] = plan.Number("NetworkPreferences.PeakStartHour", 20),
        ["PeakEndHour"] = plan.Number("NetworkPreferences.PeakEndHour", 23)
    };
    // Reserve 20% for small probes/protocol overhead and half of the remaining payload for the retest.
    public static long PayloadBudget(JsonObject options) => FlowBudgetMiB(options) * 1048576L * 4 / 10 / BudgetPartitions(options);
    public static int DurationSeconds(JsonObject options) => (options.Text("TestSize") == "Light" ? 100 : options.Text("TestSize") == "Full" ? 240 : FlowBudgetMiB(options) <= 128 ? 120 : FlowBudgetMiB(options) <= 1024 ? 360 : FlowBudgetMiB(options) <= 4096 ? 900 : 1800) / BudgetPartitions(options);
    public static void ValidateMeasurement(JsonObject options)
    {
        var allowed = new[] { "BandwidthMbps", "UploadMbps", "CapacityType", "Protocol", "Family", "TestSize", "TrafficBudgetMiB", "BudgetFamilyCount", "TimeZoneId", "PeakStartHour", "PeakEndHour", "Scheduled", "Topology", "PriorityDirection", "PeerInstance", "PeerFamily", "PeerEgress" };
        if (options.Any(p => !allowed.Contains(p.Key))) throw new OperationException("测速参数包含不支持的字段；RTT 由应用自动采集。");
        foreach (var key in new[] { "BandwidthMbps", "UploadMbps", "PeakStartHour", "PeakEndHour" })
            if (options.Text(key).Trim() != "" && !int.TryParse(options.Text(key), NumberStyles.Integer, CultureInfo.InvariantCulture, out _)) throw new OperationException("带宽与高峰时间请填写整数；带宽未知可留空。");
        if (options.Number("BandwidthMbps") is < 0 or > 100000 || options.Number("UploadMbps") is < 0 or > 100000) throw new OperationException("标称带宽应为 1–100000 Mbps；未知可留空。");
        if (options.Text("CapacityType") is not ("Unknown" or "Shared" or "Dedicated" or "Burst") || options.Text("Protocol") is not ("RealityEntry" or "AnyTlsEntry" or "ShadowsocksLanding") || options.Text("Family") is not ("IPv4" or "IPv6" or "Both") || options.Text("TestSize") is not ("Light" or "Full" or "Quick" or "Standard" or "Deep" or "Extended" or "Maximum" or "Custom")) throw new OperationException("请选择有效的测速用途、协议和测试档位。");
        if (options.Text("TestSize") == "Custom" && (!int.TryParse(options.Text("TrafficBudgetMiB"), out var total) || total is < 64 or > MaximumFlowBudgetMiB)) throw new OperationException("自定义总预算应为 64–20480 MiB（最多 20 GiB，覆盖双栈、双向和前后复测）。");
        if (options.ContainsKey("BudgetFamilyCount") && options.Text("BudgetFamilyCount") is not ("1" or "2" or "4")) throw new OperationException("路径预算分配无效。");
        if (Topology(options) is not ("Entry" or "Relay" or "Landing" or "ForwardOnly") || Priority(options) is not ("Download" or "Upload" or "Balanced")) throw new OperationException("请选择有效的 TCP 角色和优化偏好。");
        if (Topology(options) == "Landing" && options.Text("Protocol") != "ShadowsocksLanding" || Topology(options) is "Entry" or "Relay" && options.Text("Protocol") == "ShadowsocksLanding") throw new OperationException("测试路径与协议用途不一致。");
        if (Topology(options) is "Landing" or "Relay" && options.Text("PeerEgress", "IPv4") is not ("IPv4" or "IPv6" or "Both")) throw new OperationException("请选择落地访问网站使用的 IP：IPv4、IPv6 或两者都测。");
        if (Topology(options) == "Relay")
        {
            var names = options.Text("PeerInstance").Split('/');
            if (names.Length != 3 || names[2] != "MXH-VPS-Deploy" || AppPaths.Segment(names[0]) != names[0] || AppPaths.Segment(names[1]) != names[1] || options.Text("PeerFamily", "IPv4") is not ("IPv4" or "IPv6")) throw new OperationException("请选择已纳管的落地及有效连接地址族。");
        }
        if (options.Text("PeakStartHour").Trim() == "" || options.Text("PeakEndHour").Trim() == "" || options.Number("PeakStartHour") is < 0 or > 23 || options.Number("PeakEndHour") is < 0 or > 24 || options.Number("PeakStartHour") == options.Number("PeakEndHour")) throw new OperationException("高峰开始应在 0–23 时，结束应在 0–24 时，且不能相同；24 表示次日零点。");
        _ = Zone(options.Text("TimeZoneId"));
    }
    public static string TimeDescription(JsonObject options)
    {
        try
        {
            var zone = Zone(options.Text("TimeZoneId"));
            if (!int.TryParse(options.Text("PeakStartHour"), out var start) || !int.TryParse(options.Text("PeakEndHour"), out var end) || start is < 0 or > 23 || end is < 0 or > 24 || start == end) return "请填写有效高峰时段：开始 0–23 时，结束 0–24 时，且不能相同。";
            var suffix = end == 24 ? "24:00（次日零点）" : (end < start ? "次日 " : "") + end.ToString("00") + ":00";
            return "当前高峰：" + start.ToString("00") + ":00–" + suffix + " · " + zone.Id + "。其他时段的结果不代表此高峰；缺少该时段样本时保留余量。时间按主要使用地计算。";
        }
        catch (OperationException) { return "此时区无法识别。请选择常用时区，或填写有效的 IANA / Windows 时区 ID。"; }
    }
    public static TimeZoneInfo Zone(string id)
    {
        if (string.IsNullOrWhiteSpace(id)) throw new OperationException("主要使用地时区无效。");
        try { return TimeZoneInfo.FindSystemTimeZoneById(id); }
        catch (Exception error) when (error is TimeZoneNotFoundException or InvalidTimeZoneException) { throw new OperationException("主要使用地时区无效。"); }
    }
    public static bool InPeak(DateTimeOffset at, JsonObject options)
    {
        var hour = TimeZoneInfo.ConvertTime(at, Zone(options.Text("TimeZoneId"))).Hour;
        var start = options.Number("PeakStartHour"); var end = options.Number("PeakEndHour");
        return start < end ? hour >= start && hour < end : hour >= start || hour < end;
    }
    public static string SourceFingerprint(JsonObject plan, JsonObject secrets)
    {
        var identity = new JsonObject();
        foreach (var key in new[] { "Server", "Ports", "Role", "Roles", "ActiveEntry", "ProtocolInventory", "Reality", "AnyTls", "Shadowsocks" }) identity[key] = plan[key]?.DeepClone();
        identity["Credentials"] = new JsonObject();
        foreach (var key in new[] { "Xray", "AnyTls", "Shadowsocks" }) identity["Credentials"]![key] = secrets[key]?.DeepClone();
        return ArchiveStore.Fingerprint(identity);
    }
    public static string Sysctl(JsonObject observation, string key) => (observation["Sysctl"] as JsonObject)?[key]?.ToString() ?? "";
    public static string QueueFingerprint(JsonObject observation) => ArchiveStore.Fingerprint(new JsonArray((observation["Devices"] as JsonArray ?? []).OfType<JsonObject>().Select(device => (JsonNode?)new JsonObject
    {
        ["Name"] = device.Text("Name"), ["Mtu"] = device.Text("Mtu"),
        ["Queues"] = new JsonArray((device["Queues"] as JsonArray ?? []).OfType<JsonObject>().Select(queue => (JsonNode?)new JsonObject
        { ["kind"] = queue["kind"]?.DeepClone(), ["handle"] = queue["handle"]?.DeepClone(), ["root"] = queue["root"]?.DeepClone(), ["parent"] = queue["parent"]?.DeepClone(), ["options"] = queue["options"]?.DeepClone() }).ToArray())
    }).ToArray()));
    public static JsonObject ReadReport(string directory, string id)
    {
        var file = SafePath.Resolve(directory, "network-measurements/" + Id(id) + ".json");
        if (!File.Exists(file) || new FileInfo(file).Length > 1048576) throw new OperationException("测量记录不存在或大小异常，请重新测量。");
        var report = ArchiveStore.ReadJson(file);
        if (report.Text("Id") != id || report.Number("SchemaVersion") is not (1 or 2) || report.Number("SchemaVersion") == 2 && report["Paths"] is not JsonArray) throw new OperationException("测量记录身份不一致。");
        return report;
    }
    public static IEnumerable<JsonObject> History(string directory)
    {
        var root = SafePath.Resolve(directory, "network-measurements"); if (!Directory.Exists(root)) yield break;
        SafePath.CheckTree(root);
        foreach (var file in Directory.EnumerateFiles(root, "*.json").OrderByDescending(File.GetLastWriteTimeUtc).Take(40))
        {
            JsonObject? report = null;
            try { if (Regex.IsMatch(Path.GetFileNameWithoutExtension(file), "^[a-f0-9]{32}$") && new FileInfo(file).Length <= 1048576) report = ReadReport(directory, Path.GetFileNameWithoutExtension(file)); }
            catch (Exception error) when (error is OperationException or System.Text.Json.JsonException or IOException) { }
            if (report != null) yield return report;
        }
    }
    private static JsonObject AnalyzeSingle(JsonObject report, IEnumerable<JsonObject>? history = null)
    {
        var options = report["Options"]!.AsObject(); var client = report["Client"]!.AsObject(); var server = report["ServerAfter"]!.AsObject();
        var idle = Values(client, "IdleLatencyMs"); var loaded = Values(client, "LoadedLatencyMs");
        var all = (client["Transfers"] as JsonArray ?? []).OfType<JsonObject>().ToArray();
        double Speed(string direction) => Percentile(all.Where(t => t.Text("Direction") == direction && t.Flag("Complete") && Value(t, "Seconds") >= MinimumTransferSeconds).Select(t => Value(t, "Mbps")), .5);
        double StreamSpeed(string direction, int streams) => Percentile(all.Where(t => t.Text("Direction") == direction && t.Number("Streams") == streams && t.Flag("Complete") && Value(t, "Seconds") >= MinimumTransferSeconds).Select(t => Value(t, "Mbps")), .5);
        var download = Speed("Download"); var upload = Speed("Upload");
        var planningDownload = download;
        // Only actual kernel TCP samples are used to size buffers. HTTP timings include application/TLS work.
        var directional = report.Text("Client.EvidencePolicy") == EvidencePolicy;
        var preferred = Priority(options);
        var preferredTransfers = all.Where(t => t.Text("Direction") == preferred && t.Flag("Complete") && Value(t, "Seconds") >= MinimumTransferSeconds && t.Flag("TcpEvidence.CountersValid") && t.Flag("TcpEvidence.PayloadMatched")).ToArray();
        var rtts = directional ? preferredTransfers.Select(t => Value(t, "TcpEvidence.RttMs")).Where(x => x > 0).ToArray() : Values(server, "Tcp.RttMs"); var rtt = Percentile(rtts, .2);
        var notes = new JsonArray();
        var peak = InPeak(DateTimeOffset.Parse(report.Text("At"), CultureInfo.InvariantCulture), options);
        var compatible = (history ?? []).Where(old => old.Text("SourceFingerprint") == report.Text("SourceFingerprint") && old.Text("PathFingerprint") == report.Text("PathFingerprint") && old.Text("Client.EvidencePolicy") == report.Text("Client.EvidencePolicy") && new[] { "Protocol", "Family", "TimeZoneId", "PeakStartHour", "PeakEndHour", "Topology", "PriorityDirection", "PeerInstance", "PeerFamily", "PeerEgress" }.All(k => old.Text("Options."+k) == options.Text(k)) && DateTimeOffset.TryParse(old.Text("At"), out var time) && time >= DateTimeOffset.Parse(report.Text("At"), CultureInfo.InvariantCulture).AddDays(-7) && time <= DateTimeOffset.Parse(report.Text("At"), CultureInfo.InvariantCulture)).ToArray();
        var peakRecords = compatible.Where(old => old.Text("Client.Status") == "Measured" && old.Flag("Client.EgressVerified") && InPeak(DateTimeOffset.Parse(old.Text("At"), CultureInfo.InvariantCulture), old["Options"]!.AsObject()) && Value(old, "Analysis.DownloadMbps") > 0).ToArray();
        var coverage = peak || peakRecords.Length > 0;
        if (!coverage) notes.Add("尚未覆盖晚高峰；当前结果不能代表全天线路容量。建议安排一次晚间补测。");
        if (peakRecords.Length > 0 && download > 0) planningDownload = Math.Min(download, Percentile(peakRecords.Select(old => Value(old, "Analysis.DownloadMbps")), .25));
        if (options.Text("CapacityType") is "Unknown" or "Shared" or "Burst") notes.Add("套餐可能共享或突发；不依据单次峰值设定发送限速。");
        if (!client.Flag("EgressVerified")) notes.Add("所选代理的出口尚未验证，精细调优不可用。");
        if (client.Text("Status") != "Measured") notes.Add("本轮采集未完整完成；只提供基础配置建议，不调整缓冲区。");
        if (all.Count(t => t.Flag("Complete") && Value(t, "Seconds") >= MinimumTransferSeconds) < 4) notes.Add("有效持续传输样本不足，或受流量/时间限制；预算耗尽不代表测试充分。");
        if (rtt <= 0) notes.Add("未获取真实 TCP RTT，保留内核自动缓冲，不用 HTTP 响应时间代替。");
        if (options.Number("BandwidthMbps") <= 0) notes.Add("套餐标称带宽未知，暂不生成缓冲区调整。");
        var cpu = Value(server, "Cpu.BusyPercent"); var steal = Value(server, "Cpu.StealPercent");
        if (cpu >= 85 || steal >= 10) notes.Add("VPS CPU 或宿主机资源竞争较高；增加网络缓冲未必提高速度。");
        var idle95 = Percentile(idle, .95); var loaded95 = Percentile(loaded, .95);
        if (idle.Length < 3 || loaded.Length < 3) notes.Add("响应时间样本不足，无法核对排队代价，保留基础配置建议。");
        if (server.Long("MemoryKiB") <= 0 || Sysctl(server, "net.ipv4.tcp_moderate_rcvbuf") != "1") notes.Add("内存或自动接收缓冲状态未确认，不调整缓冲区。");
        if (loaded.Length >= 3 && loaded95 > Math.Max(idle95 * 1.5, idle95 + 30)) notes.Add("传输中延迟明显升高；优先观察排队，避免盲目增加缓存。此版本不自动配置全局限速。");
        var loss = LossEvidence(report);
        var retrans = loss.Long("RetransmittedSegments"); var sent = loss.Long("SentSegments");
        notes.Add(directional ? "重传参考只取关键方向中匹配端口和对端的 TCP socket 差量，未采到的连接不按零计算；同对端其他业务仍可能干扰。全机计数只作诊断。" : "历史记录使用 VPS 全机计数，不能支持新版精细建议；请重新采集方向证据。");
        if (!loss.Flag("Eligible")) notes.Add("重传计数缺失、重置或新发送段少于 " + MinimumLossSegments + "，不足以判断丢包变化；精细参数复测不会仅凭速度提高而自动保留。");
        notes.Add("吞吐为本机→所选代理→独立测试点的实测有效载荷速率；不是套餐带宽，也不是纯 VPS 网卡速率。");
        var memoryMiB = server.Long("MemoryKiB") / 1024; var cap = (memoryMiB <= 512 ? 4L : memoryMiB <= 1024 ? 8L : memoryMiB <= 2048 ? 16L : 32L) * 1048576;
        long Ceiling(string key) => long.TryParse(Sysctl(server, key).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).LastOrDefault(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : 0;
        var ceilings = new[] { "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.core.rmem_max", "net.core.wmem_max" }.Select(Ceiling).ToArray();
        if (ceilings.Any(value => value <= 0)) notes.Add("现有缓冲上限未完整确认，保留原值，仅建议基础配置。");
        else if (ceilings.Any(value => value > cap)) notes.Add("现有缓冲上限已高于本机保守内存预算；本轮保留原值，仅建议 fq 与可用 BBR。");
        var startup = (client["Startup"] as JsonArray ?? []).OfType<JsonObject>().ToArray();
        var startupCovered = new[] { "Cloudflare", "Hetzner" }.All(endpoint => startup.Where(t => t.Flag("Complete") && t.Text("Endpoint") == endpoint && Value(t, "Milliseconds") > 0).Select(t => t.Number("Round")).Distinct().Count() >= 3);
        var sendLimited = preferredTransfers.Length >= 4 && preferredTransfers.Count(t => Value(t, "TcpEvidence.SendBufferLimitedPercent") >= 10) >= Math.Ceiling(preferredTransfers.Length * 2d / 3);
        var peers = preferredTransfers.Where(t => t.Text("Endpoint") != "").GroupBy(t => t.Text("Endpoint")).Count(g => g.Select(t => t.Number("Round")).Distinct().Count() >= 2);
        var evidence = directional && startupCovered && sendLimited && peers >= 2 && Topology(options) is "Entry" or "Relay";
        if (!startupCovered) notes.Add("未取得至少两个独立目标的重复短连接样本，不推导全局精细参数。");
        if (peers < 2) notes.Add("关键方向没有覆盖两个独立测速目标；单一对端异常不能推导全局配置。上传当前公共端点覆盖有限，只提供基础配置。");
        if (!sendLimited) notes.Add("未在多数匹配样本中确认本机发送缓冲限制；保持缓冲区、初始窗口、TFO、TCP 连接及内存策略原值。");
        if (Topology(options) == "Relay") notes.Add("中转测试含入口→所选落地；本机直出速率不作为该段瓶颈证据。不会改动落地。");
        if (Topology(options) == "Landing") notes.Add("落地只诊断出站稳定性；精细参数不自动调整，仍使用 fq + BBR 基础配置。");
        if (Topology(options) == "ForwardOnly") notes.Add("纯转发不是转发 TCP 的终点或发起方；本机 BBR 不能控制其拥塞窗口，不生成精细建议。");
        var queueSafe = loaded.Length >= 3 && loaded95 <= Math.Max(idle95 * 1.5, idle95 + 30);
        var sameWindow = DateTimeOffset.TryParse(report.Text("StartedAt"), out var started) && started <= DateTimeOffset.Parse(report.Text("At"), CultureInfo.InvariantCulture) && InPeak(started, options) == peak;
        if (!sameWindow) notes.Add("测量跨越高峰边界或缺少开始时间，不将这一轮作为精细参数依据。");
        var eligible = evidence && sameWindow && queueSafe && client.Text("Status") == "Measured" && client.Flag("EgressVerified") && loss.Flag("Eligible") && rtt > 0 && download > 0 && upload > 0 && options.Number("BandwidthMbps") > 0 && cpu < 85 && steal < 10 && idle.Length >= 3 && loaded.Length >= 3 && server.Long("MemoryKiB") > 0 && Sysctl(server, "net.ipv4.tcp_moderate_rcvbuf") == "1" && ceilings.All(value => value > 0 && value <= cap) && all.Count(t => t.Flag("Complete") && Value(t, "Seconds") >= MinimumTransferSeconds) >= 4;
        var rate = preferred == "Upload" ? Math.Min(options.Number("UploadMbps", options.Number("BandwidthMbps")), upload) : Math.Min(options.Number("BandwidthMbps"), planningDownload);
        // A socket ceiling, not a preallocation. Preserve auto-tuning and existing higher values.
        var target = eligible ? Math.Min(cap, Math.Max(2097152L, (long)Math.Ceiling(rate * rtt * 125 * 2 + 2097152))) : 0;
        if (target <= ceilings[1]) eligible = false;
        if (!eligible) target = 0;
        return new JsonObject { ["EvidencePolicy"] = EvidencePolicy, ["Profile"] = eligible ? "EntryMeasured" : Topology(options) == "Landing" ? "LandingBasic" : "EntryBasic", ["DownloadMbps"] = download, ["UploadMbps"] = upload,
            ["DownloadSingleMbps"] = StreamSpeed("Download", 1), ["DownloadMultiMbps"] = StreamSpeed("Download", 4), ["UploadSingleMbps"] = StreamSpeed("Upload", 1), ["UploadMultiMbps"] = StreamSpeed("Upload", 4),
            ["PlanningDownloadMbps"] = planningDownload, ["TcpRttMs"] = rtt, ["IdleP50Ms"] = Percentile(idle, .5), ["IdleP95Ms"] = idle95, ["LoadedP95Ms"] = loaded95,
            ["JitterMs"] = Percentile(idle.Zip(idle.Skip(1), (a, b) => Math.Abs(a - b)), .5),
            ["RetransmittedSegments"] = retrans, ["SentSegments"] = sent, ["TcpRetransmitPercent"] = loss["Percent"]?.DeepClone(), ["LossEvidence"] = loss, ["BufferTargetBytes"] = target, ["BufferCapBytes"] = cap, ["BufferDirection"] = "Send", ["PriorityDirection"] = preferred,
            ["StartupP95Ms"] = Percentile(startup.Where(t => t.Flag("Complete")).Select(t => Value(t, "Milliseconds")), .95), ["StartupCovered"] = startupCovered, ["SendBufferLimited"] = sendLimited, ["IndependentEndpoints"] = peers,
            ["PeakSample"] = peak, ["PeakCovered"] = coverage, ["Confidence"] = eligible ? coverage ? "AcrossTimeWindows" : "CurrentWindowOnly" : "InsufficientForBuffers", ["Notes"] = notes };
    }
    private static double[] Values(JsonObject node, string path) => (node.At(path) as JsonArray ?? []).Select(value => Value(new JsonObject { ["v"] = value?.DeepClone() }, "v")).Where(value => value > 0).ToArray();
    public static string Compare(JsonObject before, JsonObject after) => CompareDetailed(before, after).Text("Result");
}
