using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Mxh.VpsDeploy.Core;

public interface INetworkMeasurement
{
    Task<JsonObject> MeasureAsync(JsonObject plan, JsonObject secrets, JsonObject options, string directory,
        Func<CancellationToken, Task<JsonObject>> observe, IProgress<string> progress, CancellationToken cancellationToken);
}

public static class NetworkTuning
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
        ["Protocol"] = plan.Text("ActiveEntry", plan.Text("Role")) is "AnyTlsEntry" ? "AnyTlsEntry" : "RealityEntry",
        ["Family"] = plan.Text("NetworkPreferences.Family", "IPv4"), ["TestSize"] = "Light",
        ["TimeZoneId"] = plan.Text("NetworkPreferences.TimeZoneId", TimeZoneInfo.Local.Id),
        ["PeakStartHour"] = plan.Number("NetworkPreferences.PeakStartHour", 20),
        ["PeakEndHour"] = plan.Number("NetworkPreferences.PeakEndHour", 23)
    };
    public static long PayloadBudget(JsonObject options) => options.Text("TestSize") == "Full" ? 256L * 1048576 : 32L * 1048576;
    public static int DurationSeconds(JsonObject options) => options.Text("TestSize") == "Full" ? 240 : 100;
    public static void ValidateMeasurement(JsonObject options)
    {
        var allowed = new[] { "BandwidthMbps", "UploadMbps", "CapacityType", "Protocol", "Family", "TestSize", "TimeZoneId", "PeakStartHour", "PeakEndHour", "Scheduled" };
        if (options.Any(p => !allowed.Contains(p.Key))) throw new OperationException("测速参数包含不支持的字段；RTT 由应用自动采集。");
        foreach (var key in new[] { "BandwidthMbps", "UploadMbps", "PeakStartHour", "PeakEndHour" })
            if (options.Text(key).Trim() != "" && !int.TryParse(options.Text(key), NumberStyles.Integer, CultureInfo.InvariantCulture, out _)) throw new OperationException("带宽与高峰时间请填写整数；带宽未知可留空。");
        if (options.Number("BandwidthMbps") is < 0 or > 100000 || options.Number("UploadMbps") is < 0 or > 100000) throw new OperationException("标称带宽应为 1–100000 Mbps；未知可留空。");
        if (options.Text("CapacityType") is not ("Unknown" or "Shared" or "Dedicated" or "Burst") || options.Text("Protocol") is not ("RealityEntry" or "AnyTlsEntry") || options.Text("Family") is not ("IPv4" or "IPv6") || options.Text("TestSize") is not ("Light" or "Full")) throw new OperationException("请选择有效的测速用途、协议和测试档位。");
        if (options.Number("PeakStartHour") is < 0 or > 23 || options.Number("PeakEndHour") is < 0 or > 23 || options.Number("PeakStartHour") == options.Number("PeakEndHour")) throw new OperationException("晚高峰时间应在 0–23 时，开始与结束不能相同。");
        _ = Zone(options.Text("TimeZoneId"));
    }
    public static TimeZoneInfo Zone(string id)
    {
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
        if (report.Text("Id") != id || report.Number("SchemaVersion") != 1) throw new OperationException("测量记录身份不一致。");
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
    public static JsonObject Analyze(JsonObject report, IEnumerable<JsonObject>? history = null)
    {
        var options = report["Options"]!.AsObject(); var client = report["Client"]!.AsObject(); var server = report["ServerAfter"]!.AsObject();
        var idle = Values(client, "IdleLatencyMs"); var loaded = Values(client, "LoadedLatencyMs");
        var all = (client["Transfers"] as JsonArray ?? []).OfType<JsonObject>().ToArray();
        double Speed(string direction) => Percentile(all.Where(t => t.Text("Direction") == direction && t.Flag("Complete") && Value(t, "Seconds") >= .25).Select(t => Value(t, "Mbps")), .5);
        double StreamSpeed(string direction, int streams) => Percentile(all.Where(t => t.Text("Direction") == direction && t.Number("Streams") == streams && t.Flag("Complete") && Value(t, "Seconds") >= .25).Select(t => Value(t, "Mbps")), .5);
        var download = Speed("Download"); var upload = Speed("Upload");
        var planningDownload = download;
        // Only actual kernel TCP samples are used to size buffers. HTTP timings include application/TLS work.
        var rtts = Values(server, "Tcp.RttMs"); var rtt = Percentile(rtts, .2);
        var notes = new JsonArray();
        var peak = InPeak(DateTimeOffset.Parse(report.Text("At"), CultureInfo.InvariantCulture), options);
        var compatible = (history ?? []).Where(old => old.Text("SourceFingerprint") == report.Text("SourceFingerprint") && old.Text("Options.Protocol") == options.Text("Protocol") && old.Text("Options.Family") == options.Text("Family") && old.Text("Options.TimeZoneId") == options.Text("TimeZoneId") && old.Number("Options.PeakStartHour") == options.Number("PeakStartHour") && old.Number("Options.PeakEndHour") == options.Number("PeakEndHour") && DateTimeOffset.TryParse(old.Text("At"), out var time) && time >= DateTimeOffset.Parse(report.Text("At"), CultureInfo.InvariantCulture).AddDays(-7) && time <= DateTimeOffset.Parse(report.Text("At"), CultureInfo.InvariantCulture)).ToArray();
        var peakRecords = compatible.Where(old => old.Text("Client.Status") == "Measured" && old.Flag("Client.EgressVerified") && InPeak(DateTimeOffset.Parse(old.Text("At"), CultureInfo.InvariantCulture), old["Options"]!.AsObject()) && Value(old, "Analysis.DownloadMbps") > 0).ToArray();
        var coverage = peak || peakRecords.Length > 0;
        if (!coverage) notes.Add("尚未覆盖晚高峰；当前结果不能代表全天线路容量。建议安排一次晚间补测。");
        if (peakRecords.Length > 0 && download > 0) planningDownload = Math.Min(download, Percentile(peakRecords.Select(old => Value(old, "Analysis.DownloadMbps")), .25));
        if (options.Text("CapacityType") is "Unknown" or "Shared" or "Burst") notes.Add("套餐可能共享或突发；不依据单次峰值设定发送限速。");
        if (!client.Flag("EgressVerified")) notes.Add("所选代理的出口尚未验证，精细调优不可用。");
        if (client.Text("Status") != "Measured") notes.Add("本轮采集未完整完成；只提供基础配置建议，不调整缓冲区。");
        if (all.Count(t => t.Flag("Complete") && Value(t, "Seconds") >= .25) < 4) notes.Add("有效传输样本不足，或受流量/时间限制；未确认链路容量。");
        if (rtt <= 0) notes.Add("未获取真实 TCP RTT，保留内核自动缓冲，不用 HTTP 响应时间代替。");
        if (options.Number("BandwidthMbps") <= 0) notes.Add("套餐标称带宽未知，暂不生成缓冲区调整。");
        var cpu = Value(server, "Cpu.BusyPercent"); var steal = Value(server, "Cpu.StealPercent");
        if (cpu >= 85 || steal >= 10) notes.Add("VPS CPU 或宿主机资源竞争较高；增加网络缓冲未必提高速度。");
        var idle95 = Percentile(idle, .95); var loaded95 = Percentile(loaded, .95);
        if (idle.Length < 3 || loaded.Length < 3) notes.Add("响应时间样本不足，无法核对排队代价，保留基础配置建议。");
        if (server.Long("MemoryKiB") <= 0 || Sysctl(server, "net.ipv4.tcp_moderate_rcvbuf") != "1") notes.Add("内存或自动接收缓冲状态未确认，不调整缓冲区。");
        if (loaded.Length >= 3 && loaded95 > Math.Max(idle95 * 1.5, idle95 + 30)) notes.Add("传输中延迟明显升高；优先观察排队，避免盲目增加缓存。此版本不自动配置全局限速。");
        var retransBefore = report.Long("ServerBefore.Counters.TcpRetransSegs"); var retrans = Math.Max(0, server.Long("Counters.TcpRetransSegs") - retransBefore);
        var sent = Math.Max(0, server.Long("Counters.TcpOutSegs") - report.Long("ServerBefore.Counters.TcpOutSegs"));
        if (retrans > 0) notes.Add("TCP 重传是 VPS 全机计数差值，可能包含其他连接；不等同于所选线路丢包率。");
        notes.Add("吞吐为本机→所选代理→Cloudflare 测试点的实测有效载荷速率；不是套餐带宽，也不是纯 VPS 网卡速率。");
        var memoryMiB = server.Long("MemoryKiB") / 1024; var cap = (memoryMiB <= 512 ? 4L : memoryMiB <= 1024 ? 8L : memoryMiB <= 2048 ? 16L : 32L) * 1048576;
        long Ceiling(string key) => long.TryParse(Sysctl(server, key).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).LastOrDefault(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : 0;
        var ceilings = new[] { "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.core.rmem_max", "net.core.wmem_max" }.Select(Ceiling).ToArray();
        if (ceilings.Any(value => value <= 0)) notes.Add("现有缓冲上限未完整确认，保留原值，仅建议基础配置。");
        else if (ceilings.Any(value => value > cap)) notes.Add("现有缓冲上限已高于本机保守内存预算；本轮保留原值，仅建议 fq 与可用 BBR。");
        var eligible = client.Text("Status") == "Measured" && client.Flag("EgressVerified") && rtt > 0 && download > 0 && upload > 0 && options.Number("BandwidthMbps") > 0 && cpu < 85 && steal < 10 && idle.Length >= 3 && loaded.Length >= 3 && server.Long("MemoryKiB") > 0 && Sysctl(server, "net.ipv4.tcp_moderate_rcvbuf") == "1" && ceilings.All(value => value > 0 && value <= cap) && all.Count(t => t.Flag("Complete") && Value(t, "Seconds") >= .25) >= 4;
        var rate = Math.Max(Math.Min(options.Number("BandwidthMbps"), planningDownload), options.Number("UploadMbps") > 0 ? Math.Min(options.Number("UploadMbps"), upload) : Math.Min(options.Number("BandwidthMbps"), upload));
        // A socket ceiling, not a preallocation. Preserve auto-tuning and existing higher values.
        var target = eligible ? Math.Min(cap, Math.Max(2097152L, (long)Math.Ceiling(rate * rtt * 125 * 2))) : 0;
        return new JsonObject { ["Profile"] = eligible ? "EntryMeasured" : "EntryBasic", ["DownloadMbps"] = download, ["UploadMbps"] = upload,
            ["DownloadSingleMbps"] = StreamSpeed("Download", 1), ["DownloadMultiMbps"] = StreamSpeed("Download", 4), ["UploadSingleMbps"] = StreamSpeed("Upload", 1), ["UploadMultiMbps"] = StreamSpeed("Upload", 4),
            ["PlanningDownloadMbps"] = planningDownload, ["TcpRttMs"] = rtt, ["IdleP50Ms"] = Percentile(idle, .5), ["IdleP95Ms"] = idle95, ["LoadedP95Ms"] = loaded95,
            ["JitterMs"] = Percentile(idle.Zip(idle.Skip(1), (a, b) => Math.Abs(a - b)), .5),
            ["RetransmittedSegments"] = retrans, ["SentSegments"] = sent, ["BufferTargetBytes"] = target, ["BufferCapBytes"] = cap,
            ["PeakSample"] = peak, ["PeakCovered"] = coverage, ["Confidence"] = eligible ? coverage ? "AcrossTimeWindows" : "CurrentWindowOnly" : "InsufficientForBuffers", ["Notes"] = notes };
    }
    private static double[] Values(JsonObject node, string path) => (node.At(path) as JsonArray ?? []).Select(value => Value(new JsonObject { ["v"] = value?.DeepClone() }, "v")).Where(value => value > 0).ToArray();
    public static string Compare(JsonObject before, JsonObject after)
    {
        var b = before["Analysis"]!.AsObject(); var a = after["Analysis"]!.AsObject();
        if (!before.Flag("Client.EgressVerified") || !after.Flag("Client.EgressVerified") || before.Text("SourceFingerprint") != after.Text("SourceFingerprint") || before.Text("Options.Protocol") != after.Text("Options.Protocol") || before.Text("Options.Family") != after.Text("Options.Family") || before.Text("Options.TestSize") != after.Text("Options.TestSize") || b.Text("Profile") != "EntryMeasured" || a.Text("Profile") != "EntryMeasured") return "Inconclusive";
        if (Value(a, "DownloadMbps") < Value(b, "DownloadMbps") * .7 && Value(a, "UploadMbps") < Value(b, "UploadMbps") * .7 && Value(a, "LoadedP95Ms") > Math.Max(Value(b, "LoadedP95Ms") * 1.5, Value(b, "LoadedP95Ms") + 30)) return "Regression";
        bool RepeatedGain(string direction)
        {
            var old = (before.At("Client.Transfers") as JsonArray ?? []).OfType<JsonObject>().Where(x => x.Text("Direction") == direction && x.Flag("Complete") && Value(x, "Seconds") >= .25).ToArray();
            var current = (after.At("Client.Transfers") as JsonArray ?? []).OfType<JsonObject>().Where(x => x.Text("Direction") == direction && x.Flag("Complete") && Value(x, "Seconds") >= .25).ToArray();
            var pairs = old.Select(x => (Old: x, New: current.SingleOrDefault(y => y.Number("Streams") == x.Number("Streams") && y.Number("Round") == x.Number("Round")))).Where(x => x.New != null).ToArray();
            return pairs.Length >= 4 && pairs.Count(x => Value(x.New, "Mbps") > Value(x.Old, "Mbps") * 1.1) >= Math.Ceiling(pairs.Length * 2d / 3);
        }
        if ((Value(a, "DownloadMbps") > Value(b, "DownloadMbps") * 1.1 && RepeatedGain("Download")) || (Value(a, "UploadMbps") > Value(b, "UploadMbps") * 1.1 && RepeatedGain("Upload")))
        {
            if (Value(a, "DownloadMbps") < Value(b, "DownloadMbps") * .8 || Value(a, "UploadMbps") < Value(b, "UploadMbps") * .8) return "Tradeoff";
            return Value(a, "LoadedP95Ms") <= Math.Max(Value(b, "LoadedP95Ms") * 1.15, Value(b, "LoadedP95Ms") + 15) ? "Improved" : "Tradeoff";
        }
        return "NoClearGain";
    }
}
