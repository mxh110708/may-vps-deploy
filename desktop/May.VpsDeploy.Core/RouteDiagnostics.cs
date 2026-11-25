using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record RouteDiagnosticSegment(string Id, string Label, string Instance, string Address, int Port, string Transport, string Component, string ComponentHash);
public sealed record RouteDiagnosticPlan(string SchemeId, ClientDiagnosticRoute Route, IReadOnlyList<RouteDiagnosticSegment> Segments, IReadOnlyList<string> Instances, string SourceFingerprint)
{
    public void Clear() { Route.Entry.Clear(); Route.Landing?.Clear(); }
}

// This model describes an explicitly chosen path. It never guesses the running
// client's selected group and never computes a remote RTT by subtracting probes.
public static class RouteDiagnostics
{
    public const int Schema = 1;
    public static RouteDiagnosticPlan Plan(ArchiveStore store, JsonObject scheme, string entry, string? landing = null)
    {
        _ = Id(scheme.Text("Id"));
        var route = ClientTopology.DiagnosticRoute(scheme, entry, landing);
        if (route.Entry.Text("sing_box.type") is "hysteria2" or "tuic") route = route with { RequiresApplicationUdp = true };
        try
        {
            _ = Id(route.Entry.Text("Id")); if (route.Landing != null) _ = Id(route.Landing.Text("Id"));
            VerifySources(store, route);
            var segments = new List<RouteDiagnosticSegment>(); var instances = new HashSet<string>(StringComparer.Ordinal);
            foreach (var (node, prefix) in new[] { (route.Entry, "Entry"), (route.Landing, "Landing") }.Where(p => p.Item1 != null))
            {
                var origin = node!["TcpChainOrigin"] as JsonObject;
                if (origin != null)
                {
                    var record = ArchiveStore.ReadJson(TcpChains.FileName(store.Paths, origin.Text("Id")));
                    var chain = record["Configuration"]!.AsObject(); foreach (var instance in TcpChains.Instances(chain)) instances.Add(instance);
                    foreach (var front in new[] { true, false })
                    {
                        var instance = chain.Text(front ? "FrontInstance" : "RelayInstance");
                        var plan = TcpChains.Plan(store, instance); var component = TcpChains.Component(chain);
                        var rule = TcpForwarding.Rules(plan[component]!.AsObject()).Single(r => r.Text("Id") == TcpChains.RuleId(chain, front));
                        Add(prefix + (front ? ".FrontRelay" : ".RelayLanding"), front ? "前置 → 中转" : "中转 → 落地", instance, rule, component, TcpChains.Transport(chain));
                    }
                }
                else if (node["ForwardedOrigin"] is JsonObject forward)
                {
                    var instance = forward.Text("Instance"); var plan = TcpChains.Plan(store, instance); instances.Add(instance);
                    var rule = TcpForwarding.Rules(plan["TcpForwarding"]!.AsObject()).Single(r => r.Text("Id") == forward.Text("RuleId"));
                    Add(prefix + ".Forward", "转发 → 主目标", instance, rule, "TcpForwarding", "TCP");
                    if (rule["TargetGroup"] is JsonObject)
                        foreach (var (target, i) in ForwardTargetGroups.Targets(rule).Skip(1).Select((t, i) => (t, i + 1)))
                            Add(prefix + (ForwardTargetGroups.Balanced(rule) ? ".Target." + ForwardTargetGroups.TargetIds(rule).ElementAt(i) : ".Standby"), "转发 → 目标 " + (i + 1) + "（独立检查，不代表当前选用）", instance, rule, "TcpForwarding", "TCP", target.Address, target.Port);
                }
                else
                {
                    var instance = node.Text("InboundOrigin.Instance", node.Text("ManagedOrigin.Instance"));
                    if (instance != "") instances.Add(instance);
                }
            }
            if (segments.Count > 8) throw new OperationException("单次诊断最多检查八个受管分段。");
            var identity = new JsonObject { ["Route"] = route.Fingerprint, ["Segments"] = System.Text.Json.JsonSerializer.SerializeToNode(segments),
                ["Instances"] = new JsonArray(instances.Order(StringComparer.Ordinal).Select(i => (JsonNode?)JsonValue.Create(i)).ToArray()) };
            return new(scheme.Text("Id"), route, segments, instances.Order(StringComparer.Ordinal).ToArray(), ArchiveStore.Fingerprint(identity));

            void Add(string id, string label, string instance, JsonObject rule, string component, string transport, string? address = null, int? port = null)
            {
                var state = ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(instance), "deployment-state.json"));
                var hash = state.Text(component + ".RemoteHash"); if (!Digest(hash)) throw new OperationException("分段来源缺少已应用组件摘要，请先检查原线路。");
                var target = address ?? rule.Text("TargetAddress"); var targetPort = port ?? rule.Number("TargetPort");
                if (!IPAddress.TryParse(target, out var ip) || ip.IsIPv4MappedToIPv6 || target.Contains('%') || targetPort is < 1 or > 65535) throw new OperationException("分段来源地址或端口无效。");
                segments.Add(new(id, PrefixLabel(id) + label, instance, ip.ToString(), targetPort, transport, component, hash));
            }
        }
        catch { route.Entry.Clear(); route.Landing?.Clear(); throw; }
    }
    private static string PrefixLabel(string id) => id.StartsWith("Landing", StringComparison.Ordinal) ? "客户端落地 · " : "入口 · ";
    public static void VerifySources(ArchiveStore store, ClientDiagnosticRoute route)
    {
        var nodes = new[] { route.Entry, route.Landing }.OfType<JsonObject>().ToArray();
        ManagedNodeSources.Verify(store, new JsonArray(nodes.Where(n => n["ManagedOrigin"] != null).Select(n => n["ManagedOrigin"]!.DeepClone()).ToArray()));
        ForwardedNodeSources.VerifyNodes(store, nodes);
    }
    public static bool Current(ArchiveStore store, JsonObject scheme, JsonObject report)
    {
        RouteDiagnosticPlan? plan = null;
        try
        {
            var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
            var entry = nodes.SingleOrDefault(n => n.Text("Id") == report.Text("EntryId"));
            var landing = report.Text("LandingId") == "" ? null : nodes.SingleOrDefault(n => n.Text("Id") == report.Text("LandingId"));
            if (entry == null || report.Text("LandingId") != "" && landing == null) return false;
            plan = Plan(store, scheme, entry.Text("name"), landing?.Text("name"));
            return report.Text("Status") != "SourceChanged" && plan.SourceFingerprint == report.Text("SourceFingerprint");
        }
        catch (Exception e) when (e is OperationException or IOException or UnauthorizedAccessException or InvalidOperationException) { return false; }
        finally { plan?.Clear(); }
    }
    public static string Id(string value) => Regex.IsMatch(value, "^[a-f0-9]{32}$", RegexOptions.CultureInvariant) ? value : throw new OperationException("诊断记录身份无效。");
    public static bool Digest(string value) => Regex.IsMatch(value, "^[a-f0-9]{64}$", RegexOptions.CultureInvariant);
    public static string StatusLabel(string status) => status switch
    {
        "Reachable" => "所选业务路径通过", "Degraded" => "业务路径通过 · 分段有待核对", "Failed" => "业务路径未通过", "TimedOut" => "诊断超时",
        "Cancelled" => "诊断已取消", "SourceChanged" => "来源已变化 · 需重测", _ => "诊断未完成"
    };
    public static string StageLabel(string id) => id switch
    {
        "Dns" => "本机 DNS", "Tcp" => "本机 → 入口 TCP", "Core" => "隔离核心准备", "TransportTls" => "入口 TLS／协商",
        "EntryHttps" => "入口协议与 HTTPS 出口（合并阶段）", "EntryUdp" => "入口应用 UDP DNS 回程", "ChainHttps" => "经客户端落地的协议与 HTTPS 出口（合并阶段）",
        "Preparation" => "诊断准备", "Source" => "来源复核", "NetworkContext" => "观测网络变化", "Monitor" => "监测旁证读取",
        "RemoteLeg" => "入口 → 客户端落地的纯远端 RTT", "Udp" => "QUIC 单独端口检查",
        _ when id.StartsWith("Entry.", StringComparison.Ordinal) || id.StartsWith("Landing.", StringComparison.Ordinal) => "受管远端分段",
        _ => "未独立测量"
    };
    public static string EvidenceStatus(string status) => status switch { "Connected" => "连接通过", "RouteAvailable" => "路由可选", "Passed" => "通过", "Failed" => "未通过", "Cancelled" => "已取消", _ => "未测量" };
    public static JsonArray MonitorEvidence(RouteDiagnosticPlan plan, MonitorReadConnection? connection, MonitorReadSnapshot? snapshot, DateTimeOffset now, bool failed)
    {
        var rows = new JsonArray();
        foreach (var instance in plan.Instances)
        {
            var id = connection?.Bindings.GetValueOrDefault(instance); var node = id == null ? null : snapshot?.Nodes.GetValueOrDefault(id);
            var trusted = connection != null && snapshot?.ServerInstanceId == connection.ServerInstanceId && snapshot.CredentialExpiresAt > now && snapshot.ReceivedAt <= now.AddSeconds(5) && snapshot.CapturedAt <= now.AddSeconds(5);
            var status = id == null ? "未绑定监测 UUID" : failed ? "监测读取失败" : snapshot == null ? "尚未读取监测" : !trusted ? "监测身份或凭据无效" : node == null ? "快照未返回绑定节点" : node.Status(now, snapshot.ReceivedAt, false);
            var row = new JsonObject { ["Instance"] = instance, ["Kind"] = "MonitorObservation", ["Status"] = status, ["ReportAt"] = node?.ReportAt, ["ReceivedAt"] = snapshot?.ReceivedAt };
            if (trusted && node?.Metrics is { } metrics)
            { row["CpuPercent"] = metrics.CpuPercent; row["MemoryUsed"] = metrics.MemoryUsed; row["UploadPerSec"] = metrics.UploadPerSec; row["DownloadPerSec"] = metrics.DownloadPerSec; }
            rows.Add(row);
        }
        return rows;
    }

    public static JsonObject Quality(IEnumerable<JsonObject> history, JsonObject selected)
    {
        var samples = history.Where(r => r.Text("SourceFingerprint") == selected.Text("SourceFingerprint") && r.Text("EnvironmentFingerprint") == selected.Text("EnvironmentFingerprint") &&
            r.Text("Profile") == selected.Text("Profile") && r.Text("Profile") != "" && r.Text("Status") is "Reachable" or "Degraded" or "Failed" or "TimedOut").ToArray();
        var result = new JsonObject { ["Samples"] = samples.Length, ["Passed"] = samples.Count(r => r.Text("Status") is "Reachable" or "Degraded"), ["Stages"] = new JsonArray() };
        foreach (var id in new[] { "Tcp", "EntryHttps", "EntryUdp", "ChainHttps" })
        {
            var values = samples.SelectMany(r => (r["Stages"] as JsonArray ?? []).OfType<JsonObject>()).Where(s => s.Text("Id") == id && s.Text("Status") == "Passed" && s.Text("Kind") == "Measured" && s["Milliseconds"] != null).Select(s => s.Long("Milliseconds")).Order().ToArray();
            if (values.Length == 0) continue;
            result["Stages"]!.AsArray().Add(new JsonObject { ["Id"] = id, ["Samples"] = values.Length,
                ["Median"] = values.Length % 2 == 0 ? (values[values.Length / 2 - 1] + values[values.Length / 2]) / 2d : values[values.Length / 2],
                ["P95"] = values[(int)Math.Ceiling(values.Length * .95) - 1], ["Peak"] = values[^1] });
        }
        foreach (var segment in (selected["Segments"] as JsonArray ?? []).OfType<JsonObject>())
        {
            var id = segment.Text("Id");
            var values = samples.SelectMany(r => (r["Segments"] as JsonArray ?? []).OfType<JsonObject>()).Where(s => s.Text("Id") == id && s.Text("Status") == "Connected" && s.Text("Kind") == "Measured" && s["Milliseconds"] != null).Select(s => s.Long("Milliseconds")).Order().ToArray();
            if (values.Length == 0) continue;
            result["Stages"]!.AsArray().Add(new JsonObject { ["Id"] = id, ["Label"] = segment.Text("Label") + "（TCP connect）", ["Samples"] = values.Length,
                ["Median"] = values.Length % 2 == 0 ? (values[values.Length / 2 - 1] + values[values.Length / 2]) / 2d : values[values.Length / 2], ["P95"] = values[(int)Math.Ceiling(values.Length * .95) - 1], ["Peak"] = values[^1] });
        }
        return result;
    }
}

// Separate, encrypted and bounded history: diagnostics do not dirty a client
// scheme, invalidate its export candidate or overwrite a concurrently edited form.
public sealed class RouteDiagnosticHistory(ArchiveStore store)
{
    public const int MaximumRecords = 64;
    public string FileName(string scheme) => store.Paths.Resolve("private/route-diagnostics/" + RouteDiagnostics.Id(scheme) + ".private.json");
    private FileStream Lock(string scheme)
    {
        var file = FileName(scheme) + ".lock"; Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        try { return new(file, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { throw new OperationException("诊断历史正在更新，请稍后重试。"); }
    }
    public IReadOnlyList<JsonObject> Read(string scheme)
    {
        using var guard = Lock(scheme); return Load(scheme).OfType<JsonObject>().Select(r => r.DeepClone().AsObject()).ToArray();
    }
    private JsonArray Load(string scheme)
    {
        var file = FileName(scheme); if (!File.Exists(file)) return [];
        if (new FileInfo(file).Length > 3 * 1024 * 1024) throw new OperationException("诊断历史超过大小限制，保留原文件。");
        var value = store.ReadSecret(file);
        if (value.Number("Schema") != 1 || value.Text("SchemeId") != scheme || value["Reports"] is not JsonArray rows || rows.Count > MaximumRecords) throw new OperationException("诊断历史格式无效，保留原文件。");
        foreach (var row in rows.OfType<JsonObject>()) Validate(row);
        if (rows.Any(r => r is not JsonObject) || rows.Select(r => r!.Text("Id")).Distinct().Count() != rows.Count) throw new OperationException("诊断历史存在重复或无效记录。");
        return rows.DeepClone().AsArray();
    }
    public void Append(string scheme, JsonObject report)
    {
        Validate(report); using var guard = Lock(scheme); var rows = Load(scheme);
        if (rows.Any(r => r!.Text("Id") == report.Text("Id"))) throw new OperationException("诊断记录已存在，未重复添加。");
        rows.Add(report.DeepClone()); while (rows.Count > MaximumRecords) rows.RemoveAt(0);
        store.WriteSecret(FileName(scheme), new() { ["Schema"] = 1, ["SchemeId"] = scheme, ["Reports"] = rows });
    }
    public string Fingerprint(string scheme) => File.Exists(FileName(scheme)) ? ClientSchemes.SourceFingerprint(FileName(scheme)) : "Absent";
    public void Clear(string scheme, string reviewedFingerprint)
    {
        using var guard = Lock(scheme);
        if (Fingerprint(scheme) != reviewedFingerprint) throw new OperationException("诊断历史在审阅后变化，请重新审阅。");
        if (File.Exists(FileName(scheme))) File.Delete(FileName(scheme));
    }
    private static void Validate(JsonObject report)
    {
        _ = RouteDiagnostics.Id(report.Text("Id"));
        string[] fields = ["Schema", "Id", "At", "SourceFingerprint", "EnvironmentFingerprint", "Profile", "Path", "EntryId", "LandingId", "Status", "FailureStage", "Protocol", "Stages", "Segments", "Monitor", "Scope", "EntryEgress", "ChainEgress", "ElapsedMilliseconds"];
        if (report.Any(p => !fields.Contains(p.Key)) || report.Number("Schema") != RouteDiagnostics.Schema || !RouteDiagnostics.Digest(report.Text("SourceFingerprint")) || !RouteDiagnostics.Digest(report.Text("EnvironmentFingerprint")) ||
            report.Text("Profile") != "" && !RouteDiagnostics.Digest(report.Text("Profile")) || !DateTimeOffset.TryParse(report.Text("At"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _) ||
            report.Text("Status") is not ("Reachable" or "Degraded" or "Failed" or "TimedOut" or "Cancelled" or "SourceChanged" or "Incomplete") ||
            report["Stages"] is not JsonArray stages || stages.Count > 32 || report["Segments"] is not JsonArray segments || segments.Count > 8 || ArchiveStore.JsonBytes(report).Length > 24576)
            throw new OperationException("诊断记录格式或大小无效。");
        foreach (var row in stages.OfType<JsonObject>().Concat(segments.OfType<JsonObject>()))
        {
            if (row.Text("Kind") is not ("Measured" or "NotMeasured" or "RouteOnly") || row.Any(p => p.Key is not ("Id" or "Label" or "Status" or "Kind" or "Detail" or "Milliseconds" or "FromInstance" or "Transport")) ||
                row["Milliseconds"] != null && (row["Milliseconds"] is not JsonValue v || !v.TryGetValue<long>(out var ms) || ms is < 0 or > 150000 || row.Text("Kind") != "Measured"))
                throw new OperationException("诊断阶段含无效时长或未知字段。");
        }
        if (stages.Any(s => s is not JsonObject) || segments.Any(s => s is not JsonObject)) throw new OperationException("诊断阶段格式无效。");
        if (report["Monitor"] is not JsonArray monitor || monitor.Count > 100 || monitor.Any(n => n is not JsonObject || n.AsObject().Any(p => p.Key is not ("Instance" or "Kind" or "Status" or "ReportAt" or "ReceivedAt" or "CpuPercent" or "MemoryUsed" or "UploadPerSec" or "DownloadPerSec")))) throw new OperationException("监测旁证含未知字段或格式无效。");
        foreach (var key in new[] { "EntryEgress", "ChainEgress" })
            if (report[key] != null && (report[key] is not JsonObject exit || exit.Any(p => p.Key is not ("Address" or "Family" or "Verified")) || !IPAddress.TryParse(exit.Text("Address"), out var ip) || exit.Text("Family") != (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "IPv4" : "IPv6"))) throw new OperationException("诊断出口格式无效。");
    }
}
