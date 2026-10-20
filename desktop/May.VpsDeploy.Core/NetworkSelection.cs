using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class NetworkTuning
{
    public const int MaximumFlowBudgetMiB = 20 * 1024;
    public const double MinimumTransferSeconds = 1;
    public static string[] Families(JsonObject options) => options.Text("Family") == "Both" ? ["IPv4", "IPv6"] : [options.Text("Family", "IPv4")];
    public static bool HasIpv6LandingEgress(JsonObject plan) => plan.Flag("Shadowsocks.SecondaryIpv6Enabled") && plan.Text("Shadowsocks.SecondaryIpv6Address") != "";
    public static string[] EgressFamilies(JsonObject options) => Topology(options) is "Landing" or "Relay"
        ? options.Text("PeerEgress", "IPv4") == "Both" ? ["IPv4", "IPv6"] : [options.Text("PeerEgress", "IPv4")]
        : ["IPv4"];
    public static int SelectedPathCount(JsonObject options) => Families(options).Length * EgressFamilies(options).Length;
    // Keep the persisted field for old reports; it now partitions every selected path.
    private static int BudgetPartitions(JsonObject options) => Math.Max(SelectedPathCount(options), options.Number("BudgetFamilyCount", 1));
    public static int FlowBudgetMiB(JsonObject options) => options.Text("TestSize") switch
    {
        "Light" => 80, "Full" => 640, "Quick" => 128, "Standard" => 1024,
        "Deep" => 4096, "Extended" => 10240, "Maximum" => MaximumFlowBudgetMiB,
        "Custom" => options.Number("TrafficBudgetMiB"), _ => throw new OperationException("测试流量档位无效。")
    };
    public static string BudgetDescription(JsonObject options) => "本次调优总预算 " + FlowBudgetMiB(options) + " MiB（最多 20 GiB），所有选中地址族、双向及应用前后复测共用。"
        + "共 " + SelectedPathCount(options) + " 条路径；约 20% 预留给探测和协议开销，其余前后各半；本轮每条路径有效载荷最多 " + PayloadBudget(options) / 1048576 + " MiB。"
        + "不自动加量或重试；达到时间或流量上限即停止。实际计费还受重传、协议及服务商统计口径影响，预留不是计费硬限额。";
    public static JsonObject FamilyOptions(JsonObject options, string family)
    {
        if (!Families(options).Contains(family)) throw new OperationException("地址族不在本轮选择范围内。");
        var result = options.DeepClone().AsObject(); result["Family"] = family; result["BudgetFamilyCount"] = SelectedPathCount(options);
        return result;
    }
    public static JsonObject[] SelectedPaths(JsonObject options) => Families(options).SelectMany(family => EgressFamilies(options).Select(egress =>
    {
        var result = FamilyOptions(options, family);
        if (Topology(options) is "Landing" or "Relay") result["PeerEgress"] = egress;
        return result;
    })).ToArray();
    public static string PathKey(JsonObject options) => Topology(options) + ":" + options.Text("Protocol") + ":" + options.Text("Family")
        + (Topology(options) == "Relay" ? ":" + options.Text("PeerFamily", "IPv4") : "")
        + (Topology(options) is "Landing" or "Relay" ? ":" + options.Text("PeerEgress", "IPv4") : "");
    public static string PathLabel(JsonObject options) => "连接 VPS：" + options.Text("Family", "IPv4").Replace("Both", "IPv4 和 IPv6")
        + (Topology(options) == "Relay" ? " · 入口→落地：" + options.Text("PeerFamily", "IPv4") : "")
        + (Topology(options) is "Landing" or "Relay" ? " · 落地→网站：" + options.Text("PeerEgress", "IPv4").Replace("Both", "IPv4 和 IPv6") : "");
    public static JsonObject[] PathReports(JsonObject report) => report["Paths"] is JsonArray paths ? paths.OfType<JsonObject>().ToArray() : [report];
    private static bool CompleteSelection(JsonObject report)
    {
        var expected = SelectedPaths(report["Options"]!.AsObject()); var actual = PathReports(report);
        if (actual.Length != expected.Length || actual.Select(p => PathKey(p["Options"]!.AsObject())).Distinct().Count() != expected.Length) return false;
        return expected.All(options => actual.Any(path => ArchiveStore.Fingerprint(path["Options"]!.AsObject()) == ArchiveStore.Fingerprint(options)));
    }
    public static string SelectionFingerprint(ArchiveStore store, JsonObject plan, JsonObject secrets, JsonObject options, string instance)
    {
        var parts = new JsonObject();
        foreach (var selected in SelectedPaths(options))
        {
            using var path = ResolvePath(store, plan, secrets, selected, instance);
            parts[EgressFamilies(options).Length == 1 ? selected.Text("Family") : PathKey(selected)] = path.Fingerprint;
        }
        return parts.Count == 1 ? parts.First().Value!.ToString() : ArchiveStore.Fingerprint(parts);
    }
    private static JsonObject DirectionReport(JsonObject report, string direction)
    {
        var result = report.DeepClone().AsObject(); result["Options"]!["PriorityDirection"] = direction; return result;
    }
    private static bool GuardReady(JsonObject report)
    {
        var options = report["Options"]!.AsObject(); var client = report["Client"]!.AsObject();
        var startup = (client["Startup"] as JsonArray ?? []).OfType<JsonObject>().Where(x => x.Flag("Complete") && Value(x, "Milliseconds") > 0).ToArray();
        var idle = Values(client, "IdleLatencyMs"); var loaded = Values(client, "LoadedLatencyMs");
        return client.Text("EvidencePolicy") == EvidencePolicy && client.Text("Status") == "Measured" && client.Flag("EgressVerified")
            && new[] { "Download", "Upload" }.All(d => DirectionEvidence(report, d).Flag("Eligible"))
            && new[] { "Cloudflare", "Hetzner" }.All(e => startup.Where(t => t.Text("Endpoint") == e).Select(t => t.Number("Round")).Distinct().Count() >= 3)
            && idle.Length >= 3 && loaded.Length >= 3 && Percentile(loaded, .95) <= Math.Max(Percentile(idle, .95) * 1.5, Percentile(idle, .95) + 30)
            && Value(report, "ServerAfter.Cpu.BusyPercent") < 85 && Value(report, "ServerAfter.Cpu.StealPercent") < 10
            && DateTimeOffset.TryParse(report.Text("StartedAt"), out var start) && DateTimeOffset.TryParse(report.Text("At"), out var end) && start <= end && InPeak(start, options) == InPeak(end, options);
    }
    public static JsonObject Analyze(JsonObject report, IEnumerable<JsonObject>? history = null)
    {
        if (report["Paths"] is JsonArray)
        {
            var paths = PathReports(report);
            var analyses = paths.Select(r => Analyze(r, (history ?? []).SelectMany(PathReports))).ToArray();
            var valid = CompleteSelection(report) && paths.All(GuardReady)
                && paths.All(p => p.Text("ServerAfter.BootId") == report.Text("ServerAfter.BootId") && p.Text("ServerAfter.Kernel") == report.Text("ServerAfter.Kernel") && p.Long("ServerAfter.MemoryKiB") == report.Long("ServerAfter.MemoryKiB") && ArchiveStore.Fingerprint(p.At("ServerAfter.Sysctl")!) == ArchiveStore.Fingerprint(report.At("ServerAfter.Sysctl")!) && QueueFingerprint(p["ServerAfter"]!.AsObject()) == QueueFingerprint(report["ServerAfter"]!.AsObject()))
                && DateTimeOffset.TryParse(report.Text("StartedAt"), out var start) && DateTimeOffset.TryParse(report.Text("At"), out var end) && InPeak(start, report["Options"]!.AsObject()) == InPeak(end, report["Options"]!.AsObject());
            var candidates = analyses.Where(a => a.Text("Profile") == "EntryMeasured").ToArray();
            return new JsonObject { ["EvidencePolicy"] = EvidencePolicy, ["Profile"] = valid && candidates.Length > 0 ? "EntryMeasured" : Topology(report["Options"]!.AsObject()) == "Landing" ? "LandingBasic" : "EntryBasic",
                ["BufferTargetBytes"] = valid && candidates.Length > 0 ? candidates.Max(a => a.Long("BufferTargetBytes")) : 0,
                ["BufferCapBytes"] = candidates.Length > 0 ? candidates.Min(a => a.Long("BufferCapBytes")) : 0,
                ["Paths"] = new JsonArray(analyses.Select(a => a.DeepClone()).ToArray()),
                ["Notes"] = new JsonArray("连接 VPS 的 IP 与落地访问网站的 IP 分别展开测量，不合并重传率或速率。共用 TCP 参数只应用一次，所有选中路径复测通过后才保留。",
                    valid ? "各路径均具备双向保护证据；收益仍需前后复测确认。" : "至少一条路径未完成或双向证据不足；未取得的数据不按通过处理，仅保留基础建议。") };
        }
        var options = report["Options"]!.AsObject();
        if (Priority(options) != "Balanced")
        {
            var single = AnalyzeSingle(report, history);
            if (!GuardReady(report)) { single["Profile"] = Topology(options) == "Landing" ? "LandingBasic" : "EntryBasic"; single["BufferTargetBytes"] = 0; single["Notes"]!.AsArray().Add("双向保护证据不足，不以一个方向的改善掩盖另一方向未知的状态。"); }
            return single;
        }
        var directions = new[] { "Download", "Upload" };
        var directional = directions.Select(d => AnalyzeSingle(DirectionReport(report, d), (history ?? []).Select(h => DirectionReport(h, d)))).ToArray();
        var result = directional[0].DeepClone().AsObject(); var eligible = directional.Where(a => a.Text("Profile") == "EntryMeasured").ToArray();
        result["PriorityDirection"] = "Balanced"; result["TcpRetransmitPercent"] = null; result["LossEvidence"] = LossEvidence(report);
        result["DirectionalAnalysis"] = new JsonObject { ["Download"] = directional[0].DeepClone(), ["Upload"] = directional[1].DeepClone() };
        result["Profile"] = GuardReady(report) && eligible.Length > 0 ? "EntryMeasured" : Topology(options) == "Landing" ? "LandingBasic" : "EntryBasic";
        result["BufferTargetBytes"] = result.Text("Profile") == "EntryMeasured" ? eligible.Max(a => a.Long("BufferTargetBytes")) : 0;
        result["SendBufferLimited"] = eligible.Any(a => a.Flag("SendBufferLimited"));
        result["Notes"] = new JsonArray(directional.SelectMany(a => a.Strings("Notes")).Append("双向均衡：上传和下载分别检查；一方明显退化即不保留。单目标上传只能用于当前目标的退化保护，不能证明全局上传收益。").Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        return result;
    }
    private static JsonObject? BothDirectionGuard(JsonObject before, JsonObject after)
    {
        JsonObject Failure(string result, string code, string reason) => new() { ["Policy"] = ComparisonPolicy, ["Result"] = result, ["ReasonCode"] = code, ["Reason"] = reason };
        foreach (var direction in new[] { "Download", "Upload" })
        {
            var b = DirectionEvidence(before, direction); var a = DirectionEvidence(after, direction);
            if (!b.Flag("Eligible") || !a.Flag("Eligible")) return Failure("Inconclusive", "MissingBidirectionalEvidence", direction + " 匹配 TCP 样本不足，不能验收双向保护。");
            if (Value(a, "Percent") - Value(b, "Percent") > Math.Max(LossTolerancePercentagePoints, Value(b, "Percent") * LossToleranceRelative)) return Failure("Regression", "OppositeDirectionLossWorsened", direction + " 重传明显恶化，不能用另一方向的提速抵销。");
            var old = Transfers(before).Where(t => t.Text("Direction") == direction).ToArray(); var current = Transfers(after).Where(t => t.Text("Direction") == direction).ToArray();
            foreach (var group in old.GroupBy(t => t.Text("Endpoint") + ":" + t.Number("Streams")))
            {
                var samples = current.Where(t => t.Text("Endpoint") + ":" + t.Number("Streams") == group.Key).ToArray();
                if (samples.Length < 2) return Failure("Inconclusive", "MissingBidirectionalSpeed", direction + " 单/多连接复测不完整。");
                if (Percentile(samples.Select(t => Value(t, "Mbps")), .5) < Percentile(group.Select(t => Value(t, "Mbps")), .5) * .8) return Failure("Tradeoff", "OppositeDirectionSpeedCost", direction + " 至少一个目标的单/多连接速度下降超过 20%，不以其他收益抵销。");
            }
            foreach (var endpoint in old.Select(t => t.Text("Endpoint")).Distinct())
            {
                double Loss(JsonObject[] all)
                {
                    var samples = all.Where(t => t.Text("Endpoint") == endpoint && t.Flag("TcpEvidence.CountersValid") && t.Flag("TcpEvidence.PayloadMatched")).ToArray();
                    var sent = samples.Sum(t => t.Long("TcpEvidence.SentSegments"));
                    return samples.Select(t => t.Number("Round")).Distinct().Count() >= 2 && sent >= MinimumLossSegments / 2 ? 100d * samples.Sum(t => t.Long("TcpEvidence.RetransmittedSegments")) / sent : double.NaN;
                }
                var original = Loss(old); var updated = Loss(current);
                if (!double.IsFinite(original) || !double.IsFinite(updated)) return Failure("Inconclusive", "MissingBidirectionalEndpoint", direction + " 的目标配对证据不完整。");
                if (updated - original > Math.Max(LossTolerancePercentagePoints, original * LossToleranceRelative)) return Failure("Regression", "EndpointLossWorsened", direction + " 至少一个目标的重传明显恶化。");
            }
        }
        return null;
    }
    public static JsonObject CompareDetailed(JsonObject before, JsonObject after)
    {
        if (before["Paths"] is JsonArray || after["Paths"] is JsonArray)
        {
            var old = PathReports(before); var current = PathReports(after);
            if (before["Paths"] is not JsonArray || after["Paths"] is not JsonArray || current.Length != old.Length
                || before.Text("PathFingerprint") != after.Text("PathFingerprint") || !CompleteSelection(before) || !CompleteSelection(after)
                || ArchiveStore.Fingerprint(before["Options"]!.AsObject()) != ArchiveStore.Fingerprint(after["Options"]!.AsObject()))
                return SelectionDecision([], "Inconclusive", "AddressFamiliesChanged", "连接方式、落地出站 IP 或测试路径不一致，不能验收共享参数。");
            if (new[] { before, after }.Any(r => !DateTimeOffset.TryParse(r.Text("StartedAt"), out var start) || !DateTimeOffset.TryParse(r.Text("At"), out var end) || start > end || InPeak(start, r["Options"]!.AsObject()) != InPeak(end, r["Options"]!.AsObject())))
                return SelectionDecision([], "Inconclusive", "MixedTimeWindow", "整轮多路径采集跨越高峰边界，不能把不同时间窗口合并验收。");
            var comparisons = old.Select(p => ComparePath(p, current.Single(n => PathKey(n["Options"]!.AsObject()) == PathKey(p["Options"]!.AsObject())), true)).ToArray();
            return CombineDecisions(comparisons, "所有连接与落地出站 IP 组合分别验收；任一路径退化或未测完整均恢复共享参数。", "Paths");
        }
        return ComparePath(before, after, false);
    }
    private static JsonObject ComparePath(JsonObject before, JsonObject after, bool guardOnlyAllowed)
    {
        var mode = Priority(before["Options"]!.AsObject());
        if (mode != Priority(after["Options"]!.AsObject())) return SelectionDecision([], "Inconclusive", "DirectionChanged", "优化偏好变化，前后不可比较。");
        if (mode != "Balanced")
        {
            var b = before.DeepClone().AsObject(); if (guardOnlyAllowed) b["Analysis"]!["Profile"] = "EntryMeasured";
            var decision = CompareDirectionalDetailed(b, after);
            if (decision.Text("Result") is "Improved" or "NoClearGain") return BothDirectionGuard(before, after) ?? decision;
            return decision;
        }
        var comparisons = new List<JsonObject>();
        foreach (var direction in new[] { "Download", "Upload" })
        {
            var b = DirectionReport(before, direction); var a = DirectionReport(after, direction);
            b["Analysis"] = AnalyzeSingle(b); a["Analysis"] = AnalyzeSingle(a);
            if (b.Text("Analysis.Profile") != "EntryMeasured" && !(guardOnlyAllowed && direction == "Download")) continue;
            b["Analysis"]!["Profile"] = "EntryMeasured"; var decision = CompareDirectionalDetailed(b, a); decision["Direction"] = direction; comparisons.Add(decision);
        }
        var guard = BothDirectionGuard(before, after); if (guard != null) return guard;
        return CombineDecisions(comparisons.ToArray(), "双向分别检查，至少一方有多目标重复收益，另一方未明显退化；上传单目标不宣称全局优化通过。", "Directions");
    }
    private static JsonObject CombineDecisions(JsonObject[] decisions, string reason, string field)
    {
        foreach (var state in new[] { "Regression", "Tradeoff", "Inconclusive" })
            if (decisions.FirstOrDefault(d => d.Text("Result") == state) is { } failed) return SelectionDecision(decisions, state, failed.Text("ReasonCode"), failed.Text("Reason"), field);
        return decisions.Any(d => d.Text("Result") == "Improved") ? SelectionDecision(decisions, "Improved", "SelectionImproved", reason, field)
            : SelectionDecision(decisions, decisions.Length == 0 ? "Inconclusive" : "NoClearGain", "NoRepeatedSpeedGain", "所选方向没有取得可重复的多目标收益。", field);
    }
    private static JsonObject SelectionDecision(JsonObject[] decisions, string result, string code, string reason, string field = "Directions") => new()
    {
        ["Policy"] = ComparisonPolicy, ["Result"] = result, ["ReasonCode"] = code, ["Reason"] = reason,
        [field] = new JsonArray(decisions.Select(d => d.DeepClone()).ToArray())
    };
}
