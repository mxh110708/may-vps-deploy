using System.Globalization;
using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public static partial class NetworkTuning
{
    public const long MinimumLossSegments = 1000;
    public const double LossTolerancePercentagePoints = .2;
    public const double LossToleranceRelative = .2;
    public const double ThroughputGainFraction = .1;
    public const string ComparisonPolicy = "LossFirst.v2";
    public const string ComparisonPolicyDescription = "优先降低关键方向的匹配 TCP 重传参考，阈值为 0.2 个百分点与基线比例 20% 中较大者。差异接近时，关键方向须在多个目标、多数同轮样本中提速至少 10%；短连接启动和排队延迟不能明显恶化。全机计数和 5 次 UDP 响应不决定精细调优。";

    public static JsonObject LossEvidence(JsonObject report)
    {
        if (report.Text("Client.EvidencePolicy") == EvidencePolicy) return DirectionEvidence(report);
        bool Counter(string phase, string name, out long value)
        {
            var counters = report.At(phase + ".Counters") as JsonObject;
            return long.TryParse(counters?[name]?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value) && value >= 0;
        }
        var valid = Counter("ServerBefore", "TcpRetransSegs", out var r0) & Counter("ServerAfter", "TcpRetransSegs", out var r1)
            & Counter("ServerBefore", "TcpOutSegs", out var s0) & Counter("ServerAfter", "TcpOutSegs", out var s1);
        valid &= r1 >= r0 && s1 >= s0;
        var boot0 = report.Text("ServerBefore.BootId"); var boot1 = report.Text("ServerAfter.BootId");
        valid &= boot0 == boot1;
        var retrans = valid ? r1 - r0 : 0; var sent = valid ? s1 - s0 : 0;
        // OutSegs excludes segments containing only retransmitted octets (RFC 4022).
        // This is retransmissions per new sent segment, not a packet-loss estimator.
        var percent = valid && sent > 0 ? 100d * retrans / sent : (double?)null;
        return new JsonObject { ["Scope"] = "VpsTcpCounters", ["CountersValid"] = valid, ["Eligible"] = valid && sent >= MinimumLossSegments,
            ["RetransmittedSegments"] = retrans, ["SentSegments"] = sent, ["Percent"] = percent,
            ["Status"] = !valid ? "CountersUnavailableOrReset" : sent < MinimumLossSegments ? "InsufficientSegments" : "Available" };
    }

    public static JsonObject CompareDetailed(JsonObject before, JsonObject after)
    {
        var b = before["Analysis"] as JsonObject ?? new(); var a = after["Analysis"] as JsonObject ?? new();
        var bl = LossEvidence(before); var al = LossEvidence(after);
        var tolerance = Math.Max(LossTolerancePercentagePoints, Value(bl, "Percent") * LossToleranceRelative);
        var decision = new JsonObject { ["Policy"] = ComparisonPolicy, ["LossBefore"] = bl, ["LossAfter"] = al,
            ["LossTolerancePercentagePoints"] = tolerance, ["ThroughputGainPercent"] = ThroughputGainFraction * 100 };
        JsonObject Finish(string result, string code, string reason) { decision["Result"] = result; decision["ReasonCode"] = code; decision["Reason"] = reason; return decision; }
        if (before.Text("Client.Status") != "Measured" || after.Text("Client.Status") != "Measured" || !before.Flag("Client.EgressVerified") || !after.Flag("Client.EgressVerified")
            || before.Text("SourceFingerprint") != after.Text("SourceFingerprint") || b.Text("Profile") != "EntryMeasured"
            || before.Text("Client.EvidencePolicy") != EvidencePolicy || after.Text("Client.EvidencePolicy") != EvidencePolicy || before.Text("PathFingerprint") != after.Text("PathFingerprint")
            || new[] { "Protocol", "Family", "TestSize", "TimeZoneId", "PeakStartHour", "PeakEndHour", "BandwidthMbps", "UploadMbps", "CapacityType", "Topology", "PriorityDirection", "PeerInstance", "PeerFamily", "PeerEgress" }.Any(k => before.Text("Options." + k) != after.Text("Options." + k))
            || before.Text("ServerAfter.Kernel") != after.Text("ServerAfter.Kernel") || before.Text("ServerAfter.BootId") != after.Text("ServerAfter.BootId"))
            return Finish("Inconclusive", "IncompatibleSamples", "采集未完成，或前后路径、套餐、内核及使用时段不同，不能比较。");
        if (!DateTimeOffset.TryParse(before.Text("At"), out var bt) || !DateTimeOffset.TryParse(after.Text("At"), out var at) || at < bt || InPeak(bt, before["Options"]!.AsObject()) != InPeak(at, after["Options"]!.AsObject()))
            return Finish("Inconclusive", "DifferentTimeWindows", "前后采集跨越了设定的高峰边界，或时间记录无效，不能判断参数收益。");
        if (new[] { before, after }.Any(r => !DateTimeOffset.TryParse(r.Text("StartedAt"), out var start) || !DateTimeOffset.TryParse(r.Text("At"), out var end) || start > end || InPeak(start, r["Options"]!.AsObject()) != InPeak(end, r["Options"]!.AsObject())))
            return Finish("Inconclusive", "MixedTimeWindow", "单轮采集跨越高峰边界或开始时间无效，不能用于参数比较。");
        var old = Transfers(before); var current = Transfers(after);
        if (old.GroupBy(Key).Any(g => g.Count() != 1) || current.GroupBy(Key).Any(g => g.Count() != 1))
            return Finish("Inconclusive", "DuplicateTransferSamples", "同轮传输样本重复，无法可靠核对吞吐。");
        var priority = Priority(before["Options"]!.AsObject()); decision["PriorityDirection"] = priority;
        var oldStarts = (before.At("Client.Startup") as JsonArray ?? []).OfType<JsonObject>().Where(t => t.Flag("Complete")).ToArray();
        var newStarts = (after.At("Client.Startup") as JsonArray ?? []).OfType<JsonObject>().Where(t => t.Flag("Complete")).ToArray();
        var endpoints = old.Where(t => t.Text("Direction") == priority).Select(t => t.Text("Endpoint")).Distinct().ToArray();
        if (oldStarts.GroupBy(t => t.Text("Endpoint") + ":" + t.Number("Round")).Any(g => g.Count() > 1) || newStarts.GroupBy(t => t.Text("Endpoint") + ":" + t.Number("Round")).Any(g => g.Count() > 1)) return Finish("Inconclusive", "DuplicateStartupSamples", "短连接样本重复，不能作为启动速度证据。");
        if (endpoints.Length < 2 || endpoints.Any(e => e == "" || oldStarts.Count(t => t.Text("Endpoint") == e) < 3 || newStarts.Count(t => t.Text("Endpoint") == e) < 3)
            || oldStarts.Any(t => Value(t, "Milliseconds") <= 0) || newStarts.Any(t => Value(t, "Milliseconds") <= 0))
            return Finish("Inconclusive", "MissingIndependentEvidence", "关键方向或短连接启动未覆盖两个独立目标，不从单一对端推导全局配置。");
        var startupCost = endpoints.Any(e => Percentile(newStarts.Where(t => t.Text("Endpoint") == e).Select(t => Value(t, "Milliseconds")), .95) > Math.Max(Percentile(oldStarts.Where(t => t.Text("Endpoint") == e).Select(t => Value(t, "Milliseconds")), .95) * 1.15, Percentile(oldStarts.Where(t => t.Text("Endpoint") == e).Select(t => Value(t, "Milliseconds")), .95) + 15));
        var keys = new[] { "DownloadSingleMbps", "DownloadMultiMbps", "UploadSingleMbps", "UploadMultiMbps" };
        if (keys.Any(k => Value(b, k) <= 0 || Value(a, k) <= 0)) return Finish("Inconclusive", "MissingThroughputSamples", "单连接或多连接传输信息缺失，无法核对速度代价。");
        if (new[] { before, after }.Any(r => Values(r["Client"]!.AsObject(), "IdleLatencyMs").Length < 3 || Values(r["Client"]!.AsObject(), "LoadedLatencyMs").Length < 3)
            || Value(after, "ServerAfter.Cpu.BusyPercent") >= 85 || Value(after, "ServerAfter.Cpu.StealPercent") >= 10)
            return Finish("Inconclusive", "MissingLatencyOrBusyHost", "响应样本不足或主机资源竞争较高，无法区分参数收益与其他负载。");
        if (!bl.Flag("Eligible") || !al.Flag("Eligible")) return Finish("Inconclusive", "MissingLossEvidence", "重传计数缺失、重置或发送段不足；不将缺失数据当作零丢包，也不只凭测速增快保留精细参数。");
        var change = Value(al, "Percent") - Value(bl, "Percent"); decision["LossChangePercentagePoints"] = change;
        if (change > tolerance) return Finish("Regression", "LossWorsened", "重传比例增加超过阈值；丢包参考退化优先于吞吐收益。");
        foreach (var endpoint in endpoints)
        {
            double EndpointLoss(JsonObject[] items) { var samples = items.Where(t => t.Text("Direction") == priority && t.Text("Endpoint") == endpoint && t.Flag("TcpEvidence.CountersValid") && t.Flag("TcpEvidence.PayloadMatched")).ToArray(); var sent = samples.Sum(t => t.Long("TcpEvidence.SentSegments")); return samples.Length >= 2 && sent >= MinimumLossSegments / 2 ? 100d * samples.Sum(t => t.Long("TcpEvidence.RetransmittedSegments")) / sent : double.NaN; }
            var original = EndpointLoss(old); var updated = EndpointLoss(current);
            if (!double.IsFinite(original) || !double.IsFinite(updated)) return Finish("Inconclusive", "MissingEndpointLoss", "独立目标的关键方向 TCP 样本不足。");
            if (updated - original > Math.Max(LossTolerancePercentagePoints, original * LossToleranceRelative)) return Finish("Regression", "EndpointLossWorsened", "至少一个独立目标的重传明显恶化；不以另一个目标的改善掩盖。");
        }
        if (startupCost) return Finish("Tradeoff", "ShortConnectionRegression", "短连接启动 p95 明显退化，即使长流提速或重传减少也不自动保留。");
        var oldQueue = Math.Max(0, Value(b, "LoadedP95Ms") - Value(b, "IdleP95Ms"));
        var newQueue = Math.Max(0, Value(a, "LoadedP95Ms") - Value(a, "IdleP95Ms"));
        decision["QueueDelayBeforeMs"] = oldQueue; decision["QueueDelayAfterMs"] = newQueue;
        if (newQueue > Math.Max(oldQueue * 1.25, oldQueue + 10)) return Finish(change < -tolerance ? "Tradeoff" : "Regression", "QueueDelayRegression", "负载相对空闲的附加延迟明显增加，避免以缓冲换吞吐。");
        string RateKey(JsonObject t) => t.Text("Endpoint") + ":" + t.Text("Direction") + ":" + t.Number("Streams");
        var oldRates = old.GroupBy(RateKey).ToDictionary(g => g.Key, g => Percentile(g.Select(t => Value(t, "Mbps")), .5));
        var newRates = current.GroupBy(RateKey).ToDictionary(g => g.Key, g => Percentile(g.Select(t => Value(t, "Mbps")), .5));
        if (oldRates.Keys.Any(k => !newRates.ContainsKey(k))) return Finish("Inconclusive", "MissingEndpointSpeed", "独立目标的单/多连接复测缺失，不能只比较合并平均值。");
        var severeSpeed = keys.Any(k => Value(a, k) < Value(b, k) * .7) || oldRates.Any(p => newRates[p.Key] < p.Value * .7);
        var severeLatency = Value(a, "LoadedP95Ms") > Math.Max(Value(b, "LoadedP95Ms") * 1.5, Value(b, "LoadedP95Ms") + 50);
        if (change < -tolerance)
        {
            var updated = current.ToDictionary(Key);
            var repeatedLoss = endpoints.All(e =>
            {
                var pairs = old.Where(t => t.Text("Direction") == priority && t.Text("Endpoint") == e && updated.ContainsKey(Key(t))).Select(t => (Old: t, New: updated[Key(t)])).ToArray();
                double Loss(JsonObject t) => t.Long("TcpEvidence.SentSegments") > 0 ? 100d * t.Long("TcpEvidence.RetransmittedSegments") / t.Long("TcpEvidence.SentSegments") : double.NaN;
                return pairs.Length >= 2 && pairs.Count(p => p.Old.Flag("TcpEvidence.PayloadMatched") && p.New.Flag("TcpEvidence.PayloadMatched") && Loss(p.Old) - Loss(p.New) > Math.Max(LossTolerancePercentagePoints, Loss(p.Old) * LossToleranceRelative)) >= Math.Ceiling(pairs.Length * 2d / 3);
            });
            if (!repeatedLoss) return Finish("NoClearGain", "LossGainNotRepeated", "平均重传下降，但未在多个目标、多数同轮样本中重复确认，不从异常对端推导全局配置。");
            return severeSpeed || severeLatency ? Finish("Tradeoff", "LossImprovedWithSevereCost", "重传比例改善，但有速度下降超过 30% 或传输中延迟明显恶化，未自动保留。")
                : Finish("Improved", "LossImproved", "重传比例减少超过阈值，优先保留丢包参考改善；同时已检查单、多连接速度和延迟代价。");
        }
        if (severeSpeed || severeLatency) return Finish("Regression", "SeverePerformanceRegression", "重传差异在阈值内，但单/多连接速度或传输中延迟明显退化。");
        bool RepeatedGain(string direction)
        {
            var byKey = current.ToDictionary(Key);
            var pairs = old.Where(x => x.Text("Direction") == direction && byKey.ContainsKey(Key(x))).Select(x => (Old: x, New: byKey[Key(x)])).ToArray();
            return pairs.Length >= 4 && endpoints.All(e => { var group = pairs.Where(p => p.Old.Text("Endpoint") == e).ToArray(); return group.Length >= 2 && group.Count(x => Value(x.New, "Mbps") >= Value(x.Old, "Mbps") * (1 + ThroughputGainFraction)) >= Math.Ceiling(group.Length * 2d / 3); });
        }
        var speedGain = Value(a, priority + "Mbps") >= Value(b, priority + "Mbps") * (1 + ThroughputGainFraction) && RepeatedGain(priority);
        if (!speedGain) return Finish("NoClearGain", "NoRepeatedSpeedGain", "重传差异在阈值内，吞吐未提升至少 10%，或多数同轮样本没有一致收益。");
        if (keys.Any(k => Value(a, k) < Value(b, k) * .8) || oldRates.Any(p => newRates[p.Key] < p.Value * .8) || Value(a, "LoadedP95Ms") > Math.Max(Value(b, "LoadedP95Ms") * 1.15, Value(b, "LoadedP95Ms") + 15))
            return Finish("Tradeoff", "SpeedImprovedWithCost", "重传差异在阈值内，吞吐有所提高，但其他传输速度下降超过 20% 或延迟代价较大。");
        return Finish("Improved", "StableLossFaster", "重传差异在阈值内，吞吐提升至少 10% 且多数同轮样本一致，速度和延迟检查通过。");
    }
    private static JsonObject[] Transfers(JsonObject report) => (report.At("Client.Transfers") as JsonArray ?? []).OfType<JsonObject>().Where(x => x.Flag("Complete") && Value(x, "Seconds") >= .25).ToArray();
    private static string Key(JsonObject transfer) => transfer.Text("Endpoint") + ":" + transfer.Text("Direction") + ":" + transfer.Number("Streams") + ":" + transfer.Number("Round");
}
