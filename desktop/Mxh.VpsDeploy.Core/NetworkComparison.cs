using System.Globalization;
using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public static partial class NetworkTuning
{
    public const long MinimumLossSegments = 1000;
    public const double LossTolerancePercentagePoints = .2;
    public const double LossToleranceRelative = .2;
    public const double ThroughputGainFraction = .1;
    public const string ComparisonPolicy = "LossFirst.v1";
    public const string ComparisonPolicyDescription = "优先降低丢包参考：重传比例变化阈值取 0.2 个百分点与基线比例的 20% 中较大者。差异在阈值内，再比较吞吐；提升至少 10%，且多数同轮样本一致，才视为速度收益。5 次 UDP 响应不用于判定丢包率。";

    public static JsonObject LossEvidence(JsonObject report)
    {
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
            || before.Text("SourceFingerprint") != after.Text("SourceFingerprint") || b.Text("Profile") != "EntryMeasured" || a.Text("Profile") != "EntryMeasured"
            || new[] { "Protocol", "Family", "TestSize", "TimeZoneId", "PeakStartHour", "PeakEndHour", "BandwidthMbps", "UploadMbps", "CapacityType" }.Any(k => before.Text("Options." + k) != after.Text("Options." + k))
            || before.Text("ServerAfter.Kernel") != after.Text("ServerAfter.Kernel") || before.Text("ServerAfter.BootId") != after.Text("ServerAfter.BootId"))
            return Finish("Inconclusive", "IncompatibleSamples", "采集未完成，或前后路径、套餐、内核及使用时段不同，不能比较。");
        if (!DateTimeOffset.TryParse(before.Text("At"), out var bt) || !DateTimeOffset.TryParse(after.Text("At"), out var at) || at < bt || InPeak(bt, before["Options"]!.AsObject()) != InPeak(at, after["Options"]!.AsObject()))
            return Finish("Inconclusive", "DifferentTimeWindows", "前后采集跨越了设定的高峰边界，或时间记录无效，不能判断参数收益。");
        var old = Transfers(before); var current = Transfers(after);
        if (old.GroupBy(Key).Any(g => g.Count() != 1) || current.GroupBy(Key).Any(g => g.Count() != 1))
            return Finish("Inconclusive", "DuplicateTransferSamples", "同轮传输样本重复，无法可靠核对吞吐。");
        var keys = new[] { "DownloadSingleMbps", "DownloadMultiMbps", "UploadSingleMbps", "UploadMultiMbps" };
        if (keys.Any(k => Value(b, k) <= 0 || Value(a, k) <= 0)) return Finish("Inconclusive", "MissingThroughputSamples", "单连接或多连接传输信息缺失，无法核对速度代价。");
        if (!bl.Flag("Eligible") || !al.Flag("Eligible")) return Finish("Inconclusive", "MissingLossEvidence", "重传计数缺失、重置或发送段不足；不将缺失数据当作零丢包，也不只凭测速增快保留精细参数。");
        var change = Value(al, "Percent") - Value(bl, "Percent"); decision["LossChangePercentagePoints"] = change;
        if (change > tolerance) return Finish("Regression", "LossWorsened", "重传比例增加超过阈值；丢包参考退化优先于吞吐收益。");
        var severeSpeed = keys.Any(k => Value(a, k) < Value(b, k) * .7);
        var severeLatency = Value(a, "LoadedP95Ms") > Math.Max(Value(b, "LoadedP95Ms") * 1.5, Value(b, "LoadedP95Ms") + 50);
        if (change < -tolerance)
            return severeSpeed || severeLatency ? Finish("Tradeoff", "LossImprovedWithSevereCost", "重传比例改善，但有速度下降超过 30% 或传输中延迟明显恶化，未自动保留。")
                : Finish("Improved", "LossImproved", "重传比例减少超过阈值，优先保留丢包参考改善；同时已检查单、多连接速度和延迟代价。");
        if (severeSpeed || severeLatency) return Finish("Regression", "SeverePerformanceRegression", "重传差异在阈值内，但单/多连接速度或传输中延迟明显退化。");
        bool RepeatedGain(string direction)
        {
            var byKey = current.ToDictionary(Key);
            var pairs = old.Where(x => x.Text("Direction") == direction && byKey.ContainsKey(Key(x))).Select(x => (Old: x, New: byKey[Key(x)])).ToArray();
            return pairs.Length >= 4 && pairs.Count(x => Value(x.New, "Mbps") >= Value(x.Old, "Mbps") * (1 + ThroughputGainFraction)) >= Math.Ceiling(pairs.Length * 2d / 3);
        }
        var speedGain = new[] { "Download", "Upload" }.Any(d => Value(a, d + "Mbps") >= Value(b, d + "Mbps") * (1 + ThroughputGainFraction) && RepeatedGain(d));
        if (!speedGain) return Finish("NoClearGain", "NoRepeatedSpeedGain", "重传差异在阈值内，吞吐未提升至少 10%，或多数同轮样本没有一致收益。");
        if (keys.Any(k => Value(a, k) < Value(b, k) * .8) || Value(a, "LoadedP95Ms") > Math.Max(Value(b, "LoadedP95Ms") * 1.15, Value(b, "LoadedP95Ms") + 15))
            return Finish("Tradeoff", "SpeedImprovedWithCost", "重传差异在阈值内，吞吐有所提高，但其他传输速度下降超过 20% 或延迟代价较大。");
        return Finish("Improved", "StableLossFaster", "重传差异在阈值内，吞吐提升至少 10% 且多数同轮样本一致，速度和延迟检查通过。");
    }
    private static JsonObject[] Transfers(JsonObject report) => (report.At("Client.Transfers") as JsonArray ?? []).OfType<JsonObject>().Where(x => x.Flag("Complete") && Value(x, "Seconds") >= .25).ToArray();
    private static string Key(JsonObject transfer) => transfer.Text("Direction") + ":" + transfer.Number("Streams") + ":" + transfer.Number("Round");
}
