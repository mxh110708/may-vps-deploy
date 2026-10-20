using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private void NetworkComparisonExperience(JsonObject original)
    {
        JsonObject Sample(double speed, long retrans, long sent = 100000, double latency = 120)
        {
            var r = original.DeepClone().AsObject(); r["Client"] = NetworkTestData.Client(speed, latency);
            r["ServerBefore"]!["Counters"] = new JsonObject { ["TcpOutSegs"] = 1000, ["TcpRetransSegs"] = 100 };
            r["ServerAfter"]!["Counters"] = new JsonObject { ["TcpOutSegs"] = 1000 + sent, ["TcpRetransSegs"] = 100 + retrans };
            foreach (var transfer in r["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) { transfer["TcpEvidence"]!["SentSegments"] = sent; transfer["TcpEvidence"]!["RetransmittedSegments"] = retrans; }
            r["Analysis"] = NetworkTuning.Analyze(r); return r;
        }
        var baseline = Sample(100, 1000); // 1% retransmission reference.
        var lessLoss = Sample(95, 300);
        Check(NetworkTuning.CompareDetailed(baseline, lessLoss).Text("ReasonCode") == "LossImproved" && NetworkTuning.Compare(baseline, lessLoss) == "Improved", "loss reduction lost to a minor speed decrease");
        Check(NetworkTuning.Compare(baseline, Sample(200, 2000)) == "Regression", "large speed gain hid worse retransmissions");
        Check(NetworkTuning.CompareDetailed(baseline, Sample(130, 1100)).Text("ReasonCode") == "StableLossFaster", "small retransmission variation hid repeated speed gain");
        Check(NetworkTuning.Compare(baseline, Sample(105, 1100)) == "NoClearGain", "speed noise promoted improvement");
        Check(NetworkTuning.Compare(baseline, Sample(50, 300)) == "Tradeoff", "loss priority allowed severe throughput collapse");
        Check(NetworkTuning.Compare(baseline, Sample(100, 300, latency: 400)) == "Tradeoff", "loss priority hid severe queue latency");
        Check(NetworkTuning.Compare(Sample(100, 10000), Sample(130, 11000)) == "Improved", "relative loss tolerance ignored");
        var unknown = Sample(200, 1, 50);
        Check(NetworkTuning.Compare(baseline, unknown) == "Inconclusive" && unknown.Text("Analysis.Profile") == "EntryBasic", "low sample count became zero-loss evidence");
        unknown = Sample(200, 100); foreach (var transfer in unknown["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) transfer["TcpEvidence"]!["CountersValid"] = false;
        Check(!NetworkTuning.LossEvidence(unknown).Flag("Eligible") && NetworkTuning.Compare(baseline, unknown) == "Inconclusive", "missing retransmissions became zero loss");
        unknown = Sample(200, 100); foreach (var transfer in unknown["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) transfer["TcpEvidence"]!["CountersValid"] = false;
        Check(!NetworkTuning.LossEvidence(unknown).Flag("CountersValid"), "counter reset ignored");
        unknown = Sample(200, 100); unknown["ServerAfter"]!["BootId"] = "another-boot";
        Check(NetworkTuning.Compare(baseline, unknown) == "Inconclusive", "reboot mixed incomparable counter periods");
        var zero = Sample(100, 0); Check(NetworkTuning.LossEvidence(zero).Flag("Eligible") && NetworkTuning.Value(NetworkTuning.LossEvidence(zero), "Percent") == 0, "valid zero retransmissions became missing");
        var udpChanged = Sample(130, 1100); udpChanged["Client"]!["Udp"] = new JsonObject { ["Sent"] = 5, ["Received"] = 3 };
        Check(NetworkTuning.Compare(baseline, udpChanged) == "Improved", "five UDP samples overrode TCP and throughput evidence");
        var spike = Sample(100, 1100); spike["Client"]!["Transfers"]![0]!["Mbps"] = 1000; spike["Analysis"] = NetworkTuning.Analyze(spike);
        Check(NetworkTuning.Compare(baseline, spike) == "NoClearGain", "one speed spike promoted improvement");
        var duplicates = Sample(130, 1100); duplicates["Client"]!["Transfers"]!.AsArray().Add(duplicates["Client"]!["Transfers"]![0]!.DeepClone());
        Check(NetworkTuning.Compare(baseline, duplicates) == "Inconclusive", "duplicate round crashed or improved comparison");
        var mismatch = Sample(130, 1100); mismatch["Options"]!["Family"] = "IPv6";
        Check(NetworkTuning.Compare(baseline, mismatch) == "Inconclusive", "different address family compared");
        var peakBefore = Sample(100, 1000); peakBefore["Options"]!["TimeZoneId"] = "UTC"; peakBefore["Options"]!["PeakStartHour"] = 20; peakBefore["Options"]!["PeakEndHour"] = 24; peakBefore["At"] = "2026-10-13T23:59:00Z";
        var peakAfter = Sample(130, 1100); peakAfter["Options"] = peakBefore["Options"]!.DeepClone(); peakAfter["At"] = "2026-10-14T00:01:00Z";
        Check(NetworkTuning.Compare(peakBefore, peakAfter) == "Inconclusive", "peak and off-peak samples compared");
    }
}
