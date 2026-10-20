using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed class SelectedFamilyNetwork(bool missingIpv6 = false, bool missingIpv6Egress = false) : INetworkMeasurement
{
    public List<string> Families { get; } = [];
    public List<JsonObject> Paths { get; } = [];
    public async Task<JsonObject> MeasureAsync(NetworkMeasurementPath path, JsonObject options, string directory, Func<CancellationToken, Task<JsonObject>> observe, IProgress<string> progress, CancellationToken token)
    {
        Families.Add(path.Node.Family); var client = NetworkTestData.Client();
        Paths.Add(new JsonObject { ["Options"] = options.DeepClone(), ["Egress"] = path.Node.EgressFamily, ["ExpectedEgress"] = path.ExpectedEgress, ["ViaEntry"] = path.Entry != null, ["PayloadBudget"] = NetworkTuning.PayloadBudget(options) });
        if (missingIpv6 && path.Node.Family == "IPv6" || missingIpv6Egress && path.Node.EgressFamily == "IPv6") { client["Status"] = "Incomplete"; client["EgressVerified"] = false; client["Transfers"] = new JsonArray(); }
        client["ServerAfter"] = await observe(token); return client;
    }
}
internal sealed partial class BoundaryTests
{
    private async Task NetworkSelectionExperience(Fixture f, JsonObject original)
    {
        JsonObject Analyze(JsonObject r) { foreach (var p in NetworkTuning.PathReports(r)) p["Analysis"] = NetworkTuning.Analyze(p); r["Analysis"] = NetworkTuning.Analyze(r); return r; }
        var balanced = original.DeepClone().AsObject(); balanced["Options"]!["PriorityDirection"] = "Balanced"; Analyze(balanced);
        Check(balanced.Text("Analysis.Profile") == "EntryMeasured" && NetworkTuning.LossEvidence(balanced).Text("Scope") == "SeparateDirections", "balanced mode averaged or discarded separate loss evidence");
        var faster = balanced.DeepClone().AsObject(); foreach (var t in faster["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Direction") == "Download") t["Mbps"] = 140; Analyze(faster);
        Check(NetworkTuning.Compare(balanced, faster) == "Improved", "balanced mode required simultaneous gains in both directions");
        var badUpload = faster.DeepClone().AsObject(); foreach (var t in badUpload["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Direction") == "Upload") t["TcpEvidence"]!["RetransmittedSegments"] = 300; Analyze(badUpload);
        Check(NetworkTuning.Compare(balanced, badUpload) == "Regression", "download gain masked upload loss regression");
        var uploadCost = faster.DeepClone().AsObject(); foreach (var t in uploadCost["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Direction") == "Upload") t["Mbps"] = 75; Analyze(uploadCost);
        Check(NetworkTuning.Compare(balanced, uploadCost) == "Tradeoff", "balanced mode allowed a 25 percent upload speed cost");
        var downloadPriority = balanced.DeepClone().AsObject(); downloadPriority["Options"]!["PriorityDirection"] = "Download"; Analyze(downloadPriority);
        badUpload["Options"]!["PriorityDirection"] = "Download"; Analyze(badUpload);
        Check(NetworkTuning.Compare(downloadPriority, badUpload) == "Regression", "download priority disabled upload protection");
        var noUpload = balanced.DeepClone().AsObject(); foreach (var t in noUpload["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Direction") == "Upload") t["TcpEvidence"]!["CountersValid"] = false; Analyze(noUpload);
        Check(noUpload.Text("Analysis.Profile") == "EntryBasic" && NetworkTuning.Compare(balanced, noUpload) == "Inconclusive", "unknown upload treated as protected");
        var uploadFaster = balanced.DeepClone().AsObject(); foreach (var t in uploadFaster["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Direction") == "Upload") t["Mbps"] = 150; Analyze(uploadFaster);
        Check(NetworkTuning.Compare(balanced, uploadFaster) != "Improved", "one public upload provider proved global upload gain");
        var tooBrief = balanced.DeepClone().AsObject(); foreach (var t in tooBrief["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) t["Seconds"] = .3; Analyze(tooBrief);
        Check(tooBrief.Text("Analysis.Profile") == "EntryBasic", "short high-speed bursts became sustained evidence");
        var options = balanced["Options"]!.DeepClone().AsObject(); options["Family"] = "Both";
        foreach (var size in new[] { "Quick", "Standard", "Deep", "Extended", "Maximum" })
        {
            options["TestSize"] = size; NetworkTuning.ValidateMeasurement(options);
            var budget = NetworkTuning.Families(options).Sum(family => NetworkTuning.PayloadBudget(NetworkTuning.FamilyOptions(options, family)));
            Check(budget * 2 <= NetworkTuning.FlowBudgetMiB(options) * 1048576L * .8 && NetworkTuning.FlowBudgetMiB(options) <= 20480, size + " duplicated the flow budget across families or retests");
        }
        options["TestSize"] = "Custom"; options["TrafficBudgetMiB"] = 20480; NetworkTuning.ValidateMeasurement(options);
        Check(NetworkTuning.PayloadBudget(options) * 4 == 16L * 1024 * 1048576, "20 GiB budget did not reserve 20% across both address families and retests");
        foreach (var invalid in new[] { "20481", "-1", "1.5", "2147483648" }) { options["TrafficBudgetMiB"] = invalid; Refuses(() => NetworkTuning.ValidateMeasurement(options), "invalid or excessive total budget accepted"); }
        options["TrafficBudgetMiB"] = 1024;
        var plan = f.Plan("DualStackNetwork"); plan.Put("Server.IPv6", JsonValue.Create("2001:db8::44")); f.SaveInstance(plan);
        var adapter = new SelectedFamilyNetwork(); var remote = new FakeRemote();
        var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), adapter); var id = Guid.NewGuid().ToString("N");
        await engine.ExecuteAsync(new(OperationKind.MeasureNetwork, f.Relative(plan), options), id, new InlineProgress<TaskProgress>(_ => { }), default);
        var directory = f.Paths.Instance(f.Relative(plan)); var group = NetworkTuning.ReadReport(directory, id);
        Check(adapter.Families.SequenceEqual(new[] { "IPv4", "IPv6" }) && remote.Mutations == 0 && group["Paths"]!.AsArray().Count == 2, "dual stack did not make separate read-only family measurements");
        Check(group.Text("Analysis.Profile") == "EntryMeasured" && group["Analysis"]!["DownloadMbps"] == null, "dual stack aggregated rates or lost shared candidate");
        var changed = group.DeepClone().AsObject(); foreach (var path in NetworkTuning.PathReports(changed)) foreach (var t in path["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) t["Mbps"] = 140; Analyze(changed);
        Check(NetworkTuning.Compare(group, changed) == "Improved", "all-path improvement rejected");
        var badV6 = changed.DeepClone().AsObject(); foreach (var t in NetworkTuning.PathReports(badV6).Single(p => p.Text("Options.Family") == "IPv6")["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) t["TcpEvidence"]!["RetransmittedSegments"] = 300; Analyze(badV6);
        Check(NetworkTuning.Compare(group, badV6) == "Regression", "IPv4 gain hid IPv6 regression");
        var guardPath = group.DeepClone().AsObject(); foreach (var t in NetworkTuning.PathReports(guardPath)[1]["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) t["TcpEvidence"]!["SendBufferLimitedPercent"] = 0; Analyze(guardPath);
        Check(guardPath.Text("Analysis.Profile") == "EntryMeasured" && NetworkTuning.PathReports(guardPath)[1].Text("Analysis.Profile") == "EntryBasic", "a healthy family had to show the same bottleneck to protect shared parameters");
        var failedAdapter = new SelectedFamilyNetwork(true); var failedId = Guid.NewGuid().ToString("N");
        await new WorkflowEngine(f.Store, new FakeRemote(), new FakeKeys(), new FakeUser(), new FakeValidation(), failedAdapter).ExecuteAsync(new(OperationKind.MeasureNetwork, f.Relative(plan), options), failedId, new InlineProgress<TaskProgress>(_ => { }), default);
        var failed = NetworkTuning.ReadReport(directory, failedId);
        Check(failed.Text("Analysis.Profile") == "EntryBasic" && failed.Text("Client.Status") == "Incomplete", "unavailable IPv6 silently fell back to successful IPv4");
        var missing = changed.DeepClone().AsObject(); missing["Paths"]!.AsArray().RemoveAt(1);
        Check(NetworkTuning.Compare(group, missing) == "Inconclusive", "missing selected family passed shared validation");
        var tuning = new JsonObject { ["Scope"] = "Network", ["Profile"] = "EntryMeasured", ["MeasurementId"] = id, ["MeasurementSha256"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "network-measurements/" + id + ".json")) };
        var task = Guid.NewGuid().ToString("N"); remote.StatusTaskId = task; remote.StatusPhase = "Armed";
        await engine.ExecuteAsync(new(OperationKind.TuneNetwork, f.Relative(plan), tuning), task, new InlineProgress<TaskProgress>(_ => { }), default);
        var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        Check(remote.Commands.Count(c => c == "network-apply.sh") == 1 && state.Flag("LastNetworkComparison.RestoredOriginal") && remote.ArmedComponents == "Network", "dual stack applied twice or failed to restore its shared scope");
        await NetworkEgressSelectionExperience(f);
    }
}
