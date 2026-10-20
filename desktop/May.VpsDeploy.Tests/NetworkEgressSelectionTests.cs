using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task NetworkEgressSelectionExperience(Fixture f)
    {
        var landing = f.Plan("EgressLanding"); landing["Role"] = "ShadowsocksLanding"; landing["Roles"] = new JsonArray("ShadowsocksLanding");
        landing.Put("Server.IPv4", JsonValue.Create("192.0.2.81")); landing.Put("Server.IPv6", JsonValue.Create("2001:db8::81"));
        landing.Put("Ports.LandingShadowsocks", JsonValue.Create(4000)); landing.Put("Shadowsocks.Method", JsonValue.Create("2022-blake3-aes-128-gcm"));
        landing.Put("Shadowsocks.SecondaryIpv6Enabled", JsonValue.Create(true)); landing.Put("Shadowsocks.SecondaryIpv6Address", JsonValue.Create("2001:db8:1::81"));
        landing["ProtocolInventory"] = new JsonObject { ["ShadowsocksLanding"] = new JsonObject { ["Installed"] = true, ["Enabled"] = true } }; f.SaveInstance(landing);
        var directory = f.Paths.Instance(f.Relative(landing));
        var secrets = new JsonObject { ["Shadowsocks"] = new JsonObject { ["ServerKey"] = "fixture-server", ["PrimaryUserKey"] = "fixture-v4", ["SecondaryUserKey"] = "fixture-v6" } };
        f.Store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), secrets);
        var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); state["DeploymentTransaction"] = new JsonObject { ["Status"] = "Committed" }; ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state);
        var options = NetworkTuning.Defaults(landing);
        Check(options.Text("PeerEgress") == "Both" && NetworkTuning.SelectedPathCount(options) == 2, "dual egress landing did not offer both exits through one connection family");
        using (var route = NetworkTuning.ResolvePath(f.Store, landing, secrets, NetworkTuning.SelectedPaths(options).Single(o => o.Text("PeerEgress") == "IPv6"), f.Relative(landing)))
            Check(route.Node.Family == "IPv4" && route.ExpectedEgress == "2001:db8:1::81", "IPv6 exit required an IPv6 connection to the VPS");
        Refuses(() => NetworkTuning.ResolvePath(f.Store, landing, secrets, options, f.Relative(landing)), "aggregate exit selection silently resolved a single exit");
        options["Family"] = "Both"; options["TestSize"] = "Maximum"; NetworkTuning.ValidateMeasurement(options);
        var selected = NetworkTuning.SelectedPaths(options);
        Check(selected.Length == 4 && selected.Select(NetworkTuning.PathKey).Distinct().Count() == 4, "connection families and exit families were conflated");
        Check(selected.Sum(NetworkTuning.PayloadBudget) * 2 == 16L * 1024 * 1048576 && selected.All(o => NetworkTuning.PayloadBudget(o) == 2L * 1024 * 1048576), "four paths or retests duplicated the 20 GiB flow budget");
        Check(selected.Sum(NetworkTuning.DurationSeconds) <= 1800 && NetworkTuning.MeasurementSummary(options).Contains("共 4 条路径"), "four path duration or review summary missed an exit");
        var tooSmallShare = options.DeepClone().AsObject(); tooSmallShare["BudgetFamilyCount"] = 1;
        Check(NetworkTuning.PayloadBudget(tooSmallShare) == NetworkTuning.PayloadBudget(options), "caller reduced the divisor to exceed the shared budget");
        var invalid = options.DeepClone().AsObject(); invalid["PeerEgress"] = "auto";
        Refuses(() => NetworkTuning.ValidateMeasurement(invalid), "invalid landing exit selection accepted");
        var missing = landing.DeepClone().AsObject(); missing.Put("Shadowsocks.SecondaryIpv6Enabled", JsonValue.Create(false));
        Refuses(() => NetworkTuning.SelectionFingerprint(f.Store, missing, secrets, options, f.Relative(landing)), "missing IPv6 exit silently fell back to IPv4");
        var adapter = new SelectedFamilyNetwork(); var remote = new FakeRemote();
        var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), adapter); var id = Guid.NewGuid().ToString("N");
        await engine.ExecuteAsync(new(OperationKind.MeasureNetwork, f.Relative(landing), options), id, new InlineProgress<TaskProgress>(_ => { }), default);
        var report = NetworkTuning.ReadReport(directory, id);
        Check(adapter.Paths.Count == 4 && adapter.Paths.Select(p => NetworkTuning.PathKey(p["Options"]!.AsObject())).Distinct().Count() == 4 && remote.Mutations == 0, "landing did not perform all four read-only measurements");
        Check(report.Text("Analysis.Profile") == "LandingBasic" && report["Paths"]!.AsArray().Count == 4, "dual exits offered fine tuning on a landing or lost separate results");
        var badAdapter = new SelectedFamilyNetwork(missingIpv6Egress: true); var failedId = Guid.NewGuid().ToString("N");
        await new WorkflowEngine(f.Store, new FakeRemote(), new FakeKeys(), new FakeUser(), new FakeValidation(), badAdapter).ExecuteAsync(new(OperationKind.MeasureNetwork, f.Relative(landing), options), failedId, new InlineProgress<TaskProgress>(_ => { }), default);
        var incomplete = NetworkTuning.ReadReport(directory, failedId);
        Check(incomplete.Text("Client.Status") == "Incomplete" && !incomplete.Flag("Client.EgressVerified") && NetworkTuning.PathReports(incomplete).Count(p => p.Text("Client.Status") == "Measured") == 2, "IPv4 exit success concealed failed IPv6 exits");

        var entry = f.Plan("EgressRelay"); entry.Put("Server.IPv6", JsonValue.Create("2001:db8::82")); f.SaveInstance(entry);
        var relay = NetworkTuning.Defaults(entry); relay["Topology"] = "Relay"; relay["PeerInstance"] = f.Relative(landing); relay["PeerEgress"] = "Both"; relay["Family"] = "Both";
        relay["BandwidthMbps"] = 500; relay["UploadMbps"] = 500;
        var relayAdapter = new SelectedFamilyNetwork(); var relayRemote = new FakeRemote();
        var relayEngine = new WorkflowEngine(f.Store, relayRemote, new FakeKeys(), new FakeUser(), new FakeValidation(), relayAdapter); var relayId = Guid.NewGuid().ToString("N");
        await relayEngine.ExecuteAsync(new(OperationKind.MeasureNetwork, f.Relative(entry), relay), relayId, new InlineProgress<TaskProgress>(_ => { }), default);
        var entryDirectory = f.Paths.Instance(f.Relative(entry)); var baseline = NetworkTuning.ReadReport(entryDirectory, relayId);
        Check(relayAdapter.Paths.Count == 4 && relayAdapter.Paths.All(p => p.Flag("ViaEntry")) && relayRemote.Mutations == 0, "relay exit expansion bypassed the entry or changed the landing");
        Check(baseline.Text("Analysis.Profile") == "EntryMeasured", "eligible four-path relay lost its measured candidate");
        var faster = baseline.DeepClone().AsObject();
        foreach (var path in NetworkTuning.PathReports(faster)) foreach (var t in path["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) if (t.Text("Direction") == "Download") t["Mbps"] = 150;
        Check(NetworkTuning.Compare(baseline, faster) == "Improved", "four-path relay comparison could not match same-family different-exit paths");
        var regression = faster.DeepClone().AsObject();
        foreach (var path in NetworkTuning.PathReports(regression).Where(p => p.Text("Options.PeerEgress") == "IPv6")) foreach (var t in path["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) t["TcpEvidence"]!["RetransmittedSegments"] = 300;
        Check(NetworkTuning.Compare(baseline, regression) == "Regression", "IPv4 exit gains masked IPv6 exit regression");
        var absent = faster.DeepClone().AsObject(); absent["Paths"]!.AsArray().RemoveAt(3);
        Check(NetworkTuning.Compare(baseline, absent) == "Inconclusive", "missing selected exit passed shared validation");
        var duplicate = faster.DeepClone().AsObject(); duplicate["Paths"]![1] = duplicate["Paths"]![0]!.DeepClone();
        Check(NetworkTuning.Compare(baseline, duplicate) == "Inconclusive", "duplicate connection/exit pair passed validation or caused ambiguous matching");
        var changed = faster.DeepClone().AsObject(); changed["Options"]!["PeerEgress"] = "IPv4";
        Check(NetworkTuning.Compare(baseline, changed) == "Inconclusive", "changed parent exit selection reused old child paths");
        var task = Guid.NewGuid().ToString("N"); relayRemote.StatusTaskId = task; relayRemote.StatusPhase = "Armed";
        var tuning = new JsonObject { ["Scope"] = "Network", ["Profile"] = "EntryMeasured", ["MeasurementId"] = relayId, ["MeasurementSha256"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(entryDirectory, "network-measurements/" + relayId + ".json")) };
        await relayEngine.ExecuteAsync(new(OperationKind.TuneNetwork, f.Relative(entry), tuning), task, new InlineProgress<TaskProgress>(_ => { }), default);
        var result = ArchiveStore.ReadJson(SafePath.Resolve(entryDirectory, "deployment-state.json"));
        Check(relayAdapter.Paths.Count == 8 && relayRemote.Commands.Count(c => c == "network-apply.sh") == 1 && result.Flag("LastNetworkComparison.RestoredOriginal") && relayRemote.ArmedComponents == "Network", "both exits were not retested or shared parameters were applied twice");
    }
}
