using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

internal static class NetworkTestData
{
    public static JsonObject Observation() => new()
    {
        ["Kernel"] = "test-kernel", ["BootId"] = "test-boot", ["MemoryKiB"] = 1048576, ["Cpu"] = new JsonObject { ["BusyPercent"] = 20, ["StealPercent"] = 0 },
        ["Sysctl"] = new JsonObject { ["net.core.default_qdisc"] = "fq_codel", ["net.ipv4.tcp_congestion_control"] = "cubic", ["net.ipv4.tcp_available_congestion_control"] = "reno cubic bbr", ["net.ipv4.tcp_moderate_rcvbuf"] = "1", ["net.ipv4.tcp_rmem"] = "4096 131072 6291456", ["net.ipv4.tcp_wmem"] = "4096 16384 4194304", ["net.core.rmem_max"] = "212992", ["net.core.wmem_max"] = "212992" },
        ["Tcp"] = new JsonObject { ["RttMs"] = new JsonArray(100, 120, 110) }, ["Counters"] = new JsonObject { ["TcpRetransSegs"] = 5, ["TcpOutSegs"] = 100 },
        ["Devices"] = new JsonArray(new JsonObject { ["Name"] = "eth0", ["Mtu"] = "1500", ["Queues"] = new JsonArray(new JsonObject { ["kind"] = "fq", ["handle"] = "8001:", ["root"] = true, ["options"] = new JsonObject() }) })
    };
    public static JsonObject Client(double speed = 100, double latency = 120)
    {
        var transfers = new JsonArray(); foreach (var direction in new[] { "Download", "Upload" }) foreach (var endpoint in direction == "Download" ? new[] { "Cloudflare", "Hetzner" } : new[] { "Cloudflare" }) for (var i = 0; i < 3; i++) foreach (var streams in new[] { 1, 4 }) transfers.Add(new JsonObject { ["Endpoint"] = endpoint, ["Direction"] = direction, ["Streams"] = streams, ["Round"] = i + 1, ["Mbps"] = speed, ["Seconds"] = 1, ["Complete"] = true,
            ["TcpEvidence"] = new JsonObject { ["CountersValid"] = true, ["PayloadMatched"] = true, ["BootId"] = "test-boot", ["SentSegments"] = 10000, ["RetransmittedSegments"] = 100, ["RttMs"] = 100, ["SendBufferLimitedPercent"] = 20 } });
        var startup = new JsonArray(); foreach (var endpoint in new[] { "Cloudflare", "Hetzner" }) for (var i = 1; i <= 3; i++) startup.Add(new JsonObject { ["Endpoint"] = endpoint, ["Round"] = i, ["Complete"] = true, ["Milliseconds"] = 100 });
        return new JsonObject { ["Status"] = "Measured", ["EvidencePolicy"] = NetworkTuning.EvidencePolicy, ["EgressVerified"] = true, ["Transfers"] = transfers, ["Startup"] = startup, ["IdleLatencyMs"] = new JsonArray(100, 105, 100, 110), ["LoadedLatencyMs"] = new JsonArray(latency, latency, latency) };
    }
}
internal sealed class FakeNetwork(double speed = 100, double loaded = 120) : INetworkMeasurement
{
    public int Calls { get; private set; }
    public async Task<JsonObject> MeasureAsync(NetworkMeasurementPath path, JsonObject options, string directory, Func<CancellationToken, Task<JsonObject>> observe, IProgress<string> progress, CancellationToken token)
    {
        Calls++; var client = NetworkTestData.Client(speed, loaded); var after = await observe(token);
        after["Counters"]!["TcpOutSegs"] = after.Long("Counters.TcpOutSegs") + 100000;
        after["Counters"]!["TcpRetransSegs"] = after.Long("Counters.TcpRetransSegs") + 100;
        client["ServerAfter"] = after; return client;
    }
}
internal sealed partial class BoundaryTests
{
    private async Task NetworkExperience(Fixture f)
    {
        var plan = f.Plan("NetworkRead"); f.SaveInstance(plan); var options = NetworkTuning.Defaults(plan); options["BandwidthMbps"] = 500; options["UploadMbps"] = 500;
        Check(!options.ContainsKey("ReferenceRttMs") && options.Text("CapacityType") == "Unknown", "measurement invented user RTT/capacity");
        var invalid = options.DeepClone().AsObject(); invalid["ReferenceRttMs"] = 10; Refuses(() => NetworkTuning.ValidateMeasurement(invalid), "manual RTT accepted");
        Refuses(() => OperationPolicy.Validate(new(OperationKind.TuneNetwork, f.Relative(plan), new JsonObject { ["BandwidthMbps"] = 500, ["ReferenceRttMs"] = 50 })), "old unsafe tuning inputs accepted");
        Check(NetworkTuning.PayloadBudget(options) == 32L * 1048576 && NetworkTuning.DurationSeconds(options) == 100, "light budget changed");
        var now = new DateTimeOffset(2026, 10, 11, 0, 0, 0, TimeSpan.Zero); options["TimeZoneId"] = "UTC"; options["PeakStartHour"] = 20; options["PeakEndHour"] = 23;
        var job = NetworkSchedules.Create(f.Relative(plan), options, "source", now);
        var due = DateTimeOffset.Parse(job.Text("DueAt")); Check(due.Hour == 20 && NetworkSchedules.StatusAt(job, due) == "Due" && NetworkSchedules.StatusAt(job, due, true) == "Missed", "closed app replayed missed peak");
        job["Status"] = "Running"; Check(NetworkSchedules.StatusAt(job, due, true) == "Interrupted", "crashed job silently retried");
        options["PeakStartHour"] = 22; options["PeakEndHour"] = 2; Check(NetworkTuning.InPeak(now, options) && !NetworkTuning.InPeak(now.AddHours(3), options), "midnight window failed");
        var remote = new FakeRemote(); var adapter = new FakeNetwork();
        var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), adapter);
        var id = Guid.NewGuid().ToString("N"); await engine.ExecuteAsync(new(OperationKind.MeasureNetwork, f.Relative(plan), options), id, new InlineProgress<TaskProgress>(_ => { }), default);
        Check(remote.Mutations == 0 && adapter.Calls == 1, "read-only measurement mutated server");
        var directory = f.Paths.Instance(f.Relative(plan)); var report = NetworkTuning.ReadReport(directory, id);
        Check(report.Text("Analysis.Profile") == "EntryMeasured" && report.Long("Analysis.BufferTargetBytes") <= report.Long("Analysis.BufferCapBytes"), "automatic measured suggestion invalid");
        Check(ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"))["NetworkTuning"] == null, "measurement promoted applied state");
        var incomplete = report.DeepClone().AsObject(); incomplete["Client"]!["EgressVerified"] = false; Check(NetworkTuning.Analyze(incomplete).Text("Profile") == "EntryBasic", "unverified egress tuned buffers");
        incomplete = report.DeepClone().AsObject(); foreach (var transfer in incomplete["Client"]!["Transfers"]!.AsArray().OfType<JsonObject>()) transfer["TcpEvidence"]!["RttMs"] = 0; Check(NetworkTuning.Analyze(incomplete).Long("BufferTargetBytes") == 0, "HTTP timing used as TCP RTT");
        incomplete = report.DeepClone().AsObject(); incomplete["ServerAfter"]!["Cpu"]!["StealPercent"] = 20; Check(NetworkTuning.Analyze(incomplete).Text("Profile") == "EntryBasic", "host steal ignored");
        incomplete = report.DeepClone().AsObject(); incomplete["ServerAfter"]!["Sysctl"]!["net.core.rmem_max"] = "67108864"; Check(NetworkTuning.Analyze(incomplete).Text("Profile") == "EntryBasic", "existing buffers above budget offered unapplied fine tuning");
        incomplete = report.DeepClone().AsObject(); incomplete["ServerAfter"]!["Sysctl"]!.AsObject().Remove("net.ipv4.tcp_wmem"); Check(NetworkTuning.Analyze(incomplete).Text("Profile") == "EntryBasic", "unknown current buffers offered fine tuning");
        var future = report.DeepClone().AsObject(); future["At"] = DateTimeOffset.UtcNow.AddDays(1).ToString("O"); future["Analysis"]!["PeakSample"] = true; report["Options"]!["PeakStartHour"] = 3; report["Options"]!["PeakEndHour"] = 4; future["Options"] = report["Options"]!.DeepClone(); report["At"] = now.ToString("O");
        Check(!NetworkTuning.Analyze(report, [future]).Flag("PeakCovered"), "future peak substituted actual coverage");
        // Reload the unchanged persisted baseline for actual workflow comparisons.
        report = NetworkTuning.ReadReport(directory, id);
        var tuned = new JsonObject { ["Scope"] = "Network", ["Profile"] = "EntryMeasured", ["MeasurementId"] = id, ["MeasurementSha256"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "network-measurements/" + id + ".json")) };
        var coordinator = new TaskCoordinator(f.Store, engine); var review = coordinator.Review(new(OperationKind.TuneNetwork, f.Relative(plan), tuned));
        File.AppendAllText(SafePath.Resolve(directory, "network-measurements/" + id + ".json"), " ");
        await RefusesAsync(() => coordinator.ExecuteAsync(review, review.Request, new InlineProgress<TaskProgress>(_ => { }), default), "changed reviewed measurement accepted");
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "network-measurements/" + id + ".json"), report); tuned["MeasurementSha256"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "network-measurements/" + id + ".json"));
        var task = Guid.NewGuid().ToString("N"); remote.StatusTaskId = task; remote.StatusPhase = "Armed";
        await engine.ExecuteAsync(new(OperationKind.TuneNetwork, f.Relative(plan), tuned), task, new InlineProgress<TaskProgress>(_ => { }), default);
        var comparison = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        Check(comparison.Flag("LastNetworkComparison.RestoredOriginal") && remote.Commands.Contains("protocol-migration-trigger-rollback.sh") && !remote.Commands.Contains("maintenance-transaction-commit.sh"), "no gain committed instead of restoring");
        Check(remote.ArmedComponents == "Network", "network recovery expanded scope");
        var improved = report.DeepClone().AsObject(); improved["Client"] = NetworkTestData.Client(150); improved["Analysis"] = NetworkTuning.Analyze(improved); Check(NetworkTuning.Compare(report, improved) == "Improved", "improvement not identified");
        var worse = report.DeepClone().AsObject(); worse["Client"] = NetworkTestData.Client(50, 400); worse["Analysis"] = NetworkTuning.Analyze(worse); Check(NetworkTuning.Compare(report, worse) == "Regression", "clear regression ignored");
        NetworkComparisonExperience(report);
        await NetworkPathExperience(f, report);
        var landing = f.Plan("NetworkLanding"); landing["Role"] = "ShadowsocksLanding"; landing["Roles"] = new JsonArray("ShadowsocksLanding"); f.SaveInstance(landing); var landingRemote = new FakeRemote();
        var landingOutcome = await f.Engine(landingRemote).ExecuteAsync(new(OperationKind.TuneNetwork, f.Relative(landing), new JsonObject { ["Scope"] = "Network", ["Profile"] = "LandingBasic" }), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
        Check(landingOutcome == TaskOutcome.Completed, "verified BBR reported a warning through dotted sysctl lookup");
        Check(!landingRemote.Commands.Contains("network-tuning.sh") && landingRemote.Commands.Contains("network-apply.sh") && !landingRemote.Commands.Contains("xray-install.sh"), "landing replayed old fine tuning");
        Check(OperationSteps.Create(new(OperationKind.MeasureNetwork, f.Relative(plan), options), plan).Count == 3 && OperationSteps.Create(new(OperationKind.TuneNetwork, f.Relative(plan), tuned), plan).Count == 5, "inline network plan absent");
    }
}
