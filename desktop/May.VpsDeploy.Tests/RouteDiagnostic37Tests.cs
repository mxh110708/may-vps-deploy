using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunRouteDiagnostic37Tests()
    {
        using var f = new Fixture(repository);
        await RouteDiagnostic37Model(f);
        await RouteDiagnostic37Segments(f);
        await RouteDiagnostic37ChainPlan();
        await RouteDiagnostic37Profiles(f);
        await LoopbackClientDiagnostic(f);
        Console.WriteLine($"PASS: {assertions} diagnostic workbench model, finite probes, monitor binding, quality, encrypted history and actual loopback protocol assertions; no production connections.");
    }
    private static JsonObject Diagnostic37Scheme(AppPaths paths)
    {
        var scheme = ClientSchemes.New(paths); scheme["Name"] = "Diagnostic synthetic";
        ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-diagnostic-only@192.0.2.10:443#Entry", scheme, "US-West-LA Entry", "entry"));
        ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-diagnostic-only@192.0.2.11:443#Landing", scheme, "US-West-LA Entry", "landing"));
        return scheme;
    }
    private static JsonObject Diagnostic37Raw(long ms = 20) => new()
    {
        ["Status"] = "Reachable", ["Profile"] = new string('a', 64), ["EntryEgress"] = new JsonObject { ["Address"] = "192.0.2.123", ["Family"] = "IPv4", ["Verified"] = false },
        ["Stages"] = new JsonArray(new JsonObject { ["Id"] = "Tcp", ["Status"] = "Passed", ["Milliseconds"] = ms }, new JsonObject { ["Id"] = "EntryHttps", ["Status"] = "Passed", ["Milliseconds"] = ms * 2 }, new JsonObject { ["Id"] = "RemoteLeg", ["Status"] = "NotMeasured", ["Detail"] = "synthetic-private-should-not-leak" })
    };
    private async Task RouteDiagnostic37Model(Fixture f)
    {
        var scheme = Diagnostic37Scheme(f.Paths); var before = ArchiveStore.Fingerprint(scheme);
        var plan = RouteDiagnostics.Plan(f.Store, scheme, "Entry", "Landing");
        Check(plan.Segments.Count == 0 && plan.Instances.Count == 0 && ArchiveStore.Fingerprint(scheme) == before, "external path gained guessed remote segments or mutated scheme");
        var fake = new Diagnostic37Client((_, _) => Task.FromResult(Diagnostic37Raw())); var progress = new InlineProgress<string>(_ => { });
        var runner = new RouteDiagnosticWorkbench(f.Store, fake, networkContext: () => new string('b', 64));
        var report = await runner.RunAsync(plan, true, true, progress, default);
        Check(report.Text("Status") == "Reachable" && report.Text("Profile").Length == 64 && fake.Calls == 1, "workbench dropped real path result or repeated requests");
        Check(!report.ToJsonString().Contains("synthetic-private") && !report.ToJsonString().Contains("synthetic-diagnostic-only") && report.Text("Protocol") != "", "report persisted raw errors or node credentials");
        Check(report["Stages"]!.AsArray().Last()!.Text("Kind") == "NotMeasured" && report["Stages"]!.AsArray().Last()!["Milliseconds"] == null, "unmeasured remote leg got fabricated milliseconds");
        Check(RouteDiagnostics.Current(f.Store, scheme, report), "same path was incorrectly stale");
        var renamed = scheme.DeepClone().AsObject(); renamed["Nodes"]![0]!["name"] = "Renamed";
        Check(RouteDiagnostics.Current(f.Store, renamed, report), "display rename invalidated measured connection identity");
        renamed["Nodes"]![1]!["sing_box"]!["password"] = "changed";
        Check(!RouteDiagnostics.Current(f.Store, renamed, report), "changed authentication reused historical health");
        renamed["Nodes"]!.AsArray().RemoveAt(1); Check(!RouteDiagnostics.Current(f.Store, renamed, report), "removed landing kept current report");
        var history = new RouteDiagnosticHistory(f.Store); history.Append(plan.SchemeId, report);
        Check(history.Read(plan.SchemeId).Count == 1 && !File.ReadAllText(history.FileName(plan.SchemeId)).Contains("192.0.2.123"), "history was lost or not protected");
        Refuses(() => history.Append(plan.SchemeId, report), "duplicate diagnostic identity replayed");
        Refuses(() => history.FileName("../escape"), "diagnostic history escaped private root");
        var original = history.Fingerprint(plan.SchemeId); var rows = new List<JsonObject> { report };
        foreach (var ms in new[] { 10, 30, 40, 50 }) { var row = await new RouteDiagnosticWorkbench(f.Store, new Diagnostic37Client((_, _) => Task.FromResult(Diagnostic37Raw(ms))), networkContext: () => new string('b', 64)).RunAsync(plan, false, false, progress, default); rows.Add(row); history.Append(plan.SchemeId, row); }
        var quality = RouteDiagnostics.Quality(rows, report); var stage = quality["Stages"]!.AsArray().Single(s => s!.Text("Id") == "Tcp")!;
        Check(quality.Number("Samples") == 5 && quality.Number("Passed") == 5 && stage.Number("Median") == 30 && stage.Number("P95") == 50 && stage.Number("Peak") == 50, "quality median or nearest-rank P95 incorrect");
        foreach (var field in new[] { "Profile", "SourceFingerprint", "EnvironmentFingerprint" })
        {
            var other = report.DeepClone().AsObject(); other[field] = new string('c', 64); rows.Add(other);
            Check(RouteDiagnostics.Quality(rows, report).Number("Samples") == 5, "different configuration/network/core endpoint profile mixed into quality"); rows.RemoveAt(rows.Count - 1);
        }
        foreach (var status in new[] { "Cancelled", "SourceChanged", "Incomplete" })
        { var other = report.DeepClone().AsObject(); other["Status"] = status; rows.Add(other); Check(RouteDiagnostics.Quality(rows, report).Number("Samples") == 5, "cancel/stale/partial report counted as failed path sample"); rows.RemoveAt(rows.Count - 1); }
        var failed = report.DeepClone().AsObject(); failed["Status"] = "Failed"; failed["Stages"]![0]!["Status"] = "Failed"; rows.Add(failed);
        var withFailure = RouteDiagnostics.Quality(rows, report);
        Check(withFailure.Number("Samples") == 6 && withFailure.Number("Passed") == 5 && withFailure["Stages"]![0]!.Number("Samples") == 5, "failed measurement inflated latency success distribution");
        Refuses(() => history.Clear(plan.SchemeId, original), "clear overwrote newly appended history");
        for (var i = 0; i < 70; i++) { var row = report.DeepClone().AsObject(); row["Id"] = Guid.NewGuid().ToString("N"); history.Append(plan.SchemeId, row); }
        Check(history.Read(plan.SchemeId).Count == RouteDiagnosticHistory.MaximumRecords && ArchiveStore.Fingerprint(scheme) == before, "history unbounded or changed export candidate");
        var file = history.FileName(plan.SchemeId); var data = f.Store.ReadSecret(file); data["Schema"] = 999; f.Store.WriteSecret(file, data); var damaged = File.ReadAllBytes(file);
        Refuses(() => history.Append(plan.SchemeId, reportWithId()), "unsupported history schema overwritten");
        Check(File.ReadAllBytes(file).SequenceEqual(damaged), "failed history read changed protected file");
        history.Clear(plan.SchemeId, history.Fingerprint(plan.SchemeId)); Check(history.Read(plan.SchemeId).Count == 0, "reviewed local clear did not work");
        var slow = new Diagnostic37Client(async (_, token) => { await Task.Delay(Timeout.Infinite, token); return Diagnostic37Raw(); });
        using var cancel = new CancellationTokenSource(40);
        var cancelled = await new RouteDiagnosticWorkbench(f.Store, slow, networkContext: () => new string('b', 64)).RunAsync(plan, false, false, progress, cancel.Token);
        Check(cancelled.Text("Status") == "Cancelled" && cancelled.Text("FailureStage") == "Core", "cancelled owned check became success or disappeared");
        var reads = 0; var changed = await new RouteDiagnosticWorkbench(f.Store, fake, networkContext: () => new string(++reads == 1 ? 'b' : 'c', 64)).RunAsync(plan, false, false, progress, default);
        Check(changed.Text("Status") == "SourceChanged" && changed.Text("FailureStage") == "NetworkContext", "network switch mixed incomparable measurement");
        var coreFailed = await new RouteDiagnosticWorkbench(f.Store, new Diagnostic37Client((_, _) => throw new OperationException("synthetic-credential-secret")), networkContext: () => new string('b', 64)).RunAsync(plan, false, false, progress, default);
        Check(coreFailed.Text("Status") == "Failed" && coreFailed.Text("FailureStage") == "Core" && !coreFailed.ToJsonString().Contains("credential"), "core failure unclassified or raw errors archived");
        foreach (var edit in new Action<JsonObject>[] { r => r["Token"] = "synthetic-only", r => r["Stages"]![0]!["Password"] = "synthetic-only", r => r["Stages"]![0]!["Milliseconds"] = -1, r => r["Stages"]![0]!["Kind"] = "NotMeasured", r => r["Stages"]![0]!["Milliseconds"] = 150001,
            r => r["Monitor"] = new JsonArray(new JsonObject { ["Token"] = "synthetic-only" }), r => r["EntryEgress"]!["Address"] = "https://example.test/secret" })
        { var invalid = reportWithId(); edit(invalid); Refuses(() => history.Append(plan.SchemeId, invalid), "history accepted credentials, invalid duration or estimate-as-measured"); }
        plan.Clear();

        JsonObject reportWithId() { var row = report.DeepClone().AsObject(); row["Id"] = Guid.NewGuid().ToString("N"); return row; }
    }

    private async Task RouteDiagnostic37Segments(Fixture f)
    {
        var instancePlan = f.Plan("Diagnostics37"); instancePlan.Put("Import.Status", JsonValue.Create("Completed"));
        f.SaveInstance(instancePlan); var relative = f.Relative(instancePlan); var directory = f.Paths.Instance(relative);
        Directory.CreateDirectory(SafePath.Resolve(directory, "ssh")); File.WriteAllText(SafePath.Resolve(directory, "ssh/id_vps_management"), "synthetic-unused-key");
        var config = ForwardConfig(); instancePlan["TcpForwarding"] = config.DeepClone(); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), instancePlan);
        var hash = ArchiveStore.Fingerprint(config); var stateFile = SafePath.Resolve(directory, "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile); state.Put("TcpForwarding.RemoteHash", JsonValue.Create(hash)); ArchiveStore.WriteJson(stateFile, state);
        var segment = new RouteDiagnosticSegment("Entry.Forward", "primary", relative, "192.0.2.21", 443, "TCP", "TcpForwarding", hash);
        var remote = new Diagnostic37Remote(segment); var probe = new RouteSegmentProbe(f.Store, remote, new FakeUser());
        var result = await probe.ProbeAsync(segment, default);
        Check(result.Text("Status") == "Connected" && remote.Calls == 2 && remote.Mutations == 0 && remote.Disposals == 1 && remote.Endpoint?.Password == null, "segmented probe did not use read-only key-only pinned transport and dispose it");
        remote.Drift = true; await RefusesAsync(() => probe.ProbeAsync(segment, default), "remote drift did not block connection probe"); Check(remote.Calls == 3, "probe ran against drifted remote"); remote.Drift = false;
        remote.Wrong = true; await RefusesAsync(() => probe.ProbeAsync(segment, default), "wrong segment evidence accepted"); remote.Wrong = false;
        remote.Fail = true; await RefusesAsync(() => probe.ProbeAsync(segment, default), "failed remote TCP connect accepted"); remote.Fail = false;
        remote.Delay = true; using (var stop = new CancellationTokenSource(40)) { var wasCancelled = false; try { await probe.ProbeAsync(segment, stop.Token); } catch (OperationCanceledException) { wasCancelled = true; } Check(wasCancelled, "SSH cancellation not propagated"); } remote.Delay = false;
        var scheme = Diagnostic37Scheme(f.Paths); var ordinary = RouteDiagnostics.Plan(f.Store, scheme, "Entry");
        var plan = ordinary with { Segments = [segment], Instances = [relative] };
        var nodeId = Guid.NewGuid().ToString("D"); var origin = Guid.NewGuid().ToString("D");
        var connection = new MonitorReadConnection("https://monitor.example.test/", MonitorReadConnection.NewToken(), new Dictionary<string, string> { [relative] = nodeId }, origin); new MonitorReadArchive(f.Store).Save(connection);
        var now = DateTimeOffset.UtcNow;
        MonitorReadSnapshot Snapshot(DateTimeOffset at, string server, bool online = true) => new(now, now, "synthetic", new Dictionary<string, MonitorReadNode> { [nodeId] = new(nodeId, online, at, new(12, 64, 128, 1, 2, 3, 4)) }, server, now.AddDays(1));
        var snapshots = new[] { Snapshot(now, origin), Snapshot(now.AddMinutes(-5), origin), Snapshot(now.AddSeconds(30), origin), Snapshot(now, Guid.NewGuid().ToString("D")), Snapshot(now, origin, false) };
        foreach (var snapshot in snapshots)
        {
            var evidence = RouteDiagnostics.MonitorEvidence(plan, connection, snapshot, now, false); var label = evidence[0]!.Text("Status");
            Check(label == (snapshot == snapshots[0] ? "在线" : snapshot == snapshots[1] ? "在线 · 上报已过期" : snapshot == snapshots[2] ? "节点时间异常" : snapshot == snapshots[3] ? "监测身份或凭据无效" : "离线 · 保留最近上报"), "monitor freshness/binding/clock state misrepresented");
        }
        var oldSnapshot = Snapshot(now, origin) with { ReceivedAt = now.AddMinutes(-3) };
        Check(RouteDiagnostics.MonitorEvidence(plan, connection, oldSnapshot, now, false)[0]!.Text("Status").Contains("过期"), "cached old monitor snapshot represented as current");
        var missing = plan with { Instances = ["Example/Absent/May-VPS-Deploy"] };
        Check(RouteDiagnostics.MonitorEvidence(missing, connection, snapshots[0], now, false)[0]!.Text("Status") == "未绑定监测 UUID", "monitor matched by name or IP instead of explicit UUID");
        var monitor = new Diagnostic37Monitor(snapshots[0]); var fake = new Diagnostic37Client((_, _) => Task.FromResult(Diagnostic37Raw())); var progress = new InlineProgress<string>(_ => { });
        var service = new RouteDiagnosticWorkbench(f.Store, fake, probe, monitor, () => new string('d', 64));
        var report = await service.RunAsync(plan, true, true, progress, default);
        Check(report.Text("Status") == "Reachable" && report["Segments"]![0]!.Text("Kind") == "Measured" && report["Monitor"]![0]!.Text("Status") == "在线" && monitor.Calls == 1, "workbench did not combine explicitly bound independent evidence once");
        remote.Fail = true; report = await service.RunAsync(plan, true, false, progress, default);
        Check(report.Text("Status") == "Degraded" && report["Stages"]!.AsArray().Any(s => s!.Text("Id") == "EntryHttps") && monitor.Calls == 1, "failed segment skipped protocol check or falsely failed a passing business path"); remote.Fail = false;
        monitor.Fail = true; report = await service.RunAsync(plan, false, true, progress, default);
        Check(report.Text("Status") == "Reachable" && report["Monitor"]![0]!.Text("Status") != "在线" && report["Segments"]![0]!.Text("Kind") == "NotMeasured", "monitor failure changed path result or disabled probe gained measured latency");
        state.Put("UdpForwarding.RemoteHash", JsonValue.Create(hash)); ArchiveStore.WriteJson(stateFile, state);
        var udp = segment with { Transport = "UDP", Component = "UdpForwarding" }; var udpRemote = new Diagnostic37Remote(udp);
        var udpReport = await new RouteDiagnosticWorkbench(f.Store, fake, new RouteSegmentProbe(f.Store, udpRemote, new FakeUser()), networkContext: () => new string('d', 64)).RunAsync(plan with { Segments = [udp] }, true, false, progress, default);
        Check(udpReport["Segments"]![0]!.Text("Kind") == "RouteOnly" && udpReport["Segments"]![0]!["Milliseconds"] == null && !RouteDiagnostics.Quality([udpReport], udpReport)["Stages"]!.AsArray().Any(s => s!.Text("Id") == udp.Id), "UDP connect fabricated RTT or successful return path");
        var measured = report.DeepClone().AsObject(); measured["Segments"]![0]!["Kind"] = "Measured"; measured["Segments"]![0]!["Status"] = "Connected"; measured["Segments"]![0]!["Milliseconds"] = 7;
        Check(RouteDiagnostics.Quality([measured], measured)["Stages"]!.AsArray().Single(s => s!.Text("Id") == segment.Id)!.Number("Median") == 7, "measured segment not included in separate TCP-connect quality series");
        var changedSource = await new RouteDiagnosticWorkbench(f.Store, new Diagnostic37Client((_, _) => { var changed = ArchiveStore.ReadJson(stateFile); changed.Put("TcpForwarding.RemoteHash", JsonValue.Create(new string('e', 64))); ArchiveStore.WriteJson(stateFile, changed); return Task.FromResult(Diagnostic37Raw()); }), networkContext: () => new string('d', 64)).RunAsync(plan, false, false, progress, default);
        Check(changedSource.Text("Status") == "SourceChanged", "source drift during run left a current health claim");
        ordinary.Clear();
    }

    private async Task RouteDiagnostic37ChainPlan()
    {
        using var f = new Fixture(repository); var remote = new ChainRemote(); var plans = new List<JsonObject>();
        for (var i = 0; i < 3; i++)
        {
            var p = f.Plan("DiagnosticChain37-" + i); p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Server.IPv4", JsonValue.Create("192.0.2." + (30 + i))); p.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(p); plans.Add(p);
            var h = new ChainHost(p.Text("Server.IPv4"), remote); h.Inner.SeedProtocols(p); h.Inner.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes("synthetic-chain-proxy"); remote.Hosts.Add(p.Text("Server.IPv4"), h);
        }
        var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plans[2])), "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile);
        state.Put("ServerConfigHashes.RealityEntry", JsonValue.Create(ArchiveStore.Digest(remote.Hosts[plans[2].Text("Server.IPv4")].Inner.ProtocolConfigs["RealityEntry"]))); ArchiveStore.WriteJson(stateFile, state);
        var source = ClientSchemes.New(f.Paths); var credentials = f.Store.ReadSecret(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[2])), "secrets.dotnet.private.json"));
        var pair = ClientProfiles.Nodes(plans[2], credentials).First(); credentials.Clear();
        var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = pair.Name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = pair.Clash.DeepClone(), ["sing_box"] = pair.SingBox.DeepClone(), ["ManagedOrigin"] = ManagedNodeSources.Origin(f.Relative(plans[2]), pair) };
        source["Nodes"]!.AsArray().Add(node); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, source.Text("Id")), source);
        var chain = TcpChains.New(f.Relative(plans[0])); chain["RelayInstance"] = f.Relative(plans[1]); chain["LandingInstance"] = f.Relative(plans[2]); chain["FrontSourceAddress"] = plans[0].Text("Server.IPv4"); chain["FrontSources"] = new JsonArray("198.51.100.0/24"); chain["Landing"] = new JsonObject { ["SchemeId"] = source.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
        var request = new OperationRequest(OperationKind.TcpChain, f.Relative(plans[0]), new() { ["Action"] = "Apply", ["Configuration"] = chain.DeepClone() });
        var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpForwarding: new ForwardValidation("none"), tcpChains: new ChainValidation { Failure = "none", Remote = remote }));
        var completed = await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), default);
        Check(completed.Outcome == TaskOutcome.Completed, "synthetic managed chain not established for diagnostic planning: " + completed.SafeError);
        var projection = TcpChains.Project(f.Store, chain, "US-West-LA Entry"); projection["Id"] = Guid.NewGuid().ToString("N"); var scheme = ClientSchemes.New(f.Paths); scheme["Nodes"] = new JsonArray(projection);
        var plan = RouteDiagnostics.Plan(f.Store, scheme, projection.Text("name"));
        try
        {
            Check(plan.Instances.Count == 3 && plan.Segments.Count == 2 && plan.Segments[0].Instance == f.Relative(plans[0]) && plan.Segments[1].Instance == f.Relative(plans[1]), "workbench did not resolve both actual managed chain source segments");
            Check(plan.Segments[0].Address == plans[1].Text("Server.IPv4") && plan.Segments[0].Port == chain.Number("RelayPort") && plan.Segments[1].Address == plans[2].Text("Server.IPv4"), "chain diagnostics guessed hosts or bypassed selected relay");
            var before = remote.Events.Count; var report = await new RouteDiagnosticWorkbench(f.Store, new Diagnostic37Client((_, _) => Task.FromResult(Diagnostic37Raw())), networkContext: () => new string('f', 64)).RunAsync(plan, false, false, new InlineProgress<string>(_ => { }), default);
            Check(RouteDiagnostics.Current(f.Store, scheme, report) && remote.Events.Count == before && report["Segments"]!.AsArray().All(s => s!.Text("Kind") == "NotMeasured"), "planning or disabled checks made remote calls or falsely measured historical chain proof");
            var p = TcpChains.Plan(f.Store, f.Relative(plans[0])); p["TcpForwarding"]!["Rules"]![0]!["TargetPort"] = 55555; ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[0])), "deployment-plan.json"), p);
            Check(!RouteDiagnostics.Current(f.Store, scheme, report), "changed chain rule did not invalidate diagnostic evidence");
        }
        finally { plan.Clear(); }
    }
    private async Task RouteDiagnostic37Profiles(Fixture f)
    {
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0); listener.Start(); var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        var scheme = Diagnostic37Scheme(f.Paths); scheme["Nodes"]![0]!["sing_box"]!["server"] = "127.0.0.1"; scheme["Nodes"]![0]!["sing_box"]!["server_port"] = port;
        var route = ClientTopology.DiagnosticRoute(scheme, "Entry");
        var first = await new ClientRouteDiagnostics(new Diagnostic37Assets("artifact-a"), new FakeTools()).RunAsync(route, f.Paths.Resolve("private/profile-tests"), new InlineProgress<string>(_ => { }), default);
        var second = await new ClientRouteDiagnostics(new Diagnostic37Assets("artifact-b"), new FakeTools()).RunAsync(route, f.Paths.Resolve("private/profile-tests"), new InlineProgress<string>(_ => { }), default);
        Check(first.Text("Profile") != second.Text("Profile") && first.Text("Profile").Length == 64, "same version with different pinned core artifact mixed quality profiles");
        Check(first.Text("Status") == "Failed" && first["Stages"]!.AsArray().Last()!.Text("Id") == "Core", "fixed-core preparation failure disappeared instead of a named failed stage");
        Check(first["Stages"]!.AsArray().Any(s => s!.Text("Id") == "Tcp" && s.Text("Status") == "Passed"), "core error discarded already measured TCP stage");
    }
}

internal sealed class Diagnostic37Assets(string identity) : IValidationAssets
{
    public string ResolveCore(string name) => throw new OperationException("synthetic-core-unavailable");
    public string DataDirectory => "unused";
    public string ExpectedVersion(string name) => "synthetic-version";
    public string DiagnosticIdentity(string name) => identity;
}

internal sealed class Diagnostic37Client(Func<ClientDiagnosticRoute, CancellationToken, Task<JsonObject>> run) : IClientRouteDiagnostics
{
    public int Calls;
    public Task<JsonObject> RunAsync(ClientDiagnosticRoute route, string directory, IProgress<string> progress, CancellationToken token) { Calls++; return run(route, token); }
}
internal sealed class Diagnostic37Monitor(MonitorReadSnapshot snapshot) : IMonitorReadProbe
{
    public int Calls; public bool Fail;
    public Task<MonitorReadSnapshot> FetchAsync(MonitorReadConnection connection, CancellationToken token) { Calls++; if (Fail) throw new OperationException("synthetic-monitor-token"); return Task.FromResult(snapshot); }
}
internal sealed class Diagnostic37Remote(RouteDiagnosticSegment segment) : IRemoteSessionFactory, IRemoteSession
{
    public int Calls, Mutations, Disposals; public bool Drift, Wrong, Fail, Delay; public SshEndpoint? Endpoint;
    public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken ct) { Endpoint = endpoint; return Task.FromResult<IRemoteSession>(this); }
    public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken token) => throw new Exception("unreviewed command");
    public async Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken ct)
    {
        Calls++; if (mutating) Mutations++;
        if (Delay) await Task.Delay(Timeout.Infinite, ct);
        var reading = payload.StartsWith("# MXH asset: tcp-forward-read.sh", StringComparison.Ordinal) || payload.StartsWith("# MXH asset: udp-forward-read.sh", StringComparison.Ordinal);
        if (!reading && Fail) return new(1, "", "synthetic-private-error");
        var prefix = reading ? segment.Component == "UdpForwarding" ? "UDP_FORWARD_STATE" : "TCP_FORWARD_STATE" : "TCP_CHAIN_PROBE";
        var data = reading ? new JsonObject { ["Hash"] = Drift ? new string('f', 64) : segment.ComponentHash } : new JsonObject { ["Address"] = Wrong ? "192.0.2.99" : segment.Address, ["Port"] = segment.Port, ["Scope"] = segment.Transport == "UDP" ? "UdpRouteOnly" : "TcpConnectOnly", ["Status"] = segment.Transport == "UDP" ? "RouteAvailable" : "Connected", ["Milliseconds"] = 3 };
        return new(0, "VPSDEPLOY_" + prefix + "_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(data.ToJsonString())) + "\n", "");
    }
    public Task<byte[]> ReadFileAsync(string path, CancellationToken token) => throw new Exception("unreviewed read");
    public Task DownloadAsync(string path, string destination, CancellationToken token) => throw new Exception("unreviewed download");
    public ValueTask DisposeAsync() { Disposals++; return ValueTask.CompletedTask; }
}
