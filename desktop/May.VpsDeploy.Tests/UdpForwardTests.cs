using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private static JsonObject UdpConfig(int port = 55002)
    {
        var config = UdpForwarding.Empty(); var rule = UdpForwarding.NewRule(); rule["ListenPort"] = port;
        rule["TargetAddress"] = "192.0.2.20"; rule["TargetPort"] = 53; rule["AllowedSources"] = new JsonArray("198.51.100.77/24");
        rule["Validation"] = new JsonObject { ["Type"] = "Dns", ["QueryName"] = "example.test", ["QueryType"] = "A" }; config["Rules"]!.AsArray().Add(rule); return config;
    }
    public async Task RunUdpForwardTests()
    {
        using var fixture = new Fixture(repository); await UdpForwardExperience(fixture); await UdpForwardLoopback(fixture);
        Console.WriteLine($"PASS: {assertions} UDP forwarding lifecycle, source, DNS, cancellation and actual datagram assertions; no production connections.");
    }
    private async Task UdpForwardExperience(Fixture f)
    {
        var plan = f.Plan("UDP-preview"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        var relative = f.Relative(plan); var directory = f.Paths.Instance(relative); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        var config = UdpConfig(); var raw = config.ToJsonString(); var normalized = UdpForwarding.Normalize(config);
        Check(config.ToJsonString() == raw && normalized["Rules"]![0]!["AllowedSources"]![0]!.ToString() == "198.51.100.0/24", "UDP editor changed or source was not normalized");
        foreach (var edit in new Action<JsonObject>[] { c => c["Extra"] = true, c => c["Rules"]![0]!["SessionTimeoutSeconds"] = 9, c => c["Rules"]![0]!["SessionTimeoutSeconds"] = 601, c => c["Rules"]![0]!["MaximumSessions"] = 0, c => c["Rules"]![0]!["MaximumSessions"] = 1025, c => c["Rules"]![0]!["MaximumSessions"] = "256", c => c["Rules"]![0]!["Validation"]!["QueryType"] = "TXT", c => c["Rules"]![0]!["Validation"]!["QueryName"] = "bad host", c => c["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Tls" }, c => c["Rules"]!.AsArray().Add(c["Rules"]![0]!.DeepClone()) })
        { var bad = config.DeepClone().AsObject(); edit(bad); Refuses(() => UdpForwarding.Normalize(bad), "invalid UDP rule was accepted"); }
        var request = new OperationRequest(OperationKind.UdpForward, relative, UdpForwarding.Options(state, "Apply", config));
        var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed))); var review = coordinator.Review(request);
        Check(review.Summary.Contains("198.51.100.0/24") && review.Summary.Contains("清空原会话") && OperationSteps.Create(request, plan).Count == 5 && OperationPolicy.TargetLabel(request).Contains("UDP"), "UDP review lost sources, reset impact or progress");
        var sameTcpPort = config.DeepClone().AsObject(); sameTcpPort["Rules"]![0]!["ListenPort"] = plan.Number("Ports.SshPrimary");
        Check(UdpForwarding.Prepare(f.Store, request with { Options = UdpForwarding.Options(state, "Apply", sameTcpPort) }).Configuration["Rules"]!.AsArray().Count == 1, "TCP listener incorrectly reserved UDP port");
        plan.Put("ProtocolInventory.ShadowsocksLanding.Installed", JsonValue.Create(true)); plan.Put("Ports.LandingShadowsocks", JsonValue.Create(55002)); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
        Refuses(() => UdpForwarding.Prepare(f.Store, request), "Shadowsocks UDP collision accepted");
        plan.Put("ProtocolInventory.ShadowsocksLanding.Installed", JsonValue.Create(false)); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
        review = coordinator.Review(request); var changed = request.Options.DeepClone().AsObject(); changed["Configuration"]!["Rules"]![0]!["TargetPort"] = 5353;
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request with { Options = changed }, new InlineProgress<TaskProgress>(_ => { }), default), "changed UDP target survived review");
        var worker = f.Paths.Resolve("scripts/udp-forward-worker.py"); var bytes = File.ReadAllBytes(worker); File.AppendAllText(worker, "\n# changed fixture\n");
        try { await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "changed UDP worker survived review"); } finally { File.WriteAllBytes(worker, bytes); }
        var loop = config.DeepClone().AsObject(); loop["Rules"]![0]!["TargetAddress"] = plan.Text("Server.IPv4"); loop["Rules"]![0]!["TargetPort"] = 55002;
        Refuses(() => UdpForwarding.Prepare(f.Store, request with { Options = UdpForwarding.Options(state, "Apply", loop) }), "UDP local cycle accepted");
        foreach (var failure in new[] { "none", "managed", "drift", "apply-ack", "commit-ack", "incomplete", "cancel", "validation" })
        {
            var target = f.Plan("UDP-" + failure); target.Put("Import.Status", JsonValue.Create("Completed"));
            if (failure != "managed") target.Put("Firewall.Mode", JsonValue.Create("PreserveExisting"));
            f.SaveInstance(target); var instance = f.Relative(target); var root = f.Paths.Instance(instance); var before = ArchiveStore.ReadJson(SafePath.Resolve(root, "deployment-state.json"));
            var remote = new ForwardRemote("udp") { ReadDrift = failure == "drift", LoseApplyAck = failure == "apply-ack" }; remote.Inner.SeedProtocols(target); remote.Inner.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes("existing proxy sentinel"); remote.Inner.LoseOutboundCommitAcknowledgement = failure == "commit-ack";
            var probe = new ForwardValidation(failure, true); var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), udpForwarding: probe);
            Exception? error = null; TaskOutcome? outcome = null;
            try { outcome = await engine.ExecuteAsync(new(OperationKind.UdpForward, instance, UdpForwarding.Options(before, "Apply", config)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { error = e; }
            var actual = ArchiveStore.ReadJson(SafePath.Resolve(root, "deployment-plan.json")); var current = ArchiveStore.ReadJson(SafePath.Resolve(root, "deployment-state.json"));
            if (failure is "none" or "managed" or "commit-ack")
            {
                Check(error == null && outcome == (failure == "commit-ack" ? TaskOutcome.CompletedWithWarnings : TaskOutcome.Completed) && actual["UdpForwarding"] != null && current.Text("UdpForwarding.Validation.Status") == "Passed", "UDP commit or acknowledgement reconciliation failed");
                if (failure == "managed") Check(remote.LastUdpPorts == "55002", "managed firewall omitted UDP port");
                remote.Inner.LoseOutboundCommitAcknowledgement = false; var calls = remote.ApplyCalls;
                Check(await engine.ExecuteAsync(new(OperationKind.UdpForward, instance, UdpForwarding.Options(current, "Check", config)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.ApplyCalls == calls, "UDP read-only check applied resources");
                var probes = probe.Calls;
                await engine.ExecuteAsync(new(OperationKind.HealthAudit, instance, new()), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
                var health = ArchiveStore.ReadJson(SafePath.Resolve(root, "deployment-state.json"));
                Check(health["HealthReport"]!["Checks"]!.AsArray().Any(c => c!.Text("Name") == "UDP 端口转发" && c.Text("Status") == "Passed") && probe.Calls == probes, "health omitted UDP or started repeated probes");
                remote.ReadDrift = true; await engine.ExecuteAsync(new(OperationKind.HealthAudit, instance, new()), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); remote.ReadDrift = false;
                health = ArchiveStore.ReadJson(SafePath.Resolve(root, "deployment-state.json"));
                Check(health["HealthReport"]!["Checks"]!.AsArray().Any(c => c!.Text("Name") == "UDP 端口转发" && c.Text("Status") == "Warning"), "UDP drift became healthy evidence");
                var next = config.DeepClone().AsObject(); next["Rules"]![0]!["TargetAddress"] = "192.0.2.21";
                await engine.ExecuteAsync(new(OperationKind.UdpForward, instance, UdpForwarding.Options(current, "Apply", next)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
                Check(remote.ApplyCalls == calls + 1 && remote.Configuration!["Rules"]![0]!.Text("TargetAddress") == "192.0.2.21", "UDP target modification did not replace configuration");
                current = ArchiveStore.ReadJson(SafePath.Resolve(root, "deployment-state.json"));
                Check(await engine.ExecuteAsync(new(OperationKind.UdpForward, instance, UdpForwarding.Options(current, "Remove")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.Configuration == null, "UDP removal failed");
                if (failure == "managed") Check(remote.LastUdpPorts == "", "removed UDP rule remained allowed in managed firewall");
            }
            else if (failure == "drift") Check(error is OperationException && remote.ApplyCalls == 0 && !remote.Inner.Commands.Contains("protocol-migration-arm-rollback.sh"), "UDP drift mutated resources");
            else
            {
                Check(error != null && actual["UdpForwarding"] == null && current["UdpForwarding"] == null && remote.Configuration == null, "failed UDP task left partial resources or archive");
                Check(remote.ApplyCalls == 1 && ArchiveStore.ReadJson(SafePath.Resolve(root, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack", "UDP mutation was replayed or left pending");
            }
            Check(!remote.Inner.Commands.Any(c => c is "tcp-forward-apply.sh" or "server-outbound-apply.sh" or "protocol-lifecycle-apply-state.sh" or "maintenance-komari.sh") && (remote.Inner.ArmedComponents is "" or "UdpForwarding" or "UdpForwarding,Firewall"), "UDP task expanded its recovery or mutation scope");
            Check(Encoding.UTF8.GetString(remote.Inner.ProtocolConfigs["RealityEntry"]) == "existing proxy sentinel", "UDP changed existing proxy bytes");
        }
        var both = config.DeepClone().AsObject(); both["Rules"]![0]!["ListenFamily"] = "DualStack"; plan.Put("Server.IPv6", JsonValue.Create("2001:db8::10"));
        var complete = await new ForwardValidation("none", true).ValidateAsync(plan, both, directory, new InlineProgress<string>(_ => { }), default);
        UdpForwarding.RequireValidation(plan, both, complete);
        var unconfirmed = complete.DeepClone().AsObject(); unconfirmed["Items"]![0]!["Checks"]![0]!["ResponseMatched"] = false;
        Refuses(() => UdpForwarding.RequireValidation(plan, both, unconfirmed), "UDP result without a matched application response accepted");
        complete["Items"]![0]!["Checks"]!.AsArray().RemoveAt(1);
        Refuses(() => UdpForwarding.RequireValidation(plan, both, complete), "missing UDP address family was accepted");
    }
    private async Task UdpForwardLoopback(Fixture f)
    {
        await using var fixture = new DatagramFixture(); var config = UdpConfig(fixture.Port);
        var plan = new JsonObject { ["Server"] = new JsonObject { ["IPv4"] = "127.0.0.1" } }; var adapter = new UdpForwardValidation();
        config["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Echo" };
        var result = await adapter.ValidateAsync(plan, config, f.Paths.Resolve("udp-probe"), new InlineProgress<string>(_ => { }), default);
        UdpForwarding.RequireValidation(plan, config, result); Check(result["Items"]![0]!["Checks"]![0]!.Flag("ResponseMatched"), "UDP echo did not cross the relay");
        fixture.Respond = DnsAnswer;
        foreach (var type in new[] { "A", "AAAA" })
        {
            config["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Dns", ["QueryName"] = "example.test", ["QueryType"] = type };
            result = await adapter.ValidateAsync(plan, config, f.Paths.Resolve("udp-probe"), new InlineProgress<string>(_ => { }), default);
            Check(result["Status"]!.ToString() == "Passed", "actual forwarded DNS response failed");
        }
        var query = UdpDnsProbe.Query("example.test", "A"); var answer = DnsAnswer(query);
        Check(UdpDnsProbe.Matches(query, answer), "valid DNS fixture rejected");
        foreach (var edit in new Action<byte[]>[] { b => b[0] ^= 1, b => b[2] = 1, b => b[2] |= 2, b => b[3] |= 3, b => b[5] = 2, b => b[query.Length] = 0xff })
        { var bad = answer.ToArray(); edit(bad); Check(!UdpDnsProbe.Matches(query, bad), "stale, truncated, failed or malformed DNS packet accepted"); }
        Check(!UdpDnsProbe.Matches(query, answer[..^1]) && !UdpDnsProbe.Matches(query, new byte[3]), "short DNS response accepted");
        fixture.Respond = bytes => bytes.Select(b => (byte)(b ^ 1)).ToArray(); config["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Echo" };
        await RefusesAsync(async () => { await adapter.ValidateAsync(plan, config, f.Paths.Resolve("udp-probe"), new InlineProgress<string>(_ => { }), default); }, "unrelated UDP response counted as successful forwarding");
        using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(150)); var cancelled = false;
        try { await adapter.ValidateAsync(plan, config, f.Paths.Resolve("udp-probe"), new InlineProgress<string>(_ => { }), stop.Token); } catch (OperationCanceledException) { cancelled = true; }
        Check(cancelled, "UDP receive ignored user cancellation");
    }
    private static byte[] DnsAnswer(byte[] query)
    {
        var ipv6 = query[^3] == 28; var tail = new byte[12 + (ipv6 ? 16 : 4)]; tail[0] = 0xc0; tail[1] = 0x0c; tail[3] = ipv6 ? (byte)28 : (byte)1; tail[5] = 1; tail[11] = ipv6 ? (byte)16 : (byte)4;
        (ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback).GetAddressBytes().CopyTo(tail, 12);
        var response = query.Concat(tail).ToArray(); response[2] = 0x81; response[3] = 0x80; response[7] = 1; return response;
    }
    private sealed class DatagramFixture : IAsyncDisposable
    {
        private readonly UdpClient backend = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly UdpClient relay = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource stop = new(); private readonly Task server, forward;
        public int Port => ((IPEndPoint)relay.Client.LocalEndPoint!).Port;
        public Func<byte[], byte[]> Respond { get; set; } = bytes => bytes;
        public DatagramFixture()
        {
            server = Task.Run(async () => { while (true) { var packet = await backend.ReceiveAsync(stop.Token); await backend.SendAsync(Respond(packet.Buffer), packet.RemoteEndPoint, stop.Token); } });
            forward = Task.Run(async () => { while (true) { var packet = await relay.ReceiveAsync(stop.Token); using var upstream = new UdpClient(); upstream.Connect((IPEndPoint)backend.Client.LocalEndPoint!); await upstream.SendAsync(packet.Buffer, stop.Token); var response = await upstream.ReceiveAsync(stop.Token); await relay.SendAsync(response.Buffer, packet.RemoteEndPoint, stop.Token); } });
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); try { await Task.WhenAll(server, forward); } catch (OperationCanceledException) { } finally { backend.Dispose(); relay.Dispose(); stop.Dispose(); } }
    }
}
