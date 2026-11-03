using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunChain30Tests()
    {
        await Chain30Coverage();
        Console.WriteLine($"PASS: {assertions} round 30 adjacent tunnels, independent slots, scoped compensation, dependency and PROXY model assertions; synthetic only.");
    }
    private async Task Chain30Coverage()
    {
        foreach (var family in new[] { "IPv4", "IPv6" })
        {
            await Chain21Case(family, "TCP", "vless", "none", "Both");
            foreach (var protocol in new[] { "hysteria2", "tuic" }) await Chain21Case(family, "UDP", protocol, "none", "Both");
        }
        foreach (var failure in new[] { "wg-drift", "wg-late-drift", "wg-missing-udp", "wg-stale", "wg-second-drift", "wg-second-missing-udp", "validation", "cancel", "apply-ack", "commit-front", "rollback", "compensation-ack" })
            await Chain21Case("IPv6", "UDP", "tuic", failure, "Both");
        foreach (var failure in new[] { "", "apply-ack", "missing-udp", "commit-second", "compensation-ack", "rollback", "cancel" }) await WireGuard30Slots(failure);
        Proxy30Model();
    }
    private JsonObject SeedChain30Underlays(Fixture f, List<JsonObject> plans, ChainRemote remote, JsonObject chain)
    {
        var first = SeedChainUnderlay(f, plans, remote, chain, "FrontRelay"); var reference = chain["WireGuard"]!.DeepClone();
        var second = WireGuardTunnels.New(f.Relative(plans[1])); second["SecondInstance"] = f.Relative(plans[2]); second["FirstSlot"] = 1;
        second["FirstPort"] = 51821; second["FirstAddress"] = "10.203.1.1"; second["SecondAddress"] = "10.203.1.2";
        for (var index = 0; index < 2; index++)
        {
            var instance = WireGuardTunnels.Instances(second)[index]; var plan = TcpChains.Plan(f.Store, instance);
            var peer = WireGuardTunnels.Peer(second, plan, TcpChains.Plan(f.Store, WireGuardTunnels.Instances(second)[1-index]), index == 0);
            peer["PublicKey"] = Convert.ToBase64String(Enumerable.Repeat((byte)(index+3), 32).ToArray()); peer["PeerPublicKey"] = Convert.ToBase64String(Enumerable.Repeat((byte)(4-index), 32).ToArray());
            var key = WireGuardTunnels.Component(second, instance); plan[key] = peer;
            ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(instance), "deployment-plan.json"), plan);
            var file = SafePath.Resolve(f.Paths.Instance(instance), "deployment-state.json"); var state = ArchiveStore.ReadJson(file);
            state[key] = new JsonObject { ["RemoteHash"] = ArchiveStore.Fingerprint(peer), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(peer) }; ArchiveStore.WriteJson(file, state);
            if (index == 0) remote.Hosts[plan.Text("Server.IPv4")].WireGuard2 = peer.DeepClone().AsObject(); else remote.Hosts[plan.Text("Server.IPv4")].WireGuard = peer.DeepClone().AsObject();
        }
        var record = new JsonObject { ["Version"] = 1, ["Configuration"] = second.DeepClone(), ["Phase"] = "Active", ["Validation"] = new JsonObject { ["Status"] = "Passed", ["Scope"] = "BidirectionalWireGuardApplications", ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(second) } };
        ArchiveStore.WriteJson(WireGuardTunnels.FileName(f.Paths, second.Text("Id")), record);
        chain.Remove("WireGuard"); chain["WireGuards"] = new JsonArray(reference, TcpChainUnderlay.Reference(f.Store, record, "RelayLanding"));
        Check(TcpChainUnderlay.Choices(f.Store, chain).Count() == 2, "two adjacent choices were not both available");
        Check(TcpChainUnderlay.Target(f.Store, chain, true) == TcpChainUnderlay.Inner(first, chain.Text("RelayInstance")) && TcpChainUnderlay.Target(f.Store, chain, false) == second.Text("SecondAddress"), "two-leg targets escaped their selected tunnels");
        foreach (var bad in new[] { -1, 2 }) { var invalid = second.DeepClone().AsObject(); invalid["FirstSlot"] = bad; Refuses(() => WireGuardTunnels.Validate(new(OperationKind.WireGuardTunnel, invalid.Text("FirstInstance"), new() { ["Action"] = "Check", ["Configuration"] = invalid })), "out-of-range interface slot accepted"); }
        return first;
    }
    private void CheckChain30Active(Fixture f, JsonObject chain, JsonObject record, JsonObject projected, TaskCoordinator coordinator)
    {
        var proof = record["Validation"]!.AsObject();
        Check(proof.Text("WireGuard.Scope") == "AdjacentWireGuardApplications" && proof.At("WireGuard.Segments")!.AsArray().Count == 2, "two-leg chain committed without distinct proofs");
        foreach (var reference in TcpChainUnderlay.References(chain))
        {
            var path = WireGuardTunnels.FileName(f.Paths, reference.Text("Id")); var saved = ArchiveStore.ReadJson(path);
            Refuses(() => coordinator.Review(new(OperationKind.WireGuardTunnel, saved.Text("Configuration.FirstInstance"), new() { ["Action"] = "Remove", ["Configuration"] = saved["Configuration"]!.DeepClone() })), "one of two active dependencies could be removed");
            saved["LastCheck"] = new JsonObject { ["Status"] = "Failed" }; ArchiveStore.WriteJson(path, saved);
            Refuses(() => TcpChains.VerifyNodes(f.Store, [projected]), "failed adjacent segment retained client export eligibility"); saved.Remove("LastCheck"); ArchiveStore.WriteJson(path, saved);
        }
        var missing = proof.DeepClone().AsObject(); missing["WireGuard"]!["Segments"]!.AsArray().RemoveAt(1);
        Refuses(() => TcpChains.RequireValidation(chain, projected, missing), "one segment's proof substituted for two segments");
        var spoofed = proof.DeepClone().AsObject(); spoofed["WireGuard"]!["Segments"]![1]!["Segment"] = "FrontRelay";
        Refuses(() => TcpChains.RequireValidation(chain, projected, spoofed), "a first-segment proof substituted for the second");
        var duplicate = chain.DeepClone().AsObject(); duplicate["WireGuards"]![1] = duplicate["WireGuards"]![0]!.DeepClone(); Refuses(() => TcpChainUnderlay.Validate(duplicate), "duplicate segment references accepted");
        var mixed = chain.DeepClone().AsObject(); mixed["WireGuard"] = mixed["WireGuards"]![0]!.DeepClone(); Refuses(() => TcpChainUnderlay.Validate(mixed), "ambiguous single/multiple references accepted");
    }
    private async Task WireGuard30Slots(string failure)
    {
        using var f = new Fixture(repository); var remote = new WireGuard30Remote(); var plans = new List<JsonObject>();
        for (var i = 0; i < 3; i++)
        {
            var p = f.Plan("WG30-" + i); p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); p.Put("Server.IPv4", JsonValue.Create("192.0.2." + (170+i))); f.SaveInstance(p); plans.Add(p);
            remote.Hosts[p.Text("Server.IPv4")] = new WireGuard30Host(p.Text("Server.IPv4"), i);
            foreach (var host in remote.Hosts[p.Text("Server.IPv4")].Slots) host.Inner.SeedProtocols(p);
        }
        var first = WireGuardTunnels.New(f.Relative(plans[0])); first["SecondInstance"] = f.Relative(plans[1]);
        var second = WireGuardTunnels.New(f.Relative(plans[1])); second["SecondInstance"] = f.Relative(plans[2]); second["FirstSlot"] = 1; second["FirstPort"] = 51821; second["FirstAddress"] = "10.203.1.1"; second["SecondAddress"] = "10.203.1.2";
        var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation()));
        OperationRequest Request(JsonObject c, string action) => new(OperationKind.WireGuardTunnel, c.Text("FirstInstance"), new() { ["Action"] = action, ["Configuration"] = c.DeepClone() });
        async Task<TaskRecord> Execute(JsonObject c, string action) { var request = Request(c, action); return await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), default); }
        Check((await Execute(first, "Apply")).Outcome == TaskOutcome.Completed, "first independent tunnel failed");
        var original = TcpChains.Plan(f.Store, f.Relative(plans[1]))["WireGuardTunnel"]!.DeepClone();
        var firstFile = WireGuardTunnels.FileName(f.Paths,first.Text("Id")); var activeFirst = ArchiveStore.ReadJson(firstFile); var orphanPending = activeFirst.DeepClone().AsObject(); orphanPending["Phase"] = "NeedsRecovery"; ArchiveStore.WriteJson(firstFile,orphanPending);
        Refuses(() => coordinator.Review(Request(second,"Apply")), "an orphan pending record in another slot allowed a new host transaction"); ArchiveStore.WriteJson(firstFile,activeFirst);
        var conflict = second.DeepClone().AsObject(); conflict["FirstPort"] = 51820; Refuses(() => coordinator.Review(Request(conflict, "Apply")), "two interface slots shared an outer port");
        conflict = second.DeepClone().AsObject(); conflict["FirstAddress"] = first.Text("SecondAddress"); Refuses(() => coordinator.Review(Request(conflict, "Apply")), "two interface slots reused an inner address");
        remote.Hosts[plans[1].Text("Server.IPv4")].Slots[1].Failure = failure;
        if (failure == "commit-second") { remote.Hosts[plans[1].Text("Server.IPv4")].Slots[1].Failure = ""; remote.Hosts[plans[2].Text("Server.IPv4")].Slots[0].Failure = failure; }
        var result = await Execute(second, "Apply");
        if (failure == "")
        {
            Check(result.Outcome == TaskOutcome.Completed, "second independent tunnel failed: " + result.SafeError);
            Check((await Execute(first, "Check")).Outcome == TaskOutcome.Completed && (await Execute(second, "Check")).Outcome == TaskOutcome.Completed, "one slot's installation invalidated the other's evidence");
            Check((await Execute(second, "Remove")).Outcome == TaskOutcome.Completed, "removing second slot failed");
        }
        else
        {
            var pending = failure is "rollback" or "compensation-ack";
            Check(result.Outcome == (pending ? TaskOutcome.NeedsRecovery : failure == "cancel" ? TaskOutcome.Cancelled : TaskOutcome.Failed), "unexpected second-slot fault outcome: " + failure + ": " + result.SafeError);
            if (pending)
            {
                remote.Hosts[plans[1].Text("Server.IPv4")].Slots[1].Failure = "";
                Check((await Execute(second, "Recover")).Outcome == TaskOutcome.Completed, "second-slot recovery could not resume");
            }
            Check(remote.Hosts[plans[1].Text("Server.IPv4")].Slots[1].ApplyCalls <= 1 && remote.Hosts[plans[2].Text("Server.IPv4")].Slots[0].ApplyCalls <= 1, "second-slot mutation replayed after lost acknowledgement");
        }
        Check(JsonNode.DeepEquals(TcpChains.Plan(f.Store, f.Relative(plans[1]))["WireGuardTunnel"], original), "second-slot removal or compensation overwrote the first tunnel");
        Check(TcpChains.Plan(f.Store, f.Relative(plans[1]))["WireGuardTunnel2"] == null, "second-slot cleanup retained configuration");
        Check((await Execute(first, "Check")).Outcome == TaskOutcome.Completed, "first tunnel no longer healthy after second-slot cleanup");
        Check((await Execute(first, "Remove")).Outcome == TaskOutcome.Completed, "first tunnel cleanup failed");
        foreach (var host in remote.Hosts.Values) foreach (var slot in host.Slots) Check(slot.Config == null && slot.ProofStarts == slot.ProofStops, "slot-owned interface or challenge leaked");
    }
    private void Proxy30Model()
    {
        foreach (var version in new[] { "v1", "v2" })
        {
            var rule = TcpForwarding.NewRule(); rule["ListenPort"] = 19000; rule["TargetAddress"] = "192.0.2.80"; rule["TargetPort"] = 443; rule["AllowedSources"] = new JsonArray("198.51.100.0/24"); rule["Validation"]!["ServerName"] = "forward.example.test"; rule["ProxyProtocol"] = version;
            var config = new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(rule) };
            Check(TcpForwarding.Rules(TcpForwarding.Normalize(config)).Single().Text("ProxyProtocol") == version, "explicit PROXY output lost during normalization");
            foreach (var bad in new JsonNode?[] { null, JsonValue.Create(true), JsonValue.Create("auto"), JsonValue.Create("receive-v1"), new JsonObject { ["Send"] = version } })
            { var copy = config.DeepClone().AsObject(); copy["Rules"]![0]!["ProxyProtocol"] = bad; Refuses(() => TcpForwarding.Normalize(copy), "invalid PROXY or input-trust mode accepted"); }
            var bannerOnly = config.DeepClone().AsObject(); bannerOnly["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Ssh" }; Refuses(() => TcpForwarding.Normalize(bannerOnly), "an SSH banner alone could qualify PROXY acceptance");
            var checks = new JsonArray(new JsonObject { ["Address"] = "192.0.2.70", ["Type"] = "Tls", ["Status"] = "Passed" });
            var result = new JsonObject { ["Status"] = "Passed", ["Items"] = new JsonArray(new JsonObject { ["Id"] = rule.Text("Id"), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "ForwardedApplication", ["Checks"] = checks }) };
            Refuses(() => TcpForwarding.RequireValidation(config, result), "ordinary TLS proof was substituted for explicit PROXY acceptance");
            checks[0]!["ProxyProtocol"] = version; TcpForwarding.RequireValidation(config, result); Check(true, "explicit PROXY acceptance failed");
        }
    }
    private sealed class WireGuard30Remote : IRemoteSessionFactory
    {
        public Dictionary<string, WireGuard30Host> Hosts { get; } = new();
        public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken cancellationToken) => Task.FromResult<IRemoteSession>(Hosts[endpoint.Host]);
    }
    private sealed class WireGuard30Host(string address, int index) : IRemoteSession
    {
        public WireGuardHostFake[] Slots { get; } = [new(address, index*2), new(address, index*2+1)];
        private WireGuardHostFake current = null!;
        public Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutation, CancellationToken ct)
        {
            var match = Regex.Match(payload, "export VPS_PARAM_WIREGUARD_SLOT=.+?'([A-Za-z0-9+/=]*)' ");
            var slot = match.Success && Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)) == "1" ? 1 : 0;
            current = Slots[slot]; return current.RunScriptAsync(payload, timeout, mutation, ct);
        }
        public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct) => (current ?? Slots[0]).RunAsync(command, timeout, ct);
        public Task<byte[]> ReadFileAsync(string path, CancellationToken ct) => Slots[0].ReadFileAsync(path, ct);
        public Task DownloadAsync(string path, string target, CancellationToken ct) => (current ?? Slots[0]).DownloadAsync(path, target, ct);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
