using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunApplicationUdp34Tests(bool modelOnly = false)
    {
        await ApplicationUdp34Model();
        if (!modelOnly) { await InboundPolicy28Runtime(applicationUdp: true); await InboundPolicy28ProbeRuntime(applicationUdp: true); }
        Console.WriteLine($"PASS: {assertions} round34 application UDP, network scope, evidence and recovery assertions; modelOnly={modelOnly}.");
    }
    internal static JsonObject Udp34Proof(string family = "IPv4") => new()
    {
        ["Scope"] = "NativeOutboundUdpDns", ["Transport"] = "UDP", ["ResponseMatched"] = true,
        ["ResolverAddress"] = family == "IPv6" ? "2606:4700:4700::1111" : "1.1.1.1", ["ResolverPort"] = 53,
        ["QueryName"] = "example.com", ["QueryType"] = family == "IPv6" ? "AAAA" : "A"
    };
    private static JsonObject Udp34Rule(string kind, string value, string action, string network = "UDP", string target = "")
    {
        var rule = DestinationRule(kind, value, action); rule["Network"] = network;
        if (target != "") rule["Target"] = target;
        return rule;
    }
    private async Task ApplicationUdp34Model()
    {
        var old = ExampleDestinationRules(); var normal = ServerDestinationRules.Normalize(old);
        Check(JsonNode.DeepEquals(old, normal) && normal.All(r => r!["Network"] == null), "old TCP rules changed identity");
        Check(ServerDestinationRules.Match(normal, "192.0.2.8", "udp").Action == "NextHop", "old TCP reject became a UDP reject");
        var rules = new JsonArray(DestinationRule("Domain", "service.example.test", "Direct"), Udp34Rule("Domain", "service.example.test", "Reject"), Udp34Rule("Cidr", "192.0.2.0/24", "Direct", "Both"));
        rules = ServerDestinationRules.Normalize(rules);
        Check(ServerDestinationRules.Match(rules, "service.example.test").Action == "Direct" && ServerDestinationRules.Match(rules, "service.example.test", "udp").Action == "Reject", "application networks were conflated");
        Check(ServerDestinationRules.Match(rules, "192.0.2.8", "udp").Action == "Direct" && ServerDestinationRules.Match(rules, "192.0.2.8", "tcp").Action == "Direct", "both-networks rule did not match both");
        Check(ServerDestinationRules.Match(rules, "198.51.100.8", "udp").Action == "NextHop", "IP-only metadata guessed a domain");
        foreach (var bad in new JsonNode?[] { JsonValue.Create("icmp"), JsonValue.Create("udp"), JsonValue.Create(false), new JsonArray("UDP"), null })
        { var value = Udp34Rule("Domain", "example.test", "Reject"); value["Network"] = bad?.DeepClone(); Refuses(() => ServerDestinationRules.Normalize(new JsonArray(value)), "invalid application network accepted"); }
        Refuses(() => ServerDestinationRules.Normalize(new JsonArray(Udp34Rule("Domain", "example.test", "Reject", "Both"), Udp34Rule("Domain", "example.test", "Direct"))), "overlapping duplicate transport accepted");
        Refuses(() => ServerDestinationRules.Match(rules, "example.test", "quic"), "QUIC transport confused with application network");
        var category = RuleSetFixture(); var hash = ServerRuleSets.Digest(category); var pinned = ServerRuleSets.Rule(category, "Reject"); pinned["Network"] = "UDP";
        var expansion = ServerRuleSets.Expand(new JsonArray(pinned)).ToArray();
        Check(expansion.All(r => r.Text("Network") == "UDP") && ServerRuleSets.Digest(category) == hash, "protocol choice changed the pinned category or was lost on expansion");
        foreach (var xray in new[] { false, true })
        {
            var rendered = ServerDestinationRules.RenderNative(xray, rules, ["fixture"], d => d.Action == "Reject" ? "block" : "direct");
            Check(rendered[0]!.Text("network") == "tcp" && rendered[1]!.Text("network") == "udp" && (xray ? rendered[2]!.Text("network") == "tcp,udp" : rendered[2]!["network"]!.AsArray().Select(v => v!.ToString()).SequenceEqual(["tcp", "udp"])), "native protocol rendering differs");
        }
        Refuses(() => ServerUdpRouting.ValidateDefault(new JsonArray(Udp34Rule("Cidr", "0.0.0.0/0", "Reject")), "IPv4"), "default UDP acceptance silently changed path");
        ServerUdpRouting.ValidateDefault(new JsonArray(Udp34Rule("Cidr", "1.1.1.1/32", "NextHop"), Udp34Rule("Cidr", "0.0.0.0/0", "Reject")), "IPv4");
        ServerUdpRouting.RequireProof(Udp34Proof(), "IPv4"); ServerUdpRouting.RequireProof(Udp34Proof("IPv6"), "IPv6");
        foreach (var field in new[] { "Scope", "Transport", "ResponseMatched", "ResolverAddress", "ResolverPort", "QueryName", "QueryType" })
        { var proof = Udp34Proof(); proof.Remove(field); Refuses(() => ServerUdpRouting.RequireProof(proof, "IPv4"), "partial UDP evidence accepted: " + field); }
        Refuses(() => ServerUdpRouting.RequireProof(Udp34Proof("IPv6"), "IPv4"), "wrong UDP response family accepted");

        using var f = new Fixture(repository); var plan = f.Plan("Udp34"); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
        var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, credentials, "Shadowsocks2022");
        var sibling = InboundCatalog.AddInbound(model, credentials, "Shadowsocks2022");
        var original = InboundCatalog.Items(model, "Outbounds").First(); var extra = Policy28Exit(f, model, "UDP-extra");
        var policy = new JsonArray(Udp34Rule("Suffix", "udp.example.test", "NextHop", target: extra.Resource.Text("Id")), Udp34Rule("Cidr", "192.0.2.0/24", "Reject"), Udp34Rule("Cidr", "203.0.113.0/24", "Direct"));
        InboundRoutingPolicy.Set(inbound, policy); _ = InboundCatalog.Normalize(model, credentials);
        var request = InboundRoutingPolicy.ProbeRequest(f.Store, plan, model, credentials, inbound);
        Check(request["Paths"]!.AsArray().Count == 3 && request["Paths"]!.AsArray().All(p => p!.Flag("UdpRequired")), "default, extra or direct UDP proof missing");
        var evidence = Policy28Proof(request); InboundRoutingPolicy.RequirePaths(request, evidence);
        var missing = evidence.DeepClone().AsObject(); missing["Items"]![0]!.AsObject().Remove("UdpValidation");
        Refuses(() => InboundRoutingPolicy.RequirePaths(request, missing), "TCP HTTPS qualified application UDP policy");
        var before = InboundRoutingPolicy.Fingerprint(model, inbound); policy[0]!["Network"] = "Both"; InboundRoutingPolicy.Set(inbound, policy);
        Check(InboundRoutingPolicy.Fingerprint(model, inbound) != before, "network change did not invalidate policy identity");
        var statePath = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json");
        var remote = new InboundTestRemote(); remote.Inner.SeedProtocols(plan);
        var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: new InboundTestValidation(f.Store)));
        async Task<TaskRecord> Apply(JsonObject candidate)
        {
            var operation = new OperationRequest(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(statePath), "Apply", candidate, credentials));
            return await coordinator.ExecuteAsync(coordinator.Review(operation), operation, new InlineProgress<TaskProgress>(_ => { }), default);
        }
        Check((await Apply(model)).Outcome == TaskOutcome.Completed, "UDP policy did not complete scoped deployment");
        var changed = model.DeepClone().AsObject(); changed["Inbounds"]![0]!["Routing"]!["Rules"]![0]!["Network"] = "TCP";
        // Normalize TCP back to its original compact representation.
        InboundRoutingPolicy.Set(changed["Inbounds"]![0]!.AsObject(), changed["Inbounds"]![0]!["Routing"]!["Rules"]!.AsArray());
        var originalHash = ArchiveStore.Fingerprint(remote.Current!); remote.Failure = "policy-validation";
        Check((await Apply(changed)).Outcome == TaskOutcome.Failed && ArchiveStore.Fingerprint(remote.Current!) == originalHash && remote.LastAffected.SequenceEqual([inbound.Text("Id")]), "UDP acceptance failure did not restore only the changed inbound");
        Check(InboundCatalog.Items(model, "Inbounds").Any(i => i.Text("Id") == sibling.Text("Id")), "UDP policy replaced sibling identity");
        credentials.Clear();
        foreach (var role in ServerOutboundRouting.Roles)
        {
            var data = RealityFixture(f, "Fixed34-" + role, true);
            var input = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, ServerOutboundRouting.ConfigRelative(role)));
            var preview = ServerOutboundRouting.Build(role, input, data.Plan.At("ServerOutbound." + role)!.AsObject(), data.Node, "198.51.100.20", data.Plan,
                destinationRules: new JsonArray(Udp34Rule("Suffix", "udp.example.test", "Direct")));
            var active = data.Plan.DeepClone().AsObject(); active.Put("ServerOutbound." + role, preview.Metadata!.DeepClone());
            var paths = ServerOutboundRouting.ProbeRequests(role, preview.Configuration, active);
            Check(paths.Count == 2 && paths.All(p => p!.Flag("UdpRequired")) && preview.Metadata.Text("DestinationRulesNetwork") == "tcp,udp", role + " omitted default/direct UDP proof or metadata");
            var proof = new JsonObject { ["Status"] = "Passed", ["Items"] = new JsonArray(paths.OfType<JsonObject>().Select(p => (JsonNode?)new JsonObject
            {
                ["Id"] = p.Text("Id"), ["Status"] = "Passed", ["From"] = "EntryServer", ["Network"] = "TCP",
                ["Egress"] = p.Text("ExpectedAddress", "198.51.100.34") is { Length: > 0 } address ? address : "198.51.100.34",
                ["UdpValidation"] = Udp34Proof()
            }).ToArray()) };
            ServerOutboundRouting.RequireHopValidation(paths, proof);
            proof["Items"]![0]!.AsObject().Remove("UdpValidation"); Refuses(() => ServerOutboundRouting.RequireHopValidation(paths, proof), "fixed-role TCP-only evidence qualified UDP");
            Check(JsonNode.DeepEquals(ServerOutboundRouting.Build(role, preview.Configuration, preview.Metadata, null, "", active).Configuration,
                role == "RealityEntry" ? ServerConfigurations.Xray(data.Plan, data.Secrets) : ServerConfigurations.AnyTls(data.Plan, data.Secrets)), "fixed UDP policy removal lost original configuration");
            foreach (var fail in new[] { false, true })
            {
                var fixedRemote = RoutingRemote(data); fixedRemote.HopProbeFailure = fail;
                var oldConfig = fixedRemote.ProtocolConfigs[role].ToArray(); var other = role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry"; var siblingConfig = fixedRemote.ProtocolConfigs[other].ToArray();
                var engine = new WorkflowEngine(f.Store, fixedRemote, new FakeKeys(), new FakeUser(), new RealityLifecycleValidation("none"));
                var fixedRequest = new OperationRequest(OperationKind.ServerOutbound, data.Relative, ServerOutboundRouting.Options(data.State, role, "Apply", data.Scheme, data.Node, "198.51.100.20", new JsonArray(Udp34Rule("Suffix", "udp.example.test", "Direct"))));
                Exception? error = null; TaskOutcome? outcome = null;
                try { outcome = await engine.ExecuteAsync(fixedRequest, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (OperationException e) { error = e; }
                Check(fixedRemote.ProtocolConfigs[other].SequenceEqual(siblingConfig) && fixedRemote.ArmedComponents == role, "fixed-role UDP changed an unrelated component");
                Check(fail ? error != null && fixedRemote.ProtocolConfigs[role].SequenceEqual(oldConfig) : error == null && outcome == TaskOutcome.Completed && fixedRemote.Commands.Contains("server-hop-probe.sh"), "fixed-role UDP task did not verify or restore its path");
                // Restore the exact starting local archive for the independent scenario.
                ArchiveStore.WriteJson(SafePath.Resolve(data.Directory, "deployment-plan.json"), data.Plan);
                ArchiveStore.WriteJson(SafePath.Resolve(data.Directory, "deployment-state.json"), data.State);
                ArchiveStore.WriteJson(SafePath.Resolve(data.Directory, ServerOutboundRouting.ConfigRelative(role)), input);
            }
        }
    }
}
