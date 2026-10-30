using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunChain21Tests()
    {
        await TcpChainExperience();
        await Chain21Coverage();
        Console.WriteLine($"PASS: {assertions} round 21 family, QUIC-chain, evidence, preserved scope and coordinated recovery assertions; synthetic only.");
    }
    private async Task Chain21Coverage()
    {
        foreach (var family in new[] { "IPv4", "IPv6" })
        {
            await Chain21Case(family, "TCP", "vless", "none");
            foreach (var protocol in new[] { "hysteria2", "tuic" }) await Chain21Case(family, "UDP", protocol, "none");
        }
        foreach (var failure in new[] { "missing-udp", "wrong-protocol", "relay-drift", "landing-drift", "arm-before", "arm-ack", "apply-ack", "validation", "incomplete", "cancel", "commit-ack", "commit-front", "compensation-ack", "rollback", "owner" })
            await Chain21Case("IPv6", "UDP", "hysteria2", failure);
    }

    private async Task Chain21Case(string family, string transport, string protocol, string failure)
    {
        using var f = new Fixture(repository); var remote = new ChainRemote(); var plans = new List<JsonObject>();
        for (var i = 0; i < 3; i++)
        {
            var p = f.Plan("Chain21-" + i); p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Firewall.Mode", JsonValue.Create("PreserveExisting"));
            p.Put("Server.IPv4", JsonValue.Create("192.0.2." + (10+i))); p.Put("Server.IPv6", JsonValue.Create("2001:db8::" + (10+i))); f.SaveInstance(p); plans.Add(p);
            var host = new ChainHost(p.Text("Server.IPv4"), remote); host.Inner.SeedProtocols(p); host.Inner.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes("unchanged existing role"); remote.Hosts.Add(p.Text("Server.IPv4"), host);
        }
        var front = remote.Hosts[plans[0].Text("Server.IPv4")]; var relay = remote.Hosts[plans[1].Text("Server.IPv4")]; var landing = remote.Hosts[plans[2].Text("Server.IPv4")];
        var landingDir = f.Paths.Instance(f.Relative(plans[2])); var state = ArchiveStore.ReadJson(SafePath.Resolve(landingDir, "deployment-state.json"));
        var credentials = f.Store.ReadSecret(SafePath.Resolve(landingDir, "secrets.dotnet.private.json")); JsonObject node;
        if (transport == "TCP")
        {
            var pair = ClientProfiles.Nodes(plans[2], credentials).First(p => p.Family == family);
            node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = pair.Name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = pair.Clash.DeepClone(), ["sing_box"] = pair.SingBox.DeepClone(), ["ManagedOrigin"] = ManagedNodeSources.Origin(f.Relative(plans[2]), pair) };
            state.Put("ServerConfigHashes.RealityEntry", JsonValue.Create(ArchiveStore.Digest(landing.Inner.ProtocolConfigs["RealityEntry"])));
        }
        else
        {
            var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials();
            var inbound = InboundCatalog.AddInbound(model, secrets, protocol == "tuic" ? "TuicV5" : "Hysteria2"); var cert = InboundCertificate("chain.example.test");
            inbound["CertificateId"] = InboundCatalog.ImportCertificate(model, secrets, "chain TLS", cert.Certificate, cert.Key).Text("Id"); inbound["Options"]!["ServerName"] = "chain.example.test"; inbound["Listener"]!["Address"] = family == "IPv6" ? "::" : "0.0.0.0";
            model = InboundCatalog.Normalize(model, secrets); plans[2]["InboundModel"] = model.DeepClone(); credentials["Inbounds"] = secrets.DeepClone();
            var payload = InboundRendering.Payload(f.Store, plans[2], model, secrets); var nodes = InboundRendering.Nodes(f.Store, f.Relative(plans[2]), plans[2], model, secrets).ToArray(); node = nodes.Single(n => n.Text("InboundOrigin.Family") == family);
            var validation = await new TuicMockValidation(f.Store).ValidateAsync(plans[2], model, secrets, [inbound.Text("Id")], "unused", new InlineProgress<string>(_ => { }), default);
            var runtime = new JsonObject { [inbound.Text("Id")] = new JsonObject { ["Active"] = true, ["Enabled"] = true } };
            state["Inbounds"] = new JsonObject { ["RemoteHash"] = ArchiveStore.Fingerprint(payload), ["ModelFingerprint"] = ArchiveStore.Fingerprint(model), ["Runtime"] = runtime.DeepClone(), ["ValidationById"] = new JsonObject { [inbound.Text("Id")] = validation.DeepClone() } };
            landing.InboundState = new JsonObject { ["Hash"] = state.Text("Inbounds.RemoteHash"), ["Registry"] = new JsonObject { ["Model"] = model.DeepClone() }, ["Runtime"] = runtime };
        }
        ArchiveStore.WriteJson(SafePath.Resolve(landingDir, "deployment-plan.json"), plans[2]); ArchiveStore.WriteJson(SafePath.Resolve(landingDir, "deployment-state.json"), state); f.Store.WriteSecret(SafePath.Resolve(landingDir, "secrets.dotnet.private.json"), credentials); credentials.Clear();
        var scheme = ClientSchemes.New(f.Paths); scheme["Nodes"]!.AsArray().Add(node.DeepClone()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        var config = TcpChains.New(f.Relative(plans[0])); config["Family"] = family; config["Transport"] = transport; config["RelayInstance"] = f.Relative(plans[1]); config["LandingInstance"] = f.Relative(plans[2]); config["FrontSources"] = new JsonArray(family == "IPv6" ? "2001:db8:1::/64" : "198.51.100.0/24"); config["FrontSourceAddress"] = plans[0].Text("Server." + family); config["Landing"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
        OperationRequest Request(string action) => new(OperationKind.TcpChain, f.Relative(plans[0]), new JsonObject { ["Action"] = action, ["Configuration"] = config.DeepClone() });
        var validator = new ChainValidation { Failure = failure, Remote = remote }; var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpChains: validator)); var progress = new InlineProgress<TaskProgress>(_ => { });
        var preview = TcpChains.Prepare(f.Store, Request("Apply"));
        Check(preview.RelayConfiguration["Rules"]![0]!.Text("ListenFamily") == family && preview.RelayConfiguration["Rules"]![0]!.Strings("AllowedSources").Single() == plans[0].Text("Server." + family) + (family == "IPv6" ? "/128" : "/32"), "family or exact relay source scope changed");
        Check(preview.Summary.Contains(family) && preview.Summary.Contains(transport) && (node.Text("sing_box.password") == "" || !preview.Summary.Contains(node.Text("sing_box.password"), StringComparison.Ordinal)), "review omitted transport/family or exposed a credential");
        if (failure == "none")
        {
            foreach (var field in new[] { "Family", "Transport" }) foreach (var invalid in new JsonNode?[] { null, JsonValue.Create(3), JsonValue.Create("unknown") }) { var bad = Request("Apply"); bad.Options["Configuration"]![field] = invalid?.DeepClone(); Refuses(() => coordinator.Review(bad), "invalid family/transport type reached review"); }
            if (transport == "TCP" && family == "IPv4") { var legacy = Request("Apply"); legacy.Options["Configuration"]!.AsObject().Remove("Family"); legacy.Options["Configuration"]!.AsObject().Remove("Transport"); var before = ArchiveStore.Fingerprint(legacy.Options); TcpChains.Validate(legacy); Check(before == ArchiveStore.Fingerprint(legacy.Options), "reading an existing schema-1 chain changed its identity"); }
            var badAddress = Request("Apply"); badAddress.Options["Configuration"]!["FrontSourceAddress"] = family == "IPv6" ? "::ffff:192.0.2.1" : "2001:db8::1"; Refuses(() => coordinator.Review(badAddress), "wrong or mapped source address accepted");
            if (transport == "UDP") { var hopped = node.DeepClone().AsObject(); hopped["sing_box"]!["server_ports"] = new JsonArray("10000:10002"); Check(!TcpChains.Supports(hopped, "UDP", family) && !TcpChains.Supports(node, "TCP", family), "UDP chain accepted hopping or advertised TCP"); }
        }
        relay.Failure = failure; relay.Drift = failure == "relay-drift"; if (failure == "commit-front") front.Failure = failure;
        if (failure == "landing-drift") landing.InboundState!["Hash"] = new string('f', 64);
        var result = await coordinator.ExecuteAsync(coordinator.Review(Request("Apply")), Request("Apply"), progress, default); var path = TcpChains.FileName(f.Paths, config.Text("Id")); var record = ArchiveStore.ReadJson(path); var component = TcpChains.Component(config);
        Check(landing.ApplyCalls == 0 && landing.Inner.Mutations == 0, "chain mutated its landing or an unrelated component");
        if (failure == "none")
        {
            Check(result.Outcome == TaskOutcome.Completed && record.Text("Phase") == "Active", "round 21 chain did not complete: " + result.SafeError);
            var projected = TcpChains.Project(f.Store, config, "US-West-LA Entry"); TcpChains.VerifyNodes(f.Store, [projected]);
            Check(projected.Text("sing_box.server") == plans[0].Text("Server." + family) && projected.Text("sing_box.type") == protocol && projected["InboundOrigin"] == null && projected.Text("sing_box.tls.server_name") == node.Text("sing_box.tls.server_name"), "projection lost transport identity or kept the original endpoint origin");
            Check(ForwardedNodeSources.Choices(f.Store, "US-West-LA Entry").Any(c => c.RuleId == config.Text("Id") && c.Family == family && c.Node != null), "selected family chain unavailable to client schemes");
            Refuses(() => coordinator.Review(new(OperationKind.Inbounds, f.Relative(plans[2]), new())), "independent inbound could bypass landing dependency");
            var checkedResult = await coordinator.ExecuteAsync(coordinator.Review(Request("Check")), Request("Check"), progress, default); Check(checkedResult.Outcome == TaskOutcome.Completed, "read-only whole chain check failed");
            var removed = await coordinator.ExecuteAsync(coordinator.Review(Request("Remove")), Request("Remove"), progress, default); Check(removed.Outcome == TaskOutcome.Completed && front.Configuration == null && relay.Configuration == null, "round 21 removal retained owned rules"); Refuses(() => TcpChains.VerifyNodes(f.Store, [projected]), "removed round 21 source remained exportable");
            foreach (var plan in plans) Check(TcpChains.Plan(f.Store, f.Relative(plan))["TcpChain"] == null, "completed removal retained dependency");
        }
        else
        {
            var pending = failure is "rollback" or "owner" or "compensation-ack";
            Check(result.Outcome == (pending ? TaskOutcome.NeedsRecovery : failure == "cancel" ? TaskOutcome.Cancelled : TaskOutcome.Failed), "wrong UDP failure result for " + failure + ": " + result.SafeError);
            Check(front.ApplyCalls <= 1 && relay.ApplyCalls <= 1, "UDP mutation was replayed after lost acknowledgement");
            if (pending) { relay.Failure = ""; relay.Inner.StatusTaskId = record.Text("Transaction.TaskId"); Check((await coordinator.ExecuteAsync(coordinator.Review(Request("Recover")), Request("Recover"), progress, default)).Outcome == TaskOutcome.Completed, "UDP compensation could not resume"); }
            Check(ArchiveStore.ReadJson(path).Text("Phase") == "RolledBack" && front.Configuration == null && relay.Configuration == null, "failed UDP chain retained active forwarding");
            foreach (var plan in plans) Check(ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json"))["TcpChainTransaction"] == null, "finished UDP recovery left a reservation");
        }
        foreach (var p in plans.Take(2)) Check(TcpChains.Plan(f.Store, f.Relative(p))[component == "UdpForwarding" ? "TcpForwarding" : "UdpForwarding"] == null, "chain wrote another forwarding component");
    }
}
