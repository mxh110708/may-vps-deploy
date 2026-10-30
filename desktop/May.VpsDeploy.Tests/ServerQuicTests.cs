using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunServerQuicTests(bool modelOnly = false)
    {
        await ServerQuicModel();
        if (!modelOnly) await ServerQuicRuntime();
        Console.WriteLine($"PASS: {assertions} round 17 server QUIC next-hop assertions; synthetic only.");
    }
    private static JsonObject QuicHopNode(string protocol, int port = 24000)
    {
        var native = new JsonObject { ["type"] = protocol, ["tag"] = "next", ["server"] = "192.0.2.20", ["server_port"] = port, ["password"] = "synthetic-next-hop-password",
            ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "next.example.test", ["min_version"] = "1.3", ["alpn"] = new JsonArray("h3") } };
        if (protocol == "tuic") { native["uuid"] = Guid.NewGuid().ToString(); native["congestion_control"] = "cubic"; native["udp_relay_mode"] = "native"; native["heartbeat"] = "10s"; native["zero_rtt_handshake"] = false; }
        return new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Synthetic " + protocol, ["kind"] = "landing", ["sing_box"] = native };
    }
    private async Task ServerQuicModel()
    {
        using var f = new Fixture(repository);
        foreach (var protocol in new[] { "hysteria2", "tuic" })
        {
            var node = QuicHopNode(protocol); var native = node["sing_box"]!.AsObject();
            Check(ServerOutboundRouting.SupportedNode(node, "AnyTlsEntry") && ServerOutboundRouting.SupportedNode(node, "RealityEntry") == (protocol == "hysteria2"), "Core capabilities silently changed TUIC/Hysteria support");
            foreach (var field in new[] { "detour", "bind_interface", "certificate_path", "network", "token" })
            { var bad = node.DeepClone().AsObject(); bad["sing_box"]![field] = "unsupported"; Refuses(() => ServerOutboundRouting.NextHop(bad), "Unknown next-hop option was stripped: " + field); }
            foreach (var field in new[] { "insecure", "certificate_path", "ech" })
            { var bad = node.DeepClone().AsObject(); bad["sing_box"]!["tls"]![field] = field == "insecure" ? JsonValue.Create(true) : JsonValue.Create("unsupported"); Refuses(() => ServerOutboundRouting.NextHop(bad), "Unsafe next-hop TLS option accepted"); }
            if (protocol == "tuic") { var bad = node.DeepClone().AsObject(); bad["sing_box"]!["zero_rtt_handshake"] = true; Refuses(() => ServerOutboundRouting.NextHop(bad), "Server TUIC enabled 0-RTT"); }
            else
            {
                native["up_mbps"] = 20; native["down_mbps"] = 40; native["server_ports"] = new JsonArray("24000:24002"); native["hop_interval"] = "5s"; native["hop_interval_max"] = "7s"; native["obfs"] = new JsonObject { ["type"] = "salamander", ["password"] = "synthetic-next-obfuscation" };
                var xray = ServerOutboundRouting.XrayNextHop(native);
                Check(xray.Text("protocol") == "hysteria" && xray.Number("settings.version") == 2 && xray.Text("streamSettings.hysteriaSettings.auth") == native.Text("password") && xray.Text("streamSettings.finalmask.quicParams.brutalUp") == "20 Mbps", "Xray Hysteria credentials or congestion mapping failed");
                Check(xray["streamSettings"]!["finalmask"]!["udp"]![0]!.Text("settings.password") == native.Text("obfs.password") && xray.Text("streamSettings.finalmask.quicParams.udpHop.ports") == "24000-24002" && xray.Text("streamSettings.finalmask.quicParams.udpHop.interval") == "5-7", "Xray lost Salamander or port hopping");
            }
            var plan = f.Plan("Quic-" + protocol); var current = ServerConfigurations.AnyTls(plan, Fixture.RealitySecrets());
            var preview = ServerOutboundRouting.Build("AnyTlsEntry", current, null, node, "198.51.100.22", plan);
            Check(preview.Configuration["outbounds"]![1]!.Text("type") == protocol && !preview.Summary.Contains(native.Text("password")) && JsonNode.DeepEquals(current["inbounds"], preview.Configuration["inbounds"]), "Server route changed listener or exposed next-hop credentials");
            Check(JsonNode.DeepEquals(current, ServerOutboundRouting.Build("AnyTlsEntry", preview.Configuration, preview.Metadata, null, "", plan).Configuration), "Removing QUIC next hop did not restore original policy");
            var extra = QuicHopNode(protocol, 24003); var named = ServerOutboundRouting.Build("AnyTlsEntry", current, null, node, "198.51.100.22", plan, destinationRules: new JsonArray(HopRule("Domain", "extra.example.test", HopA)), additionalHops: [new(HopA, extra, "198.51.100.23")]);
            Check(named.Configuration["outbounds"]!.AsArray().Any(o => o!.Text("tag") == ServerOutboundRouting.HopTag(HopA) && o.Text("type") == protocol), "Named TCP business hop lost its QUIC transport");
            if (protocol == "hysteria2") { var reality = ServerConfigurations.Xray(plan, Fixture.RealitySecrets()); var converted = ServerOutboundRouting.Build("RealityEntry", reality, null, node, "198.51.100.22", plan); Check(JsonNode.DeepEquals(reality["inbounds"], converted.Configuration["inbounds"]) && converted.Configuration["outbounds"]!.AsArray().Any(o => o!.Text("protocol") == "hysteria"), "Xray role conversion changed Reality input identity"); }

            var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var entry = InboundCatalog.AddInbound(model, credentials, "Shadowsocks2022");
            var scheme = ClientSchemes.New(f.Paths); scheme["Nodes"] = new JsonArray(node.DeepClone()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            var outbound = InboundCatalog.Items(model, "Outbounds").Single(); outbound["Kind"] = "Proxy"; outbound["ExpectedAddress"] = "198.51.100.22"; outbound["Source"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["Fingerprint"] = ArchiveStore.Fingerprint(node) };
            _ = InboundCatalog.Normalize(model, credentials);
            var config = InboundRendering.Configuration(f.Store, plan, model, credentials, entry);
            Check(config["outbounds"]![0]!.Text("type") == protocol && config["outbounds"]![0]!.Text("tag") == "egress" && InboundRendering.RequiresApplicationUdp(f.Store, f.Relative(plan), model, entry.Text("Id")), "Independent inbound lost selected server next hop or UDP requirement");
            plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan); var remote = new InboundTestRemote(); remote.Inner.SeedProtocols(plan); var validator = new QuicHopModelValidation(f.Store); var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: validator));
            var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json");
            OperationRequest Request() => new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "Apply", model, credentials));
            async Task<TaskRecord> Apply() { var request = Request(); return await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), default); }
            Check((await Apply()).Outcome == TaskOutcome.Completed, "QUIC outbound model transaction failed");
            var exported = InboundSources.Create(f.Store, f.Relative(plan), entry.Text("Id"), entry.Strings("UserIds")[0], "IPv4"); var oldState = ArchiveStore.ReadJson(stateFile).Text("Inbounds.RemoteHash");
            var dependentPlan = f.Plan("Dependent-" + protocol); dependentPlan.Put("Server.IPv4", JsonValue.Create("192.0.2.99")); var dependentModel = InboundCatalog.Empty(); var dependentCredentials = InboundCatalog.EmptyCredentials(); var dependent = InboundCatalog.AddInbound(dependentModel, dependentCredentials, "Shadowsocks2022"); var linked = ClientSchemes.New(f.Paths); linked["Nodes"] = new JsonArray(exported.DeepClone()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, linked.Text("Id")), linked); var linkedOutbound = InboundCatalog.Items(dependentModel, "Outbounds").Single(); linkedOutbound["Kind"] = "Proxy"; linkedOutbound["Source"] = new JsonObject { ["SchemeId"] = linked.Text("Id"), ["NodeId"] = exported.Text("Id"), ["Fingerprint"] = ArchiveStore.Fingerprint(exported) };
            _ = InboundRendering.Configuration(f.Store, dependentPlan, dependentModel, dependentCredentials, dependent);
            credentials["Users"]![entry.Strings("UserIds")[0]]!["Value"] = ServerConfigurations.RandomKey(16); validator.UdpPassed = false;
            Check((await Apply()).Outcome == TaskOutcome.Failed && ArchiveStore.ReadJson(stateFile).Text("Inbounds.RemoteHash") == oldState, "HTTPS-only acceptance committed a broken QUIC server next hop"); InboundSources.VerifyNodes(f.Store, [exported]);
            validator.UdpPassed = true; Check((await Apply()).Outcome == TaskOutcome.Completed, "QUIC server path failed after recovery");
            Refuses(() => InboundRendering.Configuration(f.Store, dependentPlan, dependentModel, dependentCredentials, dependent), "Dependent inbound accepted stale managed origin after credential rotation"); dependentCredentials.Clear();
            var reviewedRequest = Request(); var review = coordinator.Review(reviewedRequest); scheme["Nodes"]![0]!["sing_box"]!["password"] = "changed-synthetic-password"; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            await RefusesAsync(() => coordinator.ExecuteAsync(review, reviewedRequest, new InlineProgress<TaskProgress>(_ => { }), default), "Changed next-hop source survived review");
            Refuses(() => InboundRendering.Configuration(f.Store, plan, model, credentials, entry), "Stale next-hop snapshot silently followed changed source"); credentials.Clear();
        }
    }
    private sealed class QuicHopModelValidation(ArchiveStore store) : IInboundValidation
    {
        public bool UdpPassed = true;
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject model, JsonObject credentials, string[] ids, string directory, IProgress<string> progress, CancellationToken ct)
        {
            var items = new JsonArray();
            foreach (var node in InboundRendering.Nodes(store, plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy", plan, model, credentials).Where(n => ids.Contains(n.Text("InboundOrigin.InboundId"))))
            {
                var result = new JsonObject { ["Status"] = "Reachable", ["ValidatedProtocol"] = node.Text("sing_box.type") };
                if (UdpPassed) result["UdpValidation"] = new JsonObject { ["Transport"] = "UDP", ["ResponseMatched"] = true };
                items.Add(new JsonObject { ["InboundId"] = node.Text("InboundOrigin.InboundId"), ["UserId"] = node.Text("InboundOrigin.UserId"), ["Family"] = node.Text("InboundOrigin.Family"), ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "ProxyHttps", ["Result"] = result });
            }
            return Task.FromResult(new JsonObject { ["Status"] = "Passed", ["Items"] = items });
        }
    }
}
