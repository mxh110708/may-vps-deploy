using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private static string[] Xhttp35Scenarios => [.. new[] { "1.1", "2", "3" }.SelectMany(v => new[] { "auto", "stream-one", "stream-up", "packet-up" }.Select(m => "tls-" + v + "-" + m)), .. new[] { "auto", "stream-one", "stream-up", "packet-up" }.Select(m => "reality-2-" + m)];
    private static JsonObject Xhttp35Node(string scenario, int port = 24035)
    {
        var parts = scenario.Split('-', 3); var security = parts[0]; var version = parts[1]; var mode = parts[2];
        var native = new JsonObject
        {
            ["type"] = "vless", ["tag"] = "Synthetic XHTTP " + scenario, ["server"] = "192.0.2.29", ["server_port"] = port, ["uuid"] = Guid.NewGuid().ToString(), ["packet_encoding"] = "xudp",
            ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "next.example.test", ["alpn"] = new JsonArray(VlessXhttp.Alpn(version)) },
            ["transport"] = new JsonObject { ["type"] = "xhttp", ["path"] = "/next35/?keep=%2F", ["host"] = "front.example.test", ["http_version"] = version, ["mode"] = mode,
                ["extra"] = new JsonObject { ["headers"] = new JsonObject { ["X-May-Test"] = "synthetic-private-metadata" }, ["xPaddingBytes"] = "100-200", ["xmux"] = new JsonObject { ["maxConcurrency"] = "4-8", ["maxConnections"] = 0, ["cMaxReuseTimes"] = "5-10", ["hKeepAlivePeriod"] = 0 } } }
        };
        if (security == "reality")
        {
            native["tls"]!["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = "chrome" };
            native["tls"]!["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = ServerConfigurations.RandomKey(32).Replace('+', '-').Replace('/', '_').TrimEnd('='), ["short_id"] = "ab12cd34" };
        }
        return new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = native.Text("tag"), ["kind"] = "landing", ["sing_box"] = native };
    }
    public async Task RunServerXhttp35Tests(bool modelOnly = false)
    {
        await ServerXhttp35Model();
        if (!modelOnly) { await ServerStream29Runtime(xhttp: true); await Xhttp35SplitRuntime(); }
        Console.WriteLine($"PASS: {assertions} round35 XHTTP next-hop model, actual paths, evidence and recovery assertions; modelOnly={modelOnly}.");
    }
    private async Task ServerXhttp35Model()
    {
        foreach (var version in new[] { "", "26.3.26", "26.4.1" }) Refuses(() => ServerOutboundRouting.RequireXhttpVersion(version), "unreviewed XHTTP core version accepted");
        foreach (var scenario in Xhttp35Scenarios)
        {
            var node = Xhttp35Node(scenario); var fingerprint = ArchiveStore.Fingerprint(node);
            var native = ServerOutboundRouting.NextHop(node); var projection = ServerOutboundRouting.XrayNextHop(native);
            Check(ServerOutboundRouting.SupportedNode(node, "RealityEntry") && !ServerOutboundRouting.SupportedNode(node, "AnyTlsEntry") && ServerOutboundRouting.SupportedIndependentNode(node), "XHTTP core capability was guessed or relay added");
            Check(ArchiveStore.Fingerprint(node) == fingerprint && projection.Text("streamSettings.network") == "xhttp" && projection["settings"]!["vnext"]![0]!["users"]![0]!.Text("id") == node.Text("sing_box.uuid"), "XHTTP source mutated or identity lost");
            Check(JsonNode.DeepEquals(native["transport"]!["extra"], projection["streamSettings"]!["xhttpSettings"]!["extra"]), "XHTTP advanced options were stripped");
            using var f = new Fixture(repository); var plan = f.Plan("Xhttp35"); var secrets = Fixture.RealitySecrets(); var baseline = ServerConfigurations.Xray(plan, secrets);
            var extra = node.DeepClone().AsObject(); extra["Id"] = Guid.NewGuid().ToString("N"); extra["sing_box"]!["server_port"] = 24036;
            var preview = ServerOutboundRouting.Build("RealityEntry", baseline, null, node, "198.51.100.35", plan, destinationRules: new JsonArray(HopRule("Domain", "research.example.test", HopA)), additionalHops: [new(HopA, extra, "198.51.100.36")]);
            Check(!preview.Summary.Contains(native.Text("uuid")) && !preview.Summary.Contains("synthetic-private-metadata") && preview.Summary.Contains("XHTTP") && JsonNode.DeepEquals(baseline["inbounds"], preview.Configuration["inbounds"]), "XHTTP review disclosed credentials or changed ingress");
            plan.Put("ServerOutbound.RealityEntry", preview.Metadata!.DeepClone()); var paths = ServerOutboundRouting.ProbeRequests("RealityEntry", preview.Configuration, plan);
            Check(paths.Count == 2 && paths.All(p => p!.Flag("UdpRequired")), "default or classified XHTTP omitted independent UDP acceptance");
            var proof = new JsonObject { ["Status"] = "Passed", ["Items"] = new JsonArray(paths.OfType<JsonObject>().Select(p =>
            {
                var item = ServerOutboundRouting.XhttpProof(p["Outbound"]!); item["Id"] = p.Text("Id"); item["Status"] = "Passed"; item["Egress"] = p.Text("ExpectedAddress"); item["From"] = "EntryServer"; item["Network"] = "TCP"; item["UdpValidation"] = Udp34Proof(); return (JsonNode)item;
            }).ToArray()) };
            ServerOutboundRouting.RequireHopValidation(paths, proof);
            var wrong = proof.DeepClone().AsObject(); wrong["Items"]![0]!["Transport"] = "TCP"; Refuses(() => ServerOutboundRouting.RequireHopValidation(paths, wrong), "raw TCP proof qualified XHTTP");
            wrong = proof.DeepClone().AsObject(); wrong["Items"]![0]!["XhttpFingerprint"] = new string('0', 64); Refuses(() => ServerOutboundRouting.RequireHopValidation(paths, wrong), "different XHTTP transport identity qualified source");
            Check(JsonNode.DeepEquals(ServerOutboundRouting.Build("RealityEntry", preview.Configuration, preview.Metadata, null, "", plan).Configuration, baseline), "XHTTP removal did not preserve original component");
            Refuses(() => ServerOutboundRouting.Build("AnyTlsEntry", ServerConfigurations.AnyTls(plan, secrets), null, node, "198.51.100.35", plan), "sing-box accepted XHTTP next hop");
        }
        var split = Xhttp35Node("tls-2-packet-up"); var source = split["sing_box"]!.AsObject(); var down = source.DeepClone().AsObject(); down["server"] = "2001:db8::35"; down["server_port"] = 24435; down["tls"]!["server_name"] = "download.example.test"; down["tls"]!["alpn"] = new JsonArray("h3"); down["transport"]!["http_version"] = "3"; down["transport"]!["path"] = "/independent/?q=%2B"; down["transport"]!["extra"]!["headers"]!["X-Download"] = "synthetic-private-download";
        source["transport"]!["download_settings"] = new JsonObject { ["server"] = down["server"]!.DeepClone(), ["server_port"] = down["server_port"]!.DeepClone(), ["tls"] = down["tls"]!.DeepClone(), ["transport"] = down["transport"]!.DeepClone() };
        var output = ServerOutboundRouting.XrayNextHop(ServerOutboundRouting.NextHop(split)); var download = output["streamSettings"]!["xhttpSettings"]!["extra"]!["downloadSettings"]!;
        Check(download.Text("address") == "2001:db8::35" && download.Text("tlsSettings.serverName") == "download.example.test" && download.Text("xhttpSettings.path") == "/independent/?q=%2B" && download["tlsSettings"]!["alpn"]![0]!.ToString() == "h3", "independent download endpoint, SNI, path or HTTP version lost");
        var previous = ServerOutboundRouting.XhttpFingerprint(output["streamSettings"]!); output["streamSettings"]!["xhttpSettings"]!["extra"]!["downloadSettings"]!["tlsSettings"]!["serverName"] = "changed.example.test";
        Check(previous != ServerOutboundRouting.XhttpFingerprint(output["streamSettings"]!), "download identity missing from proof digest");
        foreach (var mutate in new Action<JsonObject>[] { n => n["detour"] = "other", n => n["flow"] = "xtls-rprx-vision", n => n["tls"]!["insecure"] = true, n => n["tls"]!["alpn"] = new JsonArray("h2", "http/1.1"), n => n["transport"]!["http_version"] = "auto", n => n["transport"]!["extra"]!["unknown"] = true, n => n["transport"]!["mode"] = "stream-one", n => n["transport"]!["download_settings"]!["server"] = "localhost", n => n["transport"]!["download_settings"]!["tls"]!["insecure"] = true, n => n["transport"]!["download_settings"]!["transport"]!["download_settings"] = new JsonObject(), n => n["transport"]!["download_settings"]!["unknown"] = 1 })
        { var bad = split.DeepClone().AsObject(); mutate(bad["sing_box"]!.AsObject()); Refuses(() => ServerOutboundRouting.NextHop(bad), "invalid or lossy XHTTP fields survived review"); }
        using (var own = new Fixture(repository))
        {
            var plan = own.Plan("Xhttp35Loop"); var self = split.DeepClone().AsObject(); self["sing_box"]!["transport"]!["download_settings"]!["server"] = plan.Text("Server.IPv4");
            Refuses(() => ServerOutboundRouting.Build("RealityEntry", ServerConfigurations.Xray(plan, Fixture.RealitySecrets()), null, self, "198.51.100.35", plan), "download endpoint pointed back to its entry instance");
        }
        await Xhttp35Workflows(split);
    }
    private async Task Xhttp35Workflows(JsonObject split)
    {
        using var f = new Fixture(repository); var data = RealityFixture(f, "Xhttp35Fixed", true); var state = data.State; var native = split.DeepClone().AsObject(); native["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = "198.51.100.35" }; data.Scheme["Nodes"] = new JsonArray(native); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, data.Scheme.Text("Id")), data.Scheme);
        data.Plan.Put("Reality.XrayVersion", JsonValue.Create(ServerOutboundRouting.XhttpXrayVersion)); ArchiveStore.WriteJson(SafePath.Resolve(data.Directory, "deployment-plan.json"), data.Plan);
        var remote = RoutingRemote(data); var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation()));
        var options = ServerOutboundRouting.Options(state, "RealityEntry", "Apply", data.Scheme, native, "198.51.100.35"); var operation = new OperationRequest(OperationKind.ServerOutbound, f.Relative(data.Plan), options); var reviewed = coordinator.Review(operation);
        remote.XrayVersionLine = "Xray 26.3.26 synthetic";
        Check((await coordinator.ExecuteAsync(reviewed, operation, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Failed && remote.Mutations == 0, "wrong actual Xray version mutated configuration");
        remote.XrayVersionLine = "Xray 26.3.27 synthetic"; reviewed = coordinator.Review(operation);
        var fixedResult = await coordinator.ExecuteAsync(reviewed, operation, new InlineProgress<TaskProgress>(_ => { }), default);
        Check(fixedResult.Outcome == TaskOutcome.Completed, "fixed XHTTP workflow failed: " + fixedResult.SafeError);
        var before = remote.ProtocolConfigs["RealityEntry"].ToArray(); var sibling = remote.ProtocolConfigs["AnyTlsEntry"].ToArray(); var savedState = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "deployment-state.json")); options = ServerOutboundRouting.Options(savedState, "RealityEntry", "Apply", data.Scheme, native, "198.51.100.35"); operation = new OperationRequest(OperationKind.ServerOutbound, f.Relative(data.Plan), options); remote.HopProbeFailure = true;
        Check((await coordinator.ExecuteAsync(coordinator.Review(operation), operation, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Failed && remote.ProtocolConfigs["RealityEntry"].SequenceEqual(before) && remote.ProtocolConfigs["AnyTlsEntry"].SequenceEqual(sibling), "XHTTP failed probe did not restore only selected role");
        var plan = f.Plan("Xhttp35Independent"); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
        var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, credentials, "Reality"); inbound["Options"]!["ServerName"] = "www.example.com"; inbound["Options"]!["HandshakeServer"] = "www.example.com"; var second = InboundCatalog.AddInbound(model, credentials, "Shadowsocks2022");
        inbound["Options"]!["PublicKey"] = ServerConfigurations.RandomKey(32).Replace('+', '-').Replace('/', '_').TrimEnd('='); inbound["Options"]!["ShortId"] = "ab1234cd"; credentials["Inbounds"]![inbound.Text("Id")]!["RealityPrivateKey"] = ServerConfigurations.RandomKey(32).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var resource = InboundCatalog.AddDirect(model, "XHTTP source"); resource["Kind"] = "Proxy"; resource["Source"] = new JsonObject { ["SchemeId"] = data.Scheme.Text("Id"), ["NodeId"] = native.Text("Id"), ["Fingerprint"] = ArchiveStore.Fingerprint(native) }; inbound["OutboundId"] = resource.Text("Id");
        var config = InboundRendering.Configuration(f.Store, plan, model, credentials, inbound); var request = InboundRoutingPolicy.ProbeRequest(f.Store, plan, model, credentials, inbound); var proof = Policy28Proof(request); InboundRoutingPolicy.RequirePaths(request, proof);
        var oldCore = InboundRendering.Core(f.Paths); oldCore["Reality"]!["Version"] = "26.3.26"; Refuses(() => InboundRendering.Payload(f.Store, plan, model, credentials, oldCore), "old independent Xray accepted XHTTP next hop");
        Check(request["Paths"]!.AsArray().Count == 1 && request["Paths"]![0]!["Xhttp"] is JsonObject && request["Paths"]![0]!.Flag("UdpRequired"), "unclassified XHTTP default skipped native proof");
        proof["Items"]![0]!.AsObject().Remove("Xhttp"); Refuses(() => InboundRoutingPolicy.RequirePaths(request, proof), "HTTPS-only independent evidence qualified XHTTP identity");
        second["OutboundId"] = resource.Text("Id"); Refuses(() => InboundRendering.Configuration(f.Store, plan, model, credentials, second), "sing-box consumer accepted shared XHTTP resource"); second["OutboundId"] = InboundCatalog.Items(model, "Outbounds").First().Text("Id");
        var inRemote = new InboundTestRemote(); inRemote.Inner.SeedProtocols(plan); var inCoordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, inRemote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: new QuicHopModelValidation(f.Store))); var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json");
        async Task<TaskRecord> Apply() { var r = new OperationRequest(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "Apply", model, credentials)); return await inCoordinator.ExecuteAsync(inCoordinator.Review(r), r, new InlineProgress<TaskProgress>(_ => { }), default); }
        var independentResult = await Apply(); Check(independentResult.Outcome == TaskOutcome.Completed, "independent XHTTP workflow failed: " + independentResult.SafeError); var fingerprint = ArchiveStore.Fingerprint(inRemote.Current!); inRemote.Failure = "policy-validation"; credentials["Users"]![inbound.Strings("UserIds")[0]]!["Value"] = Guid.NewGuid().ToString();
        Check((await Apply()).Outcome == TaskOutcome.Failed && ArchiveStore.Fingerprint(inRemote.Current!) == fingerprint && inRemote.LastAffected.SequenceEqual([inbound.Text("Id")]), "independent XHTTP incomplete proof changed unrelated scope");
        native["sing_box"]!["transport"]!["download_settings"]!["tls"]!["server_name"] = "changed.example.test"; data.Scheme["Nodes"] = new JsonArray(native.DeepClone()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, data.Scheme.Text("Id")), data.Scheme);
        Refuses(() => InboundRendering.Configuration(f.Store, plan, model, credentials, inbound), "download source change reused an old reference"); credentials.Clear();
        savedState = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "deployment-state.json")); options = ServerOutboundRouting.Options(savedState, "RealityEntry", "Apply", data.Scheme, native, "198.51.100.35"); operation = new OperationRequest(OperationKind.ServerOutbound, f.Relative(data.Plan), options); reviewed = coordinator.Review(operation);
        var mutations = remote.Mutations; File.AppendAllText(f.Paths.Resolve("scripts/server-xhttp.py"), "\n# synthetic reviewed-code change\n");
        await RefusesAsync(() => coordinator.ExecuteAsync(reviewed, operation, new InlineProgress<TaskProgress>(_ => { }), default), "changed XHTTP validator survived the review fingerprint");
        Check(remote.Mutations == mutations, "stale XHTTP review mutated the server");
    }
    private static JsonObject Xhttp35Landing(JsonObject native, X509Certificate2 cert, RSA key, JsonObject pair, int camouflagePort)
    {
        var t = native["transport"]!; var reality = native.Flag("tls.reality.enabled"); var security = reality ? "reality" : "tls";
        var transport = new JsonObject { ["network"] = "xhttp", ["security"] = security, ["xhttpSettings"] = new JsonObject { ["host"] = t.Text("host"), ["path"] = t.Text("path"), ["mode"] = t.Text("mode"), ["extra"] = t["extra"]!.DeepClone() } };
        transport[reality ? "realitySettings" : "tlsSettings"] = reality ? new JsonObject { ["show"] = false, ["target"] = "127.0.0.1:" + camouflagePort, ["xver"] = 0, ["serverNames"] = new JsonArray(native.Text("tls.server_name")), ["privateKey"] = pair.Text("PrivateKey"), ["shortIds"] = new JsonArray(native.Text("tls.reality.short_id")) }
            : new JsonObject { ["serverName"] = native.Text("tls.server_name"), ["minVersion"] = "1.3", ["alpn"] = native["tls"]!["alpn"]!.DeepClone(), ["certificates"] = new JsonArray(new JsonObject { ["certificate"] = new JsonArray(cert.ExportCertificatePem().Trim().Split('\n').Select(s => (JsonNode?)JsonValue.Create(s.TrimEnd('\r'))).ToArray()), ["key"] = new JsonArray(key.ExportPkcs8PrivateKeyPem().Trim().Split('\n').Select(s => (JsonNode?)JsonValue.Create(s.TrimEnd('\r'))).ToArray()) }) };
        return new JsonObject { ["log"] = new JsonObject { ["loglevel"] = "none" }, ["inbounds"] = new JsonArray(new JsonObject { ["listen"] = "127.0.0.1", ["port"] = native.Number("server_port"), ["protocol"] = "vless", ["tag"] = "source", ["settings"] = new JsonObject { ["decryption"] = "none", ["clients"] = new JsonArray(new JsonObject { ["id"] = native.Text("uuid") }) }, ["streamSettings"] = transport }), ["outbounds"] = new JsonArray(new JsonObject { ["tag"] = "direct", ["protocol"] = "freedom", ["sendThrough"] = "127.0.0.6" }) };
    }
}
