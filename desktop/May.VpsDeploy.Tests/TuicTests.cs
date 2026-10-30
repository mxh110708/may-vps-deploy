using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunTuicModelTests()
    {
        await TuicModel();
        Console.WriteLine($"PASS: {assertions} TUIC v5 model, client generation and scoped recovery assertions; synthetic only.");
    }
    public async Task RunTuicTests()
    {
        await TuicModel(); await TuicRuntime();
        Console.WriteLine($"PASS: {assertions} round 16 TUIC v5 model, native clients, application UDP and recovery assertions; synthetic only.");
    }
    private async Task TuicModel()
    {
        using var f = new Fixture(repository); var plan = f.Plan("Tuic-round16"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var sibling = InboundCatalog.AddInbound(model, credentials, "Shadowsocks2022"); var tuic = InboundCatalog.AddInbound(model, credentials, "TuicV5"); var userId = tuic.Strings("UserIds")[0];
        var pem = InboundCertificate("tuic.example.test"); var certificate = InboundCatalog.ImportCertificate(model, credentials, "TLS", pem.Certificate, pem.Key); tuic["CertificateId"] = certificate.Text("Id"); tuic["Options"]!["ServerName"] = "tuic.example.test";
        _ = InboundCatalog.Normalize(model, credentials);
        Check(InboundCatalog.UdpOnly(tuic) && InboundCatalog.UsesUdp(tuic) && InboundCatalog.UserKind(tuic) == "TuicV5" && credentials.Text("Users." + userId + ".Uuid") != credentials.Text("Users." + userId + ".Value"), "TUIC mixed its transport or identity fields");
        var second = InboundCatalog.AddUser(model, credentials, "Second", "TuicV5"); tuic["UserIds"]!.AsArray().Add(second.Text("Id"));
        var config = InboundRendering.Configuration(f.Store, plan, model, credentials, tuic); var input = config["inbounds"]![0]!;
        Check(input.Text("type") == "tuic" && input["users"]!.AsArray().Count == 2 && !input.Flag("zero_rtt_handshake") && input.Text("auth_timeout") == "3s" && input.Text("heartbeat") == "10s" && input.Strings("tls.alpn").SequenceEqual(new[] { "h3" }), "TUIC server lost its users, TLS or bounded defaults");
        var nodes = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, credentials).Where(n => n.Text("sing_box.type") == "tuic").ToArray();
        Check(nodes.Length == 2 && nodes.All(n => n.Text("sing_box.uuid") == n.Text("clash.uuid") && n.Text("sing_box.password") == n.Text("clash.password") && n.Number("clash.heartbeat-interval") == 10000 && !n.Flag("sing_box.zero_rtt_handshake") && !n.Flag("clash.reduce-rtt") && n.Text("sing_box.udp_relay_mode") == "native"), "TUIC client projection changed v5 authentication, heartbeat units or 0-RTT defaults");
        foreach (var (key, value) in new (string, JsonNode)[] { ("CongestionControl", JsonValue.Create("old")!), ("UdpRelayMode", JsonValue.Create("uot")!), ("HeartbeatSeconds", JsonValue.Create(4)!), ("HeartbeatSeconds", JsonValue.Create(121)!), ("HeartbeatSeconds", JsonValue.Create("10")!), ("AuthTimeoutSeconds", JsonValue.Create(0)!), ("AuthTimeoutSeconds", JsonValue.Create(31)!), ("Token", JsonValue.Create("synthetic-v4")!), ("ZeroRtt", JsonValue.Create(true)!) })
        {
            var invalid = model.DeepClone().AsObject(); InboundCatalog.Items(invalid, "Inbounds").Single(i => i.Text("Id") == tuic.Text("Id"))["Options"]![key] = value;
            Refuses(() => InboundCatalog.Normalize(invalid, credentials), "TUIC unsupported or unbounded option accepted");
        }
        var secret = credentials["Users"]![userId]!.AsObject(); var uuid = secret.Text("Uuid"); var password = secret.Text("Value");
        secret["Uuid"] = "invalid"; Refuses(() => InboundCatalog.Normalize(model, credentials), "Invalid TUIC UUID accepted"); secret["Uuid"] = uuid; secret["Value"] = "short"; Refuses(() => InboundCatalog.Normalize(model, credentials), "Weak TUIC password accepted"); secret["Value"] = password;
        var secondUuid = credentials.Text("Users." + second.Text("Id") + ".Uuid"); credentials["Users"]![second.Text("Id")]!["Uuid"] = uuid; Refuses(() => InboundCatalog.Normalize(model, credentials), "Duplicate TUIC UUIDs bound in one service"); credentials["Users"]![second.Text("Id")]!["Uuid"] = secondUuid;
        var remote = new InboundTestRemote(); remote.Inner.SeedProtocols(plan); var validation = new TuicMockValidation(f.Store); var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: validation));
        var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json");
        OperationRequest Operation() => new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "Apply", model, credentials));
        async Task<TaskRecord> Apply() { var request = Operation(); return await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), default); }
        Check((await Apply()).Outcome == TaskOutcome.Completed, "TUIC managed apply failed");
        var node = InboundSources.Create(f.Store, f.Relative(plan), tuic.Text("Id"), userId, "IPv4");
        var evidence = await validation.ValidateAsync(plan, model, credentials, [tuic.Text("Id")], f.Root, new InlineProgress<string>(_ => { }), default); evidence["Items"]![0]!["Result"]!.AsObject().Remove("UdpValidation");
        Refuses(() => InboundSources.RequireValidation(f.Store, plan, model, credentials, [tuic.Text("Id")], evidence), "HTTPS alone substituted for TUIC application UDP");
        tuic["Options"]!["UdpRelayMode"] = "quic"; validation.UdpPassed = false;
        Check((await Apply()).Outcome == TaskOutcome.Failed, "Missing TUIC UDP evidence committed a change"); InboundSources.VerifyNodes(f.Store, [node]);
        validation.UdpPassed = true; Check((await Apply()).Outcome == TaskOutcome.Completed, "TUIC relay change failed"); Refuses(() => InboundSources.VerifyNodes(f.Store, [node]), "TUIC changed relay mode retained stale source evidence");
        node = InboundSources.Create(f.Store, f.Relative(plan), tuic.Text("Id"), userId, "IPv4"); secret["Value"] = ServerConfigurations.RandomKey(32); Check((await Apply()).Outcome == TaskOutcome.Completed, "TUIC password rotation failed"); Refuses(() => InboundSources.VerifyNodes(f.Store, [node]), "TUIC password rotation retained stale export source");
        tuic["Enabled"] = false; Check((await Apply()).Outcome == TaskOutcome.Completed, "TUIC disable failed"); Refuses(() => InboundSources.Create(f.Store, f.Relative(plan), tuic.Text("Id"), userId, "IPv4"), "Disabled TUIC remained exportable"); tuic["Enabled"] = true; Check((await Apply()).Outcome == TaskOutcome.Completed, "TUIC re-enable failed");
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64");
        if (OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") is {} python)
        {
            var scheme = ClientSchemes.New(f.Paths); ForwardedNodeSources.Apply(f.Store, scheme, [InboundSources.Create(f.Store, f.Relative(plan), tuic.Text("Id"), userId, "IPv4")], "US-West-LA Entry"); var workbench = new ClientWorkbench(f.Store, new ExternalToolRunner(), assets, python);
            await workbench.BuildAsync(scheme, default); await workbench.ValidateAsync(scheme, default); Check(scheme.Text("Candidate.ValidationStatus") == "Passed", "TUIC full dual-client candidates did not pass actual fixed cores");
        }
        var source = ClientSchemes.New(f.Paths); source["Nodes"] = new JsonArray(node.DeepClone()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, source.Text("Id")), source);
        var rule = new JsonObject { ["Validation"] = new JsonObject { ["SchemeId"] = source.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) } };
        Refuses(() => TcpForwarding.ProxyNode(f.Store, rule), "TCP forwarding accepted TUIC");
        var oldCore = ArchiveStore.ReadJson(stateFile)["Inbounds"]!["Core"]!.DeepClone(); var versions = f.Versions;
        versions.Put("sing_box.version", JsonValue.Create("1.14.3")); versions.Put("sing_box.assets.amd64.name", JsonValue.Create("sing-box-1.14.3-linux-amd64.tar.gz")); versions.Put("sing_box.assets.amd64.sha256", JsonValue.Create(new string('f', 64))); ArchiveStore.WriteJson(f.Paths.Resolve("config/versions.json"), versions);
        OperationRequest Upgrade() => new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "UpgradeSingBox", model, credentials));
        var preview = InboundCatalog.Prepare(f.Store, Upgrade()); Check(preview.Affected.Contains(tuic.Text("Id")) && preview.Affected.Contains(sibling.Text("Id")) && JsonNode.DeepEquals(preview.Payload["Core"]!["Reality"], oldCore["Reality"]), "Shared core upgrade missed TUIC or changed the Xray pin");
        validation.UdpPassed = false; var upgrade = Upgrade(); Check((await coordinator.ExecuteAsync(coordinator.Review(upgrade), upgrade, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Failed && JsonNode.DeepEquals(ArchiveStore.ReadJson(stateFile)["Inbounds"]!["Core"], oldCore), "TUIC upgrade without UDP proof did not restore its previous core pin");
        validation.UdpPassed = true; upgrade = Upgrade(); Check((await coordinator.ExecuteAsync(coordinator.Review(upgrade), upgrade, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Completed && ArchiveStore.ReadJson(stateFile).Text("Inbounds.Core.Version") == "1.14.3", "TUIC explicit shared-core upgrade failed");
        credentials.Clear();
    }
    private sealed class TuicMockValidation(ArchiveStore store) : IInboundValidation
    {
        public bool UdpPassed { get; set; } = true;
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject model, JsonObject credentials, string[] ids, string directory, IProgress<string> progress, CancellationToken ct)
        {
            var items = new JsonArray();
            foreach (var node in InboundRendering.Nodes(store, plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy", plan, model, credentials).Where(n => ids.Contains(n.Text("InboundOrigin.InboundId"))))
            {
                var result = new JsonObject { ["Status"] = "Reachable", ["ValidatedProtocol"] = node.Text("sing_box.type") };
                if (node.Text("sing_box.type") == "tuic" && UdpPassed) result["UdpValidation"] = new JsonObject { ["Transport"] = "UDP", ["ResponseMatched"] = true };
                items.Add(new JsonObject { ["InboundId"] = node.Text("InboundOrigin.InboundId"), ["UserId"] = node.Text("InboundOrigin.UserId"), ["Family"] = node.Text("InboundOrigin.Family"), ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "ProxyHttps", ["Result"] = result });
            }
            return Task.FromResult(new JsonObject { ["Status"] = "Passed", ["Items"] = items });
        }
    }
}
