using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunHysteria15Tests()
    {
        HysteriaLinks15();
        await HysteriaHoppingModel15();
        await HysteriaHoppingRuntime15();
        Console.WriteLine($"PASS: {assertions} round 15 sharing, bounded hopping, dual-client runtime and recovery assertions; synthetic only.");
    }
    private void HysteriaLinks15()
    {
        using var f = new Fixture(repository);
        var scheme = ClientSchemes.New(f.Paths); var region = scheme["Layout"]!.Strings("region_groups")[0];
        var secret = "synthetic:user@p#%/+? 中文";
        var inputs = new[] {
            "hy2://"+Uri.EscapeDataString(secret)+"@example.test/?sni=hysteria.example.test#Default",
            "hysteria2://"+Uri.EscapeDataString(secret)+"@[2001:db8::20]:22002,22000-22001/?sni=hysteria.example.test&obfs=salamander&obfs-password="+Uri.EscapeDataString("synthetic:obfs@+#")+"#%E4%B8%AD%E6%96%87",
            "hysteria2://synthetic-auth@example.test:20000-50000/?sni=hysteria.example.test#Compact"
        };
        var preview = ClientNodeImport.Preview(string.Join('\n', inputs), scheme, region, "entry");
        Check(preview.Accepted == 3 && !string.Join('\n', preview.Rows).Contains(secret), "Hysteria URI preview rejected valid authority or disclosed credentials");
        ClientNodeImport.Apply(scheme, preview); var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        Check(nodes[0].Number("sing_box.server_port") == 443 && nodes[0].Text("sing_box.password") == secret && nodes[1].Number("sing_box.server_port") == 22002 && nodes[1].Text("clash.ports") == "22000-22002" && nodes[2]["sing_box"]!["server_ports"]!.AsArray().Count == 1, "Hysteria authority, password or compact port range changed");
        var share = ClientShareLinks.Preview(scheme); Check(share.Ready && share.Rows.All(r => r.Ready), "Hysteria sharing preview failed: " + string.Join(';', share.Rows.Select(r => r.Message)));
        var plain = ClientShareLinks.Generate(scheme, share, share.Rows.Select(r => r.Id).ToArray(), "Plain");
        Check(plain.StartsWith("hysteria2://") && plain.Contains("@[2001:db8::20]:22002,22000-22001/") && !plain.Contains(secret), "Hysteria standard URI lost primary port or percent encoding");
        var fresh = ClientSchemes.New(f.Paths); var restored = ClientNodeImport.Preview(plain, fresh, region, "entry");
        Check(restored.Accepted == nodes.Length && nodes.Zip(restored.Rows).All(pair => ClientNodeImport.ConnectionFingerprint(pair.First) == ClientNodeImport.ConnectionFingerprint(pair.Second.Node!)), "Hysteria sharing round trip changed connection parameters");
        var encoded = ClientShareLinks.Generate(scheme, share, share.Rows.Select(r => r.Id).ToArray(), "Base64");
        Check(ClientSubscriptions.Decode(encoded).Trim() == plain.Trim(), "Hysteria Base64 subscription changed content");
        foreach (var text in new[] {
            "hy2://auth@example.test:0", "hy2://auth@example.test:65536", "hy2://auth@example.test:22002-22000", "hy2://auth@example.test:1,,2",
            "hy2://auth@example.test:443/path", "hy2://auth@example.test:443?sni=one.test&sni=two.test", "hy2://auth@example.test:443?insecure=1",
            "hy2://auth@example.test:443?obfs=gecko", "hy2://auth@example.test:443?obfs=salamander", "hy2://auth@example.test:443?obfs-password=synthetic",
            "hy2://auth@example.test:443?pinSHA256=synthetic", "hy2://auth@example.test:443?ech=synthetic", "hy2://auth@example.test:443?hopInterval=7", "hy2://auth@example.test:443?mport=1-2",
            "hy2://auth@example.test:443?sni=%0Asecret", "hy2://@example.test:443", "hy2://auth@[::1:443" })
        {
            var rejected = ClientNodeImport.Preview(text, fresh, region, "entry");
            Check(rejected.Accepted == 0 && rejected.Rows.Count == 1 && !rejected.Rows[0].Message.Contains("auth@"), "Malformed or unsupported Hysteria URI accepted or leaked");
        }
        void Block(Action<JsonObject> edit)
        {
            var candidate = ClientSchemes.New(f.Paths); var node = nodes[1].DeepClone().AsObject(); edit(node); candidate["Nodes"] = new JsonArray(node);
            var result = ClientShareLinks.Preview(candidate); Check(!result.Ready && !result.Rows[0].Ready && !result.Rows[0].Message.Contains(secret), "Hysteria advanced option was silently discarded");
        }
        Block(n => n["sing_box"]!["hop_interval"] = "5s"); Block(n => n["clash"]!["hop-interval"] = 5);
        Block(n => n["sing_box"]!["up_mbps"] = 12); Block(n => n["clash"]!["up"] = "12 Mbps");
        Block(n => n["sing_box"]!["tls"]!["insecure"] = true); Block(n => n["clash"]!["skip-cert-verify"] = true);
        Block(n => n["sing_box"]!["tls"]!["certificate"] = new JsonArray("synthetic private trust"));
        Block(n => n["sing_box"]!["hop_interval_max"] = "40s"); Block(n => n["sing_box"]!["quic"] = new JsonObject());
        Block(n => n["clash"]!["ports"] = "22000-22003"); Block(n => n["sing_box"]!["password"] = "other-synthetic-user");
        var standalone = ClientSchemes.New(f.Paths); standalone["Nodes"] = new JsonArray(nodes[1].DeepClone()); standalone["Nodes"]![0]!.AsObject().Remove("sing_box");
        Check(ClientShareLinks.Preview(standalone).Ready, "Clash-only Hysteria node could not be shared");
        Refuses(() => Hysteria2Ports.Expand("1-65535"), "Managed port expansion was unbounded");
        Check(Hysteria2Ports.Normalize("22002,22000-22001,22001") == "22000-22002", "Hysteria overlapping ranges did not normalize");
    }
    private async Task HysteriaHoppingModel15()
    {
        using var f = new Fixture(repository); var plan = f.Plan("Hysteria-hopping"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, secrets, "Hysteria2");
        var pem = InboundCertificate("hysteria.example.test"); var certificate = InboundCatalog.ImportCertificate(model, secrets, "TLS", pem.Certificate, pem.Key); inbound["CertificateId"] = certificate.Text("Id"); inbound["Options"]!["ServerName"] = "hysteria.example.test";
        var before = ArchiveStore.Fingerprint(model); _ = InboundCatalog.Normalize(model, secrets);
        Check(ArchiveStore.Fingerprint(model) == before && !inbound["Options"]!.AsObject().ContainsKey("HopPorts"), "Ordinary Hysteria model was rewritten by hopping defaults");
        var configuration = ArchiveStore.Fingerprint(InboundRendering.Configuration(f.Store, plan, model, secrets, inbound)); var identity = InboundRendering.BindingFingerprint(plan, model, secrets, inbound, f.Store);
        inbound["Options"]!["HopPorts"] = "22000-22002"; inbound["Options"]!["HopIntervalSeconds"] = 30;
        var normalized = InboundCatalog.Normalize(model, secrets);
        Check(Hysteria2Ports.ListenerPorts(inbound).Length == 3 && ArchiveStore.Fingerprint(InboundRendering.Configuration(f.Store, plan, model, secrets, inbound)) == configuration && InboundRendering.BindingFingerprint(plan, model, secrets, inbound, f.Store) != identity, "Hopping added a service listener or failed to invalidate client identity");
        var node = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).Single();
        Check(node.Text("clash.ports") == "22000-22002" && node.Number("clash.hop-interval") == 30 && node.Text("sing_box.hop_interval") == "30s", "Hopping parameters diverged across clients");
        var portEvidence = new JsonObject { ["HopPorts"] = new JsonArray(22000, 22001, 22002) };
        Check(Hysteria2Ports.ValidationMatches(node, portEvidence), "Complete port evidence was rejected");
        foreach (var bad in new[] { new JsonArray(22000), new JsonArray(22000, 22000, 22002), new JsonArray(22000, 22001, 22003), new JsonArray("22000", "22001", "22002") })
        {
            portEvidence["HopPorts"] = bad; Check(!Hysteria2Ports.ValidationMatches(node, portEvidence), "Missing, duplicate, wrong or untyped port evidence was accepted");
        }
        plan["InboundModel"] = model.DeepClone(); var redirects = Hysteria2Ports.Redirects(plan);
        Check(redirects.Count == 1 && redirects[0]!["Ports"]!.AsArray().Count == 3, "Managed hopping firewall plan was incomplete");
        inbound["Enabled"] = false; plan["InboundModel"] = model.DeepClone(); Check(Hysteria2Ports.Redirects(plan).Count == 0 && Hysteria2Ports.ListenerPorts(inbound).Length == 3, "Disabled hopping still redirected or released reservations"); inbound["Enabled"] = true;
        foreach (var (key, value) in new (string, JsonNode)[] { ("HopPorts", JsonValue.Create("22001-22003")!), ("HopPorts", JsonValue.Create("22000-23000")!), ("HopPorts", JsonValue.Create("22000")!), ("HopIntervalSeconds", JsonValue.Create(4)!), ("HopIntervalSeconds", JsonValue.Create(3601)!) })
        {
            var bad = model.DeepClone().AsObject(); bad["Inbounds"]![0]!["Options"]![key] = value.DeepClone(); Refuses(() => InboundCatalog.Normalize(bad, secrets), "Invalid managed hopping option accepted");
        }
        var sibling = InboundCatalog.AddInbound(model, secrets, "Shadowsocks2022"); Check(sibling.Number("Listener.Port") == 22003, "New inbound occupied a reserved hopping port"); sibling["Listener"]!["Port"] = 22001;
        Refuses(() => InboundCatalog.Normalize(model, secrets), "Hopping overlapped another inbound"); InboundCatalog.RemoveEntity(model, secrets, "Inbounds", sibling.Text("Id"));
        var conflict = plan.DeepClone().AsObject(); conflict.Put("Ports.SshPrimary", JsonValue.Create(22002)); Refuses(() => InboundRendering.ValidatePorts(conflict, new JsonObject(), model), "Hopping overlapped management SSH");
        var user = InboundCatalog.AddUser(model, secrets, "Second", "Password"); inbound["UserIds"]!.AsArray().Add(user.Text("Id")); inbound["Listener"]!["Address"] = "::"; var previousIpv6 = plan.Text("Server.IPv6"); plan.Put("Server.IPv6", JsonValue.Create("2001:db8::10"));
        var diagnostic = new HoppingProbe15(); var actualValidation = new InboundValidation(f.Store, diagnostic);
        var evidence = await actualValidation.ValidateAsync(plan, model, secrets, [inbound.Text("Id")], f.Root, new InlineProgress<string>(_ => { }), default);
        InboundSources.RequireValidation(f.Store, plan, model, secrets, [inbound.Text("Id")], evidence);
        Check(evidence["Items"]!.AsArray().Count == 4 && diagnostic.Calls.Count == 8 && diagnostic.Calls.All(c => c["server_ports"] == null) && diagnostic.Calls.Count(c => c.Number("server_port") == 22000) == 4, "Port validation skipped a user/family, randomized port selection or repeated the shared port proof");
        diagnostic.Blocked = 22002;
        var incomplete = await actualValidation.ValidateAsync(plan, model, secrets, [inbound.Text("Id")], f.Root, new InlineProgress<string>(_ => { }), default);
        Refuses(() => InboundSources.RequireValidation(f.Store, plan, model, secrets, [inbound.Text("Id")], incomplete), "A blocked alias was replaced by a successful primary or another family");
        using (var cancelled = new CancellationTokenSource())
        {
            cancelled.Cancel(); var observed = false; try { await actualValidation.ValidateAsync(plan, model, secrets, [inbound.Text("Id")], f.Root, new InlineProgress<string>(_ => { }), cancelled.Token); } catch (OperationCanceledException) { observed = true; }
            Check(observed, "Port validation ignored caller cancellation");
        }
        inbound["Listener"]!["Address"] = "0.0.0.0"; inbound["UserIds"]!.AsArray().RemoveAt(1); InboundCatalog.RemoveEntity(model, secrets, "Users", user.Text("Id")); plan.Put("Server.IPv6", JsonValue.Create(previousIpv6));
        plan.Remove("InboundModel"); f.SaveInstance(plan); var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json");
        var remote = new InboundTestRemote(); remote.Inner.SeedProtocols(plan); var validator = new HysteriaMockValidation(f.Store); var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: validator));
        OperationRequest Operation() => new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "Apply", model, secrets));
        var applied = await coordinator.ExecuteAsync(coordinator.Review(Operation()), Operation(), new InlineProgress<TaskProgress>(_ => { }), default);
        Check(applied.Outcome == TaskOutcome.Completed, "Hopping model transaction failed: " + applied.SafeError);
        var selected = InboundSources.Create(f.Store, f.Relative(plan), inbound.Text("Id"), inbound.Strings("UserIds")[0], "IPv4");
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner();
        if (OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") is {} python)
        {
            var scheme = ClientSchemes.New(f.Paths); ForwardedNodeSources.Apply(f.Store, scheme, [selected], "US-West-LA Entry"); var workbench = new ClientWorkbench(f.Store, tools, assets, python);
            await workbench.BuildAsync(scheme, default); await workbench.ValidateAsync(scheme, default); Check(scheme.Text("Candidate.ValidationStatus") == "Passed", "Both real client cores rejected hopping candidates");
        }
        inbound["Options"]!["HopPorts"] = "22000-22003"; validator.Typed = false;
        var failed = await coordinator.ExecuteAsync(coordinator.Review(Operation()), Operation(), new InlineProgress<TaskProgress>(_ => { }), default);
        Check(failed.Outcome == TaskOutcome.Failed && ArchiveStore.ReadJson(stateFile).Text("Inbounds.LastCheck") != "Failed", "Hopping failure did not restore original model transaction");
        InboundSources.VerifyNodes(f.Store, [selected]); validator.Typed = true;
        Check((await coordinator.ExecuteAsync(coordinator.Review(Operation()), Operation(), new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Completed, "Hopping edit failed");
        Refuses(() => InboundSources.VerifyNodes(f.Store, [selected]), "Changed hopping source retained an obsolete client identity");
        var preserved = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-plan.json")); preserved.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-plan.json"), preserved);
        Refuses(() => coordinator.Review(Operation()), "Hopping implicitly took over an unmanaged firewall"); secrets.Clear();
    }
    private sealed class HoppingProbe15 : IClientRouteDiagnostics
    {
        public List<JsonObject> Calls { get; } = [];
        public int Blocked { get; set; }
        public Task<JsonObject> RunAsync(ClientDiagnosticRoute route, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); var native = route.Entry["sing_box"]!.AsObject(); Calls.Add(native.DeepClone().AsObject());
            return Task.FromResult(new JsonObject { ["Status"] = native.Number("server_port") == Blocked ? "Failed" : "Reachable", ["ValidatedProtocol"] = "hysteria2" });
        }
    }
}
