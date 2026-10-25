using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunForwardedNodeTests()
    {
        using var fixture = new Fixture(repository); await ForwardedNodeExperience(fixture);
        Console.WriteLine($"PASS: {assertions} forwarded client source, transport, stale output and fixed-core assertions; no production connections.");
    }
    private async Task ForwardedNodeExperience(Fixture f)
    {
        var plan = f.Plan("Forwarded-clients"); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Server.IPv6", JsonValue.Create("2001:db8::10")); f.SaveInstance(plan);
        var relative = f.Relative(plan); var directory = f.Paths.Instance(relative); var stateFile = SafePath.Resolve(directory, "deployment-state.json");
        var sourceScheme = ClientSchemes.New(f.Paths);
        var preview = ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-password@192.0.2.20:443#Origin", sourceScheme, "US-West-LA Entry", "entry");
        ClientNodeImport.Apply(sourceScheme, preview); var source = sourceScheme["Nodes"]![0]!.AsObject();
        var sourceFile = ServerOutboundRouting.SchemeFile(f.Paths, sourceScheme.Text("Id")); f.Store.WriteSecret(sourceFile, sourceScheme);
        var tcp = ForwardConfig(); var rule = tcp["Rules"]![0]!.AsObject(); rule["ListenFamily"] = "DualStack";
        rule["Validation"] = new JsonObject { ["Type"] = "Proxy", ["SchemeId"] = sourceScheme.Text("Id"), ["NodeId"] = source.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(source) };
        plan["TcpForwarding"] = TcpForwarding.Normalize(tcp);
        async Task Save()
        {
            ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
            var state = ArchiveStore.ReadJson(stateFile);
            state["TcpForwarding"] = new JsonObject { ["RemoteHash"] = new string('a', 64), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(plan["TcpForwarding"]!), ["Validation"] = await new ForwardValidation("none").ValidateAsync(plan, plan["TcpForwarding"]!.AsObject(), directory, new InlineProgress<string>(_ => { }), default) };
            if (plan["UdpForwarding"] is JsonObject udp)
            {
                var result = await new ForwardValidation("none", true).ValidateAsync(plan, udp, directory, new InlineProgress<string>(_ => { }), default);
                foreach (var item in result["Items"]!.AsArray()) foreach (var check in item!["Checks"]!.AsArray())
                {
                    var validation = udp["Rules"]![0]!["Validation"]!;
                    foreach (var key in new[] { "NodeFingerprint", "ResolverAddress", "ResolverPort", "QueryName", "QueryType" }) check![key] = validation[key]!.DeepClone();
                    check!["Transport"] = "UDP";
                }
                state["UdpForwarding"] = new JsonObject { ["RemoteHash"] = new string('b', 64), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(udp), ["Validation"] = result };
            }
            else state.Remove("UdpForwarding");
            ArchiveStore.WriteJson(stateFile, state);
        }
        await Save(); var beforePlan = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "deployment-plan.json")); var beforeSource = ClientSchemes.SourceFingerprint(sourceFile);
        var unverified = ArchiveStore.ReadJson(stateFile); unverified["TcpForwarding"]!["ConfigurationFingerprint"] = new string('f', 64); ArchiveStore.WriteJson(stateFile, unverified);
        Refuses(() => ForwardedNodeSources.Create(f.Store, relative, rule.Text("Id"), "IPv4", "US-West-LA Entry"), "unverified edited rule reused a previous validation");
        await Save(); unverified = ArchiveStore.ReadJson(stateFile); unverified["TcpForwarding"]!["TemplateCurrent"] = false; ArchiveStore.WriteJson(stateFile, unverified);
        Refuses(() => ForwardedNodeSources.Create(f.Store, relative, rule.Text("Id"), "IPv4", "US-West-LA Entry"), "outdated unit template was advertised as current"); await Save();
        var choices = ForwardedNodeSources.Choices(f.Store, "US-West-LA Entry");
        Check(choices.Count == 2 && choices.All(c => c.Node != null), "dual-stack proxy rules did not yield separate client choices");
        var forwarded = choices[0].Node!;
        Check(forwarded.Text("clash.server") == plan.Text("Server.IPv4") && forwarded.Number("sing_box.server_port") == rule.Number("ListenPort"), "forward listener was not used");
        Check(forwarded.Text("clash.password") == source.Text("clash.password") && forwarded.Text("sing_box.password") == source.Text("sing_box.password"), "forwarding changed credentials");
        Check(!forwarded.Flag("clash.udp", true) && forwarded.Text("sing_box.network") == "tcp", "SS TCP-only forward silently advertised UDP");
        Check(forwarded["ManagedOrigin"] == null && forwarded["Source"] == null && forwarded["ForwardedOrigin"] != null, "forward projected stale source ownership");
        ForwardedNodeSources.VerifyNodes(f.Store, [forwarded]); Check(true, "valid source rejected");
        var altered = forwarded.DeepClone().AsObject(); altered["sing_box"]!["server_port"] = 1;
        Refuses(() => ForwardedNodeSources.VerifyNodes(f.Store, [altered]), "altered connection bypassed source validation");
        var scheme = ClientSchemes.New(f.Paths); scheme["Candidate"] = new JsonObject();
        ForwardedNodeSources.Apply(f.Store, scheme, [forwarded], "US-West-LA Entry");
        var selected = scheme["Nodes"]![0]!.AsObject(); var id = selected.Text("Id"); selected["name"] = "My forward"; selected["clash"]!["name"] = "My forward"; selected["sing_box"]!["tag"] = "My forward";
        ForwardedNodeSources.Apply(f.Store, scheme, [forwarded], "Europe Entry");
        Check(scheme["Nodes"]!.AsArray().Count == 1 && scheme["Nodes"]![0]!.Text("Id") == id && scheme["Nodes"]![0]!.Text("name") == "My forward" && scheme["Nodes"]![0]!.Text("region_group") == "US-West-LA Entry" && scheme["Candidate"] == null, "source update lost identity, grouping or candidate invalidation");
        Refuses(() => ForwardedNodeSources.Apply(f.Store, scheme, [], "Europe Entry"), "empty selection accepted");
        Refuses(() => ForwardedNodeSources.Apply(f.Store, scheme, [forwarded, forwarded], "Europe Entry"), "duplicate source accepted");
        var workbench = new ClientWorkbench(f.Store, new FakeTools(), new FakeAssets(), "unused");
        await RefusesAsync(() => workbench.BuildAsync(scheme, default), "fake builder unexpectedly succeeded");
        Check(beforePlan == ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "deployment-plan.json")) && beforeSource == ClientSchemes.SourceFingerprint(sourceFile), "adding client nodes changed source archive");
        var udp = UdpConfig(rule.Number("ListenPort")); var udpRule = udp["Rules"]![0]!.AsObject(); udpRule["ListenFamily"] = "DualStack"; udpRule["TargetPort"] = 443;
        udpRule["Validation"] = rule["Validation"]!.DeepClone(); udpRule["Validation"]!["Type"] = "Shadowsocks";
        foreach (var pair in new JsonObject { ["ResolverAddress"] = "192.0.2.53", ["ResolverPort"] = 53, ["QueryName"] = "example.test", ["QueryType"] = "A" }) udpRule["Validation"]![pair.Key] = pair.Value!.DeepClone();
        plan["UdpForwarding"] = UdpForwarding.Normalize(udp); await Save();
        var combined = ForwardedNodeSources.Create(f.Store, relative, rule.Text("Id"), "IPv4", "US-West-LA Entry");
        Check(combined.Flag("clash.udp") && combined.Text("sing_box.network") == "" && combined.Text("ForwardedOrigin.UdpRuleId") == udpRule.Text("Id"), "matching verified UDP rule not paired");
        ForwardedNodeSources.VerifyNodes(f.Store, [forwarded]); Check(true, "new UDP rule invalidated unchanged TCP-only projection");
        plan["UdpForwarding"]!["Rules"]![0]!["Enabled"] = false; await Save();
        Refuses(() => ForwardedNodeSources.VerifyNodes(f.Store, [combined]), "disabled UDP pair stayed exportable");
        ForwardedNodeSources.VerifyNodes(f.Store, [forwarded]); Check(true, "unbound UDP rule affected TCP-only client");
        plan.Remove("UdpForwarding"); plan["TcpForwarding"]!["Rules"]![0]!["ListenPort"] = 55003; await Save();
        Refuses(() => ForwardedNodeSources.VerifyNodes(f.Store, [forwarded]), "changed listener stayed exportable");
        var updated = ForwardedNodeSources.Create(f.Store, relative, rule.Text("Id"), "IPv4", "US-West-LA Entry");
        ForwardedNodeSources.Apply(f.Store, scheme, [updated], "Europe Entry");
        Check(scheme["Nodes"]![0]!.Text("Id") == id && scheme["Nodes"]![0]!.Number("sing_box.server_port") == 55003, "refresh appended duplicate instead of updating stable source");
        var candidate = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["OutputClients"] = "Both", ["SpecFingerprint"] = ArchiveStore.Fingerprint(ClientSchemes.Specification(scheme)), ["Sources"] = new JsonObject(), ["ForwardedSources"] = new JsonArray(updated["ForwardedOrigin"]!.DeepClone()), ["ValidationStatus"] = "Passed" };
        foreach (var format in new[] { "Clash", "SingBox" }) { var file = f.Paths.Resolve("forwarded-candidate/" + format + ".json"); ArchiveStore.WriteJson(file, new JsonObject()); candidate[format] = file; candidate[format + "Hash"] = ClientSchemes.SourceFingerprint(file); }
        scheme["Candidate"] = candidate;
        plan["TcpForwarding"]!["Rules"]![0]!["Enabled"] = false; await Save();
        var snapshot = ArchiveStore.Fingerprint(scheme);
        Refuses(() => workbench.PreparePublish(scheme, f.Paths.Resolve("output/a.yaml"), f.Paths.Resolve("output/a.json")), "disabled forwarding survived publish review");
        Check(snapshot == ArchiveStore.Fingerprint(scheme), "failed review changed the scheme");
        plan["TcpForwarding"]!["Rules"]![0]!["Enabled"] = true; await Save();
        source["sing_box"]!["password"] = "changed"; f.Store.WriteSecret(sourceFile, sourceScheme);
        Refuses(() => ForwardedNodeSources.VerifyNodes(f.Store, [updated]), "rotated target password stayed exportable");
        Check(ForwardedNodeSources.Choices(f.Store, "Europe Entry").All(c => c.Node == null && !c.Detail.Contains("synthetic-password")), "unavailable source was selectable or leaked credentials");
        source["sing_box"]!["password"] = source.Text("clash.password"); f.Store.WriteSecret(sourceFile, sourceScheme);
        var anyScheme = ClientSchemes.New(f.Paths); ClientNodeImport.Apply(anyScheme, ClientNodeImport.Preview("anytls://synthetic-password@192.0.2.20:443#TLS", anyScheme, "US-West-LA Entry", "entry"));
        var any = anyScheme["Nodes"]![0]!.AsObject(); any["sing_box"]!["tls"]!.AsObject().Remove("server_name"); any["clash"]!.AsObject().Remove("sni");
        any["sing_box"]!["tls"]!["ech"] = new JsonObject { ["enabled"] = true, ["config"] = new JsonArray("synthetic-ech") };
        any["clash"]!["ech-opts"] = new JsonObject { ["enable"] = true, ["config"] = "synthetic-ech" };
        f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, anyScheme.Text("Id")), anyScheme);
        plan["TcpForwarding"]!["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Proxy", ["SchemeId"] = anyScheme.Text("Id"), ["NodeId"] = any.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(any) }; await Save();
        var forwardedAny = ForwardedNodeSources.Create(f.Store, relative, rule.Text("Id"), "IPv6", "Europe Entry");
        Check(forwardedAny.Text("sing_box.tls.server_name") == "192.0.2.20" && forwardedAny.Text("clash.sni") == "192.0.2.20", "endpoint rewriting lost implicit TLS identity");
        Check(JsonNode.DeepEquals(forwardedAny.At("sing_box.tls.ech"), any.At("sing_box.tls.ech")) && forwardedAny.Text("sing_box.network") == "" && JsonNode.DeepEquals(forwardedAny.At("clash.udp"), any.At("clash.udp")), "TCP-carried AnyTLS UDP or ECH changed");
        var state = ArchiveStore.ReadJson(stateFile); state["TcpForwarding"]!["Validation"]!["Items"]![0]!["Checks"]![0]!["Address"] = "192.0.2.99"; ArchiveStore.WriteJson(stateFile, state);
        Refuses(() => ForwardedNodeSources.Create(f.Store, relative, rule.Text("Id"), "IPv4", "US-West-LA Entry"), "unverified new listener address accepted");
        await Save();
        if (Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") is { Length: > 0 } python)
        {
            plan["TcpForwarding"]!["Rules"]![0]!["Validation"] = rule["Validation"]!.DeepClone(); await Save();
            var real = ClientSchemes.New(f.Paths); ForwardedNodeSources.Apply(f.Store, real, [ForwardedNodeSources.Create(f.Store, relative, rule.Text("Id"), "IPv4", "US-West-LA Entry")], "US-West-LA Entry");
            var cores = Path.Combine(repository, "vendor/test-cores/windows-amd64");
            foreach (var file in Directory.EnumerateFiles(cores, "*", SearchOption.AllDirectories)) { var target = f.Paths.Resolve("vendor/test-cores/windows-amd64/" + Path.GetRelativePath(cores, file).Replace('\\', '/')); Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(file, target); }
            var assets = new ValidationAssets(f.Paths, "windows-amd64"); var realWorkbench = new ClientWorkbench(f.Store, new ExternalToolRunner(), assets, python);
            await realWorkbench.BuildAsync(real, default); await realWorkbench.ValidateAsync(real, default);
            Check(real.Text("Candidate.ValidationStatus") == "Passed", "real fixed clients rejected TCP-only forwarded node");
            var clash = f.Paths.Resolve("forwarded-output/clash.yaml"); var sing = f.Paths.Resolve("forwarded-output/sing.json"); realWorkbench.PreparePublish(real, clash, sing); realWorkbench.Publish(real, clash, sing);
            Check(File.Exists(clash) && File.Exists(sing), "forwarded client export did not complete");
            plan["TcpForwarding"]!["Rules"]![0]!["Enabled"] = false; await Save();
            Refuses(() => realWorkbench.Publish(real, clash, sing), "real exported candidate ignored subsequently disabled forwarding");
        }
    }
}
