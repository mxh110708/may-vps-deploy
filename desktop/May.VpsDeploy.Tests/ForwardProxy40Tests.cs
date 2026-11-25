using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunForwardProxy40Tests()
    {
        await ForwardProxy40Model(); await ForwardProxy40Workflows();
        Console.WriteLine($"PASS: {assertions} protocol-health consent, credentials, source, evidence and private transport assertions; no production connections.");
    }
    private async Task ForwardProxy40Workflows()
    {
        foreach (var udp in new[] { false, true }) foreach (var mode in new[] { "none", "apply-ack", "cancel", "validation" })
        {
            using var f = new Fixture(repository); var plan = f.Plan("Protocol40-" + udp + mode); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
            var scheme = ClientSchemes.New(f.Paths); var password = ServerConfigurations.RandomKey(16);
            var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "SS40", ["kind"] = "entry", ["region_group"] = "Example Entry", ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["server"] = "192.0.2.20", ["server_port"] = 443, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = password }, ["clash"] = new JsonObject { ["name"] = "SS40", ["type"] = "ss", ["server"] = "192.0.2.20", ["port"] = 443, ["cipher"] = "2022-blake3-aes-128-gcm", ["password"] = password, ["udp"] = true } };
            scheme["Nodes"] = new JsonArray(node); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            var config = Group36Config(udp); var rule = config["Rules"]![0]!.AsObject();
            rule["Validation"] = new JsonObject { ["Type"] = udp ? "Shadowsocks" : "Proxy", ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
            if (udp) foreach (var (key, value) in new JsonObject { ["ResolverAddress"] = "1.1.1.1", ["ResolverPort"] = 53, ["QueryName"] = "example.com", ["QueryType"] = "A" }) rule["Validation"]![key] = value!.DeepClone();
            rule["TargetGroup"]!["Health"] = ForwardProxyHealth.New(true);
            var directory = f.Paths.Instance(f.Relative(plan)); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); var source = File.ReadAllBytes(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")));
            var remote = new ForwardRemote(udp ? "udp" : "tcp") { LoseApplyAck = mode == "apply-ack" }; remote.Inner.SeedProtocols(plan); remote.Inner.ProtocolConfigs["RealityEntry"] = System.Text.Encoding.UTF8.GetBytes("synthetic existing proxy"); var validation = new Proxy40Validation(mode, udp);
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpForwarding: validation, udpForwarding: validation);
            Exception? error = null; TaskOutcome? outcome = null;
            try { outcome = await engine.ExecuteAsync(new(udp ? OperationKind.UdpForward : OperationKind.TcpForward, f.Relative(plan), udp ? UdpForwarding.Options(state, "Apply", config) : TcpForwarding.Options(state, "Apply", config)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { error = e; }
            var component = udp ? "UdpForwarding" : "TcpForwarding";
            if (mode == "none") Check(error == null && outcome == TaskOutcome.Completed && remote.GroupProbeCalls == 1, "protocol health group did not commit its explicit evidence: " + error?.Message);
            else Check(error != null && remote.ApplyCalls == 1 && remote.Configuration == null && ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"))[component] == null && ArchiveStore.ReadJson(SafePath.Resolve(directory, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack", "protocol health " + component + "/" + mode + ": applies=" + remote.ApplyCalls + " remaining=" + (remote.Configuration != null) + "; " + error?.Message + "; " + string.Join(',', remote.Inner.Commands));
            Check(remote.ApplyCalls == 1, "protocol health mutation replayed");
            Check(source.SequenceEqual(File.ReadAllBytes(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")))), "protocol health recovery overwrote its source scheme");
        }
    }
    private sealed class Proxy40Validation(string mode, bool udp) : ITcpForwardValidation, IUdpForwardValidation
    {
        public async Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject configuration, string directory, IProgress<string> progress, CancellationToken token)
        {
            var result = await new ForwardValidation(mode, udp).ValidateAsync(plan, configuration, directory, progress, token);
            if (udp) foreach (var item in result["Items"]!.AsArray()) foreach (var check in item!["Checks"]!.AsArray())
            {
                var rule = TcpForwarding.Rules(configuration).Single(r => r.Text("Id") == item.Text("Id")); check!["Transport"] = "UDP";
                foreach (var key in new[] { "NodeFingerprint", "ResolverAddress", "ResolverPort", "QueryName", "QueryType" }) check[key] = rule["Validation"]![key]!.DeepClone();
            }
            return result;
        }
    }
    private async Task ForwardProxy40Model()
    {
        using var f = new Fixture(repository); var plan = f.Plan("ProxyHealth40"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        var scheme = ClientSchemes.New(f.Paths); var password = ServerConfigurations.RandomKey(16);
        var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Synthetic SS40", ["kind"] = "entry", ["region_group"] = "Example Entry",
            ["clash"] = new JsonObject { ["name"] = "Synthetic SS40", ["type"] = "ss", ["server"] = "192.0.2.20", ["port"] = 443, ["cipher"] = "2022-blake3-aes-128-gcm", ["password"] = password, ["udp"] = true },
            ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["server"] = "192.0.2.20", ["server_port"] = 443, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = password } };
        scheme["Nodes"] = new JsonArray(node); var sourceFile = ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")); f.Store.WriteSecret(sourceFile, scheme);
        var samples = new List<JsonObject>();
        foreach (var udp in new[] { false, true })
        {
            var config = Group36Config(udp); var rule = config["Rules"]![0]!.AsObject();
            rule["Validation"] = new JsonObject { ["Type"] = udp ? "Shadowsocks" : "Proxy", ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
            if (udp) { rule["Validation"]!["ResolverAddress"] = "1.1.1.1"; rule["Validation"]!["ResolverPort"] = 53; rule["Validation"]!["QueryName"] = "example.com"; rule["Validation"]!["QueryType"] = "A"; }
            JsonObject Normalize(JsonObject value) => udp ? UdpForwarding.Normalize(value) : TcpForwarding.Normalize(value);
            rule["TargetGroup"]!["Health"] = ForwardProxyHealth.New(); Refuses(() => Normalize(config), "protocol credentials were accepted without explicit consent");
            rule["TargetGroup"]!["Health"] = ForwardProxyHealth.New(true); var normalized = Normalize(config);
            Check(normalized["Rules"]![0]!.Flag("TargetGroup.Health.Consent"), "probe authorization was lost");
            foreach (var change in new Action<JsonObject>[] { h => h["Consent"] = "true", h => h["SkipTls"] = true, h => h["EgressFamily"] = "Auto", h => h["PrimaryExit"] = "127.0.0.1", h => h["BackupExit"] = "2001:db8::1" })
            { var bad = config.DeepClone().AsObject(); change(bad["Rules"]![0]!["TargetGroup"]!["Health"]!.AsObject()); Refuses(() => Normalize(bad), "invalid proxy health permission, TLS bypass or exit was accepted"); }
            var document = ForwardProxyHealth.Document(f.Store, normalized);
            Check(document.Text("Rules." + rule.Text("Id") + ".Outbound.password") == password, "private probe material lost the source identity");
            Check(!ForwardTargetGroups.Summary(rule).Contains(password) && !config.ToJsonString().Contains(password), "a private credential entered plan/review");
            var payload = new RemoteAssets(f.Paths).Payload(udp ? "udp-forward-read.sh" : "tcp-forward-read.sh", new Dictionary<string, string> { ["PROXY_HEALTH"] = document.ToJsonString() });
            Check(payload.Contains("VPS_PARAM_PROXY_HEALTH_FILE=$(mktemp") && !payload.Contains("export VPS_PARAM_PROXY_HEALTH=\"") && !payload.Contains(password), "probe credentials entered environment/argv or clear log text");
            var hash = new string('a', 64); var proof = Group36Proof(config, hash); var result = new JsonObject { ["Items"] = new JsonArray(new JsonObject { ["Id"] = rule.Text("Id") }) };
            Refuses(() => ForwardTargetGroups.AttachProof(config, result, proof, hash, true), "TCP reachability substituted for proxy health");
            foreach (var target in proof["Groups"]![0]!["Targets"]!.AsArray()) target!["Evidence"] = new JsonObject { ["Scope"] = "ProxyHttpsEgress", ["TcpReachable"] = true, ["ProxyAuthenticated"] = true, ["HttpsVerified"] = true, ["EgressAddress"] = "198.51.100.40", ["UdpResponseMatched"] = udp };
            ForwardTargetGroups.AttachProof(config, result, proof, hash, true); Check(result["Items"]![0]!["TargetGroupHealth"] != null, "protocol health proof was discarded");
            proof["Groups"]![0]!["Targets"]![1]!["Evidence"]![udp ? "UdpResponseMatched" : "HttpsVerified"] = false;
            Refuses(() => ForwardTargetGroups.AttachProof(config, result, proof, hash, true), "missing secondary protocol proof passed");
            var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json"));
            var request = new OperationRequest(udp ? OperationKind.UdpForward : OperationKind.TcpForward, f.Relative(plan), udp ? UdpForwarding.Options(state, "Apply", config) : TcpForwarding.Options(state, "Apply", config));
            var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed))); var review = coordinator.Review(request);
            node["name"] = "source changed"; f.Store.WriteSecret(sourceFile, scheme);
            await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "credential source changed after review but was accepted");
            node["name"] = "Synthetic SS40"; f.Store.WriteSecret(sourceFile, scheme);
            samples.Add(config.DeepClone().AsObject());
        }
        samples[1]["Rules"]![0]!["ListenPort"] = samples[0]["Rules"]![0]!["ListenPort"]!.DeepClone();
        var localState = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json"));
        for (var index = 0; index < 2; index++)
        {
            var config = samples[index]; var rule = config["Rules"]![0]!.AsObject(); var hash = ArchiveStore.Fingerprint(config);
            var validation = await new ForwardValidation("none", index == 1).ValidateAsync(plan, config, "unused", new InlineProgress<string>(_ => { }), default);
            if (index == 1) foreach (var check in validation["Items"]![0]!["Checks"]!.AsArray())
            {
                check!["Transport"] = "UDP"; foreach (var key in new[] { "NodeFingerprint", "ResolverAddress", "ResolverPort", "QueryName", "QueryType" }) check[key] = rule["Validation"]![key]!.DeepClone();
            }
            var proof = Group36Proof(config, hash);
            foreach (var target in proof["Groups"]![0]!["Targets"]!.AsArray()) target!["Evidence"] = new JsonObject { ["Scope"] = "ProxyHttpsEgress", ["TcpReachable"] = true, ["ProxyAuthenticated"] = true, ["HttpsVerified"] = true, ["EgressAddress"] = "198.51.100.40", ["UdpResponseMatched"] = index == 1 };
            ForwardTargetGroups.AttachProof(config, validation, proof, hash, true);
            var component = index == 0 ? "TcpForwarding" : "UdpForwarding"; plan[component] = config.DeepClone(); localState[component] = new JsonObject { ["RemoteHash"] = hash, ["ConfigurationFingerprint"] = hash, ["Validation"] = validation };
        }
        var directory = f.Paths.Instance(f.Relative(plan)); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), localState);
        var projected = ForwardedNodeSources.Create(f.Store, f.Relative(plan), samples[0]["Rules"]![0]!.Text("Id"), "IPv4", "Example Entry", samples[1]["Rules"]![0]!.Text("Id"));
        Check(projected.Flag("clash.udp") && projected.Text("sing_box.network") != "tcp" && projected.Text("ForwardedOrigin.UdpRuleId") == samples[1]["Rules"]![0]!.Text("Id"), "matching protocol-health TCP/UDP groups could not retain UDP in their projection");
        plan["UdpForwarding"]!["Rules"]![0]!["TargetGroup"]!["BackupPort"] = 8999; ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
        Refuses(() => ForwardedNodeSources.VerifyNodes(f.Store, [projected]), "mismatched UDP standby retained old client source qualification");
    }
}
