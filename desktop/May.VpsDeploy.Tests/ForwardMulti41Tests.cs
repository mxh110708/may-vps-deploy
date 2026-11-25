using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunForwardMulti41Tests()
    {
        await ForwardMulti41Model(); await ForwardMulti41Workflows();
        Console.WriteLine($"PASS: {assertions} multi-target identity, policy, evidence, review and scoped recovery assertions; no production connections.");
    }
    private static JsonObject Multi41Config(bool udp = false, string strategy = "RoundRobin", int count = 3)
    {
        var config = Group36Config(udp); var rule = config["Rules"]![0]!.AsObject(); var group = ForwardTargetGroups.NewBalanced(rule, strategy);
        group["AdditionalTargets"] = new JsonArray(Enumerable.Range(1, count - 1).Select(i => (JsonNode?)new JsonObject { ["Id"] = i.ToString("x32"), ["Address"] = i % 2 == 0 ? "2001:db8::" + (20 + i) : "192.0.2." + (20 + i), ["Port"] = 8443 }).ToArray());
        rule["TargetGroup"] = group; return config;
    }
    private static JsonObject Multi41Proof(JsonObject config, string hash, params bool[] health)
    {
        var proof = Group36Proof(config, hash);
        foreach (var group in proof["Groups"]!.AsArray())
        {
            var rule = TcpForwarding.Rules(config).Single(r => r.Text("Id") == group.Text("RuleId"));
            foreach (var (check, index) in group!["Targets"]!.AsArray().Select((c, i) => (c!, i))) { check["TargetId"] = ForwardTargetGroups.TargetIds(rule).ElementAt(index); if (health.Length > 0) check["Passed"] = health[index]; }
        }
        return proof;
    }
    private async Task ForwardMulti41Model()
    {
        using var f = new Fixture(repository); var plan = f.Plan("Multi41"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        foreach (var udp in new[] { false, true }) foreach (var strategy in new[] { "RoundRobin", "SourceIpHash" })
        {
            JsonObject Normalize(JsonObject value) => udp ? UdpForwarding.Normalize(value) : TcpForwarding.Normalize(value);
            var config = Normalize(Multi41Config(udp, strategy)); var rule = config["Rules"]![0]!.AsObject();
            Check(JsonNode.DeepEquals(config, Normalize(config)) && ForwardTargetGroups.Targets(rule).Count() == 3 && ForwardTargetGroups.TargetIds(rule).Distinct().Count() == 3, "normalization changed fixed multi-target identity");
            Check(ForwardTargetGroups.Summary(rule).Contains(strategy == "RoundRobin" ? "轮询" : "来源 IP 哈希") && ForwardTargetGroups.Summary(rule).Contains("2001:db8"), "review omitted policy or additional target");
            Check(ForwardTargetGroups.Targets(Normalize(Multi41Config(udp, strategy, 8))["Rules"]![0]!.AsObject()).Count() == 8, "eight-target boundary lost");
            Refuses(() => Normalize(Multi41Config(udp, strategy, 9)), "unbounded targets accepted");
            foreach (var edit in new Action<JsonObject>[] {
                g => g["Strategy"] = "Weighted", g => g["Weight"] = 2, g => g["AdditionalTargets"] = new JsonArray(),
                g => g["TimeoutSeconds"] = 11, g => { g["IntervalSeconds"] = 5; g["TimeoutSeconds"] = 2; },
                g => g["AdditionalTargets"]![0]!["Id"] = rule.Text("Id"), g => g["AdditionalTargets"]![1]!["Id"] = g["AdditionalTargets"]![0]!["Id"]!.DeepClone(),
                g => g["AdditionalTargets"]![0]!["Address"] = "0.0.0.0", g => g["AdditionalTargets"]![0]!["Address"] = "::ffff:192.0.2.20",
                g => g["AdditionalTargets"]![0]!["Port"] = true, g => { g["AdditionalTargets"]![0]!["Address"] = rule.Text("TargetAddress"); g["AdditionalTargets"]![0]!["Port"] = rule.Number("TargetPort"); }
            }) { var bad = config.DeepClone().AsObject(); edit(bad["Rules"]![0]!["TargetGroup"]!.AsObject()); Refuses(() => Normalize(bad), "invalid multi-target configuration accepted"); }
            var loop = config.DeepClone().AsObject(); loop["Rules"]![0]!["TargetGroup"]!["AdditionalTargets"]![1]!["Address"] = plan.Text("Server.IPv4"); loop["Rules"]![0]!["TargetGroup"]!["AdditionalTargets"]![1]!["Port"] = rule.Number("ListenPort");
            Refuses(() => ForwardTargetGroups.ValidateLoops(plan, loop), "third target bypassed self-loop protection");
            var result = await new ForwardValidation("none", udp).ValidateAsync(plan, config, f.Root, new InlineProgress<string>(_ => { }), default); var hash = new string('a', 64);
            ForwardTargetGroups.AttachProof(config, result, Multi41Proof(config, hash), hash, true); ForwardTargetGroups.RequireProof(rule, result["Items"]![0]!.AsObject());
            Refuses(() => ForwardTargetGroups.AttachProof(config, result, Multi41Proof(config, hash, true, true, false), hash, true), "save accepted unqualified third target");
            ForwardTargetGroups.AttachProof(config, result, Multi41Proof(config, hash, false, false, true), hash, false);
            foreach (var edit in new Action<JsonObject>[] { p => p["Targets"]![2]!["TargetId"] = new string('f', 32), p => p["Targets"]![2]!["Port"] = 1, p => p["Targets"]!.AsArray().RemoveAt(2), p => p["RuleFingerprint"] = new string('f', 64) })
            { var bad = Multi41Proof(config, hash); edit(bad["Groups"]![0]!.AsObject()); Refuses(() => ForwardTargetGroups.AttachProof(config, result, bad, hash, false), "mismatched multi-target proof accepted"); }
            Refuses(() => ForwardTargetGroups.AttachProof(config, result, Multi41Proof(config, hash, false, false, false), hash, false), "unavailable multi-target group accepted");
            var proxy = config.DeepClone().AsObject(); var pRule = proxy["Rules"]![0]!.AsObject(); pRule["Validation"] = new JsonObject { ["Type"] = udp ? "Shadowsocks" : "Proxy", ["SchemeId"] = new string('c',32), ["NodeId"] = new string('d',32), ["NodeFingerprint"] = new string('e',64) };
            if (udp) foreach (var (key, value) in new JsonObject { ["ResolverAddress"] = "192.0.2.53", ["ResolverPort"] = 53, ["QueryName"] = "example.test", ["QueryType"] = "A" }) pRule["Validation"]![key] = value!.DeepClone();
            pRule["TargetGroup"]!["Health"] = ForwardProxyHealth.NewBalanced(pRule, true);
            Check(Normalize(proxy)["Rules"]![0].Text("TargetGroup.Health.Type") == "Proxy", "multi-target proxy consent lost");
            var identities = ForwardTargetGroups.TargetIds(pRule).ToArray(); pRule["TargetGroup"]!["Health"]!["ExpectedExits"]![identities[2]] = "198.51.100.82";
            Check(ForwardTargetGroups.ExpectedExit(pRule, 2) == "198.51.100.82", "exit expectation did not bind target identity");
            var duplicate = ForwardTargetGroups.CopyRule(pRule);
            Check(duplicate.Text("Id") != pRule.Text("Id") && !duplicate["TargetGroup"]!["Health"]!["ExpectedExits"]!.AsObject().ContainsKey(pRule.Text("Id")) && ForwardTargetGroups.ExpectedExit(duplicate, 2) == "198.51.100.82", "copy retained old primary identity or changed per-target exit");
            var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
            if (python != null)
            {
                const string program = "import importlib.util,json,sys;s=importlib.util.spec_from_file_location('forwarding',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);v=m.normalize(json.load(sys.stdin));print(json.dumps(dict(Configuration=v,Fingerprint=m.group_fingerprint(v['Rules'][0]))))";
                var cross = await new ExternalToolRunner().RunAsync(python, ["-c", program, Path.Combine(repository, "scripts", udp ? "udp-forwarding.py" : "tcp-forwarding.py")], proxy.ToJsonString(), TimeSpan.FromSeconds(15), default);
                Check(cross.ExitCode == 0, "Python multi-target normalizer failed");
                var normalized = JsonNode.Parse(cross.Output)!;
                Check(JsonNode.DeepEquals(Normalize(proxy), normalized["Configuration"]) && normalized.Text("Fingerprint") == ForwardTargetGroups.Fingerprint(pRule), "C#/Python multi-target normalization or fixed identity differs");
            }
            else Console.WriteLine("SKIP: MAY_TEST_PYTHON required for cross-language multi-target validation.");
            InstanceAddressChanges.Rewrite(proxy, new JsonObject { ["198.51.100.82"] = "198.51.100.83", ["2001:db8::22"] = "2001:db8::23" });
            Check(ForwardTargetGroups.ExpectedExit(pRule, 2) == "198.51.100.83" && pRule["TargetGroup"]!["AdditionalTargets"]![1].Text("Address") == "2001:db8::23", "address replacement missed additional target or expected exit");
            pRule["TargetGroup"]!["Health"]!["ExpectedExits"]!.AsObject().Remove(identities[2]); Refuses(() => Normalize(proxy), "missing fixed-target exit identity accepted");
        }
        var relative = f.Relative(plan); var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(relative), "deployment-state.json")); var request = new OperationRequest(OperationKind.TcpForward, relative, TcpForwarding.Options(state, "Apply", Multi41Config()));
        var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed))); var review = coordinator.Review(request);
        foreach (var edit in new Action<JsonObject>[] { o => o["Configuration"]!["Rules"]![0]!["TargetGroup"]!["Strategy"] = "SourceIpHash", o => o["Configuration"]!["Rules"]![0]!["TargetGroup"]!["AdditionalTargets"]![1]!["Id"] = new string('f',32) })
        { var options = request.Options.DeepClone().AsObject(); edit(options); await RefusesAsync(() => coordinator.ExecuteAsync(review, request with { Options = options }, new InlineProgress<TaskProgress>(_ => { }), default), "post-review strategy/target identity changed"); }
        var scheme = ClientSchemes.New(f.Paths); var password = ServerConfigurations.RandomKey(16);
        var source = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Synthetic multi41 SS", ["kind"] = "entry", ["region_group"] = "Example Entry",
            ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["server"] = "192.0.2.20", ["server_port"] = 443, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = password },
            ["clash"] = new JsonObject { ["name"] = "Synthetic multi41 SS", ["type"] = "ss", ["server"] = "192.0.2.20", ["port"] = 443, ["cipher"] = "2022-blake3-aes-128-gcm", ["password"] = password, ["udp"] = true },
            ["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = "198.51.100.40" } };
        scheme["Nodes"] = new JsonArray(source); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        foreach (var udp in new[] { false, true })
        {
            var config = Multi41Config(udp); var rule = config["Rules"]![0]!.AsObject(); rule["TargetAddress"] = "192.0.2.20"; rule["TargetPort"] = 443;
            rule["Validation"] = new JsonObject { ["Type"] = udp ? "Shadowsocks" : "Proxy", ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = source.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(source) };
            if (udp) foreach (var (key, value) in new JsonObject { ["ResolverAddress"] = "192.0.2.53", ["ResolverPort"] = 53, ["QueryName"] = "example.test", ["QueryType"] = "A" }) rule["Validation"]![key] = value!.DeepClone();
            rule["TargetGroup"]!["Health"] = ForwardProxyHealth.NewBalanced(rule, true); config = udp ? UdpForwarding.Normalize(config) : TcpForwarding.Normalize(config);
            var hash = ArchiveStore.Fingerprint(config); var validation = await new Proxy40Validation("none", udp).ValidateAsync(plan, config, f.Root, new InlineProgress<string>(_ => { }), default); var evidence = Multi41Proof(config, hash);
            foreach (var target in evidence["Groups"]![0]!["Targets"]!.AsArray()) target!["Evidence"] = new JsonObject { ["Scope"] = "ProxyHttpsEgress", ["TcpReachable"] = true, ["ProxyAuthenticated"] = true, ["HttpsVerified"] = true, ["EgressAddress"] = "198.51.100.40", ["UdpResponseMatched"] = udp };
            ForwardTargetGroups.AttachProof(config, validation, evidence, hash, true); var component = udp ? "UdpForwarding" : "TcpForwarding"; plan[component] = config; state[component] = new JsonObject { ["RemoteHash"] = hash, ["ConfigurationFingerprint"] = hash, ["Validation"] = validation };
        }
        var directory = f.Paths.Instance(relative); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state);
        var tcpRuleId = plan["TcpForwarding"]!["Rules"]![0].Text("Id"); var udpRuleId = plan["UdpForwarding"]!["Rules"]![0].Text("Id");
        var projected = ForwardedNodeSources.Create(f.Store, relative, tcpRuleId, "IPv4", "Example Entry");
        Check(projected.Text("sing_box.network") == "tcp" && !projected.Flag("clash.udp") && projected.Text("ForwardedOrigin.UdpRuleId") == "" && projected.Text("Egress.ExpectedAddress") == "", "independent multi-target groups advertised coordinated UDP or a single exit");
        Check(projected.Text("sing_box.password") == password && projected.Text("clash.password") == password, "multi-target projection changed source authentication");
        Refuses(() => ForwardedNodeSources.Create(f.Store, relative, tcpRuleId, "IPv4", "Example Entry", udpRuleId), "independent TCP/UDP multi-target groups were explicitly bound");
        plan["TcpForwarding"]!["Rules"]![0]!["TargetGroup"]!["Strategy"] = "SourceIpHash"; ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
        Refuses(() => ForwardedNodeSources.VerifyNodes(f.Store, [projected]), "changed multi-target strategy retained previous source qualification");
    }
    private async Task ForwardMulti41Workflows()
    {
        foreach (var udp in new[] { false, true }) foreach (var strategy in new[] { "RoundRobin", "SourceIpHash" }) foreach (var mode in new[] { "none", "apply-ack", "commit-ack", "cancel", "validation", "third-target", "proof" })
        {
            using var f = new Fixture(repository); var plan = f.Plan("Multi41-" + udp + strategy + mode); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
            var relative = f.Relative(plan); var directory = f.Paths.Instance(relative); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); var config = Multi41Config(udp, strategy);
            var remote = new ForwardRemote(udp ? "udp" : "tcp") { LoseApplyAck = mode == "apply-ack", GroupHealthy = [true, true, mode != "third-target"], GroupProofDrift = mode == "proof" }; remote.Inner.SeedProtocols(plan); remote.Inner.ProtocolConfigs["RealityEntry"] = System.Text.Encoding.UTF8.GetBytes("synthetic preexisting proxy"); remote.Inner.LoseOutboundCommitAcknowledgement = mode == "commit-ack";
            var validation = new ForwardValidation(mode, udp); var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpForwarding: validation, udpForwarding: validation);
            var component = udp ? "UdpForwarding" : "TcpForwarding"; var kind = udp ? OperationKind.UdpForward : OperationKind.TcpForward;
            JsonObject Options(JsonObject s, string action) => udp ? UdpForwarding.Options(s, action, action == "Remove" ? null : config) : TcpForwarding.Options(s, action, action == "Remove" ? null : config);
            Exception? error = null; TaskOutcome? outcome = null;
            try { outcome = await engine.ExecuteAsync(new(kind, relative, Options(state, "Apply")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { error = e; }
            Check(remote.ApplyCalls == 1, "multi-target mutation replayed");
            if (mode is "none" or "commit-ack")
            {
                Check(error == null && outcome == (mode == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings), "multi-target commit failed: " + error?.Message);
                state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); Check(state[component]!["Validation"]!["Items"]![0]!["TargetGroupHealth"]!["Targets"]!.AsArray().Count == 3, "multi-target evidence was not archived");
                remote.Inner.LoseOutboundCommitAcknowledgement = false; remote.GroupHealthy = [false, false, true];
                Check(await engine.ExecuteAsync(new(kind, relative, Options(state, "Check")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.ApplyCalls == 1, "degraded multi-target check replayed a mutation");
                state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
                Check(await engine.ExecuteAsync(new(kind, relative, Options(state, "Remove")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.Configuration == null, "multi-target scoped removal failed");
            }
            else Check(error != null && remote.Configuration == null && ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"))[component] == null && ArchiveStore.ReadJson(SafePath.Resolve(directory, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack", "multi-target recovery failed: " + mode + ": " + error?.Message);
            Check(!remote.Inner.Commands.Any(c => c is "maintenance-komari.sh" or "server-outbound-apply.sh" or "protocol-lifecycle-apply-state.sh"), "multi-target operation crossed component scope");
        }
    }
}
