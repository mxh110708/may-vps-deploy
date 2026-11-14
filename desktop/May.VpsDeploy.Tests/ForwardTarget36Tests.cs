using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunForwardTarget36Tests()
    {
        await ForwardTarget36Model(); await ForwardTarget36Workflows();
        Console.WriteLine($"PASS: {assertions} primary/standby configuration, evidence, review and scoped transaction assertions; no production connections.");
    }
    private static JsonObject Group36Config(bool udp = false)
    {
        var config = ForwardConfig(); var rule = config["Rules"]![0]!.AsObject(); rule["Name"] = "主备 · synthetic";
        if (udp) { rule["Validation"] = new JsonObject { ["Type"] = "Echo" }; rule["SessionTimeoutSeconds"] = 30; rule["MaximumSessions"] = 64; }
        var group = ForwardTargetGroups.New(rule); group["BackupAddress"] = "2001:db8::21"; group["BackupPort"] = 8443;
        rule["TargetGroup"] = group;
        return config;
    }
    private static JsonObject Group36Proof(JsonObject configuration, string hash, bool primary = true, bool backup = true) => new()
    {
        ["ConfigurationHash"] = hash,
        ["Groups"] = new JsonArray(TcpForwarding.Rules(configuration).Where(r => r.Flag("Enabled") && r["TargetGroup"] is JsonObject).Select(r => (JsonNode?)new JsonObject
        {
            ["RuleId"] = r.Text("Id"), ["RuleFingerprint"] = ForwardTargetGroups.Fingerprint(r), ["HealthType"] = r.Text("TargetGroup.Health.Type"),
            ["Targets"] = new JsonArray(ForwardTargetGroups.Targets(r).Select((target, index) => (JsonNode?)new JsonObject { ["Index"] = index, ["Address"] = target.Address, ["Port"] = target.Port, ["Passed"] = index == 0 ? primary : backup }).ToArray())
        }).ToArray())
    };
    private async Task ForwardTarget36Model()
    {
        using (var current = System.Diagnostics.Process.GetCurrentProcess())
        {
            var owned = QuicOwnedProcess.Capture(current);
            Check(!owned.Exited, "live owned process was considered stopped");
            Check((owned with { StartedUtc = owned.StartedUtc.AddTicks(-1) }).Exited, "reused PID with a different creation identity was considered the original process");
        }
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
        if (python != null)
        {
            var payloads = new JsonArray();
            foreach (var label in new[] { "主备 · synthetic", "quotes \" and & <> /", "emoji 🌸" })
            { var sample = Group36Config()["Rules"]![0]!.DeepClone(); sample["Name"] = label; payloads.Add(sample); }
            const string program = "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('groups',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(json.dumps([m.group_fingerprint(v) for v in json.load(sys.stdin)]))";
            var hashes = await new ExternalToolRunner().RunAsync(python, ["-c", program, Path.Combine(repository, "scripts/forward-target-groups.py")], payloads.ToJsonString(), TimeSpan.FromSeconds(15), default);
            Check(hashes.ExitCode == 0, "cross-language fingerprint program failed");
            var actual = JsonNode.Parse(hashes.Output)!.AsArray();
            for (var i = 0; i < payloads.Count; i++) Check(actual[i]!.GetValue<string>() == ForwardTargetGroups.Fingerprint(payloads[i]!), "C#/Python group identity mismatch for unicode or escaped strings");
        }
        else Console.WriteLine("SKIP: MAY_TEST_PYTHON required for cross-language group fingerprints.");
        foreach (var udp in new[] { false, true })
        {
            var config = Group36Config(udp); var rule = config["Rules"]![0]!.AsObject(); var original = config.ToJsonString();
            JsonObject Normalize(JsonObject c) => udp ? UdpForwarding.Normalize(c) : TcpForwarding.Normalize(c);
            var normalized = Normalize(config);
            Check(config.ToJsonString() == original && normalized["Rules"]![0]!.Text("TargetGroup.BackupAddress") == "2001:db8::21", "group normalization changed original or discarded standby family");
            Check(ForwardTargetGroups.Summary(rule).Contains("连续失败 3") && ForwardTargetGroups.Summary(rule).Contains("持续 30") && ForwardTargetGroups.Summary(rule).Contains("不回退"), "group review omitted thresholds, hold or fail-closed policy");
            foreach (var edit in new Action<JsonObject>[] {
                g => g["Weight"] = 2, g => g["Version"] = 2, g => g["BackupPort"] = "8443", g => g["BackupPort"] = 0,
                g => g["BackupAddress"] = "::ffff:192.0.2.21", g => g["BackupAddress"] = "backup.example.test", g => g["BackupAddress"] = "224.0.0.1",
                g => g["IntervalSeconds"] = 4, g => g["TimeoutSeconds"] = 0, g => g["TimeoutSeconds"] = 10,
                g => g["FailureThreshold"] = 1, g => g["RecoveryThreshold"] = 11, g => g["RecoveryHoldSeconds"] = 0, g => g["AutoReturn"] = "true",
                g => g["Health"] = new JsonObject { ["Type"] = "Connect" }, g => { g["BackupAddress"] = "192.0.2.20"; g["BackupPort"] = 443; }
            })
            { var bad = config.DeepClone().AsObject(); edit(bad["Rules"]![0]!["TargetGroup"]!.AsObject()); Refuses(() => Normalize(bad), "unsafe group configuration was accepted"); }
            var nullGroup = config.DeepClone().AsObject(); nullGroup["Rules"]![0]!["TargetGroup"] = null; Refuses(() => Normalize(nullGroup), "null group was silently removed");
            var plan = new JsonObject { ["Server"] = new JsonObject { ["IPv4"] = "192.0.2.10" } };
            var loop = config.DeepClone().AsObject(); loop["Rules"]![0]!["TargetGroup"]!["BackupAddress"] = "127.0.0.1"; loop["Rules"]![0]!["TargetGroup"]!["BackupPort"] = rule.Number("ListenPort");
            Refuses(() => ForwardTargetGroups.ValidateLoops(plan, loop), "standby listener self-loop accepted");
            var hash = new string('a', 64); var result = new JsonObject { ["Items"] = new JsonArray(new JsonObject { ["Id"] = rule.Text("Id") }) };
            Refuses(() => ForwardTargetGroups.RequireProof(rule, result["Items"]![0]!.AsObject()), "group accepted plain forwarding evidence");
            ForwardTargetGroups.AttachProof(config, result, Group36Proof(config, hash), hash, true); ForwardTargetGroups.RequireProof(rule, result["Items"]![0]!.AsObject());
            Check(result["Items"]![0]!["TargetGroupHealth"]!["Targets"]!.AsArray().Count == 2, "group proof lost an endpoint");
            Refuses(() => ForwardTargetGroups.AttachProof(config, result, Group36Proof(config, hash, true, false), hash, true), "new group accepted unqualified standby");
            ForwardTargetGroups.AttachProof(config, result, Group36Proof(config, hash, false, true), hash, false); Check(!result["Items"]![0]!["TargetGroupHealth"]!["Targets"]![0].Flag("Passed"), "degraded check invented a primary success");
            Refuses(() => ForwardTargetGroups.AttachProof(config, result, Group36Proof(config, hash, false, false), hash, false), "all-failed group passed current check");
            Refuses(() => ForwardTargetGroups.AttachProof(config, result, Group36Proof(config, hash), new string('b', 64), false), "stale component hash accepted");
            foreach (var edit in new Action<JsonObject>[] { p => p["RuleId"] = new string('b',32), p => p["RuleFingerprint"] = new string('b',64), p => p["Targets"]![0]!["Port"] = 444, p => p["Targets"]![0]!["Passed"] = "true", p => p["Targets"]!.AsArray().RemoveAt(1) })
            { var bad = Group36Proof(config, hash); edit(bad["Groups"]![0]!.AsObject()); Refuses(() => ForwardTargetGroups.AttachProof(config, result, bad, hash, false), "forged/mismatched group evidence accepted"); }
            var noReturn = config.DeepClone().AsObject(); noReturn["Rules"]![0]!["TargetGroup"]!["AutoReturn"] = false;
            Check(!Normalize(noReturn)["Rules"]![0]!.Flag("TargetGroup.AutoReturn") && ForwardTargetGroups.Summary(noReturn["Rules"]![0]!.AsObject()).Contains("不主动返回"), "explicit no-return policy lost");
        }
        using var f = new Fixture(repository); var plan2 = f.Plan("Group-review"); plan2.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan2);
        var directory = f.Paths.Instance(f.Relative(plan2)); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); var request = new OperationRequest(OperationKind.TcpForward, f.Relative(plan2), TcpForwarding.Options(state, "Apply", Group36Config()));
        var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed))); var review = coordinator.Review(request);
        Check(review.Summary.Contains("主备组") && review.Summary.Contains("2001:db8::21"), "standby omitted from final review");
        var changed = request.Options.DeepClone().AsObject(); changed["Configuration"]!["Rules"]![0]!["TargetGroup"]!["BackupPort"] = 8444;
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request with { Options = changed }, new InlineProgress<TaskProgress>(_ => { }), default), "post-review standby mutation accepted");
        var path = f.Paths.Resolve("scripts/forward-target-groups.py"); var bytes = File.ReadAllBytes(path); File.AppendAllText(path, "\n# fixture drift\n");
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "post-review health worker mutation accepted"); File.WriteAllBytes(path, bytes);
        var chain = Group36Config(); chain["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "TcpChain", ["ChainId"] = new string('a',32), ["FrontInstance"] = "Example/Front/May-VPS-Deploy" };
        Refuses(() => TcpForwarding.Normalize(chain), "implicit group changed a pinned cross-instance chain");
        var password = ServerConfigurations.RandomKey(16); var scheme = ClientSchemes.New(f.Paths);
        var source = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Synthetic replicated SS", ["kind"] = "entry", ["region_group"] = "Example Entry",
            ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["server"] = "192.0.2.20", ["server_port"] = 443, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = password },
            ["clash"] = new JsonObject { ["name"] = "Synthetic replicated SS", ["type"] = "ss", ["server"] = "192.0.2.20", ["port"] = 443, ["cipher"] = "2022-blake3-aes-128-gcm", ["password"] = password, ["udp"] = true },
            ["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = "192.0.2.20" } };
        scheme["Nodes"] = new JsonArray(source); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        var proxyConfig = Group36Config(); var proxyRule = proxyConfig["Rules"]![0]!.AsObject();
        proxyRule["Validation"] = new JsonObject { ["Type"] = "Proxy", ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = source.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(source) };
        proxyRule["TargetGroup"]!["Health"] = new JsonObject { ["Type"] = "Connect" }; proxyConfig = TcpForwarding.Normalize(proxyConfig); proxyRule = proxyConfig["Rules"]![0]!.AsObject();
        Check(TcpForwarding.ProxyNode(f.Store, proxyRule).Text("sing_box.password") == password && ForwardTargetGroups.Summary(proxyRule).Contains("仅为 TCP 可达性"), "proxy group lost original credentials or overstated protocol health");
        var accepted = await new ForwardValidation("none").ValidateAsync(plan2, proxyConfig, f.Root, new InlineProgress<string>(_ => { }), default);
        var proxyHash = new string('a',64); ForwardTargetGroups.AttachProof(proxyConfig, accepted, Group36Proof(proxyConfig, proxyHash), proxyHash, true);
        plan2["TcpForwarding"] = proxyConfig.DeepClone(); state["TcpForwarding"] = new JsonObject { ["RemoteHash"] = proxyHash, ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(proxyConfig), ["Validation"] = accepted };
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan2); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state);
        var derived = ForwardedNodeSources.Create(f.Store, f.Relative(plan2), proxyRule.Text("Id"), "IPv4", "Example Entry");
        Check(derived.Text("sing_box.password") == password && derived.Text("clash.password") == password, "group-derived node changed authentication");
        Check(derived.Text("sing_box.server") == plan2.Text("Server.IPv4") && derived.Text("Egress.ExpectedAddress") == "" && source.Text("Egress.ExpectedAddress") == "192.0.2.20", "group projection changed source or retained a single-target egress promise");
        Check(derived.Text("sing_box.network") == "tcp" && !derived.Flag("clash.udp") && derived.Text("ForwardedOrigin.UdpRuleId") == "", "TCP standby incorrectly bound the old single-target UDP path");
        proxyConfig["Rules"]![0]!["TargetGroup"]!["BackupPort"] = 8444; plan2["TcpForwarding"] = proxyConfig;
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan2);
        Refuses(() => ForwardedNodeSources.VerifyNodes(f.Store, [derived]), "standby change retained old forwarded source qualification");
    }
    private async Task ForwardTarget36Workflows()
    {
        foreach (var udp in new[] { false, true }) foreach (var failure in new[] { "none", "apply-ack", "commit-ack", "cancel", "validation", "backup", "proof" })
        {
            using var f = new Fixture(repository); var plan = f.Plan("Group-" + (udp ? "udp-" : "tcp-") + failure); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
            var relative = f.Relative(plan); var directory = f.Paths.Instance(relative); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); var config = Group36Config(udp);
            var remote = new ForwardRemote(udp ? "udp" : "tcp") { LoseApplyAck = failure == "apply-ack", GroupHealthy = [true, failure != "backup"], GroupProofDrift = failure == "proof" };
            remote.Inner.SeedProtocols(plan);
            remote.Inner.ProtocolConfigs["RealityEntry"] = System.Text.Encoding.UTF8.GetBytes("synthetic existing proxy");
            remote.Inner.LoseOutboundCommitAcknowledgement = failure == "commit-ack"; var validation = new ForwardValidation(failure, udp);
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpForwarding: validation, udpForwarding: validation);
            var kind = udp ? OperationKind.UdpForward : OperationKind.TcpForward; var component = udp ? "UdpForwarding" : "TcpForwarding";
            JsonObject Options(JsonObject s, string action) => udp ? UdpForwarding.Options(s, action, action == "Remove" ? null : config) : TcpForwarding.Options(s, action, action == "Remove" ? null : config);
            Exception? error = null; TaskOutcome? outcome = null;
            try { outcome = await engine.ExecuteAsync(new(kind, relative, Options(state, "Apply")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { error = e; }
            var actualPlan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json")); var actualState = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
            if (failure is "none" or "commit-ack")
            {
                Check(error == null && outcome == (failure == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings), "group apply/commit acknowledgement reconciliation failed");
                Check(remote.GroupProbeCalls == 1 && actualState.At(component + ".Validation.Items")!.AsArray()[0]!["TargetGroupHealth"] != null, "group skipped explicit per-target remote health or archival");
                var calls = remote.ApplyCalls; remote.Inner.LoseOutboundCommitAcknowledgement = false; remote.GroupHealthy = [false, true];
                Check(await engine.ExecuteAsync(new(kind, relative, Options(actualState, "Check")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.ApplyCalls == calls, "degraded group check replayed writes or required dead primary");
                actualState = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
                Check(!actualState.At(component + ".Validation.Items")!.AsArray()[0]!["TargetGroupHealth"]!["Targets"]![0].Flag("Passed"), "degraded primary was marked healthy");
                Check(await engine.ExecuteAsync(new(kind, relative, Options(actualState, "Remove")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.Configuration == null, "group scoped removal failed");
            }
            else
            {
                Check(error != null && remote.ApplyCalls == 1 && remote.Configuration == null && actualPlan[component] == null && actualState[component] == null, $"failed group {component}/{failure}: error={error?.GetType().Name} applies={remote.ApplyCalls} remote={remote.Configuration != null} plan={actualPlan[component] != null} state={actualState[component] != null}; {error?.Message}");
                Check(ArchiveStore.ReadJson(SafePath.Resolve(directory, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack", "group failure did not complete original scoped recovery");
            }
            Check(!remote.Inner.Commands.Any(c => c is "server-outbound-apply.sh" or "maintenance-komari.sh" or "protocol-lifecycle-apply-state.sh"), "group changed proxy or monitoring scope");
        }
    }
}
