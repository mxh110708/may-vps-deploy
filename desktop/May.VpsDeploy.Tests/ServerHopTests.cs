using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private const string HopA = "0123456789abcdef", HopB = "fedcba9876543210";
    private static JsonObject HopRule(string kind, string value, string id) { var rule = DestinationRule(kind, value, "NextHop"); rule["Target"] = id; return rule; }
    private sealed record HopFixture(JsonObject Scheme, JsonObject[] Nodes, JsonArray References, JsonArray Rules);
    private static HopFixture AddHopSources(Fixture f, RealityRouteFixture data)
    {
        var scheme = ClientSchemes.New(f.Paths); var nodes = new List<JsonObject>(); var refs = new JsonArray();
        foreach (var (id, index) in new[] { (HopA, 1), (HopB, 2) })
        {
            var node = data.Node.DeepClone().AsObject(); node["Id"] = Guid.NewGuid().ToString("N"); node["name"] = "Additional landing " + index;
            node["sing_box"]!["server"] = "192.0.2." + (20 + index); node["sing_box"]!["tag"] = node.Text("name");
            node["Egress"]!["ExpectedAddress"] = index == 1 ? "198.51.100.21" : "2001:db8::22"; node["Egress"]!["Family"] = index == 1 ? "IPv4" : "IPv6";
            nodes.Add(node); refs.Add(ServerOutboundRouting.HopReference(id, scheme, node, node.Text("Egress.ExpectedAddress")));
        }
        scheme["Nodes"] = new JsonArray(nodes.Select(n => (JsonNode?)n.DeepClone()).ToArray()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        return new(scheme, nodes.ToArray(), refs, new JsonArray(HopRule("Domain", "ai.example.test", HopA), HopRule("Cidr", "2001:db8::/32", HopB)));
    }
    private static ServerOutboundHop[] HopNodes(HopFixture hops) => hops.Nodes.Select((node, i) => new ServerOutboundHop(hops.References[i]!.Text("Id"), node, hops.References[i]!.Text("ExpectedAddress"), hops.References[i]!.AsObject())).ToArray();
    private static ServerOutboundPreview SaveHopPolicy(Fixture f, RealityRouteFixture data, string role, HopFixture hops)
    {
        var file = SafePath.Resolve(data.Directory, ServerOutboundRouting.ConfigRelative(role));
        var preview = ServerOutboundRouting.Build(role, ArchiveStore.ReadJson(file), data.Plan.At("ServerOutbound." + role) as JsonObject, data.Node, "198.51.100.20", data.Plan, new JsonObject { ["SchemeId"] = data.Scheme.Text("Id"), ["NodeId"] = data.Node.Text("Id") }, hops.Rules, HopNodes(hops));
        ArchiveStore.WriteJson(file, preview.Configuration); data.Plan.Put("ServerOutbound." + role, preview.Metadata!.DeepClone()); data.State.Put("ServerConfigHashes." + role, JsonValue.Create(ClientSchemes.SourceFingerprint(file)));
        ArchiveStore.WriteJson(SafePath.Resolve(data.Directory, "deployment-plan.json"), data.Plan); ArchiveStore.WriteJson(SafePath.Resolve(data.Directory, "deployment-state.json"), data.State); return preview;
    }
    public async Task RunServerHopTests()
    {
        using var f = new Fixture(repository); await ServerHopExperience(f); await ServerOutboundLoopback(f, withHops: true); await RealityOutboundLoopback(f, withHops: true); await ServerHopProbeRuntime(f);
        Console.WriteLine($"PASS: {assertions} multi-hop routing, individual acceptance and lifecycle assertions; no production connections.");
    }
    private async Task ServerHopExperience(Fixture f)
    {
        foreach (var role in ServerOutboundRouting.Roles)
        {
            var data = RealityFixture(f, "Hops-preview-" + role, true); var hops = AddHopSources(f, data);
            var options = ServerOutboundRouting.Options(data.State, role, "Apply", data.Scheme, data.Node, "198.51.100.20", hops.Rules, hops.References); var request = new OperationRequest(OperationKind.ServerOutbound, data.Relative, options);
            var preview = ServerOutboundRouting.Prepare(f.Store, request); var outputs = preview.Configuration["outbounds"]!.AsArray();
            Check(outputs.OfType<JsonObject>().Count(o => o.Text("tag").StartsWith("may-hop-")) == 2 && preview.Metadata!["AdditionalHops"]!.AsArray().Count == 2, "additional outbounds not created independently");
            var rules = preview.Configuration[role == "RealityEntry" ? "routing" : "route"]!["rules"]!.AsArray();
            Check(rules[0]!.Text(role == "RealityEntry" ? "outboundTag" : "outbound") == ServerOutboundRouting.HopTag(HopA) && rules[1]!.Text(role == "RealityEntry" ? "outboundTag" : "outbound") == ServerOutboundRouting.HopTag(HopB), "rules point to default or wrong named hop");
            Check(ServerDestinationRules.Match(hops.Rules, "ai.example.test").Target == HopA && ServerDestinationRules.Match(hops.Rules, "2001:db8::23").Target == HopB && ServerDestinationRules.Match(hops.Rules, "other.example.test").Target == "" && ServerDestinationRules.Match(hops.Rules, "ai.example.test", "udp").Target == "", "named matching changed defaults or UDP");
            Check(preview.Summary.Contains("Additional landing 1") && preview.Summary.Contains("Additional landing 2") && preview.Summary.Contains("入口机逐一") && !preview.Summary.Contains(data.Node.Text("sing_box.password")) && !preview.Metadata!.ToJsonString().Contains(data.Node.Text("sing_box.password")), "multi-hop review unclear or secret-bearing");
            var plain = ServerOutboundRouting.Build(role, preview.Configuration, preview.Metadata, null, "", data.Plan).Configuration;
            Check(ArchiveStore.Fingerprint(plain) == ArchiveStore.Fingerprint(role == "RealityEntry" ? ServerConfigurations.Xray(data.Plan, data.Secrets) : ServerConfigurations.AnyTls(data.Plan, data.Secrets)), "multi-hop removal did not restore exactly original policy");
            var onlyDefault = ServerOutboundRouting.Build(role, preview.Configuration, preview.Metadata, data.Node, "198.51.100.20", data.Plan);
            Check(!onlyDefault.Configuration["outbounds"]!.AsArray().Any(o => o!.Text("tag").StartsWith("may-hop-")), "changing to one hop left stale native outbounds");
            foreach (var change in new[] { "missing", "duplicate", "modified", "unowned" })
            {
                var drift = preview.Configuration.DeepClone().AsObject(); var list = drift["outbounds"]!.AsArray(); var owned = list.OfType<JsonObject>().First(o => o.Text("tag") == ServerOutboundRouting.HopTag(HopA));
                if (change == "missing") list.Remove(owned); else if (change == "duplicate") list.Add(owned.DeepClone()); else if (change == "unowned") { var extra = owned.DeepClone().AsObject(); extra["tag"] = "may-hop-aaaaaaaaaaaaaaaa"; list.Add(extra); } else if (role == "RealityEntry") owned["settings"]!["servers"]![0]!["port"] = 30000; else owned["server_port"] = 30000;
                Refuses(() => ServerOutboundRouting.Build(role, drift, preview.Metadata, null, "", data.Plan), "native hop drift overwritten: " + change);
            }
            var brokenRefs = hops.References.DeepClone().AsArray(); brokenRefs[1]!["Id"] = HopA; Refuses(() => ServerOutboundRouting.HopReferences(brokenRefs), "duplicate hop IDs accepted");
            brokenRefs = hops.References.DeepClone().AsArray(); brokenRefs[1]!["NodeId"] = brokenRefs[0]!["NodeId"]!.DeepClone(); Refuses(() => ServerOutboundRouting.HopReferences(brokenRefs), "duplicate sources accepted");
            Refuses(() => ServerDestinationRules.ValidatePath(hops.Rules, "IPv4", true), "missing named hop fell back to default");
            Refuses(() => ServerDestinationRules.ValidatePath(new JsonArray(), "IPv4", true, ServerOutboundRouting.HopFamilies(hops.References)), "unused extra hop accepted");
            Refuses(() => ServerDestinationRules.Normalize(new JsonArray(HopRule("Domain", "ai.example.test", "bad-tag"))), "arbitrary outbound name accepted");
            var invalidAction = HopRule("Domain", "ai.example.test", HopA); invalidAction["Action"] = "Direct"; Refuses(() => ServerDestinationRules.Normalize(new JsonArray(invalidAction)), "direct action carried named hop");
            var invalidFamily = new JsonArray(HopRule("Cidr", "2001:db8::/32", HopA), HopRule("Domain", "v6.example.test", HopB)); Refuses(() => ServerDestinationRules.ValidatePath(invalidFamily, "IPv4", true, ServerOutboundRouting.HopFamilies(hops.References)), "wrong chosen-hop address family accepted");
            var bypass = hops.Rules.DeepClone().AsArray(); bypass.Insert(0, HopRule("Suffix", "ipify.org", HopA)); Refuses(() => ServerDestinationRules.ValidatePath(bypass, "IPv4", true, ServerOutboundRouting.HopFamilies(hops.References)), "default acceptance redirected through extra hop");
            var copies = HopNodes(hops); copies[0] = copies[0] with { Node = data.Node }; Refuses(() => ServerOutboundRouting.Build(role, plain, null, data.Node, "198.51.100.20", data.Plan, destinationRules: hops.Rules, additionalHops: copies), "same SS connection duplicated under different IDs");
            copies = HopNodes(hops); var self = copies[0].Node.DeepClone().AsObject(); self["sing_box"]!["server"] = data.Plan.Text("Server.IPv4"); copies[0] = copies[0] with { Node = self }; Refuses(() => ServerOutboundRouting.Build(role, plain, null, data.Node, "198.51.100.20", data.Plan, destinationRules: hops.Rules, additionalHops: copies), "additional hop self-loop accepted");
            data.Plan.Put("ServerOutbound." + role, preview.Metadata!.DeepClone()); var probes = ServerOutboundRouting.ProbeRequests(role, preview.Configuration, data.Plan);
            JsonObject Result() => new() { ["Status"] = "Passed", ["Items"] = new JsonArray(probes.OfType<JsonObject>().Select(p => (JsonNode?)new JsonObject { ["Id"] = p.Text("Id"), ["Status"] = "Passed", ["From"] = "EntryServer", ["Network"] = "TCP", ["Egress"] = p.Text("ExpectedAddress") }).ToArray()) };
            ServerOutboundRouting.RequireHopValidation(probes, Result()); Check(probes.Count == 2, "not every named hop included in acceptance");
            foreach (var change in new[] { "missing", "duplicate", "egress", "from", "network", "status" })
            {
                var result = Result(); var items = result["Items"]!.AsArray();
                if (change == "missing") items.RemoveAt(0); else if (change == "duplicate") items[1] = items[0]!.DeepClone(); else items[0]![change switch { "egress" => "Egress", "from" => "From", "network" => "Network", _ => "Status" }] = "invalid";
                Refuses(() => ServerOutboundRouting.RequireHopValidation(probes, result), "partial/falsified named-hop acceptance accepted: " + change);
            }
            var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed))); var review = coordinator.Review(request);
            hops.Scheme["Name"] = "changed extra source"; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, hops.Scheme.Text("Id")), hops.Scheme);
            await RefusesAsync(async () => await coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "review omitted additional scheme identity");
            hops.Scheme["Nodes"]![0]!["name"] = "changed named landing"; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, hops.Scheme.Text("Id")), hops.Scheme);
            Refuses(() => ServerOutboundRouting.Prepare(f.Store, request), "changed named source accepted from stale reference");
            Check(ServerOutboundRouting.SourcesSummary(f.Store, preview.Metadata).Contains("服务器未同步"), "extra source changes invisible in status summary");
        }
        foreach (var role in ServerOutboundRouting.Roles)
        foreach (var failure in new[] { "none", "probe", "incomplete", "cancel", "apply-ack", "commit-ack" })
        {
            var data = RealityFixture(f, "Hops-task-" + role + "-" + failure, true); var hops = AddHopSources(f, data); SaveHopPolicy(f, data, role, hops);
            var remote = RoutingRemote(data); var old = remote.ProtocolConfigs[role].ToArray(); var sibling = remote.ProtocolConfigs[role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry"].ToArray(); var before = ArchiveStore.Fingerprint(data.Plan["ServerOutbound"]!);
            remote.HopProbeFailure = failure == "probe"; remote.HopProbeIncomplete = failure == "incomplete"; remote.LoseOutboundApplyAcknowledgement = failure == "apply-ack"; remote.LoseOutboundCommitAcknowledgement = failure == "commit-ack";
            if (failure == "cancel") remote.ObserveAsset = asset => { if (asset == "server-hop-probe.sh") throw new OperationCanceledException(); };
            var newRules = hops.Rules.DeepClone().AsArray(); newRules[0]!["Value"] = "changed.example.test"; var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new RealityLifecycleValidation("none"));
            Exception? error = null; TaskOutcome? outcome = null;
            try { outcome = await engine.ExecuteAsync(new(OperationKind.ServerOutbound, data.Relative, ServerOutboundRouting.Options(data.State, role, "Apply", data.Scheme, data.Node, "198.51.100.20", newRules, hops.References)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { error = e; }
            var after = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "deployment-plan.json"));
            Check(remote.ProtocolConfigs[role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry"].SequenceEqual(sibling) && remote.ArmedComponents == role && remote.Commands.Count(c => c == "server-outbound-apply.sh") == 1, "multi-hop failure changed sibling or replayed write");
            if (failure is "none" or "commit-ack")
            {
                var state = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "deployment-state.json"));
                Check(error == null && outcome == (failure == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings) && after.At("ServerOutbound." + role + ".DestinationRules")![0]!.Text("Value") == "changed.example.test" && state.At("ServerOutboundValidation." + role + ".AdditionalHops.Items") is JsonArray list && list.Count == 2, "multi-hop commit omitted individual acceptance");
            }
            else Check(error != null && remote.ProtocolConfigs[role].SequenceEqual(old) && ArchiveStore.Fingerprint(after["ServerOutbound"]!) == before, "failed extra hop did not restore previous multi-hop route");
        }
        foreach (var role in ServerOutboundRouting.Roles)
        foreach (var kind in new[] { OperationKind.Upgrade, OperationKind.RotateCredentials })
        foreach (var failure in new[] { false, true })
        {
            var data = RealityFixture(f, "Hops-life-" + role + "-" + kind + "-" + failure, true); var hops = AddHopSources(f, data); SaveHopPolicy(f, data, role, hops);
            var remote = RoutingRemote(data); remote.HopProbeFailure = failure; var old = remote.ProtocolConfigs[role].ToArray(); var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new RealityLifecycleValidation("none")); var options = new JsonObject { ["Scope"] = "Protocol", ["Protocol"] = role };
            if (kind == OperationKind.Upgrade) options["TargetVersion"] = role == "RealityEntry" ? f.Versions.Text("xray.version") : f.Versions.Text("sing_box.version");
            Exception? error = null; TaskOutcome? outcome = null; try { outcome = await engine.ExecuteAsync(new(kind, data.Relative, options), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { error = e; }
            Check(remote.Commands.Contains("server-hop-probe.sh"), "maintenance skipped extra-hop validation");
            if (failure) Check(error != null && remote.ProtocolConfigs[role].SequenceEqual(old), "failed maintenance extra-hop probe did not restore config");
            else
            {
                var after = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "deployment-plan.json")); ServerOutboundRouting.VerifyManaged(role, JsonNode.Parse(remote.ProtocolConfigs[role])!.AsObject(), after);
                Check(error == null && outcome == TaskOutcome.Completed && ArchiveStore.Fingerprint(after["ServerOutbound"]!) == ArchiveStore.Fingerprint(data.Plan["ServerOutbound"]!), "maintenance lost named-hop ownership or policy");
                if (kind == OperationKind.RotateCredentials)
                {
                    var backup = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "operation-pending.dotnet.json")).Text("TaskId");
                    foreach (var component in ServerOutboundRouting.Roles) remote.RestoreProtocolConfigs[component] = File.ReadAllBytes(SafePath.Resolve(data.Directory, "maintenance-backups/" + backup + "/artifacts/" + ServerOutboundRouting.ConfigRelative(component)));
                    var count = remote.Commands.Count(c => c == "server-hop-probe.sh");
                    Check(await engine.ExecuteAsync(new(OperationKind.Restore, data.Relative, new JsonObject { ["Scope"] = "Protocol", ["Backup"] = FakeRemote.Backup, ["RestoreMode"] = "ConfigOnly" }), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.Commands.Count(c => c == "server-hop-probe.sh") > count, "restore skipped named-hop acceptance");
                }
            }
        }
    }
}
