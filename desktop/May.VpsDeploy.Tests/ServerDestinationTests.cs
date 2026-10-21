using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private static JsonObject DestinationRule(string kind, string value, string action) => new() { ["Kind"] = kind, ["Value"] = value, ["Action"] = action };
    private static JsonArray ExampleDestinationRules() => new(DestinationRule("Domain", "ai.example.test", "NextHop"), DestinationRule("Suffix", "example.test", "Direct"), DestinationRule("Cidr", "192.0.2.0/24", "Reject"));
    private static void SaveDestinationPolicy(Fixture f, RealityRouteFixture data, string role, JsonArray policy)
    {
        var file = SafePath.Resolve(data.Directory, ServerOutboundRouting.ConfigRelative(role));
        var preview = ServerOutboundRouting.Build(role, ArchiveStore.ReadJson(file), data.Plan.At("ServerOutbound." + role)!.AsObject(), data.Node, "198.51.100.20", data.Plan, new JsonObject { ["SchemeId"] = data.Scheme.Text("Id"), ["NodeId"] = data.Node.Text("Id") }, policy);
        ArchiveStore.WriteJson(file, preview.Configuration); data.Plan.Put("ServerOutbound." + role, preview.Metadata!.DeepClone()); data.State.Put("ServerConfigHashes." + role, JsonValue.Create(ClientSchemes.SourceFingerprint(file)));
        ArchiveStore.WriteJson(SafePath.Resolve(data.Directory, "deployment-plan.json"), data.Plan); ArchiveStore.WriteJson(SafePath.Resolve(data.Directory, "deployment-state.json"), data.State);
    }
    public async Task RunServerDestinationTests()
    {
        using var fixture = new Fixture(repository); await ServerDestinationExperience(fixture); await ServerOutboundLoopback(fixture, true); await RealityOutboundLoopback(fixture, true);
        Console.WriteLine($"PASS: {assertions} destination routing and scoped lifecycle assertions; no production connections.");
    }
    private async Task ServerDestinationExperience(Fixture f)
    {
        var normalized = ServerDestinationRules.Normalize(new JsonArray(DestinationRule("Domain", " ExAmPlE.Test. ", "Direct"), DestinationRule("Suffix", "例子.测试", "Reject"), DestinationRule("Cidr", "192.0.2.15/24", "NextHop"), DestinationRule("Cidr", "2001:db8::abcd/48", "Reject")));
        Check(normalized[0]!.Text("Value") == "example.test" && normalized[1]!.Text("Value").StartsWith("xn--") && normalized[2]!.Text("Value") == "192.0.2.0/24" && normalized[3]!.Text("Value") == "2001:db8::/48", "destination rules not normalized canonically");
        var policy = ExampleDestinationRules();
        foreach (var (destination, action) in new[] { ("ai.example.test", "NextHop"), ("EXAMPLE.TEST.", "Direct"), ("web.example.test", "Direct"), ("badexample.test", "NextHop"), ("example.test.invalid", "NextHop"), ("192.0.2.80", "Reject"), ("192.0.3.1", "NextHop") }) Check(ServerDestinationRules.Decide(policy, destination) == action, "ordered match or label boundary failed: " + destination);
        Check(ServerDestinationRules.Decide(new JsonArray(DestinationRule("Cidr", "::/0", "Reject")), "2001:db8::1") == "Reject" && ServerDestinationRules.Decide(new JsonArray(DestinationRule("Cidr", "0.0.0.0/0", "Direct")), "host.example.test") == "NextHop", "IP-only matching resolved a domain or mishandled zero prefix");
        foreach (var value in new[] { "https://example.test", "*.example.test", "regexp:.*", "example.test:443", "127.0.0.1", "a..test", "-bad.test", "bad_.test", "a\nb.test" }) Refuses(() => ServerDestinationRules.Normalize(new JsonArray(DestinationRule("Domain", value, "Direct"))), "invalid domain accepted");
        foreach (var value in new[] { "192.0.2.1", "192.0.2.1/33", "::/129", "example.test/24", "fe80::1%3/64", "::ffff:192.0.2.1/128" }) Refuses(() => ServerDestinationRules.Normalize(new JsonArray(DestinationRule("Cidr", value, "Direct"))), "invalid CIDR accepted");
        Refuses(() => ServerDestinationRules.Normalize(new JsonObject()), "rule object accepted as list");
        Refuses(() => ServerDestinationRules.Normalize(new JsonArray(JsonValue.Create("native injection"))), "non-object rule accepted");
        Refuses(() => ServerDestinationRules.Normalize(new JsonArray(new JsonObject { ["Kind"] = "Domain", ["Value"] = true, ["Action"] = "Direct" })), "boolean silently converted into a domain");
        Refuses(() => ServerDestinationRules.Normalize(new JsonArray(DestinationRule("GeoIP", "cn", "Direct"))), "unsupported matcher accepted");
        Refuses(() => ServerDestinationRules.Normalize(new JsonArray(DestinationRule("Domain", "example.test", "ArbitraryOutbound"))), "unowned route action accepted");
        Refuses(() => ServerDestinationRules.Normalize(new JsonArray(DestinationRule("Domain", "example.test", "Direct"), DestinationRule("Domain", "EXAMPLE.TEST.", "Reject"))), "duplicate normalized rule accepted");
        Refuses(() => ServerDestinationRules.Normalize(new JsonArray(Enumerable.Range(0, 33).Select(i => (JsonNode?)DestinationRule("Domain", "host" + i + ".test", "Reject")).ToArray())), "unbounded rule list accepted");
        Refuses(() => ServerDestinationRules.ValidatePath(new JsonArray(DestinationRule("Suffix", "ipify.org", "Direct")), "IPv4", true), "acceptance silently bypassed fixed next hop");
        Check(ServerDestinationRules.Decide(new JsonArray(DestinationRule("Cidr", "1.1.1.0/24", "Reject")), "1.1.1.1", "udp") == "NextHop", "TCP exceptions changed UDP path");
        ServerDestinationRules.ValidatePath(new JsonArray(DestinationRule("Domain", "api.ipify.org", "NextHop"), DestinationRule("Suffix", "ipify.org", "Direct")), "IPv4", true);
        Refuses(() => ServerDestinationRules.ValidatePath(new JsonArray(DestinationRule("Cidr", "2001:db8::/32", "NextHop")), "IPv4", false), "next-hop address family guard bypassed");
        Refuses(() => ServerDestinationRules.ValidatePath(new JsonArray(DestinationRule("Cidr", "2001:db8::/32", "Direct")), "IPv6", true), "original direct IPv4 constraint bypassed");

        foreach (var role in ServerOutboundRouting.Roles)
        {
            var data = RealityFixture(f, "Rules-preview-" + role, true); var file = SafePath.Resolve(data.Directory, ServerOutboundRouting.ConfigRelative(role)); var baseline = ArchiveStore.ReadJson(file); var previous = data.Plan.At("ServerOutbound." + role)!.AsObject();
            var options = ServerOutboundRouting.Options(data.State, role, "Apply", data.Scheme, data.Node, "198.51.100.20", policy);
            var preview = ServerOutboundRouting.Prepare(f.Store, new(OperationKind.ServerOutbound, data.Relative, options));
            var actualRules = preview.Configuration[role == "RealityEntry" ? "routing" : "route"]!["rules"]!.AsArray();
            Check(actualRules.Count == 6 && preview.Configuration["inbounds"]!.ToJsonString() == baseline["inbounds"]!.ToJsonString(), "policy lost original rule or rewrote inbound");
            Check(ArchiveStore.Fingerprint(preview.Metadata!["DestinationRules"]!) == ArchiveStore.Fingerprint(policy) && preview.Metadata.Text("DestinationRulesNetwork") == "tcp" && actualRules.Take(3).All(r => r!.Text("network") == "tcp") && preview.Summary.Contains("UDP 不应用这些例外") && preview.Summary.Contains("入口机直连") && preview.Summary.Contains("未命中：所选落地") && !preview.Summary.Contains(data.Node.Text("sing_box.password")), "policy review/metadata not accurate or redacted");
            if (role == "AnyTlsEntry") Check(actualRules[1]!.Strings("domain").SequenceEqual(["example.test"]) && actualRules[1]!.Strings("domain_suffix").SequenceEqual([".example.test"]), "sing-box suffix must include root and respect label boundary");
            else Check(actualRules[1]!.Strings("domain").SequenceEqual(["domain:example.test"]) && actualRules[2]!.Text("outboundTag") == "block", "Xray rule translation failed");
            var fixedAgain = ServerOutboundRouting.Build(role, preview.Configuration, preview.Metadata, data.Node, "198.51.100.20", data.Plan);
            Check(ArchiveStore.Fingerprint(fixedAgain.Configuration) == ArchiveStore.Fingerprint(baseline), "removing exceptions changed the existing fixed next hop");
            var original = role == "RealityEntry" ? ServerConfigurations.Xray(data.Plan, data.Secrets) : ServerConfigurations.AnyTls(data.Plan, data.Secrets);
            Check(ArchiveStore.Fingerprint(ServerOutboundRouting.Build(role, preview.Configuration, preview.Metadata, null, "", data.Plan).Configuration) == ArchiveStore.Fingerprint(original), "removing entire managed route did not restore original configuration");
            var drifted = preview.Configuration.DeepClone().AsObject(); var ruleArray = drifted[role == "RealityEntry" ? "routing" : "route"]!["rules"]!.AsArray(); var first = ruleArray[0]!.DeepClone(); ruleArray.RemoveAt(0); ruleArray.Insert(1, first);
            Refuses(() => ServerOutboundRouting.Build(role, drifted, preview.Metadata, null, "", data.Plan), "external reorder overwritten on removal");
            var badMetadata = preview.Metadata!.DeepClone().AsObject(); badMetadata["DestinationRules"]![0]!["Action"] = "Reject";
            Refuses(() => ServerOutboundRouting.Build(role, preview.Configuration, badMetadata, null, "", data.Plan), "metadata policy inconsistent with actual rules accepted");
            badMetadata = preview.Metadata!.DeepClone().AsObject(); badMetadata["DestinationRulesNetwork"] = "udp";
            Refuses(() => ServerOutboundRouting.Build(role, preview.Configuration, badMetadata, null, "", data.Plan), "unexpected UDP scope was adopted");
            var changed = options.DeepClone().AsObject(); changed["DestinationRules"]![0]!["Action"] = "Reject";
            Check(TaskCoordinator.Fingerprint(new(OperationKind.ServerOutbound, data.Relative, options)) != TaskCoordinator.Fingerprint(new(OperationKind.ServerOutbound, data.Relative, changed)), "review fingerprint omitted rule policy");
            var forged = options.DeepClone().AsObject(); forged["DestinationRules"] = "invalid"; Refuses(() => ServerOutboundRouting.ValidateOptions(forged), "malformed policy silently discarded");
        }
        foreach (var role in ServerOutboundRouting.Roles)
        foreach (var failure in new[] { "none", "partial", "apply-ack", "commit-ack", "cancel" })
        {
            var data = RealityFixture(f, "Rules-task-" + role + "-" + failure, true);
            if (failure != "none") SaveDestinationPolicy(f, data, role, new JsonArray(DestinationRule("Suffix", "previous.example.test", "Reject")));
            var remote = RoutingRemote(data); var original = remote.ProtocolConfigs[role].ToArray(); var sibling = remote.ProtocolConfigs[role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry"].ToArray(); var before = ArchiveStore.Fingerprint(data.Plan["ServerOutbound"]!);
            remote.LoseOutboundApplyAcknowledgement = failure == "apply-ack"; remote.LoseOutboundCommitAcknowledgement = failure == "commit-ack";
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new RealityLifecycleValidation(failure));
            Exception? error = null; TaskOutcome? outcome = null;
            try { outcome = await engine.ExecuteAsync(new(OperationKind.ServerOutbound, data.Relative, ServerOutboundRouting.Options(data.State, role, "Apply", data.Scheme, data.Node, "198.51.100.20", policy)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { error = e; }
            var after = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "deployment-plan.json"));
            Check(remote.ProtocolConfigs[role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry"].SequenceEqual(sibling) && remote.ArmedComponents == role && remote.Commands.Count(c => c == "server-outbound-apply.sh") == 1, "policy task changed sibling or replayed mutation");
            if (failure is "none" or "commit-ack") Check(error == null && outcome == (failure == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings) && ArchiveStore.Fingerprint(after.At("ServerOutbound." + role + ".DestinationRules")!) == ArchiveStore.Fingerprint(policy), "policy not archived after commit/reconciliation");
            else Check(error != null && remote.ProtocolConfigs[role].SequenceEqual(original) && ArchiveStore.Fingerprint(after["ServerOutbound"]!) == before, "failed policy task did not restore old route");
        }
        foreach (var role in ServerOutboundRouting.Roles)
        foreach (var kind in new[] { OperationKind.Upgrade, OperationKind.RotateCredentials })
        {
            var data = RealityFixture(f, "Rules-life-" + role + "-" + kind, true); SaveDestinationPolicy(f, data, role, policy);
            var remote = RoutingRemote(data); var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new RealityLifecycleValidation("none")); var options = new JsonObject { ["Scope"] = "Protocol", ["Protocol"] = role };
            if (kind == OperationKind.Upgrade) options["TargetVersion"] = role == "RealityEntry" ? f.Versions.Text("xray.version") : f.Versions.Text("sing_box.version");
            Check(await engine.ExecuteAsync(new(kind, data.Relative, options), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "maintenance with destination rules failed");
            var after = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "deployment-plan.json")); ServerOutboundRouting.VerifyManaged(role, JsonNode.Parse(remote.ProtocolConfigs[role])!.AsObject(), after);
            Check(ArchiveStore.Fingerprint(after["ServerOutbound"]!) == ArchiveStore.Fingerprint(data.Plan["ServerOutbound"]!), "maintenance changed routing policy");
            if (kind == OperationKind.RotateCredentials)
            {
                var backup = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "operation-pending.dotnet.json")).Text("TaskId");
                foreach (var component in ServerOutboundRouting.Roles) remote.RestoreProtocolConfigs[component] = File.ReadAllBytes(SafePath.Resolve(data.Directory, "maintenance-backups/" + backup + "/artifacts/" + ServerOutboundRouting.ConfigRelative(component)));
                Check(await engine.ExecuteAsync(new(OperationKind.Restore, data.Relative, new JsonObject { ["Scope"] = "Protocol", ["Backup"] = FakeRemote.Backup, ["RestoreMode"] = "ConfigOnly" }), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "configuration restore with destination rules failed");
                var restored = ArchiveStore.ReadJson(SafePath.Resolve(data.Directory, "deployment-plan.json")); ServerOutboundRouting.VerifyManaged(role, JsonNode.Parse(remote.ProtocolConfigs[role])!.AsObject(), restored);
                Check(ArchiveStore.Fingerprint(restored["ServerOutbound"]!) == ArchiveStore.Fingerprint(data.Plan["ServerOutbound"]!), "configuration restore lost destination policy");
            }
        }
    }
}
