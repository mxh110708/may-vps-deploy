using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private sealed record RealityRouteFixture(JsonObject Plan, JsonObject State, JsonObject Secrets, JsonObject Scheme, JsonObject Node, JsonObject Baseline, string Relative, string Directory);
    private RealityRouteFixture RealityFixture(Fixture f, string name, bool chained = false)
    {
        var plan = f.Plan(name); plan["Roles"] = new JsonArray("RealityEntry", "AnyTlsEntry"); plan["ActiveEntry"] = "RealityEntry";
        plan.Put("Server.IPv6", JsonValue.Create("2001:db8::10")); plan.Put("Ports.AnyTlsPrimary", JsonValue.Create(24443));
        plan.Put("AnyTls.ServerName", JsonValue.Create("entry.example.com")); plan.Put("Reality.XrayVersion", JsonValue.Create("26.3.26"));
        plan["ProtocolInventory"] = new JsonObject { ["RealityEntry"] = new JsonObject { ["Installed"] = true, ["Enabled"] = true }, ["AnyTlsEntry"] = new JsonObject { ["Installed"] = true, ["Enabled"] = true } };
        f.SaveInstance(plan); var relative = f.Relative(plan); var directory = f.Paths.Instance(relative);
        var secrets = Fixture.RealitySecrets(); secrets["AnyTls"] = new JsonObject { ["Password"] = "synthetic-reality-sibling", ["EchClientConfigPem"] = "synthetic-ech" };
        f.Store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), secrets);
        var scheme = ClientSchemes.New(f.Paths); var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Round4 landing", ["kind"] = "landing", ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["tag"] = "Round4 landing", ["server"] = "192.0.2.20", ["server_port"] = 20001, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = ServerConfigurations.RandomKey() + ":" + ServerConfigurations.RandomKey() }, ["Egress"] = new JsonObject { ["ExpectedAddress"] = "198.51.100.20", ["Family"] = "IPv4" } };
        scheme["Nodes"] = new JsonArray(node); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); state.Put("Modules.deployment-commit.Status", JsonValue.Create("Success"));
        var baseline = ServerConfigurations.Xray(plan, secrets);
        foreach (var role in ServerOutboundRouting.Roles)
        {
            var config = role == "RealityEntry" ? baseline : ServerConfigurations.AnyTls(plan, secrets);
            if (role == "AnyTlsEntry" || chained)
            {
                var origin = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id") };
                var preview = ServerOutboundRouting.Build(role, config, null, node, role == "RealityEntry" ? "198.51.100.20" : "198.51.100.30", plan, origin);
                config = preview.Configuration; plan.Put("ServerOutbound." + role, preview.Metadata!.DeepClone()); state.Put("ServerOutboundValidation." + role, new JsonObject { ["Status"] = "Passed", ["Marker"] = role });
            }
            var file = SafePath.Resolve(directory, ServerOutboundRouting.ConfigRelative(role)); ArchiveStore.WriteJson(file, config); state.Put("ServerConfigHashes." + role, JsonValue.Create(ClientSchemes.SourceFingerprint(file)));
        }
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state);
        return new(plan, state, secrets, scheme, node, baseline, relative, directory);
    }
    private static FakeRemote RoutingRemote(RealityRouteFixture data)
    {
        var remote = new FakeRemote(); remote.SeedProtocols(data.Plan);
        foreach (var role in ServerOutboundRouting.Roles) remote.ProtocolConfigs[role] = File.ReadAllBytes(SafePath.Resolve(data.Directory, ServerOutboundRouting.ConfigRelative(role)));
        return remote;
    }
    public async Task RunRealityOutboundTests()
    {
        using var f = new Fixture(repository); await RealityOutboundExperience(f); await RealityOutboundLoopback(f);
        Console.WriteLine($"PASS: {assertions} Reality routing, source status and lifecycle assertions; no production connections.");
    }
    private async Task RealityOutboundExperience(Fixture f)
    {
        var data = RealityFixture(f, "Reality-preview");
        var request = new OperationRequest(OperationKind.ServerOutbound, data.Relative, ServerOutboundRouting.Options(data.State, "RealityEntry", "Apply", data.Scheme, data.Node, "2001:db8::20"));
        var preview = ServerOutboundRouting.Prepare(f.Store, request); var config = preview.Configuration; var tags = data.Baseline["inbounds"]!.AsArray().Select(n => n!.Text("tag")).ToArray();
        Check(tags.Length == 4 && config["inbounds"]!.ToJsonString() == data.Baseline["inbounds"]!.ToJsonString(), "Reality listeners/UUID/private keys changed");
        Check(config["routing"]!["rules"]![0]!.Strings("ip").SequenceEqual(["0.0.0.0/0"]) && config["routing"]!["rules"]![1]!.Strings("inboundTag").SequenceEqual(tags), "Reality route did not cover all primary/backup dual-stack listeners");
        Check(config["outbounds"]![2]!.Text("protocol") == "shadowsocks" && config["outbounds"]![2]!["settings"]!["servers"]![0]!.Text("password") == data.Node.Text("sing_box.password"), "SS2022 identity chain lost during Xray translation");
        Check(!preview.Metadata!.ToJsonString().Contains(data.Node.Text("sing_box.password")) && preview.Summary.Contains("主／备用") && preview.Summary.Contains("TCP 与 UDP"), "Reality metadata leaks credentials or review omits scope");
        Check(ArchiveStore.Fingerprint(ServerOutboundRouting.Build("RealityEntry", config, preview.Metadata, null, "", data.Plan).Configuration) == ArchiveStore.Fingerprint(data.Baseline), "Reality removal changed original policy");
        var modified = config.DeepClone().AsObject(); modified["outbounds"]![2]!["settings"]!["servers"]![0]!["password"] = "external edit";
        Refuses(() => ServerOutboundRouting.Build("RealityEntry", modified, preview.Metadata, null, "", data.Plan), "Reality owned outbound drift overwritten");
        Refuses(() => ServerOutboundRouting.Build("RealityEntry", config, null, data.Node, "198.51.100.20", data.Plan), "Reality reserved tag adopted without ownership");
        modified = data.Baseline.DeepClone().AsObject(); modified["inbounds"]!.AsArray().RemoveAt(0);
        Refuses(() => ServerOutboundRouting.Build("RealityEntry", modified, null, data.Node, "198.51.100.20", data.Plan), "missing Reality listener collapsed silently");
        modified = data.Baseline.DeepClone().AsObject(); modified["inbounds"]![0]!["port"] = 30000;
        Refuses(() => ServerOutboundRouting.Build("RealityEntry", modified, null, data.Node, "198.51.100.20", data.Plan), "Reality port drift accepted");
        modified = data.Baseline.DeepClone().AsObject(); modified["routing"]!["rules"]!.AsArray().Add(new JsonObject { ["type"] = "field", ["domain"] = new JsonArray("example.com"), ["outboundTag"] = "direct" });
        Refuses(() => ServerOutboundRouting.Build("RealityEntry", modified, null, data.Node, "198.51.100.20", data.Plan), "Reality custom routing rewritten");
        Check(ServerOutboundRouting.SourceStatus(f.Store, preview.Metadata).Matches, "matching source shown stale");
        var managedPlan = f.Plan("Round4-managed-landing"); managedPlan["Role"] = "ShadowsocksLanding"; managedPlan["Roles"] = new JsonArray("ShadowsocksLanding"); managedPlan.Put("Server.IPv4", JsonValue.Create("192.0.2.40"));
        managedPlan.Put("Shadowsocks.Method", JsonValue.Create("2022-blake3-aes-128-gcm")); managedPlan.Put("Ports.LandingShadowsocks", JsonValue.Create(20001)); managedPlan["Import"] = new JsonObject { ["Status"] = "Completed" }; f.SaveInstance(managedPlan);
        var managedSecrets = new JsonObject { ["Shadowsocks"] = new JsonObject { ["ServerKey"] = ServerConfigurations.RandomKey(), ["PrimaryUserKey"] = ServerConfigurations.RandomKey() } };
        var managedSecretFile = SafePath.Resolve(f.Paths.Instance(f.Relative(managedPlan)), "secrets.dotnet.private.json"); f.Store.WriteSecret(managedSecretFile, managedSecrets);
        var managedProfile = ClientProfiles.Nodes(managedPlan, managedSecrets).First(); var managedNode = data.Node.DeepClone().AsObject(); managedNode["sing_box"] = managedProfile.SingBox.DeepClone(); managedNode["ManagedOrigin"] = ManagedNodeSources.Origin(f.Relative(managedPlan), managedProfile);
        var managedScheme = ClientSchemes.New(f.Paths); managedScheme["Nodes"] = new JsonArray(managedNode); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, managedScheme.Text("Id")), managedScheme);
        var managedOptions = ServerOutboundRouting.Options(data.State, "RealityEntry", "Apply", managedScheme, managedNode, "198.51.100.20");
        var managedPreview = ServerOutboundRouting.Prepare(f.Store, new(OperationKind.ServerOutbound, data.Relative, managedOptions));
        Check(ServerOutboundRouting.SourceStatus(f.Store, managedPreview.Metadata!).Matches, "unchanged managed landing shown stale");
        managedSecrets.Put("Shadowsocks.PrimaryUserKey", JsonValue.Create(ServerConfigurations.RandomKey())); f.Store.WriteSecret(managedSecretFile, managedSecrets);
        Check(ServerOutboundRouting.SourceStatus(f.Store, managedPreview.Metadata!).Code == "ManagedChanged", "rotated managed credentials not reported without altering the saved node");
        Refuses(() => ServerOutboundRouting.Prepare(f.Store, new(OperationKind.ServerOutbound, data.Relative, managedOptions)), "stale managed credentials accepted for a new server route");
        data.Node["name"] = "Changed source name"; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, data.Scheme.Text("Id")), data.Scheme);
        Check(ServerOutboundRouting.SourceStatus(f.Store, preview.Metadata).Code == "Changed" && !data.Plan.ContainsKey("ServerOutbound.RealityEntry"), "source change not detected or applied remotely");
        data.Scheme["Nodes"]!.AsArray().Clear(); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, data.Scheme.Text("Id")), data.Scheme);
        Check(ServerOutboundRouting.SourceStatus(f.Store, preview.Metadata).Code == "Missing", "removed source node not reported");
        File.Delete(ServerOutboundRouting.SchemeFile(f.Paths, data.Scheme.Text("Id")));
        Check(ServerOutboundRouting.SourceStatus(f.Store, preview.Metadata).Code == "Missing", "removed source scheme not reported");
        var invalid = request.Options.DeepClone().AsObject(); invalid["Protocol"] = "ShadowsocksLanding";
        Refuses(() => ServerOutboundRouting.ValidateOptions(invalid), "unsupported source role accepted");

        foreach (var failure in new[] { "none", "remote-drift", "apply-ack", "commit-ack", "partial", "cancel", "validation" })
        {
            var fixture = RealityFixture(f, "Reality-" + failure); var remote = RoutingRemote(fixture); var original = remote.ProtocolConfigs["RealityEntry"].ToArray(); var sibling = remote.ProtocolConfigs["AnyTlsEntry"].ToArray(); var siblingMeta = ArchiveStore.Fingerprint(fixture.Plan["ServerOutbound"]!["AnyTlsEntry"]!);
            if (failure == "remote-drift") remote.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes(fixture.Baseline.ToJsonString());
            remote.LoseOutboundApplyAcknowledgement = failure == "apply-ack"; remote.LoseOutboundCommitAcknowledgement = failure == "commit-ack";
            var validator = new RealityLifecycleValidation(failure); var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), validator);
            var operation = new OperationRequest(OperationKind.ServerOutbound, fixture.Relative, ServerOutboundRouting.Options(fixture.State, "RealityEntry", "Apply", fixture.Scheme, fixture.Node, "2001:db8::20"));
            TaskOutcome? outcome = null; Exception? error = null;
            try { outcome = await engine.ExecuteAsync(operation, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None); } catch (Exception e) { error = e; }
            var after = ArchiveStore.ReadJson(SafePath.Resolve(fixture.Directory, "deployment-plan.json"));
            Check(remote.ProtocolConfigs["AnyTlsEntry"].SequenceEqual(sibling) && ArchiveStore.Fingerprint(after["ServerOutbound"]!["AnyTlsEntry"]!) == siblingMeta, "Reality operation changed sibling AnyTLS route");
            if (failure is "none" or "commit-ack")
            {
                Check(error == null && outcome == (failure == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings) && remote.ArmedComponents == "RealityEntry", "Reality success/commit reconciliation failed");
                Check(after.Text("ServerOutbound.RealityEntry.EgressFamily") == "IPv6" && validator.EgressByRole["RealityEntry"] == "IPv6", "Reality acceptance still expected entry IPv4");
                Check(remote.Commands.Count(c => c == "server-outbound-apply.sh") == 1 && !remote.Commands.Any(c => c.Contains("firewall") || c.Contains("komari")), "Reality write replayed or expanded scope");
            }
            else if (failure == "remote-drift") Check(error is OperationException && remote.Mutations == 0, "Reality drift not stopped before mutation");
            else Check(error != null && remote.ProtocolConfigs["RealityEntry"].SequenceEqual(original) && after.At("ServerOutbound.RealityEntry") == null && remote.Commands.Count(c => c == "server-outbound-apply.sh") == 1, "Reality failed route not recovered exactly once");
        }
        foreach (var role in ServerOutboundRouting.Roles)
        foreach (var operationKind in new[] { OperationKind.RotateCredentials, OperationKind.Upgrade })
        {
            var fixture = RealityFixture(f, "Life-" + role + "-" + operationKind, true); var remote = RoutingRemote(fixture); var beforeRoutes = ArchiveStore.Fingerprint(fixture.Plan["ServerOutbound"]!); var beforeOther = remote.ProtocolConfigs[role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry"].ToArray();
            var beforeInboundCredential = fixture.Secrets.Text(role == "RealityEntry" ? "Xray.Uuid" : "AnyTls.Password"); var validator = new RealityLifecycleValidation("none");
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), validator);
            var options = new JsonObject { ["Scope"] = "Protocol", ["Protocol"] = role }; if (operationKind == OperationKind.Upgrade) options["TargetVersion"] = role == "RealityEntry" ? f.Versions.Text("xray.version") : f.Versions.Text("sing_box.version");
            Check(await engine.ExecuteAsync(new(operationKind, fixture.Relative, options), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None) == TaskOutcome.Completed, "route lifecycle did not complete");
            var after = ArchiveStore.ReadJson(SafePath.Resolve(fixture.Directory, "deployment-plan.json"));
            Check(ArchiveStore.Fingerprint(after["ServerOutbound"]!) == beforeRoutes && remote.ProtocolConfigs[role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry"].SequenceEqual(beforeOther), "upgrade/rotation changed route or sibling config");
            foreach (var component in ServerOutboundRouting.Roles) ServerOutboundRouting.VerifyManaged(component, JsonNode.Parse(remote.ProtocolConfigs[component])!.AsObject(), after);
            Check(validator.EgressByRole[role] == "IPv4", "lifecycle egress expectation not retained");
            if (operationKind == OperationKind.RotateCredentials)
            {
                var credentials = f.Store.ReadSecret(SafePath.Resolve(fixture.Directory, "secrets.dotnet.private.json"));
                Check(credentials.Text(role == "RealityEntry" ? "Xray.Uuid" : "AnyTls.Password") != beforeInboundCredential, "rotation did not update actual inbound credential"); credentials.Clear();
                foreach (var component in ServerOutboundRouting.Roles) remote.RestoreProtocolConfigs[component] = File.ReadAllBytes(SafePath.Resolve(fixture.Directory, "maintenance-backups/" + ArchiveStore.ReadJson(SafePath.Resolve(fixture.Directory, "operation-pending.dotnet.json")).Text("TaskId") + "/artifacts/" + ServerOutboundRouting.ConfigRelative(component)));
                var restore = new OperationRequest(OperationKind.Restore, fixture.Relative, new JsonObject { ["Scope"] = "Protocol", ["Backup"] = FakeRemote.Backup, ["RestoreMode"] = "ConfigOnly" });
                Check(await engine.ExecuteAsync(restore, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None) == TaskOutcome.Completed, "protocol restore with fixed routes failed");
                var restoredPlan = ArchiveStore.ReadJson(SafePath.Resolve(fixture.Directory, "deployment-plan.json"));
                Check(ArchiveStore.Fingerprint(restoredPlan["ServerOutbound"]!) == beforeRoutes, "manual restore dropped fixed route metadata");
            }
        }
        foreach (var failure in new[] { "partial", "upgrade-corrupt", "preexisting-drift" })
        {
            var fixture = RealityFixture(f, "Life-fail-" + failure, true); var remote = RoutingRemote(fixture); var original = remote.ProtocolConfigs["RealityEntry"].ToArray(); var metadata = ArchiveStore.Fingerprint(fixture.Plan["ServerOutbound"]!);
            remote.CorruptRouteOnUpgrade = failure == "upgrade-corrupt";
            if (failure == "preexisting-drift") remote.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes(JsonNode.Parse(original)!.ToJsonString());
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new RealityLifecycleValidation(failure == "partial" ? "partial" : "none"));
            var operation = new OperationRequest(OperationKind.Upgrade, fixture.Relative, new JsonObject { ["Scope"] = "Protocol", ["Protocol"] = "RealityEntry", ["TargetVersion"] = f.Versions.Text("xray.version") });
            await RefusesAsync(() => engine.ExecuteAsync(operation, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None), "unverified/damaged route upgrade committed");
            if (failure == "preexisting-drift") Check(remote.Mutations == 0, "lifecycle drift mutated server");
            else Check(remote.ProtocolConfigs["RealityEntry"].SequenceEqual(original) && ArchiveStore.Fingerprint(ArchiveStore.ReadJson(SafePath.Resolve(fixture.Directory, "deployment-plan.json"))["ServerOutbound"]!) == metadata, "failed lifecycle did not recover route");
        }
    }
    private sealed class RealityLifecycleValidation(string failure) : IProtocolValidation
    {
        public Dictionary<string, string> EgressByRole { get; } = new();
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject secrets, string privateDirectory, IUserInteraction user, IProgress<string> progress, CancellationToken cancellationToken)
        {
            foreach (var node in ClientProfiles.Nodes(plan, secrets, true)) EgressByRole[node.Role] = node.EgressFamily;
            if (failure == "cancel") throw new OperationCanceledException();
            if (failure == "validation") throw new OperationException("synthetic wrong egress");
            return Task.FromResult(new JsonObject { ["Status"] = failure == "partial" ? "Incomplete" : "Passed" });
        }
        public void Export(JsonObject plan, JsonObject secrets, string directory) => ClientProfiles.Export(plan, secrets, directory);
    }
}
