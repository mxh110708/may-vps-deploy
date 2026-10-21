using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunServerOutboundTests()
    {
        using var f = new Fixture(repository); await ServerOutboundExperience(f); await ServerOutboundLoopback(f);
        Console.WriteLine($"PASS: {assertions} server outbound boundary and workflow assertions; no production connections.");
    }
    private async Task ServerOutboundExperience(Fixture f)
    {
        (JsonObject Plan, JsonObject State, JsonObject Secrets, JsonObject Config, JsonObject Scheme, JsonObject Node, string Relative) Create(string name)
        {
            var plan = f.Plan(name); plan["Role"] = "AnyTlsEntry"; plan["Roles"] = new JsonArray("AnyTlsEntry"); plan["ActiveEntry"] = "AnyTlsEntry";
            plan.Put("AnyTls.ServerName", JsonValue.Create("entry.example.com")); plan.Put("ProtocolInventory.AnyTlsEntry", new JsonObject { ["Installed"] = true, ["Enabled"] = true });
            f.SaveInstance(plan); var relative = f.Relative(plan); var directory = f.Paths.Instance(relative);
            var secrets = Fixture.RealitySecrets(); secrets["AnyTls"] = new JsonObject { ["Password"] = "synthetic-entry-password", ["EchClientConfigPem"] = "synthetic-ech" };
            f.Store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), secrets);
            var config = ServerConfigurations.AnyTls(plan, secrets); var file = SafePath.Resolve(directory, ServerOutboundRouting.ConfigRelative("AnyTlsEntry")); ArchiveStore.WriteJson(file, config);
            var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); state.Put("Modules.deployment-commit.Status", JsonValue.Create("Success")); state.Put("ServerConfigHashes.AnyTlsEntry", JsonValue.Create(ClientSchemes.SourceFingerprint(file))); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state);
            var scheme = ClientSchemes.New(f.Paths); var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Synthetic landing", ["kind"] = "landing", ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["tag"] = "Synthetic landing", ["server"] = "192.0.2.20", ["server_port"] = 20001, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = ServerConfigurations.RandomKey() + ":" + ServerConfigurations.RandomKey() } };
            scheme["Nodes"] = new JsonArray(node); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            return (plan, state, secrets, config, scheme, node, relative);
        }
        var source = Create("Outbound-preview"); var before = ArchiveStore.Fingerprint(source.Config);
        var options = ServerOutboundRouting.Options(source.State, "AnyTlsEntry", "Apply", source.Scheme, source.Node, "198.51.100.20"); var request = new OperationRequest(OperationKind.ServerOutbound, source.Relative, options);
        var preview = ServerOutboundRouting.Prepare(f.Store, request);
        Check(ArchiveStore.Fingerprint(source.Config) == before && preview.Configuration["inbounds"]!.ToJsonString() == source.Config["inbounds"]!.ToJsonString(), "fixed route mutated source/listener/auth/TLS");
        Check(preview.Configuration["route"]!["rules"]![1]!.Text("outbound") == ServerOutboundRouting.Tag && preview.Configuration["route"]!.Text("final") == "direct", "fixed route does not override selected inbound before original rules");
        Check(preview.Configuration["route"]!["rules"]![0]!.Number("ip_version") == 6 && !preview.Metadata!.ToJsonString().Contains(source.Node.Text("sing_box.password")), "egress restriction missing or credentials leaked into metadata");
        var v6 = ServerOutboundRouting.Build("AnyTlsEntry", source.Config, null, source.Node, "2001:db8::20", source.Plan);
        Check(v6.Configuration["route"]!["rules"]![0]!.Number("ip_version") == 4 && v6.Metadata!.Text("EgressFamily") == "IPv6", "v6 route did not reject opposite address family");
        var restored = ServerOutboundRouting.Build("AnyTlsEntry", preview.Configuration, preview.Metadata, null, "", source.Plan);
        Check(ArchiveStore.Fingerprint(restored.Configuration) == before, "remove did not preserve original policy/configuration");
        var altered = preview.Configuration.DeepClone().AsObject(); altered["outbounds"]![1]!["password"] = "external edit";
        Refuses(() => ServerOutboundRouting.Build("AnyTlsEntry", altered, preview.Metadata, null, "", source.Plan), "route drift overwritten on removal");
        Refuses(() => ServerOutboundRouting.Build("AnyTlsEntry", preview.Configuration, null, source.Node, "198.51.100.20", source.Plan), "unmanaged reserved tag adopted");
        var custom = source.Config.DeepClone().AsObject(); custom["route"]!["rules"]!.AsArray().Add(new JsonObject { ["domain"] = new JsonArray("example.com"), ["action"] = "route", ["outbound"] = "direct" });
        Refuses(() => ServerOutboundRouting.Build("AnyTlsEntry", custom, null, source.Node, "198.51.100.20", source.Plan), "custom route silently reordered");
        var extended = source.Node.DeepClone().AsObject(); extended["sing_box"]!["detour"] = "ClientEntry";
        Refuses(() => ServerOutboundRouting.NextHop(extended), "client detour copied into server");
        extended["sing_box"]!.AsObject().Remove("detour"); extended["sing_box"]!["plugin"] = "custom";
        Refuses(() => ServerOutboundRouting.NextHop(extended), "unknown field silently stripped");
        extended["sing_box"]!.AsObject().Remove("plugin"); extended["sing_box"]!["server"] = "127.0.0.1";
        Refuses(() => ServerOutboundRouting.NextHop(extended), "loopback next hop allowed");
        extended["sing_box"]!["server"] = source.Plan.Text("Server.IPv4");
        Refuses(() => ServerOutboundRouting.Build("AnyTlsEntry", source.Config, null, extended, "198.51.100.20", source.Plan), "self route allowed");
        extended["sing_box"]!["server"] = "landing.example.com";
        Refuses(() => ServerOutboundRouting.NextHop(extended), "domain endpoint accepted without remote resolution guard");
        foreach (var invalid in new[] { "169.254.1.1", "0.0.0.1", "fe80::1", "::ffff:127.0.0.1" })
        { extended["sing_box"]!["server"] = invalid; Refuses(() => ServerOutboundRouting.NextHop(extended), "ambiguous/link-local address accepted"); }
        var injected = options.DeepClone().AsObject(); injected["ConfigPath"] = "/etc/other";
        Refuses(() => ServerOutboundRouting.ValidateOptions(injected), "arbitrary remote path accepted");
        var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed)));
        var review = coordinator.Review(request);
        Check(review.Summary.Contains("TCP 与 UDP") && !review.Summary.Contains(source.Node.Text("sing_box.password")) && OperationSteps.Create(request, source.Plan).Count == 6, "review leaks credentials or progress missing");
        source.Node["sing_box"]!["password"] = "source-changed"; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, source.Scheme.Text("Id")), source.Scheme);
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None), "changed source survived review");
        Refuses(() => ServerOutboundRouting.Prepare(f.Store, request), "changed node digest ignored");

        foreach (var failure in new[] { "none", "remote-drift", "apply-ack", "commit-ack", "partial", "cancel", "validation", "archive-edit" })
        {
            var data = Create("Outbound-" + failure); var directory = f.Paths.Instance(data.Relative); var file = SafePath.Resolve(directory, ServerOutboundRouting.ConfigRelative("AnyTlsEntry")); var originalBytes = File.ReadAllBytes(file);
            var remote = new FakeRemote { LoseOutboundApplyAcknowledgement = failure == "apply-ack", LoseOutboundCommitAcknowledgement = failure == "commit-ack" }; remote.ProtocolConfigs["AnyTlsEntry"] = originalBytes.ToArray(); remote.SeedProtocols(data.Plan);
            if (failure == "remote-drift") remote.ProtocolConfigs["AnyTlsEntry"] = Encoding.UTF8.GetBytes(data.Config.ToJsonString());
            var validation = new OutboundValidation(failure, file);
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), validation);
            var operation = new OperationRequest(OperationKind.ServerOutbound, data.Relative, ServerOutboundRouting.Options(data.State, "AnyTlsEntry", "Apply", data.Scheme, data.Node, "2001:db8::20"));
            var id = Guid.NewGuid().ToString("N"); TaskOutcome? outcome = null; Exception? error = null;
            try { outcome = await engine.ExecuteAsync(operation, id, new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None); } catch (Exception e) { error = e; }
            var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json")); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
            if (failure is "none" or "commit-ack")
            {
                Check(outcome == (failure == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings) && error == null, "routing success/commit acknowledgement was not reconciled");
                Check(plan.Text("ServerOutbound.AnyTlsEntry.ExpectedAddress") == "2001:db8::20" && validation.Egress == "IPv6", "route egress not used for acceptance");
                Check(remote.ArmedComponents == "AnyTlsEntry" && remote.Commands.Count(c => c == "server-outbound-apply.sh") == 1 && !remote.Commands.Any(c => c.Contains("firewall") || c.Contains("komari") || c == "protocol-lifecycle-apply-state.sh"), "route expanded/replayed mutation scope");
                Check(state.Text("ServerConfigHashes.AnyTlsEntry") == ArchiveStore.Digest(remote.ProtocolConfigs["AnyTlsEntry"]) && state.Text("ServerOutboundValidation.AnyTlsEntry.Status") == "Passed", "accepted configuration/evidence not archived");
                Check(ClientProfiles.Nodes(plan, data.Secrets, true).All(n => n.EgressFamily == "IPv6") && ServerOutboundRouting.EgressAddress(plan, "AnyTlsEntry", "unused") == "2001:db8::20", "client probe metadata still uses entry egress");
                Check(ManagedNodeSources.Fingerprint(ClientProfiles.Nodes(plan, data.Secrets, true).Single()) != ManagedNodeSources.Fingerprint(ClientProfiles.Nodes(data.Plan, data.Secrets, true).Single()), "server route change did not invalidate old managed source");
                var removal = new OperationRequest(OperationKind.ServerOutbound, data.Relative, ServerOutboundRouting.Options(state, "AnyTlsEntry", "Remove"));
                remote.LoseOutboundCommitAcknowledgement = false;
                Check(await engine.ExecuteAsync(removal, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), CancellationToken.None) == TaskOutcome.Completed, "remove did not commit");
                Check(ArchiveStore.Fingerprint(JsonNode.Parse(remote.ProtocolConfigs["AnyTlsEntry"])!) == ArchiveStore.Fingerprint(data.Config), "remove failed to restore baseline route");
            }
            else if (failure == "remote-drift") Check(error is OperationException && remote.Mutations == 0 && File.ReadAllBytes(file).SequenceEqual(originalBytes), "remote drift was written before rejection");
            else if (failure == "archive-edit") Check(error is OperationException { NeedsRecovery: true } && File.ReadAllText(file) == "external edit", "recovery overwrote concurrent local edit");
            else
            {
                Check(error != null && !plan.ContainsKey("ServerOutbound") && remote.ProtocolConfigs["AnyTlsEntry"].SequenceEqual(originalBytes), "failure did not restore route/meta");
                Check(File.ReadAllBytes(file).SequenceEqual(originalBytes) && remote.Commands.Count(c => c == "server-outbound-apply.sh") == 1 && !state.ContainsKey("ServerOutboundValidation"), "failure replayed mutation or left new evidence");
                Check(ArchiveStore.ReadJson(SafePath.Resolve(directory, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack", "route rollback identity not closed");
            }
        }
    }
    private sealed class OutboundValidation(string failure, string configFile) : IProtocolValidation
    {
        public string Egress { get; private set; } = "";
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject secrets, string privateDirectory, IUserInteraction user, IProgress<string> progress, CancellationToken cancellationToken)
        {
            Egress = ClientProfiles.Nodes(plan, secrets, true).Single().EgressFamily;
            if (failure == "cancel") throw new OperationCanceledException();
            if (failure == "validation") throw new OperationException("synthetic failed egress");
            if (failure == "archive-edit") File.WriteAllText(configFile, "external edit");
            return Task.FromResult(new JsonObject { ["Status"] = failure == "partial" ? "Incomplete" : "Passed" });
        }
        public void Export(JsonObject plan, JsonObject secrets, string directory) => throw new Exception("routing should not rewrite client fragments");
    }
}
