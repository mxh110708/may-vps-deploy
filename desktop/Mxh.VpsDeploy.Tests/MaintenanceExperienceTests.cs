using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task MaintenanceExperience(Fixture f)
    {
        var unopened = f.Paths.Resolve("unopened-app"); Directory.CreateDirectory(unopened); var unopenedPaths = new AppPaths(unopened);
        Check(new TaskHistory(new ArchiveStore(unopenedPaths, new TestProtector())).Read().Count == 0 && !Directory.Exists(unopenedPaths.Private), "empty history read created private runtime files");
        var plan = f.Plan("Maintenance-Boundaries"); f.SaveInstance(plan); var relative = f.Relative(plan);
        var state = new JsonObject { ["KomariInstalled"] = false, ["KomariController"] = new JsonObject { ["Installed"] = true }, ["Cloudflared"] = new JsonObject { ["Installed"] = true } };
        plan.Put("Komari.Enabled", JsonValue.Create(true));
        var monitoring = MaintenanceTargets.Monitoring(plan, state);
        Check(!monitoring.Single(t => t.Scope == "KomariAgent").Installed && monitoring.Count(t => t.Installed) == 2, "explicit missing Agent overridden by plan");
        plan.Put("ProtocolInventory.AnyTlsEntry", new JsonObject { ["Installed"] = true, ["Enabled"] = false });
        plan.Put("ProtocolInventory.ShadowsocksLanding", new JsonObject { ["Installed"] = true, ["Enabled"] = true });
        var targets = MaintenanceTargets.ProxyCores(plan, f.Versions);
        Check(targets.Count == 3 && targets.Select(t => t.Service).Distinct().Count() == 3, "distinct proxy service targets collapsed");
        Check(targets.Single(t => t.Protocol == "ShadowsocksLanding").TargetVersion == f.Versions.Text("sing_box.version"), "proxy target version not pinned");
        plan.Put("ProtocolInventory.RealityEntry.Installed", JsonValue.Create(false));
        Check(MaintenanceTargets.ProxyCores(plan, f.Versions).All(t => t.Protocol != "RealityEntry"), "removed default protocol still offered");
        var agent = new OperationRequest(OperationKind.Komari, relative, new() { ["Scope"] = "KomariAgent", ["Action"] = "Upgrade", ["TargetVersion"] = f.Versions.Text("komari_agent.version") });
        Refuses(() => MaintenanceTargets.Validate(agent, plan, state, f.Versions), "unmanaged Agent upgrade allowed");
        Refuses(() => OperationPolicy.Validate(agent with { Options = new() { ["Scope"] = "KomariAgent", ["Action"] = "Upgrade", ["Protocol"] = "ShadowsocksLanding" } }), "protocol mixed into monitoring accepted");
        Refuses(() => OperationPolicy.Validate(new(OperationKind.Upgrade, relative, new() { ["Scope"] = "KomariAgent" })), "Agent offered in proxy upgrade");
        OperationPolicy.Validate(new(OperationKind.Komari, relative, new() { ["Scope"] = "Tunnel", ["Action"] = "Upgrade", ["TargetVersion"] = f.Versions.Text("cloudflared.version") }));
        var core = new OperationRequest(OperationKind.Upgrade, relative, new() { ["Scope"] = "Protocol", ["Protocol"] = "ShadowsocksLanding", ["TargetVersion"] = f.Versions.Text("sing_box.version") });
        MaintenanceTargets.Validate(core, plan, state, f.Versions);
        Refuses(() => MaintenanceTargets.Validate(core with { Options = new() { ["Scope"] = "Protocol", ["Protocol"] = "AnyTlsEntry", ["TargetVersion"] = f.Versions.Text("sing_box.version") } }, plan, state, f.Versions), "inactive service upgrade allowed");
        core.Options["TargetVersion"] = "0.0.1"; Refuses(() => MaintenanceTargets.Validate(core, plan, state, f.Versions), "stale version target accepted");
        var controller = new OperationRequest(OperationKind.Komari, relative, new() { ["Scope"] = "KomariController", ["Action"] = "Restore" });
        Refuses(() => MaintenanceTargets.Validate(controller, plan, state, f.Versions), "controller restore without backup accepted");
        Check(OperationPolicy.Summary(agent).Contains("Agent") && !OperationPolicy.Summary(agent).Contains("Shadowsocks"), "monitor review mixes proxy scope");
        var remote = new FakeRemote(); var before = remote.Commands.Count;
        await RefusesAsync(() => f.Engine(remote).ExecuteAsync(agent, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "missing Agent sent remote mutation");
        Check(remote.Commands.Count == before && remote.Mutations == 0, "unmanaged monitor touched server");
        var agentPlan = f.Plan("Agent-Upgrade-Scope"); f.SaveInstance(agentPlan); var agentRelative = f.Relative(agentPlan);
        var stateFile = SafePath.Resolve(f.Paths.Instance(agentRelative), "deployment-state.json"); var agentState = ArchiveStore.ReadJson(stateFile); agentState["KomariInstalled"] = true; ArchiveStore.WriteJson(stateFile, agentState);
        var agentRequest = agent with { InstanceRelativePath = agentRelative }; var agentRemote = new FakeRemote();
        Check(await f.Engine(agentRemote).ExecuteAsync(agentRequest, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "scoped Agent upgrade failed");
        Check(agentRemote.ArmedComponents == "KomariAgent" && !agentRemote.Commands.Any(c => c is "xray-install.sh" or "sing-box-install.sh" or "protocol-lifecycle-apply-state.sh"), "monitor upgrade touched proxy services");
        Check(ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(agentRelative), "deployment-plan.json")).Text("Komari.AgentVersion") == f.Versions.Text("komari_agent.version"), "Agent upgrade version not archived");
        var missingRemote = new FakeRemote { MonitoringPresent = false };
        await RefusesAsync(() => f.Engine(missingRemote).ExecuteAsync(agentRequest, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "missing remote monitor accepted");
        Check(missingRemote.Mutations == 0, "missing monitor armed mutation before preflight");

        foreach (var failCommit in new[] { false, true })
        {
            var tunnelPlan = f.Plan(failCommit ? "Tunnel-Token-Rollback" : "Tunnel-Token-Commit"); f.SaveInstance(tunnelPlan);
            var tunnelRelative = f.Relative(tunnelPlan); var tunnelDirectory = f.Paths.Instance(tunnelRelative);
            var tunnelStateFile = SafePath.Resolve(tunnelDirectory, "deployment-state.json");
            var tunnelState = ArchiveStore.ReadJson(tunnelStateFile); tunnelState["Cloudflared"] = FakeRemote.HealthService(true, true, true); ArchiveStore.WriteJson(tunnelStateFile, tunnelState);
            var tunnelSecretsFile = SafePath.Resolve(tunnelDirectory, "secrets.dotnet.private.json");
            var oldSecrets = f.Store.ReadSecret(tunnelSecretsFile); oldSecrets["Cloudflared"] = new JsonObject { ["Token"] = "synthetic-old-tunnel-token", ["Preserved"] = "fixture" }; f.Store.WriteSecret(tunnelSecretsFile, oldSecrets);
            var taskId = Guid.NewGuid().ToString("N");
            var tunnelRemote = new FakeRemote { StatusTaskId = taskId, StatusPhase = "Armed", FailAsset = failCommit ? "maintenance-transaction-commit.sh" : "" };
            tunnelRemote.HealthAudit.Put("Services.Cloudflared", FakeRemote.HealthService(true, true, true)); tunnelRemote.SeedProtocols(tunnelPlan);
            var tunnelEngine = new WorkflowEngine(f.Store, tunnelRemote, new FakeKeys(), new FakeUser(_ => "synthetic-updated-tunnel-token"), new FakeValidation());
            var tokenRequest = new OperationRequest(OperationKind.Komari, tunnelRelative, new() { ["Scope"] = "Tunnel", ["Action"] = "RotateToken" });
            if (failCommit) await RefusesAsync(() => tunnelEngine.ExecuteAsync(tokenRequest, taskId, new InlineProgress<TaskProgress>(_ => { }), default), "failed Tunnel commit was accepted");
            else Check(await tunnelEngine.ExecuteAsync(tokenRequest, taskId, new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "Tunnel Token update failed");
            var archived = f.Store.ReadSecret(tunnelSecretsFile);
            Check(archived.Text("Cloudflared.Token") == (failCommit ? "synthetic-old-tunnel-token" : "synthetic-updated-tunnel-token"), "Tunnel Token archive disagrees with committed or rolled-back value");
            Check(archived.Text("Cloudflared.Preserved") == "fixture" && archived["Xray"]!.ToJsonString() == oldSecrets["Xray"]!.ToJsonString(), "Tunnel update changed other private fields");
            Check(tunnelRemote.ArmedComponents == "Cloudflared", "Tunnel credential snapshot included unrelated components");
            if (failCommit) Check(ArchiveStore.ReadJson(SafePath.Resolve(tunnelDirectory, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack" && tunnelRemote.Commands.Count(asset => asset == "maintenance-transaction-commit.sh") == 1, "Tunnel failure replayed commit or failed to verify rollback");
        }

        var history = new TaskHistory(f.Store); var started = DateTimeOffset.UtcNow;
        var recoveryFile = SafePath.Resolve(f.Paths.Instance(relative), "operation-pending.dotnet.json");
        ArchiveStore.WriteJson(recoveryFile, new JsonObject { ["TaskId"] = "recovery-fixture", ["Phase"] = "Armed" });
        var exportFile = f.Paths.Resolve("private/client-publish/history-fixture/transaction.json");
        ArchiveStore.WriteJson(exportFile, new JsonObject { ["Phase"] = "Prepared" });
        var files = new[] { recoveryFile, exportFile, SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json"), SafePath.Resolve(f.Paths.Instance(relative), "secrets.dotnet.private.json") };
        var hashes = files.Select(ClientSchemes.SourceFingerprint).ToArray();
        f.Store.AppendHistory(new("history-first", OperationKind.HealthAudit, started, started, TaskOutcome.Completed, "health", InstanceRelativePath: relative));
        f.Store.AppendHistory(new("history-second", OperationKind.Komari, started, started, TaskOutcome.NeedsRecovery, "verify", InstanceRelativePath: relative));
        var deletion = history.ReviewDeletion("history-first"); history.Delete(deletion);
        Check(history.Read().All(r => r.Text("Id") != "history-first") && history.Read().Any(r => r.Text("Id") == "history-second"), "single deletion cleared other records");
        deletion = history.ReviewDeletion(); f.Store.AppendHistory(new("history-new", OperationKind.HealthAudit, started, started, TaskOutcome.Completed, "health"));
        Refuses(() => history.Delete(deletion), "stale clear erased new records");
        history.Delete(history.ReviewDeletion()); Check(history.Read().Count == 0, "clear left records");
        Check(files.Select(ClientSchemes.SourceFingerprint).SequenceEqual(hashes), "clearing history deleted recovery or private archive");
        f.Store.AppendHistory(new("history-running", OperationKind.HealthAudit, started, null, TaskOutcome.Running, "health", InstanceRelativePath: relative));
        using (f.Store.LockInstanceGuard(relative)) Refuses(() => history.ReviewDeletion(), "active task deleted from history");
        history.Delete(history.ReviewDeletion()); Check(history.Read().Count == 0, "stale running record cannot be cleared");
        var historyFile = f.Paths.Resolve("private/task-history.dotnet.json"); File.WriteAllText(historyFile, "invalid JSON");
        Refuses(() => history.ReviewDeletion(), "invalid history silently destroyed"); Check(File.ReadAllText(historyFile) == "invalid JSON", "invalid history changed");
        ArchiveStore.WriteJson(historyFile, new JsonArray());
        using (var busy = new FileStream(f.Paths.Resolve("private/task-history.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None)) Refuses(() => f.Store.AppendHistory(new("busy", OperationKind.HealthAudit, started, null, TaskOutcome.Running, "health")), "history lock bypassed");
    }
}
