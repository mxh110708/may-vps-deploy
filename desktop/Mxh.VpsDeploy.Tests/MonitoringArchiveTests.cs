using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task MonitoringArchiveExperience(Fixture f)
    {
        var plan = f.Plan("Historical-Monitoring"); f.SaveInstance(plan); var relative = f.Relative(plan);
        var stateFile = SafePath.Resolve(f.Paths.Instance(relative), "deployment-state.json");
        var state = ArchiveStore.ReadJson(stateFile);
        state["KomariController"] = new JsonObject { ["BackupMetadata"] = "preserve-controller-backup" };
        state["Cloudflared"] = new JsonObject { ["OriginMetadata"] = "preserve-tunnel-origin" };
        state["DesktopImport"] = new JsonObject { ["OfflineOnly"] = true, ["KomariAgentLastKnown"] = new JsonObject { ["Installed"] = true, ["CurrentStateVerified"] = false }, ["KomariControllerLastKnown"] = new JsonObject { ["Version"] = "1.5.0-fix1" }, ["CloudflaredLastKnown"] = new JsonObject { ["Installed"] = true } };
        var historical = state["DesktopImport"]!.ToJsonString();
        var targets = MaintenanceTargets.Monitoring(plan, state);
        Check(targets.All(t => !t.Installed && t.RequiresVerification), "offline monitoring silently promoted or inaccessible");
        var request = new OperationRequest(OperationKind.Komari, relative, new() { ["Scope"] = "KomariAgent", ["Action"] = "Upgrade", ["TargetVersion"] = f.Versions.Text("komari_agent.version") });
        Refuses(() => MaintenanceTargets.Validate(request, plan, state, f.Versions), "historical evidence permits a mutation");
        var remote = new FakeRemote(); remote.SeedProtocols(plan); remote.HealthAudit.Put("Services.KomariAgent", FakeRemote.HealthService(true, true, true)); remote.HealthAudit.Put("Services.KomariController", FakeRemote.HealthService(true, false, false));
        remote.HealthAudit["Versions"] = new JsonObject { ["KomariAgent"] = "1.5.11", ["KomariController"] = "Komari Monitor 1.5.0-fix1" };
        var untouched = plan.DeepClone().AsObject(); var oldState = state.DeepClone().AsObject(); var invalid = remote.HealthAudit.DeepClone().AsObject();
        invalid["ChecksIncomplete"] = new JsonArray("systemctl");
        Refuses(() => MonitoringArchives.ApplyHealth(plan, state, invalid), "incomplete read promoted monitoring");
        Check(JsonNode.DeepEquals(plan, untouched) && JsonNode.DeepEquals(state, oldState), "incomplete read partially changed state");
        invalid = remote.HealthAudit.DeepClone().AsObject(); invalid.Put("Services.Cloudflared.Active", JsonValue.Create("unknown"));
        Refuses(() => MonitoringArchives.ApplyHealth(plan, state, invalid), "unavailable component treated as absent");
        Check(JsonNode.DeepEquals(state, oldState), "last malformed component partially changed preceding components");
        ArchiveStore.WriteJson(stateFile, state);
        var protectedFile = SafePath.Resolve(f.Paths.Instance(relative), "secrets.dotnet.private.json");
        var secrets = f.Store.ReadSecret(protectedFile); secrets["Cloudflared"] = new JsonObject { ["Token"] = "synthetic-original-tunnel" }; f.Store.WriteSecret(protectedFile, secrets);
        var health = new OperationRequest(OperationKind.HealthAudit, relative, new());
        Check(await f.Engine(remote).ExecuteAsync(health, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "health did not complete monitoring reconciliation");
        var updatedPlan = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json")); var updated = ArchiveStore.ReadJson(stateFile); var captured = f.Store.ReadSecret(protectedFile);
        Check(updated.Flag("KomariInstalled") && updated.Flag("KomariController.Installed") && !updated.Flag("Cloudflared.Installed"), "current inventory not reconciled");
        Check(updatedPlan.Flag("Komari.Enabled") && updatedPlan.Text("Komari.Endpoint") == remote.AgentConfiguration.Text("endpoint") && updatedPlan.Text("Komari.AgentVersion") == "1.5.11", "Agent plan or actual version missing");
        Check(captured.Text("KomariAgent.Token") == remote.AgentConfiguration.Text("token") && captured.Text("Cloudflared.Token") == "synthetic-original-tunnel", "missing Agent secrets not protected or Tunnel altered");
        Check(!File.ReadAllText(protectedFile).Contains("synthetic-agent-token"), "captured Agent token saved as plaintext");
        Check(updated["DesktopImport"]!.ToJsonString() == historical, "historical evidence rewritten as current");
        Check(updated.Text("KomariController.BackupMetadata") == "preserve-controller-backup" && updated.Text("Cloudflared.OriginMetadata") == "preserve-tunnel-origin", "monitor reconciliation deleted component metadata");
        Check(remote.Commands.SequenceEqual(new[] { "maintenance-health-audit.sh" }) && remote.Mutations == 0, "reconciliation changed a remote service");
        targets = MaintenanceTargets.Monitoring(updatedPlan, updated);
        Check(targets.Single(t => t.Scope == "KomariController").Installed && targets.Single(t => t.Scope == "KomariController").Status.Contains("已停用"), "installed disabled controller cannot be managed");
        Check(!targets.Single(t => t.Scope == "Tunnel").RequiresVerification, "current absence overridden by historical Tunnel");
        updated.Put("MonitoringInventory.KomariController.SupportedLayout", JsonValue.Create(false));
        Check(!MaintenanceTargets.Monitoring(updatedPlan, updated).Single(t => t.Scope == "KomariController").Installed, "unsupported controller layout permits management");
        var stale = remote.HealthAudit.DeepClone().AsObject(); stale["CollectedAt"] = DateTimeOffset.UtcNow.AddDays(-1);
        Refuses(() => MonitoringArchives.ApplyHealth(updatedPlan, updated, stale), "stale inventory overwrote fresh evidence");
        captured.Put("KomariAgent.Token", JsonValue.Create("synthetic-user-change")); var protectedBefore = captured.ToJsonString();
        Check(!MonitoringArchives.SupplementAgent(updatedPlan, captured, remote.AgentConfiguration) && captured.ToJsonString() == protectedBefore, "credential drift overwritten");
        var driftRemote = new FakeRemote(); driftRemote.HealthAudit.Put("Services.KomariAgent", FakeRemote.HealthService(true, true, true)); driftRemote.AgentConfiguration["token"] = "synthetic-remote-change";
        Check(await f.Engine(driftRemote).ExecuteAsync(health, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.CompletedWithWarnings, "credential drift not reported by health");
        var driftState = ArchiveStore.ReadJson(stateFile); var driftSecrets = f.Store.ReadSecret(protectedFile);
        Check(!MaintenanceTargets.Monitoring(updatedPlan, driftState).Single(t => t.Scope == "KomariAgent").Installed && driftSecrets.Text("KomariAgent.Token") == "synthetic-agent-token", "credential drift permits management or overwrites archive");
        var unreadableRemote = new FakeRemote { AgentConfiguration = new() }; unreadableRemote.HealthAudit.Put("Services.KomariAgent", FakeRemote.HealthService(true, true, true));
        var beforeFailure = updated["MonitoringInventory"]!.ToJsonString(); ArchiveStore.WriteJson(stateFile, updated);
        await RefusesAsync(() => f.Engine(unreadableRemote).ExecuteAsync(health, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "empty Agent config silently promoted");
        Check(ArchiveStore.ReadJson(stateFile)["MonitoringInventory"]!.ToJsonString() == beforeFailure && unreadableRemote.Mutations == 0, "failed private config read changed component inventory");
    }
}
