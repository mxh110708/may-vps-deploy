using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task RecoveryExperience(Fixture f)
    {
        foreach (var mode in new[] { "Unowned", "ActiveRollback", "CompletedRollback", "WrongTask" })
        {
            var plan = f.Plan("Recovery-" + mode); f.SaveInstance(plan);
            var directory = f.Paths.Instance(f.Relative(plan));
            var oldState = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
            var task = Guid.NewGuid().ToString("N"); var backup = "maintenance-backups/" + task;
            f.Store.WriteSecret(SafePath.Resolve(directory, backup + "/secrets.dotnet.private.json"), Fixture.RealitySecrets());
            var pending = new JsonObject { ["TaskId"] = task, ["Phase"] = mode is "Unowned" or "ActiveRollback" ? "Arming" : "Armed",
                ["Components"] = new JsonArray("KomariController"), ["LocalBackup"] = backup,
                ["OldPlan"] = plan.DeepClone(), ["OldState"] = oldState.DeepClone() };
            if (mode is "CompletedRollback" or "WrongTask") pending["RemoteBackup"] = FakeRemote.Backup;
            var file = SafePath.Resolve(directory, "operation-pending.dotnet.json"); ArchiveStore.WriteJson(file, pending);
            var remote = new FakeRemote { StatusBackup = mode is "Unowned" or "ActiveRollback" ? "" : FakeRemote.Backup,
                StatusPhase = mode is "Unowned" or "ActiveRollback" ? "None" : "RolledBack",
                StatusTaskId = mode is "Unowned" or "ActiveRollback" ? "" : mode == "WrongTask" ? Guid.NewGuid().ToString("N") : task,
                VerifyUnownedAllowed = mode != "ActiveRollback" };
            var request = new OperationRequest(OperationKind.Recover, f.Relative(plan), new());
            if (mode is "ActiveRollback" or "WrongTask")
            {
                await RefusesAsync(() => f.Engine(remote).ExecuteAsync(request, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "uncertain remote state was cleared");
                Check(ArchiveStore.ReadJson(file).Text("Phase") == pending.Text("Phase"), "refused recovery changed its phase");
                Check(!remote.Commands.Contains("protocol-migration-trigger-rollback.sh"), "wrong owner or active rollback was stopped");
            }
            else
            {
                var outcome = await f.Engine(remote).ExecuteAsync(request, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
                Check(outcome == TaskOutcome.Completed && ArchiveStore.ReadJson(file).Text("Phase") == "RolledBack", "verified recovery remained pending");
                Check(remote.Commands.Contains("protocol-migration-trigger-rollback.sh") == (mode == "CompletedRollback"), "completed timer was not reconciled or unowned arm replayed");
                Check(JsonNode.DeepEquals(plan, ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"))), "monitor recovery changed proxy plan");
            }
            Check(!remote.Commands.Contains("protocol-migration-arm-rollback.sh") && !remote.Commands.Contains("monitoring-component-install.sh"), "recovery replayed an installation");
        }
        foreach (var phase in new[] { "service-process", "controller-initialization", "synthetic-secret-not-an-allowed-phase" })
        {
            var encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(phase));
            var error = SafeFailures.Remote(new CommandResult(1, "VPSDEPLOY_MONITORING_FAILURE_PHASE_B64=" + encoded + "\n", "private remote output"), "组件步骤失败");
            Check(!error.Message.Contains("synthetic-secret") && !error.Message.Contains("private remote output"), "untrusted diagnostics leaked");
            Check(error.Code == (phase.StartsWith("synthetic-") ? "RemoteStepFailed" : "MonitoringStepFailed"), "safe monitoring failure phase was lost");
        }
    }
}
