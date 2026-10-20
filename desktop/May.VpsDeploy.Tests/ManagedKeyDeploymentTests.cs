using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task ManagedKeyDeployment(Fixture f)
    {
        var plan = f.Plan("DeniedLocalKey"); var relative = f.Relative(plan); var remote = new FakeRemote();
        var engine = new WorkflowEngine(f.Store, remote, new DeniedManagedKeys(), new FakeUser(), new FakeValidation());
        var request = new OperationRequest(OperationKind.Deploy, relative, new JsonObject { ["Plan"] = plan });
        var coordinator = new TaskCoordinator(f.Store, engine);
        var record = await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), default);
        Check(record.Outcome == TaskOutcome.Failed && record.ErrorCode == "LocalAccessDenied" && record.Stage == "management-key", "local key failure misclassified or attributed to previous remote step");
        Check(remote.Mutations == 0 && remote.Commands.SequenceEqual(new[] { "audit.sh" }), "remote baseline armed before local key was ready");
        Check(InstanceLifecycle.Read(f.Store, relative, plan).CanContinue, "preflight failure created a recovery transaction");

        // Reproduce a v0.9.5 archive with a private key created locally but never installed remotely.
        var recovering = f.Plan("InterruptedBeforeBootstrap"); f.SaveInstance(recovering); relative = f.Relative(recovering);
        var directory = f.Paths.Instance(relative); var stateFile = SafePath.Resolve(directory, "deployment-state.json");
        var state = new JsonObject
        {
            ["Engine"] = "dotnet-v1",
            ["DeploymentTransaction"] = new JsonObject { ["Status"] = "Armed", ["RemoteBaselineDirectory"] = "/root/vps-deploy-transaction-baselines/" + recovering.Text("DeploymentTransaction.Id") },
            ["Modules"] = new JsonObject { ["audit"] = new JsonObject { ["Status"] = "Success" }, ["deployment-baseline"] = new JsonObject { ["Status"] = "Success" }, ["bootstrap-access"] = new JsonObject { ["Status"] = "NeedsRecovery" } }
        };
        ArchiveStore.WriteJson(stateFile, state); new FakeKeys().Prepare(SafePath.Resolve(directory, "ssh"), "");
        var refused = new FakeRemote(); var user = new RecoveryUser(false);
        engine = new(f.Store, refused, new FakeKeys(), user, new FakeValidation());
        var recover = new OperationRequest(OperationKind.Recover, relative, new());
        try { await engine.ExecuteAsync(recover, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); throw new Exception("cancelled recovery completed"); }
        catch (OperationException error) { Check(error.NeedsRecovery, "cancelled armed recovery released the transaction"); }
        Check(refused.Mutations == 0 && refused.Commands.SequenceEqual(new[] { "deployment-baseline-status.sh" }) && user.Confirmations == 1, "recovery changed server before explicit baseline restore confirmation");
        Check(refused.Endpoints.All(e => e.Port == recovering.Number("Server.BootstrapSshPort") && e.KeyPath == null && e.Password != null), "recovery used uninstalled local key or future management port");
        Check(InstanceLifecycle.Read(f.Store, relative, recovering).NeedsRecovery, "cancelled recovery cleared pending state");
        var restored = new FakeRemote(); engine = new(f.Store, restored, new FakeKeys(), new RecoveryUser(true), new FakeValidation());
        await engine.ExecuteAsync(recover, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
        Check(restored.Mutations == 1 && restored.Commands.SequenceEqual(new[] { "deployment-baseline-status.sh", "deployment-baseline-rollback.sh" }), "recovery replayed deployment or skipped status reconciliation");
        Check(restored.Endpoints.All(e => e.Port == recovering.Number("Server.BootstrapSshPort") && e.KeyPath == null), "rollback or restored access used uninstalled local key");
        Check(InstanceLifecycle.Read(f.Store, relative, recovering).CanContinue && ArchiveStore.ReadJson(stateFile).Text("DeploymentTransaction.Status") == "RolledBack", "verified recovery did not release the draft");
        var restoredState = ArchiveStore.ReadJson(stateFile);

        // Once bootstrap access is verified, keep using that installed management key.
        state.Put("Modules.bootstrap-access.Status", JsonValue.Create("Success")); state["CurrentManagementPort"] = recovering.Number("Ports.SshPrimary"); ArchiveStore.WriteJson(stateFile, state);
        var installed = new FakeRemote(); engine = new(f.Store, installed, new FakeKeys(), new RecoveryUser(false), new FakeValidation());
        await RefusesAsync(() => engine.ExecuteAsync(recover, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "cancelled established-key recovery completed");
        Check(installed.Endpoints.Single().KeyPath == SafePath.Resolve(directory, "ssh/id_vps_management") && installed.Endpoints.Single().Port == recovering.Number("Ports.SshPrimary"), "verified management access regressed to bootstrap authentication");
        ArchiveStore.WriteJson(stateFile, restoredState); var next = new FakeRemote();
        Check(await f.Engine(next).ExecuteAsync(recover with { Kind = OperationKind.Resume }, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "restored draft could not start a new deployment");
        var nextPlan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json")); var nextState = ArchiveStore.ReadJson(stateFile);
        Check(nextPlan.Text("DeploymentTransaction.Id") != recovering.Text("DeploymentTransaction.Id") && nextState.Text("DeploymentTransaction.RemoteBaselineDirectory") == "/root/vps-deploy-transaction-baselines/" + nextPlan.Text("DeploymentTransaction.Id"), "new deployment reused old rollback marker or captured under another identity");
    }
}

internal sealed class DeniedManagedKeys : IManagedKeyStore
{
    public string Prepare(string directory, string source, string? passphrase = null) => throw new UnauthorizedAccessException("synthetic private key access denied");
}
internal sealed class RecoveryUser(bool allow) : IUserInteraction
{
    public int Confirmations { get; private set; }
    public Task<bool> ConfirmHostAsync(HostIdentity identity, CancellationToken token) => Task.FromResult(true);
    public Task<bool> ConfirmAsync(UserDecision decision, CancellationToken token) { Confirmations++; return Task.FromResult(allow); }
    public Task<string?> SecretAsync(string title, CancellationToken token) => Task.FromResult<string?>("synthetic-bootstrap-password");
}
