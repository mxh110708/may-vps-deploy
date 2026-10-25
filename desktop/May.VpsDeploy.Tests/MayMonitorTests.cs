using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunMayMonitorTests()
    {
        using var fixture = new Fixture(repository); await MayMonitorExperience(fixture);
        Console.WriteLine($"PASS: {assertions} May Monitor review, lifecycle, encrypted scope and acknowledgement assertions; inert remote only.");
    }

    private async Task MayMonitorExperience(Fixture f)
    {
        JsonObject Options(string action, string role = "Server") => new() { ["Role"] = role, ["Action"] = action, ["Configuration"] = action is "Install" or "Upgrade" ? role == "Server" ? new JsonObject { ["Port"] = 25775, ["Username"] = "admin" } : new JsonObject { ["Endpoint"] = "https://monitor.example/" } : new JsonObject() };
        foreach (var role in MayMonitorLifecycle.Roles)
            foreach (var action in new[] { "Check", "Install", "Upgrade", "Backup", "Enable", "Disable", "Remove" }) { MayMonitorLifecycle.Validate(Options(action, role)); Check(true, "valid May operation rejected"); }
        foreach (var bad in new[] { Options("ConfigureRead", "Agent"), Options("Restore"), Options("Upgrade", "Komari"), Options("Unknown") }) Refuses(() => MayMonitorLifecycle.Validate(bad), "unknown May action/scope accepted");
        var invalid = Options("Install", "Agent"); invalid["Configuration"]!["Endpoint"] = "http://public.example/"; Refuses(() => MayMonitorLifecycle.Validate(invalid), "insecure public agent endpoint accepted");
        invalid = Options("Install"); invalid["Configuration"]!["AgentToken"] = "synthetic"; Refuses(() => MayMonitorLifecycle.Validate(invalid), "credential accepted in public options");
        invalid = Options("Check"); invalid["Scope"] = "KomariController"; Refuses(() => MayMonitorLifecycle.Validate(invalid), "legacy scope mixed into May options");
        var catalog = new JsonObject { ["SchemaVersion"] = 1 };
        foreach (var role in MayMonitorLifecycle.Roles)
        {
            var name = role == "Server" ? "may-monitor-server-linux-amd64.tar.gz" : "may-monitor-agent-linux-amd64";
            catalog[role] = new JsonObject { ["Version"] = "0.1.0-rc.2", ["Sha256"] = new string('b', 64), ["Bytes"] = 123, ["Name"] = name, ["Url"] = "https://github.com/mxh110708/may-monitor-" + role.ToLowerInvariant() + "/releases/download/v0.1.0-rc.2/" + name };
        }
        var catalogFile = f.Paths.Resolve("config/may-monitor.json"); File.Delete(catalogFile);
        Refuses(() => MayMonitorLifecycle.Asset(f.Paths, "Server"), "missing paired asset manifest did not produce a safe error");
        ArchiveStore.WriteJson(catalogFile, catalog);
        Check(MayMonitorLifecycle.Asset(f.Paths, "Server").Text("Version") == "0.1.0-rc.2", "fixed May asset lost");
        var badCatalog = catalog.DeepClone().AsObject(); badCatalog["Server"]!["Url"] = "https://other.example/install.sh"; ArchiveStore.WriteJson(catalogFile, badCatalog); Refuses(() => MayMonitorLifecycle.Asset(f.Paths, "Server"), "unowned mutable install asset accepted"); ArchiveStore.WriteJson(catalogFile, catalog);
        var plan = f.Plan("May-lifecycle"); f.SaveInstance(plan); var relative = f.Relative(plan); var directory = f.Paths.Instance(relative);
        var stateFile = SafePath.Resolve(directory, "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile); state["KomariSentinel"] = "retained"; ArchiveStore.WriteJson(stateFile, state);
        var remote = new MayLifecycleRemote(); var user = new FakeUser(_ => "Synthetic-Password1"); var workflow = new WorkflowEngine(f.Store, remote, new FakeKeys(), user, new FakeValidation()); var coordinator = new TaskCoordinator(f.Store, workflow);
        OperationRequest Request(string action, string role = "Server") => new(OperationKind.MayMonitor, relative, Options(action, role));
        async Task<TaskRecord> Execute(OperationRequest request) => await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), default);
        var review = coordinator.Review(Request("Install")); Check(review.Summary.Contains("0.1.0-rc.2") && review.Summary.Contains(new string('b', 64)) && review.Summary.Contains("127.0.0.1:25775"), "review omitted concrete pin or destination");
        File.AppendAllText(f.Paths.Resolve("scripts/may-monitor-lifecycle.py"), "\n# changed after review\n");
        await RefusesAsync(() => coordinator.ExecuteAsync(review, review.Request, new InlineProgress<TaskProgress>(_ => { }), default), "changed runtime executed an old review"); Check(remote.Calls.Count == 0, "stale review opened remote");
        Check((await Execute(Request("Install"))).Outcome == TaskOutcome.Completed, "May install failed");
        var saved = ArchiveStore.ReadJson(stateFile); Check(saved.Flag("MayMonitorServer.Installed") && saved.Text("KomariSentinel") == "retained", "May install changed another component");
        var secretFile = SafePath.Resolve(directory, "secrets.dotnet.private.json"); Check(!File.ReadAllText(secretFile).Contains("Synthetic-Password1"), "May password was not encrypted");
        Check(user.SecretPrompts.Count(t => t.StartsWith("May Monitor")) == 1, "May install prompted repeatedly");
        var calls = remote.Calls.Count; Check((await Execute(Request("Check"))).Outcome == TaskOutcome.Completed && remote.Calls.Skip(calls).SequenceEqual(["Check"]), "read-only check mutated remote");
        calls = remote.Calls.Count; Check((await Execute(Request("Backup"))).Outcome == TaskOutcome.Completed && !remote.Calls.Skip(calls).Contains("Apply"), "backup rewrote installation");
        var backups = MayMonitorLifecycle.Backups(f.Store, relative, "Server"); Check(backups.Count == 1 && MayMonitorLifecycle.Backups(f.Store, relative, "Agent").Count == 0, "restore picker crossed role/absence boundary");
        // Lost apply acknowledgement causes one status reconciliation and one
        // selected-scope rollback, never a second Apply.
        remote.LoseApply = true; calls = remote.Calls.Count; var failed = await Execute(Request("Disable"));
        Check(failed.Outcome == TaskOutcome.Failed && remote.Calls.Skip(calls).Count(x => x == "Apply") == 1 && remote.Calls.Skip(calls).Count(x => x == "Rollback") == 1, "lost apply replayed or was not recovered");
        Check(ArchiveStore.ReadJson(stateFile).Flag("MayMonitorServer.Active") && ArchiveStore.ReadJson(stateFile).Text("KomariSentinel") == "retained", "rollback failed to restore only May state");
        remote.LoseCommit = true; calls = remote.Calls.Count; var committed = await Execute(Request("Disable"));
        Check(committed.Outcome == TaskOutcome.CompletedWithWarnings && remote.Calls.Skip(calls).Count(x => x == "Commit") == 1 && !remote.Calls.Skip(calls).Contains("Rollback"), "lost commit was replayed or rolled back");
        Check(!ArchiveStore.ReadJson(stateFile).Flag("MayMonitorServer.Active"), "confirmed commit left old local state");
        remote.LoseApply = true; remote.WrongTransactionIdentity = true; calls = remote.Calls.Count; var uncertain = await Execute(Request("Enable"));
        Check(uncertain.Outcome == TaskOutcome.NeedsRecovery && !remote.Calls.Skip(calls).Contains("Rollback"), "unknown transaction was destructively recovered");
        remote.WrongTransactionIdentity = false;
        var recovered = await Execute(new(OperationKind.Recover, relative, new())); Check(recovered.Outcome == TaskOutcome.Completed, "typed May recovery failed");
        Check(remote.Legacy.Commands.All(c => c is not ("protocol-migration-trigger-rollback.sh" or "maintenance-komari.sh")), "May lifecycle used legacy recovery");
        var authorization = new JsonObject { ["Sha256"] = new string('a', 64), ["Clients"] = new JsonArray(Guid.NewGuid().ToString("D")), ["ExpiresAt"] = DateTimeOffset.UtcNow.AddDays(30).ToString("O") };
        var readOptions = Options("ConfigureRead"); readOptions["ReadSourceIdentity"] = new string('a',64); readOptions["Configuration"]!["ReadAuthorization"] = authorization; MayMonitorLifecycle.Validate(readOptions);
        authorization["ExpiresAt"] = DateTimeOffset.UtcNow.AddDays(91).ToString("O"); Refuses(() => MayMonitorLifecycle.Validate(readOptions), "unbounded read authorization accepted");
        foreach (var role in MayMonitorLifecycle.Roles)
        {
            var weakPlan = f.Plan("May-weak-" + role); f.SaveInstance(weakPlan); var inert = new MayLifecycleRemote();
            var weakEngine = new WorkflowEngine(f.Store, inert, new FakeKeys(), new FakeUser(_ => role == "Server" ? "weak-password" : MonitorReadConnection.NewToken()), new FakeValidation());
            await RefusesAsync(() => weakEngine.ExecuteAsync(new(OperationKind.MayMonitor, f.Relative(weakPlan), Options("Install", role)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "weak/admin read credential reached May installation");
            Check(!inert.Calls.Contains("Begin"), "invalid credential armed remote mutation");
        }
    }
}

internal sealed class MayLifecycleRemote : IRemoteSessionFactory, IRemoteSession
{
    internal readonly FakeRemote Legacy = new();
    internal readonly List<string> Calls = [];
    internal bool LoseApply, LoseCommit, WrongTransactionIdentity;
    private JsonObject current = new() { ["Installed"] = false, ["Version"] = "", ["Hash"] = "Absent", ["Active"] = false, ["Enabled"] = false, ["Configuration"] = new JsonObject() };
    private JsonObject before = new(); private string phase = "None", task = "", role = "";
    public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken ct) => Task.FromResult<IRemoteSession>(this);
    public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct) => Legacy.RunAsync(command, timeout, ct);
    public Task<byte[]> ReadFileAsync(string path, CancellationToken ct) => Legacy.ReadFileAsync(path, ct);
    public Task DownloadAsync(string path, string destination, CancellationToken ct) => Legacy.DownloadAsync(path, destination, ct);
    public Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken ct)
    {
        if (!payload.StartsWith("# MXH asset: may-monitor-lifecycle.sh\n")) return Legacy.RunScriptAsync(payload, timeout, mutating, ct);
        string Parameter(string name) { var match = Regex.Match(payload, "export VPS_PARAM_" + name + "=.+?'([A-Za-z0-9+/=]*)' "); return match.Success ? Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)) : ""; }
        var action = Parameter("ACTION"); Calls.Add(action); JsonObject result;
        switch (action)
        {
            case "Check": result = current.DeepClone().AsObject(); break;
            case "Begin":
                task = Parameter("TASK_ID"); role = Parameter("ROLE"); before = current.DeepClone().AsObject(); phase = "Armed";
                result = new() { ["Backup"] = MayMonitorLifecycle.BackupPath(task), ["Sha256"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes("fixture-archive")), ["Phase"] = phase }; break;
            case "Apply":
                var operation = Parameter("OPERATION");
                if (operation == "Install") current = new() { ["Installed"] = true, ["Active"] = true, ["Enabled"] = true, ["Version"] = "0.1.0-rc.2", ["Configuration"] = JsonNode.Parse(Parameter("CONFIGURATION")) };
                if (operation is "Enable" or "Disable") { current["Active"] = operation == "Enable"; current["Enabled"] = operation == "Enable"; }
                current["Hash"] = ArchiveStore.Fingerprint(current); phase = "Applied"; result = current.DeepClone().AsObject();
                if (LoseApply) { LoseApply = false; throw new IOException("synthetic acknowledgement lost"); } break;
            case "Commit": phase = "Committed"; result = new() { ["Phase"] = phase, ["State"] = current.DeepClone() }; if (LoseCommit) { LoseCommit = false; throw new IOException("synthetic commit acknowledgement lost"); } break;
            case "Rollback": phase = "RolledBack"; current = before.DeepClone().AsObject(); result = new() { ["Phase"] = phase, ["State"] = current.DeepClone() }; break;
            case "Transaction": result = new() { ["Phase"] = phase, ["Role"] = role, ["TaskId"] = WrongTransactionIdentity ? Guid.NewGuid().ToString("N") : task }; break;
            default: throw new Exception("Unexpected May lifecycle command");
        }
        return Task.FromResult(new CommandResult(0, "VPSDEPLOY_MAY_MONITOR_RESULT_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(result.ToJsonString())) + "\n", ""));
    }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
