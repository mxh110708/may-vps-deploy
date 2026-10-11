using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Mxh.VpsDeploy.Core;

internal sealed class KernelRemote : IRemoteSessionFactory, IRemoteSession
{
    private readonly FakeRemote legacy = new();
    public JsonObject State { get; set; } = new();
    public bool Compatible { get; set; } = true;
    public bool LosePrepareAck { get; set; }
    public bool LoseBootAck { get; set; }
    public bool LoseCommitAck { get; set; }
    public bool BadVersion { get; set; }
    public List<string> Commands { get; } = [];
    public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken token) => Task.FromResult<IRemoteSession>(this);
    public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken token) => legacy.RunAsync(command, timeout, token);
    public Task<byte[]> ReadFileAsync(string path, CancellationToken token) => legacy.ReadFileAsync(path, token);
    public Task DownloadAsync(string path, string destination, CancellationToken token) => legacy.DownloadAsync(path, destination, token);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    public Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutation, CancellationToken token)
    {
        var name = payload.Split('\n')[0].Replace("# MXH asset: ", "");
        if (!name.StartsWith("kernel-")) return legacy.RunScriptAsync(payload, timeout, mutation, token);
        Commands.Add(name);
        if (mutation && payload.Contains("export VPS_PARAM_EXPECTED_TRANSACTION")) throw new Exception("Kernel crossed legacy rollback scope");
        string Parameter(string key) { var m = Regex.Match(payload, "export VPS_PARAM_" + key + "=.+?'([A-Za-z0-9+/=]*)' "); return m.Success ? Encoding.UTF8.GetString(Convert.FromBase64String(m.Groups[1].Value)) : ""; }
        JsonObject result;
        if (name == "kernel-audit.sh") result = new() { ["Kernel"] = "stock", ["BbrVersion"] = "VersionUnverified", ["Compatible"] = Compatible, ["Reasons"] = new JsonArray("synthetic boot incompatibility") };
        else
        {
            if (name == "kernel-prepare.sh")
            {
                State = new() { ["SchemaVersion"] = 1, ["Owner"] = "mxh-dotnet-kernel-v1", ["Id"] = Parameter("TRANSACTION"), ["Phase"] = "Prepared", ["OldKernel"] = "stock", ["Catalog"] = JsonNode.Parse(Parameter("CATALOG")), ["Runtime"] = new JsonObject { ["Kernel"] = "stock" } };
                if (LosePrepareAck) { LosePrepareAck = false; throw new IOException("synthetic lost prepare acknowledgement"); }
            }
            if (name == "kernel-boot.sh") { State["Phase"] = "Booted"; State["Runtime"] = new JsonObject { ["Kernel"] = State.Text("Catalog.Kernel"), ["BbrVersion"] = BadVersion ? "VersionUnverified" : "v3" }; State["ServicesHealthy"] = true; if (LoseBootAck) { LoseBootAck = false; throw new IOException("synthetic lost reboot acknowledgement"); } }
            if (name == "kernel-confirm.sh") { State["Phase"] = "Committed"; if (LoseCommitAck) { LoseCommitAck = false; throw new IOException("synthetic lost commit acknowledgement"); } }
            if (name == "kernel-rollback.sh") { State["Phase"] = "RolledBack"; State["Runtime"] = new JsonObject { ["Kernel"] = "stock", ["BbrVersion"] = "VersionUnverified" }; }
            result = State.DeepClone().AsObject();
        }
        return Task.FromResult(new CommandResult(0, "VPSDEPLOY_KERNEL_RESULT_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(result.ToJsonString())) + "\n", ""));
    }
}

internal sealed partial class BoundaryTests
{
    private async Task KernelExperience(Fixture f)
    {
        var catalog = BbrKernels.Catalog(f.Paths); var plan = f.Plan("KernelLifecycle"); f.SaveInstance(plan);
        var remote = new KernelRemote { LosePrepareAck = true }; var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation());
        var relative = f.Relative(plan); var progress = new InlineProgress<TaskProgress>(_ => { });
        Task<TaskOutcome> Run(string action) => engine.ExecuteAsync(new(OperationKind.BbrKernel, relative, action == "Install" ? new() { ["Action"] = action, ["CatalogId"] = catalog.Text("Id") } : new() { ["Action"] = action }), Guid.NewGuid().ToString("N"), progress, default);
        Refuses(() => BbrKernels.Validate(new() { ["Action"] = "Install", ["CatalogId"] = "x", ["Url"] = "https://example.com" }), "arbitrary kernel URL accepted");
        Refuses(() => BbrKernels.Validate(new() { ["Action"] = "Reboot" }), "unknown kernel action accepted");
        await RefusesAsync(() => Run("Install"), "lost kernel install ACK treated as completion");
        await RefusesAsync(() => Run("Install"), "pending install replayed");
        Check(remote.Commands.Count(x => x == "kernel-prepare.sh") == 1, "kernel install was replayed");
        await Run("Reconcile");
        var stateFile = SafePath.Resolve(f.Paths.Instance(relative), "deployment-state.json");
        Check(ArchiveStore.ReadJson(stateFile).Text("KernelUpgrade.Phase") == "Prepared", "prepared kernel not reconciled");
        await RefusesAsync(() => engine.ExecuteAsync(new(OperationKind.TuneNetwork, relative, new() { ["Scope"] = "Network", ["Profile"] = "EntryBasic" }), Guid.NewGuid().ToString("N"), progress, default), "tuning bypassed pending kernel");
        remote.LoseBootAck = true; await RefusesAsync(() => Run("Activate"), "lost reboot ACK not preserved");
        remote.LoseCommitAck = true; var outcome = await Run("Reconcile");
        Check(outcome == TaskOutcome.CompletedWithWarnings && ArchiveStore.ReadJson(stateFile).Text("KernelUpgrade.Phase") == "Committed", "lost commit ACK not reconciled");
        Check(remote.Commands.Count(x => x == "kernel-boot.sh") == 1 && remote.Commands.Count(x => x == "kernel-confirm.sh") == 1, "reboot or commit replayed");
        await Run("Rollback"); Check(ArchiveStore.ReadJson(stateFile).Text("KernelUpgrade.Phase") == "RolledBack", "kernel rollback not archived");
        remote.LoseBootAck = true; await RefusesAsync(() => Run("Activate"), "reactivation ACK loss ignored");
        Check(BbrKernels.Pending(ArchiveStore.ReadJson(stateFile)), "reactivation from a terminal state lost its recovery barrier");
        await Run("Reconcile"); await Run("Rollback");
        Check(!remote.Commands.Any(x => x.Contains("protocol-migration")), "kernel rollback widened scope");
        remote.BadVersion = true; await RefusesAsync(() => Run("Activate"), "unverified bbr promoted to v3");
        var confirms = remote.Commands.Count(x => x == "kernel-confirm.sh");
        remote.State["Id"] = Guid.NewGuid().ToString("N"); await RefusesAsync(() => Run("Reconcile"), "foreign kernel identity accepted");
        Check(remote.Commands.Count(x => x == "kernel-confirm.sh") == confirms, "foreign kernel committed");
        var options = NetworkTuning.Defaults(plan); options["TimeZoneId"] = "UTC"; options["PeakStartHour"] = 20; options["PeakEndHour"] = 24;
        NetworkTuning.ValidateMeasurement(options); Check(NetworkTuning.TimeDescription(options).Contains("24:00") && NetworkTuning.InPeak(DateTimeOffset.Parse("2026-10-11T23:00:00Z"), options) && !NetworkTuning.InPeak(DateTimeOffset.Parse("2026-10-12T00:00:00Z"), options), "24:00 boundary wrong");
        options["PeakEndHour"] = 2; Check(NetworkTuning.TimeDescription(options).Contains("次日 02:00"), "live overnight description stale");
        options["PeakEndHour"] = 25; Check(NetworkTuning.TimeDescription(options).Contains("有效"), "invalid time silently described");
        options["TimeZoneId"] = "Bad/Zone"; Check(NetworkTuning.TimeDescription(options).Contains("无法识别"), "invalid zone not explained");
        options["TimeZoneId"] = ""; Check(NetworkTuning.TimeDescription(options).Contains("无法识别"), "clearing custom zone crashed description");
        options["TimeZoneId"] = "UTC"; options["PeakEndHour"] = ""; Refuses(() => NetworkTuning.ValidateMeasurement(options), "blank peak time silently accepted as midnight");
        var latestCatalog = catalog.DeepClone().AsObject(); latestCatalog["Selection"] = "Latest";
        var sources = new JsonObject(); foreach (var name in new[] { "xanmod.gpg", "InRelease", "Packages.gz" }) sources[name] = Convert.ToBase64String(File.ReadAllBytes(f.Paths.Resolve("assets/kernel/" + name)));
        var candidate = new JsonObject { ["Catalog"] = latestCatalog, ["Sources"] = sources, ["FetchedAt"] = DateTimeOffset.UtcNow.ToString("O") };
        BbrKernels.ValidateCandidate(candidate, catalog);
        candidate["FetchedAt"] = DateTimeOffset.UtcNow.AddDays(-2).ToString("O"); Refuses(() => BbrKernels.ValidateCandidate(candidate, catalog), "stale latest query accepted");
        candidate["FetchedAt"] = DateTimeOffset.UtcNow.ToString("O");
        var candidateFile = SafePath.Resolve(f.Paths.Instance(relative), "kernel-latest-candidate.json"); ArchiveStore.WriteJson(candidateFile, candidate);
        var requests = 0; var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => { requests++; return Task.FromResult(TaskOutcome.Completed); }));
        var install = new OperationRequest(OperationKind.BbrKernel, relative, new() { ["Action"] = "Install", ["Source"] = "Latest", ["CatalogId"] = latestCatalog.Text("Id"), ["CatalogSha256"] = latestCatalog.Text("Sha256") });
        var reviewed = coordinator.Review(install); candidate["FetchedAt"] = DateTimeOffset.UtcNow.AddMinutes(-5).ToString("O"); ArchiveStore.WriteJson(candidateFile, candidate);
        await RefusesAsync(() => coordinator.ExecuteAsync(reviewed, install, progress, default), "latest candidate drift after review accepted");
        Check(requests == 0, "stale latest review reached workflow");
        candidate["Sources"]!["xanmod.gpg"] = Convert.ToBase64String(Encoding.UTF8.GetBytes("unknown key")); Refuses(() => BbrKernels.ValidateCandidate(candidate, catalog), "unknown latest signing materials accepted");
    }
}
