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
    public int Uploads { get; private set; }
    public Task<string> UploadTemporaryFileAsync(string source, CancellationToken token) { token.ThrowIfCancellationRequested(); Uploads++; return Task.FromResult("/tmp/mxh-vps.ABCDEF1234/kernel.deb"); }
    public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken token) => Task.FromResult<IRemoteSession>(this);
    public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken token) => legacy.RunAsync(command, timeout, token);
    public Task<byte[]> ReadFileAsync(string path, CancellationToken token) => legacy.ReadFileAsync(path, token);
    public Task DownloadAsync(string path, string destination, CancellationToken token) => legacy.DownloadAsync(path, destination, token);
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    public Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutation, CancellationToken token)
    {
        var name = payload.Split('\n')[0].Replace("# MXH asset: ", "");
        if (!name.StartsWith("kernel-")) return legacy.RunScriptAsync(payload, timeout, mutation, token);
        if (payload.Contains("VPS_KERNEL_BUILD_PROGRAM") || payload.Contains("def latest_candidate") || payload.Contains("def build_google_kernel")) throw new Exception("Maintainer compiler or floating version query leaked into VPS execution payload");
        Commands.Add(name);
        if (mutation && payload.Contains("export VPS_PARAM_EXPECTED_TRANSACTION")) throw new Exception("Kernel crossed legacy rollback scope");
        string Parameter(string key) { var m = Regex.Match(payload, "export VPS_PARAM_" + key + "=.+?'([A-Za-z0-9+/=]*)' "); return m.Success ? Encoding.UTF8.GetString(Convert.FromBase64String(m.Groups[1].Value)) : ""; }
        JsonObject result;
        if (name == "kernel-audit.sh") result = new() { ["Kernel"] = "6.12.1-amd64", ["BbrVersion"] = "VersionUnverified", ["Compatible"] = Compatible, ["Reasons"] = new JsonArray("synthetic boot incompatibility") };
        else
        {
            if (name == "kernel-prepare.sh")
            {
                State = new() { ["SchemaVersion"] = 2, ["Owner"] = BbrKernels.Owner, ["Id"] = Parameter("TRANSACTION"), ["Phase"] = "Prepared", ["OldKernel"] = "6.12.1-amd64", ["Catalog"] = JsonNode.Parse(Parameter("CATALOG")), ["Runtime"] = new JsonObject { ["Kernel"] = "6.12.1-amd64" } };
                if (LosePrepareAck) { LosePrepareAck = false; throw new IOException("synthetic lost prepare acknowledgement"); }
            }
            if (name == "kernel-boot.sh") { State["Phase"] = "Booted"; State["Runtime"] = new JsonObject { ["Kernel"] = State.Text("Catalog.Kernel"), ["BbrVersion"] = BadVersion ? "VersionUnverified" : "v3" }; State["ServicesHealthy"] = true; if (LoseBootAck) { LoseBootAck = false; throw new IOException("synthetic lost reboot acknowledgement"); } }
            if (name == "kernel-confirm.sh") { State["Phase"] = "Committed"; if (LoseCommitAck) { LoseCommitAck = false; throw new IOException("synthetic lost commit acknowledgement"); } }
            if (name == "kernel-rollback.sh") { State["Phase"] = "RolledBack"; State["Runtime"] = new JsonObject { ["Kernel"] = "6.12.1-amd64", ["BbrVersion"] = "VersionUnverified" }; }
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
        Task<TaskOutcome> Run(string action) => engine.ExecuteAsync(new(OperationKind.BbrKernel, relative, action == "Install" ? new() { ["Action"] = action, ["CatalogId"] = catalog.Text("Id"), ["CatalogSha256"] = catalog.Text("Sha256"), ["SourceCommit"] = catalog.Text("Commit") } : new() { ["Action"] = action }), Guid.NewGuid().ToString("N"), progress, default);
        remote.Compatible = false;
        try
        {
            await engine.ExecuteAsync(new(OperationKind.BbrKernel, relative, new() { ["Action"] = "Check" }), Guid.NewGuid().ToString("N"), progress, default);
            throw new Exception("incompatible boot layout accepted");
        }
        catch (OperationException error) { Check(error.Code == "KernelIncompatible" && error.Message.Contains("synthetic boot incompatibility"), "compatibility cause was hidden by latest query"); }
        Check(!remote.Commands.Contains("kernel-latest.sh") && !remote.Commands.Contains("kernel-prepare.sh"), "incompatible check continued into repository or installation");
        Check(!BbrKernels.Pending(ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(relative), "deployment-state.json"))), "read-only incompatibility created a kernel transaction");
        remote.Compatible = true;
        foreach (var code in new[] { "KernelPrebuiltRejected", "KernelSourceRejected", "KernelSourcePrerelease", "KernelSourceNotV3", "KernelMetadataRejected", "KernelOperationRefused", "synthetic-secret" })
        {
            var marker = "VPSDEPLOY_KERNEL_FAILURE_CODE_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(code)) + "\n";
            var safe = SafeFailures.Remote(new(1, marker, "synthetic-secret"), "内核检查失败");
            Check(safe.Code == (code == "synthetic-secret" ? "RemoteStepFailed" : code) && !safe.Message.Contains("synthetic-secret"), "kernel failure cause lost or untrusted detail shown");
        }
        Refuses(() => BbrKernels.Validate(new() { ["Action"] = "Install", ["CatalogId"] = "x", ["Url"] = "https://example.com" }), "arbitrary kernel URL accepted");
        Refuses(() => BbrKernels.Validate(new() { ["Action"] = "Reboot" }), "unknown kernel action accepted");
        await RefusesAsync(() => Run("Install"), "lost kernel install ACK treated as completion");
        await RefusesAsync(() => Run("Install"), "pending install replayed");
        Check(remote.Commands.Count(x => x == "kernel-prepare.sh") == 1, "kernel install was replayed");
        Check(remote.Uploads == 1, "embedded kernel was not uploaded once or was replayed after acknowledgement loss");
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
        var runningCatalog = catalog.DeepClone().AsObject(); runningCatalog["Kernel"] = "6.13.6-mxh-bbr3-" + catalog.Text("Commit")[..12];
        var committed = new JsonObject { ["Phase"] = "Committed", ["Catalog"] = runningCatalog };
        var running = new JsonObject { ["Compatible"] = true, ["BbrVersion"] = "v3", ["Kernel"] = "6.13.6-mxh-bbr3-" + catalog.Text("Commit")[..12] };
        Check(BbrKernels.CanUpgrade(committed, running, catalog), "committed v3 cannot upgrade to newer target");
        Check(!BbrKernels.CanUpgrade(null, running, catalog), "unmanaged v3 upgrade accepted");
        committed["Phase"] = "Prepared"; Check(!BbrKernels.CanUpgrade(committed, running, catalog), "unfinished v3 upgraded again");
        committed["Phase"] = "Aborted"; committed["OldKernel"] = running.Text("Kernel"); committed["PreviousTransaction"] = new string('a',32);
        Check(BbrKernels.CanUpgrade(committed, running, catalog), "aborted upgrade cannot retry from retained committed v3");
        committed["Phase"] = "RolledBack"; Check(BbrKernels.CanUpgrade(committed, running, catalog), "rolled-back v3 cannot upgrade from retained history");
        committed["Phase"] = "Committed"; running["Kernel"] = catalog.Text("Kernel"); Check(!BbrKernels.CanUpgrade(committed, running, catalog), "same v3 target reinstalled");
        BbrKernels.Validate(new() { ["Action"] = "RollbackOriginal" });
        Check(OperationPolicy.Summary(new(OperationKind.BbrKernel, relative, new() { ["Action"] = "RollbackOriginal" })).Contains("VPS 原有内核"), "original rollback scope missing from review");
        Refuses(() => BbrKernels.Validate(new() { ["Action"] = "Check", ["Source"] = "Latest" }), "removed BBR latest option still accepted");
        var requests = 0; var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => { requests++; return Task.FromResult(TaskOutcome.Completed); }));
        var install = new OperationRequest(OperationKind.BbrKernel, relative, new() { ["Action"] = "Install", ["CatalogId"] = catalog.Text("Id"), ["CatalogSha256"] = catalog.Text("Sha256"), ["SourceCommit"] = catalog.Text("Commit") });
        var reviewed = coordinator.Review(install);
        Check(reviewed.Summary.Contains(catalog.Text("BaseKernel")) && reviewed.Summary.Contains(catalog.Text("SourceDate")) && reviewed.Summary.Contains(catalog.Text("Prebuilt.Sha256")) && reviewed.Summary.Contains("不安装编译依赖"), "review omitted embedded provenance or still compiles on VPS");
        BbrKernels.ValidatePrebuilt(f.Paths, catalog);
        var manifestFile = f.Paths.Resolve("assets/kernel/build-manifest.json"); var manifestBytes = File.ReadAllBytes(manifestFile);
        File.AppendAllText(manifestFile, " ");
        Refuses(() => BbrKernels.ValidatePrebuilt(f.Paths, catalog), "tampered build receipt accepted");
        await RefusesAsync(() => coordinator.ExecuteAsync(reviewed, install, progress, default), "embedded receipt drift after review accepted");
        Check(requests == 0, "tampered embedded review reached workflow"); File.WriteAllBytes(manifestFile, manifestBytes);
        var foreign = catalog.DeepClone().AsObject(); foreign["Repository"] = "https://deb.xanmod.org/";
        Check(!BbrKernels.CanUpgrade(null, new JsonObject { ["Compatible"] = true, ["Kernel"] = "6.12.1-amd64" }, foreign), "third-party kernel was offered as an official source upgrade");
        Check(!BbrKernels.CanUpgrade(null, new JsonObject { ["Compatible"] = true, ["Kernel"] = "6.18.1-amd64" }, catalog), "older official source implicitly downgraded a newer stock kernel");
        var sourcePlan = f.Plan("KernelRuntimeSource"); f.SaveInstance(sourcePlan); var sourceRelative = f.Relative(sourcePlan);
        var sourceStateFile = SafePath.Resolve(f.Paths.Instance(sourceRelative), "deployment-state.json");
        var sourceRemote = new FakeRemote(); sourceRemote.NetworkAudit["Kernel"] = catalog.Text("Kernel"); sourceRemote.NetworkAudit["BbrVersion"] = "v3";
        var sourceEngine = f.Engine(sourceRemote);
        var receipt = new JsonObject { ["SchemaVersion"] = 2, ["Owner"] = BbrKernels.Owner, ["Delivery"] = "Prebuilt", ["Phase"] = "Committed", ["Catalog"] = catalog.DeepClone(), ["NewImageSha256"] = new string('a', 64), ["NewInitrdSha256"] = new string('b', 64) };
        foreach (var scenario in new[] { "Missing", "ForeignOwner", "ForeignCatalog" })
        {
            var sourceState = ArchiveStore.ReadJson(sourceStateFile); sourceState.Remove("KernelUpgrade");
            if (scenario != "Missing")
            {
                var invalidReceipt = receipt.DeepClone().AsObject();
                if (scenario == "ForeignOwner") invalidReceipt["Owner"] = "unmanaged";
                else invalidReceipt["Catalog"]!["Repository"] = "https://example.com/kernel";
                sourceState["KernelUpgrade"] = invalidReceipt;
            }
            ArchiveStore.WriteJson(sourceStateFile, sourceState);
            await RefusesAsync(() => sourceEngine.ExecuteAsync(new(OperationKind.TuneNetwork, sourceRelative, new() { ["Scope"] = "Network", ["Profile"] = "EntryBasic", ["BbrVersion"] = "v3" }), Guid.NewGuid().ToString("N"), progress, default), "runtime v3 alone bypassed official source ownership: " + scenario);
            Check(sourceRemote.Mutations == 0, "unverified source mutated network before refusal");
        }
        var originalState = ArchiveStore.ReadJson(sourceStateFile); originalState.Remove("KernelUpgrade"); ArchiveStore.WriteJson(sourceStateFile, originalState);
        var originalTask = Guid.NewGuid().ToString("N"); sourceRemote.StatusTaskId = originalTask; sourceRemote.StatusPhase = "Armed";
        Check(await sourceEngine.ExecuteAsync(new(OperationKind.TuneNetwork, sourceRelative, new() { ["Scope"] = "Network", ["Profile"] = "EntryBasic", ["BbrVersion"] = "Current" }), originalTask, progress, default) == TaskOutcome.Completed, "original kernel mode no longer supports existing v3 without claiming a Google source");
        var acceptedState = ArchiveStore.ReadJson(sourceStateFile); acceptedState["KernelUpgrade"] = receipt; ArchiveStore.WriteJson(sourceStateFile, acceptedState);
        var acceptedTask = Guid.NewGuid().ToString("N"); sourceRemote.StatusTaskId = acceptedTask; sourceRemote.StatusPhase = "Armed";
        Check(await sourceEngine.ExecuteAsync(new(OperationKind.TuneNetwork, sourceRelative, new() { ["Scope"] = "Network", ["Profile"] = "EntryBasic", ["BbrVersion"] = "v3" }), acceptedTask, progress, default) == TaskOutcome.Completed && sourceRemote.ArmedComponents == "Network", "accepted Google source v3 could not apply scoped basic network configuration");
    }
}
