using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;
using Mxh.VpsDeploy.Infrastructure;
using Renci.SshNet.Common;

internal sealed partial class BoundaryTests
{
    public async Task RunDeploymentTests()
    {
        using var fixture = new Fixture(repository); await DeploymentExperience(fixture); await ManagedKeyDeployment(fixture);
        var python = Environment.GetEnvironmentVariable("MXH_TEST_SSH_PYTHON");
        if (!string.IsNullOrEmpty(python)) await LocalSshConfirmation(fixture, python);
        Console.WriteLine($"PASS: {assertions} deployment, failure, trust and deletion assertions; synthetic fixtures only.");
    }
    private async Task DeploymentExperience(Fixture f)
    {
        var naming = new DeploymentNaming(); var name = naming.Update("", "", "");
        name = naming.Update("Example", "Test instance", name); Check(name == "Example-Test-instance", "default node name not populated");
        name = naming.Update("Second", "Test instance", name); Check(name == "Second-Test-instance", "generated name stopped following provider");
        Check(naming.Update("Third", "Another", "My custom name") == "My custom name", "custom node name overwritten");
        Check(naming.Update("Third", "Another", "") == "Third-Another", "blank name not regenerated");
        var form = new JsonObject { ["Provider"] = "Example", ["Instance"] = "Default Name", ["IPv4"] = "192.0.2.11", ["RealityTarget"] = "example.com", ["KomariEnabled"] = false, ["KomariEndpoint"] = "invalid endpoint" };
        var generated = DeploymentPlans.Create(form, f.Versions, f.Paths, false);
        Check(generated.Text("NodeName") == "Example-Default-Name" && generated.Text("Komari.Endpoint") == "", "inactive fields leaked into plan");
        var review = DeploymentReview.Sections(generated, OperationKind.Deploy);
        Check(review.Count >= 6 && review.Any(s => s.Title == "Reality") && !review.Any(s => s.Title == "AnyTLS / ECH"), "review omits details or adds unselected protocol");
        Check(review.SelectMany(s => s.Items).Any(i => i.Label == "当前状态" && i.Value.Contains("待执行")), "review claims planned checks passed");
        generated.Put("Komari.Enabled", JsonValue.Create(true)); generated.Put("Komari.Endpoint", JsonValue.Create("https://user:synthetic-secret@example.com/controller?token=synthetic-secret#synthetic-secret"));
        Check(!string.Join("\n", DeploymentReview.Sections(generated, OperationKind.Deploy).SelectMany(s => s.Items).Select(i => i.Value)).Contains("synthetic-secret"), "review discloses URL credentials");
        var fp = "SHA256:" + new string('A', 43);
        Check(HostFingerprint.Compare("", fp) == FingerprintComparison.Empty && HostFingerprint.Compare("256 " + fp + " console (ED25519)", fp) == FingerprintComparison.Match, "fingerprint reference not comparable");
        Check(HostFingerprint.Compare("SHA256:" + new string('B', 43), fp) == FingerprintComparison.Mismatch && HostFingerprint.Compare(fp + "\n" + fp, fp) == FingerprintComparison.Invalid, "ambiguous or changed fingerprint accepted");
        foreach (var item in new (Exception Error, string Code)[] { (new SshOperationTimeoutException("synthetic-secret"), "SshTimeout"), (new SshAuthenticationException("synthetic-secret"), "SshAuthenticationFailed"), (new SftpPermissionDeniedException("synthetic-secret"), "SftpAccessDenied") })
        { var safe = TransportFailures.Describe(item.Error); Check(safe.Code == item.Code && !safe.Message.Contains("synthetic-secret"), "transport cause lost or secret shown"); }
        var remoteFailure = SafeFailures.Remote(new(127, "synthetic-secret", "command not found: synthetic-secret"), "执行失败");
        Check(remoteFailure.Message.Contains("127") && remoteFailure.Message.Contains("缺少") && !remoteFailure.Message.Contains("synthetic-secret"), "remote safe failure lost cause");
        Check(!SafeFailures.Describe(new Exception("synthetic-secret")).Message.Contains("synthetic-secret"), "unknown exception text disclosed");

        var plan = f.Plan("FailedDraft"); var relative = f.Relative(plan);
        var engine = new WorkflowEngine(f.Store, new RefusedConnection(new OperationException("SSH 连接超时。", code: "SshTimeout", nextAction: "核对当前端口后继续部署。")), new FakeKeys(), new FakeUser(), new FakeValidation());
        var coordinator = new TaskCoordinator(f.Store, engine); var request = new OperationRequest(OperationKind.Deploy, relative, new JsonObject { ["Plan"] = plan });
        var record = await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), default);
        var directory = f.Paths.Instance(relative); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        Check(record.Outcome == TaskOutcome.Failed && record.ErrorCode == "SshTimeout" && record.InstanceRelativePath == relative && record.NextAction != null, "failed task lacks cause, instance or next step");
        Check(state.Text("Modules.audit.Status") == "Failed" && state.Text("Modules.audit.FinishedAt") != "" && state.Text("LastTask.Outcome") == "Failed", "failed audit still Running");
        var lifecycle = InstanceLifecycle.Read(f.Store, relative, plan); Check(lifecycle.CanContinue && !lifecycle.Managed && !lifecycle.NeedsRecovery && lifecycle.LastError.Contains("超时"), "failed draft reported as managed or recovery");
        var noRemote = new FakeRemote(); await f.Engine(noRemote).ExecuteAsync(new(OperationKind.Recover, relative, new()), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
        Check(noRemote.Commands.Count == 0 && InstanceLifecycle.Read(f.Store, relative, plan).LastError.Contains("超时"), "read-only failure triggered remote recovery or lost reason");
        var retry = new FakeRemote(); var outcome = await f.Engine(retry).ExecuteAsync(new(OperationKind.Resume, relative, new()), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
        Check(outcome == TaskOutcome.Completed && retry.Commands.First() == "audit.sh" && InstanceLifecycle.Read(f.Store, relative, plan).Managed, "draft cannot continue to completion");
        Check(ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json")).Text("NodeName") == plan.Text("NodeName"), "continue replaced saved plan");
        var complete = new FakeRemote(); await RefusesAsync(() => f.Engine(complete).ExecuteAsync(new(OperationKind.Resume, relative, new()), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "completed deployment replayed"); Check(complete.Commands.Count == 0, "completed archive contacted deployment steps");

        var cancelled = f.Plan("CancelledDraft"); var cancelledRequest = new OperationRequest(OperationKind.Deploy, f.Relative(cancelled), new JsonObject { ["Plan"] = cancelled });
        var cancellationEngine = new WorkflowEngine(f.Store, new RefusedConnection(new OperationCanceledException()), new FakeKeys(), new FakeUser(), new FakeValidation());
        var cancelCoordinator = new TaskCoordinator(f.Store, cancellationEngine);
        var canceled = await cancelCoordinator.ExecuteAsync(cancelCoordinator.Review(cancelledRequest), cancelledRequest, new InlineProgress<TaskProgress>(_ => { }), default);
        state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(cancelled)), "deployment-state.json"));
        Check(canceled.Outcome == TaskOutcome.Cancelled && state.Text("Modules.audit.Status") == "Cancelled" && InstanceLifecycle.Read(f.Store, f.Relative(cancelled), cancelled).CanContinue, "cancelled audit remained Running or not resumable");
        var offline = plan.DeepClone().AsObject(); offline["DesktopImport"] = new JsonObject { ["OfflineOnly"] = true };
        Check(InstanceLifecycle.Describe(offline, new JsonObject { ["Engine"] = "legacy-cli-offline" }).Managed, "offline production import hidden");
        LocalDeletion(f);
    }
    private void LocalDeletion(Fixture f)
    {
        InstanceDiscovery(f);
        var plan = f.Plan("DeleteLocal"); f.SaveInstance(plan); var relative = f.Relative(plan); var directory = f.Paths.Instance(relative);
        var source = f.Paths.Resolve("external/source-key"); Directory.CreateDirectory(Path.GetDirectoryName(source)!); File.WriteAllText(source, "synthetic-source-key");
        var settings = f.Paths.Resolve("private/desktop-settings.json"); File.WriteAllText(settings, "{}");
        var owned = SafePath.Resolve(directory, "ssh/managed"); Directory.CreateDirectory(Path.GetDirectoryName(owned)!); File.WriteAllText(owned, "synthetic-copy");
        var other = f.Plan("KeepLocal"); f.SaveInstance(other); var otherFile = SafePath.Resolve(f.Paths.Instance(f.Relative(other)), "deployment-plan.json"); var otherHash = ClientSchemes.SourceFingerprint(otherFile);
        var deletion = new InstanceDeletion(f.Store); var review = deletion.Review(relative); Check(review.FileCount >= 4 && review.Bytes > 0, "delete review incomplete");
        File.WriteAllText(SafePath.Resolve(directory, "new.private"), "changed"); Refuses(() => deletion.Delete(review), "stale delete review accepted"); Check(Directory.Exists(directory), "stale review removed archive");
        review = deletion.Review(relative);
        using (f.Store.LockInstance(relative)) { Refuses(() => deletion.Delete(review), "running archive deleted"); Check(Directory.Exists(directory), "busy refusal removed archive"); }
        using (var legacy = new FileStream(SafePath.Resolve(directory, ".operation.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)) Refuses(() => deletion.Delete(review), "legacy instance lock bypassed");
        var pending = SafePath.Resolve(directory, "operation-pending.dotnet.json"); ArchiveStore.WriteJson(pending, new JsonObject { ["Phase"] = "Armed" }); Refuses(() => deletion.Review(relative), "unresolved transaction deleted"); File.Delete(pending);
        Refuses(() => deletion.Review("../KeepLocal/MXH-VPS-Deploy"), "delete escaped instance root");
        var link = SafePath.Resolve(directory, "outside-link");
        try { File.CreateSymbolicLink(link, source); Refuses(() => deletion.Review(relative), "external source link traversed"); File.Delete(link); }
        catch (Exception e) when (OperatingSystem.IsWindows() && (e is UnauthorizedAccessException || e.HResult == unchecked((int)0x80070522))) { Console.WriteLine("SKIP: delete symlink fixture requires Windows privilege."); }
        review = deletion.Review(relative); deletion.Delete(review);
        Check(!Directory.Exists(directory) && !Directory.Exists(Path.GetDirectoryName(directory)!), "deleted instance or useless parent remains");
        Check(ClientSchemes.SourceFingerprint(otherFile) == otherHash && File.ReadAllText(source) == "synthetic-source-key" && File.ReadAllText(settings) == "{}", "delete affected another archive, original key or settings");
        Check(!Directory.Exists(f.Paths.Resolve("private/instance-deletions")), "delete left useless backup staging");
    }
    private void InstanceDiscovery(Fixture f)
    {
        var original = f.Plan("ArchiveDiscovery"); f.SaveInstance(original);
        var relative = f.Relative(original); var directory = f.Paths.Instance(relative);
        var backup = SafePath.Resolve(directory, "ip-change-example/deployment-plan.json"); ArchiveStore.WriteJson(backup, original);
        var nested = SafePath.Resolve(directory, "backups/example/instance-copy/deployment-plan.json"); ArchiveStore.WriteJson(nested, original);
        var misplaced = f.Paths.Resolve("private/instances/Example/MisplacedArchive/copy/deployment-plan.json"); ArchiveStore.WriteJson(misplaced, original);
        var mismatch = f.Plan("ArchiveIdentityMismatch"); var mismatchFile = SafePath.Resolve(f.Paths.Instance(f.Relative(mismatch)), "deployment-plan.json"); ArchiveStore.WriteJson(mismatchFile, original);
        var peer = f.Plan("ArchiveDiscoveryPeer"); peer["NodeName"] = original["NodeName"]!.DeepClone(); f.SaveInstance(peer);
        var draft = f.Plan("ArchiveDiscoveryDraft"); ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(draft)), "deployment-plan.json"), draft);
        var hash = ClientSchemes.SourceFingerprint(backup); var records = f.Store.ListInstances().ToArray();
        Check(records.Count(r => r.RelativePath == relative) == 1 && !records.Any(r => r.RelativePath.StartsWith(relative + "/", StringComparison.Ordinal)), "nested IP-change backup became a duplicate instance");
        Check(!records.Any(r => r.RelativePath.Contains("MisplacedArchive", StringComparison.Ordinal)) && !records.Any(r => r.RelativePath == f.Relative(mismatch)), "discovery accepted noncanonical layout or mismatched plan identity");
        Check(records.Any(r => r.RelativePath == f.Relative(peer)) && records.Any(r => r.RelativePath == f.Relative(draft)), "display-name deduplication hid legitimate peers or drafts");
        Check(File.Exists(nested) && File.Exists(misplaced) && ClientSchemes.SourceFingerprint(backup) == hash, "instance discovery changed backup data");
        foreach (var record in records) OperationPolicy.Validate(new(OperationKind.HealthAudit, record.RelativePath, new()));
        Refuses(() => new InstanceDeletion(f.Store).Review(relative + "/ip-change-example"), "deletion path validation was relaxed to delete backup entries");
        Check(new InstanceDeletion(f.Store).Review(relative).FileCount >= 4 && ClientSchemes.SourceFingerprint(backup) == hash, "normal deletion review failed or modified nested backups");
    }
}

internal sealed class RefusedConnection(Exception error) : IRemoteSessionFactory
{
    public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken token) => Task.FromException<IRemoteSession>(error);
}
