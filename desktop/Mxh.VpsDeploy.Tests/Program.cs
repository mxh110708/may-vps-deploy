using System.Text;
using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;
using Mxh.VpsDeploy.Infrastructure;

var repository = Path.GetFullPath(args.Length == 0 ? Path.Combine(AppContext.BaseDirectory, "../../../../../") : args[0]);
if (args.Contains("--fonts-only")) new BoundaryTests(repository).RunFontTests();
else if (args.Contains("--deployment-only")) await new BoundaryTests(repository).RunDeploymentTests();
else if (args.Contains("--background-only")) await new BoundaryTests(repository).RunBackgroundTests();
else if (args.Contains("--network-only")) await new BoundaryTests(repository).RunNetworkTests();
else if (args.Contains("--ssh-only")) await new BoundaryTests(repository).RunSshTests();
else await new BoundaryTests(repository).Run();

internal sealed partial class BoundaryTests(string repository)
{
    private int assertions;
    private void Check(bool value, string message) { if (!value) throw new Exception(message); assertions++; }
    private void Refuses(Action action, string message) { try { action(); } catch (OperationException) { assertions++; return; } throw new Exception(message); }
    private async Task RefusesAsync(Func<Task> action, string message) { try { await action(); } catch (OperationException) { assertions++; return; } throw new Exception(message); }
    public async Task RunNetworkTests()
    {
        using var f = new Fixture(repository); await NetworkExperience(f); Console.WriteLine($"PASS: {assertions} network direction, evidence, recovery and path assertions; no production connections.");
    }
    public async Task RunSshTests()
    {
        using var f = new Fixture(repository);
        var python = Environment.GetEnvironmentVariable("MXH_TEST_SSH_PYTHON") ?? throw new Exception("MXH_TEST_SSH_PYTHON is required for transport tests.");
        await LocalSshConfirmation(f, python); Console.WriteLine($"PASS: {assertions} loopback SSH/SFTP transport assertions; no production connections.");
    }
    public async Task Run()
    {
        using var f = new Fixture(repository); Paths(f); Fonts(f); await Coordinator(f); Publisher(f); SinglePublisher(f); Profiles(f); MultiPurpose(f); Keys(f); await Workflows(f); await DesktopDeployment(f); await Credentials(f); await Workbench(f); await Trust(f); await DeploymentExperience(f); await MaintenanceExperience(f);
        CloudflareCredentialExperience(f);
        ClientLayoutUpgradeExperience(f);
        await MonitoringArchiveExperience(f);
        await ComponentUpdateExperience(f);
        await RecoveryExperience(f);
        await PrivateDirectoryExperience();
        WindowPlacementExperience();
        await ManagedKeyDeployment(f);
        await AdditionsExperience(f);
        await TunnelAccessExperience(f); await NetworkExperience(f); await KernelExperience(f); await InstallationVersionExperience(f);
        await BackgroundTestTransport(f);
        await ReviewRepairExperience();
        await GlobalReviewExperience();
        await BackgroundFaultExperience(f);
        var sshPython = Environment.GetEnvironmentVariable("MXH_TEST_SSH_PYTHON"); if (!string.IsNullOrEmpty(sshPython)) await LocalSshConfirmation(f, sshPython);
        var python = Environment.GetEnvironmentVariable("MXH_TEST_PYTHON"); if (!string.IsNullOrEmpty(python)) { using var clients = new Fixture(repository); await RealClientWorkbench(clients, python); }
        Console.WriteLine($"PASS: {assertions} C# boundary and workflow assertions; no production connections.");
    }
    public void RunFontTests()
    {
        using var f = new Fixture(repository); Fonts(f); Console.WriteLine($"PASS: {assertions} font import and storage boundary assertions.");
    }
    private void Fonts(Fixture f)
    {
        var source = Path.Combine(repository, "assets/gui/fonts/LXGWWenKai-Regular.ttf"); var original = File.ReadAllBytes(source); var digest = ArchiveStore.Digest(original);
        Check(LocalFonts.Family(original) == "LXGW WenKai", "bundled font family incorrect");
        var catalog = new LocalFonts(f.Paths); var font = catalog.Import(source); var repeated = catalog.Import(source);
        Check(font.Id == repeated.Id && Directory.EnumerateFiles(f.Paths.Resolve("private/fonts")).Count() == 1, "duplicate import created backup");
        Check(font.FilePath.StartsWith(f.Paths.Private) && catalog.Resolve(font.Id).Family == "LXGW WenKai", "font escaped app data or lost family");
        Check(ArchiveStore.Digest(File.ReadAllBytes(source)) == digest, "source font modified"); Check(catalog.List().Single().Id == font.Id, "font selection unavailable");
        Refuses(() => catalog.Resolve("Custom:../outside.ttf"), "font path escaped app"); Refuses(() => catalog.Resolve("Custom:" + new string('a', 64) + ".ttf"), "missing font accepted");
        var fake = f.Paths.Resolve("fake.ttf"); File.WriteAllBytes(fake, new byte[40]); Refuses(() => catalog.Import(fake), "renamed non-font accepted");
        Refuses(() => catalog.Import(source + ".woff"), "unsupported font format accepted");
        var large = f.Paths.Resolve("large.ttf"); using (var file = File.Create(large)) file.SetLength(LocalFonts.MaximumBytes + 1L); Refuses(() => catalog.Import(large), "unbounded font read");
        var corrupt = original.ToArray(); corrupt[12 + 8] = 0x7F; Refuses(() => LocalFonts.Family(corrupt), "font table bounds ignored");
        corrupt = original.ToArray(); Encoding.ASCII.GetBytes("ttcf").CopyTo(corrupt, 0); Refuses(() => LocalFonts.Family(corrupt), "unsupported collection accepted");
        corrupt = original.ToArray(); Encoding.ASCII.GetBytes("OTTO").CopyTo(corrupt, 0); Refuses(() => LocalFonts.Family(corrupt), "mismatched outlines accepted");
        File.WriteAllBytes(font.FilePath, new byte[40]); Refuses(() => catalog.Resolve(font.Id), "modified imported font trusted");
        Refuses(() => catalog.Import(source), "modified font overwritten"); Check(File.ReadAllBytes(font.FilePath).Length == 40 && !catalog.List().Any(), "font tamper lost or remained selectable");
    }
    private void Paths(Fixture f)
    {
        foreach (var name in new[] { "..", "../outside", "a/b", "a\\b", "NUL", "CON.txt", "a.", "a:" }) Refuses(() => AppPaths.Segment(name), "unsafe segment accepted");
        foreach (var name in new[] { "../outside", "/outside", "a/../outside", "a//b", "a\\b", "a:b" }) Refuses(() => f.Paths.Resolve(name), "escaping path accepted");
        Check(f.Paths.Instance("Example/Node/MXH-VPS-Deploy").StartsWith(f.Paths.Private), "archive not centralized");
        var path = f.Paths.Resolve("private/secret.private.json"); f.Store.WriteSecret(path, new JsonObject { ["Password"] = "synthetic-credential" });
        Check(!File.ReadAllText(path).Contains("synthetic-credential"), "clear secret stored"); Check(f.Store.ReadSecret(path).Text("Password") == "synthetic-credential", "protected secret roundtrip");
        Check(ArchiveStore.Fingerprint(JsonNode.Parse("{\"a\":1,\"b\":2}")!) == ArchiveStore.Fingerprint(JsonNode.Parse("{\"b\":2,\"a\":1}")!), "canonical hash unstable");
        var outside = Path.Combine(f.Root, "link-target"); Directory.CreateDirectory(outside); var link = Path.Combine(f.Root, "private", "link");
        try { Directory.CreateSymbolicLink(link, outside); Refuses(() => f.Paths.Resolve("private/link/value"), "link boundary bypass"); Directory.Delete(link); File.CreateSymbolicLink(link, Path.Combine(outside, "missing")); Refuses(() => f.Paths.Resolve("private/link"), "dangling link bypass"); File.Delete(link); }
        catch (Exception error) when (OperatingSystem.IsWindows() && (error is UnauthorizedAccessException || error.HResult == unchecked((int)0x80070522))) { Console.WriteLine("SKIP: Windows symlink privilege; Unix CI runs link assertions."); }
    }
    private async Task Coordinator(Fixture f)
    {
        var called = 0; var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => { called++; return Task.FromResult(TaskOutcome.Completed); }));
        var request = new OperationRequest(OperationKind.HealthAudit, "Example/Coordinator/MXH-VPS-Deploy", new()); var review = coordinator.Review(request); request.Options["changed"] = true;
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "changed form executed"); Check(called == 0, "stale form sent command"); request.Options.Clear(); review = coordinator.Review(request);
        ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(request.InstanceRelativePath), "deployment-state.json"), new JsonObject { ["Changed"] = true });
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "changed archive executed"); Check(called == 0, "stale archive sent command");
        var entered = new TaskCompletionSource(); var release = new TaskCompletionSource(); var serial = new TaskCoordinator(f.Store, new FakeWorkflow(async _ => { entered.SetResult(); await release.Task; return TaskOutcome.Completed; }));
        var a = request with { InstanceRelativePath = "Example/Concurrency/MXH-VPS-Deploy" }; var r = serial.Review(a); var running = serial.ExecuteAsync(r, a, new InlineProgress<TaskProgress>(_ => { }), default); await entered.Task;
        await RefusesAsync(() => serial.ExecuteAsync(r, a, new InlineProgress<TaskProgress>(_ => { }), default), "concurrent task entered"); release.SetResult(); Check((await running).Outcome == TaskOutcome.Completed, "success lost");
        using (f.Store.LockInstance(a.InstanceRelativePath)) Refuses(() => f.Store.LockInstance(a.InstanceRelativePath), "instance lock bypass");
        var cancel = new TaskCoordinator(f.Store, new FakeWorkflow(_ => throw new OperationCanceledException())); Check((await cancel.ExecuteAsync(cancel.Review(a), a, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Cancelled, "cancel misclassified");
        var recovery = new TaskCoordinator(f.Store, new FakeWorkflow(_ => throw new OperationException("recover", true))); Check((await recovery.ExecuteAsync(recovery.Review(a), a, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.NeedsRecovery, "uncertainty hidden");
        var failure = new TaskCoordinator(f.Store, new FakeWorkflow(_ => throw new Exception("synthetic-credential"))); var record = await failure.ExecuteAsync(failure.Review(a), a, new InlineProgress<TaskProgress>(_ => { }), default); Check(!record.SafeError!.Contains("synthetic-credential"), "exception leaked secret");
        Refuses(() => coordinator.Review(request with { InstanceRelativePath = "Example/../escape" }), "invalid instance accepted");
        Refuses(() => OperationPolicy.Validate(new(OperationKind.Komari, a.InstanceRelativePath, new JsonObject { ["Scope"] = "KomariController", ["Action"] = "Remove" })), "controller removal affects Tunnel");
        Refuses(() => OperationPolicy.Validate(new(OperationKind.Upgrade, a.InstanceRelativePath, new JsonObject { ["Scope"] = "Firewall" })), "upgrade scope mismatch accepted");
    }
    private void Publisher(Fixture f)
    {
        var directory = f.Paths.Resolve("authority"); Directory.CreateDirectory(directory); var c = SafePath.Resolve(directory, "clash.yaml"); var s = SafePath.Resolve(directory, "sing.json"); var cc = SafePath.Resolve(directory, "clash.candidate"); var ss = SafePath.Resolve(directory, "sing.candidate");
        File.WriteAllText(c, "old-clash"); File.WriteAllText(s, "old-sing"); File.WriteAllText(cc, "new-clash"); File.WriteAllText(ss, "new-sing");
        JsonObject Candidate() => new() { ["ValidationStatus"] = "Passed", ["Clash"] = cc, ["SingBox"] = ss, ["ClashHash"] = ClientSchemes.SourceFingerprint(cc), ["SingBoxHash"] = ClientSchemes.SourceFingerprint(ss), ["Sources"] = new JsonObject(), ["Targets"] = new JsonObject { [c] = ClientSchemes.SourceFingerprint(c), [s] = ClientSchemes.SourceFingerprint(s) } };
        var candidate = Candidate(); candidate["ValidationStatus"] = "Pending"; Refuses(() => new CandidatePublisher(f.Paths).Publish(candidate, c, s), "unchecked candidate published");
        candidate = Candidate(); File.WriteAllText(s, "external-edit"); Refuses(() => new CandidatePublisher(f.Paths).Publish(candidate, c, s), "stale target overwritten"); Check(File.ReadAllText(c) == "old-clash", "first target changed before stale check"); File.WriteAllText(s, "old-sing");
        var writes = 0; var publisher = new CandidatePublisher(f.Paths, (path, bytes) => { ArchiveStore.AtomicWrite(path, bytes); if (++writes == 2) throw new IOException("lost after replace"); });
        Refuses(() => publisher.Publish(Candidate(), c, s), "failure not reported"); Check(File.ReadAllText(c) == "old-clash" && File.ReadAllText(s) == "old-sing", "pair not restored after lost acknowledgement");
        new CandidatePublisher(f.Paths).Publish(Candidate(), c, s); Check(File.ReadAllText(c) == "new-clash" && File.ReadAllText(s) == "new-sing", "pair incomplete");
        var journalDirectory = f.Paths.Resolve("private/client-publish/" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(journalDirectory); var journal = SafePath.Resolve(journalDirectory, "transaction.json");
        File.WriteAllText(c, "after-crash"); var newHash = ClientSchemes.SourceFingerprint(c); ArchiveStore.AtomicWrite(SafePath.Resolve(journalDirectory, "0.backup"), Encoding.UTF8.GetBytes("new-clash")); ArchiveStore.AtomicWrite(SafePath.Resolve(journalDirectory, "1.backup"), Encoding.UTF8.GetBytes("new-sing"));
        ArchiveStore.WriteJson(journal, new JsonObject { ["Phase"] = "Prepared", ["Targets"] = new JsonArray(c, s), ["Hashes"] = new JsonArray(newHash, ClientSchemes.SourceFingerprint(s)), ["OriginalHashes"] = new JsonArray(ArchiveStore.Digest(Encoding.UTF8.GetBytes("new-clash")), ClientSchemes.SourceFingerprint(s)) });
        Refuses(() => new CandidatePublisher(f.Paths).Publish(Candidate(), c, s), "unfinished publish ignored"); new CandidatePublisher(f.Paths).Recover(journal); Check(File.ReadAllText(c) == "new-clash", "crash before Applied not recovered");
        var data = ArchiveStore.ReadJson(journal); data["Phase"] = "Prepared"; ArchiveStore.WriteJson(journal, data); File.WriteAllText(c, "external-after-crash"); Refuses(() => new CandidatePublisher(f.Paths).Recover(journal), "recovery overwrote external edit"); Check(File.ReadAllText(c) == "external-after-crash", "external edit lost"); data["Phase"] = "RolledBack"; ArchiveStore.WriteJson(journal, data);
    }
    private void SinglePublisher(Fixture f)
    {
        foreach (var mode in new[] { "SingBox", "Clash" })
        {
            var directory = f.Paths.Resolve("single-authority/" + mode); Directory.CreateDirectory(directory);
            var target = SafePath.Resolve(directory, "output"); var source = SafePath.Resolve(directory, "candidate"); File.WriteAllText(target, "original"); File.WriteAllText(source, "candidate");
            var format = mode == "SingBox" ? "SingBox" : "Clash";
            JsonObject Candidate() => new() { ["OutputClients"] = mode, ["ValidationStatus"] = "Passed", [format] = source, [format + "Hash"] = ClientSchemes.SourceFingerprint(source), ["Sources"] = new JsonObject(), ["Targets"] = new JsonObject { [target] = ClientSchemes.SourceFingerprint(target) } };
            var publisher = new CandidatePublisher(f.Paths, (path, bytes) => { ArchiveStore.AtomicWrite(path, bytes); throw new IOException("lost single-file acknowledgement"); });
            Refuses(() => publisher.Publish(Candidate(), mode == "Clash" ? target : "", mode == "SingBox" ? target : ""), "single lost ack accepted"); Check(File.ReadAllText(target) == "original", "single lost ack did not rollback");
            var candidate = Candidate(); File.WriteAllText(target, "outside edit"); Refuses(() => new CandidatePublisher(f.Paths).Publish(candidate, mode == "Clash" ? target : "", mode == "SingBox" ? target : ""), "single stale target replaced"); Check(File.ReadAllText(target) == "outside edit", "single outside edit lost");
            new CandidatePublisher(f.Paths).Publish(Candidate(), mode == "Clash" ? target : "", mode == "SingBox" ? target : ""); Check(File.ReadAllText(target) == "candidate", "single export failed without other target");
            var transaction = f.Paths.Resolve("private/client-publish/" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(transaction); var journal = SafePath.Resolve(transaction, "transaction.json");
            ArchiveStore.AtomicWrite(SafePath.Resolve(transaction, "0.backup"), Encoding.UTF8.GetBytes("recovery original"));
            var data = new JsonObject { ["SchemaVersion"] = 2, ["Formats"] = new JsonArray(format), ["Phase"] = "Prepared", ["Targets"] = new JsonArray(target), ["Hashes"] = new JsonArray(ClientSchemes.SourceFingerprint(target)), ["OriginalHashes"] = new JsonArray(ArchiveStore.Digest(Encoding.UTF8.GetBytes("recovery original"))) };
            ArchiveStore.WriteJson(journal, data); new CandidatePublisher(f.Paths).Recover(journal); Check(File.ReadAllText(target) == "recovery original", "single recovery failed");
            data["Phase"] = "Prepared"; data["SchemaVersion"] = 99; ArchiveStore.WriteJson(journal, data); Refuses(() => new CandidatePublisher(f.Paths).Recover(journal), "unknown schema recovered");
            data["SchemaVersion"] = 2; ArchiveStore.WriteJson(journal, data); File.WriteAllText(target, "external after crash"); Refuses(() => new CandidatePublisher(f.Paths).Recover(journal), "single recovery overwrote outside edit"); data["Phase"] = "RolledBack"; ArchiveStore.WriteJson(journal, data);
        }
    }
    private void MultiPurpose(Fixture f)
    {
        var tokenFile = f.Paths.Resolve("private/synthetic-cert-token.txt"); File.WriteAllText(tokenFile, "synthetic-token");
        var form = new JsonObject { ["Provider"] = "Example", ["Instance"] = "Multi", ["NodeName"] = "Multi", ["IPv4"] = "192.0.2.10", ["SshPort"] = 22, ["Roles"] = new JsonArray("AnyTlsEntry", "ShadowsocksLanding", "RealityEntry"), ["ActiveEntry"] = "RealityEntry", ["RealityTarget"] = "example.com", ["AnyTlsName"] = "entry.example.com", ["EchPublicName"] = "ech.example.com", ["TrustedEntries"] = "192.0.2.20", ["ZoneName"] = "example.com", ["CertbotEmail"] = "ops@example.com", ["CloudflareTokenFile"] = tokenFile };
        var plan = DeploymentPlans.Create(form, f.Versions, f.Paths, false);
        Check(DeploymentPlans.Purposes(plan).Length == 3 && DeploymentPlans.InitiallyEnabled(plan, "RealityEntry") && !DeploymentPlans.InitiallyEnabled(plan, "AnyTlsEntry") && DeploymentPlans.InitiallyEnabled(plan, "ShadowsocksLanding"), "multi-purpose default listener lost");
        Check(plan.Text("NetworkTuning.Mode") == "Manual" && plan.Number("NetworkTuning.BandwidthMbps") == 0, "new deployment requires tuning values");
        var secrets = Fixture.RealitySecrets(); secrets["AnyTls"] = new JsonObject { ["Password"] = "synthetic-password", ["EchClientConfigPem"] = "fixture" }; secrets["Shadowsocks"] = new JsonObject { ["ServerKey"] = "fixture", ["PrimaryUserKey"] = "fixture" };
        var nodes = ClientProfiles.Nodes(plan, secrets).ToArray(); Check(nodes.Select(n => n.Name).Distinct().Count() == nodes.Length && nodes.Any(n => n.Role == "AnyTlsEntry") && nodes.Any(n => n.Role == "ShadowsocksLanding"), "combined node names collided");
        Check(ClientProfiles.Nodes(plan, secrets, true).All(n => n.Role != "AnyTlsEntry"), "inactive entry exported as active");
        plan.Put("Ports.LandingShadowsocks", JsonValue.Create(443)); Refuses(() => DeploymentPlans.Validate(plan), "shared entry/landing listener accepted");
        form["ActiveEntry"] = "ShadowsocksLanding"; Refuses(() => DeploymentPlans.Create(form, f.Versions, f.Paths, false), "non-entry selected as active entry");
        form["Roles"] = new JsonArray("RealityEntry", "unknown"); Refuses(() => DeploymentPlans.Create(form, f.Versions, f.Paths, false), "unknown purpose accepted");
    }
    private async Task DesktopDeployment(Fixture f)
    {
        foreach (var mode in new[] { "Single", "EntryLanding", "All" })
        {
            var multiple = mode != "Single"; var plan = f.Plan("DesktopDeploy" + mode);
            if (multiple) { plan["Roles"] = new JsonArray("ShadowsocksLanding", "RealityEntry"); plan.Put("Shadowsocks.TrustedEntryIPv4s", new JsonArray("192.0.2.20")); }
            if (mode == "All")
            {
                plan["Roles"] = new JsonArray("AnyTlsEntry", "ShadowsocksLanding", "RealityEntry"); plan.Put("AnyTls.ServerName", JsonValue.Create("entry.example.com")); plan.Put("AnyTls.EchPublicName", JsonValue.Create("ech.example.com"));
                var tokenFile = f.Paths.Resolve("private/deploy-synthetic-token.txt"); File.WriteAllText(tokenFile, "synthetic-token"); plan.Put("TrustedTls.Enabled", JsonValue.Create(true)); plan.Put("TrustedTls.ZoneName", JsonValue.Create("example.com")); plan.Put("TrustedTls.CertbotEmail", JsonValue.Create("ops@example.com")); plan.Put("TrustedTls.CloudflareTokenFile", JsonValue.Create(tokenFile));
            }
            var remote = new FakeRemote(); var task = Guid.NewGuid().ToString("N");
            var outcome = await f.Engine(remote).ExecuteAsync(new(OperationKind.Deploy, f.Relative(plan), new JsonObject { ["Plan"] = plan }), task, new InlineProgress<TaskProgress>(_ => { }), default);
            Check(outcome == TaskOutcome.Completed && !remote.Commands.Contains("network-tuning.sh"), "deployment applied network tuning");
            Check(remote.Commands.Contains("xray-apply-config.sh") && (!multiple || remote.Commands.Contains("sing-box-apply-config.sh") && remote.Commands.Contains("protocol-lifecycle-apply-state.sh")), "combined deployment did not install selected protocols");
            if (mode == "All") { Check(remote.Commands.IndexOf("xray-apply-config.sh") < remote.Commands.IndexOf("anytls-apply-config.sh"), "conflicting entry installed in wrong order"); var actual = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-plan.json")); Check(actual.Flag("ProtocolInventory.RealityEntry.Enabled") && actual.Flag("ProtocolInventory.AnyTlsEntry.Installed") && !actual.Flag("ProtocolInventory.AnyTlsEntry.Enabled") && actual.Flag("ProtocolInventory.ShadowsocksLanding.Enabled"), "default entry/landing state lost"); }
            var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json")); Check(state.Text("Modules.network-tuning.Status") == "Skipped" && state["NetworkTuning"] == null, "manual tuning boundary not recorded");
        }
    }
    private void Profiles(Fixture f)
    {
        var unselected = ClientSchemes.New(f.Paths); unselected["OutputClients"] = "None"; Check(ClientSchemes.OutputLabel(unselected) == "未选择生成目标", "unselected draft cannot be displayed");
        Refuses(() => ClientSchemes.Specification(unselected), "unselected draft generated client files");
        var plan = f.Plan("Profiles"); plan.Put("Server.IPv6", JsonValue.Create("2001:db8::10")); var nodes = ClientProfiles.Nodes(plan, Fixture.RealitySecrets()).ToArray();
        Check(nodes.Length == 4 && nodes.Select(n => n.Name).Distinct().Count() == 4, "dual entries missing/duplicated");
        foreach (var node in nodes) { var clash = ClientProfiles.ClashProbe(node, 12345); var sing = ClientProfiles.SingProbe(node, 12345); Check(!clash.Flag("allow-lan") && clash.Text("bind-address") == "127.0.0.1" && clash.Text("mode") == "rule", "probe controls system routing"); Check(sing.At("inbounds")!.AsArray()[0]!.Text("listen") == "127.0.0.1" && sing.Text("route.final") == node.Name, "probe not forced to target"); }
        var network = DeploymentPlans.Network("RealityEntry", 1024 * 1024, 500, 120); Check(network.Long("BUFFER_TARGET_BYTES") <= network.Long("BUFFER_CAP_BYTES"), "buffer exceeds memory cap"); Refuses(() => DeploymentPlans.Network("RealityEntry", 1, 500, 120), "invalid memory tuned");
        var p = f.Plan("BadPorts"); Check(p.Number("Ports.SshPrimary") != p.Number("Ports.SshRescue"), "duplicate SSH entries"); p.Put("Ports.SshRescue", p.At("Ports.SshPrimary")!.DeepClone()); Refuses(() => DeploymentPlans.Validate(p), "duplicate SSH plan accepted");
    }
    private void Keys(Fixture f)
    {
        var manager = new ManagedKeys(new NoopKeyAccess()); var path = manager.Prepare(f.Paths.Resolve("private/test-key"), ""); var bytes = File.ReadAllBytes(path); Check(File.ReadAllText(path + ".pub").StartsWith("ecdsa-sha2-nistp256 "), "key not OpenSSH compatible");
        Check(manager.Prepare(Path.GetDirectoryName(path)!, "") == path && bytes.SequenceEqual(File.ReadAllBytes(path)), "key regenerated"); var copy = manager.Prepare(f.Paths.Resolve("private/key-copy"), path); Check(bytes.SequenceEqual(File.ReadAllBytes(path)) && bytes.SequenceEqual(File.ReadAllBytes(copy)), "provider key changed");
        File.WriteAllText(copy + ".pub", "mismatch fixture"); Refuses(() => manager.Prepare(Path.GetDirectoryName(copy)!, ""), "mismatched key accepted"); Check(File.ReadAllText(copy + ".pub") == "mismatch fixture", "public key overwritten");
    }
    private async Task Workflows(Fixture f)
    {
        var plan = f.Plan("ReadOnly"); f.SaveInstance(plan); var remote = new FakeRemote(); var engine = f.Engine(remote); var request = new OperationRequest(OperationKind.HealthAudit, f.Relative(plan), new());
        await engine.ExecuteAsync(request, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); Check(remote.Commands.SequenceEqual(new[] { "maintenance-health-audit.sh" }) && remote.Mutations == 0, "health mutated remote");
        var identity = request with { InstanceRelativePath = "Example/Wrong/MXH-VPS-Deploy" }; ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(identity.InstanceRelativePath), "deployment-plan.json"), plan); await RefusesAsync(() => engine.ExecuteAsync(identity, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "identity mismatch executed");
        var pending = new JsonObject { ["Phase"] = "Armed", ["TaskId"] = Guid.NewGuid().ToString("N"), ["RemoteBackup"] = FakeRemote.Backup }; ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(request.InstanceRelativePath), "operation-pending.dotnet.json"), pending);
        var before = remote.Commands.Count; await RefusesAsync(() => engine.ExecuteAsync(request, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "pending ignored"); Check(before == remote.Commands.Count, "blocked task contacted remote"); remote.StatusTaskId = Guid.NewGuid().ToString("N"); remote.StatusPhase = "Armed";
        await RefusesAsync(() => engine.ExecuteAsync(request with { Kind = OperationKind.Recover }, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "wrong transaction recovered"); Check(!remote.Commands.Contains("protocol-migration-trigger-rollback.sh"), "unknown rollback sent");
        var deployPlan = f.Plan("LostBaseline"); var deployRemote = new FakeRemote { FailAsset = "deployment-baseline-arm.sh" }; var deploy = new OperationRequest(OperationKind.Deploy, f.Relative(deployPlan), new JsonObject { ["Plan"] = deployPlan });
        await RefusesAsync(() => f.Engine(deployRemote).ExecuteAsync(deploy, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "lost baseline accepted"); var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(deploy.InstanceRelativePath), "deployment-state.json")); Check(state.Text("DeploymentTransaction.Status") == "Arming", "no baseline recovery identity");
        await RefusesAsync(() => f.Engine(deployRemote).ExecuteAsync(deploy with { Kind = OperationKind.Resume, Options = new() }, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "uncertain deploy replayed"); Check(!deployRemote.Commands.Contains("base-system.sh"), "uncertain deploy advanced");
        Check(deployRemote.BaselineNetworkCapture == "false", "native deployment baseline captured independent network settings");
        await f.Engine(deployRemote).ExecuteAsync(deploy with { Kind = OperationKind.Recover, Options = new() }, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
        Check(deployRemote.BaselineNetworkRestore == "false", "native initial recovery requested a network rollback");
        var scopePlan = f.Plan("Scope"); f.SaveInstance(scopePlan); var networkRemote = new FakeRemote(); var network = new OperationRequest(OperationKind.TuneNetwork, f.Relative(scopePlan), new JsonObject { ["Scope"] = "Network", ["Profile"] = "EntryBasic" }); var task = Guid.NewGuid().ToString("N"); networkRemote.StatusTaskId = task;
        await f.Engine(networkRemote).ExecuteAsync(network, task, new InlineProgress<TaskProgress>(_ => { }), default); Check(networkRemote.ArmedComponents == "Network", "backup scope expanded"); Check(!networkRemote.Commands.Any(x => x is "xray-install.sh" or "ssh-transition.sh" or "nftables-apply.sh"), "network replayed unrelated modules");
        var commitPlan = f.Plan("LostCommit"); f.SaveInstance(commitPlan); var commitRemote = new FakeRemote { FailAsset = "maintenance-transaction-commit.sh", StatusPhase = "Committed" }; task = Guid.NewGuid().ToString("N"); commitRemote.StatusTaskId = task;
        Check(await f.Engine(commitRemote).ExecuteAsync(network with { InstanceRelativePath = f.Relative(commitPlan) }, task, new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.CompletedWithWarnings, "committed remote misclassified"); Check(!commitRemote.Commands.Contains("protocol-migration-trigger-rollback.sh"), "committed remote rolled back");
        var failPlan = f.Plan("ScopedRollback"); f.SaveInstance(failPlan); var failure = new FakeRemote { FailAsset = "network-apply.sh", StatusPhase = "Armed" }; task = Guid.NewGuid().ToString("N"); failure.StatusTaskId = task;
        await RefusesAsync(() => f.Engine(failure).ExecuteAsync(network with { InstanceRelativePath = f.Relative(failPlan) }, task, new InlineProgress<TaskProgress>(_ => { }), default), "failed tune accepted"); Check(ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(failPlan)), "deployment-plan.json")).Text("Reality.Target") == "example.com", "rollback changed protocol"); Check(failure.Commands.Contains("protocol-migration-trigger-rollback.sh"), "network not recovered");
        before = networkRemote.Commands.Count; await RefusesAsync(() => f.Engine(networkRemote).ExecuteAsync(network with { Kind = OperationKind.Komari, Options = new JsonObject { ["Scope"] = "KomariController", ["Action"] = "Remove" } }, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "destructive controller scope accepted"); Check(before == networkRemote.Commands.Count, "invalid task armed backup");
    }
    private async Task Workbench(Fixture f)
    {
        var scheme = ClientSchemes.New(f.Paths); var node = ClientProfiles.Nodes(f.Plan("Client"), Fixture.RealitySecrets()).First(); scheme["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = node.Name, ["kind"] = "entry", ["region_group"] = "US-West Entry", ["transit_group"] = "US-West Entry", ["clash"] = node.Clash.DeepClone(), ["sing_box"] = node.SingBox.DeepClone() });
        var clash = f.Paths.Resolve("private/fake.candidate.yaml"); var sing = f.Paths.Resolve("private/fake.candidate.json"); File.WriteAllText(clash, "fixture"); File.WriteAllText(sing, "fixture"); scheme["Candidate"] = new JsonObject { ["Clash"] = clash, ["SingBox"] = sing, ["ClashHash"] = ClientSchemes.SourceFingerprint(clash), ["SingBoxHash"] = ClientSchemes.SourceFingerprint(sing), ["ValidationStatus"] = "Passed", ["SpecFingerprint"] = ArchiveStore.Fingerprint(ClientSchemes.Specification(scheme)) };
        var workbench = new ClientWorkbench(f.Store, new FakeTools(), new FakeAssets(), "unused"); await RefusesAsync(() => workbench.ValidateAsync(scheme, default), "failed core accepted"); Check(scheme.Text("Candidate.ValidationStatus") == "Failed" && scheme.Text("Candidate.ValidationError") != "" && !scheme.Text("Candidate.ValidationError").Contains("synthetic-credential"), "failure retained Passed or leaked validator output");
    }
    private async Task Credentials(Fixture f)
    {
        foreach (var imported in new[] { false, true })
        {
            var plan = f.Plan(imported ? "ImportedPassword" : "ManagedPassword");
            if (imported) plan["Import"] = new JsonObject { ["SshAuthenticationPreserved"] = true };
            f.SaveInstance(plan); var secretFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "secrets.dotnet.private.json"); var secrets = f.Store.ReadSecret(secretFile);
            if (imported) secrets.Remove("AdminPassword"); else secrets["AdminPassword"] = "synthetic-admin";
            f.Store.WriteSecret(secretFile, secrets); secrets.Clear();
            var task = Guid.NewGuid().ToString("N"); var remote = new FakeRemote { StatusTaskId = task }; var user = new FakeUser(title => title.StartsWith("root ", StringComparison.Ordinal) ? "synthetic-root" : "synthetic-admin");
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), user, new FakeValidation());
            await engine.ExecuteAsync(new(OperationKind.TuneNetwork, f.Relative(plan), new JsonObject { ["Scope"] = "Network", ["Profile"] = "EntryBasic" }), task, new InlineProgress<TaskProgress>(_ => { }), default);
            Check(remote.Endpoints.Any(e => e.User == "admin") && remote.Endpoints.Where(e => e.User == "admin").All(e => e.Password == "synthetic-admin"), "root credential reused for admin");
            Check(remote.Endpoints.Where(e => e.User == "root").All(e => e.Password == "synthetic-root"), "admin credential reused for root");
            Check(user.SecretPrompts.Count(title => title.StartsWith("root ", StringComparison.Ordinal)) == 1 && user.SecretPrompts.Count(title => title.StartsWith("admin ", StringComparison.Ordinal)) == (imported ? 1 : 0), "task credential cache mixed users");
        }
    }
    private async Task RealClientWorkbench(Fixture f, string python)
    {
        var source = Path.Combine(repository, "vendor/test-cores/windows-amd64"); if (!OperatingSystem.IsWindows()) return;
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories)) { var target = f.Paths.Resolve("vendor/test-cores/windows-amd64/" + Path.GetRelativePath(source, file).Replace('\\', '/')); Directory.CreateDirectory(Path.GetDirectoryName(target)!); File.Copy(file, target); }
        var assets = new ValidationAssets(f.Paths, "windows-amd64"); var workbench = new ClientWorkbench(f.Store, new ExternalToolRunner(), assets, python);
        var scheme = ClientSchemes.New(f.Paths); var secrets = Fixture.RealitySecrets(); secrets.Put("Xray.RealityClientKey", JsonValue.Create(ServerConfigurations.RandomKey(32).Replace('+', '-').Replace('/', '_').TrimEnd('=')));
        var node = ClientProfiles.Nodes(f.Plan("RealCore"), secrets).First(); scheme["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = node.Name, ["kind"] = "entry", ["region_group"] = "US-West Entry", ["transit_group"] = "US-West Entry", ["clash"] = node.Clash.DeepClone(), ["sing_box"] = node.SingBox.DeepClone() });
        var candidate = await workbench.BuildAsync(scheme, default); await workbench.ValidateAsync(scheme, default); Check(candidate.Text("ValidationStatus") == "Passed", "real fixed cores rejected candidate");
        var clash = f.Paths.Resolve("real-authority/clash.yaml"); var sing = f.Paths.Resolve("real-authority/sing.json"); workbench.PreparePublish(scheme, clash, sing); workbench.Publish(scheme, clash, sing); Check(File.Exists(clash) && File.Exists(sing), "real candidate not published to fixture");
        foreach (var mode in new[] { "SingBox", "Clash" })
        {
            var format = mode == "Clash" ? "Clash" : "SingBox"; var other = format == "Clash" ? "SingBox" : "Clash";
            var single = ClientSchemes.New(f.Paths); single["OutputClients"] = mode; single[other] = f.Paths.Resolve("nonexistent-unused-source"); single["Nodes"] = scheme["Nodes"]!.DeepClone();
            foreach (var item in single["Nodes"]!.AsArray()) item![other == "Clash" ? "clash" : "sing_box"] = null;
            var singleWorkbench = new ClientWorkbench(f.Store, new ExternalToolRunner(), new SelectedAssets(assets, mode == "Clash" ? "mihomo" : "sing-box"), python);
            var onlyCandidate = await singleWorkbench.BuildAsync(single, default); await singleWorkbench.ValidateAsync(single, default); Check(onlyCandidate.Text("ValidationStatus") == "Passed" && onlyCandidate[other] == null, "single build or validation used unselected client");
            var target = f.Paths.Resolve("real-authority/" + mode + "/config" + (mode == "Clash" ? ".yaml" : ".json")); singleWorkbench.PreparePublish(single, mode == "Clash" ? target : "", mode == "SingBox" ? target : ""); singleWorkbench.Publish(single, mode == "Clash" ? target : "", mode == "SingBox" ? target : ""); Check(File.Exists(target), "single core-validated export failed");
            if (mode == "SingBox")
            {
                var existing = ArchiveStore.ReadJson(target); var group = existing["outbounds"]!.AsArray().Single(item => item!.Text("tag") == "US-West Entry")!.AsObject();
                group["type"] = "urltest"; group.Remove("default"); group["url"] = "https://example.com/"; group["interval"] = "10m";
                ArchiveStore.WriteJson(target, existing);
            }
            var fingerprint = ClientSchemes.SourceFingerprint(target); var imported = await singleWorkbench.ReadSourcesAsync(mode == "Clash" ? target : "", mode == "SingBox" ? target : "", default);
            Check(imported.Count == 1 && imported[0]![other == "Clash" ? "clash" : "sing_box"] == null && fingerprint == ClientSchemes.SourceFingerprint(target), "single source import changed source or required pair");
            single["Nodes"] = imported; single[format] = target; single["SourceMode"] = "ExistingAuthority"; single["SourceFingerprints"] = new JsonObject { [format] = fingerprint };
            foreach (var item in imported) { item!["region_group"] = "US-West Entry"; item["transit_group"] = "US-West Entry"; }
            await singleWorkbench.BuildAsync(single, default); await singleWorkbench.ValidateAsync(single, default); Check(single.Text("Candidate.ValidationStatus") == "Passed", "single imported config did not rebuild");
            if (mode == "SingBox") Check(ArchiveStore.ReadJson(single.Text("Candidate.SingBox"))["outbounds"]!.AsArray().Count(item => item!.Text("tag") == "US-West Entry") == 1, "actual urltest source rebuild duplicated the generated group");
            File.AppendAllText(target, "\n "); await RefusesAsync(() => singleWorkbench.BuildAsync(single, default), "changed imported source accepted");
            singleWorkbench.Delete(single); Check(!singleWorkbench.List().Any(s => s.Text("Id") == single.Text("Id")) && File.Exists(target), "deleting scheme removed exported authority");
        }
        var cache = assets.ResolveCore("mihomo"); File.AppendAllText(cache, "fixture-tamper"); Refuses(() => assets.ResolveCore("mihomo"), "tampered cache accepted"); Check(File.ReadAllBytes(cache).AsSpan().EndsWith(Encoding.UTF8.GetBytes("fixture-tamper")), "tampered cache silently cleared");
        Console.WriteLine("PASS: real Python builder, pinned cores, selected-client import/build/check/export/delete.");
    }
    private async Task Trust(Fixture f)
    {
        var trust = new HostTrust(f.Store); var accept = new FakeUser(); Check(await trust.AcceptAsync("192.0.2.123", 22, "fixture", [1, 2, 3], accept, default), "first host not confirmed");
        Check(await trust.AcceptAsync("192.0.2.123", 23456, "fixture", [1, 2, 3], accept, default), "rescue port lost host identity"); var file = f.Paths.Resolve("private/ssh-hosts.dotnet.json"); var before = File.ReadAllBytes(file);
        await RefusesAsync(async () => { await trust.AcceptAsync("192.0.2.123", 22, "fixture", [4, 5, 6], accept, default); }, "changed key accepted"); Check(before.SequenceEqual(File.ReadAllBytes(file)), "trust overwritten by changed host key");
    }
}
