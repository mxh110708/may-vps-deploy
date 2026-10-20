using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task ReviewRepairExperience()
    {
        using var f = new Fixture(repository);
        var progress = new InlineProgress<TaskProgress>(_ => { });
        (JsonObject Plan, string Relative, string Directory) Managed(string name)
        {
            var plan = f.Plan(name); f.SaveInstance(plan); var relative = f.Relative(plan); var directory = f.Paths.Instance(relative);
            var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); state.Put("DeploymentTransaction.Status", JsonValue.Create("Committed")); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state);
            return (plan, relative, directory);
        }
        var random = new RandomTestProtector(); var encryptedStore = new ArchiveStore(f.Paths, random);
        var source = Managed("Stable-node-origin"); var secretFile = SafePath.Resolve(source.Directory, "secrets.dotnet.private.json"); File.Delete(secretFile);
        var credentials = Fixture.RealitySecrets(); encryptedStore.WriteSecret(secretFile, credentials); var encryptedHash = ClientSchemes.SourceFingerprint(secretFile);
        encryptedStore.WriteSecret(secretFile, credentials.DeepClone().AsObject());
        Check(random.ProtectCalls == 1 && encryptedHash == ClientSchemes.SourceFingerprint(secretFile), "unchanged secret was randomly encrypted again");
        var node = ClientProfiles.Nodes(source.Plan, credentials).First(); var origin = ManagedNodeSources.Origin(source.Relative, node);
        var remote = new FakeRemote(); remote.SeedProtocols(source.Plan); var engine = new WorkflowEngine(encryptedStore, remote, new FakeKeys(), new FakeUser(), new FakeValidation());
        Check(await engine.ExecuteAsync(new(OperationKind.HealthAudit, source.Relative, new()), Guid.NewGuid().ToString("N"), progress, default) == TaskOutcome.Completed, "read-only health failed");
        Check(encryptedHash == ClientSchemes.SourceFingerprint(secretFile) && remote.Mutations == 0, "health changed identical private credentials");
        ManagedNodeSources.Verify(encryptedStore, new JsonArray(origin.DeepClone()));
        var changedPlan = ArchiveStore.ReadJson(SafePath.Resolve(source.Directory, "deployment-plan.json"));
        changedPlan["Roles"] = new JsonArray("RealityEntry", "AnyTlsEntry"); changedPlan.Put("ProtocolInventory.AnyTlsEntry.Installed", JsonValue.Create(true)); ArchiveStore.WriteJson(SafePath.Resolve(source.Directory, "deployment-plan.json"), changedPlan);
        ManagedNodeSources.Verify(encryptedStore, new JsonArray(origin.DeepClone()));
        Check(ManagedNodeSources.Fingerprint(node) == ManagedNodeSources.Fingerprint(ClientProfiles.Nodes(changedPlan, credentials).First(n => n.Role == "RealityEntry")), "adding another protocol invalidated an unchanged connection by display name");
        var legacy = ClientSchemes.New(f.Paths);
        legacy["Sources"] = new JsonObject { [SafePath.Resolve(source.Directory, "deployment-plan.json")] = new string('a', 64), [secretFile] = encryptedHash };
        legacy["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = node.Name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["clash"] = node.Clash.DeepClone(), ["sing_box"] = node.SingBox.DeepClone() });
        var source2 = Managed("Second-legacy-source"); var secret2 = SafePath.Resolve(source2.Directory, "secrets.dotnet.private.json"); File.Delete(secret2); var credentials2 = Fixture.RealitySecrets(); encryptedStore.WriteSecret(secret2, credentials2);
        legacy["Sources"]![SafePath.Resolve(source2.Directory, "deployment-plan.json")] = new string('c', 64); legacy["Sources"]![secret2] = ClientSchemes.SourceFingerprint(secret2);
        var node2 = ClientProfiles.Nodes(source2.Plan, credentials2).First(); legacy["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = node2.Name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["clash"] = node2.Clash.DeepClone(), ["sing_box"] = node2.SingBox.DeepClone() });
        var legacyWorkbench = new ClientWorkbench(encryptedStore, new FakeTools(), new FakeAssets(), "synthetic-python");
        await RefusesAsync(() => legacyWorkbench.BuildAsync(legacy, default), "synthetic builder unexpectedly ran");
        Check(legacy["Nodes"]!.AsArray().All(n => n!["ManagedOrigin"] != null) && legacy["Sources"]!.AsObject().Count == 0, "multi-instance legacy sources did not migrate renamed connections in one pass");
        var unresolved = legacy.DeepClone().AsObject(); unresolved["Nodes"]!.AsArray()[0]!.AsObject().Remove("ManagedOrigin"); unresolved["Nodes"]!.AsArray()[0]!["clash"]!["uuid"] = "different-credential"; unresolved["Nodes"]!.AsArray()[0]!["sing_box"]!["uuid"] = "different-credential";
        unresolved["Sources"] = new JsonObject { [SafePath.Resolve(source.Directory, "deployment-plan.json")] = new string('a', 64), [secretFile] = encryptedHash };
        await RefusesAsync(() => legacyWorkbench.BuildAsync(unresolved, default), "unresolved changed source was discarded");
        Check(unresolved["Sources"]!.AsObject().Count == 2 && unresolved["Nodes"]!.AsArray()[0]!["ManagedOrigin"] == null, "ambiguous old source silently became unmanaged");
        File.Delete(secret2); f.Store.WriteSecret(secret2, credentials2);
        changedPlan.Put("Reality.XrayVersion", JsonValue.Create("99.0.0")); ArchiveStore.WriteJson(SafePath.Resolve(source.Directory, "deployment-plan.json"), changedPlan);
        ManagedNodeSources.Verify(encryptedStore, new JsonArray(origin.DeepClone()));
        credentials.Put("Xray.Uuid", JsonValue.Create(Guid.NewGuid().ToString())); encryptedStore.WriteSecret(secretFile, credentials);
        Refuses(() => ManagedNodeSources.Verify(encryptedStore, new JsonArray(origin.DeepClone())), "rotated credential kept stale managed node accepted");
        // Remaining tests use the fixture's independent deterministic protector.
        File.Delete(secretFile); f.Store.WriteSecret(secretFile, credentials);

        var c = f.Paths.Resolve("authority-a.yaml"); var s = f.Paths.Resolve("authority-b.json"); var cc = f.Paths.Resolve("private/candidate-a.yaml"); var ss = f.Paths.Resolve("private/candidate-b.json");
        File.WriteAllText(c, "old-a"); File.WriteAllText(s, "old-b"); File.WriteAllText(cc, "new-a"); File.WriteAllText(ss, "new-b");
        var candidate = new JsonObject { ["ValidationStatus"] = "Passed", ["Clash"] = cc, ["SingBox"] = ss, ["ClashHash"] = ClientSchemes.SourceFingerprint(cc), ["SingBoxHash"] = ClientSchemes.SourceFingerprint(ss), ["Sources"] = new JsonObject(), ["Targets"] = new JsonObject { [c] = ClientSchemes.SourceFingerprint(c), [s] = ClientSchemes.SourceFingerprint(s) } };
        Refuses(() => new CandidatePublisher(f.Paths, (path, bytes) => { ArchiveStore.AtomicWrite(path, bytes); if (path == c) File.WriteAllText(s, "midpoint-external-edit"); }).Publish(candidate, c, s), "second-file external edit overwritten");
        Check(File.ReadAllText(c) == "old-a" && File.ReadAllText(s) == "midpoint-external-edit", "publication did not preserve external edit or roll back first target");

        var scheme = ClientSchemes.New(f.Paths); scheme["AuthorityNodes"] = new JsonArray("A", "B");
        scheme["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = "B", ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["clash"] = new JsonObject { ["name"] = "B" }, ["sing_box"] = new JsonObject { ["tag"] = "B" } });
        Check(ClientSchemes.Specification(scheme).Strings("remove_nodes").SequenceEqual(new[] { "A" }), "editor deletion did not reach builder specification");
        var renamed = scheme["Nodes"]!.AsArray()[0]!; renamed["AuthorityName"] = "B"; renamed["name"] = "C"; renamed["clash"]!["name"] = "C"; renamed["sing_box"]!["tag"] = "C";
        var specification = ClientSchemes.Specification(scheme); Check(specification.Text("rename_nodes.B") == "C" && specification.Strings("remove_nodes").Contains("B"), "rename kept source name in export");

        var landing = Managed("Trusted-landing"); landing.Plan["Role"] = "ShadowsocksLanding"; landing.Plan["Roles"] = new JsonArray("ShadowsocksLanding"); landing.Plan.Put("Shadowsocks.TrustedEntryIPv4s", new JsonArray("192.0.2.30"));
        var entry = Managed("Trusted-entry"); entry.Plan.Put("Server.IPv4", JsonValue.Create("192.0.2.30")); ArchiveStore.WriteJson(SafePath.Resolve(entry.Directory, "deployment-plan.json"), entry.Plan);
        var validator = new ProtocolValidation(new FakeAssets(), new FakeTools(), f.Store); var transit = validator.FindTrustedEntry(landing.Plan, Fixture.RealitySecrets(), "IPv4"); Check(transit?.Role == "RealityEntry", "trusted managed entry not resolved");
        var landingSecrets = new JsonObject { ["Shadowsocks"] = new JsonObject { ["ServerKey"] = "fixture", ["PrimaryUserKey"] = "fixture" } }; var exitNode = ClientProfiles.Nodes(landing.Plan, landingSecrets, true).First();
        var chained = ClientProfiles.SingProbe(exitNode, 23000, transit); var chainedClash = ClientProfiles.ClashProbe(exitNode, 23000, transit);
        Check(chained["outbounds"]!.AsArray().Count == 2 && chained["outbounds"]!.AsArray()[0]!.Text("detour") == "mxh-probe-entry" && chainedClash["proxies"]!.AsArray()[0]!.Text("dialer-proxy") == "mxh-probe-entry", "landing probes bypass trusted entry");
        landing.Plan.Put("Shadowsocks.TrustedEntryIPv4s", new JsonArray("192.0.2.99"));
        var missing = await validator.ValidateAsync(landing.Plan, landingSecrets, SafePath.Resolve(landing.Directory, "validation"), new FakeUser(), new InlineProgress<string>(_ => { }), default);
        Check(missing.Text("Status") == "Incomplete" && missing["Items"]!.AsArray().All(i => i!.Text("FailedStage") == "TrustedEntryMissing"), "missing entry was probed directly or marked passed");

        var multi = f.Plan("Validate-standby"); multi["Roles"] = new JsonArray("RealityEntry", "AnyTlsEntry"); multi.Put("AnyTls.ServerName", JsonValue.Create("entry.example.com")); multi.Put("AnyTls.EchPublicName", JsonValue.Create("ech.example.com"));
        var token = f.Paths.Resolve("private/test-dns-token"); File.WriteAllText(token, "synthetic-token"); multi.Put("TrustedTls.Enabled", JsonValue.Create(true)); multi.Put("TrustedTls.ZoneName", JsonValue.Create("example.com")); multi.Put("TrustedTls.CertbotEmail", JsonValue.Create("ops@example.com")); multi.Put("TrustedTls.CloudflareTokenFile", JsonValue.Create(token));
        var validation = new RecordingValidation("AnyTlsEntry"); var initialRemote = new FakeRemote(); var initialEngine = new WorkflowEngine(f.Store, initialRemote, new FakeKeys(), new FakeUser(), validation);
        Check(await initialEngine.ExecuteAsync(new(OperationKind.Deploy, f.Relative(multi), new JsonObject { ["Plan"] = multi }), Guid.NewGuid().ToString("N"), progress, default) == TaskOutcome.CompletedWithWarnings, "unverified standby disappeared behind global Passed");
        var multiPlan = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(multi)), "deployment-plan.json")); var multiState = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(multi)), "deployment-state.json"));
        Check(validation.Roles.Contains("AnyTlsEntry") && validation.Roles.Contains("RealityEntry") && multiPlan.Flag("ProtocolInventory.RealityEntry.Enabled") && !multiPlan.Flag("ProtocolInventory.AnyTlsEntry.Enabled") && multiState.Text("ProtocolValidation.Status") == "Incomplete", "standby not tested independently or chosen state not restored");

        var bad = Managed("Unhealthy-read"); var healthRemote = new FakeRemote(); healthRemote.HealthAudit["Ssh"] = new JsonObject { ["Valid"] = false, ["PubkeyAuthentication"] = "no", ["Ports"] = new JsonArray(22) }; healthRemote.HealthAudit.Put("Services.RealityEntry", FakeRemote.HealthService(true, true, false));
        Check(await f.Engine(healthRemote).ExecuteAsync(new(OperationKind.HealthAudit, bad.Relative, new()), Guid.NewGuid().ToString("N"), progress, default) == TaskOutcome.CompletedWithWarnings, "unhealthy SSH and protocol silently completed");
        var report = ArchiveStore.ReadJson(SafePath.Resolve(bad.Directory, "deployment-state.json")); Check(report.Text("HealthReport.Status") == "Warnings" && report["HealthReport"]!["Checks"]!.AsArray().Count >= 4 && healthRemote.Mutations == 0, "health diagnostics hidden or mutated remote");
        var incomplete = HealthReports.Build(bad.Plan, new(), new JsonObject { ["SchemaVersion"] = 2, ["CollectedAt"] = DateTimeOffset.UtcNow, ["ChecksIncomplete"] = new JsonArray() });
        Check(incomplete.Text("Status") == "Warnings" && incomplete["Checks"]!.AsArray().Any(c => c!.Text("Message").Contains("证据")), "partial health audit silently marked healthy");

        var disabled = Managed("No-agent-decommission"); var disableRemote = new FakeRemote(); disableRemote.SeedProtocols(disabled.Plan);
        Check(await f.Engine(disableRemote).ExecuteAsync(new(OperationKind.Decommission, disabled.Relative, new() { ["Scope"] = "ManagedInstance", ["Action"] = "Disable" }), Guid.NewGuid().ToString("N"), progress, default) == TaskOutcome.Completed, "disable failed");
        Check(!ArchiveStore.ReadJson(SafePath.Resolve(disabled.Directory, "deployment-state.json")).Flag("KomariInstalled"), "decommission fabricated Agent installation");

        var restore = Managed("Reject-other-snapshot"); var restoreRoot = SafePath.Resolve(restore.Directory, "maintenance-backups/" + new string('a', 32)); Directory.CreateDirectory(restoreRoot);
        var record = new JsonObject { ["RemoteBackup"] = FakeRemote.Backup, ["Components"] = new JsonArray("Network"), ["SshPorts"] = restore.Plan.Text("Ports.SshPrimary") + "," + restore.Plan.Text("Ports.SshRescue"), ["OldPlan"] = restore.Plan.DeepClone(), ["OldState"] = new JsonObject(), ["SecretsRelativePath"] = "maintenance-backups/" + new string('a', 32) + "/secrets.dotnet.private.json", ["BackupSha256"] = new string('a', 64) }; ArchiveStore.WriteJson(SafePath.Resolve(restoreRoot, "restore-metadata.json"), record);
        Check(!ProtocolRestores.Compatible(record, restore.Plan), "network snapshot offered as protocol restore"); var restoreRemote = new FakeRemote();
        await RefusesAsync(() => f.Engine(restoreRemote).ExecuteAsync(new(OperationKind.Restore, restore.Relative, new() { ["Scope"] = "Protocol", ["RestoreMode"] = "Full", ["Backup"] = FakeRemote.Backup }), Guid.NewGuid().ToString("N"), progress, default), "incompatible restore reached mutation");
        Check(restoreRemote.Mutations == 0 && !restoreRemote.Commands.Contains("protocol-migration-arm-rollback.sh"), "restore checked scope only after arming remote");
        foreach (var port in new[] { 25774, 20241 })
        {
            var compatible = Managed("Restore-without-monitor-" + port); compatible.Plan.Put("Ports.XrayPrimary", JsonValue.Create(port)); ArchiveStore.WriteJson(SafePath.Resolve(compatible.Directory, "deployment-plan.json"), compatible.Plan);
            var backupRelative = "maintenance-backups/" + new string('b', 32); var localBackup = SafePath.Resolve(compatible.Directory, backupRelative);
            f.Store.WriteSecret(SafePath.Resolve(localBackup, "secrets.dotnet.private.json"), f.Store.ReadSecret(SafePath.Resolve(compatible.Directory, "secrets.dotnet.private.json")));
            File.WriteAllText(SafePath.Resolve(localBackup, "remote-files.tar.gz"), "fixture-archive");
            ArchiveStore.WriteJson(SafePath.Resolve(localBackup, "restore-metadata.json"), new JsonObject { ["RemoteBackup"] = FakeRemote.Backup, ["Components"] = new JsonArray("Protocols"), ["SshPorts"] = compatible.Plan.Text("Ports.SshPrimary") + "," + compatible.Plan.Text("Ports.SshRescue"), ["OldPlan"] = compatible.Plan.DeepClone(), ["OldState"] = new JsonObject(), ["SecretsRelativePath"] = backupRelative + "/secrets.dotnet.private.json", ["BackupSha256"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes("fixture-archive")) });
            var compatibleRemote = new FakeRemote(); compatibleRemote.SeedProtocols(compatible.Plan);
            Check(await f.Engine(compatibleRemote).ExecuteAsync(new(OperationKind.Restore, compatible.Relative, new() { ["Scope"] = "Protocol", ["RestoreMode"] = "Full", ["Backup"] = FakeRemote.Backup }), Guid.NewGuid().ToString("N"), progress, default) == TaskOutcome.Completed, "uninstalled monitoring default reserved a legitimate protocol port");
        }

        var controller = Managed("Controller-restored-version"); var controllerStateFile = SafePath.Resolve(controller.Directory, "deployment-state.json"); var controllerState = ArchiveStore.ReadJson(controllerStateFile);
        controllerState["KomariController"] = new JsonObject { ["Installed"] = true, ["Enabled"] = true, ["Active"] = false, ["Version"] = "1.5.1" }; controllerState.Put("MonitoringInventory.KomariController", controllerState["KomariController"]!.DeepClone()); ArchiveStore.WriteJson(controllerStateFile, controllerState);
        var oldBackup = "/root/komari-controller-19990101-000000.tar.gz";
        ArchiveStore.WriteJson(SafePath.Resolve(controller.Directory, "komari-backups/older.json"), new JsonObject { ["RemoteBackup"] = oldBackup, ["Sha256"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes("fixture-archive")), ["IncludeTunnel"] = false, ["ControllerPort"] = 25774 });
        var controllerRemote = new FakeRemote { RestoredControllerVersion = "1.0.0" };
        Check(await f.Engine(controllerRemote).ExecuteAsync(new(OperationKind.Komari, controller.Relative, new() { ["Scope"] = "KomariController", ["Action"] = "Restore", ["Backup"] = oldBackup }), Guid.NewGuid().ToString("N"), progress, default) == TaskOutcome.Completed, "controller restore failed");
        var restoredState = ArchiveStore.ReadJson(controllerStateFile); var restoredPlan = ArchiveStore.ReadJson(SafePath.Resolve(controller.Directory, "deployment-plan.json"));
        Check(ComponentUpdates.MonitoringVersion(restoredPlan, restoredState, "KomariController") == "1.0.0" && restoredState.Text("InstalledProgramVersions.komari_controller.Version") == "1.0.0" && restoredState.Text("ComponentUpgrades.KomariController.Sha256") == new string('b', 64), "restore left newer program or inventory version");

        foreach (var fail in new[] { false, true })
        {
            var removal = Managed("Uninstall-artifacts-" + fail); removal.Plan.Put("ProtocolInventory.RealityEntry", new JsonObject { ["Installed"] = true, ["Enabled"] = false, ["Active"] = false }); ArchiveStore.WriteJson(SafePath.Resolve(removal.Directory, "deployment-plan.json"), removal.Plan);
            var secrets = f.Store.ReadSecret(SafePath.Resolve(removal.Directory, "secrets.dotnet.private.json")); ClientProfiles.Export(removal.Plan, secrets, SafePath.Resolve(removal.Directory, "client-exports"));
            var configPath = SafePath.Resolve(removal.Directory, "server-configs/xray-config.private.json"); ArchiveStore.WriteJson(configPath, ServerConfigurations.Xray(removal.Plan, secrets)); var originalConfig = File.ReadAllBytes(configPath);
            var taskId = Guid.NewGuid().ToString("N"); var removeRemote = new FakeRemote { FailAsset = fail ? "maintenance-transaction-commit.sh" : "", StatusTaskId = taskId, StatusPhase = "Armed" }; removeRemote.SeedProtocols(removal.Plan);
            var removeEngine = new WorkflowEngine(f.Store, removeRemote, new FakeKeys(), new FakeUser(), new RecordingValidation()); var request = new OperationRequest(OperationKind.ProtocolState, removal.Relative, new() { ["Scope"] = "Protocol", ["Protocol"] = "RealityEntry", ["Action"] = "Uninstall" });
            if (fail) await RefusesAsync(() => removeEngine.ExecuteAsync(request, taskId, progress, default), "failed uninstall commit accepted"); else Check(await removeEngine.ExecuteAsync(request, taskId, progress, default) == TaskOutcome.Completed, "uninstall failed");
            var afterSecrets = f.Store.ReadSecret(SafePath.Resolve(removal.Directory, "secrets.dotnet.private.json")); var exported = SafePath.Resolve(removal.Directory, "client-exports/mihomo-test-primary.yaml");
            Check((afterSecrets["Xray"] != null) == fail && File.Exists(configPath) == fail && File.Exists(exported) == fail, "current credentials/config/exports inconsistent with uninstall or rollback");
            if (fail) Check(File.ReadAllBytes(configPath).SequenceEqual(originalConfig), "uninstall rollback lost original config bytes");
            Check(Directory.EnumerateFiles(SafePath.Resolve(removal.Directory, "maintenance-backups"), "secrets.dotnet.private.json", SearchOption.AllDirectories).Any(), "historical encrypted recovery secrets deleted");
        }
        var edited = Managed("Uninstall-preserve-external-artifact"); var editedConfig = SafePath.Resolve(edited.Directory, "server-configs/xray-config.private.json"); ArchiveStore.AtomicWrite(editedConfig, Encoding.UTF8.GetBytes("original-private-artifact"));
        var editedId = Guid.NewGuid().ToString("N"); var editedRemote = new FakeRemote { StatusTaskId = editedId, StatusPhase = "Armed" }; editedRemote.SeedProtocols(edited.Plan);
        editedRemote.ObserveAsset = asset => { if (asset == "protocol-lifecycle-uninstall.sh") File.WriteAllText(editedConfig, "external-private-artifact"); };
        await RefusesAsync(() => f.Engine(editedRemote).ExecuteAsync(new(OperationKind.ProtocolState, edited.Relative, new() { ["Scope"] = "Protocol", ["Protocol"] = "RealityEntry", ["Action"] = "Uninstall" }), editedId, progress, default), "uninstall overwrote a midpoint local edit");
        Check(File.ReadAllText(editedConfig) == "external-private-artifact" && ArchiveStore.ReadJson(SafePath.Resolve(edited.Directory, "deployment-state.json")).Text("LastTask.Outcome") == "NeedsRecovery", "external artifact edit not preserved for explicit recovery");
    }
}

internal sealed class RandomTestProtector : ISecretProtector
{
    public string Format => "TEST-RANDOM";
    public int ProtectCalls { get; private set; }
    public byte[] Protect(ReadOnlySpan<byte> data) { ProtectCalls++; return [.. RandomNumberGenerator.GetBytes(16), .. data.ToArray().Select(b => (byte)(b ^ 0x73))]; }
    public byte[] Unprotect(ReadOnlySpan<byte> data) => data[16..].ToArray().Select(b => (byte)(b ^ 0x73)).ToArray();
}
internal sealed class RecordingValidation(string incomplete = "") : IProtocolValidation
{
    public HashSet<string> Roles { get; } = new();
    public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject secrets, string directory, IUserInteraction user, IProgress<string> progress, CancellationToken token)
    {
        var roles = ClientProfiles.Nodes(plan, secrets, true).Select(n => n.Role).Distinct().ToArray(); foreach (var role in roles) Roles.Add(role);
        return Task.FromResult(new JsonObject { ["Status"] = roles.Contains(incomplete) ? "Incomplete" : "Passed" });
    }
    public void Export(JsonObject plan, JsonObject secrets, string directory) => ClientProfiles.Export(plan, secrets, directory);
}
