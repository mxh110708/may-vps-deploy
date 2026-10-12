using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private static JsonObject ReleaseCandidate(string component, string version) => new()
    {
        ["SchemaVersion"] = 1, ["Component"] = component, ["Repository"] = ComponentUpdates.Repository(component), ["Architecture"] = "amd64",
        ["Version"] = version, ["Tag"] = "v" + version, ["AssetName"] = ComponentUpdates.AssetName(component, version),
        ["Url"] = "https://github.com/" + ComponentUpdates.Repository(component) + "/releases/download/v" + version + "/" + ComponentUpdates.AssetName(component, version),
        ["Sha256"] = new string('a', 64), ["Bytes"] = 1024, ["ReleaseId"] = 123, ["AssetId"] = 456,
        ["DigestSource"] = "GitHubAssetDigest", ["FetchedAt"] = DateTimeOffset.UtcNow.ToString("O")
    };
    private async Task ComponentUpdateExperience(Fixture f)
    {
        var progress = new InlineProgress<TaskProgress>(_ => { });
        foreach (var component in ComponentUpdates.Components)
        {
            var plan = f.Plan("VersionQuery-" + component); f.SaveInstance(plan); var relative = f.Relative(plan);
            var candidate = ReleaseCandidate(component, "9.8.7"); ComponentUpdates.ValidateCandidate(candidate, component);
            var remote = new FakeRemote { ComponentRelease = candidate };
            Check(await f.Engine(remote).ExecuteAsync(new(OperationKind.CheckComponentUpdate, relative, new() { ["Component"] = component }), Guid.NewGuid().ToString("N"), progress, default) == TaskOutcome.Completed, "official candidate query failed");
            Check(remote.Mutations == 0 && !remote.Commands.Any(x => x.Contains("install") || x.Contains("rollback")), "release query mutated services");
            Check(ComponentUpdates.Candidate(f.Paths, relative, component).Text("Sha256") == candidate.Text("Sha256"), "candidate digest not archived");
            foreach (var (field, value) in new[] { ("Url", "https://example.com/program"), ("Tag", "v9.8.7-beta"), ("Architecture", "arm64"), ("Repository", "another/repository"), ("AssetName", "other"), ("DigestSource", "unverified"), ("Sha256", "bad"), ("Version", "9.8.7-beta"), ("FetchedAt", DateTimeOffset.UtcNow.AddDays(-2).ToString("O")) })
            {
                var bad = candidate.DeepClone().AsObject(); bad[field] = value; Refuses(() => ComponentUpdates.ValidateCandidate(bad, component), "untrusted candidate accepted: " + field);
            }
            var oversized = candidate.DeepClone().AsObject(); oversized["Bytes"] = 536870913L; Refuses(() => ComponentUpdates.ValidateCandidate(oversized, component), "unbounded release accepted");
        }
        Refuses(() => ComponentUpdates.ValidateQuery(new() { ["Component"] = "xray", ["Scope"] = "Tunnel" }), "query mixed component and target");
        Check(ComponentUpdates.IsOlder("1.14.2", "1.14.3") && !ComponentUpdates.IsOlder("1.14.3", "1.14.2"), "component version ordering failed");
        var upgradePlan = f.Plan("LatestCoreUpgrade"); f.SaveInstance(upgradePlan); var upgradeRelative = f.Relative(upgradePlan);
        var release = ReleaseCandidate("xray", "99.1.0"); var releaseFile = ComponentUpdates.CandidateFile(f.Paths, upgradeRelative, "xray"); ArchiveStore.WriteJson(releaseFile, release);
        var request = new OperationRequest(OperationKind.Upgrade, upgradeRelative, new() { ["Scope"] = "Protocol", ["Protocol"] = "RealityEntry", ["Source"] = "Latest", ["TargetVersion"] = "99.1.0", ["ReleaseSha256"] = ClientSchemes.SourceFingerprint(releaseFile) });
        var calls = 0; var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => { calls++; return Task.FromResult(TaskOutcome.Completed); }));
        var reviewed = coordinator.Review(request); release["Sha256"] = new string('b', 64); ArchiveStore.WriteJson(releaseFile, release);
        await RefusesAsync(() => coordinator.ExecuteAsync(reviewed, request, progress, default), "release changed after review was installed"); Check(calls == 0, "changed release reached workflow");
        Refuses(() => ComponentUpdates.Versions(f.Paths, upgradeRelative, request, f.Versions), "changed candidate fingerprint accepted");
        request.Options["ReleaseSha256"] = ClientSchemes.SourceFingerprint(releaseFile);
        var resolved = ComponentUpdates.Versions(f.Paths, upgradeRelative, request, f.Versions);
        Check(resolved.Text("xray.version") == "99.1.0" && resolved.Text("sing_box.version") == f.Versions.Text("sing_box.version"), "latest target altered another component");
        var coreRemote = new FakeRemote(); coreRemote.SeedProtocols(upgradePlan);
        Check(await f.Engine(coreRemote).ExecuteAsync(request, Guid.NewGuid().ToString("N"), progress, default) == TaskOutcome.Completed, "latest protocol workflow failed");
        var upgraded = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(upgradeRelative), "deployment-state.json"));
        Check(upgraded.Text("ComponentUpgrades.RealityEntry.Version") == "99.1.0" && upgraded.Text("ComponentUpgrades.RealityEntry.Sha256") == new string('b', 64), "completed version identity not archived");
        Check(coreRemote.Commands.Contains("proxy-core-upgrade.sh") && !coreRemote.Commands.Contains("xray-install.sh") && !coreRemote.Commands.Contains("xray-apply-config.sh"), "program upgrade rewrote configuration");
        Check(coreRemote.ArmedComponents == "Protocols", "program upgrade backup escaped protocol scope");
        await RefusesAsync(() => f.Engine(coreRemote).ExecuteAsync(request, Guid.NewGuid().ToString("N"), progress, default), "same latest version reinstalled");

        foreach (var fail in new[] { false, true })
        {
            var plan = f.Plan(fail ? "TunnelUpgradeRollback" : "TunnelUpgradeSuccess"); f.SaveInstance(plan); var relative = f.Relative(plan); var directory = f.Paths.Instance(relative);
            var stateFile = SafePath.Resolve(directory, "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile); state["Cloudflared"] = FakeRemote.HealthService(true, false, false); state.Put("Cloudflared.Version", JsonValue.Create("2025.1.0")); ArchiveStore.WriteJson(stateFile, state);
            var secretFile = SafePath.Resolve(directory, "secrets.dotnet.private.json"); var secrets = f.Store.ReadSecret(secretFile); secrets["Cloudflared"] = new JsonObject { ["Token"] = "synthetic-preserved-token" }; f.Store.WriteSecret(secretFile, secrets); var secretHash = ClientSchemes.SourceFingerprint(secretFile);
            var id = Guid.NewGuid().ToString("N"); var remote = new FakeRemote { StatusTaskId = id, StatusPhase = "Armed", FailAsset = fail ? "maintenance-transaction-commit.sh" : "" }; remote.SeedProtocols(plan);
            var task = new OperationRequest(OperationKind.Komari, relative, new() { ["Scope"] = "Tunnel", ["Action"] = "Upgrade", ["Source"] = "Fixed", ["TargetVersion"] = f.Versions.Text("cloudflared.version") });
            if (fail) await RefusesAsync(() => f.Engine(remote).ExecuteAsync(task, id, progress, default), "failed Tunnel upgrade commit accepted");
            else Check(await f.Engine(remote).ExecuteAsync(task, id, progress, default) == TaskOutcome.Completed, "Tunnel program upgrade failed");
            var after = ArchiveStore.ReadJson(stateFile);
            Check(remote.ArmedComponents == "Cloudflared" && after.Text("Cloudflared.Version") == (fail ? "2025.1.0" : f.Versions.Text("cloudflared.version")), "Tunnel upgrade or rollback scope wrong");
            Check(!after.Flag("Cloudflared.Active") && !after.Flag("Cloudflared.Enabled") && ClientSchemes.SourceFingerprint(secretFile) == secretHash, "program upgrade changed token or activation");
            Check(!remote.Commands.Contains("protocol-lifecycle-apply-state.sh") && (!fail || after.At("ComponentUpgrades.Tunnel") == null), "Tunnel upgrade changed protocols or retained rolled-back upgrade identity");
        }
    }
}
