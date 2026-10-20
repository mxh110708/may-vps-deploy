using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task PrivateDirectoryExperience()
    {
        using var f = new Fixture(repository); var source = f.Paths.Private;
        var plan = f.Plan("Relocated"); f.SaveInstance(plan); var relative = f.Relative(plan);
        var directory = f.Paths.Instance(relative);
        var key = SafePath.Resolve(directory, "ssh/id_vps_management"); ArchiveStore.AtomicWrite(key, Encoding.UTF8.GetBytes("synthetic-management-key"));
        plan.Put("Server.BootstrapKeyPath", JsonValue.Create(key)); plan.Put("SshKey.SourcePrivateKeyPath", JsonValue.Create(key));
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
        var secret = SafePath.Resolve(directory, "secrets.dotnet.private.json"); var secretBefore = File.ReadAllBytes(secret);
        var sums = SafePath.Resolve(directory, "SHA256SUMS.txt");
        File.WriteAllText(sums, ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "deployment-plan.json")) + "  deployment-plan.json\n" + ArchiveStore.Digest(secretBefore) + "  secrets.dotnet.private.json\n");
        var originalJson = "[1,2,3]"; File.WriteAllText(f.Paths.Resolve("private/user-array.json"), originalJson);
        var font = new LocalFonts(f.Paths).Import(Path.Combine(repository, "assets/gui/fonts/LXGWWenKai-Regular.ttf"));
        var workbench = new ClientWorkbench(f.Store, new FakeTools(), new FakeAssets(), "unused");
        var scheme = ClientSchemes.New(f.Paths); var planFile = SafePath.Resolve(directory, "deployment-plan.json");
        var vault = f.Paths.Resolve("private/vault.dotnet.private.json"); f.Store.WriteSecret(vault, new JsonObject { ["ManagedKeyPath"] = key, ["Password"] = "synthetic-vault-credential" });
        scheme["Sources"] = new JsonObject { [planFile] = ClientSchemes.SourceFingerprint(planFile), [vault] = ClientSchemes.SourceFingerprint(vault) };
        scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" }; workbench.Save(scheme);
        var mover = new PrivateDirectory(f.Store); var destination = f.Root + "-external-archive";
        var review = mover.Review(destination);
        Refuses(() => mover.Review(f.Root), "installation root accepted as private data");
        Refuses(() => mover.Review(Path.GetPathRoot(f.Root)!), "drive root accepted as private data");
        Refuses(() => mover.Review(Path.Combine(source, "nested")), "nested migration accepted");
        Refuses(() => mover.Review(Path.Combine(f.Root, "config")), "managed app assets accepted as private data");
        var occupied = Path.Combine(f.Root, "occupied"); Directory.CreateDirectory(occupied); File.WriteAllText(Path.Combine(occupied, "unrelated.txt"), "keep");
        Refuses(() => mover.Review(occupied), "nonempty destination merged");
        var stateFile = SafePath.Resolve(directory, "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile);
        state.Put("DeploymentTransaction.Status", JsonValue.Create("Armed")); ArchiveStore.WriteJson(stateFile, state);
        Refuses(() => mover.Review(destination), "pending recovery allowed to relocate");
        state.Remove("DeploymentTransaction"); ArchiveStore.WriteJson(stateFile, state);
        review = mover.Review(destination); File.WriteAllText(f.Paths.Resolve("private/new-file.txt"), "late");
        Refuses(() => mover.Move(review), "stale migration fingerprint accepted");
        Check(!Directory.Exists(destination) && File.ReadAllBytes(secret).SequenceEqual(secretBefore), "stale move touched credentials");
        review = mover.Review(destination);
        try { mover.Move(review, new CancellationToken(true)); throw new Exception("cancelled migration ran"); }
        catch (OperationCanceledException) { Check(f.Paths.Private == source && Directory.Exists(source) && !Directory.Exists(destination), "cancellation switched archive root"); }
        await RefusesAsync(async () => { using var held = new FileStream(key, FileMode.Open, FileAccess.ReadWrite, FileShare.None); try { await Task.Run(() => mover.Move(review)); } catch (IOException) { throw new OperationException("expected locked source"); } }, "locked source moved");
        Check(f.Paths.Private == source && !Directory.Exists(destination), "locked source produced duplicate copy");
        var foreign = Path.Combine(destination, "foreign.txt");
        Refuses(() => mover.Move(review, prepareDestination: folder => { File.WriteAllText(foreign, "keep user content"); throw new OperationException("synthetic destination failure"); }), "destination preparation failure ignored");
        Check(f.Paths.Private == source && File.ReadAllText(foreign) == "keep user content", "rollback removed unrelated destination content");
        File.Delete(foreign); Directory.Delete(destination);
        var result = mover.Move(review);
        Check(result.SourceRemoved && !Directory.Exists(source) && f.Paths.Private == destination, "old private copy left behind");
        Check(new AppPaths(f.Root).Private == destination && f.Paths.Resolve("private/instances") == Path.Combine(destination, "instances"), "custom directory not loaded on startup");
        Check(f.Paths.Resolve("config/versions.json") == Path.Combine(f.Root, "config", "versions.json"), "relocation moved application assets");
        var movedPlanFile = SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json"); var movedPlan = ArchiveStore.ReadJson(movedPlanFile);
        Check(movedPlan.Text("Paths.Archive") == f.Paths.Instance(relative) && movedPlan.Text("Server.BootstrapKeyPath") == SafePath.Resolve(f.Paths.Instance(relative), "ssh/id_vps_management"), "instance or key paths remained stale");
        var movedScheme = workbench.List().Single();
        Check(movedScheme["Candidate"] == null && movedScheme["Sources"]!.AsObject().All(p => !p.Key.StartsWith(source + Path.DirectorySeparatorChar)), "old candidate or source reference survived migration");
        Check(movedScheme["Sources"]!.AsObject()[movedPlanFile]!.ToString() == ClientSchemes.SourceFingerprint(movedPlanFile), "scheme source fingerprint not refreshed");
        var movedVault = f.Paths.Resolve("private/vault.dotnet.private.json");
        Check(movedScheme["Sources"]!.AsObject()[movedVault]!.ToString() == ClientSchemes.SourceFingerprint(movedVault) && f.Store.ReadSecret(movedVault).Text("ManagedKeyPath") == SafePath.Resolve(f.Paths.Instance(relative), "ssh/id_vps_management"), "encrypted source rebasing left a stale scheme fingerprint");
        Check(File.ReadAllBytes(SafePath.Resolve(f.Paths.Instance(relative), "secrets.dotnet.private.json")).SequenceEqual(secretBefore) && f.Store.ReadSecret(SafePath.Resolve(f.Paths.Instance(relative), "secrets.dotnet.private.json")).Text("AdminPassword") == "synthetic-password", "encrypted credentials changed or unreadable");
        Check(new LocalFonts(f.Paths).Resolve(font.Id).Family == "LXGW WenKai", "custom fonts lost on relocation");
        var checksums = File.ReadAllLines(SafePath.Resolve(f.Paths.Instance(relative), "SHA256SUMS.txt"));
        Check(checksums[0][..64] == ClientSchemes.SourceFingerprint(movedPlanFile), "private checksum manifest stale after path update");
        Check(File.ReadAllText(f.Paths.Resolve("private/user-array.json")) == originalJson && File.ReadAllText(Path.Combine(occupied, "unrelated.txt")) == "keep", "unrelated files modified");
        var locator = f.Paths.Resolve(PrivateDirectory.LocationFile);
        File.Delete(f.Paths.Resolve("private/" + PrivateDirectory.OwnershipFile));
        Refuses(() => new AppPaths(f.Root), "missing custom archive silently became empty data");
        ArchiveStore.WriteJson(f.Paths.Resolve("private/" + PrivateDirectory.OwnershipFile), new JsonObject { ["SchemaVersion"] = 1, ["AppRoot"] = f.Root, ["OwnerId"] = ArchiveStore.ReadJson(locator).Text("OwnerId") });
        result = mover.Move(mover.Review(source));
        Check(result.SourceRemoved && new AppPaths(f.Root).Private == source && !Directory.Exists(destination), "move back to default failed");
        var nodes = ClientProfiles.Nodes(plan, Fixture.RealitySecrets()).ToArray();
        Check(nodes.Length == 2 && nodes.Count(n => n.IsBackup) == 1 && nodes.Single(n => n.IsBackup).DisplayName.EndsWith("备用入口"), "fallback connection confused with archive backup");
        plan.Put("Ports.XrayBackup", JsonValue.Create(plan.Number("Ports.XrayPrimary")));
        Check(ClientProfiles.Nodes(plan, Fixture.RealitySecrets()).Count() == 1, "same fallback listener duplicated");
    }
}
