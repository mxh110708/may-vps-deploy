using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task InstallationVersionExperience(Fixture f)
    {
        var plan = f.Plan("InstallationVersionSelection"); plan["Roles"] = new JsonArray("RealityEntry", "AnyTlsEntry", "ShadowsocksLanding");
        var components = InstallationVersions.DeploymentComponents(plan);
        Check(components.Count(x => x == "sing_box") == 1 && components.Contains("xray"), "shared protocol package queried twice");
        var fixedSelection = InstallationVersions.Selection("Fixed", f.Versions);
        Check(ArchiveStore.Fingerprint(InstallationVersions.Resolve(fixedSelection, components, f.Versions)) == ArchiveStore.Fingerprint(f.Versions), "fixed installation versions changed");
        var latest = InstallationVersions.Selection("Latest", f.Versions);
        foreach (var component in components) latest["Candidates"]![component] = ReleaseCandidate(component, "99.2.3");
        var resolved = InstallationVersions.Resolve(latest, components, f.Versions);
        Check(resolved.Text("xray.version") == "99.2.3" && resolved.Text("sing_box.version") == "99.2.3" && resolved.Text("cloudflared.version") == f.Versions.Text("cloudflared.version"), "latest install changed an unselected package");
        InstallationVersions.ApplyPlan(plan, resolved, components, "Latest");
        Check(plan.Text("Reality.XrayVersionChannel") == "OfficialStable" && plan.Text("AnyTls.SingBoxVersion") == "99.2.3" && plan.Text("Shadowsocks.SingBoxVersion") == "99.2.3", "planned installed versions were not updated");
        plan["InstallationVersions"] = latest.DeepClone();
        Check(DeploymentReview.Sections(plan, OperationKind.Deploy).Any(section => section.Items.Any(item => item.Value.Contains("SHA256") && item.Value.Contains("99.2.3"))), "deployment review omitted concrete package digests");
        var missing = latest.DeepClone().AsObject(); missing["Candidates"]!.AsObject().Remove(components[0]);
        Refuses(() => InstallationVersions.Resolve(missing, components, f.Versions), "latest installation silently fell back to fixed");
        var mixed = latest.DeepClone().AsObject(); mixed["Source"] = "Fixed";
        Refuses(() => InstallationVersions.Resolve(mixed, components, f.Versions), "fixed source accepted latest candidates");
        var changed = latest.DeepClone().AsObject(); changed["FixedVersions"]!.AsObject()["unreviewed"] = true;
        Refuses(() => InstallationVersions.Resolve(changed, components, f.Versions, true), "accepted draft ignored snapshot pin");
        var catalog = f.Versions.DeepClone().AsObject(); catalog["catalog_changed"] = true;
        Refuses(() => InstallationVersions.Resolve(latest, components, catalog), "initial deployment used changed fixed catalog");
        Check(InstallationVersions.Resolve(latest, components, catalog, true).Text("xray.version") == "99.2.3", "accepted draft changed its locked versions after application update");
        var expired = latest.DeepClone().AsObject(); foreach (var item in expired["Candidates"]!.AsObject()) item.Value!["FetchedAt"] = DateTimeOffset.UtcNow.AddDays(-2).ToString("O");
        Refuses(() => InstallationVersions.Resolve(expired, components, f.Versions), "new install accepted expired query");
        Check(InstallationVersions.Resolve(expired, components, f.Versions, true).Text("xray.version") == "99.2.3", "accepted draft implicitly re-resolved latest");
        Check(InstallationVersions.Summary(expired, components).Contains("99.2.3"), "accepted draft could not be reviewed after query aged");

        var current = f.Plan("LatestAdditionalShadowsocks"); current["Import"] = new JsonObject { ["Status"] = "Completed" }; f.SaveInstance(current);
        var options = new JsonObject { ["Component"] = "ShadowsocksLanding", ["Settings"] = new JsonObject { ["LandingPort"] = 45011, ["TrustedEntries"] = "192.0.2.90", ["TransitGroup"] = "Test Entry" }, ["VersionSource"] = "Latest", ["AssetPin"] = ArchiveStore.Fingerprint(f.Versions) };
        var selection = InstallationVersions.Selection("Latest", f.Versions); selection["Candidates"]!["sing_box"] = ReleaseCandidate("sing_box", "99.3.4"); options["InstallationVersions"] = selection;
        var prepared = ComponentInstallations.Prepare(current, ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(current)), "deployment-state.json")), options, f.Versions);
        Check(prepared.Text("Shadowsocks.SingBoxVersion") == "99.3.4" && prepared.Text("Reality.XrayVersion") == current.Text("Reality.XrayVersion"), "additional latest version overwrote existing protocol");
        var task = Guid.NewGuid().ToString("N"); var remote = new FakeRemote { StatusTaskId = task, StatusPhase = "Armed" }; remote.SeedProtocols(current);
        var request = new OperationRequest(OperationKind.InstallComponent, f.Relative(current), options);
        Check(await f.Engine(remote).ExecuteAsync(request, task, new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "latest additional install workflow failed");
        var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(current)), "deployment-state.json"));
        Check(state.Text("InstalledProgramVersions.ShadowsocksLanding.Version") == "99.3.4" && state.Text("InstalledProgramVersions.ShadowsocksLanding.Source") == "Latest", "installed package identity/source not recorded");
        Check(OperationPolicy.Summary(request).Contains("99.3.4") && OperationPolicy.Summary(request).Contains("SHA256"), "additional review omitted version or checksum");

        var draft = f.Plan("LatestInitialDeployment");
        var initialComponents = InstallationVersions.DeploymentComponents(draft);
        var initialSelection = InstallationVersions.Selection("Latest", f.Versions);
        foreach (var component in initialComponents) initialSelection["Candidates"]![component] = ReleaseCandidate(component, "99.4.5");
        draft["InstallationVersions"] = initialSelection;
        InstallationVersions.ApplyPlan(draft, InstallationVersions.Resolve(initialSelection, initialComponents, f.Versions), initialComponents, "Latest");
        var initialRemote = new FakeRemote();
        var initialTask = Guid.NewGuid().ToString("N");
        Check(await f.Engine(initialRemote).ExecuteAsync(new(OperationKind.Deploy, f.Relative(draft), new JsonObject { ["Plan"] = draft }), initialTask, new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "first deployment did not consume locked latest versions");
        var initialState = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(draft)), "deployment-state.json"));
        var initialPlan = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(draft)), "deployment-plan.json"));
        Check(initialPlan.Text("Reality.XrayVersion") == "99.4.5" && initialState.Text("InstalledProgramVersions.RealityEntry.Version") == "99.4.5" && initialState.Text("InstalledProgramVersions.RealityEntry.Source") == "Latest", "first install archived the fixed version instead of queried version");
        Check(initialState.Text("InstallationVersionPin") == ArchiveStore.Fingerprint(initialSelection), "accepted first-deployment candidate was not pinned for continuation");
    }
}
