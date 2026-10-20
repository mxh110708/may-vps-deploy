using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task TunnelAccessExperience(Fixture f)
    {
        foreach (var url in new[] { "http://monitor.example.com", "https://127.0.0.1", "https://localhost", "https://user:password@monitor.example.com", "https://monitor.example.com/path", "https://monitor.example.com?token=value", "https://monitor.example.com#fragment" })
            Refuses(() => OperationPolicy.Validate(new(OperationKind.TunnelAccess, "Example/Route/May-VPS-Deploy", new() { ["PublicUrl"] = url })), "unsafe or incomplete public URL accepted");
        Refuses(() => OperationPolicy.Validate(new(OperationKind.TunnelAccess, "Example/Route/May-VPS-Deploy", new() { ["PublicUrl"] = "https://monitor.example.com", ["Token"] = "synthetic" })), "route check accepts a credential");
        Check(TunnelAccess.Failure("HttpRejected", 403).Contains("HTTP 403") && !TunnelAccess.Failure("HttpRejected", 0).Contains("HTTP 0"), "public route failure hides HTTP status or invents an invalid one");
        foreach (var failure in new[] { "", "TunnelNotConnected", "ControllerUnavailable", "DnsFailure", "HttpRejected", "WrongApplication", "VersionMismatch", "TlsFailure", "Timeout", "EvidenceIncomplete" })
        {
            var plan = f.Plan("public-route-" + (failure == "" ? "passed" : failure)); plan["Cloudflared"] = new JsonObject { ["PublicUrl"] = "https://old.example.com", ["MetricsPort"] = 20241 }; plan["KomariController"] = new JsonObject { ["Port"] = 25774 }; f.SaveInstance(plan);
            var relative = f.Relative(plan); var directory = f.Paths.Instance(relative); var stateFile = SafePath.Resolve(directory, "deployment-state.json");
            var state = ArchiveStore.ReadJson(stateFile); state["Cloudflared"] = FakeRemote.HealthService(true, true, true); state["KomariController"] = FakeRemote.HealthService(true, true, true); ArchiveStore.WriteJson(stateFile, state);
            var remote = new FakeRemote();
            if (failure != "") remote.TunnelAccessAudit = failure == "EvidenceIncomplete" ? new JsonObject { ["Passed"] = true } : new JsonObject { ["Passed"] = false, ["Code"] = failure };
            var secretFile = SafePath.Resolve(directory, "secrets.dotnet.private.json"); var secretBefore = f.Store.ReadSecret(secretFile).ToJsonString();
            var request = new OperationRequest(OperationKind.TunnelAccess, relative, new() { ["PublicUrl"] = "https://monitor.example.com/" });
            if (failure == "") Check(await f.Engine(remote).ExecuteAsync(request, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed, "public route did not pass");
            else await RefusesAsync(() => f.Engine(remote).ExecuteAsync(request, Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "failed public route reported success");
            var savedPlan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json")); var savedState = ArchiveStore.ReadJson(stateFile);
            Check(remote.Mutations == 0 && !remote.Commands.Any(name => name.Contains("rollback") || name.Contains("commit")), "public check restarted or mutated services");
            Check(savedState.Text("TunnelAccess.Status") == (failure == "" ? "Passed" : "Failed") && savedState.Text("TunnelAccess.PublicUrl") == "https://monitor.example.com", "route verification state missing or incorrect");
            Check(savedPlan.Text("Cloudflared.PublicUrl") == (failure == "" ? "https://monitor.example.com" : "https://old.example.com") && JsonNode.DeepEquals(savedPlan["Reality"], plan["Reality"]) && secretBefore == f.Store.ReadSecret(secretFile).ToJsonString(), "failed route overwrote working URL or unrelated plan/secrets");
        }
        var missing = f.Plan("route-no-controller"); f.SaveInstance(missing); var missingRemote = new FakeRemote();
        await RefusesAsync(() => f.Engine(missingRemote).ExecuteAsync(new(OperationKind.TunnelAccess, f.Relative(missing), new() { ["PublicUrl"] = "https://monitor.example.com" }), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default), "route check ran without controller and connector");
        Check(missingRemote.Commands.Count == 0, "missing components reached remote route probe");
    }
}
