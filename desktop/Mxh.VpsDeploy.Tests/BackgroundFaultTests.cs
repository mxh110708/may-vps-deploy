using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;
using Mxh.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task BackgroundFaultExperience(Fixture fixture)
    {
        var root = fixture.Paths.Resolve("fault-test"); Directory.CreateDirectory(root);
        Directory.CreateDirectory(SafePath.Resolve(root, "test-secrets"));
        var id = Guid.NewGuid().ToString("N");
        var config = new JsonObject { ["SchemaVersion"] = 1, ["SessionId"] = id, ["Root"] = root,
            ["PipeName"] = "mxh-test-" + id, ["Token"] = new string('a', 64),
            ["AllowedEndpoints"] = new JsonArray(new JsonObject { ["Host"] = "192.0.2.10", ["Port"] = 22 }) };
        ArchiveStore.WriteJson(SafePath.Resolve(root, BackgroundTestSession.Marker), new JsonObject { ["IsolatedTestRoot"] = true, ["SessionId"] = id });
        var manifest = SafePath.Resolve(root, "test-session.private.json"); ArchiveStore.WriteJson(manifest, config);
        var faultFile = SafePath.Resolve(root, "test-secrets/transport-fault.private.json");
        void Fault(string asset, string action) => ArchiveStore.WriteJson(faultFile, new JsonObject { ["SchemaVersion"] = 1, ["Id"] = Guid.NewGuid().ToString("N"), ["Asset"] = asset, ["Action"] = action });
        var fake = new FakeRemote(); var endpoint = new SshEndpoint("192.0.2.10", 22, "root", null);
        var payload = "# MXH asset: audit.sh\n# sensitive-fixture-content\n";
        Fault("audit.sh", "ExitAfter");
        var disabled = BackgroundTestSession.Load(manifest, fixture.Root + "-app").Restrict(fake);
        await using (var connection = await disabled.OpenAsync(endpoint, new FakeUser(), default))
            await connection.RunScriptAsync(payload, TimeSpan.FromSeconds(10), false, default);
        Check(fake.Commands.Count == 1, "fault file affected a session without explicit opt-in");
        config["AllowTransportFaults"] = true; ArchiveStore.WriteJson(manifest, config);
        var session = BackgroundTestSession.Load(manifest, fixture.Root + "-app"); var enabled = session.Restrict(fake);
        Fault("audit.sh", "DisconnectBefore");
        await using (var connection = await enabled.OpenAsync(endpoint, new FakeUser(), default))
            await RefusesAsync(() => connection.RunScriptAsync(payload, TimeSpan.FromSeconds(10), false, default), "pre-request fault was not applied");
        Check(fake.Commands.Count == 1, "pre-request fault dispatched a command");
        Fault("audit.sh", "DisconnectAfter");
        await using (var connection = await enabled.OpenAsync(endpoint, new FakeUser(), default))
            await RefusesAsync(() => connection.RunScriptAsync(payload, TimeSpan.FromSeconds(10), false, default), "lost acknowledgement not applied");
        Check(fake.Commands.Count == 2, "lost acknowledgement did not execute exactly once");
        var restarted = BackgroundTestSession.Load(manifest, fixture.Root + "-app").Restrict(fake);
        await using (var connection = await restarted.OpenAsync(endpoint, new FakeUser(), default))
            await connection.RunScriptAsync(payload, TimeSpan.FromSeconds(10), false, default);
        Check(fake.Commands.Count == 3, "consumed injection was applied again after restart");
        foreach (var (asset, action) in new[] { ("arbitrary.sh", "DisconnectAfter"), ("audit.sh", "ExecuteShell"), ("../audit.sh", "ExitAfter") })
        {
            Fault(asset, action);
            await using var connection = await enabled.OpenAsync(endpoint, new FakeUser(), default);
            await RefusesAsync(() => connection.RunScriptAsync(payload, TimeSpan.FromSeconds(10), false, default), "unsafe fault configuration accepted");
        }
        Check(fake.Commands.Count == 3, "invalid fault parameters reached the remote transport");
        Check(!File.ReadAllText(session.Artifact("transport-journal.private.jsonl")).Contains("sensitive-fixture-content"), "request payload leaked in fault journal");
        config["AllowedEndpoints"] = new JsonArray(); ArchiveStore.WriteJson(manifest, config);
        Refuses(() => BackgroundTestSession.Load(manifest, fixture.Root + "-app"), "fault testing enabled without a test host");
    }
}
