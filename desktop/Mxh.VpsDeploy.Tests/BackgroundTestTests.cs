using System.IO.Pipes;
using System.Text;
using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;
using Mxh.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunBackgroundTests()
    {
        using var f = new Fixture(repository); await BackgroundTestTransport(f); await BackgroundFaultExperience(f);
        Console.WriteLine($"PASS: {assertions} background session boundary assertions; no production connections.");
    }
    private async Task BackgroundTestTransport(Fixture f)
    {
        var root = f.Paths.Resolve("background-test"); Directory.CreateDirectory(root);
        var app = f.Root + "-independent-app";
        var id = Guid.NewGuid().ToString("N"); var token = new string('a', 64);
        var config = new JsonObject { ["SchemaVersion"] = 1, ["SessionId"] = id, ["Root"] = root, ["PipeName"] = "mxh-test-" + id, ["Token"] = token,
            ["AllowedEndpoints"] = new JsonArray(new JsonObject { ["Host"] = "192.0.2.10", ["Port"] = 22022 }) };
        var manifest = SafePath.Resolve(root, "test-session.private.json"); ArchiveStore.WriteJson(manifest, config);
        Refuses(() => BackgroundTestSession.Load(manifest, app), "unmarked test root accepted");
        ArchiveStore.WriteJson(SafePath.Resolve(root, BackgroundTestSession.Marker), new JsonObject { ["IsolatedTestRoot"] = true, ["SessionId"] = id });
        Refuses(() => BackgroundTestSession.Load(manifest, root), "production root reused for tests");
        Refuses(() => BackgroundTestSession.Load(manifest, f.Root), "nested production root reused for tests");
        var session = BackgroundTestSession.Load(manifest, app);
        Refuses(() => session.Artifact("../escape.png"), "test artifact escaped");
        Refuses(() => session.RequireLocalPath(repository), "test output touched production directory");
        Refuses(() => session.Secret("../../outside"), "test credential escaped");
        Refuses(() => session.Secret("../test-session.private.json"), "credential reference read outside test-secrets");
        var fake = new FakeRemote(); var restricted = session.Restrict(fake);
        await RefusesAsync(() => restricted.OpenAsync(new("192.0.2.11", 22022, "root", null), new FakeUser(), default), "other test VPS accepted");
        await RefusesAsync(() => restricted.OpenAsync(new("192.0.2.10", 22, "root", null), new FakeUser(), default), "unlisted SSH port accepted");
        await RefusesAsync(() => restricted.OpenAsync(new("192.0.2.10", 22022, "root", repository), new FakeUser(), default), "production private key reused");
        Check(fake.Endpoints.Count == 0, "remote scope rejection happened after connecting");
        await using (await restricted.OpenAsync(new("192.0.2.10", 22022, "root", null), new FakeUser(), default)) { }
        Check(fake.Endpoints.Count == 1, "explicit test endpoint blocked");
        var plan = new JsonObject { ["Server"] = new JsonObject { ["IPv4"] = "192.0.2.10", ["BootstrapSshPort"] = 22022 },
            ["Ports"] = new JsonObject { ["SshPrimary"] = 23022, ["SshRescue"] = 33022 } };
        Refuses(() => session.PrepareReviewedDeployment(plan), "default session silently expanded management ports");
        await RefusesAsync(() => restricted.OpenAsync(new("192.0.2.10", 23022, "root", null), new FakeUser(), default), "rejected plan changed endpoint scope");
        config["AllowManagementPortTransition"] = true; ArchiveStore.WriteJson(manifest, config);
        var transition = BackgroundTestSession.Load(manifest, app); var migrating = transition.Restrict(fake);
        var wrongHost = (JsonObject)plan.DeepClone(); wrongHost["Server"]!["IPv4"] = "192.0.2.11";
        Refuses(() => transition.PrepareReviewedDeployment(wrongHost), "review authorized unlisted host");
        var wrongBootstrap = (JsonObject)plan.DeepClone(); wrongBootstrap["Server"]!["BootstrapSshPort"] = 22;
        Refuses(() => transition.PrepareReviewedDeployment(wrongBootstrap), "review authorized unlisted bootstrap port");
        var invalid = (JsonObject)plan.DeepClone(); invalid["Ports"]!["SshRescue"] = 65536;
        Refuses(() => transition.PrepareReviewedDeployment(invalid), "invalid management port accepted");
        await RefusesAsync(() => migrating.OpenAsync(new("192.0.2.10", 23022, "root", null), new FakeUser(), default), "invalid review partly expanded scope");
        transition.PrepareReviewedDeployment(plan);
        foreach (var port in new[] { 23022, 33022 }) await using (await migrating.OpenAsync(new("192.0.2.10", port, "root", null), new FakeUser(), default)) { }
        Check(fake.Endpoints.Count == 3, "reviewed management ports remained blocked");
        await RefusesAsync(() => migrating.OpenAsync(new("192.0.2.10", 24022, "root", null), new FakeUser(), default), "unrelated same-host port accepted");
        wrongBootstrap["Server"]!["BootstrapSshPort"] = 23022;
        Refuses(() => transition.PrepareReviewedDeployment(wrongBootstrap), "derived port authorized another transition");
        Check(Directory.GetFiles(Path.Combine(root, "test-artifacts"), "reviewed-management-*.private.json").Length == 1, "reviewed port scope evidence missing");
        var count = 0;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new BackgroundTestPipe(session, async (command, args) =>
        {
            if (command != "ui.read") throw new OperationException("Unknown test command.", code: "TestUnknownCommand");
            count++;
            if (args.Flag("hold")) { entered.SetResult(); await release.Task; }
            return new JsonObject { ["calls"] = count };
        }); server.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        async Task<JsonObject> Send(JsonObject request)
        {
            await using var pipe = new NamedPipeClientStream(".", session.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(3000, timeout.Token); await BackgroundTestPipe.Write(pipe, request, timeout.Token); return await BackgroundTestPipe.Read(pipe, timeout.Token);
        }
        JsonObject Request(string credential = "") => new() { ["version"] = 1, ["id"] = Guid.NewGuid().ToString("N"), ["token"] = credential == "" ? token : credential, ["command"] = "ui.read" };
        var result = await Send(Request("wrong")); Check(!result.Flag("ok") && result.Text("error_code") == "TestAuthenticationDenied" && count == 0, "unauthenticated pipe executed");
        var request = Request(); result = await Send(request); Check(result.Flag("ok") && count == 1, "authenticated command failed");
        result = await Send(request); Check(result.Text("error_code") == "TestDuplicateRequest" && count == 1, "pipe replay executed twice");
        request = Request(); request["command"] = "shell.run"; result = await Send(request); Check(result.Text("error_code") == "TestUnknownCommand", "arbitrary shell test command accepted");
        var excessive = new MemoryStream(Encoding.UTF8.GetBytes(new string('x', BackgroundTestPipe.MaximumBytes + 1) + "\n"));
        await RefusesAsync(() => BackgroundTestPipe.Read(excessive, default), "unbounded pipe request accepted");
        await using (var pipe = new NamedPipeClientStream(".", session.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
        {
            await pipe.ConnectAsync(3000, timeout.Token); await pipe.WriteAsync(Encoding.UTF8.GetBytes("[1]\n"), timeout.Token);
        }
        result = await BackgroundTestPipe.SendAsync(session, "ui.read", new(), timeout.Token); Check(result.Flag("ok") && count == 2, "malformed JSON killed test listener");
        request = Request(); request["arguments"] = new JsonObject { ["hold"] = true };
        var held = Send(request);
        await entered.Task.WaitAsync(timeout.Token);
        await using (var queued = new NamedPipeClientStream(".", session.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
        {
            var connecting = queued.ConnectAsync(3000, timeout.Token);
            try
            {
                // Unix can queue a connected client while the previous dispatch is held.
                // Windows waits for the occupied pipe instance to become available.
                if (!OperatingSystem.IsWindows()) await connecting;
                Check(count == 3, "queued request executed before current dispatch completed");
            }
            finally { release.TrySetResult(); }
            result = await held; Check(result.Flag("ok") && count == 3, "held pipe response failed");
            await connecting;
            await BackgroundTestPipe.Write(queued, Request(), timeout.Token);
            result = await BackgroundTestPipe.Read(queued, timeout.Token);
            Check(result.Flag("ok") && count == 4, "queued connection lost during previous client cleanup");
        }
        for (var attempt = 0; attempt < 20; attempt++)
        {
            result = await BackgroundTestPipe.SendAsync(session, "ui.read", new(), timeout.Token);
            Check(result.Flag("ok") && count == 5 + attempt, "consecutive pipe request lost or replayed");
        }
        await using (var abandoned = new NamedPipeClientStream(".", session.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
            await abandoned.ConnectAsync(3000, timeout.Token);
        result = await BackgroundTestPipe.SendAsync(session, "ui.read", new(), timeout.Token);
        Check(result.Flag("ok") && count == 25, "client disconnect left listener unable to accept requests");
        var log = File.ReadAllText(session.Artifact("commands.jsonl")); Check(!log.Contains(token) && !log.Contains("wrong"), "test session credentials leaked into audit");
        File.WriteAllText(SafePath.Resolve(root, PrivateDirectory.LocationFile), "{}");
        Refuses(() => BackgroundTestSession.Load(manifest, app), "external production archive reused by test process");
    }
}
