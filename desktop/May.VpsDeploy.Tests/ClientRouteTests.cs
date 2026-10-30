using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunClientRouteTests()
    {
        using var fixture = new Fixture(repository); await ClientRouteExperience(fixture);
        Console.WriteLine($"PASS: {assertions} node import, topology, stale evidence and isolated diagnostic assertions; no production connections.");
    }
    private static readonly string ImportTestUuid = Guid.NewGuid().ToString();
    private static string TestRealityLink => "vless://" + ImportTestUuid + "@entry.example:443?security=reality&flow=xtls-rprx-vision&encryption=none&type=tcp&sni=tls.example&fp=chrome&pbk=" + new string('A', 43) + "&sid=abcd#Entry";
    private async Task ClientRouteExperience(Fixture f)
    {
        var scheme = ClientSchemes.New(f.Paths); scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" };
        var key = Convert.ToBase64String(Enumerable.Repeat((byte)7, 16).ToArray());
        var ss = "ss://2022-blake3-aes-128-gcm:" + Uri.EscapeDataString(key + ":" + key) + "@[2001:db8::20]:8443#Landing";
        var any = "anytls://synthetic%40password@any.example/?sni=tls.example#AnyTLS";
        var input = TestRealityLink + "\n" + any + "\n" + ss + "\n" + TestRealityLink.Replace("#Entry", "#AnotherName") + "\n" + any.Replace("synthetic%40password", "different-password") + "\nhy2://unsupported@invalid.example:443?unsupported=1";
        var initial = ArchiveStore.Fingerprint(scheme); var preview = ClientNodeImport.Preview(input, scheme, "US-West-LA Entry");
        Check(preview.Accepted == 4 && preview.Rows.Count(r => r.Status == "Duplicate") == 1 && preview.Rows.Count(r => r.Status == "Rejected") == 1, "batch dropped errors or deduplicated only by endpoint");
        Check(ArchiveStore.Fingerprint(scheme) == initial, "preview mutated the scheme");
        Check(preview.Rows[4].Node!.Text("name") == "AnyTLS (2)" && preview.Rows[4].Message.Contains("名称重复"), "name collision not visible in preview");
        Check(preview.Rows[1].Node!.Number("sing_box.server_port") == 443 && preview.Rows[1].Node!.Text("sing_box.password") == "synthetic@password" && preview.Rows[1].Node!.At("sing_box.tls.ech") == null, "AnyTLS URI defaults or optional ECH corrupted");
        Check(preview.Rows[2].Node!.Text("sing_box.server") == "2001:db8::20" && preview.Rows[2].Node!.Text("sing_box.password") == key + ":" + key, "IPv6 or SS2022 identity chain changed");
        Check(ClientNodeImport.Apply(scheme, preview) == 4 && scheme["Candidate"] == null && scheme["Nodes"]!.AsArray().Count == 4, "import did not invalidate generated files");
        Refuses(() => ClientNodeImport.Apply(scheme, preview), "same stale preview applied twice");
        var node = scheme["Nodes"]!.AsArray()[0]!.AsObject();
        Check(node.Text("Id").Length == 32 && node.Text("Source.Kind") == "ShareLink" && !node["Source"]!.ToJsonString().Contains("://"), "provenance retained raw credentials or lost stable identity");
        var renamed = node.DeepClone().AsObject(); renamed["name"] = "Renamed"; renamed["clash"]!["name"] = "Renamed"; renamed["sing_box"]!["tag"] = "Renamed";
        Check(ClientNodeImport.ConnectionFingerprint(node) == ClientNodeImport.ConnectionFingerprint(renamed), "display rename changed connection identity");
        var legacy = Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-128-gcm:synthetic:with+symbols"));
        var legacyPreview = ClientNodeImport.Preview("ss://" + legacy + "@ss.example:443#SS%20one+two", scheme, "Europe Entry", "entry");
        Check(legacyPreview.Accepted == 1 && legacyPreview.Rows[0].Node!.Text("sing_box.password") == "synthetic:with+symbols" && legacyPreview.Rows[0].Node!.Text("name") == "SS one+two" && legacyPreview.Rows[0].Node!.Text("kind") == "entry", "SIP002, literal plus or explicit node role changed");
        foreach (var invalid in new[]
        {
            TestRealityLink.Replace("type=tcp", "type=ws"), TestRealityLink.Replace("#Entry", "&unknown=1#Entry"), TestRealityLink.Replace("security=reality", "security=none"),
            TestRealityLink.Replace("sid=abcd", "sid=abc"), TestRealityLink.Replace("sid=abcd", "sid=abcd&sid=abcd"), TestRealityLink.Replace("sid=abcd", "sid=abcd&spx=%2F"),
            TestRealityLink.Replace("fp=chrome", "fp=randomized"),
            any.Replace("#AnyTLS", "&insecure=1#AnyTLS"), any.Replace("#AnyTLS", "&plugin=unknown#AnyTLS"), any.Replace("synthetic%40password", "bad%ZZ"), any.Replace("synthetic%40password", "bad%FF"),
            ss.Replace("#Landing", "?plugin=unknown#Landing"), ss.Replace("8443", "0"), ss.Replace("8443", "65536"), ss.Replace("#Landing", "#bad%0Aname"),
            "ss://" + Convert.ToBase64String(Encoding.UTF8.GetBytes("2022-blake3-aes-128-gcm:" + key)) + "@ss.example:443", Convert.ToBase64String(Encoding.UTF8.GetBytes(any))
        })
        {
            var rejected = ClientNodeImport.Preview(invalid, scheme, "Europe Entry");
            Check(rejected.Accepted == 0 && rejected.Rows.All(r => r.Node == null && !r.Message.Contains("synthetic") && !r.Message.Contains("password@")), "unsupported/malformed link accepted or leaked credentials");
        }
        Refuses(() => ClientNodeImport.Preview(new string('x', ClientNodeImport.MaximumCharacters + 1), scheme, "Europe Entry"), "unbounded import accepted");
        Refuses(() => ClientNodeImport.Preview(new string('\n', 201), scheme, "Europe Entry"), "unbounded import line count");
        var regions = ClientTopology.Regions(scheme); Check(regions.Count == 1 && regions[0].Entries.Count == 3 && regions[0].Landings.Count == 1, "topology mixed node roles");
        var route = ClientTopology.DiagnosticRoute(scheme, "Entry", "Landing"); var raw = ArchiveStore.Fingerprint(scheme);
        var directRoute = ClientTopology.DiagnosticRoute(scheme, "Entry"); var directConfig = ClientTopology.DiagnosticConfiguration(directRoute, 12005, 12006);
        Check(directRoute.Landing == null && directConfig["inbounds"]!.AsArray().Count == 1 && directConfig["outbounds"]!.AsArray().Count == 1, "entry-only diagnostic constructed a landing or extra listener");
        var config = ClientTopology.DiagnosticConfiguration(route, 12001, 12002);
        Check(config["inbounds"]!.AsArray().All(n => n!.Text("listen") == "127.0.0.1") && config["outbounds"]!.AsArray().All(n => n!.Text("type") != "direct"), "diagnostics exposed a listener or direct fallback");
        Check(config["outbounds"]![1]!.Text("detour") == "diagnostic-entry" && config["route"]!.Text("final") == "diagnostic-landing" && ArchiveStore.Fingerprint(scheme) == raw, "diagnostic detour bypassed selected path or changed scheme");
        Check(ClientTopology.ConnectionFamily(route.Landing!) == "IPv6" && ClientTopology.EgressFamily(route.Landing!) == "Unknown", "connection IPv6 falsely treated as IPv6 egress");
        node["name"] = "Renamed"; node["clash"]!["name"] = "Renamed"; node["sing_box"]!["tag"] = "Renamed";
        Check(ClientTopology.DiagnosticRoute(scheme, "Renamed", "Landing").Fingerprint == route.Fingerprint, "rename invalidated an unchanged route");
        var landing = scheme["Nodes"]!.AsArray().OfType<JsonObject>().Single(n => n.Text("name") == "Landing");
        landing["Egress"] = new JsonObject { ["Family"] = "IPv6" };
        Check(ClientTopology.DiagnosticRoute(scheme, "Renamed", "Landing").Fingerprint != route.Fingerprint, "changed egress reused healthy evidence");
        landing["Egress"]!["ExpectedAddress"] = "192.0.2.1"; Refuses(() => ClientTopology.DiagnosticRoute(scheme, "Renamed", "Landing"), "inconsistent expected egress accepted"); landing.Remove("Egress");
        landing["transit_group"] = "Europe Entry"; Refuses(() => ClientTopology.DiagnosticRoute(scheme, "Renamed", "Landing"), "cross-region path silently constructed"); landing["transit_group"] = "US-West-LA Entry";
        landing["sing_box"]!["detour"] = "Europe Entry";
        Check(ClientTopology.DiagnosticConfiguration(ClientTopology.DiagnosticRoute(scheme, "Renamed", "Landing"), 12003, 12004)["outbounds"]![1]!.Text("detour") == "diagnostic-entry", "edited transit group did not replace imported group dependency"); landing["sing_box"]!.AsObject().Remove("detour");
        node["sing_box"]!["detour"] = "other-upstream"; Refuses(() => ClientTopology.DiagnosticRoute(scheme, "Renamed"), "unrepresented upstream silently discarded"); node["sing_box"]!.AsObject().Remove("detour");
        var business = scheme["Layout"]!["business_groups"]![0]!.AsObject(); business["default"] = "Landing";
        Check(ClientTopology.RemovalImpact(scheme, landing).Contains("业务组：AI Services"), "removal impact missed business default");
        ClientSchemes.RenameNodeReferences(scheme, "Landing", "NewLanding"); Check(business.Text("default") == "NewLanding", "rename left dangling business default"); business["default"] = "";
        Refuses(() => ClientSchemes.Specification(scheme), "removed business default silently fell back"); business["default"] = "Default Exit";
        var workbench = new ClientWorkbench(f.Store, new ExternalToolRunner(), new ValidationAssets(new AppPaths(repository), "windows-amd64"), Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") ?? "python");
        workbench.Save(scheme); Check(workbench.List().Single(s => s.Text("Id") == scheme.Text("Id"))["Nodes"]![0]!.Text("Id") == node.Text("Id"), "node identities were not persisted with encrypted scheme");
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
        if (!string.IsNullOrEmpty(python)) { await workbench.BuildAsync(scheme, CancellationToken.None); await workbench.ValidateAsync(scheme, CancellationToken.None); Check(scheme.Text("Candidate.ValidationStatus") == "Passed", "imported real dual-client candidate failed validation"); }
        if (OperatingSystem.IsWindows()) await LoopbackClientDiagnostic(f);
        else Console.WriteLine("SKIP: client route runtime fixture requires the bundled Windows core; portable boundaries still run.");
    }

    private async Task LoopbackClientDiagnostic(Fixture f)
    {
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner(); var executable = assets.ResolveCore("sing-box");
        using var entrySocket = new TcpListener(IPAddress.Loopback, 0); entrySocket.Start(); using var landingSocket = new TcpListener(IPAddress.Loopback, 0); landingSocket.Start();
        var entryPort = ((IPEndPoint)entrySocket.LocalEndpoint).Port; var landingPort = ((IPEndPoint)landingSocket.LocalEndpoint).Port;
        var directory = f.Paths.Resolve("private/diagnostic-tests"); Directory.CreateDirectory(directory);
        JsonObject Inbound(int port) => new() { ["type"] = "shadowsocks", ["listen"] = "127.0.0.1", ["listen_port"] = port, ["method"] = "aes-128-gcm", ["password"] = "synthetic-loopback-only" };
        var serverFile = SafePath.Resolve(directory, "server.private.json"); ArchiveStore.WriteJson(serverFile, new JsonObject { ["log"] = new JsonObject { ["level"] = "error" }, ["inbounds"] = new JsonArray(Inbound(entryPort), Inbound(landingPort)), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "local" }), ["route"] = new JsonObject { ["final"] = "local" } });
        var check = await tools.RunAsync(executable, ["check", "-c", serverFile], null, TimeSpan.FromSeconds(15), CancellationToken.None); check.RequireSuccess("Loopback fixture core refused configuration.");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true }; foreach (var arg in new[] { "run", "-c", serverFile }) start.ArgumentList.Add(arg);
        entrySocket.Stop(); landingSocket.Stop(); using var process = Process.Start(start)!; var errors = process.StandardError.ReadToEndAsync(); var output = process.StandardOutput.ReadToEndAsync();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        using var web = new TcpListener(IPAddress.Loopback, 0); web.Start(); var webPort = ((IPEndPoint)web.LocalEndpoint).Port;
        var requestArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var hang = false; var responseBody = "192.0.2.123"; var requests = 0;
        var server = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    using var client = await web.AcceptTcpClientAsync(stop.Token); using var stream = client.GetStream(); using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                    string? line; do { line = await reader.ReadLineAsync(stop.Token); } while (!string.IsNullOrEmpty(line));
                    Interlocked.Increment(ref requests); requestArrived.TrySetResult();
                    if (hang) { await Task.Delay(Timeout.Infinite, stop.Token); continue; }
                    var bytes = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + responseBody.Length + "\r\n\r\n" + responseBody); await stream.WriteAsync(bytes, stop.Token);
                }
            }
            catch (OperationCanceledException) { }
        });
        try
        {
            var ready = false; for (var i = 0; i < 40 && !process.HasExited; i++) { try { using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, entryPort, stop.Token); ready = true; break; } catch (SocketException) { await Task.Delay(100, stop.Token); } }
            Check(ready, "loopback proxy server not ready");
            var scheme = ClientSchemes.New(f.Paths);
            var preview = ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-loopback-only@localhost:" + entryPort + "#LoopEntry", scheme, "US-West-LA Entry", "entry"); ClientNodeImport.Apply(scheme, preview);
            preview = ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-loopback-only@127.0.0.1:" + landingPort + "#LoopLanding", scheme, "US-West-LA Entry", "landing"); ClientNodeImport.Apply(scheme, preview);
            foreach (var n in scheme["Nodes"]!.AsArray().OfType<JsonObject>()) n["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = responseBody };
            var route = ClientTopology.DiagnosticRoute(scheme, "LoopEntry", "LoopLanding"); var target = new Uri("http://127.0.0.1:" + webPort + "/"); var diagnostic = new ClientRouteDiagnostics(assets, tools, new(target, target, target));
            var progress = new Progress<string>(); var report = await diagnostic.RunAsync(route, directory, progress, stop.Token);
            Check(report.Text("Status") == "Reachable" && report.Flag("EntryEgress.Verified") && report.Flag("ChainEgress.Verified") && requests == 2, "real loopback chain did not traverse both proxies or verify egress");
            Check(report["Stages"]!.AsArray().Any(s => s!.Text("Id") == "RemoteLeg" && s.Text("Status") == "NotMeasured"), "local elapsed falsely presented as remote RTT");
            Check(!Directory.EnumerateDirectories(directory, "client-diagnostic-*").Any(), "successful diagnostic retained plaintext credentials");
            var loopEntry = scheme["Nodes"]![0]!.AsObject(); var expectedEgress = loopEntry["Egress"]!.DeepClone(); loopEntry.Remove("Egress");
            var directReport = await diagnostic.RunAsync(ClientTopology.DiagnosticRoute(scheme, "LoopEntry"), directory, progress, stop.Token); loopEntry["Egress"] = expectedEgress;
            Check(directReport.Text("Status") == "Reachable" && !directReport.Flag("EntryEgress.Verified") && directReport.Text("EntryEgress.Address") == responseBody && directReport["ChainEgress"] == null && requests == 3, "entry-only observation falsely verified an unknown egress or ran extra requests");
            var loopLanding = scheme["Nodes"]![1]!.AsObject(); loopLanding["sing_box"]!["password"] = "synthetic-wrong-password";
            var badRoute = ClientTopology.DiagnosticRoute(scheme, "LoopEntry", "LoopLanding"); loopLanding["sing_box"]!["password"] = "synthetic-loopback-only";
            var broken = await diagnostic.RunAsync(badRoute, directory, progress, stop.Token);
            Check(broken.Text("Status") == "Failed" && broken["Stages"]!.AsArray().Any(s => s!.Text("Id") == "EntryHttps" && s.Text("Status") == "Passed") && broken["Stages"]!.AsArray().Any(s => s!.Text("Id") == "ChainHttps" && s.Text("Status") == "Failed") && requests == 4, "wrong landing password bypassed the selected chain or fell back to a direct request");
            responseBody = new string('x', 129); report = await diagnostic.RunAsync(route, directory, progress, stop.Token);
            Check(report.Text("Status") == "Failed" && requests == 5, "oversized egress response accepted or chain retried");
            responseBody = "192.0.2.124"; report = await diagnostic.RunAsync(route, directory, progress, stop.Token);
            Check(report.Text("Status") == "Failed" && !report.Flag("EntryEgress.Verified"), "wrong egress marked healthy");
            hang = true; requestArrived = new(TaskCreationOptions.RunContinuationsAsynchronously); using var cancel = new CancellationTokenSource();
            var pending = diagnostic.RunAsync(route, directory, progress, cancel.Token); await requestArrived.Task.WaitAsync(TimeSpan.FromSeconds(15)); var watch = Stopwatch.StartNew(); cancel.Cancel(); var cancelled = false;
            try { await pending; } catch (OperationCanceledException) { cancelled = true; }
            Check(cancelled && watch.Elapsed < TimeSpan.FromSeconds(5) && !Directory.EnumerateDirectories(directory, "client-diagnostic-*").Any(), "cancel did not terminate owned child and remove credential file promptly");
        }
        finally { stop.Cancel(); web.Stop(); if (!process.HasExited) process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); await Task.WhenAll(output, errors, server); }
    }
}
