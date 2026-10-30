using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunXhttpTests(bool modelOnly = false) { XhttpExpandedModel();await XhttpModel(); if (!modelOnly) await XhttpRuntime(); Console.WriteLine($"PASS: {assertions} XHTTP model, fixed-core protocol, provenance and lifecycle assertions."); }
    public async Task RunXhttpRuntimeTests() { await XhttpRuntime(); Console.WriteLine($"PASS: {assertions} actual TLS/Reality XHTTP assertions; loopback only."); }
    private async Task XhttpRuntime()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("MAY_TEST_XRAY") is not {} xray) { Console.WriteLine("SKIP: fixed Xray and bundled Windows Mihomo required for XHTTP actual runtime."); return; }
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(5)); var ct = budget.Token; var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner();
        Check(ArchiveStore.Digest(File.ReadAllBytes(xray)) == "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1", "XHTTP runtime used an unpinned Xray core");
        using var key = RSA.Create(2048); var request = new CertificateRequest("CN=xhttp.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("xhttp.example.test"); names.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(names.Build()); request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-3), DateTimeOffset.UtcNow.AddDays(2));
        await using var target = await HysteriaHttpsTarget.Start(repository, f, ca, key, ct); await using var dns = new TuicDnsTarget(); var directory = f.Paths.Resolve("private/xhttp-runtime"); Directory.CreateDirectory(directory); var ids = new List<int>(); var outcomes = new JsonArray();
        var targetPort = TcpPort();
        var tlsTarget = new JsonObject { ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "anytls", ["listen"] = "127.0.0.1", ["listen_port"] = targetPort, ["users"] = new JsonArray(new JsonObject { ["password"] = "synthetic-target-only" }), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "xhttp.example.test", ["min_version"] = "1.3", ["alpn"] = new JsonArray("h2"), ["certificate"] = PemLines(ca.ExportCertificatePem()), ["key"] = PemLines(key.ExportPkcs8PrivateKeyPem()) } }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct" }) };
        await using var camouflage = await ServerQuicProcess.Start(assets.ResolveCore("sing-box"), tlsTarget, directory, false, targetPort, ct); ids.Add(camouflage.Process.Id);
        var keys = await InboundKeyGeneration.RealityAsync(assets, tools, ct);
        foreach (var security in new[] { "TLS", "Reality" })
        {
            var plan = f.Plan("Xhttp-native"); var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, credentials, "VLESS"); inbound["Options"]!["ServerName"] = "xhttp.example.test"; inbound["Options"]!["Transport"]!["Host"] = "front.example.test";
            inbound["Listener"]!["Port"] = TcpPort(); var second = InboundCatalog.AddUser(model, credentials, "second", "Uuid"); inbound["UserIds"]!.AsArray().Add(second.Text("Id"));
            if (security == "TLS") inbound["CertificateId"] = InboundCatalog.ImportCertificate(model, credentials, "TLS", ca.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()).Text("Id");
            else { inbound["Options"]!["Security"] = "Reality"; inbound["Options"]!["Reality"] = VlessXhttp.RealityOptions(); inbound["Options"]!["Reality"]!["HandshakeServer"] = "target.example.test"; inbound["Options"]!["Reality"]!["HandshakePort"] = targetPort; inbound["Options"]!["Reality"]!["PublicKey"] = keys.Text("PublicKey"); credentials["Inbounds"]![inbound.Text("Id")]!["RealityPrivateKey"] = keys.Text("PrivateKey"); }
            _ = InboundCatalog.Normalize(model, credentials); var config = InboundRendering.Configuration(f.Store, plan, model, credentials, inbound); config["inbounds"]![0]!["listen"] = "127.0.0.1"; if (security == "Reality") config["inbounds"]![0]!["streamSettings"]!["realitySettings"]!["target"] = "127.0.0.1:" + targetPort;
            await using var running = await ServerQuicProcess.Start(xray, config, directory, true, inbound.Number("Listener.Port"), ct); ids.Add(running.Process.Id);
            var nodes = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, credentials).ToArray();
            foreach (var node in nodes)
            {
                node["clash"]!["server"] = "127.0.0.1";node["sing_box"]!["server"]="127.0.0.1";
                foreach(var coreName in new[]{"mihomo","may-core"})
                {
                await using var client = await Round15Client.Start(coreName=="may-core"?"sing-box":"mihomo", assets.ResolveCore(coreName), node, ca, directory, ct); ids.Add(client.Process.Id); using var http = TuicHttp(client.Port, ca);
                try { Check(await http.GetStringAsync("https://127.0.0.1:" + target.Port, ct) == "198.51.100.22", security + " XHTTP authenticated HTTPS failed"); }
                catch (HttpRequestException) { Console.WriteLine("XHTTP client: " + await client.StopAndRead() + "\nServer: " + await running.StopAndRead()); throw; }
                Check((await ClientProxyUdp.ProbeAsync(client.Port, new(IPAddress.Loopback, dns.Port), ct)).Flag("ResponseMatched"), security + " XHTTP real UDP did not return");
                outcomes.Add(new JsonObject { ["Security"] = security,["Core"]=coreName, ["User"] = node.Text("InboundOrigin.UserId"), ["Https"] = true, ["ApplicationUdp"] = true });
                }
            }
            var selected = nodes[0].DeepClone().AsObject(); selected["clash"]!["server"] = "127.0.0.1";selected["sing_box"]!["server"]="127.0.0.1"; var endpoints = new ClientDiagnosticEndpoints(new("https://127.0.0.1:" + target.Port), new("https://127.0.0.1:" + target.Port), new("https://127.0.0.1:" + target.Port)) { Udp4 = new(IPAddress.Loopback, dns.Port) };
            var diagnostic = new ClientRouteDiagnostics(assets, tools, endpoints, ca); var scheme = new JsonObject { ["Nodes"] = new JsonArray(selected), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray(selected.Text("region_group")) } }; var route = ClientTopology.DiagnosticRoute(scheme, selected.Text("name"));
            var report = await diagnostic.RunAsync(route, directory, new InlineProgress<string>(_ => { }), ct); Check(VlessXhttp.Evidence(selected, report), security + " product XHTTP diagnostic did not produce typed evidence: " + report.ToJsonString());
            foreach (var fault in security == "TLS" ? new[] { "uuid", "sni", "path", "host" } : new[] { "uuid", "sni", "path", "host", "public-key", "short-id" })
            {
                var bad = selected.DeepClone().AsObject(); var c = bad["clash"]!;
                switch (fault) { case "uuid": c["uuid"] = Guid.NewGuid().ToString(); break; case "sni": c["servername"] = "wrong.example.test"; break; case "path": c["xhttp-opts"]!["path"] = "/wrong/"; break; case "host": c["xhttp-opts"]!["host"] = "wrong.example.test"; break; case "public-key": c["reality-opts"]!["public-key"] = keys.Text("PrivateKey"); break; case "short-id": c["reality-opts"]!["short-id"] = "deadbeef"; break; }
                await using var client = await Round15Client.Start("mihomo", assets.ResolveCore("mihomo"), bad, ca, directory, ct); ids.Add(client.Process.Id); using var http = TuicHttp(client.Port, ca); http.Timeout = TimeSpan.FromSeconds(2); var before = target.Requests; var refused = false;
                try { await http.GetStringAsync("https://127.0.0.1:" + target.Port, ct); } catch (Exception e) when (e is HttpRequestException or OperationCanceledException) { refused = true; }
                Check(refused && target.Requests == before, security + " XHTTP bypassed invalid " + fault);
            }
            Console.WriteLine("Round 19 native: VLESS / " + security + " / XHTTP h2 stream-one, two users, HTTPS/UDP, product diagnostic and failure cases passed."); credentials.Clear();
        }
        await camouflage.DisposeAsync(); // Include its process in the explicit closure check.
        Check(ids.All(id => { try { using var p = System.Diagnostics.Process.GetProcessById(id); return p.HasExited; } catch (ArgumentException) { return true; } }), "XHTTP fixture left an owned core running");
        if (Environment.GetEnvironmentVariable("MAY_R19_EVIDENCE") is {} path) ArchiveStore.WriteJson(Path.GetFullPath(path), new JsonObject { ["SyntheticOnly"] = true, ["Cases"] = outcomes, ["OwnedCoresStopped"] = true }); keys.Clear();
        static JsonArray PemLines(string text) => new(text.Trim().Split('\n').Select(l => (JsonNode?)JsonValue.Create(l.TrimEnd('\r'))).ToArray());
    }
}
