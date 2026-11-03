using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task InboundPolicy28Runtime()
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: round28 real protocol fixture uses fixed Windows cores; portable policy/recovery checks still run."); return; }
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(5)); var ct = budget.Token;
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner(); var directory = f.Paths.Resolve("private/round28-native"); Directory.CreateDirectory(directory);
        using var key = RSA.Create(2048); var request = new CertificateRequest("CN=inbound.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("inbound.example.com"); san.AddDnsName("www.example.com"); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build()); request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        await using var https = await HysteriaHttpsTarget.Start(repository, f, cert, key, ct); await using var origin = new Policy28HttpTarget(ct); await using var exceptionOrigin = new Policy28HttpTarget(ct, IPAddress.Parse("127.0.0.3")); await using var denied = new DestinationHttpTarget(ct); await using var dns = new TuicDnsTarget(IPAddress.Parse("127.0.0.2"));
        var children = new List<TestProcessIdentity>(); var cases = new JsonArray(); var xray = Environment.GetEnvironmentVariable("MAY_TEST_XRAY");
        var camouflagePort = MixedPort();
        var tlsTarget = new JsonObject { ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "anytls", ["listen"] = "127.0.0.1", ["listen_port"] = camouflagePort, ["users"] = new JsonArray(new JsonObject { ["password"] = "synthetic-target-only" }), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "www.example.com", ["min_version"] = "1.3", ["alpn"] = new JsonArray("h2"), ["certificate"] = new JsonArray(cert.ExportCertificatePem()), ["key"] = new JsonArray(key.ExportPkcs8PrivateKeyPem()) } }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct" }) };
        await using var camouflage = await Policy28Core.Start(assets.ResolveCore("sing-box"), tlsTarget, directory, false, camouflagePort, false, ct); children.Add(new TestProcessIdentity(camouflage.Process));
        foreach (var variant in new[] { "Shadowsocks2022", "AnyTLS", "Hysteria2", "TuicV5", "Reality", "XhttpTLS", "XhttpReality", "XhttpH3" })
        {
            var isXray = variant is "Reality" or "XhttpTLS" or "XhttpReality" or "XhttpH3";
            if (isXray && string.IsNullOrEmpty(xray)) { Console.WriteLine("SKIP: round28 " + variant + " requires MAY_TEST_XRAY."); continue; }
            var plan = f.Plan("Runtime28-" + variant); var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials(); var protocol = variant.StartsWith("Xhttp", StringComparison.Ordinal) ? "VLESS" : variant;
            var inbound = InboundCatalog.AddInbound(model, secrets, protocol); inbound["Listener"]!["Port"] = MixedPort(); var options = inbound["Options"]!.AsObject();
            if (protocol != "Shadowsocks2022") options["ServerName"] = "inbound.example.com";
            if (protocol is "AnyTLS" or "Hysteria2" or "TuicV5" or "VLESS") inbound["CertificateId"] = InboundCatalog.ImportCertificate(model, secrets, "synthetic cert", cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()).Text("Id");
            if (variant is "Reality" or "XhttpReality")
            {
                var keys = await InboundKeyGeneration.RealityAsync(assets, tools, ct); secrets["Inbounds"]![inbound.Text("Id")]!["RealityPrivateKey"] = keys.Text("PrivateKey");
                options["ServerName"] = "www.example.com";
                if (variant == "Reality") { options["HandshakeServer"] = "www.example.com"; options["HandshakePort"] = 443; options["PublicKey"] = keys.Text("PublicKey"); }
                else { options["Security"] = "Reality"; options["Reality"] = VlessXhttp.RealityOptions(); options["Reality"]!["PublicKey"] = keys.Text("PublicKey"); options["Reality"]!["HandshakeServer"] = "www.example.com"; inbound["CertificateId"] = ""; }
                keys.Clear();
            }
            if (protocol == "VLESS") { options["Transport"]!["Host"] = "front.example.test"; options["Transport"]!["Path"] = "/round28/"; options["Transport"]!["Mode"] = "auto"; options["Transport"]!["HTTPVersion"] = variant == "XhttpH3" ? "3" : "2"; }
            var defaultPort = MixedPort(); var extraPort = MixedPort(); var original = Policy28Exit(f, model, "default-" + variant, "192.0.2.28", defaultPort); var extra = Policy28Exit(f, model, "extra-" + variant, "192.0.2.29", extraPort); inbound["OutboundId"] = original.Resource.Text("Id");
            JsonObject Landing(JsonObject node, string bind) => new() { ["log"] = new JsonObject { ["disabled"] = true }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "shadowsocks", ["tag"] = "ss", ["listen"] = "127.0.0.1", ["listen_port"] = node.Number("sing_box.server_port"), ["method"] = node.Text("sing_box.method"), ["password"] = node.Text("sing_box.password") }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct", ["inet4_bind_address"] = bind }), ["route"] = new JsonObject { ["final"] = "direct" } };
            var policy = new JsonArray(new JsonObject { ["Kind"] = "Domain", ["Value"] = "localhost", ["Action"] = "NextHop", ["Target"] = extra.Resource.Text("Id") }, new JsonObject { ["Kind"] = "Cidr", ["Value"] = "127.0.0.3/32", ["Action"] = "NextHop", ["Target"] = extra.Resource.Text("Id") }, DestinationRule("Cidr", "127.0.0.2/32", "Reject")); InboundRoutingPolicy.Set(inbound, LoopbackRuleSets(policy, 1, InboundCatalog.Id)); _ = InboundCatalog.Normalize(model, secrets);
            var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
            if (!string.IsNullOrEmpty(python))
            {
                var payloadFile = SafePath.Resolve(directory, "payload.private.json"); ArchiveStore.WriteJson(payloadFile, InboundRendering.Payload(f.Store, plan, model, secrets));
                var program = "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('host',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.normalize(json.load(open(sys.argv[2],encoding='utf-8-sig'))); print('NORMALIZED')";
                var normalized = await tools.RunAsync(python, ["-c", program, Path.Combine(repository, "scripts/inbound-host.py"), payloadFile], null, TimeSpan.FromSeconds(10), ct);
                Check(normalized.ExitCode == 0 && normalized.Output.Trim() == "NORMALIZED", variant + " policy payload differs between controller and remote parser: " + normalized.Error);
            }
            JsonObject Render()
            {
                var config = InboundRendering.Configuration(f.Store, plan, model, secrets, inbound); config["inbounds"]![0]!["listen"] = "127.0.0.1";
                // Only this fixture maps reviewed synthetic remote endpoints to
                // owned loopback services; production address checks stay strict.
                foreach (var output in config["outbounds"]!.AsArray().OfType<JsonObject>())
                {
                    if (output.Text("server") is "192.0.2.28" or "192.0.2.29") output["server"] = "127.0.0.1";
                    if (output.Text("protocol") == "shadowsocks") output["settings"]!["servers"]![0]!["address"] = "127.0.0.1";
                }
                if (variant is "Reality" or "XhttpReality") config["inbounds"]![0]!["streamSettings"]!["realitySettings"]!["target"] = "127.0.0.1:" + camouflagePort; return config;
            }
            var defaultConfig = Landing(original.Node, "127.0.0.5"); var extraConfig = Landing(extra.Node, "127.0.0.6"); var udp = InboundCatalog.UdpOnly(inbound) || variant == "XhttpH3";
            await using var defaultCore = await Policy28Core.Start(assets.ResolveCore("sing-box"), defaultConfig, directory, false, defaultPort, false, ct); children.Add(new TestProcessIdentity(defaultCore.Process));
            await using var extraCore = await Policy28Core.Start(assets.ResolveCore("sing-box"), extraConfig, directory, false, extraPort, false, ct); children.Add(new TestProcessIdentity(extraCore.Process));
            var server = await Policy28Core.Start(isXray ? xray! : assets.ResolveCore("sing-box"), Render(), directory, isXray, inbound.Number("Listener.Port"), udp, ct); children.Add(new TestProcessIdentity(server.Process));
            var node = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).Single(); node["clash"]!["server"] = "127.0.0.1"; node["sing_box"]!["server"] = "127.0.0.1";
            try
            {
                foreach (var clientName in new[] { "native", "mihomo" })
                {
                    Policy28Core? native = null; Round15Client? mihomo = null;
                    try
                    {
                        int port;
                        if (clientName == "mihomo") { mihomo = await Round15Client.Start("mihomo", assets.ResolveCore("mihomo"), node, cert, directory, ct); children.Add(new TestProcessIdentity(mihomo.Process)); port = mihomo.Port; }
                        else
                        {
                            port = MixedPort(); var output = node["sing_box"]!.DeepClone().AsObject(); output["tag"] = "entry"; if (output["tls"] is JsonObject tls && !tls.Flag("reality.enabled")) tls["certificate"] = new JsonArray(cert.ExportCertificatePem());
                            var client = new JsonObject { ["log"] = new JsonObject { ["disabled"] = true }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "mixed", ["listen"] = "127.0.0.1", ["listen_port"] = port }), ["outbounds"] = new JsonArray(output), ["route"] = new JsonObject { ["final"] = "entry" } };
                            native = await Policy28Core.Start(assets.ResolveCore(protocol == "VLESS" ? "may-core" : "sing-box"), client, directory, false, port, false, ct); children.Add(new TestProcessIdentity(native.Process));
                        }
                        using var http = TuicHttp(port, cert); Check(await http.GetStringAsync("http://127.0.0.1:" + origin.Port, ct) == "127.0.0.5", variant + "/" + clientName + " default did not traverse its SS exit"); Check(await http.GetStringAsync("http://127.0.0.3:" + exceptionOrigin.Port, ct) == "127.0.0.6", variant + "/" + clientName + " category did not reach its distinct SS exit");
                        var domain = await http.GetStringAsync("http://localhost:" + origin.Port, ct); Check(domain == "127.0.0.6" || clientName == "mihomo" && domain == "127.0.0.5", variant + "/" + clientName + " unexpected original-domain metadata result");
                        Check(await http.GetStringAsync("https://127.0.0.1:" + https.Port, ct) == "198.51.100.22", variant + "/" + clientName + " HTTPS failed"); await CheckDeniedTarget(port, denied, ct);
                        Check((await ClientProxyUdp.ProbeAsync(port, new(IPAddress.Parse("127.0.0.2"), dns.Port), ct)).Flag("ResponseMatched"), variant + "/" + clientName + " TCP reject changed application UDP");
                        cases.Add(new JsonObject { ["Inbound"] = variant, ["Client"] = clientName, ["DistinctDefaultAndCategory"] = true, ["DomainReachedCategory"] = domain == "127.0.0.6", ["Https"] = true, ["TcpReject"] = true, ["UdpDefault"] = true });
                    }
                    finally { if (native != null) await native.DisposeAsync(); if (mihomo != null) await mihomo.DisposeAsync(); }
                }
                await using var failureClient = await Round15Client.Start("mihomo", assets.ResolveCore("mihomo"), node, cert, directory, ct); children.Add(new TestProcessIdentity(failureClient.Process)); using var web = TuicHttp(failureClient.Port, cert); web.Timeout = TimeSpan.FromSeconds(2); await extraCore.Stop(); var blocked = false;
                try { await web.GetStringAsync("http://127.0.0.3:" + exceptionOrigin.Port, ct); } catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { blocked = true; }
                Check(blocked && await web.GetStringAsync("http://127.0.0.1:" + origin.Port, ct) == "127.0.0.5", variant + " failed exception fell back to the live default");
                await using var restoredExtra = await Policy28Core.Start(assets.ResolveCore("sing-box"), extraConfig, directory, false, extraPort, false, ct); children.Add(new TestProcessIdentity(restoredExtra.Process));
                await server.DisposeAsync(); var updated = policy.DeepClone().AsArray(); foreach (var rule in updated.OfType<JsonObject>().Where(r=>r.ContainsKey("Target"))) { rule["Action"] = "Direct"; rule.Remove("Target"); } InboundRoutingPolicy.Set(inbound, LoopbackRuleSets(updated, 2, InboundCatalog.Id)); server = await Policy28Core.Start(isXray ? xray! : assets.ResolveCore("sing-box"), Render(), directory, isXray, inbound.Number("Listener.Port"), udp, ct); children.Add(new TestProcessIdentity(server.Process));
                await using (var after = await Round15Client.Start("mihomo", assets.ResolveCore("mihomo"), node, cert, directory, ct)) { children.Add(new TestProcessIdentity(after.Process)); using var http = TuicHttp(after.Port, cert); Check(await http.GetStringAsync("http://127.0.0.3:" + exceptionOrigin.Port, ct) == "127.0.0.1", variant + " updated category did not use explicit server direct"); }
                await server.DisposeAsync(); InboundRoutingPolicy.Set(inbound, LoopbackRuleSets(policy, 1, InboundCatalog.Id)); server = await Policy28Core.Start(isXray ? xray! : assets.ResolveCore("sing-box"), Render(), directory, isXray, inbound.Number("Listener.Port"), udp, ct); children.Add(new TestProcessIdentity(server.Process));
                await using (var restored = await Round15Client.Start("mihomo", assets.ResolveCore("mihomo"), node, cert, directory, ct)) { children.Add(new TestProcessIdentity(restored.Process)); using var http = TuicHttp(restored.Port, cert); Check(await http.GetStringAsync("http://127.0.0.3:" + exceptionOrigin.Port, ct) == "127.0.0.6", variant + " old category restore lost its target"); }
                Console.WriteLine("Round28: " + variant + " dual-client distinct exits, TCP reject, UDP default, failure and category restore passed.");
            }
            finally { await server.DisposeAsync(); secrets.Clear(); }
        }
        await camouflage.DisposeAsync();
        Check(children.All(identity => identity.Exited), "round28 left an owned core running");
        if (Environment.GetEnvironmentVariable("MAY_R28_EVIDENCE") is {} evidence) ArchiveStore.WriteJson(Path.GetFullPath(evidence), new JsonObject { ["SyntheticOnly"] = true, ["Cases"] = cases, ["OwnedCoresStopped"] = true });
    }
    private sealed class Policy28Core(Process process, Task<string> output, Task<string> error) : IAsyncDisposable
    {
        private bool disposed;
        public Process Process => process;
        public async Task Stop() { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
        private async Task<string> Detail() { var detail = await output + await error; return detail[^Math.Min(1600, detail.Length)..]; }
        public static async Task<Policy28Core> Start(string binary, JsonObject config, string directory, bool xray, int port, bool udp, CancellationToken ct)
        {
            var filename = SafePath.Resolve(directory, "core-" + Guid.NewGuid().ToString("N") + ".private.json"); ArchiveStore.WriteJson(filename, config); var result = await new ExternalToolRunner().RunAsync(binary, xray ? ["run", "-test", "-config", filename] : ["check", "-c", filename], null, TimeSpan.FromSeconds(15), ct); result.RequireSuccess("Round28 generated config rejected: " + result.Error);
            var start = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var argument in new[] { "run", xray ? "-config" : "-c", filename }) start.ArgumentList.Add(argument); var child = Process.Start(start)!; var running = new Policy28Core(child, child.StandardOutput.ReadToEndAsync(), child.StandardError.ReadToEndAsync());
            try
            {
                var watch = Stopwatch.StartNew(); while (!child.HasExited && watch.Elapsed < TimeSpan.FromSeconds(8)) { ct.ThrowIfCancellationRequested(); if (udp ? IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Any(e => e.Port == port && e.Address.Equals(IPAddress.Loopback)) : IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(e => e.Port == port && e.Address.Equals(IPAddress.Loopback))) return running; await Task.Delay(30, ct); }
                await running.Stop(); throw new OperationException("Round28 owned core did not become ready: " + await running.Detail());
            }
            catch { await running.DisposeAsync(); throw; }
        }
        public async ValueTask DisposeAsync() { if (disposed) return; disposed = true; await Stop(); await Task.WhenAll(output, error); process.Dispose(); }
    }
    private sealed class Policy28HttpTarget : IAsyncDisposable
    {
        private readonly TcpListener listener; private readonly CancellationTokenSource stop; private readonly Task server; public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
        public Policy28HttpTarget(CancellationToken ct, IPAddress? address = null)
        {
            listener = new(address ?? IPAddress.Loopback, 0); stop = CancellationTokenSource.CreateLinkedTokenSource(ct); listener.Start(); server = Task.Run(async () =>
            {
                try { while (!stop.IsCancellationRequested) { using var socket = await listener.AcceptTcpClientAsync(stop.Token); using var stream = socket.GetStream(); using var reader = new StreamReader(stream, leaveOpen:true); while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 }) { } var body = ((IPEndPoint)socket.Client.RemoteEndPoint!).Address.ToString(); await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: " + body.Length + "\r\nConnection: close\r\n\r\n" + body), stop.Token); } }
                catch (Exception e) when (e is OperationCanceledException or SocketException or IOException or ObjectDisposedException) { }
            });
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await server; stop.Dispose(); }
    }
}
