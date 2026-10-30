using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task TuicRuntime()
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: native dual-client TUIC fixture is Windows-only; Debian lifecycle is separate."); return; }
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(7)); var ct = budget.Token;
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner();
        using var key = RSA.Create(2048); var request = new CertificateRequest("CN=tuic.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("tuic.example.test"); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build()); request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        using var unrelatedKey = RSA.Create(2048); var unrelatedRequest = new CertificateRequest("CN=unrelated.example.test", unrelatedKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); unrelatedRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); using var unrelatedCa = unrelatedRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        await using var origin = await HysteriaHttpsTarget.Start(repository, f, ca, key, ct); await using var dns = new TuicDnsTarget();
        var plan = f.Plan("Tuic-runtime"); f.SaveInstance(plan); var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, credentials, "TuicV5"); var certificate = InboundCatalog.ImportCertificate(model, credentials, "TLS", ca.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()); inbound["CertificateId"] = certificate.Text("Id"); inbound["Options"]!["ServerName"] = "tuic.example.test"; inbound["Listener"]!["Port"] = UdpPort();
        var second = InboundCatalog.AddUser(model, credentials, "Second", "TuicV5"); inbound["UserIds"]!.AsArray().Add(second.Text("Id")); var directory = f.Paths.Resolve("private/tuic-runtime"); Directory.CreateDirectory(directory); var measurements = new JsonArray(); var processes = new List<int>();
        foreach (var congestion in new[] { "cubic", "new_reno", "bbr" })
        {
            inbound["Options"]!["CongestionControl"] = congestion; var config = InboundRendering.Configuration(f.Store, plan, model, credentials, inbound); config["inbounds"]![0]!["listen"] = "127.0.0.1";
            await using var server = await HysteriaCore.Start(assets.ResolveCore("sing-box"), tools, config, directory, "server-" + congestion, ct); processes.Add(server.Process.Id);
            await using var relay = new HysteriaUdpRelay(inbound.Number("Listener.Port"));
            foreach (var mode in new[] { "native", "quic" })
            {
                inbound["Options"]!["UdpRelayMode"] = mode;
                var nodes = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, credentials).ToArray();
                foreach (var core in new[] { "sing-box", "mihomo" })
                {
                    var node = nodes[0].DeepClone().AsObject(); node["sing_box"]!["server"] = "127.0.0.1"; node["clash"]!["server"] = "127.0.0.1"; node["sing_box"]!["server_port"] = relay.Port; node["clash"]!["port"] = relay.Port;
                    await using var client = await Round15Client.Start(core, assets.ResolveCore(core), node, ca, directory, ct); processes.Add(client.Process.Id);
                    using var http = TuicHttp(client.Port, ca); var target = "https://127.0.0.1:" + origin.Port; var before = dns.Packets;
                    Check(await http.GetStringAsync(target, ct) == "198.51.100.22", core + " TUIC HTTPS did not authenticate");
                    var udpResult = await ClientProxyUdp.ProbeAsync(client.Port, new(IPAddress.Loopback, dns.Port), ct);
                    Check(udpResult.Flag("ResponseMatched") && dns.Packets > before && relay.Forwarded > 0, core + " TUIC application UDP did not traverse the encrypted path");
                    if (congestion == "cubic")
                    {
                        var watch = Stopwatch.StartNew(); server.Process.Refresh(); client.Process.Refresh(); var serverCpu = server.Process.TotalProcessorTime; var clientCpu = client.Process.TotalProcessorTime; var samples = new List<(double Server, double Client)>();
                        using var response = await http.GetAsync(target + "/stream", HttpCompletionOption.ResponseHeadersRead, ct); response.EnsureSuccessStatusCode(); await using var stream = await response.Content.ReadAsStreamAsync(ct); var received = 0; var bytes = new byte[4096];
                        while (true) { var size = await stream.ReadAsync(bytes, ct); if (size == 0) break; received += size; server.Process.Refresh(); client.Process.Refresh(); if (watch.Elapsed.TotalSeconds >= 2) samples.Add((server.Process.WorkingSet64 / 1048576d, client.Process.WorkingSet64 / 1048576d)); }
                        Check(received == 18 * 4096, core + " TUIC continuous response failed");
                        static JsonObject Rss(IEnumerable<double> values) { var sorted = values.Order().ToArray(); return new() { ["MedianMiB"] = sorted[sorted.Length / 2], ["P95MiB"] = sorted[(int)Math.Ceiling(sorted.Length * .95) - 1], ["PeakMiB"] = sorted[^1] }; }
                        measurements.Add(new JsonObject { ["Core"] = core, ["Mode"] = mode, ["WallSeconds"] = watch.Elapsed.TotalSeconds, ["Samples"] = samples.Count, ["ServerRss"] = Rss(samples.Select(s => s.Server)), ["ClientRss"] = Rss(samples.Select(s => s.Client)), ["ServerCpuPercentOfOneCore"] = (server.Process.TotalProcessorTime - serverCpu).TotalSeconds / watch.Elapsed.TotalSeconds * 100, ["ClientCpuPercentOfOneCore"] = (client.Process.TotalProcessorTime - clientCpu).TotalSeconds / watch.Elapsed.TotalSeconds * 100 });
                        var oldRequests = origin.Requests; relay.Drop = true;
                        using (var decoy = new TcpListener(IPAddress.Loopback, relay.Port))
                        {
                            decoy.Start(); using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(2)); var blocked = false;
                            try { await http.GetStringAsync(target, timeout.Token); } catch (Exception error) when (error is HttpRequestException or OperationCanceledException) { blocked = true; }
                            Check(blocked && origin.Requests == oldRequests, "TUIC used TCP/direct fallback while transport UDP was blocked");
                        }
                        relay.Drop = false; Check(await http.GetStringAsync(target, ct) == "198.51.100.22", "TUIC did not recover after transport restoration");
                        dns.Invalid = true; using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
                        {
                            timeout.CancelAfter(TimeSpan.FromSeconds(2)); var refused = false; try { await ClientProxyUdp.ProbeAsync(client.Port, new(IPAddress.Loopback, dns.Port), timeout.Token); } catch (Exception error) when (error is OperationException or OperationCanceledException) { refused = true; }
                            Check(refused, "TUIC accepted mismatched DNS identities as UDP proof");
                        }
                        dns.Invalid = false;
                    }
                    Console.WriteLine("TUIC native: " + core + " / " + congestion + " / " + mode + " HTTPS + application UDP passed.");
                }
            }
            if (congestion != "cubic") continue;
            var variants = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, credentials).ToArray();
            foreach (var core in new[] { "sing-box", "mihomo" })
            foreach (var variant in new[] { "second", "uuid", "password", "sni", "trust" })
            {
                var node = variants[variant == "second" ? 1 : 0].DeepClone().AsObject(); node["sing_box"]!["server"] = "127.0.0.1"; node["clash"]!["server"] = "127.0.0.1"; node["sing_box"]!["server_port"] = relay.Port; node["clash"]!["port"] = relay.Port;
                if (variant == "uuid") { var wrong = Guid.NewGuid().ToString(); node["sing_box"]!["uuid"] = wrong; node["clash"]!["uuid"] = wrong; }
                if (variant == "password") { node["sing_box"]!["password"] = "wrong-synthetic-password"; node["clash"]!["password"] = "wrong-synthetic-password"; }
                if (variant == "sni") { node["sing_box"]!["tls"]!["server_name"] = "wrong.example.test"; node["clash"]!["sni"] = "wrong.example.test"; }
                await using var client = await Round15Client.Start(core, assets.ResolveCore(core), node, variant == "trust" ? unrelatedCa : ca, directory, ct); processes.Add(client.Process.Id); using var http = TuicHttp(client.Port, ca); var before = origin.Requests;
                if (variant == "second") Check(await http.GetStringAsync("https://127.0.0.1:" + origin.Port, ct) == "198.51.100.22" && (await ClientProxyUdp.ProbeAsync(client.Port, new(IPAddress.Loopback, dns.Port), ct)).Flag("ResponseMatched"), "Second TUIC user was not independently authenticated");
                else { var rejected = false; try { await http.GetStringAsync("https://127.0.0.1:" + origin.Port, ct); } catch (Exception error) when (error is HttpRequestException or OperationCanceledException) { rejected = true; } Check(rejected && origin.Requests == before, "TUIC accepted wrong " + variant); }
            }
        }
        Check(processes.All(id => { try { using var process = Process.GetProcessById(id); return process.HasExited; } catch (ArgumentException) { return true; } }), "TUIC fixture left its owned core running");
        if (Environment.GetEnvironmentVariable("MAY_R16_EVIDENCE") is {} path) ArchiveStore.WriteJson(Path.GetFullPath(path), new JsonObject { ["SyntheticOnly"] = true, ["Scope"] = "Windows loopback; cubic; same 18-chunk HTTPS workload; first two seconds excluded from RSS; short observation only", ["Measurements"] = measurements, ["CoresStopped"] = true }); credentials.Clear();
    }
    private static HttpClient TuicHttp(int port, X509Certificate2 ca) => new(new HttpClientHandler { Proxy = new WebProxy("http://127.0.0.1:" + port), UseProxy = true, ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert?.GetCertHashString() == ca.GetCertHashString() }) { Timeout = TimeSpan.FromSeconds(7) };
    private sealed class TuicDnsTarget : IAsyncDisposable
    {
        private readonly UdpClient socket = new(new IPEndPoint(IPAddress.Loopback, 0)); private readonly CancellationTokenSource stop = new(); private readonly Task worker; public int Packets; public volatile bool Invalid; public int Port => ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
        public TuicDnsTarget() { worker = Task.Run(async () => { try { while (!stop.IsCancellationRequested) { var packet = await socket.ReceiveAsync(stop.Token); Interlocked.Increment(ref Packets); var response = DnsAnswer(packet.Buffer); if (Invalid) response[0] ^= 1; await socket.SendAsync(response, packet.RemoteEndPoint, stop.Token); } } catch (Exception error) when (error is OperationCanceledException or SocketException or ObjectDisposedException) { } }); }
        public async ValueTask DisposeAsync() { stop.Cancel(); socket.Dispose(); await worker; stop.Dispose(); }
    }
}
