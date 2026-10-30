using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task ClientStreamRuntime()
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: external transport dual Windows cores; model and builder run cross-platform."); return; }
        var xray = Environment.GetEnvironmentVariable("MAY_TEST_XRAY");
        if (string.IsNullOrEmpty(xray)) { Console.WriteLine("SKIP: set MAY_TEST_XRAY to the fixed Xray 26.3.27 asset for external WS/gRPC real runtime."); return; }
        using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(4)); var ct = budget.Token; using var f = new Fixture(repository);
        var directory = f.Paths.Resolve("private/client-stream-runtime"); Directory.CreateDirectory(directory); var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64");
        var version = await new ExternalToolRunner().RunAsync(xray, ["version"], null, TimeSpan.FromSeconds(10), ct); Check(version.ExitCode == 0 && version.Output.Contains("26.3.27"), "external transport fixture used another Xray version");
        using var key = RSA.Create(2048); var request = new CertificateRequest("CN=stream.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("stream.example.test"); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build()); request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        await using var origin = await HysteriaHttpsTarget.Start(repository, f, cert, key, ct); await using var dns = new TuicDnsTarget(); var processes = new List<int>(); var cases = new JsonArray();
        foreach (var (protocol, transport, early) in new[] { ("vless", "ws", false), ("trojan", "ws", false), ("vless", "ws", true), ("trojan", "ws", true), ("vless", "grpc", false), ("trojan", "grpc", false) })
        {
            var port = TcpPort(); var scheme = ClientSchemes.New(f.Paths); var region = scheme["Layout"]!.Strings("region_groups")[0];
            // WebSocket TLS is terminated by our finite recording gate; it
            // records the actual on-wire path/Host before handing bytes to Xray.
            await using var gate = transport == "ws" ? new StreamWsGate(port, cert) : null;
            if (gate?.Port == port) throw new Exception("Synthetic WebSocket gate reused its upstream port.");
            var endpoint = gate?.Port ?? port; var link = StreamLink(protocol, transport, "127.0.0.1", endpoint, early: early);
            ClientNodeImport.Apply(scheme, ClientNodeImport.Preview(link, scheme, region)); var node = scheme["Nodes"]![0]!.AsObject();
            var stream = new JsonObject { ["network"] = transport, ["security"] = transport == "ws" ? "none" : "tls" };
            if (transport == "ws") stream["wsSettings"] = new JsonObject { ["path"] = Uri.UnescapeDataString(node.Text("sing_box.transport.path").Split('?')[0]), ["host"] = "front.example.test" };
            else { stream["grpcSettings"] = new JsonObject { ["serviceName"] = node.Text("sing_box.transport.service_name"), ["multiMode"] = false }; stream["tlsSettings"] = new JsonObject { ["alpn"] = new JsonArray("h2"), ["certificates"] = new JsonArray(new JsonObject { ["certificate"] = Lines(cert.ExportCertificatePem()), ["key"] = Lines(key.ExportPkcs8PrivateKeyPem()) }) }; }
            var settings = protocol == "vless" ? new JsonObject { ["decryption"] = "none", ["clients"] = new JsonArray(new JsonObject { ["id"] = StreamUuid }) } : new JsonObject { ["clients"] = new JsonArray(new JsonObject { ["password"] = node.Text("sing_box.password") }) };
            var server = new JsonObject { ["log"] = new JsonObject { ["loglevel"] = "error" }, ["inbounds"] = new JsonArray(new JsonObject { ["listen"] = "127.0.0.1", ["port"] = port, ["protocol"] = protocol, ["settings"] = settings, ["streamSettings"] = stream }), ["outbounds"] = new JsonArray(new JsonObject { ["protocol"] = "freedom", ["tag"] = "local-test-targets" }) };
            await using var running = await ServerQuicProcess.Start(xray, server, directory, true, port, ct); processes.Add(running.Process.Id);
            foreach (var clientName in new[] { "sing-box", "mihomo" })
            {
                var candidate = node.DeepClone().AsObject();
                // Exercise both native configs emitted by a URI, including an
                // explicit verified fingerprint/ALPN on selected cases.
                if (!early) { candidate["sing_box"]!["tls"]!["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = "firefox" }; candidate["clash"]!["client-fingerprint"] = "firefox"; candidate["sing_box"]!["tls"]!["alpn"] = new JsonArray(transport == "ws" ? "http/1.1" : "h2"); candidate["clash"]!["alpn"] = new JsonArray(transport == "ws" ? "http/1.1" : "h2"); }
                await using (var client = await Round15Client.Start(clientName, assets.ResolveCore(clientName), candidate, cert, directory, ct))
                {
                    processes.Add(client.Process.Id); using var http = TuicHttp(client.Port, cert); var before = origin.Requests;
                    try { Check(await http.GetStringAsync("https://127.0.0.1:" + origin.Port, ct) == "198.51.100.22" && origin.Requests > before, clientName + " failed authenticated " + protocol + "/" + transport + (early ? " early data" : "")); }
                    catch (HttpRequestException) { Console.WriteLine("Round 18 synthetic client diagnostic: " + await client.StopAndRead() + "\nServer: " + await running.StopAndRead() + "\nGate: " + gate?.LastError + " Path: " + gate?.LastPath); throw; }
                    Check((await ClientProxyUdp.ProbeAsync(client.Port, new(IPAddress.Loopback, dns.Port), ct)).Flag("ResponseMatched"), clientName + " did not carry real UDP via " + protocol + "/" + transport);
                    if (gate != null) Check(gate.LastPath == node.Text("sing_box.transport.path") && gate.LastHost == "front.example.test" && gate.LastSni == "stream.example.test" && (!early || gate.EarlyHeaders > 0), clientName + " changed on-wire WebSocket path/Host/SNI/early-data header");
                }
                if (!early)
                {
                    foreach (var failure in transport == "ws" ? new[] { "auth", "sni", "transport", "host" } : new[] { "auth", "sni", "transport" })
                    {
                        var bad = node.DeepClone().AsObject();
                        if (failure == "auth") { bad["sing_box"]![protocol == "vless" ? "uuid" : "password"] = protocol == "vless" ? Guid.NewGuid().ToString() : "wrong-synthetic-password"; bad["clash"]![protocol == "vless" ? "uuid" : "password"] = bad["sing_box"]![protocol == "vless" ? "uuid" : "password"]!.DeepClone(); }
                        else if (failure == "sni") { bad["sing_box"]!["tls"]!["server_name"] = "wrong.example.test"; bad["clash"]![protocol == "vless" ? "servername" : "sni"] = "wrong.example.test"; }
                        else if (failure == "host") { bad["sing_box"]!["transport"]!["headers"]!["Host"] = "wrong.example.test"; bad["clash"]!["ws-opts"]!["headers"]!["Host"] = "wrong.example.test"; }
                        else if (transport == "ws") { bad["sing_box"]!["transport"]!["path"] = "/wrong-path"; bad["clash"]!["ws-opts"]!["path"] = "/wrong-path"; }
                        else { bad["sing_box"]!["transport"]!["service_name"] = "WrongService"; bad["clash"]!["grpc-opts"]!["grpc-service-name"] = "WrongService"; }
                        await using var client = await Round15Client.Start(clientName, assets.ResolveCore(clientName), bad, cert, directory, ct); processes.Add(client.Process.Id); using var http = TuicHttp(client.Port, cert); http.Timeout = TimeSpan.FromSeconds(2); var count = origin.Requests; var refused = false;
                        try { await http.GetStringAsync("https://127.0.0.1:" + origin.Port, ct); } catch (Exception e) when (e is HttpRequestException or OperationCanceledException) { refused = true; }
                        Check(refused && origin.Requests == count, clientName + " bypassed " + protocol + "/" + transport + " failure " + failure);
                    }
                }
                cases.Add(new JsonObject { ["Protocol"] = protocol, ["Transport"] = transport, ["EarlyData"] = early, ["Client"] = clientName, ["Https"] = true, ["ApplicationUdp"] = true });
            }
            Console.WriteLine("Round 18 native: " + protocol + "/" + transport + (early ? " early-data" : "") + " dual clients authenticated HTTPS/UDP passed.");
        }
        Check(processes.All(id => { try { using var process = Process.GetProcessById(id); return process.HasExited; } catch (ArgumentException) { return true; } }), "round 18 left owned protocol cores running");
        if (Environment.GetEnvironmentVariable("MAY_R18_EVIDENCE") is {} evidence) ArchiveStore.WriteJson(Path.GetFullPath(evidence), new JsonObject { ["SyntheticOnly"] = true, ["Xray"] = "26.3.27", ["Cases"] = cases, ["OwnedCoresStopped"] = true });
        static JsonArray Lines(string pem) => new(pem.Trim().Split('\n').Select(l => (JsonNode?)JsonValue.Create(l.TrimEnd('\r'))).ToArray());
    }
    private sealed class StreamWsGate : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0); private readonly CancellationTokenSource stop = new(); private readonly Task worker; private readonly List<Task> connections = []; private readonly int upstream; private readonly X509Certificate2 certificate;
        public int Port { get; } public string LastPath = "", LastHost = "", LastSni = "", LastError = ""; public int EarlyHeaders;
        public StreamWsGate(int upstream, X509Certificate2 certificate)
        {
            this.upstream = upstream;
            // Schannel cannot serve a TLS connection with CreateSelfSigned's
            // ephemeral key handle. Import a disposable PFX (no PersistKeySet,
            // no certificate store or global trust changes); dispose its key.
            this.certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
            listener.Start(); Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            worker = Task.Run(async () => { try { while (!stop.IsCancellationRequested) { var client = await listener.AcceptTcpClientAsync(stop.Token); connections.Add(Serve(client)); } } catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { } });
        }
        private async Task Serve(TcpClient client)
        {
            using (client) using (var tls = new SslStream(client.GetStream()))
            {
                try
                {
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13, ApplicationProtocols = [SslApplicationProtocol.Http11], ServerCertificateSelectionCallback = (_, sni) => { LastSni = sni ?? ""; return certificate; } }, stop.Token);
                    var bytes = new List<byte>(); var one = new byte[1];
                    while (bytes.Count < 16384) { if (await tls.ReadAsync(one, stop.Token) == 0) return; bytes.Add(one[0]); if (bytes.Count >= 4 && bytes[^4] == 13 && bytes[^3] == 10 && bytes[^2] == 13 && bytes[^1] == 10) break; }
                    var header = Encoding.ASCII.GetString(bytes.ToArray()); var rows = header.Split("\r\n"); LastPath = rows[0].Split(' ')[1]; LastHost = rows.FirstOrDefault(r => r.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))?[5..].Trim() ?? "";
                    if (rows.Any(r => r.StartsWith("Sec-WebSocket-Protocol:", StringComparison.OrdinalIgnoreCase))) Interlocked.Increment(ref EarlyHeaders);
                    using var backend = new TcpClient(); await backend.ConnectAsync(IPAddress.Loopback, upstream, stop.Token); using var back = backend.GetStream(); await back.WriteAsync(bytes.ToArray(), stop.Token);
                    using var done = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); var upload = tls.CopyToAsync(back, done.Token); var download = back.CopyToAsync(tls, done.Token); await Task.WhenAny(upload, download); done.Cancel(); try { await Task.WhenAll(upload, download); } catch (Exception e) when (e is IOException or OperationCanceledException) { }
                }
                catch (Exception e) when (e is IOException or SocketException or AuthenticationException or OperationCanceledException or ObjectDisposedException) { LastError = e.Message; }
            }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await worker; await Task.WhenAll(connections); certificate.Dispose(); stop.Dispose(); }
    }
}
