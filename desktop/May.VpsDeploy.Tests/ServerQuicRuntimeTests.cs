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
    private async Task ServerQuicRuntime()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") == null) { Console.WriteLine("SKIP: round 17 native fixtures require Windows and MAY_TEST_PYTHON."); return; }
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(7)); var ct = budget.Token;
        var directory = f.Paths.Resolve("private/server-quic-runtime"); Directory.CreateDirectory(directory); var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner();
        using var key = RSA.Create(2048); var csr = new CertificateRequest("CN=next.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("next.example.test"); san.AddIpAddress(IPAddress.Loopback); csr.CertificateExtensions.Add(san.Build()); csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); using var certificate = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        await using var origin = await HysteriaHttpsTarget.Start(repository, f, certificate, key, ct); await using var dns = new TuicDnsTarget();
        var measurements = new JsonArray(); var processes = new List<int>();
        foreach (var scenario in new[] { "hysteria2", "hysteria2-advanced", "tuic-native", "tuic-quic" })
        {
            var protocol = scenario.StartsWith("hysteria2", StringComparison.Ordinal) ? "Hysteria2" : "TuicV5"; var advanced = scenario == "hysteria2-advanced";
            var plan = f.Plan("Server-" + scenario); var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials(); var landing = InboundCatalog.AddInbound(model, secrets, protocol); landing["Listener"]!["Port"] = UdpPort(); landing["Options"]!["ServerName"] = "next.example.test";
            var cert = InboundCatalog.ImportCertificate(model, secrets, "Synthetic TLS", certificate.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()); landing["CertificateId"] = cert.Text("Id");
            if (protocol == "TuicV5") landing["Options"]!["UdpRelayMode"] = scenario == "tuic-quic" ? "quic" : "native";
            if (advanced) { landing["Options"]!["ObfsEnabled"] = true; landing["Options"]!["UploadMbps"] = 20; landing["Options"]!["DownloadMbps"] = 40; }
            var landingConfig = InboundRendering.Configuration(f.Store, plan, model, secrets, landing); landingConfig["inbounds"]![0]!["listen"] = "127.0.0.1";
            await using var server = await HysteriaCore.Start(assets.ResolveCore("sing-box"), tools, landingConfig, directory, "landing-" + scenario, ct); processes.Add(server.Process.Id);
            await using var relay = new HysteriaUdpRelay(landing.Number("Listener.Port"));
            var node = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).First(); node.Remove("InboundOrigin"); node["sing_box"]!["server"] = "192.0.2.20"; node["sing_box"]!["server_port"] = relay.Port; node["sing_box"]!["tls"]!["certificate"] = new JsonArray(certificate.ExportCertificatePem());
            if (advanced) { node["sing_box"]!["server_ports"] = new JsonArray(relay.Port.ToString()); node["sing_box"]!["hop_interval"] = "5s"; }
            var scheme = ClientSchemes.New(f.Paths); scheme["Nodes"] = new JsonArray(node.DeepClone()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            var entryModel = InboundCatalog.Empty(); var entrySecrets = InboundCatalog.EmptyCredentials(); var entry = InboundCatalog.AddInbound(entryModel, entrySecrets, "AnyTLS"); var entryCert = InboundCatalog.ImportCertificate(entryModel, entrySecrets, "Synthetic TLS", certificate.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()); entry["CertificateId"] = entryCert.Text("Id"); entry["Options"]!["ServerName"] = "next.example.test"; entry["Listener"]!["Port"] = TcpPort();
            var outbound = InboundCatalog.Items(entryModel, "Outbounds").Single(); outbound["Kind"] = "Proxy"; outbound["ExpectedAddress"] = "198.51.100.22"; outbound["Source"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["Fingerprint"] = ArchiveStore.Fingerprint(node) };
            var rendered = InboundRendering.Configuration(f.Store, plan, entryModel, entrySecrets, entry); rendered["inbounds"]![0]!["listen"] = "127.0.0.1"; rendered["outbounds"]![0]!["server"] = "127.0.0.1";
            var entryNode = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, entryModel, entrySecrets).First(); entryNode["sing_box"]!["server"] = "127.0.0.1"; entryNode["clash"]!["server"] = "127.0.0.1";
            var target = "https://127.0.0.1:" + origin.Port;
            await using (var running = await ServerQuicProcess.Start(assets.ResolveCore("sing-box"), rendered, directory, false, entry.Number("Listener.Port"), ct))
            {
                processes.Add(running.Process.Id);
                foreach (var clientName in new[] { "sing-box", "mihomo" })
                {
                    await using var client = await Round15Client.Start(clientName, assets.ResolveCore(clientName), entryNode, certificate, directory, ct); processes.Add(client.Process.Id); using var http = TuicHttp(client.Port, certificate);
                    var datagrams = relay.Forwarded; var queries = dns.Packets;
                    Check(await http.GetStringAsync(target, ct) == "198.51.100.22" && (await ClientProxyUdp.ProbeAsync(client.Port, new(IPAddress.Loopback, dns.Port), ct)).Flag("ResponseMatched") && relay.Forwarded > datagrams && dns.Packets > queries, clientName + " did not traverse AnyTLS -> " + scenario + " for HTTPS and application UDP");
                    if (clientName == "sing-box")
                    {
                        var clock = Stopwatch.StartNew(); var cpu = running.Process.TotalProcessorTime; var samples = new List<double>();
                        for (var n = 0; n < 6; n++) { Check(await http.GetStringAsync(target, ct) == "198.51.100.22", "QUIC server stream interrupted"); await Task.Delay(250, ct); running.Process.Refresh(); samples.Add(running.Process.WorkingSet64 / 1048576d); }
                        measurements.Add(new JsonObject { ["Scenario"] = scenario, ["Seconds"] = clock.Elapsed.TotalSeconds, ["EntryRssMedianMiB"] = samples.Order().ElementAt(samples.Count / 2), ["EntryRssPeakMiB"] = samples.Max(), ["EntryCpuPercentOneCore"] = (running.Process.TotalProcessorTime - cpu).TotalSeconds / clock.Elapsed.TotalSeconds * 100 });
                        relay.Drop = true; var before = origin.Requests; var failed = false;
                        try { using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(2)); await http.GetStringAsync(target, timeout.Token); } catch (Exception error) when (error is HttpRequestException or OperationCanceledException) { failed = true; }
                        finally { relay.Drop = false; }
                        Check(failed && origin.Requests == before && await http.GetStringAsync(target, ct) == "198.51.100.22", "Broken server QUIC transport fell back or failed to recover");
                    }
                }
                var diagnosticNode = entryNode.DeepClone().AsObject(); diagnosticNode["sing_box"]!["tls"]!["certificate"] = new JsonArray(certificate.ExportCertificatePem()); var diagnosticScheme = new JsonObject { ["Nodes"] = new JsonArray(diagnosticNode), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray(diagnosticNode.Text("region_group")) } }; var diagnosticRoute = ClientTopology.DiagnosticRoute(diagnosticScheme, diagnosticNode.Text("name")) with { RequiresApplicationUdp = true }; var endpoints = new ClientDiagnosticEndpoints(new(target), new(target), new(target)) { Udp4 = new(IPAddress.Loopback, dns.Port) }; var diagnostics = new ClientRouteDiagnostics(assets, tools, endpoints, certificate);
                var proof = await diagnostics.RunAsync(diagnosticRoute, directory, new InlineProgress<string>(_ => { }), ct); Check(proof.Text("Status") == "Reachable" && proof.Flag("UdpValidation.ResponseMatched"), "Production diagnostic omitted server next-hop UDP");
                if (scenario == "hysteria2")
                {
                    dns.Invalid = true;
                    try { proof = await diagnostics.RunAsync(diagnosticRoute, directory, new InlineProgress<string>(_ => { }), ct); Check(proof.Text("Status") != "Reachable" && proof["Stages"]!.AsArray().Any(s => s!.Text("Id") == "EntryHttps" && s.Text("Status") == "Passed") && !proof.Flag("UdpValidation.ResponseMatched"), "HTTPS-only chain falsely passed production UDP acceptance"); }
                    finally { dns.Invalid = false; }
                }
            }
            if (protocol == "Hysteria2" && Environment.GetEnvironmentVariable("MAY_TEST_XRAY") is {} xray)
            {
                var converted = ServerOutboundRouting.XrayNextHop(node["sing_box"]!.AsObject()); converted["settings"]!["address"] = "127.0.0.1"; var mixed = TcpPort();
                var config = new JsonObject { ["log"] = new JsonObject { ["loglevel"] = "warning" }, ["inbounds"] = new JsonArray(new JsonObject { ["listen"] = "127.0.0.1", ["port"] = mixed, ["protocol"] = "socks", ["settings"] = new JsonObject { ["auth"] = "noauth", ["udp"] = true } }), ["outbounds"] = new JsonArray(converted) };
                await using var running = await ServerQuicProcess.Start(xray, config, directory, true, mixed, ct); processes.Add(running.Process.Id); using var http = TuicHttp(mixed, certificate);
                Check(await http.GetStringAsync(target, ct) == "198.51.100.22" && (await ClientProxyUdp.ProbeAsync(mixed, new(IPAddress.Loopback, dns.Port), ct)).Flag("ResponseMatched"), "Fixed Xray -> " + scenario + " did not carry HTTPS/application UDP");
            }
            await ServerQuicRemoteProbe(node, certificate, origin.Port, assets, directory, processes, ct);
            Console.WriteLine("Round 17 native: AnyTLS -> " + scenario + ", dual clients, HTTPS/UDP, interruption/recovery passed."); secrets.Clear(); entrySecrets.Clear();
        }
        Check(processes.All(id => { try { using var process = Process.GetProcessById(id); return process.HasExited; } catch (ArgumentException) { return true; } }), "Round 17 left an owned core running");
        if (Environment.GetEnvironmentVariable("MAY_R17_EVIDENCE") is {} output) ArchiveStore.WriteJson(Path.GetFullPath(output), new JsonObject { ["SyntheticOnly"] = true, ["Scope"] = "Short loopback request workload; not a performance comparison or long-run measurement", ["Measurements"] = measurements, ["CoresStopped"] = true });
    }
    private async Task ServerQuicRemoteProbe(JsonObject node, X509Certificate2 certificate, int targetPort, ValidationAssets assets, string directory, List<int> processes, CancellationToken ct)
    {
        var asset = File.ReadAllText(Path.Combine(repository, "assets/remote/server-hop-probe.sh")).Replace("\r\n", "\n"); var script = asset.Split("<<'PY'\n", StringSplitOptions.None)[1]; script = script[..script.LastIndexOf("\nPY", StringComparison.Ordinal)]; script = script.Replace("PROBE_HOST_V4 = 'api.ipify.org'", "PROBE_HOST_V4 = '127.0.0.1'").Replace("PROBE_PORT = 443", "PROBE_PORT = " + targetPort);
        foreach (var role in ServerOutboundRouting.Roles.Where(r => ServerOutboundRouting.SupportedNode(node, r)))
        {
            var binary = role == "RealityEntry" ? Environment.GetEnvironmentVariable("MAY_TEST_XRAY") : assets.ResolveCore("sing-box"); if (binary == null) continue;
            var work = SafePath.Resolve(directory, "probe-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work); var file = SafePath.Resolve(work, "probe.py"); var pem = SafePath.Resolve(work, "trust.pem"); File.WriteAllText(file, script); File.WriteAllText(pem, certificate.ExportCertificatePem());
            var native = ServerOutboundRouting.NextHop(node); var outbound = role == "RealityEntry" ? ServerOutboundRouting.XrayNextHop(native) : native; outbound["tag"] = ServerOutboundRouting.HopTag(HopA); if (role == "RealityEntry") outbound["settings"]!["address"] = "127.0.0.1"; else outbound["server"] = "127.0.0.1";
            var items = new JsonArray(new JsonObject { ["Id"] = HopA, ["ExpectedAddress"] = "198.51.100.22", ["Outbound"] = outbound });
            var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("MAY_TEST_PYTHON")!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var argument in new[] { file, binary, role }) start.ArgumentList.Add(argument); start.Environment["SSL_CERT_FILE"] = pem; start.Environment["VPS_PARAM_PROBES_JSON"] = items.ToJsonString(); start.Environment["TMPDIR"] = work; start.Environment["TEMP"] = work; start.Environment["TMP"] = work;
            using var process = Process.Start(start)!; processes.Add(process.Id); var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            try { await process.WaitForExitAsync(ct); var output = await stdout; var error = await stderr; Check(process.ExitCode == 0 && !output.Contains(node.Text("sing_box.password")) && !error.Contains(node.Text("sing_box.password")), "Remote next-hop probe rejected " + role + " / " + node.Text("sing_box.type") + ": " + error); var result = JsonNode.Parse(RemoteAssets.Marker(output, "HOP_VALIDATION"))!.AsObject(); ServerOutboundRouting.RequireHopValidation(items, result); Check(Directory.GetDirectories(work, "may-hop-probe-*").Length == 0, "Remote QUIC probe left temporary credentials"); }
            finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } }
        }
    }
    private sealed class ServerQuicProcess(Process process, Task<string> output, Task<string> error) : IAsyncDisposable
    {
        private bool disposed; public Process Process => process;
        private Task<string> Error => error;
        private Task<string> Output => output;
        public async Task<string> StopAndRead() { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(); var detail = await output + "\n" + await error; return detail[^Math.Min(2200, detail.Length)..]; }
        public static async Task<ServerQuicProcess> Start(string binary, JsonObject config, string directory, bool xray, int port, CancellationToken ct)
        {
            var file = SafePath.Resolve(directory, "core-" + Guid.NewGuid().ToString("N") + ".private.json"); ArchiveStore.WriteJson(file, config); var tools = new ExternalToolRunner();
            var check = await tools.RunAsync(binary, xray ? ["run", "-test", "-config", file] : ["check", "-c", file], null, TimeSpan.FromSeconds(15), ct);
            if (check.ExitCode != 0) throw new Exception("Round 17 synthetic core validation: " + check.Error + check.Output);
            var start = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var argument in new[] { "run", xray ? "-config" : "-c", file }) start.ArgumentList.Add(argument);
            var process = Process.Start(start)!; var result = new ServerQuicProcess(process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync());
            string socketFailure = ""; try { for (var n = 0; n < 80 && !process.HasExited; n++) { try { using var socket = new TcpClient(); await socket.ConnectAsync(IPAddress.Loopback, port, ct); return result; } catch (SocketException failure) { socketFailure = failure.SocketErrorCode.ToString(); await Task.Delay(50, ct); } } if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(ct); var detail = await result.Output + "\n" + await result.Error; throw new Exception("Synthetic core did not start on " + port + " (" + socketFailure + "): " + detail[^Math.Min(2400, detail.Length)..]); }
            catch { await result.DisposeAsync(); throw; }
        }
        public async ValueTask DisposeAsync() { if (disposed) return; disposed = true; if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); await Task.WhenAll(output, error); process.Dispose(); }
    }
}
