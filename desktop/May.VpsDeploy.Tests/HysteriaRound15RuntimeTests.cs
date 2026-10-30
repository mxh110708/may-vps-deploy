using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task HysteriaHoppingRuntime15()
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: dual Windows cores; Debian firewall/runtime is a separate disposable VM test."); return; }
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(5)); var ct = budget.Token;
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner();
        using var key = RSA.Create(2048); var csr = new CertificateRequest("CN=hysteria.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("hysteria.example.test"); san.AddIpAddress(IPAddress.Loopback); csr.CertificateExtensions.Add(san.Build()); csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        await using var origin = await HysteriaHttpsTarget.Start(repository, f, cert, key, ct);
        var plan = f.Plan("Hysteria15-native"); f.SaveInstance(plan); var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials();
        var inbound = InboundCatalog.AddInbound(model, secrets, "Hysteria2"); var resource = InboundCatalog.ImportCertificate(model, secrets, "TLS", cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
        inbound["CertificateId"] = resource.Text("Id"); inbound["Options"]!["ServerName"] = "hysteria.example.test"; inbound["Options"]!["ObfsEnabled"] = true; inbound["Listener"]!["Port"] = UdpPort();
        var config = InboundRendering.Configuration(f.Store, plan, model, secrets, inbound); config["inbounds"]![0]!["listen"] = "127.0.0.1";
        var directory = f.Paths.Resolve("private/hysteria15-runtime"); Directory.CreateDirectory(directory);
        await using var server = await HysteriaCore.Start(assets.ResolveCore("sing-box"), tools, config, directory, "server", ct);
        await using var first = new HysteriaUdpRelay(inbound.Number("Listener.Port")); await using var second = new HysteriaUdpRelay(inbound.Number("Listener.Port"));
        var node = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).Single(); node["sing_box"]!["server"] = "127.0.0.1"; node["clash"]!["server"] = "127.0.0.1"; node["sing_box"]!["server_port"] = first.Port; node["clash"]!["port"] = first.Port;
        var measurements = new JsonArray(); var owned = new List<int>();
        foreach (var coreName in new[] { "sing-box", "mihomo" }.Where(c => Environment.GetEnvironmentVariable("MAY_R15_CORE") is not {} selected || selected == c))
        {
            foreach (var hopping in new[] { false, true })
            {
                var candidate = node.DeepClone().AsObject();
                if (hopping) Hysteria2Ports.Apply(candidate["clash"]!.AsObject(), candidate["sing_box"]!.AsObject(), first.Port + "," + second.Port, 5);
                var beforeFirst = first.Forwarded; var beforeSecond = second.Forwarded;
                await using var client = await Round15Client.Start(coreName, assets.ResolveCore(coreName), candidate, cert, directory, ct); owned.Add(client.Process.Id);
                using var handler = new HttpClientHandler { Proxy = new WebProxy("http://127.0.0.1:" + client.Port), UseProxy = true, ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate?.GetCertHashString() == cert.GetCertHashString() };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
                var target = "https://127.0.0.1:" + origin.Port;
                try { Check(await http.GetStringAsync(target, ct) == "198.51.100.22", coreName + " did not authenticate over real Hysteria2"); }
                catch (HttpRequestException) { Console.WriteLine("Round 15 core diagnostic: " + await client.StopAndRead()); throw; }
                await Task.Delay(1200, ct); server.Process.Refresh(); client.Process.Refresh(); var watch = Stopwatch.StartNew(); var cpuServer = server.Process.TotalProcessorTime; var cpuClient = client.Process.TotalProcessorTime;
                var samples = new List<(double Server, double Client)>();
                // A hop may randomly choose the same port again. Keep a
                // continuous stream for several intervals and, if necessary,
                // another bounded stream before judging observed migration.
                for (var attempt = 0; attempt < (hopping ? 4 : 1); attempt++)
                {
                    using var response = await http.GetAsync(target + "/stream", HttpCompletionOption.ResponseHeadersRead, ct); response.EnsureSuccessStatusCode();
                    await using var stream = await response.Content.ReadAsStreamAsync(ct); var buffer = new byte[4096]; var received = 0;
                    while (true)
                    {
                        var read = await stream.ReadAsync(buffer, ct); if (read == 0) break; received += read;
                        server.Process.Refresh(); client.Process.Refresh(); if (watch.Elapsed.TotalSeconds >= 2) samples.Add((server.Process.WorkingSet64 / 1048576d, client.Process.WorkingSet64 / 1048576d));
                    }
                    Check(received == 18 * 4096, coreName + " long HTTPS stream was interrupted during hopping");
                    if (!hopping || first.Forwarded > beforeFirst && second.Forwarded > beforeSecond) break;
                }
                if (hopping) Check(first.Forwarded > beforeFirst && second.Forwarded > beforeSecond, coreName + " stream did not traverse both hopping ports");
                static JsonObject Memory(IEnumerable<double> values)
                {
                    var ordered = values.Order().ToArray(); return new JsonObject { ["MedianMiB"] = ordered[ordered.Length / 2], ["P95MiB"] = ordered[(int)Math.Ceiling(ordered.Length * .95) - 1], ["PeakMiB"] = ordered[^1] };
                }
                measurements.Add(new JsonObject { ["Core"] = coreName, ["Hopping"] = hopping, ["WallSeconds"] = watch.Elapsed.TotalSeconds, ["Samples"] = samples.Count, ["ServerRss"] = Memory(samples.Select(s => s.Server)), ["ClientRss"] = Memory(samples.Select(s => s.Client)), ["ServerCpuPercentOfOneCore"] = (server.Process.TotalProcessorTime - cpuServer).TotalSeconds / watch.Elapsed.TotalSeconds * 100, ["ClientCpuPercentOfOneCore"] = (client.Process.TotalProcessorTime - cpuClient).TotalSeconds / watch.Elapsed.TotalSeconds * 100 });
                if (hopping)
                {
                    var requests = origin.Requests; first.Drop = second.Drop = true;
                    using var decoy = new TcpListener(IPAddress.Loopback, first.Port); decoy.Start();
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(3));
                    var blocked = false; try { await http.GetStringAsync(target, timeout.Token); } catch (Exception e) when (e is HttpRequestException or OperationCanceledException) { blocked = true; }
                    Check(blocked && origin.Requests == requests, coreName + " bypassed blocked UDP using TCP or DIRECT"); first.Drop = second.Drop = false;
                    Check(await http.GetStringAsync(target, ct) == "198.51.100.22", coreName + " did not recover after restoring the same UDP path");
                }
                Console.WriteLine("Round 15 native: " + coreName + (hopping ? " hopping" : " baseline") + " authenticated HTTPS stream passed.");
            }
            foreach (var bad in new[] { "password", "sni", "obfs" })
            {
                var candidate = node.DeepClone().AsObject(); candidate["sing_box"]!["password"] = bad == "password" ? "wrong-synthetic-password" : node.Text("sing_box.password"); candidate["clash"]!["password"] = candidate.Text("sing_box.password");
                if (bad == "sni") { candidate["sing_box"]!["tls"]!["server_name"] = "wrong.example.test"; candidate["clash"]!["sni"] = "wrong.example.test"; }
                if (bad == "obfs") { candidate["sing_box"]!["obfs"]!["password"] = "wrong-synthetic-obfuscation"; candidate["clash"]!["obfs-password"] = "wrong-synthetic-obfuscation"; }
                await using var client = await Round15Client.Start(coreName, assets.ResolveCore(coreName), candidate, cert, directory, ct); owned.Add(client.Process.Id);
                using var handler = new HttpClientHandler { Proxy = new WebProxy("http://127.0.0.1:" + client.Port), UseProxy = true, ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate?.GetCertHashString() == cert.GetCertHashString() };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) }; var requests = origin.Requests; var rejected = false;
                try { await http.GetStringAsync("https://127.0.0.1:" + origin.Port, ct); } catch (Exception e) when (e is HttpRequestException or OperationCanceledException) { rejected = true; }
                Check(rejected && origin.Requests == requests, coreName + " accepted invalid Hysteria " + bad);
            }
        }
        Check(owned.All(id => { try { using var p = Process.GetProcessById(id); return p.HasExited; } catch (ArgumentException) { return true; } }), "Round 15 left an owned client process running");
        var evidence = Environment.GetEnvironmentVariable("MAY_R15_EVIDENCE"); if (!string.IsNullOrEmpty(evidence)) ArchiveStore.WriteJson(Path.GetFullPath(evidence), new JsonObject { ["SyntheticOnly"] = true, ["Scope"] = "Windows loopback; same serial HTTPS workload, two-second stream warmup excluded from RSS samples; short observation only", ["Measurements"] = measurements, ["ClientsStopped"] = true });
        secrets.Clear();
    }
    private sealed class Round15Client(Process process, Task<string> output, Task<string> error, int port) : IAsyncDisposable
    {
        public Process Process => process;
        private Task<string> Error => error;
        public async Task<string> StopAndRead() { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); var text = await output + "\n" + await error; return text[^Math.Min(1800, text.Length)..]; }
        public int Port => port;
        public static async Task<Round15Client> Start(string name, string executable, JsonObject node, X509Certificate2 certificate, string directory, CancellationToken ct)
        {
            var port = TcpPort(); JsonObject config; var controller = TcpPort(); var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            if (name == "sing-box")
            {
                var outbound = node["sing_box"]!.DeepClone().AsObject(); outbound["tag"] = "review"; outbound["tls"]!["certificate"] = new JsonArray(certificate.ExportCertificatePem());
                config = new JsonObject { ["log"] = new JsonObject { ["disabled"] = Environment.GetEnvironmentVariable("MAY_HYSTERIA_TRACE") != "1", ["level"] = "debug" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "mixed", ["listen"] = "127.0.0.1", ["listen_port"] = port }), ["outbounds"] = new JsonArray(outbound), ["route"] = new JsonObject { ["final"] = "review" } };
            }
            else
            {
                // This fixed core constructs proxy TLS pools before applying
                // global custom roots. Reload our own disposable configuration
                // once after startup so its proxy uses the synthetic CA pool.
                var outbound = node["clash"]!.DeepClone().AsObject(); outbound["name"] = "review";
                config = new JsonObject { ["mixed-port"] = port, ["bind-address"] = "127.0.0.1", ["allow-lan"] = false, ["mode"] = "rule", ["log-level"] = Environment.GetEnvironmentVariable("MAY_HYSTERIA_TRACE") == "1" ? "debug" : "error", ["external-controller"] = "127.0.0.1:" + controller, ["secret"] = token, ["tls"] = new JsonObject { ["custom-certifactes"] = new JsonArray(certificate.ExportCertificatePem()) }, ["proxies"] = new JsonArray(outbound), ["rules"] = new JsonArray("MATCH,review") };
            }
            var subdirectory = SafePath.Resolve(directory, Guid.NewGuid().ToString("N")); Directory.CreateDirectory(subdirectory); var file = SafePath.Resolve(subdirectory, "client.private.json"); ArchiveStore.WriteJson(file, config);
            var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in name == "sing-box" ? new[] { "run", "-c", file } : new[] { "-d", subdirectory, "-f", file }) start.ArgumentList.Add(argument);
            var process = Process.Start(start)!; var result = new Round15Client(process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync(), port);
            try
            {
                var watch = Stopwatch.StartNew();
                while (!IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(e => e.Port == port))
                {
                    ct.ThrowIfCancellationRequested(); if (process.HasExited) throw new IOException("Round 15 core exited: " + await result.Error);
                    if (watch.Elapsed > TimeSpan.FromSeconds(8)) throw new TimeoutException(name + " local listener did not start: " + await result.StopAndRead()); await Task.Delay(25, ct);
                }
                if(name=="mihomo")
                {
                    using var http=new HttpClient(new SocketsHttpHandler{UseProxy=false}){Timeout=TimeSpan.FromSeconds(5)};
                    http.DefaultRequestHeaders.Authorization=new("Bearer",token);
                    using var request=new StringContent(new JsonObject{["payload"]=config.ToJsonString()}.ToJsonString(),System.Text.Encoding.UTF8,"application/json");
                    using var response=await http.PutAsync("http://127.0.0.1:"+controller+"/configs?force=true",request,ct);response.EnsureSuccessStatusCode();
                }
                return result;
            }
            catch { await result.DisposeAsync(); throw; }
        }
        public async ValueTask DisposeAsync() { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); await Task.WhenAll(output, error); process.Dispose(); }
    }
}
