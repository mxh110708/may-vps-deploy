using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task ServerOutboundLoopback(Fixture f, bool withRules = false, bool withHops = false)
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: server route runtime fixture requires the bundled Windows core; portable boundaries still run."); return; }
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var executable = assets.ResolveCore("sing-box"); var tools = new ExternalToolRunner();
        var directory = f.Paths.Resolve("private/server-outbound-loopback"); Directory.CreateDirectory(directory);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(35)); var children = new List<(Process Process, Task<string> Output, Task<string> Error)>();
        await using var deniedTarget = withRules ? new DestinationHttpTarget(stop.Token) : null;
        using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certRequest = new CertificateRequest("CN=localhost", certKey, HashAlgorithmName.SHA256);
        certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); certRequest.CertificateExtensions.Add(san.Build());
        using var certificate = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        var certFile = SafePath.Resolve(directory, "server.pem"); var keyFile = SafePath.Resolve(directory, "server-key.pem");
        File.WriteAllText(certFile, certificate.ExportCertificatePem()); File.WriteAllText(keyFile, certKey.ExportPkcs8PrivateKeyPem());
        static int Port() { using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port; }
        var entryPort = Port(); var landingPort = Port(); var extraPort = Port(); var mixedPort = Port();
        using var web = new TcpListener(IPAddress.Loopback, 0); web.Start(); var webPort = ((IPEndPoint)web.LocalEndpoint).Port; var requests = 0;
        var webTask = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    using var socket = await web.AcceptTcpClientAsync(stop.Token); using var stream = socket.GetStream();
                    using var reader = new StreamReader(stream, leaveOpen: true);
                    while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 }) { }
                    Interlocked.Increment(ref requests);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nchain-ok!"), stop.Token);
                }
            }
            catch (Exception e) when (e is OperationCanceledException or SocketException or IOException or ObjectDisposedException) { }
        });
        async Task<Process> Start(string name, JsonObject config, int readyPort)
        {
            var file = SafePath.Resolve(directory, name + ".private.json"); ArchiveStore.WriteJson(file, config);
            (await tools.RunAsync(executable, ["check", "-c", file], null, TimeSpan.FromSeconds(10), stop.Token)).RequireSuccess("Synthetic server route rejected by real core.");
            var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
            foreach (var arg in new[] { "run", "-c", file }) info.ArgumentList.Add(arg);
            var process = Process.Start(info)!; children.Add((process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync()));
            for (var i = 0; i < 40 && !process.HasExited; i++)
            {
                try { using var socket = new TcpClient(); await socket.ConnectAsync(IPAddress.Loopback, readyPort, stop.Token); return process; } catch (SocketException) { await Task.Delay(50, stop.Token); }
            }
            throw new Exception("Owned loopback core did not become ready.");
        }
        try
        {
            var plan = f.Plan("Loopback-anytls"); var secrets = Fixture.RealitySecrets(); secrets["AnyTls"] = new JsonObject { ["Password"] = "synthetic-anytls-loopback" };
            plan.Put("Ports.AnyTlsPrimary", JsonValue.Create(entryPort)); var current = ServerConfigurations.AnyTls(plan, secrets);
            current["inbounds"]![0]!["listen"] = "127.0.0.1";
            current["inbounds"]![0]!["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "localhost", ["min_version"] = "1.3", ["certificate_path"] = certFile, ["key_path"] = keyFile };
            var serverKey = ServerConfigurations.RandomKey(); var userKey = ServerConfigurations.RandomKey();
            var node = new JsonObject { ["name"] = "Loopback landing", ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["tag"] = "landing", ["server"] = "192.0.2.20", ["server_port"] = landingPort, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = serverKey + ":" + userKey } };
            var extraNode = node.DeepClone().AsObject(); extraNode["name"] = "Extra loopback landing"; extraNode["sing_box"]!["server"] = "192.0.2.21"; extraNode["sing_box"]!["server_port"] = extraPort;
            JsonObject EntryConfiguration(JsonArray? policy)
            {
                var result = ServerOutboundRouting.Build("AnyTlsEntry", current, null, node, "198.51.100.20", plan, destinationRules: policy, additionalHops: withHops ? [new(HopA, extraNode, "198.51.100.21")] : null).Configuration;
                // Only this fixture maps its planned remote address to an isolated loopback listener.
                result["outbounds"]![1]!["server"] = "127.0.0.1"; if (withHops) result["outbounds"]![2]!["server"] = "127.0.0.1"; return result;
            }
            var rendered = EntryConfiguration(withHops ? new JsonArray(HopRule("Domain", "localhost", HopA)) : withRules ? LoopbackDestinationRules() : null);
            var landing = new JsonObject { ["log"] = new JsonObject { ["level"] = "error" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "shadowsocks", ["tag"] = "landing-in", ["listen"] = "127.0.0.1", ["listen_port"] = landingPort, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = serverKey, ["users"] = new JsonArray(new JsonObject { ["name"] = "fixture", ["password"] = userKey }) }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" }), ["route"] = new JsonObject { ["final"] = "direct" } };
            var landingProcess = await Start("landing", landing, landingPort);
            var extra = landing.DeepClone().AsObject(); extra["inbounds"]![0]!["listen_port"] = extraPort;
            var extraProcess = withHops ? await Start("extra-landing", extra, extraPort) : null;
            var entryProcess = await Start("entry", rendered, entryPort);
            var client = new JsonObject { ["log"] = new JsonObject { ["level"] = "error" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "mixed", ["tag"] = "local-client", ["listen"] = "127.0.0.1", ["listen_port"] = mixedPort }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "anytls", ["tag"] = "entry", ["server"] = "127.0.0.1", ["server_port"] = entryPort, ["password"] = secrets.Text("AnyTls.Password"), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "localhost", ["certificate_path"] = certFile } }), ["route"] = new JsonObject { ["final"] = "entry" } };
            await Start("client", client, mixedPort);
            using var handler = new HttpClientHandler { UseProxy = true, Proxy = new WebProxy("http://127.0.0.1:" + mixedPort) };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
            Check(await http.GetStringAsync("http://127.0.0.1:" + webPort, stop.Token) == "chain-ok!" && requests == 1, "real AnyTLS to SS2022 chain did not carry HTTP");
            if (withHops)
            {
                Check(await http.GetStringAsync("http://localhost:" + webPort, stop.Token) == "chain-ok!" && requests == 2, "AnyTLS named domain did not reach extra SS landing");
                extraProcess!.Kill(true); await extraProcess.WaitForExitAsync(stop.Token); var refused = false;
                try { await http.GetStringAsync("http://localhost:" + webPort, stop.Token); } catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { refused = true; }
                Check(refused && requests == 2 && await http.GetStringAsync("http://127.0.0.1:" + webPort, stop.Token) == "chain-ok!" && requests == 3, "failed named hop fell back to available default or disrupted default");
                await Start("extra-restarted", extra, extraPort);
            }
            if (withRules) await CheckDeniedTarget(mixedPort, deniedTarget!, stop.Token);
            // SOCKS UDP association through AnyTLS/UoT and the Shadowsocks UDP outbound.
            using var echo = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var echoPort = ((IPEndPoint)echo.Client.LocalEndPoint!).Port;
            var echoTask = Task.Run(async () => { var packet = await echo.ReceiveAsync(stop.Token); await echo.SendAsync(packet.Buffer, packet.RemoteEndPoint, stop.Token); });
            using var control = new TcpClient(); await control.ConnectAsync(IPAddress.Loopback, mixedPort, stop.Token); using var controlStream = control.GetStream();
            await controlStream.WriteAsync(new byte[] { 5, 1, 0 }, stop.Token); var greeting = new byte[2]; await controlStream.ReadExactlyAsync(greeting, stop.Token);
            await controlStream.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, stop.Token); var reply = new byte[10]; await controlStream.ReadExactlyAsync(reply, stop.Token);
            Check(greeting[1] == 0 && reply[1] == 0 && reply[3] == 1, "SOCKS UDP association failed");
            var relayPort = (reply[8] << 8) | reply[9]; using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var payload = new byte[] { 0, 0, 0, 1, 127, 0, 0, 1, (byte)(echoPort >> 8), (byte)echoPort, 11, 22, 33, 44 };
            await udp.SendAsync(payload, new IPEndPoint(IPAddress.Loopback, relayPort), stop.Token); var echoed = await udp.ReceiveAsync(stop.Token); await echoTask;
            Check(echoed.Buffer.AsSpan(10).SequenceEqual(payload.AsSpan(10)), "server fixed route did not forward UDP");
            if (withRules) await CheckUdpKeepsFixedPath(relayPort, true, stop.Token);
            var beforeFailure = requests; landingProcess.Kill(true); await landingProcess.WaitForExitAsync(stop.Token); var blocked = false;
            try { await http.GetStringAsync("http://127.0.0.1:" + webPort + "/after-landing-stopped", stop.Token); } catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { blocked = true; }
            Check(blocked && requests == beforeFailure, "broken server next hop fell back to direct or extra hop");
            if (withHops) Check(await http.GetStringAsync("http://localhost:" + webPort, stop.Token) == "chain-ok!" && requests == beforeFailure + 1, "default failure disrupted separately routed extra hop");
            if (withRules) await CheckUdpKeepsFixedPath(relayPort, false, stop.Token);
            if (withRules)
            {
                Check(await http.GetStringAsync("http://localhost:" + webPort, stop.Token) == "chain-ok!" && requests == 2, "ordered exact-domain direct rule stopped working with landing offline");
                entryProcess.Kill(true); await entryProcess.WaitForExitAsync(stop.Token);
                var suffixOnly = LoopbackDestinationRules(); suffixOnly.RemoveAt(0); suffixOnly[0]!["Action"] = "Direct";
                await Start("entry-suffix", EntryConfiguration(suffixOnly), entryPort);
                Check(await http.GetStringAsync("http://localhost:" + webPort, stop.Token) == "chain-ok!" && requests == 3, "sing-box suffix did not include its root domain");
            }
        }
        finally
        {
            stop.Cancel(); web.Stop();
            foreach (var child in children) { if (!child.Process.HasExited) child.Process.Kill(true); await child.Process.WaitForExitAsync(); await Task.WhenAll(child.Output, child.Error); child.Process.Dispose(); }
            await webTask;
        }
    }
}
