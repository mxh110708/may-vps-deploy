using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task RealityOutboundLoopback(Fixture f, bool withRules = false, bool withHops = false)
    {
        var xray = Environment.GetEnvironmentVariable("MAY_TEST_XRAY");
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(xray)) { Console.WriteLine("SKIP: actual Reality fixture requires Windows and MAY_TEST_XRAY; portable routing/lifecycle boundaries still run."); return; }
        SafePath.CheckLinks(xray);
        Check(ArchiveStore.Digest(File.ReadAllBytes(xray)) == "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1", "Reality test runtime is not the verified official Xray 26.3.27");
        var tools = new ExternalToolRunner(); var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var sing = assets.ResolveCore("sing-box");
        var version = await tools.RunAsync(xray, ["version"], null, TimeSpan.FromSeconds(10), CancellationToken.None); version.RequireSuccess("Reality fixture version unavailable."); Check(version.Output.Contains("Xray 26.3.27"), "Reality test version mismatch");
        var generated = await tools.RunAsync(xray, ["x25519"], null, TimeSpan.FromSeconds(10), CancellationToken.None); generated.RequireSuccess("Reality fixture key generation failed.");
        var privateKey = Regex.Match(generated.Output, @"(?m)^PrivateKey:\s*(\S+)").Groups[1].Value;
        var publicKey = Regex.Match(generated.Output, @"(?m)^Password \(PublicKey\):\s*(\S+)").Groups[1].Value;
        Check(privateKey.Length == 43 && publicKey.Length == 43, "Reality fixture generated keys unrecognized");
        var directory = f.Paths.Resolve("private/reality-outbound-loopback"); Directory.CreateDirectory(directory);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(45)); var children = new List<(string Name, Process Process, Task<string> Output, Task<string> Error)>();
        await using var deniedTarget = withRules ? new DestinationHttpTarget(stop.Token) : null;
        var redactions = new List<string> { privateKey, publicKey }; var failed = false;
        static int Port() { using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port; }
        var primary = Port(); var backup = Port(); var landingPort = Port(); var extraPort = Port(); var mixedPrimary = Port(); var mixedBackup = Port();
        using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certificateRequest = new CertificateRequest("CN=example.test", certKey, HashAlgorithmName.SHA256); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("example.test"); certificateRequest.CertificateExtensions.Add(san.Build());
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        var targetPort = Port(); var certFile = SafePath.Resolve(directory, "target.pem"); var keyFile = SafePath.Resolve(directory, "target-key.pem");
        File.WriteAllText(certFile, certificate.ExportCertificatePem()); File.WriteAllText(keyFile, certKey.ExportPkcs8PrivateKeyPem());
        using var web = new TcpListener(IPAddress.Loopback, 0); web.Start(); var webPort = ((IPEndPoint)web.LocalEndpoint).Port; var requests = 0;
        var webTask = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    using var socket = await web.AcceptTcpClientAsync(stop.Token); using var stream = socket.GetStream(); using var reader = new StreamReader(stream, leaveOpen: true);
                    while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 }) { }
                    Interlocked.Increment(ref requests); await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nreality-ok"), stop.Token);
                }
            }
            catch (Exception error) when (error is OperationCanceledException or SocketException or IOException or ObjectDisposedException) { }
        });
        async Task<Process> Start(string name, string executable, JsonObject configuration, int port)
        {
            var file = SafePath.Resolve(directory, name + ".private.json"); ArchiveStore.WriteJson(file, configuration);
            var isXray = executable == xray; var result = await tools.RunAsync(executable, isXray ? ["run", "-test", "-config", file] : ["check", "-c", file], null, TimeSpan.FromSeconds(10), stop.Token); result.RequireSuccess("Actual core rejected Reality/SS2022 fixture.");
            var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
            foreach (var argument in isXray ? new[] { "run", "-config", file } : ["run", "-c", file]) start.ArgumentList.Add(argument);
            var process = Process.Start(start)!; children.Add((name, process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync()));
            for (var i = 0; i < 60 && !process.HasExited; i++) { try { using var socket = new TcpClient(); await socket.ConnectAsync(IPAddress.Loopback, port, stop.Token); return process; } catch (SocketException) { await Task.Delay(50, stop.Token); } }
            throw new Exception("Owned Reality fixture did not become ready.");
        }
        try
        {
            // A Go TLS 1.3/H2 target provides the X25519 ServerHello REALITY requires.
            // Windows Schannel may select an unsupported key share even with TLS 1.3 enabled.
            var tlsTarget = new JsonObject { ["log"] = new JsonObject { ["level"] = "error" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "anytls", ["listen"] = "127.0.0.1", ["listen_port"] = targetPort, ["users"] = new JsonArray(new JsonObject { ["password"] = "synthetic-target-only" }), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "example.test", ["min_version"] = "1.3", ["alpn"] = new JsonArray("h2"), ["certificate_path"] = certFile, ["key_path"] = keyFile } }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" }) };
            await Start("tls-target", sing, tlsTarget, targetPort);
            var plan = f.Plan("Loopback-reality"); plan.Put("Ports.XrayPrimary", JsonValue.Create(primary)); plan.Put("Ports.XrayBackup", JsonValue.Create(backup)); plan.Put("Reality.ServerName", JsonValue.Create("example.test")); plan.Put("Reality.TargetMode", JsonValue.Create("LocalOwnedTls")); plan.Put("Reality.LocalHttpsPort", JsonValue.Create(targetPort));
            var secrets = Fixture.RealitySecrets(); secrets.Put("Xray.RealityPrivateKey", JsonValue.Create(privateKey)); secrets.Put("Xray.RealityClientKey", JsonValue.Create(publicKey));
            var serverKey = ServerConfigurations.RandomKey(); var userKey = ServerConfigurations.RandomKey();
            redactions.AddRange([secrets.Text("Xray.Uuid"), serverKey, userKey]);
            var node = new JsonObject { ["name"] = "Reality fixture landing", ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["tag"] = "landing", ["server"] = "192.0.2.20", ["server_port"] = landingPort, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = serverKey + ":" + userKey } };
            var extraNode = node.DeepClone().AsObject(); extraNode["name"] = "Extra Reality fixture landing"; extraNode["sing_box"]!["server"] = "192.0.2.21"; extraNode["sing_box"]!["server_port"] = extraPort;
            JsonObject EntryConfiguration(JsonArray? policy)
            {
                var result = ServerOutboundRouting.Build("RealityEntry", ServerConfigurations.Xray(plan, secrets), null, node, "198.51.100.20", plan, destinationRules: policy, additionalHops: withHops ? [new(HopA, extraNode, "198.51.100.21")] : null).Configuration;
                result["log"] = new JsonObject { ["loglevel"] = "debug" };
                foreach (var inbound in result["inbounds"]!.AsArray()) inbound!["listen"] = "127.0.0.1";
                result["outbounds"]![2]!["settings"]!["servers"]![0]!["address"] = "127.0.0.1"; if (withHops) result["outbounds"]![3]!["settings"]!["servers"]![0]!["address"] = "127.0.0.1"; return result;
            }
            var rendered = EntryConfiguration(withHops ? new JsonArray(HopRule("Domain", "localhost", HopA)) : withRules ? LoopbackDestinationRules() : null);
            var landing = new JsonObject { ["log"] = new JsonObject { ["level"] = "error" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "shadowsocks", ["tag"] = "landing", ["listen"] = "127.0.0.1", ["listen_port"] = landingPort, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = serverKey, ["users"] = new JsonArray(new JsonObject { ["name"] = "fixture", ["password"] = userKey }) }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" }), ["route"] = new JsonObject { ["final"] = "direct" } };
            var landingProcess = await Start("landing", sing, landing, landingPort);
            var extra = landing.DeepClone().AsObject(); extra["inbounds"]![0]!["listen_port"] = extraPort;
            var extraProcess = withHops ? await Start("extra-landing", sing, extra, extraPort) : null;
            var entryProcess = await Start("entry", xray, rendered, primary);
            var clients = ClientProfiles.Nodes(plan, secrets, true).ToArray(); var clientInbounds = new JsonArray(); var clientOutbounds = new JsonArray(); var rules = new JsonArray();
            foreach (var (client, index) in clients.Select((client, index) => (client, index)))
            {
                var outbound = client.SingBox.DeepClone().AsObject(); outbound["server"] = "127.0.0.1";
                clientOutbounds.Add(outbound); var tag = "local-" + index; clientInbounds.Add(new JsonObject { ["type"] = "mixed", ["tag"] = tag, ["listen"] = "127.0.0.1", ["listen_port"] = index == 0 ? mixedPrimary : mixedBackup });
                rules.Add(new JsonObject { ["inbound"] = new JsonArray(tag), ["action"] = "route", ["outbound"] = client.Name });
            }
            await Start("client", sing, new JsonObject { ["log"] = new JsonObject { ["level"] = "debug" }, ["inbounds"] = clientInbounds, ["outbounds"] = clientOutbounds, ["route"] = new JsonObject { ["rules"] = rules, ["final"] = clients[0].Name } }, mixedPrimary);
            async Task<string> Request(int port, string host = "127.0.0.1")
            {
                using var handler = new HttpClientHandler { UseProxy = true, Proxy = new WebProxy("http://127.0.0.1:" + port) }; using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(4) };
                return await client.GetStringAsync("http://" + host + ":" + webPort, stop.Token);
            }
            Check(await Request(mixedPrimary) == "reality-ok" && await Request(mixedBackup) == "reality-ok" && requests == 2, "actual primary/backup Reality to SS2022 chain failed");
            if (withHops)
            {
                Check(await Request(mixedPrimary, "localhost") == "reality-ok" && await Request(mixedBackup, "localhost") == "reality-ok" && requests == 4, "Reality primary/backup named routing did not reach extra landing");
                extraProcess!.Kill(true); await extraProcess.WaitForExitAsync(stop.Token); var refused = false;
                try { await Request(mixedPrimary, "localhost"); } catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { refused = true; }
                Check(refused && requests == 4 && await Request(mixedPrimary) == "reality-ok" && requests == 5, "Reality extra-hop failure fell back to available default or disrupted it");
                await Start("extra-restarted", sing, extra, extraPort);
            }
            if (withRules) await CheckDeniedTarget(mixedPrimary, deniedTarget!, stop.Token);
            using var echo = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var echoPort = ((IPEndPoint)echo.Client.LocalEndPoint!).Port;
            var echoTask = Task.Run(async () => { var packet = await echo.ReceiveAsync(stop.Token); await echo.SendAsync(packet.Buffer, packet.RemoteEndPoint, stop.Token); });
            using var control = new TcpClient(); await control.ConnectAsync(IPAddress.Loopback, mixedPrimary, stop.Token); using var controlStream = control.GetStream();
            await controlStream.WriteAsync(new byte[] { 5, 1, 0 }, stop.Token); var greeting = new byte[2]; await controlStream.ReadExactlyAsync(greeting, stop.Token);
            await controlStream.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, stop.Token); var reply = new byte[10]; await controlStream.ReadExactlyAsync(reply, stop.Token);
            Check(reply[1] == 0 && reply[3] == 1, "Reality UDP association failed");
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var payload = new byte[] { 0, 0, 0, 1, 127, 0, 0, 1, (byte)(echoPort >> 8), (byte)echoPort, 9, 8, 7, 6 };
            await udp.SendAsync(payload, new IPEndPoint(IPAddress.Loopback, (reply[8] << 8) | reply[9]), stop.Token); var echoed = await udp.ReceiveAsync(stop.Token); await echoTask;
            Check(echoed.Buffer.AsSpan(10).SequenceEqual(payload.AsSpan(10)), "actual Reality/SS2022 UDP bridge failed");
            if (withRules) await CheckUdpKeepsFixedPath((reply[8] << 8) | reply[9], true, stop.Token);
            var beforeFailure = requests; landingProcess.Kill(true); await landingProcess.WaitForExitAsync(stop.Token); var blocked = false;
            try { await Request(mixedPrimary); } catch (Exception error) when (error is HttpRequestException or TaskCanceledException) { blocked = true; }
            Check(blocked && requests == beforeFailure, "broken Reality next hop fell back to direct or extra hop");
            if (withHops) Check(await Request(mixedPrimary, "localhost") == "reality-ok" && await Request(mixedBackup, "localhost") == "reality-ok" && requests == beforeFailure + 2, "default failure broke independent Reality named-hop routes");
            if (withRules) await CheckUdpKeepsFixedPath((reply[8] << 8) | reply[9], false, stop.Token);
            if (withRules)
            {
                Check(await Request(mixedPrimary, "localhost") == "reality-ok" && await Request(mixedBackup, "localhost") == "reality-ok" && requests == 4, "Reality primary/backup explicit direct rule failed or order was ignored");
                entryProcess.Kill(true); await entryProcess.WaitForExitAsync(stop.Token);
                var suffixOnly = LoopbackDestinationRules(); suffixOnly.RemoveAt(0); suffixOnly[0]!["Action"] = "Direct";
                await Start("entry-suffix", xray, EntryConfiguration(suffixOnly), primary);
                Check(await Request(mixedPrimary, "localhost") == "reality-ok" && requests == 5, "Xray suffix did not include its root domain");
            }
        }
        catch { failed = true; throw; }
        finally
        {
            stop.Cancel(); web.Stop();
            foreach (var child in children) { if (!child.Process.HasExited) child.Process.Kill(true); await child.Process.WaitForExitAsync(); await Task.WhenAll(child.Output, child.Error); child.Process.Dispose(); }
            await webTask;
            if (failed)
            {
                var diagnostic = "Target requests=" + requests + "\n" + string.Join('\n', children.Select(c => c.Name + ":\n" + c.Output.Result + c.Error.Result));
                foreach (var value in redactions) diagnostic = diagnostic.Replace(value, "[synthetic-secret]", StringComparison.Ordinal);
                File.WriteAllText(Path.Combine(repository, ".test-output", "reality-loopback-last.log"), diagnostic);
            }
        }
    }
}
