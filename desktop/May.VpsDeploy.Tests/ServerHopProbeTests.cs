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
    public async Task RunHopProbeTests() { using var f = new Fixture(repository); await ServerHopProbeRuntime(f); Console.WriteLine($"PASS: {assertions} real Python/core TLS acceptance and cleanup assertions."); }
    private async Task ServerHopProbeRuntime(Fixture f)
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(python)) { Console.WriteLine("SKIP: remote probe Python runtime fixture requires Windows and MAY_TEST_PYTHON."); return; }
        var directory = f.Paths.Resolve("private/server-hop-probe-runtime"); Directory.CreateDirectory(directory);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(80)); var children = new List<Process>(); var serverLogs = new List<Task<string>>();
        using var rootKey = RSA.Create(2048); var rootRequest = new CertificateRequest("CN=May synthetic probe root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true)); rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        using var key = RSA.Create(2048); var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true)); request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true)); request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        using var issued = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(12)); using var certificate = issued.CopyWithPrivateKey(key);
        var trustFile = SafePath.Resolve(directory, "synthetic-root.pem"); File.WriteAllText(trustFile, root.ExportCertificatePem());
        using var tlsReservation = new TcpListener(IPAddress.Loopback, 0); tlsReservation.Start(); var tlsPort = ((IPEndPoint)tlsReservation.LocalEndpoint).Port; tlsReservation.Stop();
        var certFile = SafePath.Resolve(directory, "localhost.pem"); var keyFile = SafePath.Resolve(directory, "localhost-key.pem"); var hitsFile = SafePath.Resolve(directory, "target-hits.txt");
        File.WriteAllText(certFile, certificate.ExportCertificatePem() + "\n" + root.ExportCertificatePem()); File.WriteAllText(keyFile, key.ExportPkcs8PrivateKeyPem());
        var targetFile = SafePath.Resolve(directory, "tls-target.py");
        File.WriteAllText(targetFile, """
import socket, ssl, sys
from pathlib import Path
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
hits = 0
with socket.socket() as listener:
    listener.bind(('127.0.0.1', int(sys.argv[1])))
    listener.listen(8)
    print('READY', flush=True)
    while True:
        stream, _ = listener.accept()
        try:
            stream.settimeout(4)
            with ctx.wrap_socket(stream, server_side=True) as tls:
                request = b''
                while b'\r\n\r\n' not in request and len(request) < 8192:
                    chunk = tls.recv(1024)
                    if not chunk:
                        break
                    request += chunk
                if b'\r\n\r\n' in request:
                    hits += 1
                    Path(sys.argv[4]).write_text(str(hits))
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n198.51.100.21')
        except OSError:
            stream.close()
""");
        var sing = new ValidationAssets(new AppPaths(repository), "windows-amd64").ResolveCore("sing-box");
        using var reserve = new TcpListener(IPAddress.Loopback, 0); reserve.Start(); var landingPort = ((IPEndPoint)reserve.LocalEndpoint).Port; reserve.Stop();
        var password = ServerConfigurations.RandomKey(); var landing = new JsonObject { ["log"] = new JsonObject { ["level"] = "error" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "shadowsocks", ["listen"] = "127.0.0.1", ["listen_port"] = landingPort, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = password }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" }) };
        var landingFile = SafePath.Resolve(directory, "landing.private.json"); ArchiveStore.WriteJson(landingFile, landing);
        var landingStart = new ProcessStartInfo(sing) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var arg in new[] { "run", "-c", landingFile }) landingStart.ArgumentList.Add(arg);
        var process = Process.Start(landingStart)!; children.Add(process); var landingOutput = process.StandardOutput.ReadToEndAsync(); var landingError = process.StandardError.ReadToEndAsync();
        try
        {
            // OpenSSL fixture avoids Windows server credential-store requirements; no OS trust changes.
            var targetStart = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { targetFile, tlsPort.ToString(), certFile, keyFile, hitsFile }) targetStart.ArgumentList.Add(arg);
            var target = Process.Start(targetStart)!; children.Add(target); var targetReady = await target.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5), stop.Token); serverLogs.Add(target.StandardOutput.ReadToEndAsync()); serverLogs.Add(target.StandardError.ReadToEndAsync()); Check(targetReady == "READY", "synthetic TLS target did not start");
            using (var directHandler = new HttpClientHandler { UseProxy = false, ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert?.Thumbprint == certificate.Thumbprint })
            using (var direct = new HttpClient(directHandler) { Timeout = TimeSpan.FromSeconds(5) }) Check(await direct.GetStringAsync("https://127.0.0.1:" + tlsPort, stop.Token) == "198.51.100.21", "synthetic TLS egress target unavailable before proxy acceptance");
            var landingReady = false;
            for (var i = 0; i < 60 && !process.HasExited; i++)
            {
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); attempt.CancelAfter(TimeSpan.FromMilliseconds(500));
                try { using var ready = new TcpClient(); await ready.ConnectAsync(IPAddress.Loopback, landingPort, attempt.Token); landingReady = true; break; }
                catch (SocketException) { await Task.Delay(50, stop.Token); }
                catch (OperationCanceledException) when (!stop.IsCancellationRequested) { }
            }
            if (!landingReady)
            {
                if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync();
                throw new Exception("Synthetic Shadowsocks listener did not start: " + (await landingError).Replace(password, "[synthetic-secret]", StringComparison.Ordinal));
            }
            var asset = File.ReadAllText(Path.Combine(repository, "assets/remote/server-hop-probe.sh")).Replace("\r\n", "\n");
            var source = asset.Split("<<'PY'\n", StringSplitOptions.None)[1]; source = source[..source.LastIndexOf("\nPY", StringComparison.Ordinal)];
            source = source.Replace("PROBE_HOST_V4 = 'api.ipify.org'", "PROBE_HOST_V4 = 'localhost'").Replace("PROBE_PORT = 443", "PROBE_PORT = " + tlsPort);
            Check(source.Contains("PROBE_HOST_V4 = 'localhost'") && source.Contains("PROBE_PORT = " + tlsPort), "probe test did not isolate TLS destination");
            // Test-only observation of owned child IDs, preserving the probe implementation.
            var observer = "\n_original_popen = subprocess.Popen\ndef observed_popen(*args, **kwargs):\n    p = _original_popen(*args, **kwargs)\n    with open(os.environ['TEST_PID_FILE'], 'a') as trace:\n        trace.write(str(p.pid) + '\\n')\n    return p\nsubprocess.Popen = observed_popen\n";
            source = source.Replace("if __name__ == '__main__':", observer + "\nif __name__ == '__main__':");
            source = source.Replace("except Exception:\n        print('Server TCP", "except Exception as failure:\n        Path(os.environ['TEST_FAILURE_FILE']).write_text(type(failure).__name__ + ': ' + str(failure), encoding='utf-8')\n        print('Server TCP");
            var probeFile = SafePath.Resolve(directory, "probe-fixture.py"); File.WriteAllText(probeFile, source);
            foreach (var role in ServerOutboundRouting.Roles)
            {
                var binary = role == "RealityEntry" ? Environment.GetEnvironmentVariable("MAY_TEST_XRAY") : sing; if (string.IsNullOrEmpty(binary)) { Console.WriteLine("SKIP: actual Xray probe runtime not configured."); continue; }
                JsonObject Item(string id, int port, string expected) => new() { ["Id"] = id, ["ExpectedAddress"] = expected, ["Outbound"] = role == "RealityEntry" ? new JsonObject { ["tag"] = ServerOutboundRouting.HopTag(id), ["protocol"] = "shadowsocks", ["settings"] = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["address"] = "127.0.0.1", ["port"] = port, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = password }) } } : new JsonObject { ["tag"] = ServerOutboundRouting.HopTag(id), ["type"] = "shadowsocks", ["server"] = "127.0.0.1", ["server_port"] = port, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = password } };
                foreach (var scenario in new[] { "pass", "mismatch", "second-unavailable", "untrusted", "cancel" })
                {
                    var temp = SafePath.Resolve(directory, role + "-" + scenario); Directory.CreateDirectory(temp); var trace = SafePath.Resolve(temp, "children.txt");
                    var items = new JsonArray(Item(HopA, landingPort, scenario == "mismatch" ? "198.51.100.22" : "198.51.100.21"), Item(HopB, scenario == "second-unavailable" ? 1 : landingPort, "198.51.100.21"));
                    var testSource = scenario == "cancel" ? source.Replace("actual = query(port,", "raise InterruptedError('synthetic cancellation')\n            actual = query(port,") : source;
                    if (scenario == "cancel") File.WriteAllText(probeFile, testSource); else File.WriteAllText(probeFile, source);
                    var start = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var arg in new[] { probeFile, binary, role }) start.ArgumentList.Add(arg);
                    start.Environment["SSL_CERT_FILE"] = scenario == "untrusted" ? SafePath.Resolve(temp, "missing.pem") : trustFile; start.Environment["VPS_PARAM_PROBES_JSON"] = items.ToJsonString(); start.Environment["TEST_PID_FILE"] = trace; start.Environment["TEST_FAILURE_FILE"] = SafePath.Resolve(temp, "failure.txt"); start.Environment["TMP"] = temp; start.Environment["TEMP"] = temp; start.Environment["TMPDIR"] = temp;
                    using var probe = Process.Start(start)!; var stdout = probe.StandardOutput.ReadToEndAsync(); var stderr = probe.StandardError.ReadToEndAsync(); await probe.WaitForExitAsync(stop.Token); var output = await stdout; var error = await stderr;
                    var detail = File.Exists(SafePath.Resolve(temp, "failure.txt")) ? File.ReadAllText(SafePath.Resolve(temp, "failure.txt")).Replace(password, "[synthetic-secret]", StringComparison.Ordinal) : "";
                    Check((probe.ExitCode == 0) == (scenario == "pass") && !output.Contains(password) && !error.Contains(password) && !error.Contains("Traceback"), "real probe status or redaction failed: " + role + "/" + scenario + ": " + detail);
                    if (scenario == "pass") { var result = JsonNode.Parse(RemoteAssets.Marker(output, "HOP_VALIDATION"))!.AsObject(); ServerOutboundRouting.RequireHopValidation(items, result); Check(result["Items"]!.AsArray().Count == 2, "real probe omitted a hop"); }
                    else Check(!output.Contains("VPSDEPLOY_SERVER_HOPS_PASSED") && !output.Contains("VPSDEPLOY_HOP_VALIDATION"), "failed probe returned partial success marker");
                    Check(Directory.GetDirectories(temp, "may-hop-probe-*").Length == 0 && File.ReadAllLines(trace).All(pid => { try { using var owned = Process.GetProcessById(int.Parse(pid)); return owned.HasExited; } catch (ArgumentException) { return true; } }), "probe leaked child process or temporary credentials: " + scenario);
                }
            }
            Check(int.Parse(File.ReadAllText(hitsFile)) >= 4, "probe fixture did not perform TLS HTTP requests through actual Shadowsocks");
        }
        finally
        {
            stop.Cancel(); foreach (var child in children) { if (!child.HasExited) child.Kill(true); await child.WaitForExitAsync(); child.Dispose(); } await Task.WhenAll(landingOutput, landingError); await Task.WhenAll(serverLogs);
        }
    }
}
