using System.Net;
using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private static JsonObject ForwardConfig(int port = 55001) { var config = TcpForwarding.Empty(); var rule = TcpForwarding.NewRule(); rule["ListenPort"] = port; rule["TargetAddress"] = "192.0.2.20"; rule["TargetPort"] = 443; rule["AllowedSources"] = new JsonArray("198.51.100.0/24"); rule["Validation"] = new JsonObject { ["Type"] = "Tls", ["ServerName"] = "target.example.test" }; config["Rules"]!.AsArray().Add(rule); return config; }
    public async Task RunTcpForwardTests()
    {
        using var f = new Fixture(repository); await TcpForwardExperience(f); await TcpForwardValidationLoopback(f);
        Console.WriteLine($"PASS: {assertions} TCP forwarding boundaries, lifecycle and application-level loopback assertions; no production connections.");
    }
    private async Task TcpForwardExperience(Fixture f)
    {
        var plan = f.Plan("Forward-preview"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan); var directory = f.Paths.Instance(f.Relative(plan)); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        var config = ForwardConfig(); var original = config.ToJsonString(); var normalized = TcpForwarding.Normalize(config);
        Check(original == config.ToJsonString() && normalized["Rules"]![0]!.Text("AllowedSources.0") == "", "normalization mutated the editor");
        Check(TcpForwarding.Source("192.0.2.199/24") == "192.0.2.0/24" && TcpForwarding.Source("2001:db8::1/64") == "2001:db8::/64", "source network host bits were not normalized");
        foreach (var bad in new[] { "../etc/passwd", "192.0.2.1/33", "::ffff:127.0.0.1", "fe80::1%eth0" }) Refuses(() => TcpForwarding.Source(bad), "invalid source accepted");
        foreach (var bad in new[] { "0.0.0.0", "::", "224.0.0.1", "ff02::1", "::ffff:192.0.2.1", "target.example.test" }) Refuses(() => TcpForwarding.Address(bad), "ambiguous target accepted");
        foreach (var edit in new Action<JsonObject>[] { c => c["Extra"] = true, c => c["Rules"]![0]!["AllowedSources"] = new JsonArray(), c => c["Rules"]![0]!["ListenPort"] = "55001", c => c["Rules"]![0]!["Enabled"] = "true", c => c["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "TcpOnly" }, c => c["Rules"]!.AsArray().Add(c["Rules"]![0]!.DeepClone()) })
        { var bad = config.DeepClone().AsObject(); edit(bad); Refuses(() => TcpForwarding.Normalize(bad), "invalid forwarding configuration accepted"); }
        var request = new OperationRequest(OperationKind.TcpForward, f.Relative(plan), TcpForwarding.Options(state, "Apply", config));
        var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed)));
        var review = coordinator.Review(request); Check(review.Summary.Contains("55001") && review.Summary.Contains("198.51.100.0/24") && OperationSteps.Create(request, plan).Count == 5, "review omitted source, listener or scoped steps");
        var conflict = config.DeepClone().AsObject(); conflict["Rules"]![0]!["ListenPort"] = plan.Number("Ports.SshPrimary");
        Refuses(() => TcpForwarding.Prepare(f.Store, request with { Options = TcpForwarding.Options(state, "Apply", conflict) }), "SSH listener collision accepted");
        conflict["Rules"]![0]!["ListenPort"] = config["Rules"]![0]!["ListenPort"]!.DeepClone(); conflict["Rules"]![0]!["TargetAddress"] = plan.Text("Server.IPv4"); conflict["Rules"]![0]!["TargetPort"] = config["Rules"]![0]!["ListenPort"]!.DeepClone();
        Refuses(() => TcpForwarding.Prepare(f.Store, request with { Options = TcpForwarding.Options(state, "Apply", conflict) }), "self forwarding loop accepted");
        conflict = config.DeepClone().AsObject(); conflict["Rules"]![0]!["ListenFamily"] = "DualStack";
        Refuses(() => TcpForwarding.Prepare(f.Store, request with { Options = TcpForwarding.Options(state, "Apply", conflict) }), "dual listener accepted without archived IPv6");
        var draft = request.Options.DeepClone().AsObject(); draft["Configuration"]!["Rules"]![0]!["TargetPort"] = 444;
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request with { Options = draft }, new InlineProgress<TaskProgress>(_ => { }), default), "editor mutation survived review");
        var program = f.Paths.Resolve("scripts/tcp-forwarding.py"); var bytes = File.ReadAllBytes(program); File.AppendAllText(program, "\n# changed fixture\n");
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "changed remote program survived review"); File.WriteAllBytes(program, bytes);
        var proxyScheme = ClientSchemes.New(f.Paths); var proxy = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Synthetic proxy", ["kind"] = "landing", ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["server"] = "192.0.2.20", ["server_port"] = 443, ["method"] = "2022-blake3-aes-128-gcm", ["password"] = ServerConfigurations.RandomKey() } };
        proxyScheme["Nodes"] = new JsonArray(proxy); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, proxyScheme.Text("Id")), proxyScheme);
        var proxyConfig = config.DeepClone().AsObject(); proxyConfig["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Proxy", ["SchemeId"] = proxyScheme.Text("Id"), ["NodeId"] = proxy.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(proxy) };
        var proxyRule = proxyConfig["Rules"]![0]!.AsObject(); Check(TcpForwarding.ProxyNode(f.Store, proxyRule).Text("kind") == "entry" && proxy.Text("kind") == "landing", "proxy validation changed source purpose");
        proxy["sing_box"]!["password"] = ServerConfigurations.RandomKey(); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, proxyScheme.Text("Id")), proxyScheme);
        Refuses(() => TcpForwarding.ProxyNode(f.Store, proxyRule), "changed proxy credential source accepted");
        foreach (var failure in new[] { "none", "drift", "apply-ack", "commit-ack", "incomplete", "cancel", "validation" })
        {
            var targetPlan = f.Plan("Forward-" + failure); targetPlan.Put("Import.Status", JsonValue.Create("Completed")); targetPlan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(targetPlan);
            var relative = f.Relative(targetPlan); var targetDir = f.Paths.Instance(relative); var targetState = ArchiveStore.ReadJson(SafePath.Resolve(targetDir, "deployment-state.json"));
            var remote = new ForwardRemote { ReadDrift = failure == "drift", LoseApplyAck = failure == "apply-ack" }; remote.Inner.SeedProtocols(targetPlan); remote.Inner.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes("synthetic existing proxy"); remote.Inner.LoseOutboundCommitAcknowledgement = failure == "commit-ack";
            var forwardValidation = new ForwardValidation(failure); var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpForwarding: forwardValidation);
            TaskOutcome? outcome = null; Exception? error = null;
            try { outcome = await engine.ExecuteAsync(new(OperationKind.TcpForward, relative, TcpForwarding.Options(targetState, "Apply", config)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { error = e; }
            var actualPlan = ArchiveStore.ReadJson(SafePath.Resolve(targetDir, "deployment-plan.json")); var actualState = ArchiveStore.ReadJson(SafePath.Resolve(targetDir, "deployment-state.json"));
            if (failure is "none" or "commit-ack")
            {
                Check(error == null && outcome == (failure == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings), "forwarding commit/ack reconciliation failed");
                Check(actualPlan["TcpForwarding"] != null && actualState.Text("TcpForwarding.Validation.Status") == "Passed", "successful forwarding not archived");
                var checksBefore = remote.ApplyCalls; remote.Inner.LoseOutboundCommitAcknowledgement = false;
                Check(await engine.ExecuteAsync(new(OperationKind.TcpForward, relative, TcpForwarding.Options(actualState, "Check", config)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.ApplyCalls == checksBefore, "read-only forwarding check wrote resources");
                var probesBeforeHealth = forwardValidation.Calls;
                await engine.ExecuteAsync(new(OperationKind.HealthAudit, relative, new()), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
                var healthy = ArchiveStore.ReadJson(SafePath.Resolve(targetDir, "deployment-state.json"));
                Check(healthy["HealthReport"]!["Checks"]!.AsArray().Any(c => c!.Text("Name") == "TCP 端口转发" && c.Text("Status") == "Passed") && forwardValidation.Calls == probesBeforeHealth && remote.ApplyCalls == checksBefore, "health omitted forwarding or started application probes/mutations");
                remote.ReadDrift = true;
                await engine.ExecuteAsync(new(OperationKind.HealthAudit, relative, new()), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default);
                var drifted = ArchiveStore.ReadJson(SafePath.Resolve(targetDir, "deployment-state.json"));
                Check(drifted["HealthReport"]!["Checks"]!.AsArray().Any(c => c!.Text("Name") == "TCP 端口转发" && c.Text("Status") == "Warning") && forwardValidation.Calls == probesBeforeHealth, "health promoted drift or added continuous probes"); remote.ReadDrift = false;
                Check(await engine.ExecuteAsync(new(OperationKind.TcpForward, relative, TcpForwarding.Options(actualState, "Remove")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.Configuration == null, "forward removal failed");
            }
            else if (failure == "drift") Check(error is OperationException && remote.ApplyCalls == 0 && !remote.Inner.Commands.Contains("protocol-migration-arm-rollback.sh"), "drift mutated resources or armed a snapshot");
            else
            {
                Check(error != null && !actualPlan.ContainsKey("TcpForwarding") && !actualState.ContainsKey("TcpForwarding") && remote.Configuration == null, "forwarding failure left new state or resources");
                Check(remote.ApplyCalls == 1 && ArchiveStore.ReadJson(SafePath.Resolve(targetDir, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack", "failed mutation was replayed or recovery remained open");
            }
            Check(!remote.Inner.Commands.Any(c => c is "server-outbound-apply.sh" or "protocol-lifecycle-apply-state.sh" or "maintenance-komari.sh") && (remote.Inner.ArmedComponents is "" or "TcpForwarding"), "forwarding expanded into proxy or monitoring scope");
            Check(Encoding.UTF8.GetString(remote.Inner.ProtocolConfigs["RealityEntry"]) == "synthetic existing proxy", "forwarding changed existing proxy bytes");
        }
    }
    private sealed class ForwardValidation(string failure, bool udp = false) : ITcpForwardValidation, IUdpForwardValidation
    {
        public int Calls { get; private set; }
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject config, string directory, IProgress<string> progress, CancellationToken token)
        {
            Calls++;
            if (failure == "cancel") throw new OperationCanceledException(); if (failure == "validation") throw new OperationException("synthetic forwarded request failure");
            return Task.FromResult(new JsonObject { ["Status"] = failure == "incomplete" ? "Incomplete" : "Passed", ["Items"] = new JsonArray(TcpForwarding.Rules(config).Where(r => r.Flag("Enabled")).Select(r => (JsonNode?)new JsonObject { ["Id"] = r.Text("Id"), ["From"] = "Controller", ["Scope"] = udp ? "ForwardedDatagramApplication" : "ForwardedApplication", ["Status"] = "Passed", ["Checks"] = new JsonArray(TcpForwarding.ProbeAddresses(plan, r).Select(address => (JsonNode?)new JsonObject { ["Address"] = address, ["Type"] = r.Text("Validation.Type"), ["Status"] = "Passed", ["ResponseMatched"] = udp }).ToArray()) }).ToArray()) });
        }
    }
    private sealed class ForwardRemote(string transport = "tcp") : IRemoteSessionFactory, IRemoteSession
    {
        public FakeRemote Inner { get; } = new(); public JsonObject? Configuration { get; private set; } private JsonObject? original;
        public bool ReadDrift { get; set; } public bool LoseApplyAck { get; set; } public int ApplyCalls { get; private set; }
        public string LastUdpPorts { get; private set; } = "";
        public async Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken token) { await Inner.OpenAsync(endpoint, user, token); return this; }
        public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken token) => Inner.RunAsync(command, timeout, token);
        public async Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken token)
        {
            var asset = payload.Split('\n')[0].Replace("# MXH asset: ", "");
            string Parameter(string name) { var match = Regex.Match(payload, "export VPS_PARAM_" + name + "=.+?'([A-Za-z0-9+/=]*)' "); return match.Success ? Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)) : ""; }
            var marker = transport.ToUpperInvariant() + "_FORWARD";
            if (asset == "nftables-apply.sh") LastUdpPorts = Parameter("UDP_PORTS");
            if (asset == transport + "-forward-read.sh")
            {
                Inner.Commands.Add(asset); var state = new JsonObject { ["Hash"] = ReadDrift ? new string('f', 64) : Configuration == null ? "Absent" : ArchiveStore.Fingerprint(Configuration), ["Configuration"] = Configuration?.DeepClone() };
                return new(0, "VPSDEPLOY_" + marker + "_STATE_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(state.ToJsonString())) + "\nVPSDEPLOY_" + marker + "_READ\n", "");
            }
            if (asset == transport + "-forward-apply.sh")
            {
                Inner.Commands.Add(asset); ApplyCalls++; Configuration = Parameter("ACTION") == "Remove" ? null : JsonNode.Parse(Parameter("CONFIG_JSON"))!.AsObject();
                if (LoseApplyAck) throw new IOException("synthetic lost apply acknowledgement"); return new(0, "VPSDEPLOY_" + marker + "_APPLIED\n", "");
            }
            if (asset == "protocol-migration-arm-rollback.sh")
            {
                if (Parameter(marker + "_EXPECTED_HASH") != (Configuration == null ? "Absent" : ArchiveStore.Fingerprint(Configuration))) throw new OperationException("synthetic snapshot hash did not match reviewed forwarding resources");
                original = Configuration?.DeepClone().AsObject();
            }
            var result = await Inner.RunScriptAsync(payload, timeout, mutating, token);
            if (asset == "protocol-migration-trigger-rollback.sh") Configuration = original?.DeepClone().AsObject();
            return result;
        }
        public Task<byte[]> ReadFileAsync(string path, CancellationToken token) => Inner.ReadFileAsync(path, token);
        public Task DownloadAsync(string path, string destination, CancellationToken token) => Inner.DownloadAsync(path, destination, token);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    private async Task TcpForwardValidationLoopback(Fixture f)
    {
        using var key = RSA.Create(2048); var certificateRequest = new CertificateRequest("CN=target.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("target.example.test"); certificateRequest.CertificateExtensions.Add(names.Build()); certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        using var relay = new TcpListener(IPAddress.Loopback, 0); relay.Start(); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        await using var target = await ForwardTlsTarget.Start(repository, f, certificate, key, cancellation.Token);
        var destinationPort = target.Port; var relayPort = ((IPEndPoint)relay.LocalEndpoint).Port;
        var relayTask = Task.Run(async () => { using var accepted = await relay.AcceptTcpClientAsync(cancellation.Token); using var backend = new TcpClient(); await backend.ConnectAsync(IPAddress.Loopback, destinationPort, cancellation.Token); await Task.WhenAny(accepted.GetStream().CopyToAsync(backend.GetStream(), cancellation.Token), backend.GetStream().CopyToAsync(accepted.GetStream(), cancellation.Token)); });
        var config = ForwardConfig(relayPort); var plan = new JsonObject { ["Server"] = new JsonObject { ["IPv4"] = "127.0.0.1" } };
        var adapter = new TcpForwardValidation(f.Store, new ClientRouteDiagnostics(new FakeAssets(), new FakeTools()), certificate);
        var result = await adapter.ValidateAsync(plan, config, f.Paths.Resolve("forward-fixture"), new InlineProgress<string>(_ => { }), cancellation.Token);
        TcpForwarding.RequireValidation(config, result); Check(result["Items"]![0]!["Checks"]![0]!.Flag("CertificateValidated"), "TLS forwarded handshake not checked");
        await relayTask;
        config["Rules"]![0]!["ListenPort"] = destinationPort;
        var untrusted = new TcpForwardValidation(f.Store, new ClientRouteDiagnostics(new FakeAssets(), new FakeTools())); var refusedCertificate = false;
        try { await untrusted.ValidateAsync(plan, config, f.Paths.Resolve("forward-fixture"), new InlineProgress<string>(_ => { }), cancellation.Token); } catch (OperationException error) when (error.Code == "TcpForwardTlsFailed") { refusedCertificate = true; }
        Check(refusedCertificate, "untrusted TLS certificate was accepted");
        config["Rules"]![0]!["Validation"]!["ServerName"] = "wrong.example.test"; var refusedHostname = false;
        try { await adapter.ValidateAsync(plan, config, f.Paths.Resolve("forward-fixture"), new InlineProgress<string>(_ => { }), cancellation.Token); } catch (OperationException error) when (error.Code == "TcpForwardTlsFailed") { refusedHostname = true; }
        Check(refusedHostname, "TLS hostname mismatch was accepted");
        using var ssh = new TcpListener(IPAddress.Loopback, 0); ssh.Start(); config["Rules"]![0]!["ListenPort"] = ((IPEndPoint)ssh.LocalEndpoint).Port; config["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Ssh" };
        var banner = Task.Run(async () => { using var accepted = await ssh.AcceptTcpClientAsync(cancellation.Token); await accepted.GetStream().WriteAsync(Encoding.ASCII.GetBytes("SSH-2.0-synthetic-fixture\r\n"), cancellation.Token); });
        result = await adapter.ValidateAsync(plan, config, f.Paths.Resolve("forward-fixture"), new InlineProgress<string>(_ => { }), cancellation.Token); await banner;
        Check(result["Items"]![0]!["Checks"]![0]!.Text("Type") == "Ssh", "SSH payload validation did not run");
        var invalid = Task.Run(async () => { using var accepted = await ssh.AcceptTcpClientAsync(cancellation.Token); await accepted.GetStream().WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n"), cancellation.Token); });
        await RefusesAsync(async () => { await adapter.ValidateAsync(plan, config, f.Paths.Resolve("forward-fixture"), new InlineProgress<string>(_ => { }), cancellation.Token); }, "TCP accept or unrelated banner passed SSH validation"); await invalid;
        using var alreadyCancelled = new CancellationTokenSource(); alreadyCancelled.Cancel(); var cancelled = false;
        try { await adapter.ValidateAsync(plan, config, f.Paths.Resolve("forward-fixture"), new InlineProgress<string>(_ => { }), alreadyCancelled.Token); } catch (OperationCanceledException) { cancelled = true; }
        Check(cancelled, "forwarded application validation ignored cancellation");
    }
    private sealed class ForwardTlsTarget(Process process, int port, Task<string> output, Task<string> error) : IAsyncDisposable
    {
        public int Port { get; } = port;
        public static async Task<ForwardTlsTarget> Start(string repository, Fixture f, X509Certificate2 certificate, RSA key, CancellationToken token)
        {
            var directory = f.Paths.Resolve("private/forward-tls"); Directory.CreateDirectory(directory);
            var cert = Path.Combine(directory, "certificate.pem"); var pem = Path.Combine(directory, "key.private.pem"); File.WriteAllText(cert, certificate.ExportCertificatePem()); File.WriteAllText(pem, key.ExportPkcs8PrivateKeyPem());
            var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") ?? "python") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in new[] { Path.Combine(repository, "tests/tcp-forward-tls-fixture.py"), cert, pem }) start.ArgumentList.Add(argument);
            var process = Process.Start(start)!;
            try { var line = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(6), token); return new(process, int.Parse(line!), process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync()); }
            catch { if (!process.HasExited) process.Kill(true); process.WaitForExit(); process.Dispose(); throw; }
        }
        public async ValueTask DisposeAsync()
        {
            try { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); await Task.WhenAll(output, error); }
            finally { process.Dispose(); }
        }
    }
}
