using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunForwardProxy42Tests()
    {
        await ForwardProxy42Model(); await ForwardProxy42Workflows(); await ForwardProxy42Validation();
        Console.WriteLine($"PASS: {assertions} trusted PROXY policy, cross-language identity, TLS input, evidence and scoped recovery assertions; no production connections.");
    }
    private static JsonObject Receive42Config(string protocol = "Auto", bool balanced = false)
    {
        var config = balanced ? Multi41Config() : ForwardConfig(); var rule = config["Rules"]![0]!.AsObject();
        rule["ProxyProtocol"] = "v2";
        rule["ProxyReceive"] = new JsonObject { ["Version"] = 1, ["Protocol"] = protocol, ["TrustedSources"] = new JsonArray("198.51.100.1/32"), ["ClientSources"] = new JsonArray("192.0.2.0/24"), ["ProbeSource"] = "192.0.2.9", ["ProbeDestination"] = "203.0.113.9", ["TimeoutSeconds"] = 3 };
        return config;
    }
    private async Task ForwardProxy42Model()
    {
        using var f = new Fixture(repository); var plan = f.Plan("Proxy42-review"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        foreach (var protocol in new[] { "Auto", "v1", "v2" }) foreach (var balanced in new[] { false, true })
        {
            var config = TcpForwarding.Normalize(Receive42Config(protocol, balanced)); var rule = config["Rules"]![0]!.AsObject(); var original = config.ToJsonString();
            Check(JsonNode.DeepEquals(config, TcpForwarding.Normalize(config)) && original == config.ToJsonString(), "receive normalization mutated or lost policy");
            Check(ForwardProxyReceive.Summary(rule).Contains("198.51.100.1/32") && ForwardProxyReceive.Summary(rule).Contains("192.0.2.9") && ForwardProxyReceive.Summary(rule).Contains("无头直连"), "receive review omitted trust, client or direct-connect boundary");
            foreach (var edit in new Action<JsonObject>[] {
                r => r.Remove("ProxyProtocol"), r => r["Validation"] = new JsonObject { ["Type"] = "Ssh" },
                r => r["ProxyReceive"]!["Version"] = true, r => r["ProxyReceive"]!["Protocol"] = "Optional",
                r => r["ProxyReceive"]!["TrustedSources"] = new JsonArray("0.0.0.0/0"), r => r["ProxyReceive"]!["TrustedSources"] = new JsonArray("::/0"),
                r => r["ProxyReceive"]!["TrustedSources"] = new JsonArray("203.0.113.1"), r => r["ProxyReceive"]!["TrustedSources"] = new JsonArray(),
                r => r["ProxyReceive"]!["ClientSources"] = new JsonArray(), r => r["ProxyReceive"]!["ClientSources"] = new JsonArray("ff00::/8"),
                r => r["ProxyReceive"]!["TimeoutSeconds"] = true, r => r["ProxyReceive"]!["TimeoutSeconds"] = 11,
                r => r["ProxyReceive"]!["ProbeSource"] = "203.0.113.1", r => r["ProxyReceive"]!["ProbeDestination"] = "::1",
                r => r["ProxyReceive"]!["ProbeSource"] = "::ffff:192.0.2.9", r => r["ProxyReceive"]!["Unexpected"] = true,
                r => r["ProxyReceive"] = null
            }) { var bad = config.DeepClone().AsObject(); edit(bad["Rules"]![0]!.AsObject()); Refuses(() => TcpForwarding.Normalize(bad), "invalid receive trust/protocol accepted"); }
            var proof = await new Receive42Validation("none").ValidateAsync(plan, config, f.Root, new InlineProgress<string>(_ => { }), default);
            if (balanced) ForwardTargetGroups.AttachProof(config, proof, Multi41Proof(config, "abc"), "abc", true);
            TcpForwarding.RequireValidation(config, proof);
            foreach (var key in new[] { "Source", "Destination", "Protocol", "RuleFingerprint", "Scope" })
            { var bad = proof.DeepClone().AsObject(); bad["Items"]![0]!["Checks"]![0]!["ProxyReceive"]![key] = "changed"; Refuses(() => TcpForwarding.RequireValidation(config, bad), "stale declared-source evidence accepted"); }
            var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
            if (python != null)
            {
                const string program = "import importlib.util,json,sys;s=importlib.util.spec_from_file_location('f',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);v=m.normalize(json.load(sys.stdin));print(json.dumps(dict(Configuration=v,Fingerprint=m.group_fingerprint(v['Rules'][0]))))";
                var result = await new ExternalToolRunner().RunAsync(python, ["-c", program, Path.Combine(repository, "scripts/tcp-forwarding.py")], config.ToJsonString(), TimeSpan.FromSeconds(15), default);
                Check(result.ExitCode == 0, "Python receive normalization failed"); var value = JsonNode.Parse(result.Output)!;
                Check(JsonNode.DeepEquals(config, value["Configuration"]) && value.Text("Fingerprint") == ForwardTargetGroups.Fingerprint(rule), "C#/Python receive normalization or identity differs");
            }
            var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json"));
            var request = new OperationRequest(OperationKind.TcpForward, f.Relative(plan), TcpForwarding.Options(state, "Apply", config));
            var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => Task.FromResult(TaskOutcome.Completed))); var review = coordinator.Review(request);
            var changed = request.Options.DeepClone().AsObject(); changed["Configuration"]!["Rules"]![0]!["ProxyReceive"]!["TrustedSources"] = new JsonArray("198.51.100.2/32");
            await RefusesAsync(() => coordinator.ExecuteAsync(review, request with { Options = changed }, new InlineProgress<TaskProgress>(_ => { }), default), "trust change survived review");
        }
        var addresses = Receive42Config(); InstanceAddressChanges.Rewrite(addresses, new JsonObject { ["198.51.100.1"] = "198.51.100.2" });
        Check(addresses["Rules"]![0]!["ProxyReceive"]!.Strings("TrustedSources").Single() == "198.51.100.2/32", "instance address change missed trusted relay");
        InstanceAddressChanges.Rewrite(addresses, new JsonObject { ["203.0.113.9"] = "203.0.113.10" });
        Check(addresses["Rules"]![0]!.Text("ProxyReceive.ProbeDestination") == "203.0.113.10", "instance address change missed declared validation destination");
        Check(TcpForwarding.Normalize(ForwardConfig())["Rules"]![0]!["ProxyReceive"] == null, "legacy rules acquired implicit trust");
    }
    private sealed class Receive42Validation(string mode) : ITcpForwardValidation
    {
        public async Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject configuration, string directory, IProgress<string> progress, CancellationToken token)
        {
            var result = await new ForwardValidation(mode).ValidateAsync(plan, configuration, directory, progress, token);
            foreach (var item in result["Items"]!.AsArray().OfType<JsonObject>()) foreach (var check in item["Checks"]!.AsArray().OfType<JsonObject>())
            {
                var rule = TcpForwarding.Rules(configuration).Single(r => r.Text("Id") == item.Text("Id")); check["CertificateValidated"] = true;
                check["ProxyProtocol"] = rule.Text("ProxyProtocol"); check["ProxyReceive"] = ForwardProxyReceive.ProbeEvidence(rule);
                if (mode == "proof") check["ProxyReceive"]!["Source"] = "192.0.2.99";
            }
            return result;
        }
    }
    private async Task ForwardProxy42Workflows()
    {
        foreach (var balanced in new[] { false, true }) foreach (var mode in new[] { "none", "apply-ack", "commit-ack", "cancel", "validation", "proof" })
        {
            using var f = new Fixture(repository); var plan = f.Plan("Proxy42-" + balanced + mode); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
            var relative = f.Relative(plan); var directory = f.Paths.Instance(relative); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); var config = Receive42Config(balanced: balanced);
            var remote = new ForwardRemote { LoseApplyAck = mode == "apply-ack", GroupHealthy = [true, true, true] }; remote.Inner.SeedProtocols(plan); remote.Inner.ProtocolConfigs["RealityEntry"] = System.Text.Encoding.UTF8.GetBytes("synthetic preexisting proxy42"); remote.Inner.LoseOutboundCommitAcknowledgement = mode == "commit-ack";
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpForwarding: new Receive42Validation(mode));
            Exception? failure = null; TaskOutcome? outcome = null;
            try { outcome = await engine.ExecuteAsync(new(OperationKind.TcpForward, relative, TcpForwarding.Options(state, "Apply", config)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { failure = e; }
            Check(remote.ApplyCalls == 1, "receive mutation replayed after failure or acknowledgement loss");
            if (mode is "none" or "commit-ack")
            {
                Check(failure == null && outcome == (mode == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings), "receive workflow failed: " + failure?.Message);
                state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
                Check(state.At("TcpForwarding.Validation.Items")!.AsArray()[0]!["Checks"]![0]!.Text("ProxyReceive.Scope") == "ControllerDeclaredSourceTls", "receive proof not archived");
                remote.Inner.LoseOutboundCommitAcknowledgement = false;
                Check(await engine.ExecuteAsync(new(OperationKind.TcpForward, relative, TcpForwarding.Options(state, "Check", config)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.ApplyCalls == 1, "receive check replayed mutation");
                state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
                Check(await engine.ExecuteAsync(new(OperationKind.TcpForward, relative, TcpForwarding.Options(state, "Remove")), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default) == TaskOutcome.Completed && remote.Configuration == null, "receive component removal failed");
            }
            else Check(failure != null && remote.Configuration == null && ArchiveStore.ReadJson(SafePath.Resolve(directory, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack", "receive scoped recovery failed: " + mode + ": " + failure?.Message);
            Check(!remote.Inner.Commands.Any(c => c is "maintenance-komari.sh" or "server-outbound-apply.sh" or "protocol-lifecycle-apply-state.sh"), "receive operation crossed component scope");
        }
    }
    private async Task ForwardProxy42Validation()
    {
        using var f = new Fixture(repository); using var key = RSA.Create(2048); var request = new CertificateRequest("CN=target.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("target.example.test"); request.CertificateExtensions.Add(names.Build()); request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        var folder = f.Paths.Resolve("private/proxy42-tls"); Directory.CreateDirectory(folder); var certPath = Path.Combine(folder, "cert.pem"); var keyPath = Path.Combine(folder, "key.pem");
        File.WriteAllText(certPath, certificate.ExportCertificatePem()); File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
        foreach (var protocol in new[] { "Auto", "v1", "v2" }) foreach (var family in new[] { "IPv4", "IPv6" })
        {
            var proofPath = Path.Combine(folder, "proof.json"); if (File.Exists(proofPath)) File.Delete(proofPath);
            var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") ?? "python") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var value in new[] { Path.Combine(repository, "tests/tcp-proxy-receive-tls-fixture.py"), certPath, keyPath, proofPath, family }) start.ArgumentList.Add(value);
            using var process = Process.Start(start)!; var error = process.StandardError.ReadToEndAsync();
            try
            {
                var port = int.Parse((await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(8)))!);
                var config = Receive42Config(protocol); var rule = config["Rules"]![0]!.AsObject(); rule["ListenPort"] = port; rule["ListenFamily"] = family;
                var plan = new JsonObject { ["Server"] = new JsonObject { ["IPv4"] = "127.0.0.1", ["IPv6"] = "::1" } };
                var adapter = new TcpForwardValidation(f.Store, new ClientRouteDiagnostics(new FakeAssets(), new FakeTools()), certificate);
                var result = await adapter.ValidateAsync(plan, config, folder, new InlineProgress<string>(_ => { }), default); TcpForwarding.RequireValidation(config, result);
                var until = DateTimeOffset.UtcNow.AddSeconds(3); while (!File.Exists(proofPath) && DateTimeOffset.UtcNow < until) await Task.Delay(20);
                var observed = ArchiveStore.ReadJson(proofPath);
                Check(observed.Text("Source") == rule.Text("ProxyReceive.ProbeSource") && observed.Text("Destination") == rule.Text("ProxyReceive.ProbeDestination") && observed.Flag("CertificateHandshake"), "actual infrastructure header or verified TLS identity changed");
                Check(result["Items"]![0]!["Checks"]![0]!.Text("ProxyReceive.Protocol") == ForwardProxyReceive.ProbeProtocol(rule), "received protocol evidence differs from actual header");
            }
            finally { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); await error; }
        }
    }
}
