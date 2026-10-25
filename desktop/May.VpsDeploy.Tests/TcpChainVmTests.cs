using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunTcpChainVmTests(string manifestFile)
    {
        if (!Path.GetFullPath(manifestFile).Contains(Path.DirectorySeparatorChar + ".codex-tmp" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new Exception("Use the disposable fixture manifest, never production targets.");
        var manifest = ArchiveStore.ReadJson(manifestFile);
        if (manifest.Number("Version") != 1 || !manifest.Flag("SyntheticOnly") || manifest["Nodes"] is not JsonObject { Count: 3 }) throw new Exception("Disposable three-guest manifest required.");
        var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(12)); var token = budget.Token; var user = new FakeUser();
        Console.WriteLine("Disposable controller evidence: " + f.Root);
        var factory = new TcpChainVmFactory(f.Store, manifest["Nodes"]!.AsObject());
        var plans = new List<JsonObject>();
        foreach (var name in new[] { "Front", "Relay", "Landing" })
        {
            var host = manifest["Nodes"]![name]!.AsObject(); var role = name == "Landing" ? "ShadowsocksLanding" : "MonitorOnly";
            var plan = f.Plan("TcpChainVM-" + name); plan["Role"] = role; plan["Roles"] = new JsonArray(role); plan["ActiveEntry"] = ""; plan["AdminUser"] = "root";
            plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Import.SshAuthenticationPreserved", JsonValue.Create(true)); plan.Put("Server.IPv4", JsonValue.Create(host.Text("Address"))); plan.Put("Server.IPv6", JsonValue.Create("")); plan.Put("Server.BootstrapSshPort", JsonValue.Create(22)); plan.Put("Ports.SshPrimary", JsonValue.Create(22)); plan.Put("Ports.SshRescue", JsonValue.Create(2222)); plan.Put("Ports.LandingShadowsocks", JsonValue.Create(34443)); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); plan.Put("SshKey.SourcePrivateKeyPath", JsonValue.Create(host.Text("KeyFile"))); plan.Put("Shadowsocks.Method", JsonValue.Create("2022-blake3-aes-128-gcm")); plan.Put("Shadowsocks.SecondaryIpv6Enabled", JsonValue.Create(false));
            plan["ProtocolInventory"] = new JsonObject(); foreach (var protocol in DeploymentPlans.Roles[..3]) plan["ProtocolInventory"]![protocol] = new JsonObject { ["Installed"] = protocol == role, ["Enabled"] = protocol == role, ["Active"] = protocol == role };
            f.SaveInstance(plan); plans.Add(plan);
            await using var remote = await factory.OpenAsync(new(host.Text("Address"), 22, "root", host.Text("KeyFile")), user, token);
            var guard = await remote.RunAsync("python3 -c \"from pathlib import Path; print(Path('/etc/may-tcp-chain-fixture').read_text().strip()); print(Path('/sys/class/dmi/id/product_uuid').read_text().strip())\"", TimeSpan.FromSeconds(10), token);
            Check(guard.ExitCode == 0 && guard.Output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).All(v => v.Trim().Equals(host.Text("FixtureId"), StringComparison.OrdinalIgnoreCase)) && guard.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == 2, "disposable DMI and marker did not match before operations");
        }
        var secret = new JsonObject { ["Shadowsocks"] = new JsonObject { ["ServerKey"] = ServerConfigurations.RandomKey(16), ["PrimaryUserKey"] = ServerConfigurations.RandomKey(16) } };
        f.Store.WriteSecret(SafePath.Resolve(f.Paths.Instance(f.Relative(plans[2])), "secrets.dotnet.private.json"), secret);
        var server = ServerConfigurations.Shadowsocks(plans[2], secret); var serverBytes = ArchiveStore.JsonBytes(server); var serverHash = ArchiveStore.Digest(serverBytes);
        var serverEncoded = Convert.ToBase64String(serverBytes);
        using var tlsKey = RSA.Create(2048); var certificateRequest = new CertificateRequest("CN=Disposable TCP chain HTTPS", tlsKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddIpAddress(IPAddress.Loopback); certificateRequest.CertificateExtensions.Add(names.Build()); certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var authority = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
        await using (var remote = await factory.OpenAsync(new(plans[2].Text("Server.IPv4"), 22, "root", manifest.Text("Nodes.Landing.KeyFile")), user, token))
        {
            var script = "set -euo pipefail\ninstall -d -m 0700 /etc/sing-box\nprintf '%s' '" + serverEncoded + "' | base64 -d > /etc/sing-box/config.json\n/opt/may-tcp-chain-fixture/sing-box check -c /etc/sing-box/config.json\ncat > /etc/systemd/system/may-tcp-chain-landing.service <<'EOF'\n[Unit]\nDescription=Disposable encrypted TCP chain target\nAfter=network-online.target\n[Service]\nExecStart=/opt/may-tcp-chain-fixture/sing-box run -c /etc/sing-box/config.json\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload\nsystemctl enable --now may-tcp-chain-landing.service\n";
            (await remote.RunScriptAsync(script + "systemctl restart may-tcp-chain-landing.service\n", TimeSpan.FromSeconds(25), true, token)).RequireSuccess("Disposable SS2022 setup failed.");
            var https = "import http.server,ssl\nclass Response(http.server.BaseHTTPRequestHandler):\n def do_GET(self):\n  body=b'198.51.100.30'\n  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)\n def log_message(self,*args):pass\nserver=http.server.HTTPServer(('127.0.0.1',9443),Response)\ncontext=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/opt/may-tcp-chain-fixture/https.pem','/opt/may-tcp-chain-fixture/https.key')\nserver.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()\n";
            var tlsSetup = "set -euo pipefail\numask 077\n";
            foreach (var (name, content) in new[] { ("https.py", https), ("https.pem", authority.ExportCertificatePem()), ("https.key", tlsKey.ExportPkcs8PrivateKeyPem()) }) tlsSetup += "printf '%s' '" + Convert.ToBase64String(Encoding.UTF8.GetBytes(content)) + "' | base64 -d > /opt/may-tcp-chain-fixture/" + name + "\n";
            tlsSetup += "cat > /etc/systemd/system/may-tcp-chain-https.service <<'EOF'\n[Unit]\nDescription=Disposable HTTPS application behind SS2022\n[Service]\nExecStart=/usr/bin/python3 /opt/may-tcp-chain-fixture/https.py\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload\nsystemctl enable --now may-tcp-chain-https.service\nsystemctl restart may-tcp-chain-https.service\n";
            (await remote.RunScriptAsync(tlsSetup, TimeSpan.FromSeconds(20), true, token)).RequireSuccess("Disposable HTTPS setup failed.");
        }
        var landingStateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plans[2])), "deployment-state.json"); var landingState = ArchiveStore.ReadJson(landingStateFile); landingState.Put("ServerConfigHashes.ShadowsocksLanding", JsonValue.Create(serverHash)); ArchiveStore.WriteJson(landingStateFile, landingState);
        var pair = ClientProfiles.Nodes(plans[2], secret).First(); secret.Clear();
        var scheme = ClientSchemes.New(f.Paths); var node = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = pair.Name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = pair.Clash.DeepClone(), ["sing_box"] = pair.SingBox.DeepClone(), ["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = "198.51.100.30" }, ["ManagedOrigin"] = ManagedNodeSources.Origin(f.Relative(plans[2]), pair) }; scheme["Nodes"]!.AsArray().Add(node); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        var config = TcpChains.New(f.Relative(plans[0])); config["RelayInstance"] = f.Relative(plans[1]); config["LandingInstance"] = f.Relative(plans[2]); config["FrontPort"] = 18443; config["RelayPort"] = 18444; config["FrontSources"] = new JsonArray("10.0.2.2/32"); config["FrontSourceAddress"] = plans[0].Text("Server.IPv4"); config["Landing"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner();
        var endpoints = new ClientDiagnosticEndpoints(new("https://127.0.0.1:9443"), new("https://127.0.0.1:9443"), new("https://127.0.0.1:9443"));
        var validator = new TcpChainVmValidation(new TcpChainValidation(new ClientRouteDiagnostics(assets, tools, endpoints, authority)), manifest.Number("Nodes.Front.ApplicationPort"));
        var engine = new WorkflowEngine(f.Store, factory, new FakeKeys(), user, new FakeValidation(), tcpChains: validator); var coordinator = new TaskCoordinator(f.Store, engine);
        var progress = new InlineProgress<TaskProgress>(p => { if (p.Stage != "tcp-forward-read" && p.Stage != "maintenance-transaction-status") Console.WriteLine("VM stage: " + p.Stage); });
        OperationRequest Request(string action) => new(OperationKind.TcpChain, f.Relative(plans[0]), new JsonObject { ["Action"] = action, ["Configuration"] = config.DeepClone() });
        async Task<TaskRecord> Execute(string action) => await coordinator.ExecuteAsync(coordinator.Review(Request(action)), Request(action), progress, token);
        var applied = await Execute("Apply"); Check(applied.Outcome == TaskOutcome.Completed, "real three-VM application failed: " + applied.SafeError);
        var chainFile = TcpChains.FileName(f.Paths, config.Text("Id")); var record = ArchiveStore.ReadJson(chainFile);
        Check(record.Text("Validation.Result.Status") == "Reachable" && record["Validation"]!["Segments"]!.AsArray().Count == 2, "whole encrypted chain or segment evidence absent");
        Check(record.Text("Validation.Result.EntryEgress.Family") == "IPv4", "real proxy HTTPS did not observe a matching egress family");
        var export = ClientSchemes.New(f.Paths); var projected = TcpChains.Project(f.Store, config, "US-West-LA Entry"); ForwardedNodeSources.Apply(f.Store, export, [projected], "US-West-LA Entry"); Check(!projected.Flag("clash.udp", true) && projected.Text("sing_box.network") == "tcp", "TCP SS2022 projection advertised UDP");
        var untrusted = new TcpChainVmValidation(new TcpChainValidation(new ClientRouteDiagnostics(assets, tools, endpoints)), manifest.Number("Nodes.Front.ApplicationPort"));
        Check((await untrusted.ValidateAsync(projected, f.Paths.Resolve("fixture-tls-untrusted"), new InlineProgress<string>(_ => { }), token)).Text("Status") != "Passed", "test-private TLS certificate bypassed default OS trust");
        var wrongName = new ClientDiagnosticEndpoints(new("https://localhost:9443"), new("https://localhost:9443"), new("https://localhost:9443"));
        var wrongHostname = new TcpChainVmValidation(new TcpChainValidation(new ClientRouteDiagnostics(assets, tools, wrongName, authority)), manifest.Number("Nodes.Front.ApplicationPort"));
        Check((await wrongHostname.ValidateAsync(projected, f.Paths.Resolve("fixture-tls-name"), new InlineProgress<string>(_ => { }), token)).Text("Status") != "Passed", "custom test CA disabled TLS hostname validation");
        var workbench = new ClientWorkbench(f.Store, tools, assets, Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") ?? "python");
        await workbench.BuildAsync(export, token); await workbench.ValidateAsync(export, token); Check(ClientSchemes.CanExport(export) == false && export.Text("Candidate.ValidationStatus") == "Passed", "generated dual-client chain configurations did not pass fixed cores");
        foreach (var name in new[] { "Front", "Relay" })
        {
            var host = manifest["Nodes"]![name]!; await using var remote = await factory.OpenAsync(new(host.Text("Address"), 22, "root", host.Text("KeyFile")), user, token);
            if (name == "Relay")
            {
                // Loopback is intentionally allowed by the forwarding ACL, so
                // rejection must originate from the other guest's real NIC.
                await using var outsider = await factory.OpenAsync(new(manifest.Text("Nodes.Landing.Address"), 22, "root", manifest.Text("Nodes.Landing.KeyFile")), user, token);
                var probe = "python3 - <<'PY'\nimport socket\ns=socket.socket();s.settimeout(2)\ntry:s.connect(('198.51.100.20',18444));s.sendall(b'test');data=s.recv(16);print('UNEXPECTED' if data else 'DENIED')\nexcept OSError:print('DENIED')\nPY";
                var response = await outsider.RunScriptAsync(probe, TimeSpan.FromSeconds(5), false, token); Check(response.Output.Trim() == "DENIED", "relay accepted a source other than its reviewed front");
            }
        }
        async Task Reboot(string name)
        {
            var host = manifest["Nodes"]![name]!; string before;
            await using (var remote = await factory.OpenAsync(new(host.Text("Address"), 22, "root", host.Text("KeyFile")), user, token))
            {
                before = (await remote.RunAsync("cat /proc/sys/kernel/random/boot_id", TimeSpan.FromSeconds(5), token)).Output.Trim();
                try { await remote.RunAsync("systemctl reboot", TimeSpan.FromSeconds(5), token); } catch (IOException) { }
            }
            for (var i = 0; i < 80; i++)
            {
                await Task.Delay(1500, token);
                try
                {
                    await using var remote = await factory.OpenAsync(new(host.Text("Address"), 22, "root", host.Text("KeyFile")), user, token);
                    var observed = (await remote.RunAsync("cat /proc/sys/kernel/random/boot_id", TimeSpan.FromSeconds(5), token)).Output.Trim();
                    if (observed != before && observed.Length > 0) { Console.WriteLine("VM reboot verified: " + name); return; }
                }
                catch (Exception e) when (e is IOException or OperationException or System.Net.Sockets.SocketException) { }
            }
            throw new Exception("Disposable reboot did not establish a new boot identity.");
        }
        await Reboot("Relay"); await Reboot("Front");
        Check((await Execute("Check")).Outcome == TaskOutcome.Completed, "active chain did not survive actual Debian reboots");
        Check((await Execute("Remove")).Outcome == TaskOutcome.Completed, "real chain removal failed");
        factory.Fault = "relay-commit-ack"; config["Id"] = Guid.NewGuid().ToString("N");
        var failed = await Execute("Apply"); Check(failed.Outcome == TaskOutcome.Failed && factory.LostAcknowledgements == 1, "real lost commit acknowledgement was not handled: " + failed.SafeError);
        foreach (var name in new[] { "Front", "Relay" })
        {
            var host = manifest["Nodes"]![name]!; await using var remote = await factory.OpenAsync(new(host.Text("Address"), 22, "root", host.Text("KeyFile")), user, token);
            var response = await remote.RunAsync("test ! -e /etc/may-tcp-forward/config.json && test ! -e /var/lib/may-vps-deploy/transaction.owner && ! systemctl is-active --quiet mxh-protocol-migration-rollback.timer && printf RESTORED", TimeSpan.FromSeconds(8), token);
            Check(response.Output.Trim() == "RESTORED" && response.ExitCode == 0, "real partial commit left rules, ownership or a rollback timer");
        }
        await using (var remote = await factory.OpenAsync(new(plans[2].Text("Server.IPv4"), 22, "root", manifest.Text("Nodes.Landing.KeyFile")), user, token)) Check(ArchiveStore.Digest(await remote.ReadFileAsync("/etc/sing-box/config.json", token)) == serverHash, "real orchestration touched the landing proxy bytes");
        var report = new JsonObject { ["Status"] = "Passed", ["Assertions"] = assertions, ["Debian"] = new JsonArray(12, 13), ["WholeChain"] = record["Validation"]!.DeepClone(), ["LostCommitAcknowledgement"] = factory.LostAcknowledgements, ["ProductionTargets"] = false, ["HostRoutesChanged"] = false };
        ArchiveStore.WriteJson(Path.Combine(Path.GetDirectoryName(manifestFile)!, "core-result.json"), report);
        f.Dispose();
        Console.WriteLine($"PASS: {assertions} real three-VM TCP orchestration, SS2022+HTTPS, source ACL, reboots, dual-client cores and lost-commit compensation assertions.");
    }
    private sealed class TcpChainVmValidation(ITcpChainValidation inner, int port) : ITcpChainValidation
    {
        public async Task<JsonObject> ValidateAsync(JsonObject node, string directory, IProgress<string> progress, CancellationToken ct)
        {
            // Only the test adapter maps the front guest's public endpoint to
            // QEMU's controller-loopback forward. No product fallback or route.
            var copy = node.DeepClone().AsObject(); copy["clash"]!["server"] = "127.0.0.1"; copy["clash"]!["port"] = port; copy["sing_box"]!["server"] = "127.0.0.1"; copy["sing_box"]!["server_port"] = port;
            var result = await inner.ValidateAsync(copy, directory, progress, ct); result["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node);
            ArchiveStore.WriteJson(SafePath.Resolve(directory, "vm-whole-chain-result.json"), result);
            if (result.Text("Status") != "Passed" && result.At("Result.Stages") is JsonArray stages) foreach (var stage in stages) Console.WriteLine("VM diagnostic: " + stage.Text("Id") + " " + stage.Text("Status") + " " + stage.Text("Detail"));
            return result;
        }
    }
    private sealed class TcpChainVmFactory(ArchiveStore store, JsonObject nodes) : IRemoteSessionFactory
    {
        private readonly Dictionary<string, SshSessionFactory> trust = new(StringComparer.Ordinal);
        public string Fault { get; set; } = ""; public int LostAcknowledgements { get; private set; }
        public async Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken ct)
        {
            var host = nodes.Select(p => p.Value!).Single(n => n.Text("Address") == endpoint.Host);
            if (endpoint.Port is not (22 or 2222)) throw new Exception("Unreviewed disposable management port.");
            if (!trust.TryGetValue(host.Text("Name"), out var inner))
            {
                // Product trust binds an address across SSH port transitions.
                // Distinct guests share 127.0.0.1 only in this fixture, so give
                // each its own temporary trust archive rather than weakening it.
                inner = new SshSessionFactory(new ArchiveStore(new AppPaths(store.Paths.Resolve("fixture-host-trust/" + host.Text("Name"))), new TestProtector()), TimeSpan.FromSeconds(15)); trust.Add(host.Text("Name"), inner);
            }
            var session = await inner.OpenAsync(endpoint with { Host = "127.0.0.1", Port = host.Number(endpoint.Port == 22 ? "ManagementPort" : "RescuePort") }, user, ct);
            return new FaultSession(this, session, host.Text("Name"));
        }
        private sealed class FaultSession(TcpChainVmFactory owner, IRemoteSession inner, string name) : IRemoteSession
        {
            public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct) => inner.RunAsync(command, timeout, ct);
            public async Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutation, CancellationToken ct)
            {
                var result = await inner.RunScriptAsync(payload, timeout, mutation, ct);
                if (result.ExitCode != 0) Console.WriteLine("VM remote failure: " + payload.Split('\n')[0] + " " + result.Error);
                if (name == "Inbound" && owner.Fault == "inbound-commit-ack" && payload.StartsWith("# MXH asset: maintenance-transaction-commit.sh\n", StringComparison.Ordinal) && result.ExitCode == 0)
                { owner.Fault = ""; owner.LostAcknowledgements++; throw new IOException("Disposable lost acknowledgement after real inbound commit."); }
                if (name == "Relay" && owner.Fault == "relay-commit-ack" && payload.StartsWith("# MXH asset: maintenance-transaction-commit.sh\n", StringComparison.Ordinal) && result.ExitCode == 0)
                { owner.Fault = ""; owner.LostAcknowledgements++; throw new IOException("Disposable transport fault after the real remote commit."); }
                return result;
            }
            public Task<byte[]> ReadFileAsync(string path, CancellationToken ct) => inner.ReadFileAsync(path, ct);
            public Task DownloadAsync(string path, string target, CancellationToken ct) => inner.DownloadAsync(path, target, ct);
            public ValueTask DisposeAsync() => inner.DisposeAsync();
        }
    }
}
