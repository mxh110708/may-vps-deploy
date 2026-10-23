using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunUdpProxyTests()
    {
        using var f = new Fixture(repository); await UdpProxySourceExperience(f); await UdpProxyWorkflow(f); await UdpProxyRuntime(f);
        Console.WriteLine($"PASS: {assertions} UDP proxy source, encrypted datagram, evidence and cancellation assertions; no production connections.");
    }
    private static (JsonObject Scheme, JsonObject Node, JsonObject Config) UdpProxySource(Fixture f, string method, string password, int targetPort, int listenPort)
    {
        var scheme = ClientSchemes.New(f.Paths); scheme["Name"] = "UDP synthetic source";
        var link = "ss://" + method + ":" + Uri.EscapeDataString(password) + "@192.0.2.20:" + targetPort + "#UDP-proxy";
        ClientNodeImport.Apply(scheme, ClientNodeImport.Preview(link, scheme, scheme["Layout"]!.Strings("region_groups")[0]));
        var node = scheme["Nodes"]![0]!.AsObject();
        f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        var config = UdpConfig(listenPort); config["Rules"]![0]!["TargetAddress"] = "192.0.2.20"; config["Rules"]![0]!["TargetPort"] = targetPort;
        config["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Shadowsocks", ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node), ["ResolverAddress"] = "127.0.0.1", ["ResolverPort"] = 53, ["QueryName"] = "example.test", ["QueryType"] = "A" };
        return (scheme, node, config);
    }
    private async Task UdpProxySourceExperience(Fixture f)
    {
        var (scheme, node, config) = UdpProxySource(f, "aes-128-gcm", "synthetic-udp-proxy-secret", 55103, 55104);
        var before = config.ToJsonString(); var normalized = UdpForwarding.Normalize(config);
        Check(config.ToJsonString() == before && normalized["Rules"]![0]!.Text("Validation.Type") == "Shadowsocks", "UDP proxy normalization mutated input");
        var plan = f.Plan("UDP-proxy-source"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        var relative = f.Relative(plan); var state = ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(relative), "deployment-state.json"));
        var request = new OperationRequest(OperationKind.UdpForward, relative, UdpForwarding.Options(state, "Apply", config));
        var calls = 0; var coordinator = new TaskCoordinator(f.Store, new FakeWorkflow(_ => { calls++; return Task.FromResult(TaskOutcome.Completed); }));
        var review = coordinator.Review(request);
        Check(review.Summary.Contains("Shadowsocks UDP") && review.Summary.Contains("example.test") && !review.Summary.Contains("synthetic-udp-proxy-secret") && !request.Options.ToJsonString().Contains("synthetic-udp-proxy-secret"), "UDP source review omitted scope or leaked credentials");
        foreach (var edit in new Action<JsonObject>[] { c => c["Rules"]![0]!["Validation"]!["ResolverAddress"] = "::", c => c["Rules"]![0]!["Validation"]!["ResolverAddress"] = "224.0.0.1", c => c["Rules"]![0]!["Validation"]!["ResolverAddress"] = "dns.example", c => c["Rules"]![0]!["Validation"]!["ResolverPort"] = 0, c => c["Rules"]![0]!["Validation"]!["ResolverPort"] = "53", c => c["Rules"]![0]!["Validation"]!["NodeFingerprint"] = "stale", c => c["Rules"]![0]!["Validation"]!["Password"] = "not-allowed" })
        { var bad = config.DeepClone().AsObject(); edit(bad); Refuses(() => UdpForwarding.Normalize(bad), "invalid UDP proxy destination, source or secret field accepted"); }
        var actual = UdpForwarding.ProxyConfiguration(node, config["Rules"]![0]!["Validation"]!.AsObject(), "127.0.0.2", 55104, 55105);
        Check(actual["inbounds"]![0]!.Text("network") == "udp" && actual["inbounds"]![0]!.Text("listen") == "127.0.0.1" && actual["outbounds"]!.AsArray().Count == 1 && actual["outbounds"]![0]!.Text("network") == "udp" && actual["outbounds"]![0]!.Text("server") == "127.0.0.2" && actual["outbounds"]![0]!.Number("server_port") == 55104 && !actual["outbounds"]!.AsArray().Any(n => n!.Text("type") == "direct") && actual.Text("route.final") == "udp-proxy", "UDP probe escaped forwarded endpoint or gained TCP/direct fallback");
        var mismatch = config.DeepClone().AsObject(); mismatch["Rules"]![0]!["TargetPort"] = 55106;
        Refuses(() => UdpForwarding.Prepare(f.Store, request with { Options = UdpForwarding.Options(state, "Apply", mismatch) }), "UDP source and target mismatch accepted");
        var schemeFile = ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id"));
        node["sing_box"]!["password"] = "synthetic-replaced-secret"; f.Store.WriteSecret(schemeFile, scheme);
        await RefusesAsync(() => coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default), "changed UDP source survived review");
        Check(calls == 0, "changed UDP credentials reached workflow");
        node["sing_box"]!["password"] = "synthetic-udp-proxy-secret";
        foreach (var key in new[] { "udp_over_tcp", "multiplex", "plugin", "detour", "bind_interface" })
        {
            node["sing_box"]![key] = "unsupported"; f.Store.WriteSecret(schemeFile, scheme);
            config["Rules"]![0]!["Validation"]!["NodeFingerprint"] = ArchiveStore.Fingerprint(node);
            Refuses(() => UdpForwarding.Prepare(f.Store, request with { Options = UdpForwarding.Options(state, "Apply", config) }), "UDP transport override or dependency silently discarded");
            node["sing_box"]!.AsObject().Remove(key);
        }
        f.Store.WriteSecret(schemeFile, scheme); config["Rules"]![0]!["Validation"]!["NodeFingerprint"] = ArchiveStore.Fingerprint(node);
        File.Delete(schemeFile);
        Refuses(() => UdpForwarding.Prepare(f.Store, request with { Options = UdpForwarding.Options(state, "Apply", config) }), "removed UDP source accepted");
    }
    private async Task UdpProxyRuntime(Fixture f)
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: encrypted UDP runtime uses the bundled Windows core; source/evidence checks still run."); return; }
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner(); var executable = assets.ResolveCore("sing-box");
        var directory = f.Paths.Resolve("private/udp-proxy-runtime"); Directory.CreateDirectory(directory);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(100));
        using var dns = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var dnsPort = ((IPEndPoint)dns.Client.LocalEndPoint!).Port; var queries = 0;
        var server = Task.Run(async () => { while (true) { var packet = await dns.ReceiveAsync(stop.Token); Interlocked.Increment(ref queries); await dns.SendAsync(DnsAnswer(packet.Buffer), packet.RemoteEndPoint, stop.Token); } });
        try
        {
            var cases = new[] { "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305" }.Select(method => (Method: method, MultiUser: false))
                .Concat(new[] { (Method: "2022-blake3-aes-128-gcm", MultiUser: true), (Method: "2022-blake3-aes-256-gcm", MultiUser: true) });
            foreach (var (method, multiUser) in cases)
            {
                var password = method.StartsWith("2022-") ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(method.Contains("aes-128") ? 16 : 32)) : "synthetic-core-only-secret";
                var userKey = multiUser ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(method.Contains("aes-128") ? 16 : 32)) : null;
                using var reservation = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var ssPort = ((IPEndPoint)reservation.Client.LocalEndPoint!).Port;
                await using var relay = new ProxyDatagramRelay(new(IPAddress.Loopback, ssPort));
                await using var ipv6Relay = multiUser && method.Contains("aes-128") && Socket.OSSupportsIPv6 ? new ProxyDatagramRelay(new(IPAddress.Loopback, ssPort), IPAddress.IPv6Loopback, relay.Port) : null;
                var (scheme, node, config) = UdpProxySource(f, method, multiUser ? password + ":" + userKey : password, ssPort, relay.Port);
                if (ipv6Relay != null) config["Rules"]![0]!["ListenFamily"] = "DualStack";
                var check = config["Rules"]![0]!["Validation"]!.AsObject(); check["ResolverPort"] = dnsPort;
                var ss = new JsonObject { ["log"] = new JsonObject { ["level"] = "error" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "shadowsocks", ["listen"] = "127.0.0.1", ["listen_port"] = ssPort, ["network"] = "udp", ["method"] = method, ["password"] = password }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" }), ["route"] = new JsonObject { ["final"] = "direct" } };
                if (multiUser) ss["inbounds"]![0]!["users"] = new JsonArray(new JsonObject { ["name"] = "fixture", ["password"] = userKey });
                var file = SafePath.Resolve(directory, "server.private.json"); ArchiveStore.WriteJson(file, ss);
                (await tools.RunAsync(executable, ["check", "-c", file], null, TimeSpan.FromSeconds(10), stop.Token)).RequireSuccess("Synthetic UDP server config rejected.");
                var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var arg in new[] { "run", "-c", file }) start.ArgumentList.Add(arg);
                reservation.Dispose(); using var process = Process.Start(start)!; var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
                try
                {
                    await Task.Delay(150, stop.Token);
                    var plan = new JsonObject { ["Server"] = new JsonObject { ["IPv4"] = "127.0.0.1", ["IPv6"] = "::1" } }; var adapter = new UdpForwardValidation(f.Store, assets, tools);
                    foreach (var type in new[] { "A", "AAAA" })
                    {
                        check["QueryType"] = type; var previous = queries;
                        var result = await adapter.ValidateAsync(plan, config, directory, new InlineProgress<string>(_ => { }), stop.Token);
                        UdpForwarding.RequireValidation(plan, config, result);
                        Check(queries > previous && relay.Packets > 0 && result["Items"]![0]!["Checks"]![0]!.Text("Transport") == "UDP", method + " did not perform real encrypted UDP DNS through relay");
                        var missing = result.DeepClone().AsObject(); missing["Items"]![0]!["Checks"]![0]!.AsObject().Remove("Transport"); Refuses(() => UdpForwarding.RequireValidation(plan, config, missing), "proxy validation accepted missing UDP evidence");
                        var wrong = result.DeepClone().AsObject(); wrong["Items"]![0]!["Checks"]![0]!["ResolverPort"] = dnsPort + 1; Refuses(() => UdpForwarding.RequireValidation(plan, config, wrong), "proxy validation accepted a different DNS target");
                    }
                    if (method == "aes-128-gcm")
                    {
                        var previous = queries;
                        node["sing_box"]!["password"] = "synthetic-incorrect-password"; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme); check["NodeFingerprint"] = ArchiveStore.Fingerprint(node);
                        await RefusesAsync(async () => { await adapter.ValidateAsync(plan, config, directory, new InlineProgress<string>(_ => { }), stop.Token); }, "incorrect UDP proxy credentials passed");
                        Check(queries == previous, "incorrect proxy credentials reached plain DNS");
                        node["sing_box"]!["password"] = password; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme); check["NodeFingerprint"] = ArchiveStore.Fingerprint(node);
                        relay.Forward = false;
                        await RefusesAsync(async () => { await adapter.ValidateAsync(plan, config, directory, new InlineProgress<string>(_ => { }), stop.Token); }, "unreachable relay passed through DNS/direct fallback");
                        Check(queries == previous, "blocked relay still sent a direct DNS query");
                        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(350)); var cancelled = false;
                        try { await adapter.ValidateAsync(plan, config, directory, new InlineProgress<string>(_ => { }), cancel.Token); } catch (OperationCanceledException) { cancelled = true; }
                        Check(cancelled && !Directory.EnumerateFiles(directory, "probe.private.json", SearchOption.AllDirectories).Any(), "UDP probe ignored cancellation or retained credentials");
                    }
                }
                finally { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); await Task.WhenAll(output, error); File.Delete(file); }
            }
        }
        finally { stop.Cancel(); try { await server; } catch (OperationCanceledException) { } }
    }
    private async Task UdpProxyWorkflow(Fixture f)
    {
        foreach (var scenario in new[] { "success", "missing-evidence", "source-changed", "cancelled", "failed" })
        {
            var (scheme, node, config) = UdpProxySource(f, "aes-128-gcm", "synthetic-workflow-secret", 55103, 55104);
            var plan = f.Plan("UDP-proxy-" + scenario); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
            var relative = f.Relative(plan); var directory = f.Paths.Instance(relative); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
            var remote = new ForwardRemote("udp"); remote.Inner.SeedProtocols(plan); remote.Inner.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes("existing proxy sentinel");
            var adapter = new ProxyEvidenceValidation(scenario, () => { node["sing_box"]!["password"] = "synthetic-source-change"; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme); });
            var engine = new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), udpForwarding: adapter);
            Exception? failure = null;
            try { await engine.ExecuteAsync(new(OperationKind.UdpForward, relative, UdpForwarding.Options(state, "Apply", config)), Guid.NewGuid().ToString("N"), new InlineProgress<TaskProgress>(_ => { }), default); } catch (Exception e) { failure = e; }
            var saved = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"));
            if (scenario == "success") Check(failure == null && saved["UdpForwarding"] != null && remote.Configuration != null, "valid proxy UDP evidence did not commit");
            else { Check(failure != null && saved["UdpForwarding"] == null && remote.Configuration == null && ArchiveStore.ReadJson(SafePath.Resolve(directory, "operation-pending.dotnet.json")).Text("Phase") == "RolledBack", "UDP proxy rollback: " + scenario + "; failure=" + failure?.GetType().Name + "; detail=" + failure?.Message + "; phase=" + ArchiveStore.ReadJson(SafePath.Resolve(directory, "operation-pending.dotnet.json")).Text("Phase")); }
            Check(remote.ApplyCalls == 1 && !remote.Inner.Commands.Any(c => c is "tcp-forward-apply.sh" or "server-outbound-apply.sh" or "protocol-lifecycle-apply-state.sh"), "UDP proxy validation replayed or expanded its mutation scope");
        }
    }
    private sealed class ProxyEvidenceValidation(string scenario, Action changeSource) : IUdpForwardValidation
    {
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject configuration, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
        {
            if (scenario == "cancelled") throw new OperationCanceledException();
            if (scenario == "failed") throw new OperationException("synthetic UDP response absent");
            var items = new JsonArray();
            foreach (var rule in UdpForwarding.Rules(configuration))
            {
                var checks = new JsonArray();
                foreach (var address in TcpForwarding.ProbeAddresses(plan, rule))
                {
                    var check = rule["Validation"]!.DeepClone().AsObject(); check.Remove("SchemeId"); check.Remove("NodeId"); check["Address"] = address; check["Transport"] = scenario == "missing-evidence" ? "TCP" : "UDP"; check["Status"] = "Passed"; check["ResponseMatched"] = true; checks.Add(check);
                }
                items.Add(new JsonObject { ["Id"] = rule.Text("Id"), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "ForwardedDatagramApplication", ["Checks"] = checks });
            }
            if (scenario == "source-changed") changeSource();
            return Task.FromResult(new JsonObject { ["Status"] = "Passed", ["Items"] = items });
        }
    }
    private sealed class ProxyDatagramRelay : IAsyncDisposable
    {
        private readonly UdpClient incoming; private readonly CancellationTokenSource stop = new(); private readonly Task loop;
        public int Port => ((IPEndPoint)incoming.Client.LocalEndPoint!).Port;
        public int Packets { get; private set; }
        public bool Forward { get; set; } = true;
        public ProxyDatagramRelay(IPEndPoint target, IPAddress? listener = null, int port = 0)
        {
            listener ??= IPAddress.Loopback; incoming = new UdpClient(listener.AddressFamily);
            if (listener.AddressFamily == AddressFamily.InterNetworkV6) incoming.Client.DualMode = false;
            incoming.Client.Bind(new IPEndPoint(listener, port));
            loop = Task.Run(async () =>
            {
                while (true)
                {
                    var packet = await incoming.ReceiveAsync(stop.Token); Packets++; if (!Forward) continue;
                    using var upstream = new UdpClient(target.AddressFamily); upstream.Connect(target);
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); deadline.CancelAfter(TimeSpan.FromSeconds(2));
                    try { await upstream.SendAsync(packet.Buffer, deadline.Token); var response = await upstream.ReceiveAsync(deadline.Token); await incoming.SendAsync(response.Buffer, packet.RemoteEndPoint, stop.Token); }
                    catch (OperationCanceledException) when (!stop.IsCancellationRequested) { }
                    catch (SocketException) when (!stop.IsCancellationRequested) { }
                }
            });
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); try { await loop; } catch (OperationCanceledException) { } finally { incoming.Dispose(); stop.Dispose(); } }
    }
}
