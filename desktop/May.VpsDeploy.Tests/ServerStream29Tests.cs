using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunServerStream29Tests(bool modelOnly = false)
    {
        await ServerStream29Model();
        if (!modelOnly) await ServerStream29Runtime();
        Console.WriteLine($"PASS: {assertions} round29 next-hop parameters, capabilities, real paths and scoped recovery assertions; modelOnly={modelOnly}.");
    }
    public async Task RunServerProbeInputTests() { await ServerStream29PrivateInput(); Console.WriteLine($"PASS: {assertions} bounded private probe input assertions."); }
    private static JsonObject Stream29Node(string scenario, int port = 24029)
    {
        var protocol = scenario.StartsWith("vless", StringComparison.Ordinal) || scenario == "reality" ? "vless" : scenario.StartsWith("anytls", StringComparison.Ordinal) ? "anytls" : "trojan";
        var tls = new JsonObject { ["enabled"] = true, ["server_name"] = "next.example.test", ["min_version"] = "1.3", ["alpn"] = new JsonArray(scenario.EndsWith("grpc", StringComparison.Ordinal) ? "h2" : "http/1.1") };
        var native = new JsonObject { ["type"] = protocol, ["tag"] = "synthetic next hop", ["server"] = "192.0.2.29", ["server_port"] = port, ["tls"] = tls };
        if (protocol == "vless") { native["uuid"] = Guid.NewGuid().ToString(); native["packet_encoding"] = "xudp"; if (scenario is "reality" or "vless-vision") native["flow"] = "xtls-rprx-vision"; }
        else native["password"] = "synthetic-next-hop-password-29";
        if (protocol == "anytls") { native["idle_session_check_interval"] = "30s"; native["idle_session_timeout"] = "45s"; native["min_idle_session"] = 1; native["client_metadata"] = "may-deploy-test"; }
        if (scenario == "reality")
        {
            tls.Remove("min_version"); tls.Remove("alpn"); tls["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = "chrome" };
            tls["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = ServerConfigurations.RandomKey(32).Replace('+', '-').Replace('/', '_').TrimEnd('='), ["short_id"] = "ab12cd34" };
        }
        if (scenario.EndsWith("ws", StringComparison.Ordinal)) native["transport"] = new JsonObject { ["type"] = "ws", ["path"] = "/next-hop/", ["headers"] = new JsonObject { ["Host"] = "front.example.test" }, ["max_early_data"] = 512, ["early_data_header_name"] = "Sec-WebSocket-Protocol" };
        if (scenario.EndsWith("grpc", StringComparison.Ordinal)) native["transport"] = new JsonObject { ["type"] = "grpc", ["service_name"] = "MayNextHop" };
        if (scenario == "anytls-ech") tls["ech"] = new JsonObject { ["enabled"] = true, ["config"] = new JsonArray("-----BEGIN ECH CONFIGS-----\nAAQBAgME\n-----END ECH CONFIGS-----") };
        return new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "Synthetic " + scenario, ["kind"] = "landing", ["sing_box"] = native };
    }
    private static string[] Stream29Scenarios => ["reality", "vless-tls", "vless-vision", "trojan", "anytls", "anytls-ech", "vless-ws", "trojan-ws", "vless-grpc", "trojan-grpc"];
    private async Task ServerStream29Model()
    {
        foreach (var scenario in Stream29Scenarios)
        {
            using var f = new Fixture(repository); var node = Stream29Node(scenario); var native = node["sing_box"]!.AsObject(); var original = ArchiveStore.Fingerprint(node);
            var convertible = scenario is "reality" or "vless-tls" or "vless-vision" or "trojan";
            Check(ServerOutboundRouting.SupportedNode(node, "AnyTlsEntry") && ServerOutboundRouting.SupportedNode(node, "RealityEntry") == convertible, "round29 core support matrix changed parameters or guessed a conversion: " + scenario);
            var next = ServerOutboundRouting.NextHop(node); var compared = next.DeepClone().AsObject(); compared["tag"] = native["tag"]!.DeepClone();
            Check(JsonNode.DeepEquals(native, compared) && ArchiveStore.Fingerprint(node) == original, "round29 normalized away source protocol/TLS/session/transport parameters");
            var forwardedCandidate = node.DeepClone().AsObject(); forwardedCandidate["ForwardedOrigin"] = new JsonObject { ["Instance"] = "Example/Other/May-VPS-Deploy" };
            Check(!ServerOutboundRouting.SupportedNode(forwardedCandidate) && ServerOutboundRouting.SupportedIndependentNode(forwardedCandidate), "fixed-role source restrictions hid a previously supported independent stream candidate");
            foreach (var field in new[] { "detour", "network", "bind_interface", "certificate_path", "multiplex" }) { var bad = node.DeepClone().AsObject(); bad["sing_box"]![field] = "unsupported"; Refuses(() => ServerOutboundRouting.NextHop(bad), "round29 accepted hidden native dial/relay field " + field); }
            foreach (var field in new[] { "insecure", "certificate_path", "key", "enabled", "alpn" })
            {
                var bad = node.DeepClone().AsObject(); bad["sing_box"]!["tls"]![field] = field == "insecure" ? JsonValue.Create(true) : field == "enabled" ? JsonValue.Create(false) : JsonValue.Create("unsupported");
                Refuses(() => ServerOutboundRouting.NextHop(bad), "round29 relaxed TLS or accepted a file/private field " + field);
            }
            var wrong = node.DeepClone().AsObject(); wrong["sing_box"]![native.Text("type") == "vless" ? "uuid" : "password"] = ""; Refuses(() => ServerOutboundRouting.NextHop(wrong), "round29 accepted missing authentication");
            if (native.Text("type") == "anytls") { wrong = node.DeepClone().AsObject(); wrong["sing_box"]!["tls"]!.AsObject().Remove("min_version"); wrong["sing_box"]!["tls"]!["max_version"] = "1.2"; Refuses(() => ServerOutboundRouting.NextHop(wrong), "AnyTLS next-hop TLS maximum bypassed the protocol version requirement"); }
            var plan = f.Plan("Stream29-" + scenario); var secrets = Fixture.RealitySecrets(); var basis = ServerConfigurations.AnyTls(plan, secrets);
            foreach (var role in ServerOutboundRouting.Roles.Where(role => ServerOutboundRouting.SupportedNode(node, role)))
            {
                var baseline = role == "RealityEntry" ? ServerConfigurations.Xray(plan, secrets) : basis;
                var extra = Stream29Node(scenario, 24030);
                var preview = ServerOutboundRouting.Build(role, baseline, null, node, "198.51.100.29", plan, destinationRules: new JsonArray(HopRule("Domain", "research.example.test", HopA)), additionalHops: [new(HopA, extra, "198.51.100.30")]);
                var output = preview.Configuration["outbounds"]!.AsArray().Single(o => o!.Text("tag") == ServerOutboundRouting.Tag)!;
                Check(ServerOutboundRouting.OutboundProtocol(output) == native.Text("type") && JsonNode.DeepEquals(baseline["inbounds"], preview.Configuration["inbounds"]) && preview.Summary.Contains(ServerOutboundRouting.ConnectionLabel(native)), "round29 changed ingress identity, lost protocol or omitted review scope");
                Check(!preview.Summary.Contains(native.Text("type") == "vless" ? native.Text("uuid") : native.Text("password")), "round29 preview disclosed next-hop authentication");
                Check(JsonNode.DeepEquals(baseline, ServerOutboundRouting.Build(role, preview.Configuration, preview.Metadata, null, "", plan).Configuration), "round29 route removal did not restore the original component");
                plan.Put("ServerOutbound." + role, preview.Metadata!.DeepClone()); var requests = ServerOutboundRouting.ProbeRequests(role, preview.Configuration, plan);
                var proof = new JsonObject { ["Status"] = "Passed", ["Items"] = new JsonArray(new JsonObject { ["Id"] = HopA, ["Status"] = "Passed", ["Egress"] = "198.51.100.30", ["From"] = "EntryServer", ["Network"] = "TCP", ["Transport"] = "TCP", ["ValidatedProtocol"] = native.Text("type") }) };
                ServerOutboundRouting.RequireHopValidation(requests, proof);
                foreach (var field in new[] { "ValidatedProtocol", "Transport" }) { var bad = proof.DeepClone().AsObject(); bad["Items"]![0]![field] = "other"; Refuses(() => ServerOutboundRouting.RequireHopValidation(requests, bad), "round29 accepted incorrect native protocol proof"); }
                Check(ServerOutboundRouting.ProbeRequests(role, preview.Configuration, plan).Count == 1, "round29 named hop acceptance was not retained");
            }
            if (!convertible) Refuses(() => ServerOutboundRouting.XrayNextHop(native), "round29 stripped unsupported stream/ECH or added a hidden relay");
            plan.Remove("ServerOutbound");
            var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var first = InboundCatalog.AddInbound(model, credentials, "Shadowsocks2022"); var second = InboundCatalog.AddInbound(model, credentials, "Shadowsocks2022");
            var scheme = ClientSchemes.New(f.Paths); scheme["Nodes"] = new JsonArray(node.DeepClone()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            var resource = InboundCatalog.AddDirect(model, "Stream " + scenario); resource["Kind"] = "Proxy"; resource["Source"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = node.Text("Id"), ["Fingerprint"] = ArchiveStore.Fingerprint(node) }; first["OutboundId"] = resource.Text("Id");
            Check(InboundRendering.Configuration(f.Store, plan, model, credentials, first)["outbounds"]![0]!.Text("type") == native.Text("type") && InboundRendering.RequiresApplicationUdp(f.Store, f.Relative(plan), model, first.Text("Id")), "round29 independent next hop bypassed protocol or UDP acceptance");
            scheme["Nodes"] = new JsonArray(forwardedCandidate.DeepClone()); resource["Source"]!["Fingerprint"] = ArchiveStore.Fingerprint(forwardedCandidate); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            Refuses(() => InboundRendering.Configuration(f.Store, plan, model, credentials, first), "round29 candidate filtering bypassed forwarding provenance qualification");
            scheme["Nodes"] = new JsonArray(node.DeepClone()); resource["Source"]!["Fingerprint"] = original; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
            var remote = new InboundTestRemote(); remote.Inner.SeedProtocols(plan); var validator = new QuicHopModelValidation(f.Store); var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: validator)); var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json");
            async Task<TaskRecord> Apply()
            { var request = new OperationRequest(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "Apply", model, credentials)); return await coordinator.ExecuteAsync(coordinator.Review(request), request, new InlineProgress<TaskProgress>(_ => { }), default); }
            Check((await Apply()).Outcome == TaskOutcome.Completed, "round29 independent stream application failed"); var origin = InboundSources.Create(f.Store, f.Relative(plan), first.Text("Id"), first.Strings("UserIds")[0], "IPv4"); var before = ArchiveStore.Fingerprint(remote.Current!);
            credentials["Inbounds"]![first.Text("Id")]!["ServerKey"] = ServerConfigurations.RandomKey(16); validator.UdpPassed = false;
            Check((await Apply()).Outcome == TaskOutcome.Failed && ArchiveStore.Fingerprint(remote.Current!) == before && remote.LastAffected.SequenceEqual(new[] { first.Text("Id") }), "round29 HTTPS-only path committed or recovery changed another inbound");
            validator.UdpPassed = true; Check((await Apply()).Outcome == TaskOutcome.Completed, "round29 stream failed to apply after scoped recovery"); Refuses(() => InboundSources.VerifyNodes(f.Store, [origin]), "round29 credential rotation preserved stale source qualification");
            scheme["Nodes"]![0]!["sing_box"]![native.Text("type") == "vless" ? "uuid" : "password"] = native.Text("type") == "vless" ? Guid.NewGuid().ToString() : "changed-synthetic-password"; f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
            Refuses(() => InboundRendering.Configuration(f.Store, plan, model, credentials, first), "round29 silently followed a changed next-hop source"); Check(second.Text("Id") != first.Text("Id"), "round29 changed unrelated identities"); credentials.Clear();
        }
        using (var current = System.Diagnostics.Process.GetCurrentProcess())
        {
            var identity = new TestProcessIdentity(current); Check(!identity.Exited, "live owned process was marked as exited"); Check((identity with { StartedUtc = identity.StartedUtc.AddSeconds(-1) }).Exited, "reused PID was claimed as the original owned process");
        }
        await ServerStream29PrivateInput();
    }
    private async Task ServerStream29PrivateInput()
    {
        var bash = OperatingSystem.IsWindows() ? "D:/Program Files/Git/bin/bash.exe" : "/bin/bash";
        if (!File.Exists(bash)) { Console.WriteLine("SKIP: private probe transport shell fixture requires Bash."); return; }
        using var f = new Fixture(repository); var script = f.Paths.Resolve("assets/remote/probe-input-check.sh"); Directory.CreateDirectory(Path.GetDirectoryName(script)!);
        // Git Bash on NTFS reports synthesized Unix modes; it cannot prove a
        // Debian permission bit. The same test enforces 0600 on Unix CI.
        var permission = OperatingSystem.IsWindows() ? "" : "[[ $(find \"$VPS_PARAM_PROBES_JSON_FILE\" -prune -perm 0600) == \"$VPS_PARAM_PROBES_JSON_FILE\" ]]\n";
        if (OperatingSystem.IsWindows()) Console.WriteLine("SKIP: NTFS/Git Bash is not POSIX permission evidence; Unix CI enforces probe-input mode 0600.");
        File.WriteAllText(script, "set -euo pipefail\n[[ ! ${VPS_PARAM_PROBES_JSON+x} && -f \"$VPS_PARAM_PROBES_JSON_FILE\" && ! -L \"$VPS_PARAM_PROBES_JSON_FILE\" ]]\n" + permission + "[[ $(wc -c < \"$VPS_PARAM_PROBES_JSON_FILE\") == \"$VPS_PARAM_BYTES\" ]]\nprintf 'INPUT_OK\\n'\nexit \"$VPS_PARAM_EXIT\"\n");
        var work = f.Paths.Resolve("private/probe-transport"); Directory.CreateDirectory(work); var posix = work.Replace('\\', '/'); if (OperatingSystem.IsWindows()) posix = "/" + char.ToLowerInvariant(posix[0]) + posix[2..];
        var input = string.Concat(Enumerable.Repeat("synthetic-probe-only-", 26000));
        foreach (var exit in new[] { 0, 9 })
        {
            var payload = new RemoteAssets(f.Paths).Payload("probe-input-check.sh", new Dictionary<string,string> { ["PROBES_JSON"] = input, ["BYTES"] = input.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), ["EXIT"] = exit.ToString(System.Globalization.CultureInfo.InvariantCulture) }).Replace("/tmp/may-server-probes.", posix + "/probe-input.");
            var result = await new ExternalToolRunner().RunAsync(bash, ["-s"], payload, TimeSpan.FromSeconds(15), default);
            Check(result.ExitCode == exit && result.Output.Trim() == "INPUT_OK" && !result.Output.Contains(input[..40]), "private probe transport failed permission/size/environment boundaries: " + result.ExitCode + " / " + result.Error[..Math.Min(256, result.Error.Length)]);
            Check(Directory.GetFiles(work, "probe-input.*").Length == 0, "private probe document survived normal/error shell exit");
        }
    }
}
