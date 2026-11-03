using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task ServerStream29Runtime()
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: round29 fixed Windows cores; portable model and remote validators still run."); return; }
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(6)); var ct = budget.Token; var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner(); var directory = f.Paths.Resolve("private/server-stream-29"); Directory.CreateDirectory(directory); var xray = Environment.GetEnvironmentVariable("MAY_TEST_XRAY");
        using var key = RSA.Create(2048); var request = new CertificateRequest("CN=next.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("next.example.test"); san.AddDnsName("entry.example.test"); san.AddDnsName("www.example.com"); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build()); request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        await using var https = await HysteriaHttpsTarget.Start(repository, f, cert, key, ct); await using var httpTarget = new Policy28HttpTarget(ct, IPAddress.Parse("127.0.0.3")); await using var dns = new TuicDnsTarget(IPAddress.Parse("127.0.0.2"));
        var camouflagePort = MixedPort(); var camouflageConfig = new JsonObject { ["log"] = new JsonObject { ["disabled"] = true }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "anytls", ["listen"] = "127.0.0.1", ["listen_port"] = camouflagePort, ["users"] = new JsonArray(new JsonObject { ["password"] = "synthetic-camouflage-only" }), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "www.example.com", ["min_version"] = "1.3", ["alpn"] = new JsonArray("h2"), ["certificate"] = new JsonArray(cert.ExportCertificatePem()), ["key"] = new JsonArray(key.ExportPkcs8PrivateKeyPem()) } }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct" }) };
        await using var camouflage = await Policy28Core.Start(assets.ResolveCore("sing-box"), camouflageConfig, directory, false, camouflagePort, false, ct); var children = new List<TestProcessIdentity> { new(camouflage.Process) }; var cases = new JsonArray(); var pair = await InboundKeyGeneration.RealityAsync(assets, tools, ct); var ech = await InboundKeyGeneration.EchAsync(assets, tools, "next.example.test", ct);
        foreach (var scenario in Stream29Scenarios)
        {
            if (scenario is "reality" or "vless-vision" && string.IsNullOrEmpty(xray)) { Console.WriteLine("SKIP: round29 Reality/Vision peer requires fixed MAY_TEST_XRAY."); continue; }
            var source = Stream29Node(scenario, MixedPort()); var native = source["sing_box"]!.AsObject(); var protocol = native.Text("type");
            var sourceTls = native["tls"]!.AsObject();
            if (scenario == "reality") { sourceTls["reality"]!["public_key"] = pair.Text("PublicKey"); sourceTls["server_name"] = "www.example.com"; }
            else sourceTls["certificate"] = new JsonArray(cert.ExportCertificatePem());
            if (scenario == "anytls-ech") sourceTls["ech"]!["config"] = new JsonArray(ech.Text("Config"));
            JsonObject Landing()
            {
                if (scenario == "reality") return new JsonObject { ["log"] = new JsonObject { ["loglevel"] = "none" }, ["inbounds"] = new JsonArray(new JsonObject { ["listen"] = "127.0.0.1", ["port"] = native.Number("server_port"), ["protocol"] = "vless", ["tag"] = "source", ["settings"] = new JsonObject { ["decryption"] = "none", ["clients"] = new JsonArray(new JsonObject { ["id"] = native.Text("uuid"), ["flow"] = "xtls-rprx-vision" }) }, ["streamSettings"] = new JsonObject { ["network"] = "raw", ["security"] = "reality", ["realitySettings"] = new JsonObject { ["show"] = false, ["target"] = "127.0.0.1:" + camouflagePort, ["xver"] = 0, ["serverNames"] = new JsonArray("www.example.com"), ["privateKey"] = pair.Text("PrivateKey"), ["shortIds"] = new JsonArray("ab12cd34") } } }), ["outbounds"] = new JsonArray(new JsonObject { ["tag"] = "direct", ["protocol"] = "freedom", ["sendThrough"] = "127.0.0.6" }) };
                if (scenario == "vless-vision") return new JsonObject { ["log"] = new JsonObject { ["loglevel"] = "none" }, ["inbounds"] = new JsonArray(new JsonObject { ["listen"] = "127.0.0.1", ["port"] = native.Number("server_port"), ["protocol"] = "vless", ["settings"] = new JsonObject { ["decryption"] = "none", ["clients"] = new JsonArray(new JsonObject { ["id"] = native.Text("uuid"), ["flow"] = "xtls-rprx-vision" }) }, ["streamSettings"] = new JsonObject { ["network"] = "raw", ["security"] = "tls", ["tlsSettings"] = new JsonObject { ["minVersion"] = "1.3", ["alpn"] = sourceTls["alpn"]!.DeepClone(), ["certificates"] = new JsonArray(new JsonObject { ["certificate"] = new JsonArray(cert.ExportCertificatePem()), ["key"] = new JsonArray(key.ExportPkcs8PrivateKeyPem()) }) } } }), ["outbounds"] = new JsonArray(new JsonObject { ["protocol"] = "freedom", ["sendThrough"] = "127.0.0.6" }) };
                var user = new JsonObject(); user[protocol == "vless" ? "uuid" : "password"] = native[protocol == "vless" ? "uuid" : "password"]!.DeepClone(); if (native.Text("flow") != "") user["flow"] = native["flow"]!.DeepClone();
                var tls = new JsonObject { ["enabled"] = true, ["server_name"] = "next.example.test", ["min_version"] = "1.3", ["certificate"] = new JsonArray(cert.ExportCertificatePem()), ["key"] = new JsonArray(key.ExportPkcs8PrivateKeyPem()), ["alpn"] = sourceTls["alpn"]!.DeepClone() }; if (scenario == "anytls-ech") tls["ech"] = new JsonObject { ["enabled"] = true, ["key"] = new JsonArray(ech.Text("Key")) };
                var inbound = new JsonObject { ["type"] = protocol, ["tag"] = "source", ["listen"] = "127.0.0.1", ["listen_port"] = native.Number("server_port"), ["users"] = new JsonArray(user), ["tls"] = tls };
                if (native["transport"] != null) { inbound["transport"] = native["transport"]!.DeepClone(); if (inbound["transport"]!.Text("type") == "ws") { inbound["transport"]!.AsObject().Remove("headers"); } }
                return new JsonObject { ["log"] = new JsonObject { ["disabled"] = true }, ["inbounds"] = new JsonArray(inbound), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct", ["inet4_bind_address"] = "127.0.0.6" }), ["route"] = new JsonObject { ["final"] = "direct" } };
            }
            var xrayPeer = scenario is "reality" or "vless-vision";
            await using var landing = await Policy28Core.Start(xrayPeer ? xray! : assets.ResolveCore("sing-box"), Landing(), directory, xrayPeer, native.Number("server_port"), false, ct); children.Add(new TestProcessIdentity(landing.Process));
            foreach (var role in ServerOutboundRouting.Roles.Where(role => ServerOutboundRouting.SupportedNode(source, role)))
            {
                var isXray = role == "RealityEntry"; if (isXray && string.IsNullOrEmpty(xray)) { Console.WriteLine("SKIP: round29 Xray next-hop matrix requires MAY_TEST_XRAY."); continue; }
                var plan = f.Plan("Stream29Runtime-" + scenario + role); var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, secrets, isXray ? "VLESS" : "Shadowsocks2022"); inbound["Listener"]!["Port"] = MixedPort();
                if (isXray) { inbound["Options"]!["ServerName"] = "entry.example.test"; inbound["Options"]!["Transport"]!["Path"] = "/next29/"; inbound["Options"]!["Transport"]!["Host"] = "front.example.test"; inbound["CertificateId"] = InboundCatalog.ImportCertificate(model, secrets, "synthetic TLS", cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()).Text("Id"); }
                var direct = InboundCatalog.Items(model, "Outbounds").Single(); var resource = InboundCatalog.AddDirect(model, "next " + scenario); resource["Kind"] = "Proxy"; var scheme = ClientSchemes.New(f.Paths); scheme["Nodes"] = new JsonArray(source.DeepClone()); f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme); resource["Source"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = source.Text("Id"), ["Fingerprint"] = ArchiveStore.Fingerprint(source) }; inbound["OutboundId"] = resource.Text("Id");
                JsonObject Render()
                {
                    var configuration = InboundRendering.Configuration(f.Store, plan, model, secrets, inbound); configuration["inbounds"]![0]!["listen"] = "127.0.0.1";
                    foreach (var output in configuration["outbounds"]!.AsArray().OfType<JsonObject>()) { if (output.Text("server") == "192.0.2.29") output["server"] = "127.0.0.1"; if (output["settings"]?["vnext"] is JsonArray vnext) vnext[0]!["address"] = "127.0.0.1"; if (output["settings"]?["servers"] is JsonArray servers) servers[0]!["address"] = "127.0.0.1"; }
                    return configuration;
                }
                var node = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).Single(); node["sing_box"]!["server"] = "127.0.0.1"; node["clash"]!["server"] = "127.0.0.1";
                var server = await Policy28Core.Start(isXray ? xray! : assets.ResolveCore("sing-box"), Render(), directory, isXray, inbound.Number("Listener.Port"), false, ct); children.Add(new TestProcessIdentity(server.Process));
                try
                {
                    foreach (var clientName in new[] { "sing-box", "mihomo" })
                    {
                        await using var client = await Round15Client.Start(clientName, assets.ResolveCore(isXray && clientName == "sing-box" ? "may-core" : clientName), node, cert, directory, ct); children.Add(new TestProcessIdentity(client.Process)); using var http = TuicHttp(client.Port, cert);
                        Check(await http.GetStringAsync("http://127.0.0.3:" + httpTarget.Port, ct) == "127.0.0.6" && await http.GetStringAsync("https://127.0.0.1:" + https.Port, ct) == "198.51.100.22", scenario + "/" + role + "/" + clientName + " did not traverse the authenticated stream next hop");
                        Check((await ClientProxyUdp.ProbeAsync(client.Port, new(IPAddress.Parse("127.0.0.2"), dns.Port), ct)).Flag("ResponseMatched"), scenario + "/" + role + " omitted actual application UDP");
                        cases.Add(new JsonObject { ["NextHop"] = scenario, ["EntryCore"] = isXray ? "xray" : "sing-box", ["Client"] = clientName, ["Https"] = true, ["Udp"] = true, ["DistinctEgress"] = true });
                    }
                    await server.DisposeAsync(); inbound["OutboundId"] = direct.Text("Id"); InboundRoutingPolicy.Set(inbound, new JsonArray(new JsonObject { ["Kind"] = "Cidr", ["Value"] = "127.0.0.3/32", ["Action"] = "NextHop", ["Target"] = resource.Text("Id") }));
                    await Stream29RemotePayload(f, plan, model, secrets, directory, ct);
                    server = await Policy28Core.Start(isXray ? xray! : assets.ResolveCore("sing-box"), Render(), directory, isXray, inbound.Number("Listener.Port"), false, ct); children.Add(new TestProcessIdentity(server.Process));
                    await using (var client = await Round15Client.Start("mihomo", assets.ResolveCore("mihomo"), node, cert, directory, ct))
                    {
                        children.Add(new TestProcessIdentity(client.Process)); using var http = TuicHttp(client.Port, cert); Check(await http.GetStringAsync("http://127.0.0.3:" + httpTarget.Port, ct) == "127.0.0.6" && await http.GetStringAsync("https://127.0.0.1:" + https.Port, ct) == "198.51.100.22" && (await ClientProxyUdp.ProbeAsync(client.Port, new(IPAddress.Parse("127.0.0.2"), dns.Port), ct)).Flag("ResponseMatched"), scenario + "/" + role + " category or default UDP changed");
                    }
                    await server.DisposeAsync(); inbound["OutboundId"] = resource.Text("Id"); InboundRoutingPolicy.Set(inbound, new());
                    foreach (var damage in new[] { "authentication", "tls" })
                    {
                        var broken = Render(); var target = broken["outbounds"]![0]!.AsObject();
                        if (damage == "authentication") { if (!isXray) target[protocol == "vless" ? "uuid" : "password"] = protocol == "vless" ? Guid.NewGuid().ToString() : "wrong-synthetic-auth"; else if (protocol == "vless") target["settings"]!["vnext"]![0]!["users"]![0]!["id"] = Guid.NewGuid().ToString(); else target["settings"]!["servers"]![0]!["password"] = "wrong-synthetic-auth"; }
                        else if (!isXray) target["tls"]!["server_name"] = "wrong.example.test"; else target["streamSettings"]![scenario == "reality" ? "realitySettings" : "tlsSettings"]!["serverName"] = "wrong.example.test";
                        server = await Policy28Core.Start(isXray ? xray! : assets.ResolveCore("sing-box"), broken, directory, isXray, inbound.Number("Listener.Port"), false, ct); children.Add(new TestProcessIdentity(server.Process));
                        await using var client = await Round15Client.Start("mihomo", assets.ResolveCore("mihomo"), node, cert, directory, ct); children.Add(new TestProcessIdentity(client.Process)); using var http = TuicHttp(client.Port, cert); http.Timeout = TimeSpan.FromSeconds(2); var refused = false;
                        try { await http.GetStringAsync("https://127.0.0.1:" + https.Port, ct); } catch (Exception error) when (error is HttpRequestException or TaskCanceledException) { refused = true; }
                        Check(refused, scenario + "/" + role + " accepted wrong next-hop " + damage + " or fell back direct"); await server.DisposeAsync();
                    }
                    server = await Policy28Core.Start(isXray ? xray! : assets.ResolveCore("sing-box"), Render(), directory, isXray, inbound.Number("Listener.Port"), false, ct); children.Add(new TestProcessIdentity(server.Process));
                    await using (var recovered = await Round15Client.Start("mihomo", assets.ResolveCore("mihomo"), node, cert, directory, ct)) { children.Add(new TestProcessIdentity(recovered.Process)); using var http = TuicHttp(recovered.Port, cert); Check(await http.GetStringAsync("https://127.0.0.1:" + https.Port, ct) == "198.51.100.22", "round29 did not reconnect after restoring the reviewed stream source"); }
                    await Stream29RemoteProbe(f, source, role, cert, https.Port, directory, children, ct);
                    Console.WriteLine("Round29: " + scenario + " / " + role + " dual-client HTTPS/UDP, TCP category, wrong identity and recovery passed.");
                }
                finally { await server.DisposeAsync(); secrets.Clear(); }
            }
        }
        pair.Clear(); ech.Clear(); await camouflage.DisposeAsync(); Check(children.All(identity => identity.Exited), "round29 left an owned validation core running");
        if (Environment.GetEnvironmentVariable("MAY_R29_EVIDENCE") is { } evidence) ArchiveStore.WriteJson(Path.GetFullPath(evidence), new JsonObject { ["SyntheticOnly"] = true, ["Cases"] = cases, ["OwnedCoresStopped"] = true });
    }
    private async Task Stream29RemotePayload(Fixture f, JsonObject plan, JsonObject model, JsonObject secrets, string directory, CancellationToken ct)
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON"); if (string.IsNullOrEmpty(python)) return;
        var file = SafePath.Resolve(directory, "payload.private.json"); ArchiveStore.WriteJson(file, InboundRendering.Payload(f.Store, plan, model, secrets)); var program = "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('host',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.normalize(json.load(open(sys.argv[2],encoding='utf-8-sig'))); print('NORMALIZED')";
        var result = await new ExternalToolRunner().RunAsync(python, ["-c", program, Path.Combine(repository, "scripts/inbound-host.py"), file], null, TimeSpan.FromSeconds(10), ct); Check(result.ExitCode == 0 && result.Output.Trim() == "NORMALIZED", "round29 generated policy differs from remote parser: " + result.Error);
    }
    private async Task Stream29RemoteProbe(Fixture f, JsonObject source, string role, X509Certificate2 certificate, int targetPort, string directory, List<TestProcessIdentity> processes, CancellationToken ct)
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON"); if (string.IsNullOrEmpty(python)) return; var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var binary = role == "RealityEntry" ? Environment.GetEnvironmentVariable("MAY_TEST_XRAY")! : assets.ResolveCore("sing-box");
        var asset = File.ReadAllText(Path.Combine(repository, "assets/remote/server-hop-probe.sh")).Replace("\r\n", "\n"); var script = asset.Split("<<'PY'\n", StringSplitOptions.None)[1]; script = script[..script.LastIndexOf("\nPY", StringComparison.Ordinal)]; script = script.Replace("PROBE_HOST_V4 = 'api.ipify.org'", "PROBE_HOST_V4 = '127.0.0.1'").Replace("PROBE_PORT = 443", "PROBE_PORT = " + targetPort);
        var work = SafePath.Resolve(directory, "probe-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work); var program = SafePath.Resolve(work, "probe.py"); var trust = SafePath.Resolve(work, "trust.pem"); File.WriteAllText(program, script); File.WriteAllText(trust, certificate.ExportCertificatePem());
        var native = ServerOutboundRouting.NextHop(source); var outbound = role == "RealityEntry" ? ServerOutboundRouting.XrayNextHop(native) : native; outbound["tag"] = ServerOutboundRouting.HopTag(HopA); if (role != "RealityEntry") outbound["server"] = "127.0.0.1"; else if (native.Text("type") == "vless") outbound["settings"]!["vnext"]![0]!["address"] = "127.0.0.1"; else outbound["settings"]!["servers"]![0]!["address"] = "127.0.0.1";
        var items = new JsonArray(new JsonObject { ["Id"] = HopA, ["ExpectedAddress"] = "198.51.100.22", ["Outbound"] = outbound }); var start = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var a in new[] { program, binary, role }) start.ArgumentList.Add(a); start.Environment["SSL_CERT_FILE"] = trust; SetHopProbeInput(start, work, items); start.Environment["TMP"] = work; start.Environment["TEMP"] = work; start.Environment["TMPDIR"] = work;
        using var process = Process.Start(start)!; processes.Add(new TestProcessIdentity(process)); var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync(ct); var output = await stdout; var error = await stderr; Check(process.ExitCode == 0, "round29 actual remote native probe rejected " + role + "/" + native.Text("type") + ": " + error); var proof = JsonNode.Parse(RemoteAssets.Marker(output, "HOP_VALIDATION"))!.AsObject(); ServerOutboundRouting.RequireHopValidation(items, proof); Check(!output.Contains(native.Text(native.Text("type") == "vless" ? "uuid" : "password")) && Directory.GetDirectories(work, "may-hop-probe-*").Length == 0, "round29 probe leaked credentials or left temporary files"); }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } }
    }
}
