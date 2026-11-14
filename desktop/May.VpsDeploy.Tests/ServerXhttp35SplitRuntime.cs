using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunServerXhttp35SplitTests() { await Xhttp35SplitRuntime(); Console.WriteLine($"PASS: {assertions} round35 fixed-Reality split download, actual paths and cleanup assertions."); }
    private async Task Xhttp35SplitRuntime()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("MAY_TEST_XRAY") is not { } xray) { Console.WriteLine("SKIP: round35 split runtime needs fixed Windows Xray."); return; }
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(3)); var ct = budget.Token;
        var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64"); var tools = new ExternalToolRunner(); var directory = f.Paths.Resolve("private/xhttp35-split"); Directory.CreateDirectory(directory); var children = new List<TestProcessIdentity>(); var cases = new JsonArray();
        using var key = RSA.Create(2048); var req = new CertificateRequest("CN=next.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("next.example.test"); san.AddDnsName("entry.example.test"); san.AddIpAddress(IPAddress.Loopback); req.CertificateExtensions.Add(san.Build()); req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        await using var web = new Policy28HttpTarget(ct, IPAddress.Parse("127.0.0.3")); await using var defaultWeb = new Policy28HttpTarget(ct, IPAddress.Parse("127.0.0.4")); await using var dns = new Policy34UdpTarget("127.0.0.3");
        var camouflagePort = MixedPort(); var camouflageConfig = new JsonObject { ["log"] = new JsonObject { ["disabled"] = true }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "anytls", ["listen"] = "127.0.0.1", ["listen_port"] = camouflagePort, ["users"] = new JsonArray(new JsonObject { ["password"] = "synthetic-camouflage-35" }), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "next.example.test", ["min_version"] = "1.3", ["alpn"] = new JsonArray("h2"), ["certificate"] = new JsonArray(cert.ExportCertificatePem()), ["key"] = new JsonArray(key.ExportPkcs8PrivateKeyPem()) } }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct" }) };
        await using var camouflage = await Policy28Core.Start(assets.ResolveCore("sing-box"), camouflageConfig, directory, false, camouflagePort, false, ct); children.Add(new(camouflage.Process)); var pair = await InboundKeyGeneration.RealityAsync(assets, tools, ct);
        var ssPort = MixedPort(); var password = "synthetic-default-35"; var ssConfig = new JsonObject { ["log"] = new JsonObject { ["disabled"] = true }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "shadowsocks", ["listen"] = "127.0.0.1", ["listen_port"] = ssPort, ["method"] = "chacha20-ietf-poly1305", ["password"] = password }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["inet4_bind_address"] = "127.0.0.5" }) };
        await using var ss = await Policy28Core.Start(assets.ResolveCore("sing-box"), ssConfig, directory, false, ssPort, false, ct); children.Add(new(ss.Process));
        foreach (var scenario in new[] { "tls-1.1-stream-up", "tls-2-packet-up", "tls-3-packet-up", "reality-2-stream-up" })
        {
            var source = Xhttp35Node(scenario, MixedPort()); var native = source["sing_box"]!.AsObject(); var isReality = native.Flag("tls.reality.enabled");
            if (isReality) native["tls"]!["reality"]!["public_key"] = pair.Text("PublicKey"); else native["tls"]!["certificate"] = new JsonArray(cert.ExportCertificatePem());
            var backend = Xhttp35Landing(native, cert, key, pair, camouflagePort);
            if (isReality) backend["inbounds"]![0]!["streamSettings"]!["realitySettings"]!["serverNames"]!.AsArray().Add("entry.example.test");
            var h3 = VlessXhttp.Version(native) == "3";
            await using var landing = await Policy28Core.Start(xray, backend, directory, true, native.Number("server_port"), h3, ct); children.Add(new(landing.Process));
            await using var datagrams = h3 ? new HysteriaUdpRelay(native.Number("server_port")) : null;
            var downPort = h3 ? datagrams!.Port : MixedPort();
            await using var tcp = h3 ? null : new HysteriaVmTcpBridge(downPort, native.Number("server_port"));
            var download = native.DeepClone().AsObject(); download["server"] = "192.0.2.36"; download["server_port"] = downPort; download["tls"]!["server_name"] = "entry.example.test"; download["transport"]!["extra"]!["headers"]!["X-Download-35"] = "synthetic-down-private";
            native["transport"]!["download_settings"] = new JsonObject { ["server"] = download["server"]!.DeepClone(), ["server_port"] = download["server_port"]!.DeepClone(), ["tls"] = download["tls"]!.DeepClone(), ["transport"] = download["transport"]!.DeepClone() };
            var plan = f.Plan("Split35"); plan.Put("Ports.XrayPrimary", JsonValue.Create(MixedPort())); plan.Put("Ports.XrayBackup", JsonValue.Create(0)); plan.Put("Reality.TargetMode", JsonValue.Create("LocalOwnedTls")); plan.Put("Reality.LocalHttpsPort", JsonValue.Create(camouflagePort)); plan.Put("Reality.ServerName", JsonValue.Create("next.example.test"));
            var secrets = Fixture.RealitySecrets(); secrets["Xray"]!["RealityPrivateKey"] = pair["PrivateKey"]!.DeepClone(); secrets["Xray"]!["RealityClientKey"] = pair["PublicKey"]!.DeepClone();
            var defaultNode = new JsonObject { ["name"] = "default SS", ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["server"] = "192.0.2.28", ["server_port"] = ssPort, ["method"] = "chacha20-ietf-poly1305", ["password"] = password } };
            var rule = HopRule("Cidr", "127.0.0.3/32", HopA); rule["Network"] = "Both";
            var preview = ServerOutboundRouting.Build("RealityEntry", ServerConfigurations.Xray(plan, secrets), null, defaultNode, "198.51.100.35", plan, destinationRules: new JsonArray(rule), additionalHops: [new(HopA, source, "198.51.100.36")]);
            JsonObject Render(string damage = "")
            {
                var config = preview.Configuration.DeepClone().AsObject(); config["log"] = new JsonObject { ["loglevel"] = "none" }; foreach (var input in config["inbounds"]!.AsArray()) input!["listen"] = "127.0.0.1";
                foreach (var outbound in config["outbounds"]!.AsArray().OfType<JsonObject>())
                {
                    if (outbound.At("settings.servers") is JsonArray servers) servers[0]!["address"] = "127.0.0.1";
                    if (outbound.At("settings.vnext") is JsonArray peers) peers[0]!["address"] = "127.0.0.1";
                    if (outbound.At("streamSettings.xhttpSettings.extra.downloadSettings") is JsonObject down)
                    {
                        down["address"] = "127.0.0.1";
                        if (damage == "identity") down[isReality ? "realitySettings" : "tlsSettings"]!["serverName"] = "wrong.example.test";
                        if (damage == "endpoint") down["port"] = MixedPort();
                    }
                }
                return config;
            }
            var pairNode = ClientProfiles.Nodes(plan, secrets, true).Single(); var node = new JsonObject { ["name"] = pairNode.Name, ["clash"] = pairNode.Clash.DeepClone(), ["sing_box"] = pairNode.SingBox.DeepClone() }; node["clash"]!["server"] = "127.0.0.1"; node["sing_box"]!["server"] = "127.0.0.1";
            async Task CheckPaths(bool failed, string clientName)
            {
                await using var client = await Round15Client.Start(clientName, assets.ResolveCore(clientName), node, cert, directory, ct); children.Add(new(client.Process)); using var http = TuicHttp(client.Port, cert); http.Timeout = TimeSpan.FromSeconds(3);
                Check(await http.GetStringAsync("http://127.0.0.4:" + defaultWeb.Port, ct) == "127.0.0.5", "split XHTTP changed default SS path");
                if (!failed)
                {
                    Check(await http.GetStringAsync("http://127.0.0.3:" + web.Port, ct) == "127.0.0.6", "split download did not use classified XHTTP path");
                    Check(await Udp34Exchange(client.Port, dns.Endpoint, ct) == "127.0.0.6", "split classified UDP did not use XHTTP next hop");
                }
                else
                {
                    var refused = false; try { await http.GetStringAsync("http://127.0.0.3:" + web.Port, ct); } catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { refused = true; }
                    Check(refused, "download fault fell back to default or direct");
                }
            }
            foreach (var damage in new[] { "", "identity", "endpoint", "" })
            {
                await using var entry = await Policy28Core.Start(xray, Render(damage), directory, true, plan.Number("Ports.XrayPrimary"), false, ct); children.Add(new(entry.Process));
                await CheckPaths(damage != "", "mihomo");
                if (damage == "") await CheckPaths(false, "sing-box");
            }
            var observed = h3 ? datagrams!.Forwarded > 0 : tcp!.Connections > 0; Check(observed, "independent download endpoint was never reached");
            cases.Add(new JsonObject { ["Scenario"] = scenario, ["Entry"] = "FixedReality", ["TcpClassification"] = true, ["UdpClassification"] = true, ["IndependentDownloadObserved"] = observed, ["DownloadSni"] = "entry.example.test", ["DownloadIdentityAndEndpointRejected"] = true, ["DefaultPreserved"] = true, ["Restored"] = true });
            Console.WriteLine("Round35 split: " + scenario + " fixed Reality, dual-client classified TCP/UDP, independent endpoint, faults and recovery passed."); secrets.Clear();
        }
        await ss.DisposeAsync(); await camouflage.DisposeAsync(); Check(children.All(p => p.Exited), "round35 split left owned cores running"); pair.Clear();
        if (Environment.GetEnvironmentVariable("MAY_R35_EVIDENCE") is { } path) ArchiveStore.WriteJson(Path.GetFullPath(path + ".split.json"), new JsonObject { ["SyntheticOnly"] = true, ["Cases"] = cases, ["OwnedCoresStopped"] = true });
    }
}
