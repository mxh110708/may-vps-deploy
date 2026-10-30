using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private static readonly string StreamUuid = Guid.NewGuid().ToString();
    private static string StreamLink(string protocol, string transport, string host = "192.0.2.18", int port = 443, string? name = null, bool early = false)
    {
        return protocol + "://" + (protocol == "vless" ? StreamUuid : "synthetic%3Aa%40ss%2B%25") + "@" + host + ":" + port + "?security=tls&type=" + transport + "&sni=stream.example.test" + (protocol == "vless" ? "&encryption=none" : "")
            + (transport == "ws" ? "&path=%2Ftransport-18%2Fsegment&host=front.example.test" + (early ? "&ed=1024&eh=Sec-WebSocket-Protocol" : "") : "&serviceName=May.Test-Service_18&mode=gun") + "#" + Uri.EscapeDataString(name ?? protocol + "-" + transport + (early ? "-early" : ""));
    }
    public async Task RunClientStreamTests(bool modelOnly = false)
    {
        await ClientStreamModel(); if (!modelOnly) await ClientStreamRuntime();
        Console.WriteLine($"PASS: {assertions} external WS/gRPC model, import, output and native assertions; no production changes.");
    }
    private async Task ClientStreamModel()
    {
        using var f = new Fixture(repository); var scheme = ClientSchemes.New(f.Paths); var region = scheme["Layout"]!.Strings("region_groups")[0];
        var links = new[] { StreamLink("vless", "ws"), StreamLink("vless", "grpc"), StreamLink("trojan", "ws", early: true), StreamLink("trojan", "grpc", "[2001:db8::18]") };
        var initial = ArchiveStore.Fingerprint(scheme); var parsed = ClientNodeImport.Preview(string.Join('\n', links), scheme, region);
        Check(parsed.Accepted == 4 && ArchiveStore.Fingerprint(scheme) == initial, "stream import lost protocol/transport or mutated preview: " + string.Join(";", parsed.Rows.Select(r => r.Message)));
        ClientNodeImport.Apply(scheme, parsed); var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        Check(nodes[0].Text("sing_box.transport.path") == "/transport-18/segment" && nodes[0].Text("clash.ws-opts.headers.Host") == "front.example.test" && nodes[0].Text("sing_box.tls.server_name") == "stream.example.test", "WS URI path, Host and TLS SNI were conflated or decoded twice");
        Check(nodes[1].Text("sing_box.transport.service_name") == "May.Test-Service_18" && nodes[1].Text("clash.grpc-opts.grpc-service-name") == "May.Test-Service_18", "gRPC service name was lost");
        Check(nodes[2].Text("sing_box.password") == "synthetic:a@ss+%" && nodes[2].Number("clash.ws-opts.max-early-data") == 1024 && nodes[3].Text("sing_box.server") == "2001:db8::18", "Trojan credential/IPv6/early data did not survive import");
        foreach (var n in nodes)
        {
            Check(!n["sing_box"]!.AsObject().ContainsKey("flow") && n.At("tls.reality") == null && n.At("sing_box.tls.reality") == null && ClientStreamTransports.Label(n).Contains("/"), "external transport became a Reality or Vision connection");
            var native = n["sing_box"]!.AsObject(); Check(JsonNode.DeepEquals(native, ClientStreamTransports.FromClash(n["clash"]!.AsObject(), n.Text("name"))), "native protocol/transport projection is not equivalent");
            var config = ClientTopology.DiagnosticConfiguration(ClientTopology.DiagnosticRoute(scheme, n.Text("name")), 15301, 15302);
            Check(JsonNode.DeepEquals(config["outbounds"]![0]!["transport"], native["transport"]) && config["outbounds"]!.AsArray().All(o => o!.Text("type") != "direct"), "diagnostic dropped transport or added DIRECT fallback");
        }
        var preview = ClientShareLinks.Preview(scheme); Check(preview.Rows.All(r => r.Ready), "stream sharing refused: " + string.Join(';', preview.Rows.Select(r => r.Message)));
        var text = ClientShareLinks.Generate(scheme, preview, preview.Rows.Select(r => r.Id).ToArray(), "Plain");
        var restored = ClientNodeImport.Preview(text, ClientSchemes.New(f.Paths), region); Check(restored.Accepted == 4, "stream share output not importable");
        foreach (var (a, b) in nodes.Zip(restored.Rows.Select(r => r.Node!))) Check(ClientNodeImport.ConnectionFingerprint(a) == ClientNodeImport.ConnectionFingerprint(b), "stream share serialization lost connection data");
        var optional = ClientNodeImport.Preview(links[0].Replace("#vless-ws", "&fp=firefox&alpn=http%2F1.1#tls-options"), ClientSchemes.New(f.Paths), region);
        Check(optional.Accepted == 1 && optional.Rows[0].Node!.Text("clash.client-fingerprint") == "firefox", "optional TLS fingerprint and ALPN not preserved");
        foreach (var invalid in new[]
        {
            links[0].Replace("security=tls", "security=none"), links[0].Replace("security=tls", "security=reality"), links[0].Replace("encryption=none", "encryption=mlkem768"), links[0].Replace("encryption=none", "flow=xtls-rprx-vision"),
            links[0].Replace("type=ws", "type=unknown-transport"), links[0].Replace("type=ws", "type=httpupgrade"), links[0].Replace("#vless-ws", "&allowInsecure=1#bad"), links[0].Replace("#vless-ws", "&serviceName=other#bad"),
            links[0].Replace("path=%2Ftransport-18%2Fsegment", "path=%2Fpath%3Fed%3D1024"), links[0].Replace("path=%2Ftransport-18%2Fsegment", "path=%2Fpath%3Ftoken%3Da"), links[0].Replace("path=%2Ftransport-18%2Fsegment", "path=%2Ftransport%252Fsegment"), links[0].Replace("front.example.test", "bad%0D%0AX-Header%3Avalue"),
            links[0].Replace("#vless-ws", "&path=%2Fother#bad"), links[0].Replace("#vless-ws", "&alpn=h2#bad"), links[0].Replace("#vless-ws", "&ed=4096#bad"), links[0].Replace("#vless-ws", "&ed=1&eh=other#bad"),
            links[1].Replace("mode=gun", "mode=multi"), links[1].Replace("May.Test-Service_18", "invalid%2Fservice"), links[1].Replace("#vless-grpc", "&authority=front.example.test#bad"), links[1].Replace("#vless-grpc", "&path=%2Fpath#bad"),
            links[1].Replace("#vless-grpc", "&alpn=http%2F1.1#bad"), links[0].Replace("#vless-ws", "&fp=unsupported#bad"), "trojan://password@example.test:443?type=tcp", "vmess://legacy"
        })
        {
            var rejected = ClientNodeImport.Preview(invalid, scheme, region); Check(rejected.Accepted == 0 && rejected.Rows.All(r => r.Status == "Rejected" && !r.Message.Contains("synthetic") && !r.Message.Contains(StreamUuid)), "unsupported stream option accepted/dropped or error leaked credentials");
        }
        var withHeaders = nodes[0].DeepClone().AsObject(); withHeaders["sing_box"]!["transport"]!["headers"]!["X-Custom"] = "preserved"; withHeaders["clash"]!["ws-opts"]!["headers"]!["X-Custom"] = "preserved";
        Check(ClientStreamTransports.Canonical(withHeaders["sing_box"]!.AsObject(), withHeaders.Text("name")).Text("transport.headers.X-Custom") == "preserved", "full native WS header was dropped");
        var custom = scheme.DeepClone().AsObject(); custom["Nodes"] = new JsonArray(withHeaders); Check(!ClientShareLinks.Preview(custom).Rows[0].Ready, "share link silently dropped an extra header");
        foreach (var edit in new Action<JsonObject>[] { n => n["tls"]!["insecure"] = true, n => n["tls"]!["certificate_path"] = "outside.pem", n => n["transport"]!["headers"]!["host"] = "duplicate.example", n => n["transport"]!["headers"]!["Upgrade"] = "h2c", n => n["detour"] = "extra", n => n["transport"]!["max_early_data"] = "1", n => n["tls"]!["utls"] = new JsonObject { ["enabled"] = false } })
        { var n = nodes[0]["sing_box"]!.DeepClone().AsObject(); edit(n); Refuses(() => ClientStreamTransports.Canonical(n, nodes[0].Text("name")), "advanced native stream option silently projected"); }
        var mismatch = scheme.DeepClone().AsObject(); mismatch["Nodes"]![0]!["clash"]!["ws-opts"]!["path"] = "/different"; Check(!ClientShareLinks.Preview(mismatch).Rows[0].Ready, "sharing ignored mismatched paired WS path");
        var stale = ClientNodeImport.Preview(links[0], ClientSchemes.New(f.Paths), region); Refuses(() => ClientNodeImport.Apply(scheme, stale), "stale stream preview applied");
        var sourceScheme = ClientSchemes.New(f.Paths); var source = ClientSubscriptions.New(region); source["Url"] = "https://subscription.example.test/list";
        ClientSubscriptions.Apply(sourceScheme, ClientSubscriptions.Preview(sourceScheme, source, links[0])); var sourceId = sourceScheme["Nodes"]![0]!.Text("Id");
        var change = ClientSubscriptions.Preview(sourceScheme, source, links[0].Replace("front.example.test", "updated.example.test")); Check(change.Ready && change.Changes.Any(c => c.Kind == "Changed"), "subscription ignored changed HTTP Host");
        ClientSubscriptions.Apply(sourceScheme, change); Check(sourceScheme["Nodes"]![0]!.Text("Id") == sourceId, "transport refresh replaced stable node identity");
        sourceScheme["Nodes"]![0]!["sing_box"]!["transport"]!["path"] = "/local-change"; Check(!ClientSubscriptions.Preview(sourceScheme, source, links[0]).Ready, "source refresh overwrote local stream edit");
        if (Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") is {} python)
        {
            var workbench = new ClientWorkbench(f.Store, new ExternalToolRunner(), new ValidationAssets(new AppPaths(repository), "windows-amd64"), python);
            var hashes = new[] { scheme.Text("Clash"), scheme.Text("SingBox") }.Select(ClientSchemes.SourceFingerprint).ToArray();
            await workbench.BuildAsync(scheme, default); await workbench.ValidateAsync(scheme, default); Check(scheme.Text("Candidate.ValidationStatus") == "Passed", "generated dual native WS/gRPC outputs did not parse");
            foreach (var formats in new[] { "Both", "Clash", "SingBox" })
            {
                var read = await workbench.ReadSourcesAsync(formats == "SingBox" ? "" : scheme.Text("Candidate.Clash"), formats == "Clash" ? "" : scheme.Text("Candidate.SingBox"), default);
                Check(read.Count == 4 && read.All(n => n!.Text(formats == "Clash" ? "clash.network" : "sing_box.transport.type") is "ws" or "grpc"), "source extraction hid supported external transports in " + formats);
                foreach (var item in read.OfType<JsonObject>())
                {
                    var original = nodes.Single(n => n.Text("name") == item.Text("name"));
                    foreach (var field in formats == "Both" ? new[] { "clash", "sing_box" } : new[] { formats == "Clash" ? "clash" : "sing_box" }) Check(JsonNode.DeepEquals(original[field], item[field]), "native candidate source roundtrip dropped connection fields");
                }
            }
            Check(new[] { scheme.Text("Clash"), scheme.Text("SingBox") }.Select(ClientSchemes.SourceFingerprint).SequenceEqual(hashes), "stream candidate builder modified source files");
            var directory = f.Paths.Resolve("exports"); var clash = Path.Combine(directory, "stream.yaml"); var sing = Path.Combine(directory, "stream.json");
            workbench.PreparePublish(scheme, clash, sing); workbench.Publish(scheme, clash, sing); Check(File.Exists(clash) && File.Exists(sing), "local stream candidate export was not published");
            var exported = ClientSchemes.SourceFingerprint(sing); scheme["Nodes"]![0]!["sing_box"]!["transport"]!["path"] = "/after-validation"; Refuses(() => workbench.PreparePublish(scheme, clash, sing), "transport change reused stale validated candidate"); Check(ClientSchemes.SourceFingerprint(sing) == exported, "stale export changed existing files");
        }
    }
}
