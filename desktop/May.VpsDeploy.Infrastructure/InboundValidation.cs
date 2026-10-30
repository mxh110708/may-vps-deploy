using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class InboundValidation(ArchiveStore store, IClientRouteDiagnostics diagnostics) : IInboundValidation
{
    public async Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject model, JsonObject credentials, string[] ids, string directory, IProgress<string> progress, CancellationToken ct)
    {
        var instance = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var items = new JsonArray();
        var checkedPorts = new Dictionary<(string Id, string Family), int[]>();
        foreach (var node in InboundRendering.Nodes(store, instance, plan, model, credentials).Where(n => ids.Contains(n.Text("InboundOrigin.InboundId"))))
        {
            progress.Report("验收入站 / 用户 / 地址族：" + node.Text("name"));
            var ports = Hysteria2Ports.ValidationPorts(node); var key = (node.Text("InboundOrigin.InboundId"), node.Text("InboundOrigin.Family"));
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMinutes(5));
            async Task<JsonObject> Probe(int? port = null)
            {
                var candidate = node.DeepClone().AsObject();
                if (port != null)
                {
                    // Probe each alias deterministically. A random successful
                    // hop must not stand in for a blocked member of the set.
                    var native = candidate["sing_box"]!.AsObject(); native["server_port"] = port.Value; native.Remove("server_ports"); native.Remove("hop_interval"); native.Remove("hop_interval_max");
                }
                var scheme = new JsonObject { ["Nodes"] = new JsonArray(candidate), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray(candidate.Text("region_group")) } };
                var route = ClientTopology.DiagnosticRoute(scheme, candidate.Text("name")) with { RequiresApplicationUdp = InboundRendering.RequiresApplicationUdp(store, instance, model, node.Text("InboundOrigin.InboundId")) };
                return await diagnostics.RunAsync(route, directory, progress, deadline.Token);
            }
            var result = await Probe(ports.Length == 0 ? null : node.Number("sing_box.server_port"));
            if (ports.Length > 0 && result.Text("Status") == "Reachable" && !checkedPorts.ContainsKey(key))
            {
                var passed = new List<int> { node.Number("sing_box.server_port") };
                foreach (var port in ports.Where(p => p != node.Number("sing_box.server_port")))
                {
                    progress.Report("核对跳跃端口：" + port);
                    var check = await Probe(port);
                    if (check.Text("Status") != "Reachable" || check.Text("ValidatedProtocol") != "hysteria2") break;
                    passed.Add(port);
                }
                checkedPorts[key] = passed.Order().ToArray();
            }
            var item = new JsonObject { ["InboundId"] = key.Item1, ["UserId"] = node.Text("InboundOrigin.UserId"), ["Family"] = key.Item2, ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node), ["Status"] = result.Text("Status") == "Reachable" ? "Passed" : "Incomplete", ["From"] = "Controller", ["Scope"] = "ProxyHttps", ["Udp"] = result.Flag("UdpValidation.ResponseMatched") ? "Passed" : "NotMeasured", ["Result"] = result };
            if (ports.Length > 0)
            {
                // All users still authenticate separately; port reachability
                // is shared only within this invocation and address family.
                item["HopPorts"] = new JsonArray(checkedPorts.GetValueOrDefault(key, []).Select(p => (JsonNode?)JsonValue.Create(p)).ToArray());
                if (!Hysteria2Ports.ValidationMatches(node, item)) item["Status"] = "Incomplete";
            }
            items.Add(item);
        }
        return new JsonObject { ["Status"] = items.All(i => i!.Text("Status") == "Passed") ? "Passed" : "Incomplete", ["Items"] = items, ["At"] = DateTimeOffset.UtcNow };
    }
}

public static class InboundKeyGeneration
{
    public static async Task<JsonObject> RealityAsync(IValidationAssets assets, IExternalToolRunner tools, CancellationToken ct)
    {
        var executable = assets.ResolveCore("sing-box"); await ProtocolValidation.VerifyVersion(assets, tools, "sing-box", executable, ct);
        var result = await tools.RunAsync(executable, ["generate", "reality-keypair"], null, TimeSpan.FromSeconds(15), ct); result.RequireSuccess("无法生成 Reality 密钥。");
        var privateKey = Regex.Match(result.Output, @"(?mi)^PrivateKey:\s*(\S+)").Groups[1].Value; var publicKey = Regex.Match(result.Output, @"(?mi)^PublicKey:\s*(\S+)").Groups[1].Value;
        if (privateKey.Length != 43 || publicKey.Length != 43) throw new OperationException("固定核心返回的 Reality 密钥格式不受支持。");
        return new JsonObject { ["PrivateKey"] = privateKey, ["PublicKey"] = publicKey };
    }
    public static async Task<JsonObject> EchAsync(IValidationAssets assets, IExternalToolRunner tools, string name, CancellationToken ct)
    {
        InboundCatalog.ServerName(name); var executable = assets.ResolveCore("sing-box"); await ProtocolValidation.VerifyVersion(assets, tools, "sing-box", executable, ct);
        var result = await tools.RunAsync(executable, ["generate", "ech-keypair", name], null, TimeSpan.FromSeconds(15), ct); result.RequireSuccess("无法生成 ECH 密钥。");
        var key = Regex.Match(result.Output, @"(?s)-----BEGIN ECH KEYS-----.*?-----END ECH KEYS-----").Value; var config = Regex.Match(result.Output, @"(?s)-----BEGIN ECH CONFIGS-----.*?-----END ECH CONFIGS-----").Value;
        if (key == "" || config == "") throw new OperationException("固定核心返回的 ECH 材料格式不受支持。"); return new JsonObject { ["Key"] = key, ["Config"] = config };
    }
}
