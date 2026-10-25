using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class InboundValidation(ArchiveStore store, ClientRouteDiagnostics diagnostics) : IInboundValidation
{
    public async Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject model, JsonObject credentials, string[] ids, string directory, IProgress<string> progress, CancellationToken ct)
    {
        var instance = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var items = new JsonArray();
        foreach (var node in InboundRendering.Nodes(store, instance, plan, model, credentials).Where(n => ids.Contains(n.Text("InboundOrigin.InboundId"))))
        {
            progress.Report("验收入站 / 用户 / 地址族：" + node.Text("name"));
            var scheme = new JsonObject { ["Nodes"] = new JsonArray(node.DeepClone()), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray(node.Text("region_group")) } };
            var route = ClientTopology.DiagnosticRoute(scheme, node.Text("name")); var result = await diagnostics.RunAsync(route, directory, progress, ct);
            items.Add(new JsonObject { ["InboundId"] = node.Text("InboundOrigin.InboundId"), ["UserId"] = node.Text("InboundOrigin.UserId"), ["Family"] = node.Text("InboundOrigin.Family"), ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node), ["Status"] = result.Text("Status") == "Reachable" ? "Passed" : "Incomplete", ["From"] = "Controller", ["Scope"] = "ProxyHttps", ["Udp"] = "NotMeasured", ["Result"] = result });
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
