using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class TcpChainValidation(ClientRouteDiagnostics diagnostics) : ITcpChainValidation
{
    public async Task<JsonObject> ValidateAsync(JsonObject node, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
    {
        var scheme = new JsonObject { ["Nodes"] = new JsonArray(node.DeepClone()), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray(node.Text("region_group")) } };
        var route = ClientTopology.DiagnosticRoute(scheme, node.Text("name"));
        if (node.Text("sing_box.type") is "hysteria2" or "tuic") route = route with { RequiresApplicationUdp = true };
        var result = await diagnostics.RunAsync(route, privateDirectory, progress, cancellationToken);
        return new JsonObject { ["Status"] = result.Text("Status") == "Reachable" ? "Passed" : "Incomplete", ["From"] = "Controller", ["Scope"] = "TcpChainProxyHttps", ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node), ["Result"] = result, ["At"] = DateTimeOffset.UtcNow };
    }
}
