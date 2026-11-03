using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<JsonObject?> CheckChainUnderlay(JsonObject chain, IReadOnlyList<Context> contexts, bool applications)
    {
        if (chain.ContainsKey("WireGuards"))
        {
            var results = new JsonArray();
            foreach (var reference in TcpChainUnderlay.References(chain))
            {
                var segmentProof = await CheckChainUnderlay(TcpChainUnderlay.WithReference(chain, reference), contexts, applications);
                if (segmentProof != null) { segmentProof["Id"] = reference.Text("Id"); segmentProof["Segment"] = reference.Text("Segment"); results.Add(segmentProof); }
            }
            return applications ? new JsonObject { ["Status"] = "Passed", ["Scope"] = "AdjacentWireGuardApplications", ["Segments"] = results } : null;
        }
        var tunnel = TcpChainUnderlay.Resolve(store, chain);
        if (tunnel == null) return null;
        var pair = WireGuardTunnels.Instances(tunnel).Select(i => contexts.Single(c => c.Request.InstanceRelativePath == i)).ToArray();
        async Task ReadPeers()
        {
            foreach (var context in pair)
            {
                var component = WireGuardTunnels.Component(tunnel, context.Request.InstanceRelativePath); var expected = context.State.Text(component + ".RemoteHash");
                var response = await context.Run("wireguard-read.sh", new() { ["WIREGUARD_EXPECTED_HASH"] = expected, ["WIREGUARD_SLOT"] = WireGuardTunnels.Slot(tunnel, context.Request.InstanceRelativePath).ToString(System.Globalization.CultureInfo.InvariantCulture) }, timeout: 45, marker: "WIREGUARD_READ");
                var state = JsonNode.Parse(RemoteAssets.Marker(response.Output, "WIREGUARD_STATE"))!.AsObject();
                if (state.Text("Hash") != expected || !state.Flag("Healthy") || !JsonNode.DeepEquals(state["Configuration"], context.Plan[component]))
                    throw new OperationException("线路所依赖的 WireGuard 实际配置、密钥身份、启停状态或路由不同；未回退到公网连接。", code: "TcpChainUnderlayDrift");
            }
        }
        await ReadPeers();
        if (!applications) return null;
        var proof = await WireGuardProof(pair[0], pair[1], tunnel);
        await ReadPeers();
        proof["DependencyFingerprint"] = chain.Text("WireGuard.Fingerprint");
        return proof;
    }
}
