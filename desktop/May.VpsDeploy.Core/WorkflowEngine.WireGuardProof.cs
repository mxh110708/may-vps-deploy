using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<JsonObject> WireGuardProof(Context first, Context second, JsonObject c)
    {
        var results = new JsonArray();
        foreach (var (source, destination) in new[] { (first, second), (second, first) })
        {
            var nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)); var id = Guid.NewGuid().ToString("N");
            var parameters = new Dictionary<string, string> { ["PROOF_ID"] = id, ["PROOF_PORT"] = RandomNumberGenerator.GetInt32(40000, 60000).ToString(System.Globalization.CultureInfo.InvariantCulture), ["PROOF_NONCE"] = nonce };
            try
            {
                await destination.Run("wireguard-proof.sh", new(parameters) { ["ACTION"] = "proof-start" }, timeout: 25, marker: "WIREGUARD_PROOF_DONE");
                var response = await source.Run("wireguard-proof.sh", new(parameters) { ["ACTION"] = "proof" }, timeout: 25, marker: "WIREGUARD_PROOF_DONE");
                var proof = JsonNode.Parse(RemoteAssets.Marker(response.Output, "WIREGUARD_PROOF"))!.AsObject();
                if (proof.Text("Status") != "Passed" || !proof.Flag("TCP") || !proof.Flag("UDP") || !proof.Flag("ResponseMatched") || proof.Text("Scope") != "WireGuardPeerApplication" || proof.Text("ChallengeDigest") != ArchiveStore.Digest(Encoding.UTF8.GetBytes("may-wireguard:" + nonce))) throw new OperationException("隧道缺少匹配本次双向 TCP／UDP 业务证据。");
                proof["FromInstance"] = source.Request.InstanceRelativePath; results.Add(proof);
            }
            finally
            {
                var token = destination.Cancellation; destination.Cancellation = CancellationToken.None;
                try { await destination.Run("wireguard-proof.sh", new(parameters) { ["ACTION"] = "proof-stop" }, timeout: 25, marker: "WIREGUARD_PROOF_DONE"); }
                finally { destination.Cancellation = token; }
            }
        }
        return new() { ["Status"] = "Passed", ["Scope"] = "BidirectionalWireGuardApplications", ["At"] = DateTimeOffset.UtcNow, ["Directions"] = results, ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(c) };
    }
}
