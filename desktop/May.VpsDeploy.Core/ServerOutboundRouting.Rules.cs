using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class ServerOutboundRouting
{
    private static JsonArray AddedRules(string role, JsonArray policy, string[] tags, string family, JsonObject plan, JsonArray? additional = null)
    {
        if (family is not ("IPv4" or "IPv6")) throw new OperationException("服务器出站的出口地址族无效。");
        ServerDestinationRules.ValidatePath(policy, family, plan.Flag((role == "RealityEntry" ? "Reality" : "AnyTls") + ".ForceIpv4Egress", true), (additional ?? new JsonArray()).OfType<JsonObject>().ToDictionary(h => h.Text("Id"), h => h.Text("EgressFamily"), StringComparer.Ordinal));
        var result = ServerDestinationRules.Render(role, policy, tags);
        JsonArray Inbounds() => new(tags.Select(t => (JsonNode?)JsonValue.Create(t)).ToArray());
        if (role == "RealityEntry")
        {
            result.Add(new JsonObject { ["type"] = "field", ["inboundTag"] = Inbounds(), ["ip"] = new JsonArray(family == "IPv4" ? "::/0" : "0.0.0.0/0"), ["outboundTag"] = "block" });
            result.Add(new JsonObject { ["type"] = "field", ["inboundTag"] = Inbounds(), ["outboundTag"] = Tag });
        }
        else
        {
            result.Add(new JsonObject { ["inbound"] = Inbounds(), ["ip_version"] = family == "IPv4" ? 6 : 4, ["action"] = "reject" });
            result.Add(new JsonObject { ["inbound"] = Inbounds(), ["action"] = "route", ["outbound"] = Tag });
        }
        return result;
    }
    private static bool OwnedRulesMatch(string role, JsonObject[] actual, JsonObject previous, string[] tags, JsonObject plan)
    {
        var policy = ServerDestinationRules.Normalize(previous["DestinationRules"]);
        if (policy.Count > 0 && previous.Text("DestinationRulesNetwork") != "tcp") return false;
        var expected = AddedRules(role, policy, tags, previous.Text("EgressFamily"), plan, MetadataHops(previous));
        return actual.Length == expected.Count && ArchiveStore.Fingerprint(expected) == previous.Text("RulesFingerprint") && ArchiveStore.Fingerprint(new JsonArray(actual.Select(r => (JsonNode?)r.DeepClone()).ToArray())) == previous.Text("RulesFingerprint");
    }
}
