using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class ServerUdpRouting
{
    public static bool Required(JsonArray rules, string id, string defaultId) =>
        ServerDestinationRules.HasUdp(rules) && (id == defaultId || rules.Any(r => ServerDestinationRules.Applies(r!, "udp") &&
            (id == "Direct" ? r!.Text("Action") == "Direct" : r!.Text("Action") == "NextHop" && r.Text("Target") == id)));

    public static void ValidateDefault(JsonArray rules, string family, string defaultId = "")
    {
        if (!ServerDestinationRules.HasUdp(rules)) return;
        foreach (var address in family == "IPv4" ? new[] { "1.1.1.1" } : family == "IPv6" ? new[] { "2606:4700:4700::1111" } : new[] { "1.1.1.1", "2606:4700:4700::1111" })
        {
            var decision = ServerDestinationRules.Match(rules, address, "udp");
            if (decision.Action != "NextHop" || decision.Target != "" && decision.Target != defaultId)
                throw new OperationException("UDP 规则遮挡默认路径的 DNS 回程验收目标，请缩小范围或添加明确的默认去向例外；不会插入隐藏规则。");
        }
    }

    public static void RequireProof(JsonNode? value, string family)
    {
        string[] keys = ["Scope", "Transport", "ResponseMatched", "ResolverAddress", "ResolverPort", "QueryName", "QueryType"];
        if (value is not JsonObject proof || proof.Count != keys.Length || proof.Any(p => !keys.Contains(p.Key)) ||
            proof.Text("Scope") != "NativeOutboundUdpDns" || proof.Text("Transport") != "UDP" ||
            proof["ResponseMatched"] is not JsonValue matched || !matched.TryGetValue<bool>(out var success) || !success ||
            proof["ResolverPort"] is not JsonValue port || !port.TryGetValue<int>(out var portNumber) || portNumber != 53 || proof.Text("QueryName") != "example.com")
            throw new OperationException("应用 UDP 回程验收缺失或不完整，不能用 TCP／QUIC 连接成功代替。");
        var v6 = proof.Text("ResolverAddress") == "2606:4700:4700::1111" && proof.Text("QueryType") == "AAAA";
        var v4 = proof.Text("ResolverAddress") == "1.1.1.1" && proof.Text("QueryType") == "A";
        if (!(v4 || v6) || family == "IPv4" && !v4 || family == "IPv6" && !v6)
            throw new OperationException("应用 UDP 回程的目标或地址族不符。");
    }
}
