using System.Net;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class ForwardProxyHealth
{
    public static bool Selected(JsonNode? rule) => rule.Text("TargetGroup.Health.Type") == "Proxy";
    public static JsonObject New(bool consent = false) => new() { ["Type"] = "Proxy", ["Consent"] = consent, ["EgressFamily"] = "IPv4", ["PrimaryExit"] = "", ["BackupExit"] = "" };
    public static JsonObject NewBalanced(JsonObject rule, bool consent = false) => new()
    {
        ["Type"] = "Proxy", ["Consent"] = consent, ["EgressFamily"] = "IPv4",
        ["ExpectedExits"] = new JsonObject(ForwardTargetGroups.TargetIds(rule).Select(id => new KeyValuePair<string, JsonNode?>(id, JsonValue.Create(""))))
    };
    public static void Validate(JsonObject rule, string transport)
    {
        var h = rule["TargetGroup"]!["Health"]!.AsObject();
        var balanced = ForwardTargetGroups.Balanced(rule);
        string[] fields = balanced ? ["Type", "Consent", "EgressFamily", "ExpectedExits"] : ["Type", "Consent", "EgressFamily", "PrimaryExit", "BackupExit"];
        if (h.Count != fields.Length || h.Any(p => !fields.Contains(p.Key)) || h["Consent"] is not JsonValue consent || !consent.TryGetValue<bool>(out var accepted) || !accepted || h.Text("EgressFamily") is not ("IPv4" or "IPv6") || transport is not ("TCP" or "UDP") || transport == "TCP" && rule.Text("Validation.Type") != "Proxy" || transport == "UDP" && rule.Text("Validation.Type") != "Shadowsocks") throw new OperationException("协议健康须选择支持的代理来源，并明确授权在此 VPS 私有保存探测凭据。UDP 仅支持 SS／SS2022。");
        if (balanced && (h["ExpectedExits"] is not JsonObject exits || !exits.Select(p => p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(ForwardTargetGroups.TargetIds(rule)))) throw new OperationException("预期出口必须逐一匹配全部固定目标身份。");
        var values = balanced ? h["ExpectedExits"]!.AsObject().Select(p => p.Value) : new[] { h["PrimaryExit"], h["BackupExit"] };
        foreach (var value in values)
        {
            if (value is not JsonValue text || !text.TryGetValue<string>(out var expected)) throw new OperationException("预期出口必须为字符串。");
            if (expected != "" && (!IPAddress.TryParse(expected, out var ip) || ip.ToString() != expected || ip.IsIPv4MappedToIPv6 || IPAddress.IsLoopback(ip) || (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) != (h.Text("EgressFamily") == "IPv6") || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6Multicast || ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && ip.GetAddressBytes()[0] >= 224)) throw new OperationException("预期出口须为所选地址族的规范单播 IP；留空仍核对实际出口地址族。");
        }
    }
    public static JsonObject Document(ArchiveStore store, JsonObject configuration)
    {
        var rules = TcpForwarding.Rules(configuration).Where(Selected).ToArray();
        if (rules.Length > 4) throw new OperationException("每个转发组件最多 4 个协议健康组；每组使用一个受限核心进程。");
        var entries = new JsonObject();
        if (rules.Length == 0) return new JsonObject { ["Version"] = 1, ["Core"] = new JsonObject(), ["Rules"] = entries };
        foreach (var rule in rules)
        {
            var node = TcpForwarding.ProxyNode(store, rule);
            try
            {
                var native = ServerOutboundRouting.NextHop(node);
                if (native.Text("type") == "shadowsocks" && !new[] { "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305" }.Contains(native.Text("method")) || native["tls"] is JsonObject t && t.Flag("insecure") || native.Text("type") is "vless" or "trojan" or "anytls" && !native.Flag("tls.enabled")) throw new OperationException("协议健康需要受支持的加密认证方法和启用的 TLS／Reality 校验，不接受不校验证书的来源。");
                if (native.Text("type") is not ("shadowsocks" or "anytls" or "vless" or "trojan") || VlessXhttp.IsNode(node) || native["plugin"] != null || native["udp_over_tcp"] != null || native.Text("network") == "udp" && rule.Text("Validation.Type") == "Proxy" || rule.Text("Validation.Type") == "Shadowsocks" && (native.Text("type") != "shadowsocks" || native.Text("network") == "tcp")) throw new OperationException("协议健康支持原生 SS／SS2022、AnyTLS、VLESS TLS／Reality、Trojan TLS；本轮不包含 XHTTP、插件、额外链式、QUIC 或 UDP-over-TCP。");
                if (native["tls"] is JsonObject tls && tls.Flag("enabled") && tls.Text("server_name") == "") tls["server_name"] = native.Text("server");
                native.Remove("tag"); native.Remove("network");
                entries[rule.Text("Id")] = new JsonObject { ["RuleFingerprint"] = ForwardTargetGroups.Fingerprint(rule), ["NodeFingerprint"] = rule.Text("Validation.NodeFingerprint"), ["Outbound"] = native };
            }
            finally { node.Clear(); }
        }
        var core = InboundRendering.Core(store.Paths).DeepClone().AsObject(); core.Remove("Reality");
        return new JsonObject { ["Version"] = 1, ["Core"] = core, ["Rules"] = entries };
    }
}
