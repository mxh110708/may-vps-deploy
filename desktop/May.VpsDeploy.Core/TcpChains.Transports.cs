using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class TcpChains
{
    // Existing schema-1 IPv4/TCP records retain their exact serialized identity;
    // reading a record does not migrate its fingerprints or dependent nodes.
    private static string Selection(JsonObject c, string key, string fallback, string alternative)
    {
        if (!c.ContainsKey(key)) return fallback;
        if (c[key] is JsonValue value && value.TryGetValue<string>(out var selected) && (selected == fallback || selected == alternative)) return selected;
        throw new OperationException("线路地址族或传输选择无效。");
    }
    public static string Family(JsonObject c) => Selection(c, "Family", "IPv4", "IPv6");
    public static string Transport(JsonObject c) => Selection(c, "Transport", "TCP", "UDP");
    public static string Component(JsonObject c) => Transport(c) == "UDP" ? "UdpForwarding" : "TcpForwarding";
    public static string Prefix(JsonObject c) => Family(c) == "IPv6" ? "/128" : "/32";
    public static string ServerAddress(JsonObject plan, JsonObject c) => Address(plan.Text("Server." + Family(c)), Family(c));
    public static JsonObject NormalizeForwarding(JsonObject c, JsonObject config) => Transport(c) == "UDP" ? UdpForwarding.Normalize(config) : TcpForwarding.Normalize(config);
    public static void ValidateForwarding(JsonObject c, JsonObject plan, JsonObject config, JsonObject state)
    {
        if (Transport(c) == "UDP") UdpForwarding.ValidateCandidate(plan, config);
        else TcpForwarding.ValidateCandidate(plan, config, state);
    }
    public static JsonObject? SourceOrigin(JsonObject node) => (node["InboundOrigin"] ?? node["ManagedOrigin"]) as JsonObject;
    public static bool Supports(JsonObject node, string transport, string family)
    {
        if (SourceOrigin(node)?.Text("Family") != family || node["ForwardedOrigin"] != null || node["TcpChainOrigin"] != null) return false;
        var sing = node["sing_box"] as JsonObject;
        if (sing == null) return false;
        if (transport == "UDP") return (sing.Text("type") is "hysteria2" or "tuic") && node["InboundOrigin"] != null &&
            (sing["server_ports"] is not JsonArray ports || ports.Count == 0) && node.Text("clash.ports") == "";
        return transport == "TCP" && (sing.Text("type") is "vless" or "anytls" or "shadowsocks") && sing.Text("network") != "udp" &&
            (!VlessXhttp.IsNode(node) || VlessXhttp.Version(sing) != "3");
    }
}
