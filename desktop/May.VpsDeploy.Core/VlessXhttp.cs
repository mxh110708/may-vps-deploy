using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

// VLESS XHTTP with native client projections; no additional service.
public static partial class VlessXhttp
{
    public static bool IsNode(JsonObject node) => node.Text("clash.type") == "vless" && node.Text("clash.network") == "xhttp" || node.Text("sing_box.type") == "vless" && node.Text("sing_box.transport.type") == "xhttp";
    public static JsonObject Options() => new() { ["ServerName"] = "", ["Security"] = "TLS", ["Reality"] = new JsonObject(), ["Transport"] = new JsonObject { ["Type"] = "XHTTP", ["Path"] = "/may-" + Guid.NewGuid().ToString("N")[..12] + "/", ["Host"] = "", ["Mode"] = "stream-one" } };
    public static JsonObject RealityOptions() => new() { ["HandshakeServer"] = "", ["HandshakePort"] = 443, ["PublicKey"] = "", ["ShortId"] = Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)) };
    private static void Fields(JsonObject item, params string[] keys)
    { if (item.Count != keys.Length || item.Any(p => !keys.Contains(p.Key))) throw new OperationException("XHTTP 模型含未知或缺失字段。"); }
    public static string Path(string value)
    {
        if (value.Length > 8192 || value.Any(char.IsControl) || !Uri.TryCreate("https://example.test/" + value.TrimStart('/'), UriKind.Absolute, out _)) throw new OperationException("XHTTP 路径无效或超过 8192 字符；查询串与转义按原值保留。");
        return value;
    }
    public static void Validate(JsonObject options, JsonNode own)
    {
        Fields(options, "ServerName", "Security", "Transport", "Reality"); DeploymentPlans.Domain(options.Text("ServerName"));
        if (options.Text("Security") is not ("TLS" or "Reality") || options["Transport"] is not JsonObject t || options["Reality"] is not JsonObject r) throw new OperationException("本轮 VLESS XHTTP 使用明确的 TLS 或 Reality 传输安全。");
        if (options.Text("Security") == "TLS") { Fields(r); if (own.AsObject().Count != 0) throw new OperationException("TLS XHTTP 不应保留 Reality 私钥。"); }
        else
        {
            Fields(r, "HandshakeServer", "HandshakePort", "PublicKey", "ShortId"); DeploymentPlans.Domain(r.Text("HandshakeServer"));
            if (r["HandshakePort"] is not JsonValue v || !v.TryGetValue<int>(out var port) || port is < 1 or > 65535) throw new OperationException("Reality 目标端口无效。");
            Fields(own.AsObject(), "RealityPrivateKey"); Key(r.Text("PublicKey")); Key(own.Text("RealityPrivateKey")); ShortId(r.Text("ShortId"));
        }
        Only(t, "Type", "Path", "Host", "Mode", "HTTPVersion", "Extra", "DownloadSettings");
        if (t.Text("Type") != "XHTTP") throw new OperationException("VLESS 入站需要独立的 XHTTP 传输。");
        if(t.Text("HTTPVersion","2") is not ("1.1" or "2" or "3"))throw new OperationException("受管服务端须明确选择 HTTP/1.1、HTTP/2 或 HTTP/3；客户端导入另保留 auto。");
        ValidateTransport(Transport(t), options.Text("Security") == "Reality");
        if (t["DownloadSettings"] != null) throw new OperationException("独立下载地址属于客户端参数；受管入站不部署额外下载服务，请在完整客户端来源中设置。");
    }
    private static void Key(string key) { try { if (Regex.IsMatch(key, "^[A-Za-z0-9_-]{43}$") && Convert.FromBase64String(key.Replace('-', '+').Replace('_', '/') + "=").Length == 32) return; } catch (FormatException) { } throw new OperationException("Reality X25519 密钥格式无效。"); }
    private static void ShortId(string id, bool client = false) { if (!(client && id == "") && !Regex.IsMatch(id, "^(?:[a-fA-F0-9]{2}){1,8}$")) throw new OperationException("Reality short ID 无效。"); }
    public static string Security(JsonObject node) => node.At("clash.reality-opts") != null || node.Flag("sing_box.tls.reality.enabled") ? "Reality" : "TLS";
    public static string Summary(JsonObject inbound) => inbound.Text("Protocol") != "VLESS" ? "" : " · " + inbound.Text("Options.Security") + " / XHTTP / HTTP/" + inbound.Text("Options.Transport.HTTPVersion", "2") + " / " + inbound.Text("Options.Transport.Mode", "auto") + " · SNI " + inbound.Text("Options.ServerName") + " · Host " + inbound.Text("Options.Transport.Host") + " · 路径 " + inbound.Text("Options.Transport.Path").Split('?')[0] + (inbound.Text("Options.Transport.Path").Contains('?') ? "（含查询参数，记录中隐藏）" : "") + " · 高级参数 " + ((inbound.At("Options.Transport.Extra") as JsonObject)?.Count ?? 0) + (inbound.Text("Options.Security") == "Reality" ? " · 握手目标 " + inbound.Text("Options.Reality.HandshakeServer") + ":" + inbound.Number("Options.Reality.HandshakePort") : "") + " · May Core／Mihomo";
    public static JsonObject Clash(string name, string address, int port, string uuid, JsonNode options)
    {
        return ToClash(Native(name, address, port, uuid, options), name);
    }
    public static JsonObject RequireClash(JsonObject node)
    {
        if (!IsNode(node) || node["clash"] is not JsonObject) throw new OperationException("节点缺少可等价表达的完整 Mihomo XHTTP 配置。");
        var probe=node["clash"]!.DeepClone().AsObject();var x=probe["xhttp-opts"]!.AsObject();
        foreach(var key in new[]{"session-table","session-length"})if(x[key]!=null){if(x[key] is not JsonValue v||!v.TryGetValue<string>(out var value)||value.Any(char.IsControl)||value.Length>256)throw new OperationException("Mihomo 会话扩展格式无效。");if(key=="session-length")_ = Range(x[key]);x.Remove(key);}
        _ = FromClash(probe, node.Text("name"));
        return node["clash"]!.DeepClone().AsObject();
    }
    public static string NodeVersion(JsonObject node)=>node["sing_box"] is JsonObject n?Version(n):node.At("clash.alpn") is JsonArray {Count:1} a?a[0]?.ToString() switch{"h3"=>"3","http/1.1"=>"1.1",_=>"2"}:"2";
    public static bool Evidence(JsonObject node, JsonNode? result) => result.Text("Status") == "Reachable" && result.Text("ValidatedProtocol") == "vless" && result.Text("Transport") == "xhttp" && result.Text("TransportSecurity") == Security(node) && result.Text("TransportAlpn") == Alpn(NodeVersion(node)) && result.Text("ClientCore") is "mihomo" or "may-core" && result.Flag("UdpValidation.ResponseMatched") && result.Text("UdpValidation.Transport") == "UDP" && (result?["Stages"] as JsonArray ?? []).Any(s => s!.Text("Id") == "EntryHttps" && s.Text("Status") == "Passed");
}
