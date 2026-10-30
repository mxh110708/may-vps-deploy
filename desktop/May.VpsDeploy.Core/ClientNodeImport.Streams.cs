using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class ClientNodeImport
{
    private static JsonObject ParseStream(string protocol, string name, string host, int port, string auth, Dictionary<string, string> query)
    {
        RequireKeys(query, protocol == "vless"
            ? ["security", "type", "encryption", "flow", "sni", "fp", "alpn", "path", "host", "serviceName", "mode", "ed", "eh"]
            : ["security", "type", "sni", "fp", "alpn", "path", "host", "serviceName", "mode", "ed", "eh"]);
        var type = query.GetValueOrDefault("type", "");
        if (type is not ("ws" or "grpc") || query.GetValueOrDefault("security", protocol == "trojan" ? "tls" : "") != "tls" || query.GetValueOrDefault("encryption", "none") != "none" || query.GetValueOrDefault("flow", "") != "") throw new OperationException("外部节点本轮支持 TLS 的 WS／gRPC；Reality、Vision flow、裸 TCP 和 XHTTP 不能按此方式转换。");
        if (type == "ws" && new[] { "serviceName", "mode" }.Any(query.ContainsKey) || type == "grpc" && new[] { "host", "path", "ed", "eh" }.Any(query.ContainsKey)) throw new OperationException("WS 路径／Host 与 gRPC serviceName 不能混用，未丢弃多余参数。");
        if (type == "grpc" && query.GetValueOrDefault("mode", "gun") != "gun") throw new OperationException("gRPC 仅支持单流 gun 模式，不能把多路模式静默改成单流。");
        var tls = new JsonObject { ["enabled"] = true, ["server_name"] = query.GetValueOrDefault("sni", host) };
        if (query.TryGetValue("fp", out var fp)) tls["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = fp };
        if (query.TryGetValue("alpn", out var alpn)) tls["alpn"] = new JsonArray(alpn.Split(',').Select(a => (JsonNode?)JsonValue.Create(a)).ToArray());
        var native = new JsonObject { ["type"] = protocol, ["tag"] = name, ["server"] = host, ["server_port"] = port, ["tls"] = tls };
        native[protocol == "vless" ? "uuid" : "password"] = auth;
        var transport = new JsonObject { ["type"] = type }; native["transport"] = transport;
        if (type == "ws")
        {
            transport["path"] = query.GetValueOrDefault("path", "/");
            if (query.TryGetValue("host", out var httpHost)) transport["headers"] = new JsonObject { ["Host"] = httpHost };
            if (query.TryGetValue("ed", out var ed))
            {
                if (!int.TryParse(ed, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var early) || early < 1) throw new OperationException("WebSocket ed 必须为正整数。");
                transport["max_early_data"] = early; transport["early_data_header_name"] = query.GetValueOrDefault("eh", "Sec-WebSocket-Protocol");
            }
            else if (query.ContainsKey("eh")) throw new OperationException("WebSocket eh 必须与非零 ed 一同提供。");
        }
        else transport["service_name"] = query.GetValueOrDefault("serviceName", "");
        var sing = ClientStreamTransports.Canonical(native, name);
        return new JsonObject { ["name"] = name, ["sing_box"] = sing, ["clash"] = ClientStreamTransports.ToClash(sing, name) };
    }
}
