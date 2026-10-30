using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

// External client connections only. A transport never becomes a deployment role.
// This bounded projection is also the sharing equivalence check; unknown options
// must use the original full native configuration instead of a lossy conversion.
public static class ClientStreamTransports
{
    public static bool IsNative(JsonObject value) => value.Text("type") is "vless" or "trojan" && value["transport"] != null;
    public static bool IsClash(JsonObject value) => value.Text("type") is "vless" or "trojan" && value.Text("network") is "ws" or "grpc";
    public static string Label(JsonObject node)
    {
        var transport = node.Text("sing_box.transport.type", node.Text("clash.network"));
        return node.Text("sing_box.type", node.Text("clash.type")) + (transport is "ws" or "grpc" or "xhttp" ? " / " + (transport == "ws" ? "WebSocket" : transport == "xhttp" ? "XHTTP" : "gRPC") : "");
    }
    private static void Fields(JsonObject value, params string[] keys)
    { if (value.Any(p => !keys.Contains(p.Key, StringComparer.Ordinal))) throw new OperationException("WS／gRPC 参数超出可完整转换的范围，请保留完整原生配置。"); }
    private static string S(JsonObject value, string key, string fallback = "")
    { if (!value.TryGetPropertyValue(key, out var item)) return fallback; return item is JsonValue v && v.TryGetValue<string>(out var text) ? text : throw new OperationException("协议或传输参数类型无效。"); }
    private static bool B(JsonObject value, string key, bool fallback = false)
    { if (!value.TryGetPropertyValue(key, out var item)) return fallback; return item is JsonValue v && v.TryGetValue<bool>(out var flag) ? flag : throw new OperationException("协议或 TLS 开关类型无效。"); }
    private static int I(JsonObject value, string key, int fallback = 0)
    { if (!value.TryGetPropertyValue(key, out var item)) return fallback; return item is JsonValue v && v.TryGetValue<int>(out var number) ? number : throw new OperationException("传输端口或大小必须为整数。"); }
    private static string Host(string value)
    {
        if (value.Length is < 1 or > 253 || value.Any(char.IsControl) || value.Contains('%') || Uri.CheckHostName(value) == UriHostNameType.Unknown) throw new OperationException("服务器地址或 TLS 名称无效。");
        return Uri.CheckHostName(value) == UriHostNameType.Dns ? new IdnMapping().GetAscii(value).ToLowerInvariant() : value.ToLowerInvariant();
    }
    private static string Path(string path)
    {
        if (path.Length is < 1 or > 2048 || !path.StartsWith('/') || path.StartsWith("//") || !Regex.IsMatch(path, "^/[A-Za-z0-9/._~-]*$")) throw new OperationException("固定核心的 WS 路径转义方式不同；双客户端链接转换仅支持 /、字母、数字、点、下划线、连字符和波浪号，不转换查询串或已转义路径，请保留原生配置。");
        return path;
    }
    private static string Service(string value)
    { if (!Regex.IsMatch(value, "^[A-Za-z0-9_.-]{1,128}$")) throw new OperationException("gRPC serviceName 应为 1–128 个字母、数字、点、下划线或连字符；多路和特殊路径暂不转换。"); return value; }
    public static JsonObject Canonical(JsonObject source, string name)
    {
        var protocol = S(source, "type");
        if (protocol is not ("vless" or "trojan")) throw new OperationException("此 WS／gRPC 投影只适用于 VLESS 或 Trojan。");
        Fields(source, "type", "tag", "server", "server_port", protocol == "vless" ? "uuid" : "password", "flow", "tls", "transport", "packet_encoding");
        var port = I(source, "server_port");
        if (S(source, "tag") != name || port is < 1 or > 65535 || S(source, "flow") != "" || source.ContainsKey("packet_encoding") && (protocol != "vless" || S(source, "packet_encoding") != "xudp")) throw new OperationException("节点名称、端口或流控无效；WS／gRPC 不使用 Vision flow。");
        var result = new JsonObject { ["type"] = protocol, ["tag"] = name, ["server"] = Host(S(source, "server")), ["server_port"] = port };
        if (protocol == "vless")
        {
            if (!Guid.TryParseExact(S(source, "uuid"), "D", out var uuid) || uuid == Guid.Empty) throw new OperationException("VLESS UUID 无效。");
            result["uuid"] = uuid.ToString(); result["packet_encoding"] = "xudp";
        }
        else
        {
            var password = S(source, "password"); if (password.Length is < 1 or > 4096 || password.Any(char.IsControl)) throw new OperationException("Trojan 密码缺失、过长或含控制字符。"); result["password"] = password;
        }
        var tls = source["tls"] as JsonObject ?? throw new OperationException("外部 WS／gRPC 需要启用可验证的 TLS。");
        Fields(tls, "enabled", "server_name", "insecure", "utls", "alpn");
        if (!B(tls, "enabled") || B(tls, "insecure")) throw new OperationException("外部 WS／gRPC 必须保留 TLS 证书验证。");
        var outputTls = new JsonObject { ["enabled"] = true, ["server_name"] = Host(S(tls, "server_name", result.Text("server"))) }; result["tls"] = outputTls;
        if (tls["utls"] is JsonObject utls)
        {
            Fields(utls, "enabled", "fingerprint"); var fingerprint = S(utls, "fingerprint");
            if (!B(utls, "enabled") || !new[] { "chrome", "firefox", "edge", "safari", "ios", "android", "random" }.Contains(fingerprint)) throw new OperationException("TLS 指纹不在双客户端支持范围内。");
            outputTls["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = fingerprint };
        }
        else if (tls.ContainsKey("utls")) throw new OperationException("TLS 指纹参数类型无效。");
        var transport = source["transport"] as JsonObject ?? throw new OperationException("缺少独立的 WS／gRPC 传输参数。"); var type = S(transport, "type");
        var output = new JsonObject { ["type"] = type }; result["transport"] = output;
        if (type == "ws")
        {
            Fields(transport, "type", "path", "headers", "max_early_data", "early_data_header_name"); output["path"] = Path(S(transport, "path", "/"));
            if (transport["headers"] is JsonObject headers)
            {
                if (headers.Count > 16) throw new OperationException("WebSocket 额外请求头过多。"); var normalized = new JsonObject(); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var header in headers)
                {
                    if (!Regex.IsMatch(header.Key, "^[A-Za-z0-9-]{1,64}$") || !names.Add(header.Key) || new[] { "connection", "upgrade", "sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "content-length", "transfer-encoding" }.Contains(header.Key.ToLowerInvariant())) throw new OperationException("WebSocket 请求头冲突或覆盖了握手字段。");
                    var value = S(headers, header.Key); if (value.Length is < 1 or > 2048 || value.Any(c => c < ' ' || c > '~')) throw new OperationException("WebSocket 请求头值无效。");
                    if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) && (value.Any(char.IsWhiteSpace) || !Uri.TryCreate("http://" + value, UriKind.Absolute, out var authority) || authority.UserInfo != "" || authority.AbsolutePath != "/" || authority.Query != "" || authority.Fragment != "" || authority.Host.Length == 0)) throw new OperationException("WebSocket Host 应为域名或 IP，可含端口；不能含路径或认证信息。");
                    normalized[header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) ? "Host" : header.Key] = value;
                }
                if (normalized.Count > 0) output["headers"] = normalized;
            }
            else if (transport.ContainsKey("headers")) throw new OperationException("WebSocket 请求头必须为对象。");
            var early = I(transport, "max_early_data"); var eh = S(transport, "early_data_header_name");
            if (early is < 0 or > 2048 || early == 0 && eh != "" || early > 0 && eh != "Sec-WebSocket-Protocol") throw new OperationException("早期数据仅支持 1–2048 字节及 Sec-WebSocket-Protocol 请求头，不能猜测或改变其承载方式。");
            if (early > 0) { output["max_early_data"] = early; output["early_data_header_name"] = eh; }
        }
        else if (type == "grpc") { Fields(transport, "type", "service_name"); output["service_name"] = Service(S(transport, "service_name")); }
        else throw new OperationException("本轮只转换 WS／gRPC，XHTTP 和 HTTPUpgrade 不属于同一种传输。");
        if (tls["alpn"] != null)
        {
            if (tls["alpn"] is not JsonArray { Count: > 0 and <= 2 } alpn || alpn.Any(v => v is not JsonValue s || !s.TryGetValue<string>(out var a) || a != (type == "ws" ? "http/1.1" : "h2")) || alpn.Count != 1) throw new OperationException("显式 ALPN 必须与传输对应：WS 为 http/1.1，gRPC 为 h2。");
            outputTls["alpn"] = alpn.DeepClone();
        }
        return result;
    }
    public static JsonObject ToClash(JsonObject source, string name)
    {
        var native = Canonical(source, name); var protocol = native.Text("type"); var t = native["transport"]!.AsObject();
        var clash = new JsonObject { ["name"] = name, ["type"] = protocol, ["server"] = native.Text("server"), ["port"] = native.Number("server_port"), ["udp"] = true, ["network"] = t.Text("type"), ["skip-cert-verify"] = false };
        if (protocol == "vless") { clash["uuid"] = native.Text("uuid"); clash["tls"] = true; clash["packet-encoding"] = "xudp"; } else clash["password"] = native.Text("password");
        clash[protocol == "vless" ? "servername" : "sni"] = native.Text("tls.server_name");
        if (native.At("tls.utls") != null) clash["client-fingerprint"] = native.Text("tls.utls.fingerprint");
        if (native.At("tls.alpn") != null) clash["alpn"] = native.At("tls.alpn")!.DeepClone();
        if (t.Text("type") == "ws")
        {
            var ws = new JsonObject { ["path"] = t.Text("path") }; clash["ws-opts"] = ws;
            if (t["headers"] != null) ws["headers"] = t["headers"]!.DeepClone();
            if (t.Number("max_early_data") > 0) { ws["max-early-data"] = t.Number("max_early_data"); ws["early-data-header-name"] = t.Text("early_data_header_name"); }
        }
        else clash["grpc-opts"] = new JsonObject { ["grpc-service-name"] = t.Text("service_name") };
        return clash;
    }
    public static JsonObject FromClash(JsonObject source, string name)
    {
        var protocol = S(source, "type"); var type = S(source, "network");
        Fields(source, "type", "name", "server", "port", "udp", protocol == "vless" ? "uuid" : "password", "flow", "tls", protocol == "vless" ? "servername" : "sni", "skip-cert-verify", "client-fingerprint", "alpn", "network", type == "ws" ? "ws-opts" : "grpc-opts", "packet-encoding");
        if (S(source, "name") != name || !B(source, "udp", true) || protocol == "vless" && !B(source, "tls") || S(source, "flow") != "" || protocol == "trojan" && source.ContainsKey("tls") && !B(source, "tls")) throw new OperationException("节点 TLS、UDP 或 flow 无法等效转换。");
        var tls = new JsonObject { ["enabled"] = true, ["server_name"] = S(source, protocol == "vless" ? "servername" : "sni", S(source, "server")), ["insecure"] = B(source, "skip-cert-verify") };
        if (source.ContainsKey("client-fingerprint")) tls["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = S(source, "client-fingerprint") };
        if (source["alpn"] != null) tls["alpn"] = source["alpn"]!.DeepClone();
        var result = new JsonObject { ["type"] = protocol, ["tag"] = name, ["server"] = S(source, "server"), ["server_port"] = I(source, "port"), ["tls"] = tls, ["flow"] = S(source, "flow") };
        result[protocol == "vless" ? "uuid" : "password"] = S(source, protocol == "vless" ? "uuid" : "password");
        if (source.ContainsKey("packet-encoding")) result["packet_encoding"] = S(source, "packet-encoding");
        var t = new JsonObject { ["type"] = type }; result["transport"] = t;
        if (type == "ws")
        {
            if (source.ContainsKey("ws-opts") && source["ws-opts"] is not JsonObject) throw new OperationException("WebSocket 参数必须为对象。");
            var ws = source["ws-opts"] as JsonObject ?? new JsonObject(); Fields(ws, "path", "headers", "max-early-data", "early-data-header-name"); t["path"] = S(ws, "path", "/");
            if (ws["headers"] != null) t["headers"] = ws["headers"]!.DeepClone();
            if (ws.ContainsKey("max-early-data")) t["max_early_data"] = I(ws, "max-early-data");
            if (ws.ContainsKey("early-data-header-name")) t["early_data_header_name"] = S(ws, "early-data-header-name");
        }
        else if (type == "grpc") { var grpc = source["grpc-opts"] as JsonObject ?? throw new OperationException("缺少 gRPC 参数。"); Fields(grpc, "grpc-service-name"); t["service_name"] = S(grpc, "grpc-service-name"); }
        return Canonical(result, name);
    }
    public static string ShareLink(JsonObject source, string name)
    {
        var n = Canonical(source, name); var t = n["transport"]!;
        if (t["headers"] is JsonObject h && h.Any(p => p.Key != "Host")) throw new OperationException("分享链接不能表达额外 WebSocket 请求头，请导出完整客户端配置。");
        static string E(string value) => Uri.EscapeDataString(value);
        var host = n.Text("server"); var protocol = n.Text("type");
        var link = protocol + "://" + E(n.Text(protocol == "vless" ? "uuid" : "password")) + "@" + (host.Contains(':') ? "[" + host + "]" : host) + ":" + n.Number("server_port") + "?security=tls&type=" + t.Text("type") + "&sni=" + E(n.Text("tls.server_name"));
        if (protocol == "vless") link += "&encryption=none";
        if (n.At("tls.utls") != null) link += "&fp=" + E(n.Text("tls.utls.fingerprint"));
        if (n.At("tls.alpn") is JsonArray alpn) link += "&alpn=" + E(string.Join(',', alpn.Select(v => v!.ToString())));
        if (t.Text("type") == "ws")
        {
            link += "&path=" + E(t.Text("path")); if (t["headers"] is JsonObject headers && headers.ContainsKey("Host")) link += "&host=" + E(headers.Text("Host"));
            if (t.Number("max_early_data") > 0) link += "&ed=" + t.Number("max_early_data") + "&eh=" + E(t.Text("early_data_header_name"));
        }
        else link += "&serviceName=" + E(t.Text("service_name")) + "&mode=gun";
        return link + "#" + E(name);
    }
}
