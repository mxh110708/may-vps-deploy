using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static partial class ServerOutboundRouting
{
    public static bool IsStream(JsonNode? native) => native.Text("type") is "vless" or "trojan" or "anytls";
    public static string OutboundProtocol(JsonNode native) => native.Text("protocol") == "hysteria" ? "hysteria2" : native.Text("protocol", native.Text("type"));
    public static string CapabilitySummary => "sing-box：Shadowsocks、Hysteria2、TUIC v5、VLESS TLS／Reality、Trojan TLS、AnyTLS；VLESS／Trojan 可保留受支持的 WS／gRPC。固定 Xray：Shadowsocks、Hysteria2、原始 TCP 的 VLESS TLS／Reality、Trojan TLS。端点使用明确 IP；不增加转接核心。";
    public static string ConnectionLabel(JsonObject native) => (native.Text("type") switch
    {
        "vless" => "VLESS / " + (native.Flag("tls.reality.enabled") ? "Reality" : "TLS") + (native.Text("flow") == "" ? "" : " / Vision") + " / " + native.Text("transport.type", "TCP"),
        "trojan" => "Trojan / TLS / " + native.Text("transport.type", "TCP"),
        "anytls" => "AnyTLS / TLS",
        _ => native.Text("type")
    }) + (native.Flag("tls.ech.enabled") ? " / ECH" : "");
    public static string ConnectionSummary(JsonObject native)
    {
        var tls = native["tls"]!.AsObject(); var result = ConnectionLabel(native) + " · SNI " + tls.Text("server_name") + " · 验证身份";
        result += tls["reality"] != null ? " · 固定 Reality 公钥" : tls["certificate"] == null ? " · 系统信任" : " · 公开信任配置 " + ArchiveStore.Fingerprint(tls["certificate"]!)[..8];
        if (tls["utls"] != null) result += " · 指纹 " + tls.Text("utls.fingerprint");
        if (tls["reality"] != null) result += " · Reality 身份摘要 " + ArchiveStore.Fingerprint(tls["reality"]!)[..8];
        if (native["transport"] is JsonObject t) result += t.Text("type") == "grpc" ? " · 服务名 " + t.Text("service_name") : " · 路径 " + t.Text("path", "/") + (t.Text("headers.Host") == "" ? "" : " · Host " + t.Text("headers.Host")) + " · 早期数据 " + t.Number("max_early_data");
        if (native.Text("type") == "anytls") result += " · 空闲检查 " + native.Text("idle_session_check_interval", "30s") + " / 超时 " + native.Text("idle_session_timeout", "30s") + " / 保留 " + native.Number("min_idle_session") + (native.ContainsKey("client_metadata") ? " · 已保留客户端元数据" : "");
        return result;
    }
    private static void StreamFields(JsonObject value, params string[] names)
    { if (value.Any(p => !names.Contains(p.Key, StringComparer.Ordinal))) throw new OperationException("下一跳包含尚未支持的协议、TLS、传输或拨号字段；未删除字段，请使用可完整验收的来源。"); }
    private static string StreamText(JsonObject value, string field, string fallback = "") => !value.ContainsKey(field) ? fallback : value[field] is JsonValue v && v.TryGetValue<string>(out var text) ? text : throw new OperationException("下一跳文本字段类型无效。");
    private static bool StreamFlag(JsonObject value, string field, bool fallback = false) => !value.ContainsKey(field) ? fallback : value[field] is JsonValue v && v.TryGetValue<bool>(out var flag) ? flag : throw new OperationException("下一跳开关字段类型无效。");
    private static int StreamNumber(JsonObject value, string field, int min, int max)
    { if (value[field] is not JsonValue v || !v.TryGetValue<int>(out var number) || number < min || number > max) throw new OperationException("下一跳数值字段超出范围。"); return number; }
    private static string StreamCertificate(JsonNode value)
    {
        var pem = value is JsonArray a && a.Count is > 0 and <= 256 && a.All(v => v is JsonValue j && j.TryGetValue<string>(out _)) ? string.Join('\n', a.Select(v => v!.ToString())) : value is JsonValue s && s.TryGetValue<string>(out var text) ? text : "";
        if (pem.Length is < 1 or > 65536 || pem.Contains("PRIVATE KEY", StringComparison.Ordinal)) throw new OperationException("下一跳信任材料只能是有限的公开 PEM 证书。");
        try { using var certificate = X509Certificate2.CreateFromPem(pem); } catch (CryptographicException) { throw new OperationException("下一跳信任证书无效。"); }
        return pem;
    }
    private static void StreamParameters(JsonObject native)
    {
        var protocol = StreamText(native, "type");
        StreamFields(native, new[] { "type", "tag", "server", "server_port", "tls" }.Concat(protocol == "vless" ? ["uuid", "flow", "packet_encoding", "transport"] : protocol == "trojan" ? ["password", "transport"] : new[] { "password", "idle_session_check_interval", "idle_session_timeout", "min_idle_session", "client_metadata" }).ToArray());
        _ = StreamText(native, "server"); _ = StreamText(native, "tag"); _ = StreamNumber(native, "server_port", 1, 65535);
        if (protocol == "vless")
        {
            if (!Guid.TryParseExact(StreamText(native, "uuid"), "D", out var id) || id == Guid.Empty || StreamText(native, "flow") is not ("" or "xtls-rprx-vision") || StreamText(native, "packet_encoding", "xudp") != "xudp") throw new OperationException("VLESS 下一跳须有有效 UUID、受支持的 Vision 流控和 XUDP 编码。");
        }
        else { var password = StreamText(native, "password"); if (password.Length is < 1 or > 4096 || password.Any(char.IsControl)) throw new OperationException("下一跳认证字段缺失或无效。"); }
        if (native["tls"] is not JsonObject tls) throw new OperationException("下一跳需要完整 TLS 身份。");
        StreamFields(tls, "enabled", "server_name", "insecure", "min_version", "max_version", "alpn", "certificate", "utls", "reality", "ech");
        if (!StreamFlag(tls, "enabled") || StreamFlag(tls, "insecure")) throw new OperationException("服务器下一跳必须保留 TLS 身份验证。");
        DeploymentPlans.Domain(StreamText(tls, "server_name"));
        foreach (var field in new[] { "min_version", "max_version" }) if (tls.ContainsKey(field) && StreamText(tls, field) is not ("1.2" or "1.3")) throw new OperationException("下一跳 TLS 版本仅支持 1.2／1.3。");
        if (tls.Text("min_version") == "1.3" && tls.Text("max_version") == "1.2" || native.Text("flow") != "" && tls.Text("max_version") == "1.2" || protocol == "anytls" && (tls.Text("max_version") == "1.2" || tls.ContainsKey("min_version") && tls.Text("min_version") != "1.3")) throw new OperationException("下一跳 TLS 版本与协议或流控不兼容。");
        if (tls.ContainsKey("alpn") && (tls["alpn"] is not JsonArray { Count: > 0 and <= 8 } alpn || alpn.Any(v => v is not JsonValue j || !j.TryGetValue<string>(out var s) || s.Length is < 1 or > 32 || s.Any(c => c < 33 || c > 126)) || alpn.Select(v => v!.ToString()).Distinct(StringComparer.Ordinal).Count() != alpn.Count)) throw new OperationException("下一跳 ALPN 列表无效。");
        if (tls.ContainsKey("certificate")) _ = StreamCertificate(tls["certificate"]!);
        if (tls.ContainsKey("ech"))
        {
            if (tls["ech"] is not JsonObject ech || ech.Count != 2 || !StreamFlag(ech, "enabled") || ech["config"] is not JsonArray { Count: > 0 and <= 512 } configs || configs.Any(v => v is not JsonValue j || !j.TryGetValue<string>(out _))) throw new OperationException("ECH 须提供启用状态与公开配置，不能引用文件或私钥。");
            StreamFields(ech, "enabled", "config"); var text = string.Join('\n', configs.Select(v => v!.ToString()));
            const string begin = "-----BEGIN ECH CONFIGS-----", end = "-----END ECH CONFIGS-----"; text = text.Trim();
            if (text.Length is < 1 or > 32768 || !text.StartsWith(begin, StringComparison.Ordinal) || !text.EndsWith(end, StringComparison.Ordinal)) throw new OperationException("ECH 公开配置格式无效。");
            try { if (Convert.FromBase64String(text[begin.Length..^end.Length]).Length is < 1 or > 16384) throw new FormatException(); } catch (FormatException) { throw new OperationException("ECH 公开配置编码无效。"); }
        }
        if (tls.ContainsKey("utls"))
        {
            if (tls["utls"] is not JsonObject u) throw new OperationException("uTLS 字段无效。"); StreamFields(u, "enabled", "fingerprint");
            if (!StreamFlag(u, "enabled") || !new[] { "chrome", "firefox", "edge", "safari", "ios", "android", "random" }.Contains(StreamText(u, "fingerprint"))) throw new OperationException("下一跳 TLS 指纹不在固定核心支持范围。");
        }
        if (tls.ContainsKey("reality"))
        {
            if (protocol != "vless" || tls["reality"] is not JsonObject r || !tls.ContainsKey("utls") || native.ContainsKey("transport")) throw new OperationException("Reality 下一跳须为原始 TCP 的 VLESS 并指定 uTLS 指纹。");
            StreamFields(r, "enabled", "public_key", "short_id"); StreamFields(tls, "enabled", "server_name", "insecure", "utls", "reality");
            var key = StreamText(r, "public_key"); var shortId = StreamText(r, "short_id");
            if (!StreamFlag(r, "enabled") || !Regex.IsMatch(key, "^[A-Za-z0-9_-]{43}$") || !Regex.IsMatch(shortId, "^(?:[a-f0-9]{2}){0,8}$")) throw new OperationException("Reality 公钥或 short ID 格式无效。");
            try { if (Convert.FromBase64String(key.Replace('-', '+').Replace('_', '/') + "=").Length != 32) throw new FormatException(); } catch (FormatException) { throw new OperationException("Reality 公钥长度无效。"); }
        }
        if (native.ContainsKey("transport"))
        {
            if (native["transport"] is not JsonObject t || native.Text("flow") != "") throw new OperationException("WS／gRPC 下一跳不使用 Vision 流控。");
            var type = StreamText(t, "type");
            if (type == "grpc") { StreamFields(t, "type", "service_name"); if (!Regex.IsMatch(StreamText(t, "service_name"), "^[A-Za-z0-9_.-]{1,128}$")) throw new OperationException("gRPC 服务名无效。"); }
            else if (type == "ws")
            {
                StreamFields(t, "type", "path", "headers", "max_early_data", "early_data_header_name"); var path = StreamText(t, "path", "/"); if (path.Length is < 1 or > 2048 || !path.StartsWith('/') || path.StartsWith("//", StringComparison.Ordinal) || path.Any(char.IsControl)) throw new OperationException("WebSocket 路径无效。");
                if (t.ContainsKey("headers"))
                {
                    if (t["headers"] is not JsonObject headers || headers.Count > 16 || headers.Select(p => p.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count() != headers.Count) throw new OperationException("WebSocket 请求头数量或身份无效。");
                    foreach (var pair in headers) { var text = StreamText(headers, pair.Key); if (!Regex.IsMatch(pair.Key, "^[A-Za-z0-9-]{1,64}$") || new[] { "connection", "upgrade", "sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "content-length", "transfer-encoding" }.Contains(pair.Key.ToLowerInvariant()) || text.Length is < 1 or > 2048 || text.Any(c => c < 32 || c > 126)) throw new OperationException("WebSocket 请求头覆盖握手字段或包含无效内容。"); }
                }
                var early = t.ContainsKey("max_early_data") ? StreamNumber(t, "max_early_data", 0, 2048) : 0; if (early > 0 ? StreamText(t, "early_data_header_name") != "Sec-WebSocket-Protocol" : StreamText(t, "early_data_header_name") != "") throw new OperationException("WebSocket 早期数据参数不完整。");
            }
            else throw new OperationException("服务器下一跳传输仅支持原始 TCP 或 sing-box 的 WS／gRPC；XHTTP 不是可忽略的字段。");
        }
        if (protocol == "anytls")
        {
            foreach (var field in new[] { "idle_session_check_interval", "idle_session_timeout" }) if (native.ContainsKey(field)) _ = Duration(StreamText(native, field), 5, 3600);
            if (native.ContainsKey("min_idle_session")) _ = StreamNumber(native, "min_idle_session", 0, 32);
            var metadata = StreamText(native, "client_metadata"); if (metadata.Length > 512 || metadata.Any(char.IsControl)) throw new OperationException("AnyTLS 客户端元数据无效。");
        }
    }
    private static JsonObject XrayStream(JsonObject native, string tag)
    {
        StreamParameters(native);
        if (native.Text("type") == "anytls" || native.ContainsKey("transport") || native.At("tls.ech") != null) throw new OperationException("此下一跳需要 sing-box；固定 Xray 的本轮投影只支持原始 TCP 的 VLESS TLS／Reality 和 Trojan TLS，不删除传输／ECH 字段或增加转接进程。");
        var source = native["tls"]!.AsObject(); var reality = source["reality"] as JsonObject;
        var security = new JsonObject { ["serverName"] = source.Text("server_name") };
        if (source["utls"] != null) security["fingerprint"] = source.Text("utls.fingerprint");
        if (reality != null) { security["publicKey"] = reality.Text("public_key"); security["shortId"] = reality.Text("short_id"); }
        else
        {
            security["allowInsecure"] = false;
            foreach (var (from, to) in new[] { ("min_version", "minVersion"), ("max_version", "maxVersion"), ("alpn", "alpn") }) if (source[from] != null) security[to] = source[from]!.DeepClone();
            if (source["certificate"] != null) { security["disableSystemRoot"] = true; security["certificates"] = new JsonArray(new JsonObject { ["usage"] = "verify", ["certificate"] = new JsonArray(StreamCertificate(source["certificate"]!).Replace("\r", "").Split('\n').Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()) }); }
        }
        var stream = new JsonObject { ["network"] = "raw", ["security"] = reality != null ? "reality" : "tls", [reality != null ? "realitySettings" : "tlsSettings"] = security };
        JsonObject settings;
        if (native.Text("type") == "vless")
        {
            var user = new JsonObject { ["id"] = native.Text("uuid"), ["encryption"] = "none" }; if (native.ContainsKey("flow")) user["flow"] = native["flow"]!.DeepClone();
            settings = new JsonObject { ["vnext"] = new JsonArray(new JsonObject { ["address"] = native.Text("server"), ["port"] = native.Number("server_port"), ["users"] = new JsonArray(user) }) };
        }
        else settings = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["address"] = native.Text("server"), ["port"] = native.Number("server_port"), ["password"] = native.Text("password") }) };
        return new JsonObject { ["tag"] = tag, ["protocol"] = native.Text("type"), ["settings"] = settings, ["streamSettings"] = stream };
    }
}
