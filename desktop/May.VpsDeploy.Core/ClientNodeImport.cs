using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record ClientImportRow(int Line, string Status, JsonObject? Node, string Message);
public sealed record ClientImportPreview(string SchemeFingerprint, IReadOnlyList<ClientImportRow> Rows)
{
    public int Accepted => Rows.Count(r => r.Status == "Ready");
}

// A share link is credential material. Never retain it in provenance or error messages.
public static partial class ClientNodeImport
{
    public const int MaximumCharacters = 262144;
    public const int MaximumLines = 200;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static string ConnectionFingerprint(JsonObject node)
    {
        var clash = node["clash"]?.DeepClone().AsObject(); clash?.Remove("name");
        var sing = node["sing_box"]?.DeepClone().AsObject(); sing?.Remove("tag");
        return ArchiveStore.Fingerprint(new JsonObject { ["clash"] = clash, ["sing_box"] = sing });
    }

    public static ClientImportPreview Preview(string input, JsonObject scheme, string region, string role = "Auto")
    {
        if (input.Length > MaximumCharacters) throw new OperationException("一次最多粘贴 256 KiB 的节点链接。");
        if (!scheme["Layout"]!.Strings("region_groups").Contains(region)) throw new OperationException("请选择有效的入口组。");
        if (role is not ("Auto" or "entry" or "landing")) throw new OperationException("节点用途无效。");
        var lines = input.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        if (lines.Length > MaximumLines) throw new OperationException("一次最多导入 200 行；每行一个节点链接。");
        var names = scheme["Nodes"]!.AsArray().Select(n => n!.Text("name")).ToHashSet(StringComparer.Ordinal);
        names.UnionWith(scheme["Layout"]!.Strings("region_groups"));
        names.UnionWith(scheme["Layout"]!["business_groups"]!.AsArray().Select(g => g!.Text("name")));
        names.UnionWith((scheme["Layout"]!["guard_groups"] as JsonArray ?? []).Select(g => g!.Text("name")));
        names.UnionWith(new[] { "DIRECT", "BLOCK", scheme.Text("Layout.default_exit_group"), scheme.Text("Layout.direct_group") });
        var fingerprints = scheme["Nodes"]!.AsArray().OfType<JsonObject>().Select(ConnectionFingerprint).ToHashSet(StringComparer.Ordinal);
        var rows = new List<ClientImportRow>();
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim(); if (line.Length == 0) continue;
            try
            {
                var node = Parse(line); var fingerprint = ConnectionFingerprint(node);
                if (!fingerprints.Add(fingerprint)) { rows.Add(new(i + 1, "Duplicate", null, "与方案或本批次中的连接参数完全相同，跳过。")); continue; }
                var original = node.Text("name"); var name = original; var suffix = 2;
                while (!names.Add(name)) { var tail = " (" + suffix++ + ")"; name = original[..Math.Min(original.Length, 120 - tail.Length)] + tail; }
                node["name"] = name; if(node["clash"]!=null)node["clash"]!["name"] = name; if(node["sing_box"]!=null)node["sing_box"]!["tag"] = name;
                node["Id"] = Guid.NewGuid().ToString("N");
                node["kind"] = role == "Auto" ? node.Text("sing_box.type") == "shadowsocks" ? "landing" : "entry" : role;
                node["region_group"] = region; node["transit_group"] = region;
                node["Source"] = new JsonObject { ["Kind"] = "ShareLink", ["Protocol"] = node.Text("sing_box.type"), ["OriginalName"] = original, ["ImportedAt"] = DateTimeOffset.UtcNow.ToString("O"), ["Fingerprint"] = fingerprint };
                rows.Add(new(i + 1, "Ready", node, name == original ? "可导入" : "名称重复，导入名称已调整为：" + name));
            }
            catch (OperationException error) { rows.Add(new(i + 1, "Rejected", null, error.Message)); }
            catch (Exception error) when (error is FormatException or ArgumentException or OverflowException)
            { rows.Add(new(i + 1, "Rejected", null, "链接编码、认证信息或地址格式无效。")); }
        }
        return new(ArchiveStore.Fingerprint(scheme), rows);
    }

    public static int Apply(JsonObject scheme, ClientImportPreview preview)
    {
        if (ArchiveStore.Fingerprint(scheme) != preview.SchemeFingerprint) throw new OperationException("方案已变化，请重新预览后导入。");
        var nodes = scheme["Nodes"]!.AsArray();
        foreach (var row in preview.Rows.Where(r => r.Status == "Ready")) nodes.Add(row.Node!.DeepClone());
        if (preview.Accepted > 0) scheme.Remove("Candidate");
        return preview.Accepted;
    }

    private static JsonObject Parse(string text)
    {
        if (text.Length > 16384 || text.Any(char.IsWhiteSpace) || text.Any(char.IsControl)) throw new OperationException("链接过长或包含未转义的空白字符。");
        _ = Decode(text); // Uri normalizes malformed percent escapes; check the original first.
        var separator = text.IndexOf("://", StringComparison.Ordinal);
        if (separator < 1) throw new OperationException("每行需为一个完整的节点分享链接。");
        var protocol = text[..separator].ToLowerInvariant();
        if (protocol is "hysteria2" or "hy2") return ParseHysteria2(text);
        if (protocol is not ("vless" or "trojan" or "anytls" or "ss")) throw new OperationException("支持 VLESS Reality + Vision、TLS WS／gRPC 的 VLESS／Trojan、AnyTLS、Shadowsocks 和 Hysteria2；此协议暂不支持。");
        var uri = new Uri(text, UriKind.Absolute);
        if (uri.AbsolutePath is not ("" or "/") || uri.Host.Length == 0 || uri.Port == 0 || uri.Port > 65535) throw new OperationException("服务器地址、端口或链接路径无效。");
        var host = uri.IdnHost.Trim('[', ']').ToLowerInvariant();
        if (Uri.CheckHostName(host) == UriHostNameType.Unknown) throw new OperationException("服务器地址无效。");
        var port = uri.Port < 0 && protocol is "anytls" or "trojan" ? 443 : uri.Port;
        if (port < 1) throw new OperationException("此协议必须指定端口。");
        var name = uri.Fragment.Length > 1 ? Decode(uri.Fragment[1..]) : protocol.ToUpperInvariant() + " · " + host;
        if (name.Length is < 1 or > 120 || name.Any(char.IsControl)) throw new OperationException("显示名称应为 1–120 个可打印字符。");
        var query = Query(uri.Query);
        var clash = new JsonObject { ["name"] = name, ["server"] = host, ["port"] = port };
        var sing = new JsonObject { ["tag"] = name, ["server"] = host, ["server_port"] = port };
        var auth = Decode(uri.UserInfo);
        if(protocol=="vless"&&query.GetValueOrDefault("type")=="xhttp")return ParseXhttp(name,host,port,auth,query);
        if (protocol == "trojan" || protocol == "vless" && query.GetValueOrDefault("type") is "ws" or "grpc") return ParseStream(protocol, name, host, port, auth, query);
        if (protocol == "ss")
        {
            RequireKeys(query, []);
            var encoded = !auth.Contains(':'); if (encoded) auth = Base64(auth);
            var split = auth.IndexOf(':'); if (split < 1 || split == auth.Length - 1) throw new OperationException("Shadowsocks 认证信息不完整。");
            var method = auth[..split].ToLowerInvariant(); var password = auth[(split + 1)..];
            if (!new[] { "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305" }.Contains(method)) throw new OperationException("暂不支持此 Shadowsocks 方法。");
            if (method.StartsWith("2022-", StringComparison.Ordinal))
            {
                if (encoded) throw new OperationException("SS2022 的 method:password 应按 SIP002 使用百分号编码，不能整体 Base64 编码。");
                var size = method == "2022-blake3-aes-128-gcm" ? 16 : 32;
                if (password.Split(':').Any(k => Convert.FromBase64String(k).Length != size)) throw new OperationException("SS2022 密钥长度与方法不匹配。");
            }
            clash["type"] = "ss"; clash["cipher"] = method; clash["password"] = password; clash["udp"] = true;
            sing["type"] = "shadowsocks"; sing["method"] = method; sing["password"] = password;
        }
        else if (protocol == "anytls")
        {
            RequireKeys(query, ["sni", "insecure"]);
            if (auth.Length == 0) throw new OperationException("AnyTLS 链接缺少密码。");
            if (query.GetValueOrDefault("insecure", "0") != "0") throw new OperationException("不导入跳过证书验证的 AnyTLS 链接，请提供可验证的 TLS 配置。");
            var sni = query.GetValueOrDefault("sni", host); ValidateSni(sni);
            clash["type"] = "anytls"; clash["password"] = auth; clash["sni"] = sni; clash["skip-cert-verify"] = false;
            sing["type"] = "anytls"; sing["password"] = auth; sing["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = sni };
        }
        else
        {
            RequireKeys(query, ["security", "type", "encryption", "flow", "sni", "fp", "pbk", "sid", "alpn", "spx"]);
            if (!Guid.TryParseExact(auth, "D", out var uuid)) throw new OperationException("VLESS UUID 无效。");
            if (query.GetValueOrDefault("security") != "reality" || query.GetValueOrDefault("flow") != "xtls-rprx-vision" || query.GetValueOrDefault("type", "tcp") != "tcp" || query.GetValueOrDefault("encryption", "none") != "none") throw new OperationException("当前仅导入 TCP 的 VLESS Reality + Vision 链接。");
            // spiderX has no sing-box equivalent. Refuse a nonempty value rather than drop it.
            if (query.GetValueOrDefault("spx", "") != "") throw new OperationException("当前双客户端导入不支持 spiderX 参数，请核对后移除此参数。");
            var key = query.GetValueOrDefault("pbk", "");
            if (!Regex.IsMatch(key, "^[A-Za-z0-9_-]{43}$") || Convert.FromBase64String(key.Replace('-', '+').Replace('_', '/') + "=").Length != 32) throw new OperationException("Reality 公钥无效。");
            var shortId = query.GetValueOrDefault("sid", ""); if (!Regex.IsMatch(shortId, "^(?:[0-9a-fA-F]{2}){0,8}$")) throw new OperationException("Reality short-id 应为不超过 16 位的偶数长度十六进制。");
            var sni = query.GetValueOrDefault("sni", host); ValidateSni(sni);
            var fingerprint = query.GetValueOrDefault("fp", "chrome");
            if (!new[] { "chrome", "firefox", "edge", "safari", "ios", "android", "random" }.Contains(fingerprint)) throw new OperationException("此 TLS 指纹不在本轮双客户端支持范围内。");
            clash["type"] = "vless"; clash["uuid"] = uuid.ToString(); clash["flow"] = "xtls-rprx-vision"; clash["tls"] = true; clash["network"] = "tcp"; clash["udp"] = true;
            clash["servername"] = sni; clash["client-fingerprint"] = fingerprint; clash["reality-opts"] = new JsonObject { ["public-key"] = key, ["short-id"] = shortId.ToLowerInvariant() };
            sing["type"] = "vless"; sing["uuid"] = uuid.ToString(); sing["flow"] = "xtls-rprx-vision";
            var tls = new JsonObject { ["enabled"] = true, ["server_name"] = sni, ["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = fingerprint }, ["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = key, ["short_id"] = shortId.ToLowerInvariant() } }; sing["tls"] = tls;
            if (query.TryGetValue("alpn", out var alpn))
            {
                var values = alpn.Split(','); if (values.Any(v => v.Length is < 1 or > 32 || v.Any(char.IsControl))) throw new OperationException("ALPN 参数无效。");
                clash["alpn"] = new JsonArray(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray()); tls["alpn"] = clash["alpn"]!.DeepClone();
            }
        }
        return new JsonObject { ["name"] = name, ["clash"] = clash, ["sing_box"] = sing };
    }

    private static JsonObject ParseHysteria2(string text)
    {
        // System.Uri rejects the protocol's standard multi-port authority. Only
        // replace that field for URI parsing; do not rewrite user credentials.
        var start = text.IndexOf("://", StringComparison.Ordinal) + 3;
        var end = text.IndexOfAny(['/', '?', '#'], start); if (end < 0) end = text.Length;
        var authority = text[start..end]; var at = authority.LastIndexOf('@');
        var server = authority[(at + 1)..]; var colon = server.StartsWith('[') ? server.IndexOf(':', server.IndexOf(']') + 1) : server.LastIndexOf(':');
        var ports = colon >= 0 ? server[(colon + 1)..] : "443";
        var normalized = Hysteria2Ports.Normalize(ports);
        var main = colon >= 0 ? int.Parse(ports.Split(',')[0].Split('-')[0], System.Globalization.CultureInfo.InvariantCulture) : 443;
        var rewritten = colon < 0 ? text[..end] + ":443" + text[end..] : text[..(start + at + 1 + colon + 1)] + main + text[end..];
        var uri = new Uri(rewritten, UriKind.Absolute);
        if (uri.AbsolutePath is not ("" or "/") || uri.Host.Length == 0 || uri.Port is < 1 or > 65535) throw new OperationException("Hysteria2 服务器、端口或路径无效。");
        var host = uri.IdnHost.Trim('[', ']').ToLowerInvariant(); if (Uri.CheckHostName(host) == UriHostNameType.Unknown) throw new OperationException("Hysteria2 服务器地址无效。");
        var password = Decode(uri.UserInfo); if (password.Length is < 1 or > 4096) throw new OperationException("Hysteria2 链接缺少有效鉴权信息。");
        var query = Query(uri.Query); RequireKeys(query, ["sni", "insecure", "obfs", "obfs-password"]);
        if (query.GetValueOrDefault("insecure", "0") != "0") throw new OperationException("不导入跳过证书验证的 Hysteria2 链接。");
        var sni = query.GetValueOrDefault("sni", host); ValidateSni(sni);
        var name = uri.Fragment.Length > 1 ? Decode(uri.Fragment[1..]) : "Hysteria2 · " + host;
        if (name.Length is < 1 or > 120 || name.Any(char.IsControl)) throw new OperationException("显示名称应为 1–120 个可打印字符。");
        var clash = new JsonObject { ["name"] = name, ["type"] = "hysteria2", ["server"] = host, ["port"] = main, ["password"] = password, ["sni"] = sni, ["skip-cert-verify"] = false, ["udp"] = true };
        var sing = new JsonObject { ["tag"] = name, ["type"] = "hysteria2", ["server"] = host, ["server_port"] = main, ["password"] = password, ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = sni } };
        if (ports.Contains(',') || ports.Contains('-')) Hysteria2Ports.Apply(clash, sing, normalized, Hysteria2Ports.DefaultInterval);
        var obfs = query.GetValueOrDefault("obfs", ""); var obfsPassword = query.GetValueOrDefault("obfs-password", "");
        if (obfs != "" && obfs != "salamander" || obfs == "" && obfsPassword != "" || obfs == "salamander" && (obfsPassword.Length is < 1 or > 4096)) throw new OperationException("Hysteria2 仅支持完整的 Salamander 混淆参数。");
        if (obfs == "salamander") { clash["obfs"] = obfs; clash["obfs-password"] = obfsPassword; sing["obfs"] = new JsonObject { ["type"] = obfs, ["password"] = obfsPassword }; }
        return new JsonObject { ["name"] = name, ["clash"] = clash, ["sing_box"] = sing };
    }
    private static void ValidateSni(string value) { if (value.Length == 0 || Uri.CheckHostName(value) == UriHostNameType.Unknown) throw new OperationException("TLS 服务器名称无效。"); }
    private static string Decode(string value)
    {
        var result = new StringBuilder();
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] != '%') { result.Append(value[i]); continue; }
            var bytes = new List<byte>();
            do
            {
                if (i + 2 >= value.Length || !Uri.IsHexDigit(value[i + 1]) || !Uri.IsHexDigit(value[i + 2])) throw new FormatException();
                bytes.Add(Convert.ToByte(value.Substring(i + 1, 2), 16)); i += 3;
            } while (i < value.Length && value[i] == '%');
            result.Append(Utf8.GetString(bytes.ToArray())); i--;
        }
        var decoded = result.ToString(); if (decoded.Any(char.IsControl)) throw new FormatException(); return decoded;
    }
    private static string Base64(string value) => Utf8.GetString(Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '=')));
    private static Dictionary<string, string> Query(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var split = pair.IndexOf('='); if (split < 1) throw new OperationException("查询参数应为 key=value。");
            if (!result.TryAdd(Decode(pair[..split]), Decode(pair[(split + 1)..]))) throw new OperationException("链接包含重复参数，请核对后导入。");
        }
        return result;
    }
    private static void RequireKeys(Dictionary<string, string> query, string[] allowed)
    {
        if (query.Keys.Any(k => !allowed.Contains(k))) throw new OperationException("链接含本轮尚未支持的参数或插件，未忽略其设置，请核对链接。");
    }
}
