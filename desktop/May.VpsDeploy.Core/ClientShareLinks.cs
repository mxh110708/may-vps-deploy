using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record ClientShareRow(string Id, string Name, string Protocol, bool Ready, string Message);
// Preview and record formatting never contain credential-bearing URIs.
public sealed class ClientSharePreview(string fingerprint, IReadOnlyList<ClientShareRow> rows, IReadOnlyList<ClientOutputIssue> issues)
{
    public string SchemeFingerprint { get; } = fingerprint;
    public IReadOnlyList<ClientShareRow> Rows { get; } = rows;
    public IReadOnlyList<ClientOutputIssue> Issues { get; } = issues;
    public bool Ready => Issues.All(i => i.Severity != "Error") && Rows.Any(r => r.Ready);
}

public static partial class ClientShareLinks
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    public static ClientSharePreview Preview(JsonObject scheme)
    {
        var output = ClientOutputRules.Preview(scheme); var rows = new List<ClientShareRow>();
        var list = output.Scheme["Nodes"]!.AsArray(); var nodes = list.OfType<JsonObject>().ToArray();
        if (nodes.Length != list.Count || nodes.Length > ClientNodeImport.MaximumLines || nodes.Any(n => !Regex.IsMatch(n.Text("Id"), "^[a-f0-9]{32}$")) || nodes.Select(n => n.Text("Id")).Distinct(StringComparer.Ordinal).Count() != nodes.Length) throw new OperationException("分享列表最多 200 个节点，节点身份必须完整且唯一。");
        foreach (var node in nodes)
        {
            try { Encode(node); rows.Add(new(node.Text("Id"), node.Text("name"), node.Text("sing_box.type", node.Text("clash.type")), true, node["ServerRoute"] == null ? "可分享独立连接；不包含客户端分组和规则。" : "可分享入口连接；服务器侧落地和分流仍依赖服务器当前配置，不包含在链接中。")); }
            catch (OperationException error) { rows.Add(new(node.Text("Id"), node.Text("name"), node.Text("sing_box.type", node.Text("clash.type")), false, error.Message)); }
        }
        return new(ArchiveStore.Fingerprint(scheme), rows, output.Issues);
    }
    public static string Generate(JsonObject scheme, ClientSharePreview preview, IReadOnlyList<string> selected, string format)
    {
        if (ArchiveStore.Fingerprint(scheme) != preview.SchemeFingerprint) throw new OperationException("方案在预览后已变化，请重新打开分享预览。");
        if (!preview.Ready || selected.Count == 0 || selected.Distinct(StringComparer.Ordinal).Count() != selected.Count || selected.Any(id => !preview.Rows.Any(r => r.Id == id && r.Ready))) throw new OperationException("请选择预览中可完整分享的节点；不会忽略不支持的节点。");
        if (format is not ("Plain" or "Base64")) throw new OperationException("请选择纯文本或 Base64 链接列表。");
        var effective = ClientOutputRules.RequireReady(scheme); var included = selected.ToHashSet(StringComparer.Ordinal); var nodes = effective["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => included.Contains(n.Text("Id"))).ToArray();
        if (nodes.Length != selected.Count) throw new OperationException("所选节点已不在当前输出中，请重新预览。");
        var text = string.Join('\n', nodes.Select(Encode)) + "\n";
        if (text.Length > ClientNodeImport.MaximumCharacters || Utf8.GetByteCount(text) > ClientNodeImport.MaximumCharacters) throw new OperationException("分享内容超过 256 KiB，请减少所选节点后重试。");
        return format == "Plain" ? text : Convert.ToBase64String(Utf8.GetBytes(text));
    }
    private static void Fields(JsonObject value, params string[] allowed)
    { if (value.Any(p => !allowed.Contains(p.Key, StringComparer.Ordinal))) throw new OperationException("存在分享格式无法完整表达的高级参数，请使用完整客户端配置导出。"); }
    private static string String(JsonObject value, string key, string fallback = "")
    { if (!value.TryGetPropertyValue(key, out var item)) return fallback; return item is JsonValue text && text.TryGetValue<string>(out var result) ? result : throw new OperationException("节点参数类型无效，请核对原生配置。"); }
    private static bool Boolean(JsonObject value, string key, bool fallback = false)
    { if (!value.TryGetPropertyValue(key, out var item)) return fallback; return item is JsonValue text && text.TryGetValue<bool>(out var result) ? result : throw new OperationException("TLS 或协议开关类型无效。"); }
    private static JsonObject Object(JsonObject value, string key) => value[key] as JsonObject ?? throw new OperationException("节点缺少完整的 TLS / Reality 配置。");
    private static string Host(string raw)
    {
        if (raw.Length is < 1 or > 253 || raw.Any(char.IsControl) || raw.Contains('%')) throw new OperationException("服务器地址无效。");
        if (IPAddress.TryParse(raw, out var ip)) return ip.ToString();
        if (Uri.CheckHostName(raw) != UriHostNameType.Dns) throw new OperationException("服务器地址无效。");
        return new System.Globalization.IdnMapping().GetAscii(raw).ToLowerInvariant();
    }
    private static JsonObject Canonical(JsonObject native, string name)
    {
        var protocol = String(native, "type"); if (protocol == "hysteria2") return CanonicalHysteria(native, name);
        if (ClientStreamTransports.IsNative(native)) return ClientStreamTransports.Canonical(native, name);
        var common = new[] { "type", "tag", "server", "server_port" };
        Fields(native, common.Concat(protocol switch { "shadowsocks" => new[] { "method", "password" }, "anytls" => new[] { "password", "tls" }, "vless" => new[] { "uuid", "flow", "tls" }, _ => throw new OperationException("分享暂支持 Shadowsocks、SS2022、VLESS Reality + Vision 和基础 AnyTLS。") }).ToArray());
        if (String(native, "tag") != name || native["server_port"] is not JsonValue number || !number.TryGetValue<int>(out var port) || port is < 1 or > 65535) throw new OperationException("节点名称、服务器或端口不完整。");
        var result = new JsonObject { ["type"] = protocol, ["tag"] = name, ["server"] = Host(String(native, "server")), ["server_port"] = port };
        if (protocol == "shadowsocks") { result["method"] = String(native, "method"); result["password"] = Secret(native, "password"); return result; }
        var tls = Object(native, "tls"); if (tls["ech"] != null) throw new OperationException("通用分享链接不能完整保留 ECH，请使用完整客户端配置导出。"); Fields(tls, protocol == "anytls" ? ["enabled", "server_name", "insecure"] : ["enabled", "server_name", "insecure", "utls", "reality", "alpn"]);
        if (!Boolean(tls, "enabled") || Boolean(tls, "insecure")) throw new OperationException("分享必须保留 TLS 证书验证，不能导出关闭验证的配置。");
        var outputTls = new JsonObject { ["enabled"] = true, ["server_name"] = Host(String(tls, "server_name", result.Text("server"))) }; result["tls"] = outputTls;
        if (protocol == "anytls") { result["password"] = Secret(native, "password"); return result; }
        if (!Guid.TryParseExact(String(native, "uuid"), "D", out var uuid) || String(native, "flow") != "xtls-rprx-vision") throw new OperationException("本轮分享仅支持 VLESS Reality + Vision。");
        result["uuid"] = uuid.ToString(); result["flow"] = "xtls-rprx-vision";
        var utls = Object(tls, "utls"); var reality = Object(tls, "reality"); Fields(utls, "enabled", "fingerprint"); Fields(reality, "enabled", "public_key", "short_id");
        if (!Boolean(utls, "enabled") || !Boolean(reality, "enabled")) throw new OperationException("Reality 分享需要原配置已启用的 Reality 与 TLS 指纹，不能隐式修改握手方式。");
        outputTls["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = String(utls, "fingerprint", "chrome") };
        outputTls["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = String(reality, "public_key"), ["short_id"] = String(reality, "short_id").ToLowerInvariant() };
        if (tls["alpn"] != null)
        {
            if (tls["alpn"] is not JsonArray alpn || alpn.Count > 16 || alpn.Any(v => v is not JsonValue text || !text.TryGetValue<string>(out var value) || value.Length is < 1 or > 32 || value.Contains(',') || value.Any(char.IsControl))) throw new OperationException("ALPN 列表无法完整转换为分享参数。");
            if (alpn.Count > 0) outputTls["alpn"] = alpn.DeepClone();
        }
        return result;
    }
    private static string Secret(JsonObject native, string key)
    {
        var secret = String(native, key); if (secret.Length is < 1 or > 4096 || secret.Any(char.IsControl)) throw new OperationException("鉴权参数缺失、过长或含控制字符。"); return secret;
    }
    private static JsonObject FromClash(JsonObject clash, string name)
    {
        var protocol = String(clash, "type");
        if (protocol == "hysteria2") return HysteriaFromClash(clash, name);
        if (ClientStreamTransports.IsClash(clash)) return ClientStreamTransports.FromClash(clash, name);
        Fields(clash, new[] { "type", "name", "server", "port", "udp" }.Concat(protocol switch { "ss" => new[] { "cipher", "password" }, "anytls" => new[] { "password", "sni", "skip-cert-verify" }, "vless" => new[] { "uuid", "flow", "tls", "network", "servername", "client-fingerprint", "reality-opts", "alpn" }, _ => throw new OperationException("此 Clash 协议暂不能生成分享链接。") }).ToArray());
        if (String(clash, "name") != name || !Boolean(clash, "udp", true)) throw new OperationException("节点名称或 UDP 限制无法等效表达为分享链接。");
        var native = new JsonObject { ["type"] = protocol == "ss" ? "shadowsocks" : protocol, ["tag"] = name, ["server"] = String(clash, "server"), ["server_port"] = clash["port"]?.DeepClone() };
        if (protocol == "ss") { native["method"] = String(clash, "cipher"); native["password"] = Secret(clash, "password"); }
        else if (protocol == "anytls") { native["password"] = Secret(clash, "password"); native["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = String(clash, "sni", native.Text("server")), ["insecure"] = Boolean(clash, "skip-cert-verify") }; }
        else
        {
            if (!Boolean(clash, "tls") || String(clash, "network", "tcp") != "tcp") throw new OperationException("仅支持 TCP 的 VLESS Reality + Vision 分享。");
            var reality = Object(clash, "reality-opts"); Fields(reality, "public-key", "short-id"); native["uuid"] = String(clash, "uuid"); native["flow"] = String(clash, "flow");
            native["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = String(clash, "servername", native.Text("server")), ["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = String(clash, "client-fingerprint", "chrome") }, ["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = String(reality, "public-key"), ["short_id"] = String(reality, "short-id") } };
            if (clash["alpn"] != null) native["tls"]!["alpn"] = clash["alpn"]!.DeepClone();
        }
        return Canonical(native, name);
    }
    private static string Encode(JsonObject node)
    {
        if (node.Text("kind") == "landing" || node.Text("sing_box.detour") != "" || node.Text("clash.dialer-proxy") != "") throw new OperationException("此节点依赖客户端入口链路；普通分享链接不能保留该依赖，请导出完整配置。");
        var name = node.Text("name"); if (name.Length is < 1 or > 120 || name.Any(char.IsControl)) throw new OperationException("节点显示名无效。");
        if (VlessXhttp.IsNode(node)) return VlessXhttp.ShareLink(node);
        try
        {
            var native = node["sing_box"] is JsonObject sing ? Canonical(sing, name) : node["clash"] is JsonObject clash ? FromClash(clash, name) : throw new OperationException("节点缺少完整原生参数。");
            if (node["clash"] is JsonObject paired && ArchiveStore.Fingerprint(FromClash(paired, name)) != ArchiveStore.Fingerprint(native)) throw new OperationException("两类客户端的连接参数不一致，不能猜测应分享哪一份。");
            static string E(string value) => Uri.EscapeDataString(value);
            var host = native.Text("server"); var address = (host.Contains(':') ? "[" + host + "]" : host) + ":" + native.Number("server_port"); var tag = "#" + E(name); var protocol = native.Text("type"); string link;
            if (ClientStreamTransports.IsNative(native)) link = ClientStreamTransports.ShareLink(native, name);
            else if (protocol == "shadowsocks")
            {
                var method = native.Text("method"); var password = native.Text("password"); var info = method.StartsWith("2022-", StringComparison.Ordinal) ? E(method) + ":" + E(password) : Convert.ToBase64String(Utf8.GetBytes(method + ":" + password)).TrimEnd('=').Replace('+', '-').Replace('/', '_'); link = "ss://" + info + "@" + address + tag;
            }
            else if (protocol == "anytls") link = "anytls://" + E(native.Text("password")) + "@" + address + "/?sni=" + E(native.Text("tls.server_name")) + "&insecure=0" + tag;
            else if (protocol == "hysteria2")
            {
                if (native["server_ports"] != null) address = (host.Contains(':') ? "[" + host + "]" : host) + ":" + Hysteria2Ports.Authority(Hysteria2Ports.FromNative(native["server_ports"]), native.Number("server_port"));
                link = "hysteria2://" + E(native.Text("password")) + "@" + address + "/?sni=" + E(native.Text("tls.server_name")) + "&insecure=0";
                if (native["obfs"] != null) link += "&obfs=salamander&obfs-password=" + E(native.Text("obfs.password"));
                link += tag;
            }
            else
            {
                link = "vless://" + E(native.Text("uuid")) + "@" + address + "?encryption=none&type=tcp&security=reality&flow=xtls-rprx-vision&sni=" + E(native.Text("tls.server_name")) + "&fp=" + E(native.Text("tls.utls.fingerprint")) + "&pbk=" + E(native.Text("tls.reality.public_key")) + "&sid=" + E(native.Text("tls.reality.short_id"));
                if (native.At("tls.alpn") is JsonArray alpn) link += "&alpn=" + E(string.Join(',', alpn.Select(v => v!.ToString()))); link += tag;
            }
            // Check the complete serialized connection, not only URI syntax or a selected subset.
            var region = name == "Share Entry" ? "Share Validation" : "Share Entry";
            var fixture = new JsonObject { ["Nodes"] = new JsonArray(), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray(region), ["business_groups"] = new JsonArray() } };
            var parsed = ClientNodeImport.Preview(link, fixture, region, "entry");
            if (parsed.Rows.Count != 1 || parsed.Accepted != 1 || ArchiveStore.Fingerprint(Canonical(parsed.Rows[0].Node!["sing_box"]!.AsObject(), name)) != ArchiveStore.Fingerprint(native)) throw new OperationException("分享参数无法完整还原原连接，请使用完整配置导出。");
            return link;
        }
        catch (Exception error) when (error is FormatException or ArgumentException or UriFormatException) { throw new OperationException("分享参数编码无效，请核对服务器、TLS 和鉴权配置。"); }
    }
}
