using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class ServerOutboundRouting
{
    public const string XhttpXrayVersion = "26.3.27";
    public static void RequireXhttpVersion(string version)
    {
        if (version != XhttpXrayVersion) throw new OperationException("XHTTP 下一跳需要本轮固定 Xray " + XhttpXrayVersion + "，请先按独立维护流程核对／更新核心，再重新审阅。");
    }
    public static void RequireXhttpRuntime(JsonObject configuration, string versionLine)
    {
        if (configuration["outbounds"]!.AsArray().Any(IsXrayXhttp) && !System.Text.RegularExpressions.Regex.IsMatch(versionLine, "^Xray " + System.Text.RegularExpressions.Regex.Escape(XhttpXrayVersion) + @"(?:\s|$)"))
            throw new OperationException("实际 Xray 核心版本与 XHTTP 支持范围不符，尚未应用配置。");
    }
    public static bool IsXhttp(JsonNode? native) => native.Text("type") == "vless" && native.Text("transport.type") == "xhttp";
    public static bool IsXrayXhttp(JsonNode? native) => native.Text("protocol") == "vless" && native.Text("streamSettings.network") == "xhttp";
    private static void XhttpParameters(JsonObject native, bool download = false)
    {
        StreamFields(native, "type", "tag", "server", "server_port", "uuid", "flow", "packet_encoding", "tls", "transport");
        if (!IsXhttp(native) || native.Text("flow") != "" || native.Text("packet_encoding", "xudp") != "xudp") throw new OperationException("XHTTP 下一跳须为无 Vision flow 的 VLESS／XUDP；不删除协议字段。");
        if (native["transport"] is not JsonObject transport) throw new OperationException("XHTTP 传输须为完整对象。");
        foreach (var key in new[] { "type", "path", "host", "mode", "http_version" }) _ = StreamText(transport, key);
        if (transport.ContainsKey("download_settings") && transport["download_settings"] == null) throw new OperationException("下载设置应省略或填写完整对象。");
        VlessXhttp.ValidateTransport(transport, native.Flag("tls.reality.enabled"), download);
        var version = VlessXhttp.Version(native);
        if (transport.ContainsKey("http_version") && transport.Text("http_version") != version) throw new OperationException("服务器 XHTTP 下一跳须明确 HTTP/1.1、HTTP/2 或 HTTP/3；不将 auto 降级为固定版本。");
        if (native.At("tls.alpn") is not JsonArray { Count: 1 } alpn || alpn[0]?.ToString() != VlessXhttp.Alpn(version)) throw new OperationException("XHTTP HTTP 版本须与唯一 ALPN 一致，不能丢弃协商选项。");
        if (native.At("tls.ech") != null) throw new OperationException("固定 Xray 的本轮 XHTTP 投影不支持此 ECH 字段。");
        var plain = native.DeepClone().AsObject(); plain.Remove("transport");
        // Existing TLS/Reality validation is shared, after checking XHTTP ALPN.
        if (plain.Flag("tls.reality.enabled")) plain["tls"]!.AsObject().Remove("alpn");
        StreamParameters(plain);
        if (version == "3" && (native.At("tls.utls") != null || native.Text("tls.max_version") == "1.2")) throw new OperationException("HTTP/3 下一跳不使用 uTLS，并需要 TLS 1.3。");
        _ = Address(native.Text("server"));
        if (transport["download_settings"] is JsonObject settings)
        {
            StreamFields(settings, "server", "server_port", "tls", "transport");
            var child = DownloadNative(native, settings); XhttpParameters(child, true);
        }
    }
    private static JsonObject DownloadNative(JsonObject parent, JsonObject settings) => new()
    {
        ["type"] = "vless", ["tag"] = parent.Text("tag"), ["uuid"] = parent["uuid"]!.DeepClone(), ["packet_encoding"] = "xudp",
        ["server"] = settings["server"]?.DeepClone(), ["server_port"] = settings["server_port"]?.DeepClone(),
        ["tls"] = settings["tls"]?.DeepClone(), ["transport"] = settings["transport"]?.DeepClone()
    };
    private static JsonObject XrayXhttpNextHop(JsonObject native, string tag)
    {
        XhttpParameters(native);
        var result = XrayStream(Plain(native), tag);
        result["streamSettings"] = Stream(native);
        return result;
        static JsonObject Plain(JsonObject value)
        {
            var copy = value.DeepClone().AsObject(); copy.Remove("transport");
            if (copy.Flag("tls.reality.enabled")) copy["tls"]!.AsObject().Remove("alpn");
            return copy;
        }
        static JsonObject Stream(JsonObject value)
        {
            var stream = XrayStream(Plain(value), "projection")["streamSettings"]!.DeepClone().AsObject();
            stream["network"] = "xhttp";
            var t = value["transport"]!.AsObject();
            var x = new JsonObject { ["host"] = t.Text("host"), ["path"] = t.Text("path"), ["mode"] = t.Text("mode", "auto") };
            var extra = (t["extra"]?.DeepClone() ?? new JsonObject()).AsObject();
            if (t["download_settings"] is JsonObject download)
            {
                var child = Stream(DownloadNative(value, download)); child["address"] = download["server"]!.DeepClone(); child["port"] = download["server_port"]!.DeepClone();
                extra["downloadSettings"] = child;
            }
            if (extra.Count > 0) x["extra"] = extra;
            stream["xhttpSettings"] = x;
            return stream;
        }
    }
    public static string XhttpConnectionSummary(JsonObject native)
    {
        XhttpParameters(native);
        var text = Describe(native);
        if (native.At("transport.download_settings") is JsonObject download) text += "\n独立下载：" + Describe(DownloadNative(native, download));
        return text;
        static string Describe(JsonObject n) => "VLESS / XHTTP / " + (n.Flag("tls.reality.enabled") ? "Reality" : "TLS") + " / HTTP/" + VlessXhttp.Version(n)
            + " · " + new IPEndPoint(IPAddress.Parse(n.Text("server")), n.Number("server_port")) + " · SNI " + n.Text("tls.server_name") + " · Host " + n.Text("transport.host")
            + " · 路径 " + n.Text("transport.path") + " · 模式 " + n.Text("transport.mode", "auto") + " · 身份与高级参数摘要 " + ArchiveStore.Fingerprint(n)[..12];
    }
    public static IEnumerable<(string Address, int Port)> NextHopEndpoints(JsonObject native)
    {
        yield return (native.Text("server"), native.Number("server_port"));
        if (IsXhttp(native) && native.At("transport.download_settings") is JsonObject d) yield return (d.Text("server"), d.Number("server_port"));
    }
    private static void RejectOwnNextHop(JsonObject plan, JsonObject native)
    {
        if (NextHopEndpoints(native).Any(e => new[] { plan.Text("Server.IPv4"), plan.Text("Server.IPv6") }.Any(s => IPAddress.TryParse(s, out var own) && own.Equals(IPAddress.Parse(e.Address)))))
            throw new OperationException("下一跳的上传或独立下载端点不能指回当前实例。");
    }
    public static void RequireNativeEngine(JsonObject native, bool xray)
    {
        if (IsXhttp(native) && !xray) throw new OperationException("XHTTP 服务器下一跳需要固定 Xray 入站；当前 sing-box 不支持，不增加转接核心或删除传输参数。");
    }
    public static JsonObject XhttpProof(JsonNode outbound) => new()
    {
        ["Transport"] = "xhttp", ["ValidatedProtocol"] = "vless", ["TransportSecurity"] = outbound.Text("streamSettings.security"),
        ["TransportAlpn"] = outbound.Text("streamSettings.security") == "reality" ? "h2" : outbound["streamSettings"]!["tlsSettings"]!["alpn"]![0]!.ToString(),
        ["XhttpFingerprint"] = XhttpFingerprint(outbound["streamSettings"]!)
    };
    // A typed, language-independent digest. Values are not exposed in proof;
    // UTF-8/base64 strings avoid .NET/Python JSON escaping differences.
    public static string XhttpFingerprint(JsonNode node)
    {
        return ArchiveStore.Digest(Encoding.UTF8.GetBytes(Canonical(node)));
        static string String(string value) => "s" + Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        static string Canonical(JsonNode? value) => value switch
        {
            JsonObject o => "{" + string.Join(',', o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => String(p.Key) + ":" + Canonical(p.Value))) + "}",
            JsonArray a => "[" + string.Join(',', a.Select(Canonical)) + "]",
            JsonValue v when v.TryGetValue<string>(out var s) => String(s),
            _ => value?.ToJsonString() ?? "null"
        };
    }
    private static bool XhttpProofMatches(JsonNode outbound, JsonObject proof) => XhttpProof(outbound).All(p => JsonNode.DeepEquals(p.Value, proof[p.Key]));
}
