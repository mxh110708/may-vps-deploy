using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static partial class ServerOutboundRouting
{
    public static bool IsQuic(JsonNode? native) => native.Text("type") is "hysteria2" or "tuic";
    // A finite supported subset. Unknown dial, file, detour and TLS options must
    // fail before a server write, rather than being silently discarded.
    private static void QuicParameters(JsonObject native)
    {
        var tuic = native.Text("type") == "tuic";
        var fields = new[] { "type", "tag", "server", "server_port", "password", "tls" }.Concat(tuic
            ? ["uuid", "congestion_control", "udp_relay_mode", "heartbeat", "zero_rtt_handshake"]
            : new[] { "up_mbps", "down_mbps", "obfs", "server_ports", "hop_interval", "hop_interval_max" }).ToArray();
        if (native.Any(p => !fields.Contains(p.Key))) throw new OperationException("QUIC 下一跳含有尚未支持的拨号、封装或协议参数，未删除参数或改写服务器。");
        var password = native.Text("password");
        if (password.Length is < 1 or > 4096 || password.Any(char.IsControl)) throw new OperationException("QUIC 下一跳密码无效。");
        if (native["tls"] is not JsonObject tls || tls["enabled"] is not JsonValue enabled || !enabled.TryGetValue<bool>(out var on) || !on || tls.Any(p => p.Key is not ("enabled" or "server_name" or "insecure" or "min_version" or "alpn" or "certificate"))) throw new OperationException("QUIC 下一跳须有完整 TLS / SNI；不支持文件路径或其他高级 TLS 设置。");
        DeploymentPlans.Domain(tls.Text("server_name"));
        if (tls.ContainsKey("insecure") && (tls["insecure"] is not JsonValue insecure || !insecure.TryGetValue<bool>(out var skip) || skip)) throw new OperationException("服务器 QUIC 下一跳不能关闭证书验证。");
        if (tls.ContainsKey("min_version") && tls.Text("min_version") != "1.3") throw new OperationException("服务器 QUIC 下一跳仅支持 TLS 1.3。");
        if (tls.ContainsKey("alpn") && (tls["alpn"] is not JsonArray alpn || alpn.Count != 1 || alpn[0]?.ToString() != "h3")) throw new OperationException("本轮 QUIC 下一跳仅支持 h3 ALPN。");
        if (tls["certificate"] != null)
        {
            var pem = tls["certificate"] is JsonArray list && list.All(i => i is JsonValue j && j.TryGetValue<string>(out _)) ? string.Join('\n', list.Select(i => i!.ToString())) : tls["certificate"] is JsonValue text && text.TryGetValue<string>(out var content) ? content : "";
            if (pem.Length is < 1 or > 65536 || pem.Contains("PRIVATE KEY", StringComparison.Ordinal)) throw new OperationException("下一跳信任证书须为有限的公开 PEM 证书。");
            try { using var certificate = X509Certificate2.CreateFromPem(pem); }
            catch (CryptographicException) { throw new OperationException("下一跳信任证书 PEM 无效。"); }
        }
        if (tuic)
        {
            if (!Guid.TryParseExact(native.Text("uuid"), "D", out var uuid) || uuid == Guid.Empty) throw new OperationException("TUIC 下一跳须使用 v5 UUID 与密码，不能使用 v4 Token。");
            if (native.ContainsKey("congestion_control") && native.Text("congestion_control") is not ("cubic" or "new_reno" or "bbr") || native.ContainsKey("udp_relay_mode") && native.Text("udp_relay_mode") is not ("native" or "quic")) throw new OperationException("TUIC 下一跳拥塞控制或 UDP 中继无效。");
            if (native.ContainsKey("heartbeat")) _ = Duration(native.Text("heartbeat"), 5, 120);
            if (native.ContainsKey("zero_rtt_handshake") && (native["zero_rtt_handshake"] is not JsonValue zero || !zero.TryGetValue<bool>(out var fast) || fast)) throw new OperationException("服务器 TUIC 下一跳须关闭 0-RTT。");
        }
        else
        {
            foreach (var key in new[] { "up_mbps", "down_mbps" }) if (native.ContainsKey(key) && (native[key] is not JsonValue value || !value.TryGetValue<int>(out var rate) || rate is < 0 or > 100000)) throw new OperationException("Hysteria2 下一跳带宽须为 0–100000 Mbps 的整数。");
            if ((native.Number("up_mbps") == 0) != (native.Number("down_mbps") == 0)) throw new OperationException("Hysteria2 下一跳须同时指定两向带宽，或两向均为自适应。");
            if (native["obfs"] is JsonObject obfs)
            {
                if (obfs.Count != 2 || obfs.Any(p => p.Key is not ("type" or "password")) || obfs.Text("type") != "salamander" || obfs.Text("password").Length is < 1 or > 4096 || obfs.Text("password").Any(char.IsControl)) throw new OperationException("Hysteria2 下一跳仅支持完整 Salamander 参数。");
            }
            else if (native.ContainsKey("obfs")) throw new OperationException("Hysteria2 混淆参数无效。");
            if (native["server_ports"] != null)
            {
                var ports = Hysteria2Ports.Expand(Hysteria2Ports.FromNative(native["server_ports"]));
                if (!ports.Contains(native.Number("server_port"))) throw new OperationException("下一跳跳跃端口须包含主端口，最多 256 个。");
            }
            else if (native.ContainsKey("hop_interval") || native.ContainsKey("hop_interval_max")) throw new OperationException("下一跳跳跃间隔缺少端口集合。");
            var interval = native.ContainsKey("hop_interval") ? Duration(native.Text("hop_interval"), 5, 3600) : Hysteria2Ports.DefaultInterval;
            if (native.ContainsKey("hop_interval_max") && Duration(native.Text("hop_interval_max"), 5, 3600) < interval) throw new OperationException("跳跃最大间隔不能小于最小间隔。");
        }
    }
    private static int Duration(string value, int min, int max) => Regex.IsMatch(value, "^[0-9]{1,4}s$") && int.TryParse(value[..^1], out var seconds) && seconds >= min && seconds <= max ? seconds : throw new OperationException("QUIC 下一跳时长格式或范围无效，请使用整数秒。");
    private static JsonObject XrayHysteria(JsonObject native, string tag)
    {
        QuicParameters(native);
        if (native.Text("type") != "hysteria2") throw new OperationException("固定 Xray 不支持 TUIC 下一跳；请选择 sing-box 入站，未增加转接进程。");
        var source = native["tls"]!.AsObject(); var tls = new JsonObject { ["serverName"] = source.Text("server_name"), ["allowInsecure"] = false, ["minVersion"] = "1.3", ["alpn"] = new JsonArray("h3") };
        if (source["certificate"] != null)
        {
            tls["disableSystemRoot"] = true;
            tls["certificates"] = new JsonArray(new JsonObject { ["usage"] = "verify", ["certificate"] = source["certificate"] is JsonArray list ? list.DeepClone() : new JsonArray(source["certificate"]!.ToString()) });
        }
        var quic = new JsonObject { ["congestion"] = native.Number("up_mbps") > 0 ? "brutal" : "bbr" };
        if (native.Number("up_mbps") > 0) { quic["brutalUp"] = native.Number("up_mbps") + " Mbps"; quic["brutalDown"] = native.Number("down_mbps") + " Mbps"; }
        if (native["server_ports"] != null)
        {
            var minimum = native.ContainsKey("hop_interval") ? Duration(native.Text("hop_interval"), 5, 3600) : Hysteria2Ports.DefaultInterval;
            var maximum = native.ContainsKey("hop_interval_max") ? Duration(native.Text("hop_interval_max"), 5, 3600) : minimum;
            quic["udpHop"] = new JsonObject { ["ports"] = Hysteria2Ports.FromNative(native["server_ports"]), ["interval"] = minimum == maximum ? JsonValue.Create(minimum) : JsonValue.Create(minimum + "-" + maximum) };
        }
        var mask = new JsonObject { ["quicParams"] = quic };
        if (native["obfs"] != null) mask["udp"] = new JsonArray(new JsonObject { ["type"] = "salamander", ["settings"] = new JsonObject { ["password"] = native.Text("obfs.password") } });
        return new JsonObject { ["tag"] = tag, ["protocol"] = "hysteria", ["settings"] = new JsonObject { ["version"] = 2, ["address"] = native.Text("server"), ["port"] = native.Number("server_port") },
            ["streamSettings"] = new JsonObject { ["network"] = "hysteria", ["security"] = "tls", ["tlsSettings"] = tls, ["hysteriaSettings"] = new JsonObject { ["version"] = 2, ["auth"] = native.Text("password") }, ["finalmask"] = mask } };
    }
    public static bool SupportedNode(JsonObject node, string role)
    {
        try { var native = NextHop(node); _ = ToOutbound(role, native, Tag); return true; } catch (OperationException) { return false; }
    }
}
