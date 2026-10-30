using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class ClientShareLinks
{
    private static JsonObject CanonicalHysteria(JsonObject native, string name)
    {
        Fields(native, "type", "tag", "server", "server_port", "password", "tls", "server_ports", "hop_interval", "obfs", "up_mbps", "down_mbps");
        if (String(native, "tag") != name) throw new OperationException("Hysteria2 节点名称不完整。");
        var hopping = native["server_ports"] == null ? "" : Hysteria2Ports.FromNative(native["server_ports"]);
        var port = native["server_port"] is JsonValue number && number.TryGetValue<int>(out var value) ? value : hopping != "" && native["server_port"] == null ? Hysteria2Ports.First(hopping) : 0;
        if (port is < 1 or > 65535) throw new OperationException("Hysteria2 主端口无效。");
        // Both cores ignore the single port when hopping is enabled. Preserve
        // it when meaningful, otherwise choose one of the actual remote ports.
        if (hopping != "" && !Hysteria2Ports.Contains(hopping, port)) port = Hysteria2Ports.First(hopping);
        foreach (var key in new[] { "up_mbps", "down_mbps" })
            if (native[key] != null && (native[key] is not JsonValue rate || !rate.TryGetValue<int>(out var n) || n != 0)) throw new OperationException("标准 Hysteria2 分享链接不能保留固定带宽，请导出完整客户端配置。");
        if (String(native, "hop_interval") is not ("" or "30s")) throw new OperationException("标准 Hysteria2 分享链接不能保留自定义跳跃间隔，请导出完整客户端配置。");
        var tls = Object(native, "tls"); Fields(tls, "enabled", "server_name", "insecure", "min_version");
        if (!Boolean(tls, "enabled") || Boolean(tls, "insecure") || String(tls, "min_version") is not ("" or "1.3")) throw new OperationException("Hysteria2 分享须保留可信 TLS 1.3 验证。");
        var result = new JsonObject { ["type"] = "hysteria2", ["tag"] = name, ["server"] = Host(String(native, "server")), ["server_port"] = port, ["password"] = Secret(native, "password"), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = Host(String(tls, "server_name", String(native, "server"))) } };
        if (hopping != "") { result["server_ports"] = Hysteria2Ports.Native(hopping); result["hop_interval"] = "30s"; }
        if (native["obfs"] != null)
        {
            var obfs = Object(native, "obfs"); Fields(obfs, "type", "password");
            if (String(obfs, "type") != "salamander") throw new OperationException("分享暂支持 Salamander，不忽略其他 Hysteria2 混淆设置。");
            result["obfs"] = new JsonObject { ["type"] = "salamander", ["password"] = Secret(obfs, "password") };
        }
        return result;
    }
    private static JsonObject HysteriaFromClash(JsonObject clash, string name)
    {
        Fields(clash, "type", "name", "server", "port", "udp", "password", "sni", "skip-cert-verify", "ports", "hop-interval", "obfs", "obfs-password", "up", "down");
        if (String(clash, "name") != name || !Boolean(clash, "udp", true)) throw new OperationException("Hysteria2 名称或 UDP 限制无法等效分享。");
        foreach (var key in new[] { "up", "down" })
            if (clash[key] != null && clash[key]!.ToString() is not ("0" or "0 Mbps")) throw new OperationException("标准 Hysteria2 分享链接不能保留固定带宽，请导出完整客户端配置。");
        var interval = clash["hop-interval"]?.ToString() ?? "30";
        if (interval != "30") throw new OperationException("标准 Hysteria2 分享链接不能保留自定义跳跃间隔，请导出完整客户端配置。");
        var native = new JsonObject { ["type"] = "hysteria2", ["tag"] = name, ["server"] = String(clash, "server"), ["server_port"] = clash["port"]?.DeepClone(), ["password"] = Secret(clash, "password"), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = String(clash, "sni", String(clash, "server")), ["insecure"] = Boolean(clash, "skip-cert-verify") } };
        if (clash["ports"] != null) { native["server_ports"] = Hysteria2Ports.Native(String(clash, "ports")); native["hop_interval"] = "30s"; }
        if (String(clash, "obfs") != "") native["obfs"] = new JsonObject { ["type"] = String(clash, "obfs"), ["password"] = Secret(clash, "obfs-password") };
        else if (clash["obfs-password"] != null) throw new OperationException("Hysteria2 混淆参数不完整。");
        return CanonicalHysteria(native, name);
    }
}
