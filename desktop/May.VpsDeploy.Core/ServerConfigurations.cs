using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class ServerConfigurations
{
    private static JsonObject Object(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();
    public static string RandomKey(int bytes = 16) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes));
    public static JsonObject Xray(JsonObject plan, JsonObject secrets)
    {
        var inbounds = new JsonArray();
        foreach (var (label, port) in new[] { ("primary", plan.Number("Ports.XrayPrimary")), ("backup", plan.Number("Ports.XrayBackup")) })
        {
            if (port < 1) continue;
            foreach (var (family, address) in new[] { ("ipv4", "0.0.0.0"), ("ipv6", plan.Text("Server.IPv6")) })
            {
                if (address == "") continue;
                inbounds.Add(Object(new { tag = $"reality-{label}-{family}", listen = address, port, protocol = "vless", settings = new { clients = new[] { new { id = secrets.Text("Xray.Uuid"), flow = "xtls-rprx-vision", email = "primary-client" } }, decryption = "none" }, streamSettings = new { network = "raw", security = "reality", realitySettings = new { show = false, target = plan.Text("Reality.TargetMode") == "LocalOwnedTls" ? "127.0.0.1:" + plan.Number("Reality.LocalHttpsPort", 8443) : plan.Text("Reality.Target") + ":443", xver = 0, serverNames = new[] { plan.Text("Reality.ServerName", plan.Text("Reality.Target")) }, privateKey = secrets.Text("Xray.RealityPrivateKey"), shortIds = new[] { secrets.Text("Xray.ShortId") } } } }));
            }
        }
        return new JsonObject { ["log"] = Object(new { access = "none", error = "/var/log/xray/error.log", loglevel = "warning" }), ["inbounds"] = inbounds,
            ["outbounds"] = new JsonArray(Object(new { tag = "direct", protocol = "freedom", settings = plan.Flag("Reality.ForceIpv4Egress", true) ? new { domainStrategy = "ForceIPv4" } : (object)new { } }), Object(new { tag = "block", protocol = "blackhole" })),
            ["routing"] = new JsonObject { ["domainStrategy"] = "AsIs", ["rules"] = plan.Flag("Reality.ForceIpv4Egress", true) ? new JsonArray(Object(new { type = "field", ip = new[] { "::/0" }, outboundTag = "block" })) : new JsonArray() } };
    }
    public static JsonObject AnyTls(JsonObject plan, JsonObject secrets)
    {
        var direct = Object(new { type = "direct", tag = "direct", domain_resolver = new { server = "local", strategy = plan.Flag("AnyTls.ForceIpv4Egress", true) ? "ipv4_only" : "prefer_ipv4" } });
        var padding = plan.At("AnyTls.PaddingScheme")?.DeepClone() ?? new JsonArray("stop=8", "0=30-30", "1=100-400", "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000", "3=9-9,500-1000", "4=500-1000", "5=500-1000", "6=500-1000", "7=500-1000");
        var inbound = Object(new { type = "anytls", tag = "anytls-in", listen = plan.Text("Server.IPv6") == "" ? "0.0.0.0" : "::", listen_port = plan.Number("Ports.AnyTlsPrimary"), users = new[] { new { name = "primary", password = secrets.Text("AnyTls.Password") } }, tls = new { enabled = true, server_name = plan.Text("AnyTls.ServerName"), min_version = "1.3", certificate_path = "/etc/mxh-tls/anytls/fullchain.pem", key_path = "/etc/mxh-tls/anytls/privkey.pem", ech = new { enabled = true, key_path = "/etc/sing-box-anytls/ech-key.pem" } } });
        inbound["padding_scheme"] = padding;
        return new JsonObject { ["log"] = Object(new { level = "warn", timestamp = true }), ["dns"] = Object(new { servers = new[] { new { type = "local", tag = "local" } } }), ["inbounds"] = new JsonArray(inbound), ["outbounds"] = new JsonArray(direct), ["route"] = new JsonObject { ["final"] = "direct", ["rules"] = plan.Flag("AnyTls.ForceIpv4Egress", true) ? new JsonArray(Object(new { ip_version = 6, action = "reject" })) : new JsonArray() } };
    }
    public static JsonObject Shadowsocks(JsonObject plan, JsonObject secrets)
    {
        var users = new JsonArray(Object(new { name = "ipv4-client", password = secrets.Text("Shadowsocks.PrimaryUserKey") }));
        var outbounds = new JsonArray(Object(new { type = "direct", tag = "direct-ipv4", domain_resolver = new { server = "local", strategy = "ipv4_only" } }));
        var rules = new JsonArray(Object(new { auth_user = new[] { "ipv4-client" }, ip_version = 6, action = "reject" }), Object(new { auth_user = new[] { "ipv4-client" }, action = "route", outbound = "direct-ipv4" }));
        if (plan.Flag("Shadowsocks.SecondaryIpv6Enabled"))
        {
            users.Add(Object(new { name = "ipv6-client", password = secrets.Text("Shadowsocks.SecondaryUserKey") }));
            var ipv6 = Object(new { type = "direct", tag = "direct-ipv6", domain_resolver = new { server = "local", strategy = "ipv6_only" } });
            foreach (var (field, setting) in new[] { ("inet6_bind_address", "SecondaryIpv6Address"), ("bind_interface", "SecondaryBindInterface") }) if (plan.Text("Shadowsocks." + setting) != "") ipv6[field] = plan.Text("Shadowsocks." + setting);
            outbounds.Add(ipv6); rules.Add(Object(new { auth_user = new[] { "ipv6-client" }, ip_version = 4, action = "reject" })); rules.Add(Object(new { auth_user = new[] { "ipv6-client" }, action = "route", outbound = "direct-ipv6" }));
        }
        var inbound = Object(new { type = "shadowsocks", tag = "ss2022-in", listen = plan.Text("Server.IPv6") == "" ? "0.0.0.0" : "::", listen_port = plan.Number("Ports.LandingShadowsocks"), method = plan.Text("Shadowsocks.Method"), password = secrets.Text("Shadowsocks.ServerKey"), udp_timeout = "5m" }); inbound["users"] = users;
        return new JsonObject { ["log"] = Object(new { level = "warn", timestamp = true }), ["dns"] = Object(new { servers = new[] { new { type = "local", tag = "local" } } }), ["inbounds"] = new JsonArray(inbound), ["outbounds"] = outbounds, ["route"] = new JsonObject { ["rules"] = rules, ["final"] = "direct-ipv4" } };
    }
}
