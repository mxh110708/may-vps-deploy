using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class ClientProfiles
{
    public sealed record NodePair(string Name, string Role, string Family, JsonObject Clash, JsonObject SingBox, string EgressFamily = "IPv4", bool IsBackup = false, string ServerRouteFingerprint = "")
    {
        public string DisplayName => IsBackup ? Name[..^7] + " · 备用入口" : Name;
    }
    public static IEnumerable<NodePair> Nodes(JsonObject plan, JsonObject secrets, bool enabledOnly = false)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var role in DeploymentPlans.Roles[..3])
        {
            var installed = plan.At("ProtocolInventory." + role) == null ? enabledOnly ? DeploymentPlans.InitiallyEnabled(plan, role) : DeploymentPlans.Uses(plan, role) : plan.Flag("ProtocolInventory." + role + (enabledOnly ? ".Enabled" : ".Installed"));
            if (!installed) continue;
            foreach (var (family, address) in new[] { ("IPv4", plan.Text("Server.IPv4")), ("IPv6", plan.Text("Server.IPv6")) })
            {
                if (address == "") continue;
                // A landing IPv6 user selects its egress family; it can still use the IPv4 entry listener.
                var users = role == "ShadowsocksLanding" && plan.Flag("Shadowsocks.SecondaryIpv6Enabled") ? new[] { "IPv4", "IPv6" } : new[] { "IPv4" };
                foreach (var egress in users)
                {
                    var name = role == "ShadowsocksLanding" ? DeploymentNaming.LandingName(plan, egress, family) : plan.Text("NodeName") + (plan.Text("Server.IPv6") == "" ? "" : "-" + family);
                    if (role is "RealityEntry" or "AnyTlsEntry" && DeploymentPlans.Roles[..2].Count(r => plan.Flag("ProtocolInventory." + r + ".Installed", DeploymentPlans.Uses(plan, r))) > 1) name += role == "RealityEntry" ? "-Reality" : "-AnyTLS";
                    foreach (var port in (role == "RealityEntry" && plan.Number("Ports.XrayBackup") > 0 ? new[] { plan.Number("Ports.XrayPrimary"), plan.Number("Ports.XrayBackup") } : new[] { plan.Number(role == "RealityEntry" ? "Ports.XrayPrimary" : role == "AnyTlsEntry" ? "Ports.AnyTlsPrimary" : "Ports.LandingShadowsocks") }).Distinct())
                    {
                        var nodeName = name + (role == "RealityEntry" && port != plan.Number("Ports.XrayPrimary") ? "-Backup" : "");
                        if (!names.Add(nodeName)) throw new OperationException("导出的节点名称重复，请调整落地节点名称。");
                        var clash = new JsonObject { ["name"] = nodeName, ["server"] = address, ["port"] = port, ["udp"] = true };
                        var sing = new JsonObject { ["tag"] = nodeName, ["server"] = address, ["server_port"] = port };
                        if (role == "RealityEntry")
                        {
                            clash["type"] = "vless"; clash["uuid"] = secrets.Text("Xray.Uuid"); clash["flow"] = "xtls-rprx-vision"; clash["tls"] = true; clash["network"] = "tcp"; clash["servername"] = plan.Text("Reality.ServerName", plan.Text("Reality.Target")); clash["client-fingerprint"] = "chrome"; clash["reality-opts"] = new JsonObject { ["public-key"] = secrets.Text("Xray.RealityClientKey"), ["short-id"] = secrets.Text("Xray.ShortId") };
                            sing["type"] = "vless"; sing["uuid"] = secrets.Text("Xray.Uuid"); sing["flow"] = "xtls-rprx-vision"; sing["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = plan.Text("Reality.ServerName", plan.Text("Reality.Target")), ["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = "chrome" }, ["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = secrets.Text("Xray.RealityClientKey"), ["short_id"] = secrets.Text("Xray.ShortId") } };
                        }
                        else if (role == "AnyTlsEntry")
                        {
                            var pem = secrets.Text("AnyTls.EchClientConfigPem"); var payload = string.Join("", pem.Split('\n').Where(l => l != "" && !l.StartsWith("-----")));
                            clash["type"] = "anytls"; clash["password"] = secrets.Text("AnyTls.Password"); clash["sni"] = plan.Text("AnyTls.ServerName"); clash["skip-cert-verify"] = false; clash["ech-opts"] = new JsonObject { ["enable"] = true, ["config"] = payload };
                            sing["type"] = "anytls"; sing["password"] = secrets.Text("AnyTls.Password"); sing["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = plan.Text("AnyTls.ServerName"), ["min_version"] = "1.3", ["ech"] = new JsonObject { ["enabled"] = true, ["config"] = new JsonArray(pem.TrimEnd().Split('\n').Select(l => (JsonNode?)JsonValue.Create(l)).ToArray()) } };
                        }
                        else
                        {
                            var password = secrets.Text("Shadowsocks.ServerKey") + ":" + secrets.Text(egress == "IPv6" ? "Shadowsocks.SecondaryUserKey" : "Shadowsocks.PrimaryUserKey");
                            clash["type"] = "ss"; clash["cipher"] = plan.Text("Shadowsocks.Method"); clash["password"] = password;
                            sing["type"] = "shadowsocks"; sing["method"] = plan.Text("Shadowsocks.Method"); sing["password"] = password;
                        }
                        yield return new(nodeName, role, family, clash, sing, ServerOutboundRouting.EgressFamily(plan, role, egress), role == "RealityEntry" && port != plan.Number("Ports.XrayPrimary"), ServerOutboundRouting.Roles.Contains(role) && plan.At("ServerOutbound." + role) is JsonObject serverRoute ? ArchiveStore.Fingerprint(serverRoute) : "");
                    }
                }
            }
        }
    }
    public static JsonObject SingProbe(NodePair node, int port, NodePair? entry = null)
    {
        var outbound = node.SingBox.DeepClone(); var outbounds = new JsonArray(outbound);
        if (entry != null) { var transit = entry.SingBox.DeepClone(); transit["tag"] = "mxh-probe-entry"; outbound["detour"] = "mxh-probe-entry"; outbounds.Add(transit); }
        return new JsonObject { ["log"] = new JsonObject { ["level"] = "warn" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "mixed", ["tag"] = "probe-in", ["listen"] = "127.0.0.1", ["listen_port"] = port }), ["outbounds"] = outbounds, ["route"] = new JsonObject { ["final"] = node.Name } };
    }
    // JSON is a YAML subset and preserves all string values without manual quoting.
    public static JsonObject ClashProbe(NodePair node, int port, NodePair? entry = null)
    {
        var proxy = node.Clash.DeepClone(); var proxies = new JsonArray(proxy);
        if (entry != null) { var transit = entry.Clash.DeepClone(); transit["name"] = "mxh-probe-entry"; proxy["dialer-proxy"] = "mxh-probe-entry"; proxies.Add(transit); }
        return new JsonObject { ["mixed-port"] = port, ["allow-lan"] = false, ["bind-address"] = "127.0.0.1", ["mode"] = "rule", ["log-level"] = "warning", ["ipv6"] = true, ["geodata-mode"] = true, ["geo-auto-update"] = false, ["proxies"] = proxies, ["proxy-groups"] = new JsonArray(new JsonObject { ["name"] = "Probe", ["type"] = "select", ["proxies"] = new JsonArray(node.Name) }), ["rules"] = new JsonArray("MATCH,Probe") };
    }
    public static void Export(JsonObject plan, JsonObject secrets, string directory)
    {
        Directory.CreateDirectory(directory);
        var documents = Documents(plan, secrets).ToArray();
        foreach (var name in ExportNames.Except(documents.Select(d => d.Name), StringComparer.Ordinal))
        {
            var file = SafePath.Resolve(directory, name); if (!File.Exists(file)) continue;
            // These exact private fragment names are owned by this exporter.
            // A foreign/non-fragment file in their place needs manual review.
            var old = ArchiveStore.ReadJson(file);
            if (old.Count != 1 || old.First().Key is not ("outbounds" or "proxies") || old.First().Value is not JsonArray) throw new OperationException("当前客户端片段已被替换，未删除外部文件。");
            File.Delete(file);
        }
        foreach (var document in documents) ArchiveStore.WriteJson(SafePath.Resolve(directory, document.Name), document.Document);
    }
    public static readonly string[] ExportNames = ["sing-box-outbounds.private.json", "mihomo-test-primary.yaml", "sing-box-anytls-outbounds.private.json", "mihomo-anytls-test.yaml", "sing-box-shadowsocks-outbounds.private.json", "mihomo-shadowsocks-test.yaml"];
    public static IEnumerable<(string Name, JsonObject Document)> Documents(JsonObject plan, JsonObject secrets)
    {
        foreach (var group in Nodes(plan, secrets).GroupBy(n => n.Role))
        {
            var jsonName = group.Key == "RealityEntry" ? "sing-box-outbounds.private.json" : group.Key == "AnyTlsEntry" ? "sing-box-anytls-outbounds.private.json" : "sing-box-shadowsocks-outbounds.private.json";
            var yamlName = group.Key == "RealityEntry" ? "mihomo-test-primary.yaml" : group.Key == "AnyTlsEntry" ? "mihomo-anytls-test.yaml" : "mihomo-shadowsocks-test.yaml";
            yield return (jsonName, new JsonObject { ["outbounds"] = new JsonArray(group.Select(n => n.SingBox.DeepClone()).ToArray()) });
            yield return (yamlName, new JsonObject { ["proxies"] = new JsonArray(group.Select(n => n.Clash.DeepClone()).ToArray()) });
        }
    }
}
