using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class InboundRendering
{
    public static JsonObject Core(AppPaths paths)
    {
        var versions = ArchiveStore.ReadJson(paths.Resolve("config/versions.json"));
        return new JsonObject { ["Engine"] = "sing-box", ["Version"] = versions.Text("sing_box.version"), ["Artifact"] = versions.Text("sing_box.assets.amd64.name"), ["Sha256"] = versions.Text("sing_box.assets.amd64.sha256"), ["Reality"] = new JsonObject { ["Engine"] = "xray", ["Version"] = versions.Text("xray.version"), ["Artifact"] = versions.Text("xray.assets.amd64.name"), ["Sha256"] = versions.Text("xray.assets.amd64.sha256") } };
    }
    public static string CorePath(JsonObject core) => "/usr/local/lib/may-inbound-cores/" + core.Text("Sha256") + "/" + core.Text("Engine");
    public static string Unit(string id) => "may-inbound-" + InboundCatalog.Id(id) + ".service";
    public static JsonObject ResolveOutbound(ArchiveStore store, string instance, JsonObject outbound)
    {
        if (outbound.Text("Kind") == "Direct") return new JsonObject { ["type"] = "direct", ["tag"] = "egress", ["domain_resolver"] = new JsonObject { ["server"] = "local", ["strategy"] = outbound.Text("Family") switch { "IPv4" => "ipv4_only", "IPv6" => "ipv6_only", _ => "prefer_ipv4" } } };
        var reference = outbound["Source"]!; var scheme = store.ReadSecret(ServerOutboundRouting.SchemeFile(store.Paths, reference.Text("SchemeId")));
        try
        {
            var node = scheme["Nodes"]!.AsArray().OfType<JsonObject>().SingleOrDefault(n => n.Text("Id") == reference.Text("NodeId")) ?? throw new OperationException("出站来源节点已移除。");
            if (ArchiveStore.Fingerprint(node) != reference.Text("Fingerprint")) throw new OperationException("出站来源已变化，请重新选择并审阅。");
            if (node.Text("ManagedOrigin.Instance") == instance || node.Text("InboundOrigin.Instance") == instance || node.Text("ForwardedOrigin.Instance") == instance) throw new OperationException("入站不能将本实例的受管节点再次作为自身出站。");
            ManagedNodeSources.Verify(store, new JsonArray(node["ManagedOrigin"]?.DeepClone()).WithoutNulls());
            ForwardedNodeSources.VerifyNodes(store, [node]);
            InboundSources.VerifyNodes(store, [node]);
            if (node["sing_box"] is not JsonObject native || native.Text("type") is not ("shadowsocks" or "vless" or "anytls" or "hysteria2" or "tuic") || native.Text("detour") != "" || native.Text("network") == "udp") throw new OperationException("出站须为直接可连接的受支持原生代理节点。");
            if (ServerOutboundRouting.IsQuic(native)) { var quic = ServerOutboundRouting.NextHop(node); quic["tag"] = "egress"; return quic; }
            var result = native.DeepClone().AsObject(); result["tag"] = "egress"; return result;
        }
        finally { scheme.Clear(); }
    }
    private static JsonArray WithoutNulls(this JsonArray values) => new(values.Where(v => v != null).Select(v => v!.DeepClone()).ToArray());
    public static bool RequiresApplicationUdp(ArchiveStore store, string instance, JsonObject model, string inboundId)
    {
        var inbound = InboundCatalog.Items(model, "Inbounds").Single(i => i.Text("Id") == inboundId);
        var outbound = InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == inbound.Text("OutboundId"));
        return inbound.Text("Protocol") is "TuicV5" or "VLESS" || outbound.Text("Kind") == "Proxy" && ServerOutboundRouting.IsQuic(ResolveOutbound(store, instance, outbound));
    }
    public static JsonObject Configuration(ArchiveStore store, JsonObject plan, JsonObject model, JsonObject credentials, JsonObject inbound)
    {
        var id = inbound.Text("Id"); var options = inbound["Options"]!; var users = new JsonArray();
        foreach (var userId in inbound.Strings("UserIds"))
        {
            var value = credentials.Text("Users." + userId + ".Value");
            users.Add(inbound.Text("Protocol") == "Reality" ? new JsonObject { ["name"] = userId, ["uuid"] = value, ["flow"] = "xtls-rprx-vision" } : new JsonObject { ["name"] = userId, ["password"] = value });
            if (inbound.Text("Protocol") == "TuicV5") users[^1]!["uuid"] = credentials.Text("Users." + userId + ".Uuid");
        }
        var input = new JsonObject { ["type"] = inbound.Text("Protocol") switch { "Reality" => "vless", "AnyTLS" => "anytls", "Hysteria2" => "hysteria2", "TuicV5" => "tuic", _ => "shadowsocks" }, ["tag"] = id, ["listen"] = inbound.Text("Listener.Address"), ["listen_port"] = inbound.Number("Listener.Port"), ["users"] = users };
        if (inbound.Text("Protocol") == "Reality") input["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = options.Text("ServerName"), ["reality"] = new JsonObject { ["enabled"] = true, ["handshake"] = new JsonObject { ["server"] = options.Text("HandshakeServer"), ["server_port"] = options.Number("HandshakePort") }, ["private_key"] = credentials.Text("Inbounds." + id + ".RealityPrivateKey"), ["short_id"] = new JsonArray(options.Text("ShortId")) } };
        else if (inbound.Text("Protocol") is "AnyTLS" or "Hysteria2" or "TuicV5")
        {
            var certificate = credentials["Certificates"]![inbound.Text("CertificateId")]!;
            input["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = options.Text("ServerName"), ["min_version"] = "1.3", ["certificate"] = Lines(certificate.Text("CertificatePem")), ["key"] = Lines(certificate.Text("PrivateKeyPem")) };
            if (options.Flag("EchEnabled")) input["tls"]!["ech"] = new JsonObject { ["enabled"] = true, ["key"] = Lines(credentials.Text("Inbounds." + id + ".EchKey")) };
            if (inbound.Text("Protocol") == "TuicV5")
            {
                input["tls"]!["alpn"] = new JsonArray("h3"); input["congestion_control"] = options.Text("CongestionControl"); input["auth_timeout"] = options.Number("AuthTimeoutSeconds") + "s";
                input["heartbeat"] = options.Number("HeartbeatSeconds") + "s"; input["zero_rtt_handshake"] = false;
            }
            if (inbound.Text("Protocol") == "Hysteria2")
            {
                // The model/client rates use the client's perspective; server
                // transmit/receive caps therefore point in the other direction.
                if (options.Number("UploadMbps") > 0) { input["up_mbps"] = options.Number("DownloadMbps"); input["down_mbps"] = options.Number("UploadMbps"); }
                else input["ignore_client_bandwidth"] = true;
                if (options.Flag("ObfsEnabled")) input["obfs"] = new JsonObject { ["type"] = "salamander", ["password"] = credentials.Text("Inbounds." + id + ".ObfsPassword") };
            }
        }
        else { input["method"] = options.Text("Method"); input["password"] = credentials.Text("Inbounds." + id + ".ServerKey"); }
        var outbound = InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == inbound.Text("OutboundId"));
        var actual = ResolveOutbound(store, plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy", outbound);
        if (actual.Text("server") != "" && new[] { plan.Text("Server.IPv4"), plan.Text("Server.IPv6"), "127.0.0.1", "::1", "localhost" }.Contains(actual.Text("server")) && InboundCatalog.Items(model, "Inbounds").Any(i => Hysteria2Ports.ListenerPorts(i).Contains(actual.Number("server_port")))) throw new OperationException("出站指向本实例的入站，可能形成环路。");
        if (inbound.Text("Protocol") == "Reality") return XrayReality(inbound, credentials, options.AsObject(), outbound, actual);
        if (inbound.Text("Protocol") == "VLESS") return XrayXhttp(inbound, credentials, outbound);
        var rules = new JsonArray(); if (outbound.Text("Family") != "Auto") rules.Add(new JsonObject { ["ip_version"] = outbound.Text("Family") == "IPv4" ? 6 : 4, ["action"] = "reject" });
        return new JsonObject { ["log"] = new JsonObject { ["level"] = "warn", ["timestamp"] = true }, ["dns"] = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["type"] = "local", ["tag"] = "local" }) }, ["inbounds"] = new JsonArray(input), ["outbounds"] = new JsonArray(actual), ["route"] = new JsonObject { ["final"] = "egress", ["rules"] = rules } };
    }
    private static JsonObject XrayReality(JsonObject inbound, JsonObject credentials, JsonObject options, JsonObject outbound, JsonObject native)
    {
        var clients = new JsonArray(inbound.Strings("UserIds").Select(id => (JsonNode)new JsonObject { ["id"] = credentials.Text("Users." + id + ".Value"), ["email"] = id, ["flow"] = "xtls-rprx-vision" }).ToArray());
        var input = new JsonObject { ["tag"] = inbound.Text("Id"), ["listen"] = inbound.Text("Listener.Address"), ["port"] = inbound.Number("Listener.Port"), ["protocol"] = "vless", ["settings"] = new JsonObject { ["clients"] = clients, ["decryption"] = "none" }, ["streamSettings"] = new JsonObject { ["network"] = "raw", ["security"] = "reality", ["realitySettings"] = new JsonObject { ["show"] = false, ["target"] = options.Text("HandshakeServer") + ":" + options.Number("HandshakePort"), ["xver"] = 0, ["serverNames"] = new JsonArray(options.Text("ServerName")), ["privateKey"] = credentials.Text("Inbounds." + inbound.Text("Id") + ".RealityPrivateKey"), ["shortIds"] = new JsonArray(options.Text("ShortId")) } } };
        var output = outbound.Text("Kind") == "Direct" ? new JsonObject { ["tag"] = "egress", ["protocol"] = "freedom", ["settings"] = new JsonObject { ["domainStrategy"] = outbound.Text("Family") switch { "IPv4" => "ForceIPv4", "IPv6" => "ForceIPv6", _ => "AsIs" } } } : ServerOutboundRouting.XrayNextHop(native);
        var rules = new JsonArray(); if (outbound.Text("Family") != "Auto") rules.Add(new JsonObject { ["type"] = "field", ["ip"] = new JsonArray(outbound.Text("Family") == "IPv4" ? "::/0" : "0.0.0.0/0"), ["outboundTag"] = "block" });
        return new JsonObject { ["log"] = new JsonObject { ["access"] = "none", ["loglevel"] = "warning" }, ["inbounds"] = new JsonArray(input), ["outbounds"] = new JsonArray(output, new JsonObject { ["tag"] = "block", ["protocol"] = "blackhole" }), ["routing"] = new JsonObject { ["domainStrategy"] = "AsIs", ["rules"] = rules } };
    }
    private static JsonArray Lines(string value) => new(value.Replace("\r\n", "\n").Trim().Split('\n').Select(line => (JsonNode?)JsonValue.Create(line)).ToArray());
    public static JsonObject Payload(ArchiveStore store, JsonObject plan, JsonObject model, JsonObject credentials, JsonObject? pinnedCore = null)
    {
        var core = (pinnedCore ?? Core(store.Paths)).DeepClone(); var bindings = new JsonArray(); var configs = new JsonObject();
        foreach (var inbound in InboundCatalog.Items(model, "Inbounds"))
        {
            var config = Configuration(store, plan, model, credentials, inbound); var bytes = ArchiveStore.JsonBytes(config); var id = inbound.Text("Id");
            configs[id] = Convert.ToBase64String(bytes);
            var outbound = InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == inbound.Text("OutboundId"));
            var coreHash = InboundCatalog.UsesXray(inbound) ? core["Reality"]!.Text("Sha256") : core.Text("Sha256");
            var clientIdentity = new JsonObject { ["CoreSha256"] = coreHash, ["Options"] = inbound["Options"]!.DeepClone(), ["Certificate"] = InboundCatalog.Items(model, "Certificates").SingleOrDefault(c => c.Text("Id") == inbound.Text("CertificateId"))?.Text("Sha256") ?? "", ["Family"] = outbound.Text("Family"), ["ExpectedAddress"] = outbound.Text("ExpectedAddress") };
            bindings.Add(new JsonObject { ["Id"] = id, ["Enabled"] = inbound.Flag("Enabled"), ["Sha256"] = ArchiveStore.Digest(bytes), ["ClientSha256"] = ArchiveStore.Fingerprint(clientIdentity), ["Port"] = inbound.Number("Listener.Port"), ["Address"] = inbound.Text("Listener.Address"), ["Udp"] = InboundCatalog.UsesUdp(inbound) });
        }
        return new JsonObject { ["Version"] = 1, ["Model"] = model.DeepClone(), ["Bindings"] = bindings, ["Configurations"] = configs, ["Core"] = core };
    }
    public static string BindingFingerprint(JsonObject plan, JsonObject model, JsonObject credentials, JsonObject inbound, ArchiveStore store)
    {
        var config = Configuration(store, plan, model, credentials, inbound);
        var stateFile = SafePath.Resolve(store.Paths.Instance(plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"), "deployment-state.json");
        var core = System.IO.File.Exists(stateFile) ? ArchiveStore.ReadJson(stateFile).At("Inbounds.Core") as JsonObject ?? Core(store.Paths) : Core(store.Paths);
        var outbound = InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == inbound.Text("OutboundId"));
        var selected = InboundCatalog.UsesXray(inbound) ? core["Reality"]! : core; var coreIdentity = selected.DeepClone().AsObject(); coreIdentity.Remove("Reality");
        return ArchiveStore.Fingerprint(new JsonObject { ["Id"] = inbound.Text("Id"), ["Enabled"] = inbound.Flag("Enabled"), ["Configuration"] = config, ["Options"] = inbound["Options"]!.DeepClone(), ["Egress"] = new JsonObject { ["Family"] = outbound.Text("Family"), ["ExpectedAddress"] = outbound.Text("ExpectedAddress") }, ["Core"] = coreIdentity });
    }
    public static IEnumerable<JsonObject> Nodes(ArchiveStore store, string instance, JsonObject plan, JsonObject model, JsonObject credentials)
    {
        foreach (var inbound in InboundCatalog.Items(model, "Inbounds").Where(i => i.Flag("Enabled")))
        {
            var id = inbound.Text("Id"); var options = inbound["Options"]!; var bind = IPAddress.Parse(inbound.Text("Listener.Address"));
            var addresses = bind.Equals(IPAddress.Any) ? new[] { ("IPv4", plan.Text("Server.IPv4")) } : bind.Equals(IPAddress.IPv6Any) ? new[] { ("IPv4", plan.Text("Server.IPv4")), ("IPv6", plan.Text("Server.IPv6")) } : new[] { (bind.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "IPv4" : "IPv6", bind.ToString()) };
            var resource = BindingFingerprint(plan, model, credentials, inbound, store); var outbound = InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == inbound.Text("OutboundId"));
            foreach (var userId in inbound.Strings("UserIds"))
            foreach (var (family, address) in addresses.Where(a => a.Item2 != ""))
            {
                var user = InboundCatalog.Items(model, "Users").Single(u => u.Text("Id") == userId); var password = credentials.Text("Users." + userId + ".Value");
                var name = inbound.Text("Name") + " / " + user.Text("Name") + " / " + family;
                var clash = new JsonObject { ["name"] = name, ["server"] = address, ["port"] = inbound.Number("Listener.Port"), ["udp"] = true };
                JsonObject? sing = new JsonObject { ["tag"] = name, ["server"] = address, ["server_port"] = inbound.Number("Listener.Port") };
                switch (inbound.Text("Protocol"))
                {
                    case "VLESS":
                        sing = VlessXhttp.Native(name, address, inbound.Number("Listener.Port"), password, options); clash = VlessXhttp.ToClash(sing, name); break;
                    case "TuicV5":
                        var uuid = credentials.Text("Users." + userId + ".Uuid");
                        clash["type"] = "tuic"; clash["uuid"] = uuid; clash["password"] = password; clash["sni"] = options.Text("ServerName"); clash["skip-cert-verify"] = false; clash["alpn"] = new JsonArray("h3"); clash["congestion-controller"] = options.Text("CongestionControl"); clash["udp-relay-mode"] = options.Text("UdpRelayMode"); clash["heartbeat-interval"] = options.Number("HeartbeatSeconds") * 1000; clash["reduce-rtt"] = false; clash["fast-open"] = false;
                        sing["type"] = "tuic"; sing["uuid"] = uuid; sing["password"] = password; sing["congestion_control"] = options.Text("CongestionControl"); sing["udp_relay_mode"] = options.Text("UdpRelayMode"); sing["heartbeat"] = options.Number("HeartbeatSeconds") + "s"; sing["zero_rtt_handshake"] = false;
                        sing["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = options.Text("ServerName"), ["min_version"] = "1.3", ["alpn"] = new JsonArray("h3") }; break;
                    case "Reality":
                        clash["type"] = "vless"; clash["uuid"] = password; clash["flow"] = "xtls-rprx-vision"; clash["tls"] = true; clash["network"] = "tcp"; clash["servername"] = options.Text("ServerName"); clash["client-fingerprint"] = "chrome"; clash["reality-opts"] = new JsonObject { ["public-key"] = options.Text("PublicKey"), ["short-id"] = options.Text("ShortId") };
                        sing["type"] = "vless"; sing["uuid"] = password; sing["flow"] = "xtls-rprx-vision"; sing["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = options.Text("ServerName"), ["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = "chrome" }, ["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = options.Text("PublicKey"), ["short_id"] = options.Text("ShortId") } }; break;
                    case "Hysteria2":
                        clash["type"] = "hysteria2"; clash["password"] = password; clash["sni"] = options.Text("ServerName"); clash["skip-cert-verify"] = false;
                        sing["type"] = "hysteria2"; sing["password"] = password; sing["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = options.Text("ServerName"), ["min_version"] = "1.3" };
                        if (options.Text("HopPorts") != "") Hysteria2Ports.Apply(clash, sing, options.Text("HopPorts"), Hysteria2Ports.Interval(options.AsObject()));
                        if (options.Number("UploadMbps") > 0) { clash["up"] = options.Number("UploadMbps") + " Mbps"; clash["down"] = options.Number("DownloadMbps") + " Mbps"; sing["up_mbps"] = options.Number("UploadMbps"); sing["down_mbps"] = options.Number("DownloadMbps"); }
                        if (options.Flag("ObfsEnabled")) { var obfs = credentials.Text("Inbounds." + id + ".ObfsPassword"); clash["obfs"] = "salamander"; clash["obfs-password"] = obfs; sing["obfs"] = new JsonObject { ["type"] = "salamander", ["password"] = obfs }; } break;
                    case "AnyTLS":
                        clash["type"] = "anytls"; clash["password"] = password; clash["sni"] = options.Text("ServerName"); clash["skip-cert-verify"] = false;
                        sing["type"] = "anytls"; sing["password"] = password; sing["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = options.Text("ServerName"), ["min_version"] = "1.3" };
                        if (options.Flag("EchEnabled")) { var pem = credentials.Text("Inbounds." + id + ".EchConfig"); sing["tls"]!["ech"] = new JsonObject { ["enabled"] = true, ["config"] = Lines(pem) }; clash["ech-opts"] = new JsonObject { ["enable"] = true, ["config"] = string.Join("", pem.Split('\n').Where(l => !l.StartsWith("-----", StringComparison.Ordinal)).Select(l => l.Trim())) }; } break;
                    default:
                        password = credentials.Text("Inbounds." + id + ".ServerKey") + ":" + password; clash["type"] = "ss"; clash["cipher"] = options.Text("Method"); clash["password"] = password;
                        sing["type"] = "shadowsocks"; sing["method"] = options.Text("Method"); sing["password"] = password; break;
                }
                var node = new JsonObject { ["Id"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes(instance + ":" + id + ":" + userId + ":" + family))[..32], ["name"] = name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = clash, ["sing_box"] = sing, ["Egress"] = new JsonObject { ["Family"] = outbound.Text("Family") == "Auto" ? "Unknown" : outbound.Text("Family"), ["ExpectedAddress"] = outbound.Text("ExpectedAddress") } };
                node["InboundOrigin"] = new JsonObject { ["Instance"] = instance, ["InboundId"] = id, ["UserId"] = userId, ["Family"] = family, ["ResourceFingerprint"] = resource, ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node) }; yield return node;
            }
        }
    }
    public static void ValidatePorts(JsonObject plan, JsonObject state, JsonObject model)
    {
        var reserved = new HashSet<int> { plan.Number("Ports.SshPrimary"), plan.Number("Ports.SshRescue"), plan.Number("Server.BootstrapSshPort"), plan.Number("MayMonitorServer.Port"), plan.Number("WireGuardTunnel.ListenPort") };
        foreach (var (role, fields) in new[] { ("RealityEntry", new[] { "Ports.XrayPrimary", "Ports.XrayBackup" }), ("AnyTlsEntry", new[] { "Ports.AnyTlsPrimary" }), ("ShadowsocksLanding", new[] { "Ports.LandingShadowsocks" }) }) if (plan.Flag("ProtocolInventory." + role + ".Installed", DeploymentPlans.Uses(plan, role))) foreach (var field in fields) reserved.Add(plan.Number(field));
        foreach (var rule in TcpForwarding.Rules(plan["TcpForwarding"] as JsonObject).Concat(UdpForwarding.Rules(plan["UdpForwarding"] as JsonObject))) reserved.Add(rule.Number("ListenPort"));
        if (plan.Text("Reality.TargetMode") == "LocalOwnedTls") reserved.Add(plan.Number("Reality.LocalHttpsPort"));
        if (state.Flag("KomariController.Installed")) reserved.Add(plan.Number("KomariController.Port", 25774)); if (state.Flag("Cloudflared.Installed")) reserved.Add(plan.Number("Cloudflared.MetricsPort", 20241));
        if (InboundCatalog.Items(model, "Inbounds").SelectMany(Hysteria2Ports.ListenerPorts).Any(reserved.Contains)) throw new OperationException("通用入站监听或跳跃端口与管理、现有协议、转发或监控组件端口冲突。");
    }
}
