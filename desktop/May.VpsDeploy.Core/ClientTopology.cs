using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ClientRegion(string Name, IReadOnlyList<JsonObject> Entries, IReadOnlyList<JsonObject> Landings);
public sealed record ClientDiagnosticRoute(JsonObject Entry, JsonObject? Landing, string Fingerprint)
{
    public bool RequiresApplicationUdp { get; init; }
    public JsonObject Exit => Landing ?? Entry;
    public string Label => Entry.Text("name") + (Landing == null ? " → 网站" : " → " + Landing.Text("name") + " → 网站");
}

public static class ClientTopology
{
    public static IReadOnlyList<ClientRegion> Regions(JsonObject scheme)
    {
        var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        return scheme["Layout"]!.Strings("region_groups").Select(group => new ClientRegion(group,
            nodes.Where(n => n.Text("kind") == "entry" && n.Text("region_group") == group).ToArray(),
            nodes.Where(n => n.Text("kind") == "landing" && n.Text("transit_group") == group).ToArray())).Where(r => r.Entries.Count > 0).ToArray();
    }

    public static string ConnectionFamily(JsonObject node)
    {
        var host = node.Text("sing_box.server", node.Text("clash.server"));
        return IPAddress.TryParse(host, out var address) ? address.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4" : "域名 · 由 DNS 解析";
    }
    public static string EgressFamily(JsonObject node) => node.Text("Egress.Family", node.Text("ManagedOrigin.EgressFamily", "Unknown"));
    public static string OriginLabel(JsonObject node) => node["InboundOrigin"] != null ? "独立入站 · 按用户验收" : node["ForwardedOrigin"] != null ? "受管转发 · " + (node.Text("ForwardedOrigin.UdpRuleId") != "" ? "TCP + 独立 UDP" : node.Text("sing_box.type") == "shadowsocks" ? "仅 TCP" : "TCP · 协议 UDP 封装") : node["ManagedOrigin"] != null ? "受管实例" + (node.Text("ServerRoute.Name") == "" ? "" : " · 默认服务器落地 " + node.Text("ServerRoute.Name") + (node.At("ServerRoute.DestinationRules") is JsonArray rules && rules.Count > 0 ? " · 存在服务器 TCP 分流例外" : "") + (node.Number("ServerRoute.AdditionalHopCount") > 0 ? " · 附加落地 " + node.Number("ServerRoute.AdditionalHopCount") + " 个" : "")) : node.Text("Source.Kind") == "Subscription" ? "外部订阅来源" : node.Text("Source.Kind") == "ShareLink" ? "外部分享链接" : "外部 / 手动节点";

    public static ClientDiagnosticRoute DiagnosticRoute(JsonObject scheme, string entryName, string? landingName = null)
    {
        var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        if (nodes.Select(n => n.Text("name")).Distinct(StringComparer.Ordinal).Count() != nodes.Length) throw new OperationException("节点名称重复，请先核对方案。");
        var entry = nodes.SingleOrDefault(n => n.Text("name") == entryName && n.Text("kind") == "entry") ?? throw new OperationException("所选入口已不存在。");
        if (!scheme["Layout"]!.Strings("region_groups").Contains(entry.Text("region_group"))) throw new OperationException("入口未归属有效地区组。");
        var landing = landingName == null ? null : nodes.SingleOrDefault(n => n.Text("name") == landingName && n.Text("kind") == "landing") ?? throw new OperationException("所选落地已不存在。");
        if (landing != null && landing.Text("transit_group") != entry.Text("region_group")) throw new OperationException("落地不属于所选入口组。");
        var regions = scheme["Layout"]!.Strings("region_groups");
        ValidateOutbound(entry, false, regions);
        if (VlessXhttp.IsNode(entry) && landing != null) throw new OperationException("本轮 XHTTP 只诊断入口自身出口，不叠加客户端落地链路。");
        if (landing != null) ValidateOutbound(landing, true, regions);
        var fingerprint = ArchiveStore.Fingerprint(new JsonObject { ["Entry"] = RouteIdentity(entry), ["Landing"] = landing == null ? null : RouteIdentity(landing) });
        return new(entry.DeepClone().AsObject(), landing?.DeepClone().AsObject(), fingerprint);
    }

    private static JsonObject RouteIdentity(JsonObject node)
    {
        var identity = new JsonObject
        {
            ["Connection"] = ClientNodeImport.ConnectionFingerprint(node), ["Kind"] = node.Text("kind"),
            ["Group"] = node.Text(node.Text("kind") == "entry" ? "region_group" : "transit_group"),
            ["Egress"] = node["Egress"]?.DeepClone(), ["ManagedOrigin"] = node["ManagedOrigin"]?.DeepClone()
        };
        if (node["ForwardedOrigin"] != null) identity["ForwardedOrigin"] = node["ForwardedOrigin"]!.DeepClone();
        if (node["TcpChainOrigin"] != null) identity["TcpChainOrigin"] = node["TcpChainOrigin"]!.DeepClone();
        if (node["InboundOrigin"] != null) identity["InboundOrigin"] = node["InboundOrigin"]!.DeepClone();
        return identity;
    }
    private static void ValidateOutbound(JsonObject node, bool landing, string[] regions)
    {
        if (VlessXhttp.IsNode(node)) { if (landing) throw new OperationException("XHTTP 不能作为客户端链式落地。"); if(node["sing_box"]!=null)_ = VlessXhttp.RequireNative(node);else _=VlessXhttp.RequireClash(node); ValidateEgress(node); return; }
        if (node["sing_box"] is not JsonObject config || config.Text("type") is not ("vless" or "trojan" or "anytls" or "shadowsocks" or "hysteria2" or "tuic")) throw new OperationException("轻量诊断需要受支持的 sing-box 节点参数，请补全此节点。");
        if (config.Number("server_port") is < 1 or > 65535 || config.Text("server") == "") throw new OperationException("节点的服务器或端口无效。");
        // A landing's group is edited separately from its imported raw configuration.
        // The exporter, and this diagnostic, replace that known group with the selected entry.
        if (config.Text("detour") != "" && (!landing || !regions.Contains(config.Text("detour")))) throw new OperationException("节点含额外上游依赖，当前轻量诊断不能还原此路径。");
        if (config.ContainsKey("bind_interface") || config.ContainsKey("inet4_bind_address") || config.ContainsKey("inet6_bind_address") || config.ContainsKey("routing_mark")) throw new OperationException("节点绑定了特定网络接口或源地址，请使用对应环境的验收流程。");
        ValidateEgress(node);
    }
    private static void ValidateEgress(JsonObject node)
    {
        var family = EgressFamily(node);
        if (family is not ("Unknown" or "IPv4" or "IPv6")) throw new OperationException("出口地址族标注无效。");
        if (node.Text("Egress.ExpectedAddress") != "" && (!IPAddress.TryParse(node.Text("Egress.ExpectedAddress"), out var expected) || family == "IPv4" && expected.AddressFamily != AddressFamily.InterNetwork || family == "IPv6" && expected.AddressFamily != AddressFamily.InterNetworkV6)) throw new OperationException("预期出口地址与地址族不匹配。");
    }

    public static JsonObject DiagnosticConfiguration(ClientDiagnosticRoute route, int entryPort, int chainPort)
    {
        if (entryPort is < 1 or > 65535 || chainPort is < 1 or > 65535 || entryPort == chainPort) throw new OperationException("诊断端口无效。");
        var entry = route.Entry["sing_box"]!.DeepClone().AsObject(); entry["tag"] = "diagnostic-entry";
        var outbounds = new JsonArray(entry); var inbounds = new JsonArray(Inbound("entry-in", entryPort));
        var rules = new JsonArray(new JsonObject { ["inbound"] = new JsonArray("entry-in"), ["action"] = "route", ["outbound"] = "diagnostic-entry" });
        if (route.Landing != null)
        {
            var landing = route.Landing["sing_box"]!.DeepClone().AsObject(); landing["tag"] = "diagnostic-landing"; landing["detour"] = "diagnostic-entry"; outbounds.Add(landing);
            inbounds.Add(Inbound("chain-in", chainPort)); rules.Add(new JsonObject { ["inbound"] = new JsonArray("chain-in"), ["action"] = "route", ["outbound"] = "diagnostic-landing" });
        }
        return new JsonObject { ["log"] = new JsonObject { ["level"] = "error" }, ["inbounds"] = inbounds, ["outbounds"] = outbounds,
            ["route"] = new JsonObject { ["rules"] = rules, ["final"] = route.Landing == null ? "diagnostic-entry" : "diagnostic-landing" } };
    }
    private static JsonObject Inbound(string tag, int port) => new() { ["type"] = "mixed", ["tag"] = tag, ["listen"] = "127.0.0.1", ["listen_port"] = port };

    public static string[] RemovalImpact(JsonObject scheme, JsonObject node)
    {
        var impacts = new List<string>(); var name = node.Text("name"); var layout = scheme["Layout"]!;
        foreach (var business in layout["business_groups"]!.AsArray().OfType<JsonObject>())
            if (business.Text("default") == name || business.Strings("order").Contains(name)) impacts.Add("业务组：" + business.Text("name"));
        if (layout.Strings("default_exit_members").Contains(name)) impacts.Add("默认出口顺序");
        if (node.Text("kind") == "entry" && !scheme["Nodes"]!.AsArray().Any(n => n != node && n!.Text("kind") == "entry" && n.Text("region_group") == node.Text("region_group")))
        {
            var region = node.Text("region_group");
            impacts.AddRange(scheme["Nodes"]!.AsArray().Where(n => n!.Text("kind") == "landing" && n.Text("transit_group") == region).Select(n => "落地将失去入口：" + n!.Text("name")));
            impacts.AddRange(layout["business_groups"]!.AsArray().OfType<JsonObject>().Where(g => g.Text("default") == region).Select(g => "业务默认地区失效：" + g.Text("name")));
        }
        return impacts.Distinct().ToArray();
    }
}
