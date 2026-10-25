using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ForwardedNodeChoice(string Instance, string RuleId, string Family, string Label, JsonObject? Node, string Detail);

// Client projections of already applied forwarding rules. Reading or adding a projection never writes a VPS.
public static class ForwardedNodeSources
{
    private static string RuleHash(JsonObject rule) { var copy = rule.DeepClone().AsObject(); copy.Remove("Name"); return ArchiveStore.Fingerprint(copy); }
    private static bool Includes(JsonObject rule, string family) => rule.Text("ListenFamily") == family || rule.Text("ListenFamily") == "DualStack";
    private static JsonObject Origin(JsonObject node) => (node["InboundOrigin"] ?? node["TcpChainOrigin"] ?? node["ForwardedOrigin"])!.AsObject();
    private static string Identity(JsonObject origin) => origin.ContainsKey("InboundId") ? "Inbound:" + origin.Text("Instance") + ":" + origin.Text("InboundId") + ":" + origin.Text("UserId") + ":" + origin.Text("Family") : origin.ContainsKey("ConfigurationFingerprint") ? "TcpChain:" + origin.Text("Id") : origin.Text("Instance") + ":" + origin.Text("RuleId") + ":" + origin.Text("Family");

    public static IReadOnlyList<ForwardedNodeChoice> Choices(ArchiveStore store, string region)
    {
        var choices = new List<ForwardedNodeChoice>();
        foreach (var instance in store.ListInstances())
        {
            foreach (var rule in TcpForwarding.Rules(instance.Plan["TcpForwarding"] as JsonObject).Where(r => r.Text("Validation.Type") == "Proxy"))
            foreach (var family in rule.Text("ListenFamily") == "DualStack" ? new[] { "IPv4", "IPv6" } : new[] { rule.Text("ListenFamily") })
            {
                var label = instance.Plan.Text("NodeName") + " / " + rule.Text("Name") + " / " + family;
                try
                {
                    var node = Create(store, instance.RelativePath, rule.Text("Id"), family, region);
                    choices.Add(new(instance.RelativePath, rule.Text("Id"), family, label, node, node.Text("ForwardedOrigin.UdpRuleId") != "" ? "TCP + 独立 UDP 转发" : node.Text("sing_box.type") == "shadowsocks" ? "仅 TCP；未绑定独立 UDP 转发" : "TCP 转发；协议自带的 UDP 封装仍沿原参数"));
                }
                catch (Exception error) when (error is OperationException or IOException or UnauthorizedAccessException)
                { choices.Add(new(instance.RelativePath, rule.Text("Id"), family, label, null, error is OperationException ? error.Message : "转发或代理来源无法安全读取，请核对归档。")); }
            }
        }
        foreach (var record in TcpChains.List(store).Where(r => r.Text("Phase") == "Active"))
        {
            var config = record["Configuration"]!.AsObject(); JsonObject? node = null;
            try { node = TcpChains.Project(store, config, region); TcpChains.VerifyNodes(store, [node]); choices.Add(new(config.Text("FrontInstance"), config.Text("Id"), "IPv4", config.Text("Name"), node, "跨实例前置 → 中转 → 落地 · TCP 整链验收")); }
            catch (Exception error) when (error is OperationException or IOException or UnauthorizedAccessException) { node?.Clear(); choices.Add(new(config.Text("FrontInstance"), config.Text("Id"), "IPv4", config.Text("Name"), null, error is OperationException ? error.Message : "线路来源无法安全读取。")); }
        }
        return choices;
    }

    public static JsonObject Create(ArchiveStore store, string instance, string ruleId, string family, string region, string? udpRuleId = null)
    {
        if (family is not ("IPv4" or "IPv6")) throw new OperationException("请选择转发监听的 IPv4 或 IPv6 地址。");
        var directory = store.Paths.Instance(instance);
        var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"));
        var lifecycle = InstanceLifecycle.Read(store, instance, plan);
        if (!lifecycle.Managed || lifecycle.NeedsRecovery) throw new OperationException("转发实例正在部署或恢复，请先完成该实例的任务。");
        var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        var config = TcpForwarding.Normalize(plan["TcpForwarding"]?.AsObject() ?? throw new OperationException("受管 TCP 转发已移除。"));
        if (!System.Text.RegularExpressions.Regex.IsMatch(state.Text("TcpForwarding.RemoteHash"), "^[a-f0-9]{64}$")) throw new OperationException("TCP 转发尚无已应用的归档，请先完成转发验收。");
        if (state.Text("TcpForwarding.ConfigurationFingerprint") != ArchiveStore.Fingerprint(config)) throw new OperationException("当前规则缺少匹配的验收记录，请先执行“只读检查已保存转发”。");
        if (!state.Flag("TcpForwarding.TemplateCurrent", true)) throw new OperationException("转发单元需要更新，请先重新审阅保存转发规则。");
        TcpForwarding.RequireValidation(config, state.At("TcpForwarding.Validation")?.AsObject() ?? new());
        var rule = TcpForwarding.Rules(config).SingleOrDefault(r => r.Text("Id") == ruleId) ?? throw new OperationException("转发规则已移除，请重新选择。");
        if (!rule.Flag("Enabled") || !Includes(rule, family) || rule.Text("Validation.Type") != "Proxy") throw new OperationException("请选择启用且已通过代理验收的 TCP 转发规则。");
        var address = plan.Text("Server." + family);
        if (!IPAddress.TryParse(address, out var ip) || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv4MappedToIPv6 || (ip.AddressFamily == AddressFamily.InterNetworkV6) != (family == "IPv6")) throw new OperationException("转发监听缺少有效的实例地址。");
        var checkedRule = state.At("TcpForwarding.Validation.Items")!.AsArray().Single(i => i!.Text("Id") == ruleId)!;
        if (!checkedRule["Checks"]!.AsArray().Any(c => c!.Text("Address") == address && c.Text("Status") == "Passed")) throw new OperationException("当前监听地址缺少对应验收，请先重新检查已保存转发。");
        var source = TcpForwarding.ProxyNode(store, rule);
        if (source["ForwardedOrigin"] != null) throw new OperationException("本轮不将转发节点再次用作转发目标，请选择原始代理节点。");
        if (source["clash"] is not JsonObject originalClash || source["sing_box"] is not JsonObject originalSing
            || originalClash.Text("server") != rule.Text("TargetAddress") || originalClash.Number("port") != rule.Number("TargetPort")
            || originalClash.Text("type") != (originalSing.Text("type") == "shadowsocks" ? "ss" : originalSing.Text("type"))) throw new OperationException("目标缺少一致的双客户端原生参数，请补齐来源后重新选择。");
        if (originalClash.Text("dialer-proxy") != "" || originalSing.Text("detour") != "" || originalSing.Text("network") == "udp") throw new OperationException("目标含额外客户端链路或仅 UDP 参数，不能生成独立 TCP 转发节点。");
        var node = source.DeepClone().AsObject();
        foreach (var key in new[] { "ManagedOrigin", "Source", "AuthorityName", "ForwardedOrigin" }) node.Remove(key);
        node["Id"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes(instance + ":" + ruleId + ":" + family))[..32];
        node["name"] = plan.Text("NodeName") + " → " + rule.Text("Name") + " · " + family;
        node["kind"] = "entry"; node["region_group"] = region; node["transit_group"] = region;
        var clash = node["clash"]!.AsObject(); var sing = node["sing_box"]!.AsObject();
        // Preserve the original effective TLS identity when the original config relied on its server address.
        if (sing.At("tls") is JsonObject tls && tls.Flag("enabled") && tls.Text("server_name") == "") tls["server_name"] = originalSing.Text("server");
        if (originalClash.Text("type") == "anytls" && clash.Text("sni") == "") clash["sni"] = originalClash.Text("server");
        if (originalClash.Text("type") == "vless" && clash.Flag("tls") && clash.Text("servername") == "") clash["servername"] = originalClash.Text("server");
        clash["server"] = address; clash["port"] = rule.Number("ListenPort"); clash["name"] = node.Text("name");
        sing["server"] = address; sing["server_port"] = rule.Number("ListenPort"); sing["tag"] = node.Text("name");
        JsonObject? udp = null;
        if (sing.Text("type") == "shadowsocks")
        {
            if (originalSing.Text("network") != "tcp" && originalClash.Flag("udp", true) && udpRuleId != "" && plan["UdpForwarding"] is JsonObject udpConfig)
            {
                var normalized = UdpForwarding.Normalize(udpConfig);
                var matches = UdpForwarding.Rules(normalized).Where(r => (udpRuleId == null || r.Text("Id") == udpRuleId)
                    && r.Flag("Enabled") && Includes(r, family) && r.Number("ListenPort") == rule.Number("ListenPort")
                    && r.Text("TargetAddress") == rule.Text("TargetAddress") && r.Number("TargetPort") == rule.Number("TargetPort")
                    && r.Text("Validation.Type") == "Shadowsocks" && r.Text("Validation.SchemeId") == rule.Text("Validation.SchemeId")
                    && r.Text("Validation.NodeId") == rule.Text("Validation.NodeId") && r.Text("Validation.NodeFingerprint") == rule.Text("Validation.NodeFingerprint")).ToArray();
                if (matches.Length == 1)
                {
                    if (!System.Text.RegularExpressions.Regex.IsMatch(state.Text("UdpForwarding.RemoteHash"), "^[a-f0-9]{64}$")) throw new OperationException("匹配的 UDP 转发尚未完成应用验收。");
                    if (state.Text("UdpForwarding.ConfigurationFingerprint") != ArchiveStore.Fingerprint(normalized)) throw new OperationException("匹配的 UDP 转发缺少当前规则的验收记录，请先只读检查已保存转发。");
                    if (!state.Flag("UdpForwarding.TemplateCurrent", true)) throw new OperationException("匹配的 UDP 转发单元需要重新审阅保存更新。");
                    UdpForwarding.RequireValidation(plan, normalized, state.At("UdpForwarding.Validation")?.AsObject() ?? new());
                    _ = UdpForwarding.ProxyNode(store, matches[0]); udp = matches[0];
                }
            }
            if (udpRuleId is not null and not "" && udp == null) throw new OperationException("绑定的 UDP 转发已停用、移除或改变，请重新选择更新节点。");
            if (udp == null || originalSing.Text("network") == "tcp" || !originalClash.Flag("udp", true)) { clash["udp"] = false; sing["network"] = "tcp"; }
            else clash["udp"] = true;
        }
        var origin = new JsonObject { ["Instance"] = instance, ["RuleId"] = ruleId, ["Family"] = family, ["TcpFingerprint"] = RuleHash(rule), ["UdpRuleId"] = udp?.Text("Id") ?? "", ["UdpFingerprint"] = udp == null ? "" : RuleHash(udp) };
        origin["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node);
        node["ForwardedOrigin"] = origin;
        return node;
    }

    public static void VerifyOrigins(ArchiveStore store, JsonArray origins)
    {
        if (origins.Any(n => n is not JsonObject)) throw new OperationException("转发来源记录无效，请重新添加节点。");
        foreach (var origin in origins.OfType<JsonObject>())
        {
            var current = Create(store, origin.Text("Instance"), origin.Text("RuleId"), origin.Text("Family"), "Forward validation", origin.Text("UdpRuleId"));
            if (!JsonNode.DeepEquals(current["ForwardedOrigin"], origin)) throw new OperationException("转发节点的监听、规则或目标已变化，请在“添加转发节点”中重新选择更新。");
        }
    }
    public static void VerifyNodes(ArchiveStore store, IEnumerable<JsonObject> nodes)
    {
        var all = nodes.ToArray(); TcpChains.VerifyNodes(store, all); InboundSources.VerifyNodes(store, all);
        var forwarded = all.Where(n => n["ForwardedOrigin"] != null).ToArray();
        foreach (var node in forwarded)
            if (node.Text("ForwardedOrigin.ConnectionFingerprint") != ClientNodeImport.ConnectionFingerprint(node)) throw new OperationException("转发节点连接已被修改，请重新选择转发来源。");
        VerifyOrigins(store, new JsonArray(forwarded.Select(n => n["ForwardedOrigin"]!.DeepClone()).ToArray()));
    }

    public static void Apply(ArchiveStore store, JsonObject scheme, IReadOnlyList<JsonObject> selections, string region)
    {
        if (selections.Count == 0 || selections.Any(n => n["ForwardedOrigin"] is not JsonObject && n["TcpChainOrigin"] is not JsonObject && n["InboundOrigin"] is not JsonObject) || selections.Select(n => Identity(Origin(n))).Distinct(StringComparer.Ordinal).Count() != selections.Count) throw new OperationException("请选择有效且不重复的来源节点。");
        if (!scheme["Layout"]!.Strings("region_groups").Contains(region)) throw new OperationException("请选择方案中的入口地区组。");
        VerifyNodes(store, selections);
        var nodes = scheme["Nodes"]!.DeepClone().AsArray();
        foreach (var selected in selections)
        {
            var identity = Identity(Origin(selected));
            var matches = nodes.OfType<JsonObject>().Where(n => (n["ForwardedOrigin"] != null || n["TcpChainOrigin"] != null || n["InboundOrigin"] != null) && Identity(Origin(n)) == identity).ToArray();
            if (matches.Length > 1) throw new OperationException("方案中存在重复转发来源，请先核对节点。");
            var previous = matches.SingleOrDefault(); var node = selected.DeepClone().AsObject();
            if (nodes.OfType<JsonObject>().Any(n => n != previous && n.Text("Id") == node.Text("Id"))) throw new OperationException("转发节点身份与已有节点冲突，请核对方案。");
            node["region_group"] = previous?.Text("region_group") ?? region; node["transit_group"] = previous?.Text("transit_group") ?? region;
            if (previous != null)
            {
                node["Id"] = previous.Text("Id"); node["name"] = previous.Text("name"); node["kind"] = previous.Text("kind");
                if (previous["AuthorityName"] != null) node["AuthorityName"] = previous["AuthorityName"]!.DeepClone();
            }
            else
            {
                var used = nodes.Select(n => n!.Text("name")).Concat(scheme["Layout"]!.Strings("region_groups")).Concat(scheme["Layout"]!["business_groups"]!.AsArray().Select(g => g!.Text("name"))).Append(scheme.Text("Layout.default_exit_group")).Append(scheme.Text("Layout.direct_group")).ToHashSet(StringComparer.Ordinal);
                var basis = node.Text("name"); var name = basis; var suffix = 2;
                while (used.Contains(name)) name = basis + " (" + suffix++ + ")";
                if (name.Length > 120) throw new OperationException("转发节点名称过长，请先缩短转发规则名称。"); node["name"] = name;
            }
            node["clash"]!["name"] = node.Text("name"); node["sing_box"]!["tag"] = node.Text("name");
            if (previous == null) nodes.Add(node); else nodes[nodes.IndexOf(previous)] = node;
        }
        scheme["Nodes"] = nodes; scheme.Remove("Candidate");
    }
}
