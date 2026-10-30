using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public interface ITcpChainValidation
{
    Task<JsonObject> ValidateAsync(JsonObject node, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken);
}

public sealed record TcpChainPreview(JsonObject Configuration, JsonObject? Record, JsonObject FrontConfiguration, JsonObject RelayConfiguration, string Summary);

// Two owned transparent listeners and one existing managed proxy. Persistent
// identity stays stable; transport/family are explicit for newly created chains.
public static partial class TcpChains
{
    public static string FileName(AppPaths paths, string id) => paths.Resolve("private/tcp-chains/" + Id(id) + ".json");
    public static string Id(string id) => Regex.IsMatch(id, "^[a-f0-9]{32}$") ? id : throw new OperationException("跨实例线路身份无效。");
    public static IEnumerable<JsonObject> List(ArchiveStore store)
    {
        var directory = store.Paths.Resolve("private/tcp-chains");
        if (!Directory.Exists(directory)) yield break;
        SafePath.CheckTree(directory);
        foreach (var file in Directory.EnumerateFiles(directory, "*.json").Order(StringComparer.Ordinal))
        {
            var record = ArchiveStore.ReadJson(file);
            if (record.Number("Version") != 1 || Path.GetFileNameWithoutExtension(file) != Id(record.Text("Configuration.Id"))) throw new OperationException("跨实例线路记录不受支持。");
            yield return record;
        }
    }
    public static string[] Instances(JsonObject configuration) => new[] { "FrontInstance", "RelayInstance", "LandingInstance" }.Select(k => configuration.Text(k)).ToArray();
    public static string RuleId(JsonObject configuration, bool front) => ArchiveStore.Digest(Encoding.UTF8.GetBytes(configuration.Text("Id") + (front ? ":front" : ":relay")))[..32];
    public static bool Pending(JsonObject record) => record.Text("Phase") is not ("Active" or "Removed" or "RolledBack");
    public static string PhaseLabel(JsonObject record) => record.Text("Phase") switch { "Active" => "已应用", "Removed" => "已移除", "RolledBack" => "已恢复", _ => "待恢复" };
    public static JsonObject New(string front) => new()
    {
        ["Version"] = 1, ["Id"] = Guid.NewGuid().ToString("N"), ["Name"] = "跨实例线路", ["FrontInstance"] = front, ["Family"] = "IPv4", ["Transport"] = "TCP",
        ["RelayInstance"] = "", ["LandingInstance"] = "", ["FrontPort"] = 18443, ["RelayPort"] = 18444,
        ["FrontSources"] = new JsonArray(), ["FrontSourceAddress"] = "", ["Landing"] = new JsonObject()
    };
    private static void Fields(JsonObject value, params string[] names)
    { if (value.Count != names.Length || value.Any(p => !names.Contains(p.Key))) throw new OperationException("跨实例线路包含未知或缺少的字段。"); }
    public static void Validate(OperationRequest request)
    {
        Fields(request.Options, "Action", "Configuration");
        if (request.Options.Text("Action") is not ("Apply" or "Check" or "Remove" or "Recover")) throw new OperationException("跨实例线路操作无效。");
        var c = request.Options["Configuration"] as JsonObject ?? throw new OperationException("缺少线路配置。");
        var shape = c.DeepClone().AsObject(); shape.Remove("Family"); shape.Remove("Transport");
        Fields(shape, "Version", "Id", "Name", "FrontInstance", "RelayInstance", "LandingInstance", "FrontPort", "RelayPort", "FrontSources", "FrontSourceAddress", "Landing");
        _ = Family(c); _ = Transport(c);
        if (c["Version"] is not JsonValue version || !version.TryGetValue<int>(out var schema) || schema != 1 || c.Text("Name").Length is < 1 or > 60 || c.Text("Name").Any(char.IsControl)) throw new OperationException("线路版本或名称无效。");
        _ = Id(c.Text("Id"));
        var instances = Instances(c);
        foreach (var instance in instances) OperationPolicy.Validate(new(OperationKind.HealthAudit, instance, new()));
        if (instances.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 3 || request.InstanceRelativePath != instances[0]) throw new OperationException("请选择互不相同的前置、中转、落地实例，并从前置实例管理线路。");
        foreach (var port in new[] { "FrontPort", "RelayPort" })
            if (c[port] is not JsonValue value || !value.TryGetValue<int>(out var n) || n is < 1 or > 65535) throw new OperationException("线路端口须为 1–65535 的整数。");
        var sources = c["FrontSources"] as JsonArray ?? throw new OperationException("请填写前置允许来源。");
        if (sources.Any(s => s is not JsonValue v || !v.TryGetValue<string>(out var text) || !IPAddress.TryParse(text.Split('/')[0], out var ip) || (ip.AddressFamily == AddressFamily.InterNetworkV6) != (Family(c) == "IPv6"))) throw new OperationException("前置允许来源必须与所选地址族一致。");
        var test = Rule(c, true, Family(c) == "IPv6" ? "2001:db8::2" : "192.0.2.2", 443);
        test["AllowedSources"] = sources.DeepClone();
        var normalized = NormalizeForwarding(c, new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(test) });
        if (!JsonNode.DeepEquals(normalized["Rules"]![0]!["AllowedSources"], sources)) throw new OperationException("来源须使用规范的 IP 或网络地址 CIDR，不能重复。");
        _ = Address(c.Text("FrontSourceAddress"), Family(c));
        var landing = c["Landing"] as JsonObject ?? throw new OperationException("请选择已保存的受管落地节点。");
        Fields(landing, "SchemeId", "NodeId", "NodeFingerprint");
        foreach (var key in new[] { "SchemeId", "NodeId" }) _ = Id(landing.Text(key));
        if (!Regex.IsMatch(landing.Text("NodeFingerprint"), "^[a-f0-9]{64}$")) throw new OperationException("落地来源摘要无效。");
    }
    public static string Address(string address, string family = "IPv4")
    {
        if (family is not ("IPv4" or "IPv6") || !IPAddress.TryParse(address, out var ip) || ip.IsIPv4MappedToIPv6 || address.Contains('%') || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6Multicast || ip.IsIPv6LinkLocal || (ip.AddressFamily == AddressFamily.InterNetworkV6) != (family == "IPv6") || ip.AddressFamily == AddressFamily.InterNetwork && (ip.GetAddressBytes()[0] is 0 or >= 224 || ip.Equals(IPAddress.Broadcast))) throw new OperationException("线路需要所选地址族的明确单播地址；不接受回环、链路本地、映射地址或区域标识。");
        return ip.ToString();
    }
    public static JsonObject Rule(JsonObject c, bool front, string target, int port)
    {
        var rule = new JsonObject {
        ["Id"] = RuleId(c, front), ["Name"] = c.Text("Name") + (front ? " · 前置" : " · 中转"), ["Enabled"] = true,
        ["ListenFamily"] = Family(c), ["ListenPort"] = c.Number(front ? "FrontPort" : "RelayPort"), ["TargetAddress"] = Address(target, Family(c)), ["TargetPort"] = port,
        ["AllowedSources"] = front ? c["FrontSources"]!.DeepClone() : new JsonArray(Address(c.Text("FrontSourceAddress"), Family(c)) + Prefix(c)),
        ["Validation"] = new JsonObject { ["Type"] = "TcpChain", ["ChainId"] = c.Text("Id"), ["FrontInstance"] = c.Text("FrontInstance") }
        };
        if (Transport(c) == "UDP") { rule["SessionTimeoutSeconds"] = 120; rule["MaximumSessions"] = 256; }
        return rule;
    }
    public static JsonObject Plan(ArchiveStore store, string instance)
    {
        var plan = ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(instance), "deployment-plan.json"));
        if (instance != plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy") throw new OperationException("线路参与实例与归档身份不一致。");
        return plan;
    }
    public static JsonObject Source(ArchiveStore store, JsonObject c)
    {
        var plan = Plan(store, c.Text("LandingInstance")); var reference = c["Landing"]!.AsObject();
        var source = store.ReadSecret(ServerOutboundRouting.SchemeFile(store.Paths, reference.Text("SchemeId")));
        try
        {
            var node = source["Nodes"]!.AsArray().OfType<JsonObject>().SingleOrDefault(n => n.Text("Id") == reference.Text("NodeId")) ?? throw new OperationException("落地节点已移除。");
            if (ArchiveStore.Fingerprint(node) != reference.Text("NodeFingerprint") || SourceOrigin(node)?.Text("Instance") != c.Text("LandingInstance") || !Supports(node, Transport(c), Family(c))) throw new OperationException("请选择对应地址族的原始受管落地；TCP 支持原生 TCP 代理，UDP 支持固定端口 Hysteria2／TUIC 独立入站。");
            if (node["InboundOrigin"] is JsonObject inboundOrigin)
            {
                InboundSources.VerifyNodes(store, [node]);
                var model = plan["InboundModel"]!.AsObject();
                var inbound = InboundCatalog.Items(model, "Inbounds").Single(i => i.Text("Id") == inboundOrigin.Text("InboundId"));
                if (InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == inbound.Text("OutboundId")).Text("Kind") != "Direct") throw new OperationException("本轮线路落地使用直连出站，不叠加未审阅的服务器下一跳。");
            }
            else
            {
                var credentials = store.ReadSecret(SafePath.Resolve(store.Paths.Instance(c.Text("LandingInstance")), "secrets.dotnet.private.json"));
                try { var actual = ManagedNodeSources.Resolve(node["ManagedOrigin"]!.AsObject(), plan, credentials); if (actual == null || ManagedNodeSources.Fingerprint(actual) != node.Text("ManagedOrigin.Fingerprint")) throw new OperationException("落地协议参数与来源归档不同。"); }
                finally { credentials.Clear(); }
            }
            if (node.Text("clash.type") != (node.Text("sing_box.type") == "shadowsocks" ? "ss" : node.Text("sing_box.type")) || Address(node.Text("sing_box.server"), Family(c)) != ServerAddress(plan, c) || Address(node.Text("clash.server"), Family(c)) != ServerAddress(plan, c) || node.Number("clash.port") != node.Number("sing_box.server_port")
                || node.Text("sing_box.detour") != "" || node.Text("clash.dialer-proxy") != "") throw new OperationException("落地须为原生双客户端参数一致、直接可达的所选地址族节点。");
            _ = ClientTopology.DiagnosticRoute(new JsonObject { ["Nodes"] = new JsonArray(node.DeepClone()), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray(node.Text("region_group")) } }, node.Text("name"));
            return node.DeepClone().AsObject();
        }
        finally { source.Clear(); }
    }
    public static JsonObject Project(ArchiveStore store, JsonObject c, string region)
    {
        var node = Source(store, c); var front = Plan(store, c.Text("FrontInstance"));
        foreach (var key in new[] { "ManagedOrigin", "InboundOrigin", "ForwardedOrigin", "Source", "AuthorityName" }) node.Remove(key);
        var clash = node["clash"]!.AsObject(); var sing = node["sing_box"]!.AsObject();
        if (sing["tls"] is JsonObject tls && tls.Flag("enabled") && tls.Text("server_name") == "") tls["server_name"] = sing.Text("server");
        var sni = clash.Text("type") == "anytls" ? "sni" : "servername";
        if ((clash.Text("type") == "anytls" || clash.Flag("tls")) && clash.Text(sni) == "") clash[sni] = clash.Text("server");
        node["Id"] = c.Text("Id"); node["name"] = c.Text("Name"); node["kind"] = "entry"; node["region_group"] = region; node["transit_group"] = region;
        clash["server"] = ServerAddress(front, c); clash["port"] = c.Number("FrontPort"); clash["name"] = node.Text("name");
        sing["server"] = clash.Text("server"); sing["server_port"] = c.Number("FrontPort"); sing["tag"] = node.Text("name");
        if (sing.Text("type") == "shadowsocks") { clash["udp"] = false; sing["network"] = "tcp"; }
        node["TcpChainOrigin"] = new JsonObject { ["Id"] = c.Text("Id"), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(c), ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node) };
        return node;
    }
    public static void VerifyNodes(ArchiveStore store, IEnumerable<JsonObject> nodes)
    {
        foreach (var node in nodes.Where(n => n["TcpChainOrigin"] != null))
        {
            var record = ArchiveStore.ReadJson(FileName(store.Paths, node.Text("TcpChainOrigin.Id")));
            if (record.Text("Phase") != "Active" || record.Text("LastCheck.Status") == "Failed" || node.Text("TcpChainOrigin.ConfigurationFingerprint") != ArchiveStore.Fingerprint(record["Configuration"]!)) throw new OperationException("跨实例线路未完成、已变化或最近检查未通过，请检查线路并重新添加节点。");
            var c = record["Configuration"]!.AsObject();
            foreach (var instance in Instances(c))
            {
                var plan = Plan(store, instance); var state = ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(instance), "deployment-state.json"));
                if (InstanceLifecycle.Read(store, instance, plan).NeedsRecovery || plan.Text("TcpChain.Id") != c.Text("Id")) throw new OperationException("线路参与实例状态已变化，请先核对整条线路。");
                var component = Component(c);
                if (instance != c.Text("LandingInstance") && (state.Text(component + ".RemoteHash") != record.Text(instance == c.Text("FrontInstance") ? "FrontHash" : "RelayHash") || state.Text(component + ".ConfigurationFingerprint") != ArchiveStore.Fingerprint(plan[component]!))) throw new OperationException("线路转发摘要已变化，请先检查整条线路。");
            }
            var current = Project(store, c, node.Text("region_group"));
            if (node.Text("TcpChainOrigin.ConnectionFingerprint") != ClientNodeImport.ConnectionFingerprint(node) || node.Text("TcpChainOrigin.ConnectionFingerprint") != current.Text("TcpChainOrigin.ConnectionFingerprint")) throw new OperationException("跨实例线路连接参数已变化，请重新添加节点。");
        }
    }
    public static void RequireValidation(JsonObject configuration, JsonObject node, JsonObject result)
    {
        if (result.Text("Status") != "Passed" || result.Text("From") != "Controller" || result.Text("Scope") != "TcpChainProxyHttps" || result.Text("ConnectionFingerprint") != ClientNodeImport.ConnectionFingerprint(node)
            || result.Text("ConfigurationFingerprint") != ArchiveStore.Fingerprint(configuration) || result.Text("Result.Status") != "Reachable") throw new OperationException("整条线路未完成代理协议与 HTTPS 出口验收，不能提交。", code: "TcpChainValidationIncomplete");
        if (Transport(configuration) == "UDP" && (result.Text("Result.ValidatedProtocol") != node.Text("sing_box.type") || !result.Flag("Result.UdpValidation.ResponseMatched") || result.Text("Result.UdpValidation.Transport") != "UDP")) throw new OperationException("UDP 线路须完成所选 QUIC 协议与应用 UDP 回程，不能以 TCP、直连 DNS 或单向发包替代。", code: "TcpChainValidationIncomplete");
    }
    public static void VerifyOrigins(ArchiveStore store, JsonArray origins)
    {
        if (origins.Any(n => n is not JsonObject)) throw new OperationException("线路来源记录无效，请重新添加节点。");
        foreach (var origin in origins.OfType<JsonObject>())
        {
            var record = ArchiveStore.ReadJson(FileName(store.Paths, origin.Text("Id")));
            var node = Project(store, record["Configuration"]!.AsObject(), "TCP chain validation");
            try
            {
                if (!JsonNode.DeepEquals(origin, node["TcpChainOrigin"])) throw new OperationException("线路来源已变化，请重新添加节点。");
                VerifyNodes(store, [node]);
            }
            finally { node.Clear(); }
        }
    }
    public static TcpChainPreview Prepare(ArchiveStore store, OperationRequest request)
    {
        Validate(request); var c = request.Options["Configuration"]!.DeepClone().AsObject(); var action = request.Options.Text("Action");
        var file = FileName(store.Paths, c.Text("Id")); var record = System.IO.File.Exists(file) ? ArchiveStore.ReadJson(file) : null;
        if (record != null && (record.Number("Version") != 1 || !JsonNode.DeepEquals(c, record["Configuration"]))) throw new OperationException("线路记录已变化，请重新读取审阅。");
        if (action == "Apply" && record != null || action != "Apply" && record == null) throw new OperationException("新建线路须使用新身份，已有线路请使用检查、移除或恢复。");
        if (action == "Recover" && !Pending(record!) || action is "Check" or "Remove" && record!.Text("Phase") != "Active") throw new OperationException("线路状态与所选操作不同，请先恢复未完成任务。");
        var plans = Instances(c).Select(instance => (Instance: instance, Plan: Plan(store, instance))).ToArray();
        if (List(store).Any(r => r.Text("Configuration.Id") != c.Text("Id") && (Pending(r) || r.Text("Phase") == "Active") && Instances(r["Configuration"]!.AsObject()).Intersect(Instances(c), StringComparer.OrdinalIgnoreCase).Any())) throw new OperationException("参与实例仍属于另一条活动或待恢复线路，请先核对该线路。");
        foreach (var (instance, plan) in plans)
        {
            var lifecycle = InstanceLifecycle.Read(store, instance, plan);
            if (!lifecycle.Managed || action != "Recover" && lifecycle.NeedsRecovery) throw new OperationException("请先完成参与实例的部署、接入或待恢复事务。");
            _ = ServerAddress(plan, c);
            if (action == "Apply" && plan["TcpChain"] != null || action is "Check" or "Remove" && plan.Text("TcpChain.Id") != c.Text("Id")) throw new OperationException("本轮每台实例只参与一条跨实例线路，请先核对或移除已有线路。");
            if (action == "Recover")
            {
                var directory = store.Paths.Instance(instance); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); var pendingFile = SafePath.Resolve(directory, "operation-pending.dotnet.json"); var pending = System.IO.File.Exists(pendingFile) ? ArchiveStore.ReadJson(pendingFile) : null;
                if (state["TcpChainTransaction"] != null && state.Text("TcpChainTransaction.TaskId") != record!.Text("Transaction.TaskId") || plan["TcpChain"] != null && plan.Text("TcpChain.Id") != c.Text("Id") || pending != null && pending.Text("Phase") is not ("Committed" or "RolledBack") && pending.Text("TaskId") != record!.Text("Transaction.TaskId")) throw new OperationException("参与实例出现其他任务归属，未开始恢复。", true, "TcpChainRecoveryIdentity");
            }
        }
        if (plans.Select(p => ServerAddress(p.Plan, c)).Distinct().Count() != 3) throw new OperationException("三台参与实例的所选地址族地址不能相同。");
        var front = plans[0].Plan; var relay = plans[1].Plan;
        var source = action is "Apply" or "Check" ? Source(store, c) : null;
        JsonObject Candidate(JsonObject plan, bool isFront)
        {
            var component = Component(c);
            var config = NormalizeForwarding(c, plan[component]?.AsObject() ?? TcpForwarding.Empty());
            if (action is "Check" or "Remove")
            {
                var state = ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(isFront ? c.Text("FrontInstance") : c.Text("RelayInstance")), "deployment-state.json"));
                if (state.Text(component + ".RemoteHash") != record!.Text(isFront ? "FrontHash" : "RelayHash") || state.Text(component + ".ConfigurationFingerprint") != ArchiveStore.Fingerprint(config)) throw new OperationException("线路转发归档与最后一次整链验收不同，请先核对记录。");
            }
            if (action == "Apply")
            {
                if (TcpForwarding.Rules(config).Any(r => r.Text("Validation.Type") == "TcpChain")) throw new OperationException("参与实例含有其他线路规则，请先核对归属。");
                config["Rules"]!.AsArray().Add(Rule(c, isFront, isFront ? ServerAddress(relay, c) : ServerAddress(plans[2].Plan, c), isFront ? c.Number("RelayPort") : source!.Number("sing_box.server_port")));
            }
            else if (action == "Remove")
            {
                var rule = TcpForwarding.Rules(config).SingleOrDefault(r => r.Text("Id") == RuleId(c, isFront) && r.Text("Validation.ChainId") == c.Text("Id")) ?? throw new OperationException("线路规则归属不完整，未移除任何内容。");
                config["Rules"]!.AsArray().Remove(rule);
            }
            config = NormalizeForwarding(c, config); ValidateForwarding(c, plan, config, ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(isFront ? c.Text("FrontInstance") : c.Text("RelayInstance")), "deployment-state.json")));
            return config;
        }
        var fc = Candidate(front, true); var rc = Candidate(relay, false); var landingPort = source?.Number("sing_box.server_port") ?? record?.Number("LandingPort") ?? 0; source?.Clear();
        var procedure = action switch
        {
            "Apply" => "先核对三台实例、实际资源和端口，再从中转到前置应用，整链代理 HTTPS 验收后逐台提交。",
            "Check" => "只读核对三台实例、实际资源、分段连接及整链代理 HTTPS 出口；将检查结果保存到本机。",
            "Remove" => "先保存前置与中转的本次快照，再关闭前置并移除中转；只删除此线路规则。落地无需在线，原有独立转发仍执行验收。",
            _ => "按原任务身份读取各台实际事务状态，先恢复前置再恢复中转；已提交参与实例也按同一快照范围补偿。身份或资源漂移时保留待恢复记录。"
        };
        var actionLabel = action switch { "Apply" => "新建并验收", "Check" => "只读检查", "Remove" => "移除线路", _ => "恢复整条线路" };
        string FirewallLabel(JsonObject plan) => plan.Text("Firewall.Mode") == "PreserveExisting" ? "保留既有规则，需自行放行端口" : action == "Check" ? "当前使用受管规则" : "同步本次 " + Transport(c) + " 端口的受管放行规则";
        var summary = $"{c.Text("Name")} · {actionLabel}\n前置：{c.Text("FrontInstance")} {Family(c)}:{c.Number("FrontPort")}\n↓ {Transport(c)}\n中转：{c.Text("RelayInstance")} {Family(c)}:{c.Number("RelayPort")}\n↓ {Transport(c)}\n落地：{c.Text("LandingInstance")} · {Family(c)}:{(landingPort > 0 ? landingPort.ToString() : "原归档端口")}\n\n前置允许来源：{string.Join("，", c.Strings("FrontSources"))}\n中转仅允许前置出口：{c.Text("FrontSourceAddress")}{Prefix(c)}\n前置防火墙：{FirewallLabel(front)}\n中转防火墙：{FirewallLabel(relay)}\n落地防火墙沿用当前配置，请确认允许中转出口。\n\n{procedure}\n落地代理、鉴权及 TLS 参数沿用原配置。";
        if (action != "Check") summary += "\n现有本组件连接或数据报会话会短暂中断，其他转发规则保留。失败或取消按两台的本次快照恢复；部分提交或连接中断时按任务身份核对，无法安全完成则保留待恢复记录。";
        summary += "\n仅三台、同一地址族与一种传输。UDP 限固定端口 Hysteria2／TUIC，必须完成应用 UDP 回程；分段 UDP 仅检查路由。外部防火墙须放行，前置经 NAT 时须填真实出口。每台实例限一条线路。";
        return new(c, record, fc, rc, summary);
    }
    public static void GuardOperation(ArchiveStore store, OperationRequest request)
    {
        if (request.Kind == OperationKind.TcpChain) return;
        var planFile = SafePath.Resolve(store.Paths.Instance(request.InstanceRelativePath), "deployment-plan.json");
        if (!System.IO.File.Exists(planFile)) return;
        var stateFile = SafePath.Resolve(store.Paths.Instance(request.InstanceRelativePath), "deployment-state.json");
        var state = System.IO.File.Exists(stateFile) ? ArchiveStore.ReadJson(stateFile) : new JsonObject();
        if (state["TcpChainTransaction"] != null) throw new OperationException("此实例参与未完成的跨实例线路，请从跨实例编排页面恢复整条线路。", true, "TcpChainPending");
        var plan = ArchiveStore.ReadJson(planFile);
        if (List(store).Any(r => Pending(r) && Instances(r["Configuration"]!.AsObject()).Contains(request.InstanceRelativePath, StringComparer.OrdinalIgnoreCase))) throw new OperationException("此实例参与未完成的跨实例线路，请从跨实例编排页面恢复整条线路。", true, "TcpChainPending");
        if (plan["TcpChain"] != null)
        {
            var bound = ArchiveStore.ReadJson(FileName(store.Paths, plan.Text("TcpChain.Id")))["Configuration"]!.AsObject();
            if (request.Kind == OperationKind.TcpForward && Transport(bound) == "TCP" || request.Kind == OperationKind.UdpForward && Transport(bound) == "UDP" || request.Kind is OperationKind.Decommission or OperationKind.ProtocolState or OperationKind.RotateCredentials or OperationKind.Restore or OperationKind.ServerOutbound or OperationKind.Inbounds)
                throw new OperationException("此实例正被跨实例线路依赖，请先从跨实例编排移除线路，再修改其转发或代理身份。");
        }
    }
}
