using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public interface IUdpForwardValidation
{
    Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject configuration, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken);
}

public static class UdpForwarding
{
    public static void ValidateQueryName(string name) => DeploymentPlans.Domain(name);
    public static JsonObject Empty() => TcpForwarding.Empty();
    public static IEnumerable<JsonObject> Rules(JsonObject? configuration) => TcpForwarding.Rules(configuration);
    public static JsonObject NewRule()
    {
        var rule = TcpForwarding.NewRule(); rule["Name"] = "UDP 转发";
        rule["SessionTimeoutSeconds"] = 120; rule["MaximumSessions"] = 256;
        rule["Validation"] = new JsonObject { ["Type"] = "Dns", ["QueryName"] = "", ["QueryType"] = "A" }; return rule;
    }
    public static JsonObject Normalize(JsonObject configuration)
    {
        var common = configuration.DeepClone().AsObject(); var extras = new Dictionary<string, JsonObject>();
        if (common["Rules"] is not JsonArray rules) throw new OperationException("UDP 转发规则格式无效。");
        foreach (var rule in rules.OfType<JsonObject>())
        {
            foreach (var (name, low, high) in new[] { ("SessionTimeoutSeconds", 10, 600), ("MaximumSessions", 1, 1024) })
                if (rule[name] is not JsonValue value || !value.TryGetValue<int>(out var n) || n < low || n > high) throw new OperationException("UDP 会话超时须为 10–600 秒，上限须为 1–1024 个会话。");
            var validation = rule["Validation"] as JsonObject ?? throw new OperationException("请选择 UDP 应用验收方式。");
            if (validation.Text("Type") is "Dns" or "Shadowsocks")
            {
                var proxy = validation.Text("Type") == "Shadowsocks";
                var fields = proxy ? new[] { "Type", "QueryName", "QueryType", "ResolverAddress", "ResolverPort", "SchemeId", "NodeId", "NodeFingerprint" } : ["Type", "QueryName", "QueryType"];
                if (validation.Count != fields.Length || validation.Any(p => !fields.Contains(p.Key)) || validation.Text("QueryType") is not ("A" or "AAAA")) throw new OperationException("UDP DNS 验收参数无效。");
                DeploymentPlans.Domain(validation.Text("QueryName"));
                if (proxy)
                {
                    validation["ResolverAddress"] = TcpForwarding.Address(validation.Text("ResolverAddress"));
                    if (validation["ResolverPort"] is not JsonValue value || !value.TryGetValue<int>(out var port) || port is < 1 or > 65535 ||
                        !Regex.IsMatch(validation.Text("SchemeId"), "^[a-f0-9]{32}$") || !Regex.IsMatch(validation.Text("NodeId"), "^[a-f0-9]{32}$") || !Regex.IsMatch(validation.Text("NodeFingerprint"), "^[a-f0-9]{64}$")) throw new OperationException("请重新选择 UDP 代理来源并核对出口 DNS 地址及端口。");
                }
            }
            else if (validation.Text("Type") == "TcpChain")
            {
                if (validation.Count != 3 || validation.Any(p => p.Key is not ("Type" or "ChainId" or "FrontInstance"))) throw new OperationException("UDP 线路引用无效。");
                _ = TcpChains.Id(validation.Text("ChainId")); OperationPolicy.Validate(new(OperationKind.HealthAudit, validation.Text("FrontInstance"), new()));
            }
            else if (validation.Text("Type") != "Echo" || validation.Count != 1) throw new OperationException("UDP 验收支持 DNS、原样回显或 Shadowsocks／SS2022；目标须提供所选服务。");
            if (!extras.TryAdd(rule.Text("Id"), new JsonObject { ["SessionTimeoutSeconds"] = rule["SessionTimeoutSeconds"]!.DeepClone(), ["MaximumSessions"] = rule["MaximumSessions"]!.DeepClone(), ["Validation"] = validation.DeepClone() })) throw new OperationException("UDP 规则身份重复。");
            rule.Remove("SessionTimeoutSeconds"); rule.Remove("MaximumSessions"); rule["Validation"] = new JsonObject { ["Type"] = "Ssh" };
        }
        var normalized = TcpForwarding.Normalize(common);
        foreach (var rule in Rules(normalized)) foreach (var (key, value) in extras[rule.Text("Id")]) rule[key] = value!.DeepClone();
        return normalized;
    }
    public static JsonObject Options(JsonObject state, string action, JsonObject? configuration = null) => new()
    {
        ["Action"] = action, ["ExpectedHash"] = state.Text("UdpForwarding.RemoteHash", "Absent"), ["Configuration"] = (configuration ?? Empty()).DeepClone()
    };
    public static JsonObject ProxyNode(ArchiveStore store, JsonObject rule, string? changingInstance = null)
    {
        try
        {
            var node = TcpForwarding.ProxyNode(store, rule, changingInstance);
            _ = ServerOutboundRouting.NextHop(node);
            return node;
        }
        catch (IOException) { throw new OperationException("UDP 代理来源无法读取，请重新选择并审阅。"); }
    }
    public static JsonObject ProxyConfiguration(JsonObject node, JsonObject validation, string address, int port, int localPort)
    {
        var outbound = ServerOutboundRouting.NextHop(node);
        if (port is < 1 or > 65535 || localPort is < 1 or > 65535) throw new OperationException("UDP 验收端口无效。");
        outbound["tag"] = "udp-proxy"; outbound["server"] = TcpForwarding.Address(address); outbound["server_port"] = port; outbound["network"] = "udp";
        return new JsonObject
        {
            ["log"] = new JsonObject { ["disabled"] = true },
            ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "udp-probe", ["listen"] = "127.0.0.1", ["listen_port"] = localPort, ["network"] = "udp", ["override_address"] = validation.Text("ResolverAddress"), ["override_port"] = validation.Number("ResolverPort") }),
            ["outbounds"] = new JsonArray(outbound), ["route"] = new JsonObject { ["final"] = "udp-proxy" }
        };
    }
    public static void ValidateOptions(JsonObject options)
    {
        if (options.Any(p => p.Key is not ("Action" or "ExpectedHash" or "Configuration")) || options.Text("Action") is not ("Apply" or "Remove" or "Check") || options.Text("ExpectedHash") != "Absent" && !Regex.IsMatch(options.Text("ExpectedHash"), "^[a-f0-9]{64}$") || options["Configuration"] is not JsonObject configuration) throw new OperationException("UDP 转发操作或归档摘要无效。");
        var normalized = Normalize(configuration);
        if (options.Text("Action") == "Apply" && !Rules(normalized).Any() || options.Text("Action") == "Remove" && Rules(normalized).Any()) throw new OperationException("保存转发需要至少一条规则；移除组件请使用独立移除操作。");
    }
    public static TcpForwardPreview Prepare(ArchiveStore store, OperationRequest request)
    {
        ValidateOptions(request.Options); var directory = store.Paths.Instance(request.InstanceRelativePath);
        var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json")); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        var lifecycle = InstanceLifecycle.Read(store, request.InstanceRelativePath, plan);
        if (!lifecycle.Managed || lifecycle.NeedsRecovery) throw new OperationException("请先完成实例部署、接入或待恢复事务。");
        var expected = state.Text("UdpForwarding.RemoteHash", "Absent"); var action = request.Options.Text("Action");
        if (expected != request.Options.Text("ExpectedHash") || (plan["UdpForwarding"] == null) != (expected == "Absent")) throw new OperationException("UDP 转发归档不完整或已变化，请重新读取并审阅。");
        if (expected == "Absent" && action != "Apply") throw new OperationException("此实例尚未配置受管 UDP 转发。");
        var config = Normalize(request.Options["Configuration"]!.AsObject());
        if (action == "Check" && ArchiveStore.Fingerprint(config) != ArchiveStore.Fingerprint(plan["UdpForwarding"] ?? Empty())) throw new OperationException("只读检查只能核对已保存的 UDP 转发配置。");
        if (Rules(config).Any(r => r.Text("Validation.Type") == "TcpChain")) throw new OperationException("跨实例 UDP 规则只能由跨实例编排统一管理。");
        ValidateCandidate(plan, config);
        foreach (var rule in Rules(config))
        {
            if (rule.Flag("Enabled") && rule.Text("Validation.Type") == "Shadowsocks") _ = ProxyNode(store, rule, request.InstanceRelativePath);
        }
        var summary = action == "Remove" ? "移除全部受管 UDP 转发、独立白名单和相关 UDP 端口放行。" : action == "Check" ? "只读核对已保存配置、UDP 监听、白名单及实际往返响应。" : string.Join("\n", Rules(config).Select(r => r.Text("Name") + " · " + (r.Flag("Enabled") ? "启用" : "停用") + " · " + r.Text("ListenFamily") + ":" + r.Number("ListenPort") + " → " + new IPEndPoint(IPAddress.Parse(r.Text("TargetAddress")), r.Number("TargetPort")) + "\n允许来源：" + string.Join("，", r.Strings("AllowedSources")) + "；会话超时 " + r.Number("SessionTimeoutSeconds") + " 秒，上限 " + r.Number("MaximumSessions") + "；验收 " + r.Text("Validation.Type")));
        summary += "\n\n仅 UDP；各来源 IP／端口独立会话，不传递原客户端 IP。超时回收会话，达到上限丢弃新会话数据报，保留已有会话；无会话 60 秒后工作进程退出，监听仍可用。";
        foreach (var rule in Rules(config).Where(r => r.Flag("Enabled") && r.Text("Validation.Type") == "Shadowsocks"))
            summary += "\n代理验收：" + ProxyNode(store, rule, request.InstanceRelativePath).Text("name") + "；经转发后的 Shadowsocks UDP 向 " + rule.Text("Validation.ResolverAddress") + ":" + rule.Number("Validation.ResolverPort") + " 查询 " + rule.Text("Validation.QueryName") + " / " + rule.Text("Validation.QueryType") + "。不使用 TCP 或直连回退，不核验出口 IP，也不代表 QUIC 或其他业务已验收。";
        if (action != "Check") summary += "\n保存会重启当前 UDP 转发并清空原会话，可能丢包；目标变化不复用旧会话。不改 TCP 转发、代理、SSH 或监控。" + (plan.Text("Firewall.Mode") == "PreserveExisting" ? "保留既有防火墙，UDP 端口须事先放行。" : "同步受管防火墙 UDP 端口。") + "失败或取消恢复本组件及本次防火墙范围。";
        return new(config, expected, summary);
    }
    public static void ValidateCandidate(JsonObject plan, JsonObject config)
    {
        var ports = Rules(config).Select(r => r.Number("ListenPort")).ToHashSet();
        foreach (var rule in Rules(config))
        {
            if (rule.Number("ListenPort") == plan.Number("WireGuardTunnel.ListenPort")) throw new OperationException("UDP 转发与受管 WireGuard 端口冲突。");
            if (InboundCatalog.Items(plan["InboundModel"] as JsonObject ?? InboundCatalog.Empty(), "Inbounds").SelectMany(Hysteria2Ports.ListenerPorts).Contains(rule.Number("ListenPort"))) throw new OperationException("UDP 转发与已保留的独立入站或跳跃端口冲突。");
            if (plan.Flag("ProtocolInventory.ShadowsocksLanding.Installed", DeploymentPlans.Uses(plan, "ShadowsocksLanding")) && rule.Number("ListenPort") == plan.Number("Ports.LandingShadowsocks")) throw new OperationException("UDP 转发与已安装 Shadowsocks 的 UDP 端口冲突。");
            _ = TcpForwarding.ProbeAddresses(plan, rule);
            var target = IPAddress.Parse(rule.Text("TargetAddress"));
            if (ports.Contains(rule.Number("TargetPort")) && (IPAddress.IsLoopback(target) || new[] { plan.Text("Server.IPv4"), plan.Text("Server.IPv6") }.Contains(target.ToString()))) throw new OperationException("UDP 目标指向本组件监听，可能形成环路。");
        }
    }
    public static void RequireValidation(JsonObject plan, JsonObject config, JsonObject result)
    {
        var rules = Rules(config).Where(r => r.Flag("Enabled")).ToArray(); var items = (result["Items"] as JsonArray)?.OfType<JsonObject>().ToArray() ?? [];
        if (result.Text("Status") != "Passed" || items.Length != rules.Length) throw new OperationException("UDP 转发应用验收未全部完成。", code: "UdpForwardValidationIncomplete");
        foreach (var rule in rules)
        {
            var matches = items.Where(i => i.Text("Id") == rule.Text("Id")).ToArray();
            if (rule.Text("Validation.Type") == "TcpChain")
            {
                if (matches.Length != 1 || matches[0].Text("Status") != "Passed" || matches[0].Text("From") != "Controller" || matches[0].Text("Scope") != "TcpChainEndToEnd" || matches[0]["Checks"] is not JsonArray { Count: 1 } chainChecks || chainChecks[0].Text("Address") != TcpForwarding.ProbeAddress(plan, rule) || chainChecks[0].Text("ChainId") != rule.Text("Validation.ChainId") || chainChecks[0].Text("Result.Status") != "Passed" || !chainChecks[0].Flag("Result.Result.UdpValidation.ResponseMatched") || chainChecks[0].Text("Result.Result.UdpValidation.Transport") != "UDP") throw new OperationException("UDP 规则缺少当前整链应用回程证据。");
                continue;
            }
            if (matches.Length != 1 || matches[0].Text("Status") != "Passed" || matches[0].Text("From") != "Controller" || matches[0].Text("Scope") != "ForwardedDatagramApplication") throw new OperationException("缺少经 UDP 转发的往返验收结果。", code: "UdpForwardValidationIncomplete");
            var checks = (matches[0]["Checks"] as JsonArray)?.OfType<JsonObject>().ToArray() ?? [];
            var addresses = TcpForwarding.ProbeAddresses(plan, rule);
            if (checks.Length != addresses.Length || addresses.Any(a => checks.Count(c => c.Text("Address") == a && c.Text("Type") == rule.Text("Validation.Type") && c.Text("Status") == "Passed" && c.Flag("ResponseMatched")) != 1)) throw new OperationException("UDP 验收缺少所选地址族的真实响应。", code: "UdpForwardValidationIncomplete");
            if (rule.Text("Validation.Type") == "Shadowsocks" && checks.Any(c => c.Text("Transport") != "UDP" || c.Text("NodeFingerprint") != rule.Text("Validation.NodeFingerprint") || c.Text("ResolverAddress") != rule.Text("Validation.ResolverAddress") || c.Number("ResolverPort") != rule.Number("Validation.ResolverPort") || c.Text("QueryName") != rule.Text("Validation.QueryName") || c.Text("QueryType") != rule.Text("Validation.QueryType"))) throw new OperationException("UDP 代理验收缺少匹配所选节点及 DNS 的证据。", code: "UdpForwardValidationIncomplete");
        }
    }
}
