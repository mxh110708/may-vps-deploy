using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class ForwardTargetGroups
{
    public const int MaximumTargets = 8;
    public static int ProbeTimeout(JsonObject configuration) => Math.Max(180, 90 + TcpForwarding.Rules(configuration).Where(r => r.Flag("Enabled") && r["TargetGroup"] != null).Sum(r => Targets(r).Count() * r.Number("TargetGroup.TimeoutSeconds")));
    public static JsonObject CopyRule(JsonObject rule)
    {
        var copy = rule.DeepClone().AsObject(); var previous = copy.Text("Id"); var id = Guid.NewGuid().ToString("N"); copy["Id"] = id;
        if (Balanced(copy) && copy.At("TargetGroup.Health.ExpectedExits") is JsonObject exits) { var expected = exits[previous]?.DeepClone(); exits.Remove(previous); exits[id] = expected; }
        return copy;
    }
    public static bool Balanced(JsonObject rule) => rule.Number("TargetGroup.Version") == 2;
    public static JsonObject NewBalanced(JsonObject rule, string strategy = "RoundRobin")
    {
        var group = New(rule);
        group["Version"] = 2; group["Strategy"] = strategy;
        group["IntervalSeconds"] = 30;
        group["AdditionalTargets"] = new JsonArray(new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["Address"] = "", ["Port"] = rule.Number("TargetPort") });
        group.Remove("BackupAddress"); group.Remove("BackupPort"); group.Remove("AutoReturn");
        return group;
    }
    public static IEnumerable<string> TargetIds(JsonObject rule)
    {
        yield return rule.Text("Id");
        foreach (var target in rule.At("TargetGroup.AdditionalTargets")?.AsArray().OfType<JsonObject>() ?? []) yield return target.Text("Id");
    }
    public static string ExpectedExit(JsonObject rule, int index) => Balanced(rule)
        ? rule.At("TargetGroup.Health.ExpectedExits")!.AsObject().Text(TargetIds(rule).ElementAt(index))
        : rule.Text(index == 0 ? "TargetGroup.Health.PrimaryExit" : "TargetGroup.Health.BackupExit");
    public static string Fingerprint(JsonNode rule)
    {
        static string Enc(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        static string Canonical(JsonNode? node) => node switch
        {
            JsonObject o => "o{" + string.Join('|', o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => Enc(p.Key) + ":" + Canonical(p.Value))) + "}",
            JsonArray a => "a[" + string.Join('|', a.Select(Canonical)) + "]",
            JsonValue v when v.TryGetValue<bool>(out var b) => b ? "b1" : "b0",
            JsonValue v when v.TryGetValue<int>(out var i) => "i" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
            JsonValue v when v.TryGetValue<string>(out var s) => "s" + Enc(s),
            null => "n",
            _ => throw new OperationException("主备规则摘要包含不支持的数据类型。")
        };
        return ArchiveStore.Digest(Encoding.UTF8.GetBytes(Canonical(rule)));
    }
    public static JsonObject New(JsonObject rule) => new()
    {
        ["Version"] = 1, ["BackupAddress"] = "", ["BackupPort"] = rule.Number("TargetPort"),
        ["Health"] = rule.Text("Validation.Type") == "Proxy" ? new JsonObject { ["Type"] = "Connect" } : rule["Validation"]!.DeepClone(),
        ["IntervalSeconds"] = 10, ["TimeoutSeconds"] = 3, ["FailureThreshold"] = 3,
        ["RecoveryThreshold"] = 3, ["RecoveryHoldSeconds"] = 30, ["AutoReturn"] = true
    };
    public static JsonObject Normalize(JsonObject rule, string transport = "TCP")
    {
        var group = rule["TargetGroup"] as JsonObject ?? throw new OperationException("转发目标组格式无效。");
        if (group["Version"] is not JsonValue version || !version.TryGetValue<int>(out var v) || v is not (1 or 2)) throw new OperationException("目标组版本无效。");
        string[] fields = v == 1 ? ["Version", "BackupAddress", "BackupPort", "Health", "IntervalSeconds", "TimeoutSeconds", "FailureThreshold", "RecoveryThreshold", "RecoveryHoldSeconds", "AutoReturn"]
            : ["Version", "Strategy", "AdditionalTargets", "Health", "IntervalSeconds", "TimeoutSeconds", "FailureThreshold", "RecoveryThreshold", "RecoveryHoldSeconds"];
        if (group.Count != fields.Length || group.Any(p => !fields.Contains(p.Key))) throw new OperationException("转发目标组包含未知字段。");
        var normalized = group.DeepClone().AsObject();
        var count = 2;
        if (v == 2)
        {
            if (group.Text("Strategy") is not ("RoundRobin" or "SourceIpHash") || group["AdditionalTargets"] is not JsonArray additional || additional.Count is < 1 or >= MaximumTargets) throw new OperationException("请选择轮询或来源 IP 哈希，总目标数量为 2–8 个。");
            count = additional.Count + 1;
            var endpoints = new HashSet<(string, int)> { (rule.Text("TargetAddress"), rule.Number("TargetPort")) };
            var identities = new HashSet<string>(StringComparer.Ordinal) { rule.Text("Id") };
            foreach (var node in normalized["AdditionalTargets"]!.AsArray())
            {
                if (node is not JsonObject target || target.Count != 3 || target.Any(p => p.Key is not ("Id" or "Address" or "Port")) || !System.Text.RegularExpressions.Regex.IsMatch(target.Text("Id"), "\\A[a-f0-9]{32}\\z") || !identities.Add(target.Text("Id"))) throw new OperationException("目标需要唯一且固定的身份，不能包含未知字段。");
                var address = TcpForwarding.Address(target.Text("Address"));
                if (target["Port"] is not JsonValue number || !number.TryGetValue<int>(out var port) || port is < 1 or > 65535 || !endpoints.Add((address, port))) throw new OperationException("目标端口无效或存在重复端点。");
                target["Address"] = address;
            }
        }
        else
        {
            var backup = TcpForwarding.Address(group.Text("BackupAddress"));
            if (group["BackupPort"] is not JsonValue portValue || !portValue.TryGetValue<int>(out var port) || port is < 1 or > 65535 || backup == rule.Text("TargetAddress") && port == rule.Number("TargetPort") || group["AutoReturn"] is not JsonValue auto || !auto.TryGetValue<bool>(out _)) throw new OperationException("备用目标或自动恢复选项无效。");
            normalized["BackupAddress"] = backup;
        }
        foreach (var (key, low, high) in new[] { ("IntervalSeconds", 5, 300), ("TimeoutSeconds", 1, 10), ("FailureThreshold", 2, 10), ("RecoveryThreshold", 2, 10), ("RecoveryHoldSeconds", 10, 600) })
            if (group[key] is not JsonValue number || !number.TryGetValue<int>(out var value) || value < low || value > high) throw new OperationException("主备端口或健康确认参数超出允许范围。");
        if (group.Number("IntervalSeconds") < count * group.Number("TimeoutSeconds")) throw new OperationException("探测间隔须容纳全部目标的单次超时之和。");
        if (group["Health"] is not JsonObject health) throw new OperationException("主备目标组需要明确健康探测。");
        var kind = rule.Text("Validation.Type");
        if (health.Text("Type") == "Proxy") { ForwardProxyHealth.Validate(rule, transport); return normalized; }
        var expected = transport == "TCP" && kind == "Proxy" ? new JsonObject { ["Type"] = "Connect" } : rule["Validation"]!.DeepClone().AsObject();
        if (transport == "TCP" && kind is not ("Tls" or "Ssh" or "Proxy") || transport == "UDP" && kind is not ("Dns" or "Echo") || transport is not ("TCP" or "UDP") || ArchiveStore.Fingerprint(health) != ArchiveStore.Fingerprint(expected)) throw new OperationException("健康探测须对应已声明服务。UDP 主备使用 DNS／回显；代理 TCP 健康只判断连接可达性，不代表业务鉴权或出口正常。");
        return normalized;
    }
    public static IEnumerable<(string Address, int Port)> Targets(JsonObject rule)
    {
        yield return (rule.Text("TargetAddress"), rule.Number("TargetPort"));
        if (rule["TargetGroup"] is JsonObject group)
        {
            if (Balanced(rule)) foreach (var target in group["AdditionalTargets"]!.AsArray().OfType<JsonObject>()) yield return (target.Text("Address"), target.Number("Port"));
            else yield return (group.Text("BackupAddress"), group.Number("BackupPort"));
        }
    }
    public static void ValidateLoops(JsonObject plan, JsonObject configuration)
    {
        var ports = TcpForwarding.Rules(configuration).Select(r => r.Number("ListenPort")).ToHashSet();
        foreach (var rule in TcpForwarding.Rules(configuration)) foreach (var (address, port) in Targets(rule))
            if (ports.Contains(port) && (IPAddress.IsLoopback(IPAddress.Parse(address)) || address == plan.Text("Server.IPv4") || address == plan.Text("Server.IPv6"))) throw new OperationException("主备目标不能回指本组件监听端口。");
    }
    public static string Summary(JsonObject rule)
    {
        if (rule["TargetGroup"] is not JsonObject g) return "";
        if (Balanced(rule)) return "\n多目标策略：" + (g.Text("Strategy") == "RoundRobin" ? "轮询" : "来源 IP 哈希") + "；" +
            string.Join("；", Targets(rule).Select((t, i) => $"目标 {i + 1} [{TargetIds(rule).ElementAt(i)}] {new IPEndPoint(IPAddress.Parse(t.Address), t.Port)}")) +
            $"；健康 {g.Text("Health.Type")}，每 {g.Number("IntervalSeconds")} 秒，单次超时 {g.Number("TimeoutSeconds")} 秒；连续失败 {g.Number("FailureThreshold")} 次摘除，连续恢复 {g.Number("RecoveryThreshold")} 次且持续 {g.Number("RecoveryHoldSeconds")} 秒再纳入。" +
            (SelectedProxy(rule) ? "已授权在 VPS 私有保存同一来源的探测凭据，逐目标验证代理鉴权、可信 HTTPS 与实际出口" + (rule.Text("Validation.Type") == "Shadowsocks" ? "及加密 UDP 回程" : "") + "；预期出口：" + string.Join("／", Enumerable.Range(0, Targets(rule).Count()).Select(i => ExpectedExit(rule, i) is var e && e != "" ? e : "仅地址族")) + "。" : g.Text("Health.Type") == "Connect" ? "健康仅为 TCP 可达性；不代表鉴权或出口正常。" : g.Text("Health.Type") == "Ssh" ? "SSH 仅核对协议响应，不核实主机公钥。" : "TLS 校验证书／UDP 核对匹配回程。") +
            "全部目标须提供同一协议、鉴权及 TLS 身份。仅对新连接／会话分配；" + (rule["ProxyReceive"] != null ? "TCP 哈希使用通过可信中转及客户端网段验证的声明 IP；未完成头部核对不参与分配。" : "哈希只使用 socket 来源 IP，同一 NAT 的用户可能落到同一目标，不采信 PROXY 或应用声明。") + "已有 TCP 不迁移或重放，UDP 会话固定且不跨目标重发旧数据报。全部不可用拒绝转发，不回退直连。重启不保留连接、UDP 会话或轮询游标，哈希在目标身份与健康集合相同时保持稳定。";
        return "\n主备组：主 " + new IPEndPoint(IPAddress.Parse(rule.Text("TargetAddress")), rule.Number("TargetPort")) + "；备 " + new IPEndPoint(IPAddress.Parse(g.Text("BackupAddress")), g.Number("BackupPort")) +
            "；健康 " + g.Text("Health.Type") + "，每 " + g.Number("IntervalSeconds") + " 秒，单次超时 " + g.Number("TimeoutSeconds") + " 秒；连续失败 " + g.Number("FailureThreshold") + " 次才切换；" +
            (g.Flag("AutoReturn") ? "首选连续恢复 " + g.Number("RecoveryThreshold") + " 次且持续 " + g.Number("RecoveryHoldSeconds") + " 秒后返回。" : "备用健康时不主动返回首选；备用失效才重新选择健康目标，重启后重新按顺序选择。") +
            (g.Text("Health.Type") == "Proxy" ? "已授权在 VPS 私有保存所选来源的探测凭据；固定核心验证代理鉴权、HTTPS 证书与实际出口地址族" + (rule.Text("Validation.Type") == "Shadowsocks" ? "，并核对加密 UDP 的匹配 DNS 回程" : "") + "。主／备预期出口：" + g.Text("Health.PrimaryExit", "") + "／" + g.Text("Health.BackupExit", "") + "（留空仅约束地址族）。每组最多一个受限核心子进程，凭据不进入状态报告；退出清理。" : g.Text("Health.Type") == "Connect" ? "代理健康仅为 TCP 可达性；不检测鉴权失败、应用延迟或完整出口质量。" : g.Text("Health.Type") == "Ssh" ? "SSH 探测仅为协议响应，不核实主机公钥。" : "") +
            (rule.Text("Validation.Type") == "Proxy" ? "主备须提供相同协议、鉴权及 TLS 身份；保留客户端连接参数。出口按原地址族验收，不将主目标的单一出口地址约束套用于备用。" : "") +
            "两端均不可用则拒绝新连接／会话，不回退到直连；既有 TCP 不迁移或重放，UDP 不跨目标重发旧数据报。";
    }
    public static void AttachProof(JsonObject configuration, JsonObject result, JsonObject probe, string remoteHash, bool requireBoth)
    {
        if (probe.Text("ConfigurationHash") != remoteHash || probe["Groups"] is not JsonArray groups) throw new OperationException("主备探测缺少本次转发配置身份。");
        var rules = TcpForwarding.Rules(configuration).Where(r => r.Flag("Enabled") && r["TargetGroup"] is JsonObject).ToArray();
        if (groups.Count != rules.Length) throw new OperationException("主备探测数量与当前规则不符。");
        foreach (var rule in rules)
        {
            var matches = groups.OfType<JsonObject>().Where(g => g.Text("RuleId") == rule.Text("Id")).ToArray();
            if (matches.Length != 1) throw new OperationException("主备探测缺少本规则身份。");
            ValidateProof(rule, matches[0], requireBoth);
            var item = (result["Items"] as JsonArray)?.OfType<JsonObject>().SingleOrDefault(i => i.Text("Id") == rule.Text("Id")) ?? throw new OperationException("主备缺少实际入口验收。");
            item["TargetGroupHealth"] = matches[0].DeepClone();
        }
    }
    public static void RequireProof(JsonObject rule, JsonObject item)
    {
        if (rule["TargetGroup"] is not JsonObject) return;
        if (item["TargetGroupHealth"] is not JsonObject proof) throw new OperationException("主备组缺少本次逐目标健康证据。");
        ValidateProof(rule, proof, false);
    }
    private static void ValidateProof(JsonObject rule, JsonObject proof, bool both)
    {
        var targets = Targets(rule).ToArray();
        if (proof.Text("RuleId") != rule.Text("Id") || proof.Text("HealthType") != rule.Text("TargetGroup.Health.Type") || proof.Text("RuleFingerprint") != Fingerprint(rule) || proof["Targets"] is not JsonArray checks || checks.Count != targets.Length) throw new OperationException("目标健康证据与规则、健康方式或身份不符。");
        for (var index = 0; index < targets.Length; index++)
            if (checks[index] is not JsonObject check || check.Number("Index", -1) != index || check.Text("Address") != targets[index].Address || check.Number("Port") != targets[index].Port || Balanced(rule) && check.Text("TargetId") != TargetIds(rule).ElementAt(index) || check["Passed"] is not JsonValue value || !value.TryGetValue<bool>(out _)) throw new OperationException("目标健康证据缺少对应身份、端点或明确结果。");
        if (SelectedProxy(rule)) foreach (var check in checks.OfType<JsonObject>().Where(c => c.Flag("Passed")))
        {
            if (check.Text("Evidence.Scope") != "ProxyHttpsEgress" || !check.Flag("Evidence.TcpReachable") || !check.Flag("Evidence.ProxyAuthenticated") || !check.Flag("Evidence.HttpsVerified") || !IPAddress.TryParse(check.Text("Evidence.EgressAddress"), out var observed) || observed.IsIPv4MappedToIPv6 || IPAddress.IsLoopback(observed) || observed.Equals(IPAddress.Any) || observed.Equals(IPAddress.IPv6Any) || observed.IsIPv6Multicast || (observed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) != (rule.Text("TargetGroup.Health.EgressFamily") == "IPv6") || rule.Text("Validation.Type") == "Shadowsocks" && !check.Flag("Evidence.UdpResponseMatched")) throw new OperationException("协议健康缺少对应 HTTPS、出口或加密 UDP 回程证明。");
            var expected = ExpectedExit(rule, check.Number("Index")); if (expected != "" && observed.ToString() != expected) throw new OperationException("协议健康的实际出口不符。");
        }
        if (both ? checks.Any(c => !c.Flag("Passed")) : !checks.Any(c => c.Flag("Passed"))) throw new OperationException(both ? "保存主备组前，主目标与备用目标均须通过实际健康探测。" : "主备目标当前均未通过健康探测。");
    }
    private static bool SelectedProxy(JsonObject rule) => ForwardProxyHealth.Selected(rule);
}
