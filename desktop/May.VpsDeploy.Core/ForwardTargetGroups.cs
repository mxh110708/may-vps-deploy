using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class ForwardTargetGroups
{
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
        var group = rule["TargetGroup"] as JsonObject ?? throw new OperationException("主备目标组格式无效。");
        string[] fields = ["Version", "BackupAddress", "BackupPort", "Health", "IntervalSeconds", "TimeoutSeconds", "FailureThreshold", "RecoveryThreshold", "RecoveryHoldSeconds", "AutoReturn"];
        if (group.Count != fields.Length || group.Any(p => !fields.Contains(p.Key)) || group["Version"] is not JsonValue version || !version.TryGetValue<int>(out var v) || v != 1) throw new OperationException("主备目标组包含未知字段或版本无效。");
        foreach (var (key, low, high) in new[] { ("BackupPort", 1, 65535), ("IntervalSeconds", 5, 300), ("TimeoutSeconds", 1, 10), ("FailureThreshold", 2, 10), ("RecoveryThreshold", 2, 10), ("RecoveryHoldSeconds", 10, 600) })
            if (group[key] is not JsonValue number || !number.TryGetValue<int>(out var value) || value < low || value > high) throw new OperationException("主备端口或健康确认参数超出允许范围。");
        if (group.Number("IntervalSeconds") < 2 * group.Number("TimeoutSeconds") || group["AutoReturn"] is not JsonValue auto || !auto.TryGetValue<bool>(out _)) throw new OperationException("探测间隔须容纳主备两次超时；请明确选择自动恢复首选。");
        var backup = TcpForwarding.Address(group.Text("BackupAddress"));
        if (backup == rule.Text("TargetAddress") && group.Number("BackupPort") == rule.Number("TargetPort")) throw new OperationException("主目标与备用目标不能相同。");
        if (group["Health"] is not JsonObject health) throw new OperationException("主备目标组需要明确健康探测。");
        var kind = rule.Text("Validation.Type");
        var expected = transport == "TCP" && kind == "Proxy" ? new JsonObject { ["Type"] = "Connect" } : rule["Validation"]!.DeepClone().AsObject();
        if (transport == "TCP" && kind is not ("Tls" or "Ssh" or "Proxy") || transport == "UDP" && kind is not ("Dns" or "Echo") || transport is not ("TCP" or "UDP") || ArchiveStore.Fingerprint(health) != ArchiveStore.Fingerprint(expected)) throw new OperationException("健康探测须对应已声明服务。UDP 主备使用 DNS／回显；代理 TCP 健康只判断连接可达性，不代表业务鉴权或出口正常。");
        var normalized = group.DeepClone().AsObject(); normalized["BackupAddress"] = backup; return normalized;
    }
    public static IEnumerable<(string Address, int Port)> Targets(JsonObject rule)
    {
        yield return (rule.Text("TargetAddress"), rule.Number("TargetPort"));
        if (rule["TargetGroup"] is JsonObject group) yield return (group.Text("BackupAddress"), group.Number("BackupPort"));
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
        return "\n主备组：主 " + new IPEndPoint(IPAddress.Parse(rule.Text("TargetAddress")), rule.Number("TargetPort")) + "；备 " + new IPEndPoint(IPAddress.Parse(g.Text("BackupAddress")), g.Number("BackupPort")) +
            "；健康 " + g.Text("Health.Type") + "，每 " + g.Number("IntervalSeconds") + " 秒，单次超时 " + g.Number("TimeoutSeconds") + " 秒；连续失败 " + g.Number("FailureThreshold") + " 次才切换；" +
            (g.Flag("AutoReturn") ? "首选连续恢复 " + g.Number("RecoveryThreshold") + " 次且持续 " + g.Number("RecoveryHoldSeconds") + " 秒后返回。" : "备用健康时不主动返回首选；备用失效才重新选择健康目标，重启后重新按顺序选择。") +
            (g.Text("Health.Type") == "Connect" ? "代理健康仅为 TCP 可达性；不检测鉴权失败、应用延迟或完整出口质量。" : g.Text("Health.Type") == "Ssh" ? "SSH 探测仅为协议响应，不核实主机公钥。" : "") +
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
        if (proof.Text("RuleId") != rule.Text("Id") || proof.Text("HealthType") != rule.Text("TargetGroup.Health.Type") || proof.Text("RuleFingerprint") != Fingerprint(rule) || proof["Targets"] is not JsonArray { Count: 2 } checks) throw new OperationException("主备健康证据与规则、健康方式或身份不符。");
        var targets = Targets(rule).ToArray();
        for (var index = 0; index < 2; index++)
            if (checks[index] is not JsonObject check || check.Number("Index", -1) != index || check.Text("Address") != targets[index].Address || check.Number("Port") != targets[index].Port || check["Passed"] is not JsonValue value || !value.TryGetValue<bool>(out _)) throw new OperationException("主备健康证据缺少对应端点或明确结果。");
        if (both ? checks.Any(c => !c.Flag("Passed")) : !checks.Any(c => c.Flag("Passed"))) throw new OperationException(both ? "保存主备组前，主目标与备用目标均须通过实际健康探测。" : "主备目标当前均未通过健康探测。");
    }
}
