using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record ServerDestinationDecision(string Action, string Target);

// Ordered TCP exceptions to one fixed next hop. UDP remains on the fixed path:
// the supported cores select one route for a packet session, not for each target in it.
public static class ServerDestinationRules
{
    public const int MaximumRules = 32;
    public static string KindLabel(string kind) => kind switch { "Domain" => "完整域名", "Suffix" => "域名及其子域名", "Cidr" => "目标 IP 网段", _ => throw new OperationException("请选择受支持的匹配类型。") };
    public static string ActionLabel(string action) => action switch { "NextHop" => "所选落地", "Direct" => "入口机直连", "Reject" => "阻断", _ => throw new OperationException("请选择受支持的出站动作。") };
    public static JsonArray Normalize(JsonNode? value)
    {
        if (value == null) return new();
        if (value is not JsonArray input || input.Count > MaximumRules) throw new OperationException("分流规则最多 32 条，请分项核对。");
        var result = new JsonArray(); var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in input)
        {
            if (item is not JsonObject rule || rule.Count is < 3 or > 4 || rule.Any(p => p.Key is not ("Kind" or "Value" or "Action" or "Target") || p.Value is not JsonValue text || !text.TryGetValue<string>(out _))) throw new OperationException("分流规则字段无效。");
            var kind = rule.Text("Kind"); var action = rule.Text("Action"); KindLabel(kind); ActionLabel(action);
            var target = rule.Text("Target"); if (target != "") { if (action != "NextHop") throw new OperationException("只有落地动作可以指定附加落地。"); ServerOutboundRouting.HopId(target); }
            var raw = rule.Text("Value");
            if (raw.Length is < 1 or > 300 || raw.Any(char.IsControl)) throw new OperationException("请填写一个域名或 CIDR 网段，不支持控制字符。");
            string canonical;
            if (kind == "Cidr")
            {
                var parts = raw.Trim().Split('/');
                if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address) || address.IsIPv4MappedToIPv6 || parts[0].Contains('%') || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) || prefix < 0 || prefix > address.GetAddressBytes().Length * 8) throw new OperationException("网段需为 IPv4/前缀或 IPv6/前缀，不支持主机名、范围或作用域标识。");
                var bytes = address.GetAddressBytes();
                for (var i = 0; i < bytes.Length; i++) bytes[i] &= (byte)(0xff << Math.Clamp(8 - (prefix - i * 8), 0, 8));
                canonical = new IPAddress(bytes) + "/" + prefix;
            }
            else canonical = Domain(raw);
            if (!seen.Add(kind + ":" + canonical)) throw new OperationException("存在重复匹配项，请删除重复项或调整范围。");
            var normalized = new JsonObject { ["Kind"] = kind, ["Value"] = canonical, ["Action"] = action }; if (target != "") normalized["Target"] = target; result.Add(normalized);
        }
        return result;
    }
    private static string Domain(string raw)
    {
        string domain;
        try { domain = new IdnMapping().GetAscii(raw.Trim().TrimEnd('.')).ToLowerInvariant(); }
        catch (ArgumentException) { throw new OperationException("域名格式无效，不支持 URL、通配符、正则表达式或端口。"); }
        if (domain.Length is < 1 or > 253 || IPAddress.TryParse(domain, out _) || domain.Split('.').Any(label => !Regex.IsMatch(label, "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"))) throw new OperationException("请填写纯域名，不支持 URL、通配符、正则表达式、IP 或端口。");
        return domain;
    }
    public static string Decide(JsonArray rules, string destination, string network = "tcp") => Match(rules, destination, network).Action;
    public static ServerDestinationDecision Match(JsonArray rules, string destination, string network = "tcp")
    {
        if (network == "udp") return new("NextHop", "");
        if (network != "tcp") throw new OperationException("本轮只试算 TCP；UDP 保持固定落地。");
        var isIp = IPAddress.TryParse(destination, out var ip); var host = isIp ? "" : Domain(destination);
        if (ip?.IsIPv4MappedToIPv6 == true) ip = ip.MapToIPv4();
        foreach (var rule in rules.OfType<JsonObject>())
        {
            var value = rule.Text("Value");
            var matches = rule.Text("Kind") switch
            {
                "Domain" => !isIp && host == value,
                "Suffix" => !isIp && (host == value || host.EndsWith("." + value, StringComparison.Ordinal)),
                "Cidr" => isIp && Contains(value, ip!),
                _ => false
            };
            if (matches) return new(rule.Text("Action"), rule.Text("Target"));
        }
        return new("NextHop", "");
    }
    private static bool Contains(string cidr, IPAddress address)
    {
        var parts = cidr.Split('/'); var network = IPAddress.Parse(parts[0]); if (network.AddressFamily != address.AddressFamily) return false;
        var prefix = int.Parse(parts[1], CultureInfo.InvariantCulture); var a = address.GetAddressBytes(); var b = network.GetAddressBytes();
        for (var i = 0; i < a.Length; i++) { var mask = (byte)(0xff << Math.Clamp(8 - (prefix - i * 8), 0, 8)); if ((a[i] & mask) != b[i]) return false; }
        return true;
    }
    public static void ValidatePath(JsonArray rules, string family, bool directIpv4Only, IReadOnlyDictionary<string, string>? additionalFamilies = null)
    {
        additionalFamilies ??= new Dictionary<string, string>();
        var targets = rules.OfType<JsonObject>().Where(r => r.Text("Target") != "").Select(r => r.Text("Target")).ToHashSet(StringComparer.Ordinal);
        if (targets.Any(id => !additionalFamilies.ContainsKey(id))) throw new OperationException("规则引用的附加落地已不存在，请重新选择，不会改用默认落地。");
        if (additionalFamilies.Keys.Any(id => !targets.Contains(id))) throw new OperationException("附加落地没有规则引用，请先添加规则或移除不用的落地。");
        foreach (var rule in rules.OfType<JsonObject>().Where(r => r.Text("Kind") == "Cidr" && r.Text("Action") != "Reject"))
        {
            var isV6 = IPAddress.Parse(rule.Text("Value").Split('/')[0]).AddressFamily == AddressFamily.InterNetworkV6;
            var targetFamily = rule.Text("Target") == "" ? family : additionalFamilies[rule.Text("Target")];
            if (rule.Text("Action") == "NextHop" && isV6 != (targetFamily == "IPv6")) throw new OperationException("落地网段的地址族与预期出口不一致，请修改规则或明确阻断此网段。");
            if (rule.Text("Action") == "Direct" && isV6 && directIpv4Only) throw new OperationException("原入口机直连策略仅允许 IPv4，不能为 IPv6 网段设置直连。");
        }
        // Keep the existing independent next-hop acceptance meaningful. No hidden priority rules.
        var egressHost = family == "IPv6" ? "api64.ipify.org" : "api.ipify.org";
        var acceptance = Match(rules, egressHost);
        if (acceptance.Action != "NextHop" || acceptance.Target != "") throw new OperationException("此规则会使默认落地的出口验收绕过落地／被阻断。本轮请缩小范围，或在前面添加明确的默认落地规则保留验收路径。");
    }
    public static JsonArray Render(string role, JsonArray rules, string[] inboundTags)
    {
        if (!ServerOutboundRouting.Roles.Contains(role)) throw new OperationException("请选择受支持的入站组件。");
        var result = new JsonArray();
        foreach (var item in rules.OfType<JsonObject>())
        {
            var kind = item.Text("Kind"); var value = item.Text("Value"); var action = item.Text("Action");
            var rule = new JsonObject { [role == "RealityEntry" ? "inboundTag" : "inbound"] = new JsonArray(inboundTags.Select(t => (JsonNode?)JsonValue.Create(t)).ToArray()), ["network"] = "tcp" };
            if (role == "RealityEntry")
            {
                rule["type"] = "field"; rule[kind == "Cidr" ? "ip" : "domain"] = new JsonArray(kind == "Cidr" ? value : (kind == "Domain" ? "full:" : "domain:") + value);
                rule["outboundTag"] = action == "Reject" ? "block" : action == "Direct" ? "direct" : item.Text("Target") == "" ? ServerOutboundRouting.Tag : ServerOutboundRouting.HopTag(item.Text("Target"));
            }
            else
            {
                if (kind == "Suffix") { rule["domain"] = new JsonArray(value); rule["domain_suffix"] = new JsonArray("." + value); }
                else rule[kind == "Cidr" ? "ip_cidr" : "domain"] = new JsonArray(value);
                rule["action"] = action == "Reject" ? "reject" : "route";
                if (action != "Reject") rule["outbound"] = action == "Direct" ? "direct" : item.Text("Target") == "" ? ServerOutboundRouting.Tag : ServerOutboundRouting.HopTag(item.Text("Target"));
            }
            result.Add(rule);
        }
        return result;
    }
    public static string DecisionLabel(ServerDestinationDecision decision, IReadOnlyDictionary<string, string>? names = null) => decision.Target == "" ? ActionLabel(decision.Action) : "指定落地 · " + (names != null && names.TryGetValue(decision.Target, out var name) ? name : "落地已缺失，需重选");
    public static string Summary(JsonNode? value, IReadOnlyDictionary<string, string>? names = null)
    {
        var rules = Normalize(value);
        return rules.Count == 0 ? "未设置分流例外，全部按固定落地处理。" : "TCP 分流例外，按顺序首条命中：\n" + string.Join('\n', rules.OfType<JsonObject>().Select((r, i) => $"{i + 1}. {KindLabel(r.Text("Kind"))} {r.Text("Value")} → {DecisionLabel(new(r.Text("Action"), r.Text("Target")), names)}")) + "\n未命中：所选落地。UDP 不应用这些例外，始终按原固定落地处理。域名按原始目标匹配，IP 网段只匹配 IP 目标，不新增 DNS 解析或嗅探。直连规则明确使用入口机出口；落地故障不会触发直连。";
    }
}
