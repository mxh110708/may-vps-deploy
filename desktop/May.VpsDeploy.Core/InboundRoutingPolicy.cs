using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

// An inbound owns its ordered policy; targets are the catalogue's existing
// outbound identities. Rule-set snapshots never download or apply themselves.
public static class InboundRoutingPolicy
{
    public const int MaximumTargets = 8;
    public static JsonArray Rules(JsonObject inbound)
    {
        if (!inbound.ContainsKey("Routing")) return new();
        if (inbound["Routing"] is not JsonObject policy || policy.Count != 2 || policy.Number("Version") != 1 || policy.Any(p => p.Key is not ("Version" or "Rules")) || policy["Rules"] is not JsonArray)
            throw new OperationException("入站分流策略版本或字段无效。");
        return ServerDestinationRules.Normalize(policy["Rules"], InboundCatalog.Id);
    }
    public static void Set(JsonObject inbound, JsonArray rules)
    {
        var normalized = ServerDestinationRules.Normalize(rules, InboundCatalog.Id);
        if (normalized.Count == 0) inbound.Remove("Routing");
        else inbound["Routing"] = new JsonObject { ["Version"] = 1, ["Rules"] = normalized };
    }
    public static string[] References(JsonObject inbound) => new[] { inbound.Text("OutboundId") }.Concat((inbound["Routing"]?["Rules"] as JsonArray ?? []).OfType<JsonObject>().Where(r => r.Text("Target") != "").Select(r => r.Text("Target"))).Distinct(StringComparer.Ordinal).ToArray();
    public static JsonObject Default(JsonObject model, JsonObject inbound) => InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == inbound.Text("OutboundId"));
    public static JsonObject Identity(JsonObject model, JsonObject inbound) => new()
    {
        ["Rules"] = Rules(inbound),
        ["Targets"] = new JsonArray(References(inbound).Select(id =>
        {
            var target = InboundCatalog.Items(model, "Outbounds").SingleOrDefault(o => o.Text("Id") == id) ?? throw new OperationException("分流引用的出站已移除，请重新选择。");
            var value = target.DeepClone().AsObject(); value.Remove("Name"); return (JsonNode?)value;
        }).ToArray())
    };
    public static string Fingerprint(JsonObject model, JsonObject inbound) => ArchiveStore.Fingerprint(Identity(model, inbound));
    public static void Validate(JsonObject model, JsonObject inbound)
    {
        var rules = Rules(inbound); var ids = References(inbound);
        if (ids.Length > MaximumTargets) throw new OperationException("每个入站最多引用 8 个默认／例外出站。");
        foreach (var id in ids)
            if (!InboundCatalog.Items(model, "Outbounds").Any(o => o.Text("Id") == id)) throw new OperationException("分流引用的出站已不存在，不会自动改为默认出站或直连。");
        var original = Default(model, inbound);
        foreach (var rule in ServerRuleSets.Expand(rules).Where(r => r.Text("Kind") == "Cidr" && r.Text("Action") != "Reject"))
        {
            var target = rule.Text("Target") == "" ? original : InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == rule.Text("Target"));
            var family = rule.Text("Action") == "Direct" ? original.Text("Family") : target.Text("Family");
            var ipv6 = IPAddress.Parse(rule.Text("Value").Split('/')[0]).AddressFamily == AddressFamily.InterNetworkV6;
            if (family != "Auto" && ipv6 != (family == "IPv6")) throw new OperationException("分流网段与所选出站地址族不符，请明确阻断或选择匹配的去向。");
        }
        // Keep the real default-path acceptance independent of policy examples.
        foreach (var host in original.Text("Family") == "IPv4" ? new[] { "api.ipify.org" } : original.Text("Family") == "IPv6" ? new[] { "api6.ipify.org" } : new[] { "api64.ipify.org" })
        {
            var decision = ServerDestinationRules.Match(rules, host);
            if (decision.Action != "NextHop" || decision.Target != "" && decision.Target != original.Text("Id")) throw new OperationException("分流遮挡了默认去向的验收目标；请先添加明确的默认去向例外，不自动插入隐藏规则。");
        }
    }
    public static string Tag(JsonObject inbound, string id) => id == inbound.Text("OutboundId") ? "egress" : "policy-" + InboundCatalog.Id(id);
    public static string DirectFamily(JsonObject model, JsonObject inbound) => Default(model, inbound).Text("Family");
    private static JsonObject Direct(string family, string tag, bool xray) => xray
        ? new JsonObject { ["tag"] = tag, ["protocol"] = "freedom", ["settings"] = new JsonObject { ["domainStrategy"] = family switch { "IPv4" => "ForceIPv4", "IPv6" => "ForceIPv6", _ => "AsIs" } } }
        : new JsonObject { ["type"] = "direct", ["tag"] = tag, ["domain_resolver"] = new JsonObject { ["server"] = "local", ["strategy"] = family switch { "IPv4" => "ipv4_only", "IPv6" => "ipv6_only", _ => "prefer_ipv4" } } };
    public static JsonObject Apply(ArchiveStore store, JsonObject plan, JsonObject model, JsonObject inbound, JsonObject configuration)
    {
        var rules = Rules(inbound); if (rules.Count == 0) return configuration;
        Validate(model, inbound); var xray = InboundCatalog.UsesXray(inbound); var outputs = configuration["outbounds"]!.AsArray();
        foreach (var target in InboundCatalog.Items(model, "Outbounds").Where(o => References(inbound).Contains(o.Text("Id")) && o.Text("Id") != inbound.Text("OutboundId")))
        {
            var native = InboundRendering.ResolveOutbound(store, plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy", target);
            InboundRendering.ValidateOutboundLoop(plan, model, native);
            var value = target.Text("Kind") == "Direct" ? Direct(target.Text("Family"), Tag(inbound, target.Text("Id")), xray) : xray ? ServerOutboundRouting.XrayNextHop(native) : native;
            value["tag"] = Tag(inbound, target.Text("Id")); outputs.Add(value);
        }
        if (rules.Any(r => r!.Text("Action") == "Direct")) outputs.Add(Direct(DirectFamily(model, inbound), "policy-direct", xray));
        string Target(ServerDestinationDecision d) => d.Action == "Reject" ? "block" : d.Action == "Direct" ? "policy-direct" : d.Target == "" ? "egress" : Tag(inbound, d.Target);
        var rendered = ServerDestinationRules.RenderNative(xray, rules, [inbound.Text("Id")], Target);
        var original = configuration[xray ? "routing" : "route"]!["rules"]!.AsArray();
        foreach (var rule in original) rendered.Add(rule!.DeepClone());
        configuration[xray ? "routing" : "route"]!["rules"] = rendered;
        if (xray && !outputs.Any(o => o!.Text("tag") == "block")) outputs.Add(new JsonObject { ["tag"] = "block", ["protocol"] = "blackhole" });
        return configuration;
    }
    public static JsonArray Paths(JsonObject model, JsonObject inbound, JsonObject configuration)
    {
        var result = new JsonArray(); if (Rules(inbound).Count == 0) return result;
        foreach (var id in References(inbound))
        {
            var target = InboundCatalog.Items(model, "Outbounds").Single(o => o.Text("Id") == id);
            Add(id, Tag(inbound, id), target.Text("Family"), target.Text("ExpectedAddress"));
        }
        if (Rules(inbound).Any(r => r!.Text("Action") == "Direct")) Add("Direct", "policy-direct", DirectFamily(model, inbound), "");
        return result;
        void Add(string id, string tag, string family, string expected)
        {
            var outbound = configuration["outbounds"]!.AsArray().OfType<JsonObject>().Single(o => o.Text("tag") == tag);
            result.Add(new JsonObject { ["Id"] = id, ["Tag"] = tag, ["Family"] = family, ["ExpectedAddress"] = expected, ["OutboundFingerprint"] = ArchiveStore.Fingerprint(outbound) });
        }
    }
    public static JsonObject ProbeRequest(ArchiveStore store, JsonObject plan, JsonObject model, JsonObject credentials, JsonObject inbound)
    {
        var configuration = InboundRendering.Configuration(store, plan, model, credentials, inbound);
        return new JsonObject { ["InboundId"] = inbound.Text("Id"), ["ConfigurationSha256"] = ArchiveStore.Digest(ArchiveStore.JsonBytes(configuration)), ["PolicyFingerprint"] = Fingerprint(model, inbound), ["Paths"] = Paths(model, inbound, configuration) };
    }
    public static void RequirePaths(JsonObject request, JsonObject result)
    {
        var expected = request["Paths"]!.AsArray(); var actual = result["Items"] as JsonArray ?? [];
        if (result.Text("Status") != "Passed" || result.Text("InboundId") != request.Text("InboundId") || result.Text("ConfigurationSha256") != request.Text("ConfigurationSha256") || result.Text("PolicyFingerprint") != request.Text("PolicyFingerprint") || actual.Count != expected.Count)
            throw new OperationException("独立入站分流去向的实际验收不完整。");
        foreach (var path in expected.OfType<JsonObject>())
            if (actual.Count(item => item.Text("Id") == path.Text("Id") && item.Text("OutboundFingerprint") == path.Text("OutboundFingerprint") && item.Text("Status") == "Passed" && item.Text("From") == "EntryServer" && item.Text("Scope") == "NativeOutboundHttps" && item.Text("Network") == "TCP" && IPAddress.TryParse(item.Text("Egress"), out var ip) && (path.Text("ExpectedAddress") == "" || IPAddress.Parse(path.Text("ExpectedAddress")).Equals(ip)) && (path.Text("Family") == "Auto" || (ip!.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4") == path.Text("Family"))) != 1)
                throw new OperationException("分流去向的鉴权、TLS、地址族或预期出口验收不符，不会降级到其他去向。");
    }
    public static bool EvidenceMatches(ArchiveStore store, JsonObject plan, JsonObject model, JsonObject credentials, string inboundId, JsonNode? item)
    {
        var inbound = InboundCatalog.Items(model, "Inbounds").Single(i => i.Text("Id") == inboundId);
        if (Rules(inbound).Count == 0) return true;
        if (item?["PolicyValidation"] is not JsonObject evidence) return false;
        try { RequirePaths(ProbeRequest(store, plan, model, credentials, inbound), evidence); return true; }
        catch (OperationException) { return false; }
    }
    public static string Summary(JsonObject model, JsonObject inbound)
    {
        var rules = Rules(inbound); if (rules.Count == 0) return "分流：未设置例外，TCP／UDP 使用默认去向。";
        string Name(string id) => InboundCatalog.Items(model, "Outbounds").SingleOrDefault(o => o.Text("Id") == id)?.Text("Name") ?? "出站已缺失，须重选";
        return "TCP 分流（按顺序首条命中）：\n" + string.Join('\n', rules.OfType<JsonObject>().Select((r, n) => $"{n + 1}. {ServerDestinationRules.KindLabel(r.Text("Kind"))} · {(r.Text("Kind") == "RuleSet" ? r.Text("RuleSet.Name") + " v" + r.Text("RuleSet.Revision") + " · " + ServerRuleSets.Digest(r["RuleSet"]!.AsObject())[..8] : r.Text("Value"))} → {(r.Text("Action") == "Reject" ? "阻断" : r.Text("Action") == "Direct" ? "服务器直连" : Name(r.Text("Target") == "" ? inbound.Text("OutboundId") : r.Text("Target")))}"))
            + "\n未命中及 UDP：" + Name(inbound.Text("OutboundId")) + "。UDP 不套用 TCP 例外；分类固定版本，不后台拉取；服务器直连使用 VPS 网络。";
    }
}
