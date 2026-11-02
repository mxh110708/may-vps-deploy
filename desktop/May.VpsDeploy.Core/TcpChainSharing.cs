using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static partial class TcpChains
{
    // Schema-1 installations used a single binding. Read it without rewriting
    // archives; the next completed operation writes the collection once.
    public static JsonObject[] Bindings(JsonObject plan)
    {
        if (plan["TcpChain"] != null && plan["TcpChains"] != null) throw new OperationException("实例包含两套线路依赖，请先核对归档。");
        var items = plan["TcpChains"] switch
        {
            null => plan["TcpChain"] is JsonObject old ? new[] { old } : plan.ContainsKey("TcpChain") ? throw new OperationException("旧线路依赖格式无效。") : [],
            JsonArray array when array.All(i => i is JsonObject) => array.OfType<JsonObject>().ToArray(),
            _ => throw new OperationException("实例线路依赖列表无效。")
        };
        if (items.Length > 32 || items.Select(i => i.Text("Id")).Distinct(StringComparer.Ordinal).Count() != items.Length) throw new OperationException("实例线路依赖重复或超过 32 条。");
        foreach (var item in items)
        {
            _ = Id(item.Text("Id"));
            OperationPolicy.Validate(new(OperationKind.HealthAudit, item.Text("FrontInstance"), new()));
            if (item.Any(p => p.Key is not ("Id" or "FrontInstance" or "ConfigurationFingerprint")) ||
                item.ContainsKey("ConfigurationFingerprint") && !Regex.IsMatch(item.Text("ConfigurationFingerprint"), "^[a-f0-9]{64}$")) throw new OperationException("线路依赖字段或摘要无效。");
        }
        return items;
    }

    public static bool Bound(JsonObject plan, JsonObject chain) => Bindings(plan).Any(b => b.Text("Id") == chain.Text("Id") && b.Text("FrontInstance") == chain.Text("FrontInstance") &&
        (!b.ContainsKey("ConfigurationFingerprint") || b.Text("ConfigurationFingerprint") == ArchiveStore.Fingerprint(chain)));

    public static void Bind(JsonObject plan, JsonObject chain, bool active)
    {
        var bindings = Bindings(plan).Where(b => b.Text("Id") != chain.Text("Id")).Select(b => b.DeepClone()).ToList();
        if (active) bindings.Add(new JsonObject { ["Id"] = chain.Text("Id"), ["FrontInstance"] = chain.Text("FrontInstance"), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(chain) });
        plan.Remove("TcpChain");
        if (bindings.Count == 0) plan.Remove("TcpChains");
        else plan["TcpChains"] = new JsonArray(bindings.OrderBy(b => b.Text("Id"), StringComparer.Ordinal).ToArray());
    }

    public static JsonObject[] Preserved(ArchiveStore store, JsonObject chain) => List(store).Where(r => r.Text("Phase") == "Active" && r.Text("Configuration.Id") != chain.Text("Id") &&
        Instances(r["Configuration"]!.AsObject()).Intersect(Instances(chain)[..2], StringComparer.OrdinalIgnoreCase).Any()).OrderBy(r => r.Text("Configuration.Id"), StringComparer.Ordinal).ToArray();

    public static string[] Participants(ArchiveStore store, OperationRequest request) => Instances(request.Options["Configuration"]!.AsObject()).Concat(
        request.Options.Text("Action") is "Apply" or "Remove" ? Preserved(store, request.Options["Configuration"]!.AsObject()).SelectMany(r => Instances(r["Configuration"]!.AsObject())) : [])
        .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray();

    public static void VerifyBindings(ArchiveStore store, string instance, JsonObject plan)
    {
        var bindings = Bindings(plan);
        var records = List(store).Where(r => r.Text("Phase") == "Active" && Instances(r["Configuration"]!.AsObject()).Contains(instance, StringComparer.OrdinalIgnoreCase)).ToArray();
        foreach (var record in records)
            if (!Bound(plan, record["Configuration"]!.AsObject())) throw new OperationException("实例缺少活动线路的正确依赖，请先核对归档。");
        foreach (var binding in bindings)
        {
            var record = List(store).SingleOrDefault(r => r.Text("Configuration.Id") == binding.Text("Id"));
            if (record == null || record.Text("Phase") is "Removed" or "RolledBack" || !Instances(record["Configuration"]!.AsObject()).Contains(instance, StringComparer.OrdinalIgnoreCase) || !Bound(plan, record["Configuration"]!.AsObject()))
                throw new OperationException("实例线路依赖与线路归档不同，未继续操作。");
        }
    }

    public static JsonObject OwnedRule(JsonObject record, string instance, JsonObject plan)
    {
        var chain = record["Configuration"]!.AsObject(); var front = instance == chain.Text("FrontInstance");
        if (!front && instance != chain.Text("RelayInstance")) throw new OperationException("该实例不拥有此线路的转发规则。");
        var rule = RulesFor(plan, chain).SingleOrDefault(r => r.Text("Id") == RuleId(chain, front));
        if (rule == null || !rule.Flag("Enabled") || rule.Text("Validation.Type") != "TcpChain" || rule.Text("Validation.ChainId") != chain.Text("Id") || rule.Text("Validation.FrontInstance") != chain.Text("FrontInstance"))
            throw new OperationException("线路规则归属不完整，未修改任何线路。");
        return rule;
    }

    private static IEnumerable<JsonObject> RulesFor(JsonObject plan, JsonObject chain) => TcpForwarding.Rules(plan[Component(chain)] as JsonObject);

    public static void VerifyRule(JsonObject record, string instance, JsonObject plan, JsonObject state)
    {
        var chain = record["Configuration"]!.AsObject(); var key = instance == chain.Text("FrontInstance") ? "Front" : "Relay"; var component = Component(chain);
        var config = NormalizeForwarding(chain, plan[component] as JsonObject ?? TcpForwarding.Empty());
        if (state.Text(component + ".ConfigurationFingerprint") != ArchiveStore.Fingerprint(config) || !Regex.IsMatch(state.Text(component + ".RemoteHash"), "^[a-f0-9]{64}$")) throw new OperationException("共享转发组件的归档摘要无效。");
        var rule = OwnedRule(record, instance, plan);
        if (record.ContainsKey("RuleFingerprints"))
        {
            if (record["RuleFingerprints"] is not JsonObject fingerprints || fingerprints.Count != 2 || fingerprints.Any(p => p.Key is not ("Front" or "Relay") || !Regex.IsMatch(p.Value?.ToString() ?? "", "^[a-f0-9]{64}$")) ||
                fingerprints.Text(key) != ArchiveStore.Fingerprint(rule)) throw new OperationException("此线路的转发规则已变化，请核对该线路。");
        }
        else if (state.Text(component + ".RemoteHash") != record.Text(key + "Hash")) throw new OperationException("旧线路的转发摘要已变化，请先核对线路。");
    }

    public static void SealRules(ArchiveStore store, JsonObject record)
    {
        var c = record["Configuration"]!.AsObject();
        record["RuleFingerprints"] = new JsonObject
        {
            ["Front"] = ArchiveStore.Fingerprint(OwnedRule(record, c.Text("FrontInstance"), Plan(store, c.Text("FrontInstance")))),
            ["Relay"] = ArchiveStore.Fingerprint(OwnedRule(record, c.Text("RelayInstance"), Plan(store, c.Text("RelayInstance"))))
        };
    }

    private static void VerifyOwners(ArchiveStore store, string instance, JsonObject plan, JsonObject state, JsonObject chain)
    {
        foreach (var rule in RulesFor(plan, chain).Where(r => r.Text("Validation.Type") == "TcpChain"))
        {
            var record = List(store).SingleOrDefault(r => r.Text("Configuration.Id") == rule.Text("Validation.ChainId"));
            if (record == null || record.Text("Phase") != "Active" || !Bound(plan, record["Configuration"]!.AsObject()) || Component(record["Configuration"]!.AsObject()) != Component(chain)) throw new OperationException("共享组件存在未知或未完成线路规则。");
            VerifyRule(record, instance, plan, state);
        }
    }
}
