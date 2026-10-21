using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ClientOutputIssue(string Severity, string Message);
public sealed record ClientOutputRow(string OriginalName, string OutputName, bool Included, string Reason);
public sealed record ClientOutputPreview(JsonObject Scheme, IReadOnlyList<ClientOutputRow> Rows, IReadOnlyList<ClientOutputIssue> Issues)
{
    public bool Ready => Issues.All(i => i.Severity != "Error");
}

// Output rules are deliberately declarative. Names and credentials in the source scheme are not rewritten.
public static class ClientOutputRules
{
    public static JsonObject New() => new() { ["Enabled"] = false, ["Include"] = "", ["Exclude"] = "", ["Protocols"] = "", ["Role"] = "All", ["Find"] = "", ["Replace"] = "", ["Prefix"] = "", ["Suffix"] = "", ["Sort"] = "Source" };
    public static string Fingerprint(JsonObject scheme) => ArchiveStore.Fingerprint(scheme["OutputRules"] as JsonObject ?? New());
    private static string[] Terms(JsonObject rules, string key) => rules.Text(key).Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    public static ClientOutputPreview Preview(JsonObject source)
    {
        var rules = source["OutputRules"] as JsonObject ?? New(); var rows = new List<ClientOutputRow>(); var issues = new List<ClientOutputIssue>();
        var nodes = source["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        if (!rules.Flag("Enabled")) return new(source, nodes.Select(n => new ClientOutputRow(n.Text("name"), n.Text("name"), true, "沿用源节点")).ToArray(), issues);
        var supported = New(); if (rules.Any(p => !supported.ContainsKey(p.Key))) issues.Add(new("Error", "存在不支持的输出规则字段，未忽略其设置。"));
        foreach (var key in new[] { "Include", "Exclude", "Protocols", "Find", "Replace", "Prefix", "Suffix" })
            if (rules.Text(key).Length > 4096 || rules.Text(key).Any(c => char.IsControl(c) && c != '\n' && c != '\r')) issues.Add(new("Error", "输出规则过长或含控制字符。"));
        if (rules.Text("Role", "All") is not ("All" or "entry" or "landing") || rules.Text("Sort", "Source") is not ("Source" or "NameAscending" or "NameDescending")) issues.Add(new("Error", "输出用途或排序方式无效。"));
        var include = Terms(rules, "Include"); var exclude = Terms(rules, "Exclude"); var protocols = Terms(rules, "Protocols");
        if (include.Length > 32 || exclude.Length > 32 || protocols.Length > 16) issues.Add(new("Error", "筛选词过多；包含、排除各最多 32 行，协议最多 16 行。"));
        if (issues.Count != 0) return new(source, rows, issues);
        var effective = source.DeepClone().AsObject(); var selected = new List<JsonObject>(); var renamed = new Dictionary<string, string>(StringComparer.Ordinal);
        var names = source["Layout"]!.Strings("region_groups").Concat(new[] { "DIRECT", "BLOCK", "REJECT", source.Text("Layout.default_exit_group"), source.Text("Layout.direct_group") })
            .Concat((source.At("Layout.business_groups") as JsonArray ?? []).Select(g => g!.Text("name"))).Concat((source.At("Layout.guard_groups") as JsonArray ?? []).Select(g => g!.Text("name"))).ToHashSet(StringComparer.Ordinal);
        bool Match(string value, string term) => value.Contains(term, StringComparison.OrdinalIgnoreCase);
        foreach (var original in nodes)
        {
            var oldName = original.Text("name"); var protocol = original.Text("sing_box.type", original.Text("clash.type")); if (protocol == "ss") protocol = "shadowsocks";
            var reason = include.Length > 0 && !include.Any(t => Match(oldName, t)) ? "未命中包含词" : exclude.Any(t => Match(oldName, t)) ? "命中排除词"
                : protocols.Length > 0 && !protocols.Any(p => p.Equals(protocol, StringComparison.OrdinalIgnoreCase) || p.Equals("ss", StringComparison.OrdinalIgnoreCase) && protocol == "shadowsocks") ? "协议未选择"
                : rules.Text("Role", "All") != "All" && rules.Text("Role") != original.Text("kind") ? "用途未选择" : "";
            if (reason != "") { rows.Add(new(oldName, "", false, reason)); continue; }
            var display = rules.Text("Find") == "" ? oldName : oldName.Replace(rules.Text("Find"), rules.Text("Replace"), StringComparison.Ordinal);
            display = rules.Text("Prefix") + display + rules.Text("Suffix");
            if (display.Length is < 1 or > 120 || display.Any(char.IsControl)) issues.Add(new("Error", "输出名称应为 1–120 个可打印字符：" + oldName));
            else if (!names.Add(display)) issues.Add(new("Error", "输出名称与节点或组名冲突：" + display));
            if (display != oldName && (nodes.Any(n => n != original && (n.Text("name") == display || n.Text("AuthorityName") == display)) || source.Strings("AuthorityNodes").Contains(display) && original.Text("AuthorityName") != display)) issues.Add(new("Error", "输出名称复用了其他源节点的名称，请调整规则：" + display));
            renamed[oldName] = display; var node = original.DeepClone().AsObject(); node["name"] = display;
            if (node["clash"] is JsonObject clash) clash["name"] = display;
            if (node["sing_box"] is JsonObject sing) sing["tag"] = display;
            if (display != oldName && node.Text("AuthorityName") == "") node["AuthorityName"] = oldName;
            selected.Add(node); rows.Add(new(oldName, display, true, display == oldName ? "名称保留" : "仅改输出显示名"));
        }
        if (selected.Count == 0) issues.Add(new("Error", "筛选后没有节点，不能生成配置或回退到直连。"));
        if (rules.Text("Sort", "Source") != "Source") selected = (rules.Text("Sort") == "NameAscending" ? selected.OrderBy(n => n.Text("name"), StringComparer.Ordinal) : selected.OrderByDescending(n => n.Text("name"), StringComparer.Ordinal)).ToList();
        effective["Nodes"] = new JsonArray(selected.Select(n => (JsonNode?)n).ToArray());
        effective["AuthorityNodes"] = new JsonArray(source.Strings("AuthorityNodes").Concat(nodes.Select(n => n.Text("name"))).Distinct(StringComparer.Ordinal).Select(n => (JsonNode?)JsonValue.Create(n)).ToArray());
        // Apply maps simultaneously: a -> b, b -> c must not accidentally become a -> c.
        foreach (var key in new[] { "default_exit_members" }) RewriteArray(source["Layout"]![key] as JsonArray, effective["Layout"]!.AsObject(), key, renamed);
        var originals = source["Layout"]!["business_groups"]!.AsArray(); var outputGroups = effective["Layout"]!["business_groups"]!.AsArray();
        for (var i = 0; i < originals.Count; i++)
        {
            var old = originals[i]!.Text("default"); outputGroups[i]!["default"] = renamed.GetValueOrDefault(old, old);
            RewriteArray(originals[i]!["order"] as JsonArray, outputGroups[i]!.AsObject(), "order", renamed);
        }
        foreach (var node in selected)
            foreach (var key in new[] { "clash", "sing_box" }) if (node[key] is JsonObject config) RewriteDependencies(config, renamed);
        var active = ClientTopology.Regions(effective).Select(r => r.Name).ToHashSet(StringComparer.Ordinal);
        var lostGroups = ClientTopology.Regions(source).Select(r => r.Name).Where(r => !active.Contains(r)).ToArray();
        foreach (var group in lostGroups) issues.Add(new("Info", "筛选后移除空地区组：" + group));
        var validDefaults = active.Concat(selected.Where(n => n.Text("kind") == "landing").Select(n => n.Text("name"))).Append(source.Text("Layout.default_exit_group")).Append(source.Text("Layout.direct_group")).ToHashSet(StringComparer.Ordinal);
        foreach (var group in outputGroups.OfType<JsonObject>()) if (!validDefaults.Contains(group.Text("default"))) issues.Add(new("Error", "业务组“" + group.Text("name") + "”的默认出口被筛除，请先调整默认出口。"));
        foreach (var landing in selected.Where(n => n.Text("kind") == "landing")) if (!active.Contains(landing.Text("transit_group"))) issues.Add(new("Error", "落地“" + landing.Text("name") + "”的入口组已被筛空。"));
        foreach (var node in nodes.Where(n => renamed.ContainsKey(n.Text("name")) && n.Text("kind") != "landing"))
            foreach (var key in new[] { "clash.dialer-proxy", "sing_box.detour" })
            {
                var target = node.Text(key);
                if (target != "" && (nodes.Any(n => n.Text("name") == target) && !renamed.ContainsKey(target) || lostGroups.Contains(target))) issues.Add(new("Error", "节点“" + node.Text("name") + "”的上游被筛除。"));
            }
        return new(effective, rows, issues);
    }
    public static JsonObject RequireReady(JsonObject source)
    {
        var preview = Preview(source); var errors = preview.Issues.Where(i => i.Severity == "Error").ToArray();
        if (errors.Length != 0) throw new OperationException(string.Join("\n", errors.Select(i => i.Message).Distinct())); return preview.Scheme;
    }
    public static void Apply(JsonObject source, JsonObject rules, string expectedFingerprint)
    {
        if (ArchiveStore.Fingerprint(source) != expectedFingerprint) throw new OperationException("方案已变化，请重新预览输出规则。");
        var draft = source.DeepClone().AsObject(); draft["OutputRules"] = rules.DeepClone(); RequireReady(draft);
        source["OutputRules"] = rules.DeepClone(); source.Remove("Candidate");
    }
    private static void RewriteArray(JsonArray? original, JsonObject target, string key, Dictionary<string, string> map)
    { if (original != null) target[key] = new JsonArray(original.Select(n => (JsonNode?)JsonValue.Create(map.GetValueOrDefault(n!.ToString(), n.ToString()))).ToArray()); }
    private static void RewriteDependencies(JsonObject config, Dictionary<string, string> map)
    { foreach (var key in new[] { "detour", "dialer-proxy" }) if (map.TryGetValue(config.Text(key), out var name)) config[key] = name; }
}
