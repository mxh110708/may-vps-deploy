using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ClientFragmentRow(string Id, string Name, string Role, bool Dependency);
public sealed record ClientFragmentPreview(string SchemeFingerprint, string Format, IReadOnlyList<string> SelectedIds,
    IReadOnlyList<ClientFragmentRow> Rows, IReadOnlyList<string> Groups, IReadOnlyList<string> Errors)
{
    public bool Ready => Errors.Count == 0 && Rows.Count > 0;
}

// A native merge fragment, never a standalone DNS/routing configuration. Follow
// only explicit node/region upstreams; arbitrary policy graphs need full export.
public static class ClientNodeFragments
{
    public const int MaximumBytes = 1024 * 1024;
    public static ClientFragmentPreview Preview(JsonObject source, string format, IReadOnlyList<string> selected)
        => Describe(source, format, selected).Preview;

    private static (ClientFragmentPreview Preview, JsonObject Document) Describe(JsonObject source, string format, IReadOnlyList<string> selected)
    {
        if (!ClientSchemes.Formats(source).Contains(format)) throw new OperationException("请选择方案已启用的客户端格式。");
        var scheme = ClientOutputRules.RequireReady(source); var all = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        if (all.Length != scheme["Nodes"]!.AsArray().Count || all.Length > ClientNodeImport.MaximumLines || all.Select(n => n.Text("Id")).Distinct(StringComparer.Ordinal).Count() != all.Length || all.Select(n => n.Text("name")).Distinct(StringComparer.Ordinal).Count() != all.Length) throw new OperationException("节点结构、身份、名称或数量限制不满足要求。");
        foreach (var node in all) _ = InboundCatalog.Id(node.Text("Id"));
        if (selected.Count is < 1 or > ClientNodeImport.MaximumLines || selected.Distinct(StringComparer.Ordinal).Count() != selected.Count || selected.Any(id => !all.Any(n => n.Text("Id") == id))) throw new OperationException("请选择输出筛选后仍保留的现有节点。");
        var names = all.ToDictionary(n => n.Text("name"), StringComparer.Ordinal); var regions = scheme["Layout"]!.Strings("region_groups").ToHashSet(StringComparer.Ordinal);
        var visited = new HashSet<string>(StringComparer.Ordinal); var visiting = new HashSet<string>(StringComparer.Ordinal); var groups = new HashSet<string>(StringComparer.Ordinal); var errors = new List<string>(); var direct = false;
        var rawKey = format == "Clash" ? "clash" : "sing_box"; var detourKey = format == "Clash" ? "dialer-proxy" : "detour";
        if (names.Keys.Any(n => regions.Contains(n) || n is "DIRECT" or "BLOCK" or "REJECT")) errors.Add("节点名与地区组或内置动作冲突。");
        string Upstream(JsonObject node)
        {
            var raw = node[rawKey] as JsonObject;
            if (raw == null || raw.Text(format == "Clash" ? "name" : "tag") != node.Text("name")) { errors.Add("节点缺少对应的完整原生配置：" + node.Text("name")); return ""; }
            var upstream = raw.Text(detourKey);
            if (node.Text("kind") != "landing") return upstream;
            var transit = node.Text("transit_group");
            if (!regions.Contains(transit)) { errors.Add("落地节点缺少有效入口组：" + node.Text("name")); return ""; }
            if (upstream != "" && upstream != transit) errors.Add("落地节点的原始上游与所选入口组不一致，请改用完整配置审阅：" + node.Text("name"));
            return transit;
        }
        void Visit(string name)
        {
            if (name == "DIRECT") { direct = true; return; }
            if (visited.Contains(name)) return;
            if (!visiting.Add(name)) { errors.Add("节点片段的上游依赖形成循环。"); return; }
            if (names.TryGetValue(name, out var node))
            {
                var upstream = Upstream(node); if (upstream != "") Visit(upstream);
            }
            else if (regions.Contains(name))
            {
                var members = all.Where(n => n.Text("kind") == "entry" && n.Text("region_group") == name).ToArray();
                if (members.Length == 0) errors.Add("所需入口组没有节点：" + name);
                else { groups.Add(name); foreach (var member in members) Visit(member.Text("name")); }
            }
            else errors.Add("上游不属于可导出的节点或地区组，请使用完整配置：" + name);
            visiting.Remove(name); visited.Add(name);
        }
        foreach (var node in all.Where(n => selected.Contains(n.Text("Id")))) Visit(node.Text("name"));
        var included = all.Where(n => visited.Contains(n.Text("name"))).ToArray(); var native = new JsonArray();
        foreach (var node in included)
        {
            if (node[rawKey] is not JsonObject config) continue;
            var copy = config.DeepClone().AsObject(); if (node.Text("kind") == "landing") copy[detourKey] = node.Text("transit_group"); native.Add(copy);
        }
        var groupOrder = scheme["Layout"]!.Strings("region_groups").Where(groups.Contains).ToArray();
        var selectors = new JsonArray(groupOrder.Select(g => (JsonNode?)new JsonObject
        {
            [format == "Clash" ? "name" : "tag"] = g, ["type"] = format == "Clash" ? "select" : "selector",
            [format == "Clash" ? "proxies" : "outbounds"] = new JsonArray(included.Where(n => n.Text("kind") == "entry" && n.Text("region_group") == g).Select(n => (JsonNode?)JsonValue.Create(n.Text("name"))).ToArray())
        }).ToArray());
        JsonObject document;
        if (format == "Clash") { document = new() { ["proxies"] = native }; if (selectors.Count != 0) document["proxy-groups"] = selectors; }
        else { foreach (var group in selectors) native.Add(group!.DeepClone()); if (direct) native.Add(new JsonObject { ["type"] = "direct", ["tag"] = "DIRECT" }); document = new() { ["outbounds"] = native }; }
        var preview = new ClientFragmentPreview(ArchiveStore.Fingerprint(source), format, Array.AsReadOnly(selected.ToArray()),
            included.Select(n => new ClientFragmentRow(n.Text("Id"), n.Text("name"), n.Text("kind"), !selected.Contains(n.Text("Id")))).ToArray(), groupOrder, errors.Distinct(StringComparer.Ordinal).ToArray());
        return (preview, document);
    }
    public static JsonObject Build(JsonObject source, ClientFragmentPreview preview)
    {
        if (!preview.Ready || ArchiveStore.Fingerprint(source) != preview.SchemeFingerprint) throw new OperationException("方案已变化或节点片段存在冲突，请重新预览。");
        var current = Describe(source, preview.Format, preview.SelectedIds);
        if (!current.Preview.Ready) throw new OperationException(string.Join("\n", current.Preview.Errors));
        if (System.Text.Encoding.UTF8.GetByteCount(current.Document.ToJsonString()) > MaximumBytes) throw new OperationException("节点片段超过 1 MiB，请减少选择。");
        return current.Document;
    }
}
