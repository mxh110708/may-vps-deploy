using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ClientGroupPreview(string SchemeFingerprint, string GroupRevision, JsonObject Scheme, IReadOnlyList<ClientSourceChange> Changes, IReadOnlyList<string> Errors)
{
    public bool Ready => Errors.Count == 0;
}

// Groups are private, explicit snapshots. They never fetch subscriptions or mutate another scheme.
public static class ClientNodeGroups
{
    public static string MemberFingerprint(JsonObject node)
    {
        var value = node.DeepClone().AsObject(); value.Remove("Id"); value.Remove("GroupOrigin");
        return ArchiveStore.Fingerprint(value);
    }
    public static string Revision(JsonObject group) => ArchiveStore.Fingerprint(group);
    public static JsonObject Capture(JsonObject scheme, string name, IReadOnlyList<string> selected, string? id = null, JsonObject? previous = null)
    {
        var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => selected.Contains(n.Text("Id"))).Select(n => n.DeepClone().AsObject()).ToArray();
        if (selected.Count != nodes.Length || selected.Distinct(StringComparer.Ordinal).Count() != selected.Count) throw new OperationException("请选择不重复的现有节点。");
        foreach (var node in nodes)
        {
            if (id != null && node.Text("GroupOrigin.Id") == id) node["Id"] = node.Text("GroupOrigin.MemberId");
            node.Remove("GroupOrigin");
        }
        if (previous != null && previous.Text("Id") != id) throw new OperationException("节点组来源身份不匹配。");
        var sources = (scheme["NodeSources"] as JsonArray ?? []).OfType<JsonObject>().Concat((previous?["NodeSources"] as JsonArray ?? []).OfType<JsonObject>()).GroupBy(s => s.Text("Id"), StringComparer.Ordinal).Select(s => s.First());
        var files = scheme["Sources"]?.DeepClone().AsObject() ?? new JsonObject();
        if (previous?["Sources"] is JsonObject priorFiles && scheme["Nodes"]!.AsArray().Any(n => selected.Contains(n!.Text("Id")) && n.Text("GroupOrigin.Id") == id))
            foreach (var pair in priorFiles) if (!files.ContainsKey(pair.Key)) files[pair.Key] = pair.Value?.DeepClone();
        var group = new JsonObject { ["Schema"] = 1, ["Id"] = id ?? Guid.NewGuid().ToString("N"), ["Name"] = name.Trim(),
            ["Nodes"] = new JsonArray(nodes.Select(n => (JsonNode?)n).ToArray()),
            ["Sources"] = files,
            ["NodeSources"] = new JsonArray(sources.Where(s => nodes.Any(n => n.Text("Source.Id") == s.Text("Id"))).Select(s => s.DeepClone()).ToArray()) };
        Validate(group); return group;
    }
    public static void Validate(JsonObject group)
    {
        if (group.Number("Schema") != 1 || !Guid.TryParseExact(group.Text("Id"), "N", out _) || group.Text("Name").Length is < 1 or > 100 || group.Text("Name").Any(char.IsControl)) throw new OperationException("节点组名称、版本或身份无效。");
        if (group["Nodes"] is not JsonArray list || list.Count is < 1 or > ClientNodeImport.MaximumLines || list.Any(n => n is not JsonObject)) throw new OperationException("节点组应包含 1–200 个节点。");
        var nodes = list.OfType<JsonObject>().ToArray(); var names = nodes.Select(n => n.Text("name")).ToHashSet(StringComparer.Ordinal);
        if (names.Count != nodes.Length || nodes.Select(n => n.Text("Id")).Distinct(StringComparer.Ordinal).Count() != nodes.Length || nodes.Any(n => !Guid.TryParseExact(n.Text("Id"), "N", out _) || n["GroupOrigin"] != null || n.Text("name").Length is < 1 or > 120 || n.Text("name").Any(char.IsControl))) throw new OperationException("节点组成员身份或名称不完整、重复，或含嵌套节点组。");
        var regions = nodes.Where(n => n.Text("kind") == "entry").Select(n => n.Text("region_group")).ToHashSet(StringComparer.Ordinal);
        foreach (var node in nodes)
        {
            if (node.Text("kind") is not ("entry" or "landing") || node["clash"] is not JsonObject && node["sing_box"] is not JsonObject) throw new OperationException("节点组成员缺少用途或客户端连接。");
            if (node.Text("kind") == "landing" && !regions.Contains(node.Text("transit_group"))) throw new OperationException("落地依赖的入口也须包含在同一节点组。");
            foreach (var key in new[] { "sing_box.detour", "clash.dialer-proxy" })
                if (node.Text(key) is var upstream && upstream != "" && upstream != "DIRECT" && !names.Contains(upstream) && !regions.Contains(upstream)) throw new OperationException("节点组未包含完整上游依赖。");
        }
        var visiting = new HashSet<string>(StringComparer.Ordinal); var complete = new HashSet<string>(StringComparer.Ordinal);
        void Visit(JsonObject node)
        {
            var name = node.Text("name"); if (complete.Contains(name)) return;
            if (!visiting.Add(name)) throw new OperationException("节点组包含循环上游依赖。");
            var targets = new[] { node.Text("sing_box.detour"), node.Text("clash.dialer-proxy") }.Where(t => t != "" && t != "DIRECT").Distinct(StringComparer.Ordinal);
            foreach (var target in targets) foreach (var dependency in nodes.Where(n => n.Text("name") == target || n.Text("kind") == "entry" && n.Text("region_group") == target)) Visit(dependency);
            visiting.Remove(name); complete.Add(name);
        }
        foreach (var node in nodes) Visit(node);
    }
    public static ClientGroupPreview Preview(JsonObject scheme, JsonObject group)
    {
        Validate(group); var draft = scheme.DeepClone().AsObject(); var errors = new List<string>(); var changes = new List<ClientSourceChange>();
        var id = group.Text("Id"); var originals = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        var owned = originals.Where(n => n.Text("GroupOrigin.Id") == id).ToArray();
        foreach (var node in owned)
            if (MemberFingerprint(node) != node.Text("GroupOrigin.MemberFingerprint") && !group["Nodes"]!.AsArray().OfType<JsonObject>().Any(m => m.Text("Id") == node.Text("GroupOrigin.MemberId") && MemberFingerprint(m) == MemberFingerprint(node))) errors.Add("节点“" + node.Text("name") + "”有本地修改；请先解除节点组关联，避免覆盖。");
        if (owned.Select(n => n.Text("GroupOrigin.MemberId")).Distinct(StringComparer.Ordinal).Count() != owned.Length) errors.Add("节点组成员身份重复。");
        var outside = originals.Except(owned).ToArray(); var fresh = group["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        var reserved = scheme["Layout"]!.Strings("region_groups").Concat(scheme["Layout"]!["business_groups"]!.AsArray().Select(n => n!.Text("name"))).Concat((scheme["Layout"]!["guard_groups"] as JsonArray ?? []).Select(n => n!.Text("name"))).Concat(new[] { "DIRECT", "BLOCK", scheme.Text("Layout.default_exit_group"), scheme.Text("Layout.direct_group") }).ToHashSet(StringComparer.Ordinal);
        foreach (var node in fresh)
        {
            if (outside.Any(n => n.Text("name") == node.Text("name")) || reserved.Contains(node.Text("name"))) errors.Add("节点名称与方案现有节点或分组冲突：" + node.Text("name"));
            if (outside.Any(n => ClientNodeImport.ConnectionFingerprint(n) == ClientNodeImport.ConnectionFingerprint(node))) errors.Add("方案已有相同连接，不能接管其来源：" + node.Text("name"));
            var region = node.Text(node.Text("kind") == "entry" ? "region_group" : "transit_group");
            if (!scheme["Layout"]!.Strings("region_groups").Contains(region)) errors.Add("方案布局不包含节点组所需地区：" + region);
        }
        var replacements = new List<JsonObject>(); var renamed = new Dictionary<string, string>(StringComparer.Ordinal); var removed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var source in fresh)
        {
            var old = owned.FirstOrDefault(n => n.Text("GroupOrigin.MemberId") == source.Text("Id"));
            var node = source.DeepClone().AsObject(); node["Id"] = old?.Text("Id") ?? Guid.NewGuid().ToString("N");
            node["GroupOrigin"] = new JsonObject { ["Id"] = id, ["MemberId"] = source.Text("Id"), ["MemberFingerprint"] = MemberFingerprint(source) }; replacements.Add(node);
            changes.Add(new(old == null ? "Added" : MemberFingerprint(old) == MemberFingerprint(source) ? "Unchanged" : "Changed", source.Text("name"), "保留完整连接、用途及来源；鉴权值不在预览中展示。"));
            if (old != null && old.Text("name") != source.Text("name")) renamed[old.Text("name")] = source.Text("name");
        }
        foreach (var node in owned.Where(n => !fresh.Any(v => v.Text("Id") == n.Text("GroupOrigin.MemberId")))) { removed.Add(node.Text("name")); changes.Add(new("Removed", node.Text("name"), "移除此节点组成员，保留方案内其他节点。")); }
        var output = new JsonArray(); var inserted = false;
        foreach (var node in originals)
        {
            if (owned.Contains(node)) { if (!inserted) { foreach (var next in replacements) output.Add(next); inserted = true; } }
            else output.Add(node.DeepClone());
        }
        if (!inserted) foreach (var node in replacements) output.Add(node);
        draft["Nodes"] = output; ClientSchemes.RemapNodeReferences(draft, renamed, removed);
        var activeRegions = output.OfType<JsonObject>().Where(n => n.Text("kind") == "entry").Select(n => n.Text("region_group")).ToHashSet(StringComparer.Ordinal);
        var lostRegions = originals.Where(n => n.Text("kind") == "entry").Select(n => n.Text("region_group")).Where(r => !activeRegions.Contains(r)).ToHashSet(StringComparer.Ordinal);
        foreach (var business in draft["Layout"]!["business_groups"]!.AsArray().OfType<JsonObject>().Where(g => lostRegions.Contains(g.Text("default"))))
        { changes.Add(new("Impact", business.Text("name"), "原默认地区将为空，请重新指定出口。")); business["default"] = ""; }
        foreach (var landing in output.OfType<JsonObject>().Where(n => n.Text("kind") == "landing" && !activeRegions.Contains(n.Text("transit_group")))) errors.Add("落地依赖的地区入口将为空：" + landing.Text("name"));
        foreach (var node in output.OfType<JsonObject>().Where(n => n.Text("GroupOrigin.Id") != id))
            foreach (var key in new[] { "sing_box.detour", "clash.dialer-proxy" })
            {
                var target = node.Text(key);
                if (removed.Contains(target) || lostRegions.Contains(target)) errors.Add("方案其他节点依赖被删除的成员或地区：" + node.Text("name"));
                if (renamed.TryGetValue(target, out var name)) node.Put(key, name);
            }
        if (output.Count > ClientNodeImport.MaximumLines) errors.Add("复用后方案超过 200 个节点。");
        var refs = draft["GroupReferences"] as JsonArray ?? []; draft["GroupReferences"] = refs.Parent == null ? refs : refs.DeepClone(); refs = draft["GroupReferences"]!.AsArray();
        foreach (var old in refs.OfType<JsonObject>().Where(r => r.Text("Id") == id).ToArray()) refs.Remove(old);
        refs.Add(new JsonObject { ["Id"] = id, ["Name"] = group.Text("Name"), ["Revision"] = Revision(group) }); draft.Remove("Candidate");
        return new(ArchiveStore.Fingerprint(scheme), Revision(group), draft, changes, errors);
    }
    public static void Apply(JsonObject scheme, JsonObject group, ClientGroupPreview preview)
    {
        if (!preview.Ready || preview.SchemeFingerprint != ArchiveStore.Fingerprint(scheme) || preview.GroupRevision != Revision(group)) throw new OperationException("节点组预览有冲突或来源已变化，请重新预览。");
        // Recompute rather than trusting a mutable preview object supplied by a caller.
        var current = Preview(scheme, group); if (!current.Ready) throw new OperationException("节点组不能应用到当前方案。");
        scheme["Nodes"] = current.Scheme["Nodes"]!.DeepClone(); scheme["Layout"] = current.Scheme["Layout"]!.DeepClone(); scheme["GroupReferences"] = current.Scheme["GroupReferences"]!.DeepClone(); scheme.Remove("Candidate");
    }
    public static void Detach(JsonObject scheme, string id)
    {
        foreach (var node in scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => n.Text("GroupOrigin.Id") == id)) node.Remove("GroupOrigin");
        if (scheme["GroupReferences"] is JsonArray refs) foreach (var value in refs.OfType<JsonObject>().Where(n => n.Text("Id") == id).ToArray()) refs.Remove(value);
        scheme.Remove("Candidate");
    }
}
