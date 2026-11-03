using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ClientNodeBatchChange(string Name, string Before, string After);
public sealed record ClientNodeBatchPreview(string SchemeFingerprint, string Action, IReadOnlyList<string> SelectedIds,
    string Value, IReadOnlyList<ClientNodeBatchChange> Changes, IReadOnlyList<string> Errors, JsonObject Scheme)
{
    public bool Ready => Errors.Count == 0 && Changes.Count > 0;
}

// One reviewed local draft operation. Connection material and origin identities
// stay intact; ordering never silently changes selection or routing defaults.
public static class ClientNodeBatch
{
    public static readonly string[] Actions = ["Region", "Transit", "Remove", "MoveStart", "MoveEnd", "Sort", "DetachSubscription", "DetachGroup"];
    public static ClientNodeBatchPreview Preview(JsonObject scheme, string action, IReadOnlyList<string> selected, string value = "")
    {
        var nodes = (scheme["Nodes"] as JsonArray)?.OfType<JsonObject>().ToArray() ?? throw new OperationException("方案缺少节点。");
        if (nodes.Length != scheme["Nodes"]!.AsArray().Count || nodes.Length > ClientNodeImport.MaximumLines || nodes.Select(n => n.Text("Id")).Distinct(StringComparer.Ordinal).Count() != nodes.Length) throw new OperationException("节点结构、身份重复或数量限制不满足要求。");
        foreach (var node in nodes) _ = InboundCatalog.Id(node.Text("Id"));
        if (!Actions.Contains(action) || selected.Count is < 1 or > ClientNodeImport.MaximumLines || selected.Distinct(StringComparer.Ordinal).Count() != selected.Count || selected.Any(id => !nodes.Any(n => n.Text("Id") == id))) throw new OperationException("请选择不重复的现有节点与有效批量操作。");
        if (action is "Region" or "Transit") { if (!scheme["Layout"]!.Strings("region_groups").Contains(value)) throw new OperationException("请选择已有地区入口组。"); }
        else if (value != "") throw new OperationException("本操作不接受额外参数。");
        var ids = selected.ToHashSet(StringComparer.Ordinal); var draft = scheme.DeepClone().AsObject(); var list = draft["Nodes"]!.AsArray();
        var picked = list.OfType<JsonObject>().Where(n => ids.Contains(n.Text("Id"))).ToArray();
        var changes = new List<ClientNodeBatchChange>(); var errors = new List<string>();
        if (action is "Region" or "Transit" or "Remove" or "DetachSubscription")
            foreach (var node in picked.Where(n => n["GroupOrigin"] != null)) errors.Add("节点“" + node.Text("name") + "”属于复用组，请先显式解除整组关联，再修改成员。");
        switch (action)
        {
            case "Region": case "Transit":
                foreach (var node in picked)
                {
                    var required = action == "Region" ? "entry" : "landing"; var field = action == "Region" ? "region_group" : "transit_group";
                    if (node.Text("kind") != required) { errors.Add("所选用途不符：" + node.Text("name")); continue; }
                    if (action == "Transit" && new[] { "sing_box.detour", "clash.dialer-proxy" }.Any(k => node.Text(k) != "" && node.Text(k) != node.Text(field))) { errors.Add("节点保留了额外上游，不能用地区组覆盖：" + node.Text("name")); continue; }
                    if (node.Text(field) == value) continue;
                    changes.Add(new(node.Text("name"), node.Text(field), value)); node[field] = value;
                }
                break;
            case "Remove":
                foreach (var node in picked) { changes.Add(new(node.Text("name"), "保留在本方案", "从本方案移除；上游来源不变")); list.Remove(node); }
                var removedNames = picked.Select(n => n.Text("name")).ToHashSet(StringComparer.Ordinal);
                var liveRegions = list.OfType<JsonObject>().Where(n => n.Text("kind") == "entry").Select(n => n.Text("region_group")).ToHashSet(StringComparer.Ordinal);
                var lostRegions = nodes.Where(n => n.Text("kind") == "entry" && !liveRegions.Contains(n.Text("region_group"))).Select(n => n.Text("region_group"));
                var removedTargets = removedNames.Concat(lostRegions).ToHashSet(StringComparer.Ordinal);
                foreach (var group in draft["Layout"]!["business_groups"]!.AsArray().OfType<JsonObject>())
                    if (removedTargets.Contains(group.Text("default"))) errors.Add("先调整业务组“" + group.Text("name") + "”的默认出口，不能批量移除其当前去向。");
                foreach (var group in (draft.At("Layout.guard_groups") as JsonArray ?? []).OfType<JsonObject>())
                    if (group.Strings("members").Any(removedTargets.Contains)) errors.Add("保护组“" + group.Text("name") + "”仍引用待移除节点或地区。");
                foreach (var node in list.OfType<JsonObject>())
                    if (new[] { "sing_box.detour", "clash.dialer-proxy" }.Any(k => removedTargets.Contains(node.Text(k)))) errors.Add("保留节点“" + node.Text("name") + "”仍依赖待移除的上游。");
                if (errors.Count == 0) ClientSchemes.RemapNodeReferences(draft, new Dictionary<string, string>(), removedTargets);
                break;
            case "MoveStart": case "MoveEnd": case "Sort":
                var originals = list.OfType<JsonObject>().ToArray();
                var order = action == "MoveStart" ? picked.Concat(originals.Where(n => !ids.Contains(n.Text("Id")))).ToArray()
                    : action == "MoveEnd" ? originals.Where(n => !ids.Contains(n.Text("Id"))).Concat(picked).ToArray() : originals.ToArray();
                if (action == "Sort")
                {
                    var sorted = picked.OrderBy(n => n.Text("name"), StringComparer.Ordinal).ToArray(); var j = 0;
                    for (var i = 0; i < order.Length; i++) if (ids.Contains(order[i].Text("Id"))) order[i] = sorted[j++];
                }
                for (var i = 0; i < order.Length; i++) if (order[i].Text("Id") != originals[i].Text("Id")) changes.Add(new(order[i].Text("name"), "原顺序 " + (Array.IndexOf(originals, order[i]) + 1), "新顺序 " + (i + 1)));
                draft["Nodes"] = new JsonArray(order.Select(n => n.DeepClone()).ToArray());
                break;
            case "DetachSubscription":
                foreach (var node in picked)
                {
                    if (node.Text("Source.Kind") != "Subscription") { errors.Add("节点不是订阅成员：" + node.Text("name")); continue; }
                    ClientSubscriptions.Detach(node); changes.Add(new(node.Text("name"), "跟随订阅来源", "当前方案独立使用，连接参数保留"));
                }
                break;
            case "DetachGroup":
                var groups = picked.Select(n => n.Text("GroupOrigin.Id")).Distinct(StringComparer.Ordinal).ToArray();
                if (groups.Contains("")) errors.Add("请只选择已关联节点组的成员。");
                foreach (var group in groups.Where(g => g != ""))
                {
                    var members = list.OfType<JsonObject>().Where(n => n.Text("GroupOrigin.Id") == group).ToArray();
                    if (members.Any(n => !ids.Contains(n.Text("Id")))) { errors.Add("解除关联需选择该组的全部成员，不能静默修改未选节点。"); continue; }
                    foreach (var member in members) changes.Add(new(member.Text("name"), "关联复用节点组", "当前方案独立使用，原始来源与连接保留"));
                    ClientNodeGroups.Detach(draft, group);
                }
                break;
        }
        var remaining = draft["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        var regions = remaining.Where(n => n.Text("kind") == "entry").Select(n => n.Text("region_group")).ToHashSet(StringComparer.Ordinal);
        if (regions.Count == 0) errors.Add("批量操作至少保留一个地区入口，不生成无节点或隐式直连的结果。");
        foreach (var node in remaining.Where(n => n.Text("kind") == "landing" && !regions.Contains(n.Text("transit_group")))) errors.Add("落地“" + node.Text("name") + "”的入口组将为空。");
        foreach (var group in draft["Layout"]!["business_groups"]!.AsArray().OfType<JsonObject>())
            if (scheme["Layout"]!.Strings("region_groups").Contains(group.Text("default")) && !regions.Contains(group.Text("default"))) errors.Add("业务组“" + group.Text("name") + "”的默认地区将为空，请先调整默认出口。");
        var disappeared = nodes.Where(n => n.Text("kind") == "entry" && !regions.Contains(n.Text("region_group"))).Select(n => n.Text("region_group")).ToHashSet(StringComparer.Ordinal);
        foreach (var node in remaining)
            if (new[] { "sing_box.detour", "clash.dialer-proxy" }.Any(k => disappeared.Contains(node.Text(k)))) errors.Add("保留节点“" + node.Text("name") + "”仍依赖将变空的地区组。");
        foreach (var group in (draft.At("Layout.guard_groups") as JsonArray ?? []).OfType<JsonObject>())
            if (group.Strings("members").Any(disappeared.Contains)) errors.Add("保护组“" + group.Text("name") + "”仍引用将变空的地区。");
        if (errors.Count == 0 && disappeared.Count != 0) ClientSchemes.RemapNodeReferences(draft, new Dictionary<string, string>(), disappeared);
        if (ArchiveStore.Fingerprint(scheme["Layout"]!) != ArchiveStore.Fingerprint(draft["Layout"]!)) changes.Add(new("出口排列", "包含待移除节点或空地区的排序项", "清理这些排序项，保留其他默认出口与相对顺序"));
        if (errors.Count == 0) { try { ClientSchemes.Specification(draft); } catch (OperationException error) { errors.Add(error.Message); } }
        draft.Remove("Candidate");
        return new(ArchiveStore.Fingerprint(scheme), action, Array.AsReadOnly(selected.ToArray()), value, changes.AsReadOnly(), errors.Distinct(StringComparer.Ordinal).ToArray(), draft);
    }
    public static void Apply(JsonObject scheme, ClientNodeBatchPreview preview)
    {
        if (!preview.Ready || ArchiveStore.Fingerprint(scheme) != preview.SchemeFingerprint) throw new OperationException("方案已变化或批量预览有冲突，请重新选择预览。");
        var current = Preview(scheme, preview.Action, preview.SelectedIds, preview.Value);
        if (!current.Ready) throw new OperationException("批量操作已不再满足依赖条件。");
        foreach (var field in new[] { "Nodes", "Layout", "GroupReferences" }) if (current.Scheme[field] != null) scheme[field] = current.Scheme[field]!.DeepClone();
        scheme.Remove("Candidate");
    }
}
