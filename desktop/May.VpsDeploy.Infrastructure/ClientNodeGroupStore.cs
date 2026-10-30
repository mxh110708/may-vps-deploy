using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class ClientNodeGroupStore(ArchiveStore store)
{
    private string FileName(string id)
    {
        if (!Guid.TryParseExact(id, "N", out _)) throw new OperationException("节点组身份无效。");
        return store.Paths.Resolve("private/client-node-groups/" + id + ".dotnet.private.json");
    }
    public JsonObject Read(string id) { var value = store.ReadSecret(FileName(id)); ClientNodeGroups.Validate(value); if (value.Text("Id") != id) throw new OperationException("节点组归档身份不匹配。"); return value; }
    public IReadOnlyList<JsonObject> List()
    {
        var root = store.Paths.Resolve("private/client-node-groups"); if (!Directory.Exists(root)) return [];
        SafePath.CheckTree(root); return Directory.EnumerateFiles(root, "*.dotnet.private.json").Select(f => Read(Path.GetFileName(f).Split('.')[0])).OrderBy(g => g.Text("Name"), StringComparer.Ordinal).ToArray();
    }
    public void Save(JsonObject group, string? expectedRevision = null)
    {
        ClientNodeGroups.Validate(group); var file = FileName(group.Text("Id"));
        using var guard = Lock(group.Text("Id"));
        if (File.Exists(file) ? expectedRevision == null || ClientNodeGroups.Revision(Read(group.Text("Id"))) != expectedRevision : expectedRevision != null) throw new OperationException("节点组已变化或被删除，请重新读取。");
        VerifyDependencies(group); store.WriteSecret(file, group);
    }
    public void Delete(string id, JsonObject? activeScheme = null)
    {
        using var guard = Lock(id);
        Read(id);
        var root = store.Paths.Resolve("private/client-schemes");
        if (Directory.Exists(root)) SafePath.CheckTree(root);
        var schemes = Directory.Exists(root) ? Directory.EnumerateFiles(root, "*.dotnet.private.json").Select(store.ReadSecret) : [];
        if (schemes.Append(activeScheme ?? new JsonObject()).Any(s => (s["GroupReferences"] as JsonArray ?? []).Any(r => r!.Text("Id") == id))) throw new OperationException("仍有方案引用此节点组，请先在这些方案中解除关联并保存。");
        var file = FileName(id); SafePath.CheckLinks(file); File.Delete(file);
    }
    private FileStream Lock(string id)
    {
        var file = FileName(id) + ".lock"; SafePath.CheckLinks(file); Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        try { return new FileStream(file, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { throw new OperationException("节点组正在被其他操作使用，请稍后重新读取。"); }
    }
    public void Verify(JsonObject scheme)
    {
        var refs = scheme["GroupReferences"] as JsonArray ?? []; var nodes = scheme["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        if (refs.Count != refs.OfType<JsonObject>().Count() || refs.Select(r => r!.Text("Id")).Distinct(StringComparer.Ordinal).Count() != refs.Count) throw new OperationException("节点组引用重复或不完整。");
        foreach (var reference in refs.OfType<JsonObject>())
        {
            var group = Read(reference.Text("Id")); if (reference.Text("Revision") != ClientNodeGroups.Revision(group)) throw new OperationException("节点组“" + group.Text("Name") + "”已更新，请预览并同步，或解除关联后独立使用。");
            var members = group["Nodes"]!.AsArray().OfType<JsonObject>().ToArray(); var owned = nodes.Where(n => n.Text("GroupOrigin.Id") == group.Text("Id")).ToArray();
            if (owned.Length != members.Length || owned.Select(n => n.Text("GroupOrigin.MemberId")).Distinct(StringComparer.Ordinal).Count() != owned.Length || members.Any(m => !owned.Any(n => n.Text("GroupOrigin.MemberId") == m.Text("Id") && ClientNodeGroups.MemberFingerprint(n) == ClientNodeGroups.MemberFingerprint(m)))) throw new OperationException("已关联节点组的成员被修改或移除，请同步或解除关联。");
            VerifyDependencies(group);
        }
        if (nodes.Any(n => n["GroupOrigin"] != null && !refs.Any(r => r!.Text("Id") == n.Text("GroupOrigin.Id")))) throw new OperationException("节点缺少所属节点组引用。");
    }
    public void VerifyDependencies(JsonObject group)
    {
        if (group["Sources"] is JsonObject sources) foreach (var pair in sources) if (ClientSchemes.SourceFingerprint(pair.Key) != pair.Value!.ToString()) throw new OperationException("节点组文件来源已变化，请从更新后的方案重新保存节点组。");
        var nodes = group["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        ManagedNodeSources.Verify(store, new JsonArray(nodes.Where(n => n["ManagedOrigin"] != null).Select(n => n["ManagedOrigin"]!.DeepClone()).ToArray()));
        ForwardedNodeSources.VerifyNodes(store, nodes);
        TcpChains.VerifyOrigins(store, new JsonArray(nodes.Where(n => n["TcpChainOrigin"] != null).Select(n => n["TcpChainOrigin"]!.DeepClone()).ToArray()));
        InboundSources.VerifyOrigins(store, new JsonArray(nodes.Where(n => n["InboundOrigin"] != null).Select(n => n["InboundOrigin"]!.DeepClone()).ToArray()));
    }
    public ClientGroupPreview Preview(JsonObject scheme, string id) { var group = Read(id); VerifyDependencies(group); return ClientNodeGroups.Preview(scheme, group); }
    public void Apply(JsonObject scheme, string id, ClientGroupPreview preview)
    {
        var group = Read(id); VerifyDependencies(group); var draft = scheme.DeepClone().AsObject();
        ClientNodeGroups.Apply(draft, group, preview); Verify(draft);
        scheme["Nodes"] = draft["Nodes"]!.DeepClone(); scheme["Layout"] = draft["Layout"]!.DeepClone(); scheme["GroupReferences"] = draft["GroupReferences"]!.DeepClone(); scheme.Remove("Candidate");
    }
}
