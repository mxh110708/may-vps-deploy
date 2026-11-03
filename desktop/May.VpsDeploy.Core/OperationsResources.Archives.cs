using System.Text.Json;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class OperationsResources
{
    public static OperationsResourceOverview Load(ArchiveStore store, DateTimeOffset now)
    {
        var issues = new List<string>(); var instances = new List<ResourceInstance>();
        foreach (var archived in store.ListInstances())
        {
            try
            {
                var root = store.Paths.Instance(archived.RelativePath);
                var stateFile = SafePath.Resolve(root, "deployment-state.json"); var pendingFile = SafePath.Resolve(root, "operation-pending.dotnet.json");
                var state = File.Exists(stateFile) ? ArchiveStore.ReadJson(stateFile) : new();
                var status = InstanceLifecycle.Describe(archived.Plan, state, File.Exists(pendingFile) ? ArchiveStore.ReadJson(pendingFile) : null);
                instances.Add(new(archived.RelativePath, archived.Plan, state, status.Managed && !status.NeedsRecovery));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or OperationException) { issues.Add(archived.RelativePath + " 的状态无法安全读取；未开放维护。" ); instances.Add(new(archived.RelativePath, archived.Plan, new(), false)); }
        }
        List<JsonObject> Records(string directory, bool encrypted = false, string category = "")
        {
            var result = new List<JsonObject>(); var path = store.Paths.Resolve("private/" + directory);
            if (!Directory.Exists(path)) return result;
            SafePath.CheckTree(path);
            foreach (var file in Directory.EnumerateFiles(path, encrypted ? "*.dotnet.private.json" : "*.json").Order(StringComparer.Ordinal))
            {
                JsonObject? value = null;
                try
                {
                    if (new FileInfo(file).Length > 16 * 1024 * 1024) throw new OperationException("资源归档超出读取范围。");
                    value = encrypted ? store.ReadSecret(file) : ArchiveStore.ReadJson(file);
                    var id = encrypted ? value.Text("Id") : value.Text("Configuration.Id");
                    _ = InboundCatalog.Id(id);
                    if (Path.GetFileName(file) != id + (encrypted ? ".dotnet.private.json" : ".json") || !encrypted && value.Number("Version") != 1) throw new OperationException("资源归档身份不符。");
                    result.Add(encrypted ? ClientMetadata(value, category) : value.DeepClone().AsObject());
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or OperationException or System.Security.Cryptography.CryptographicException or FormatException) { issues.Add(directory + " 有归档无法安全读取；影响清单可能不完整，请先核对。"); }
                finally { value?.Clear(); }
            }
            return result;
        }
        var chains = Records("tcp-chains"); var tunnels = Records("wireguard-tunnels");
        var pendingHosts = chains.Where(TcpChains.Pending).SelectMany(r => TcpChains.Instances(r["Configuration"]!.AsObject()))
            .Concat(tunnels.Where(WireGuardTunnels.Pending).SelectMany(r => WireGuardTunnels.Instances(r["Configuration"]!.AsObject()))).ToHashSet(StringComparer.OrdinalIgnoreCase);
        instances = instances.Select(i => pendingHosts.Contains(i.RelativePath) ? i with { CanMaintain = false } : i).ToList();
        var clients = Records("client-schemes", true, "Scheme").Concat(Records("client-node-groups", true, "Group")).ToArray();
        return Build(instances, now, chains, tunnels, clients, issues);
    }
    // Read protected documents directly. The overview must not call workbench
    // List(), which can upgrade and save older layouts as a side effect.
    public static JsonObject ClientMetadata(JsonObject source, string category)
    {
        _ = InboundCatalog.Id(source.Text("Id"));
        if (category is not ("Scheme" or "Group") || source["Nodes"] is not JsonArray sourceNodes || sourceNodes.Count > ClientNodeImport.MaximumLines || sourceNodes.Any(n => n is not JsonObject) || sourceNodes.OfType<JsonObject>().Select(n => n.Text("Id")).Distinct(StringComparer.Ordinal).Count() != sourceNodes.Count) throw new OperationException("客户端资源元数据不完整或身份重复。");
        var nodes = new JsonArray();
        foreach (var node in sourceNodes.OfType<JsonObject>())
        {
            _ = InboundCatalog.Id(node.Text("Id"));
            var item = new JsonObject { ["Id"] = node.Text("Id"), ["Name"] = node.Text("name") };
            foreach (var (group, fields) in new[]
            {
                ("InboundOrigin", new[] { "Instance", "InboundId" }), ("ManagedOrigin", new[] { "Instance", "Role" }),
                ("TcpChainOrigin", new[] { "Id" }), ("ForwardedOrigin", new[] { "Instance", "RuleId", "UdpRuleId" }),
                ("GroupOrigin", new[] { "Id", "MemberId" })
            })
                if (node[group] is JsonObject origin) { var copy = new JsonObject(); foreach (var field in fields) copy[field] = origin.Text(field); item[group] = copy; }
            nodes.Add(item);
        }
        return new() { ["Id"] = source.Text("Id"), ["Name"] = source.Text("Name"), ["Category"] = category, ["Nodes"] = nodes };
    }
    private static void AddConnections(List<OperationsResource> result, IEnumerable<JsonObject> chains, IEnumerable<JsonObject> tunnels, IEnumerable<JsonObject> clients)
    {
        foreach (var r in tunnels.Where(r => r.Text("Phase") == "Active" || WireGuardTunnels.Pending(r)))
        {
            var c = r["Configuration"]!.AsObject();
            result.Add(new(TunnelKey(c.Text("Id")), c.Text("FirstInstance"), "WireGuard", c.Text("Name"), WireGuardTunnels.Pending(r) ? "Pending" : "Recorded", "Archive", null, null,
                c.Text("FirstInstance") + " ↔ " + c.Text("SecondInstance") + " · " + c.Text("Family"), "WireGuard", c.Text("Id"), []));
        }
        foreach (var r in chains.Where(r => r.Text("Phase") == "Active" || TcpChains.Pending(r)))
        {
            var c = r["Configuration"]!.AsObject(); var refs = new List<string> { NodeKey(c.Text("Landing.SchemeId"), c.Text("Landing.NodeId")) };
            refs.Add(Key(c.Text("FrontInstance"), TcpChains.Transport(c) == "UDP" ? "UdpForward" : "TcpForward", TcpChains.RuleId(c, true)));
            refs.Add(Key(c.Text("RelayInstance"), TcpChains.Transport(c) == "UDP" ? "UdpForward" : "TcpForward", TcpChains.RuleId(c, false)));
            if (TcpChainUnderlay.Selected(c)) refs.AddRange(TcpChainUnderlay.References(c).Select(w => TunnelKey(w.Text("Id"))));
            result.Add(new(ChainKey(c.Text("Id")), c.Text("FrontInstance"), "Chain", c.Text("Name"), TcpChains.Pending(r) ? "Pending" : "Recorded", "Archive", null, null,
                string.Join(" → ", TcpChains.Instances(c)) + " · " + TcpChains.Transport(c) + "；来源、共享依赖和整链验收从线路入口核对。", "Chain", c.Text("Id"), refs.Distinct(StringComparer.Ordinal).ToArray()));
        }
        foreach (var owner in clients)
        {
            var group = owner.Text("Category") == "Group"; var id = owner.Text("Id");
            foreach (var n in (owner["Nodes"] as JsonArray ?? []).OfType<JsonObject>())
            {
                var refs = new List<string>(); string instance = "";
                foreach (var kind in new[] { "InboundOrigin", "ManagedOrigin", "ForwardedOrigin" })
                {
                    if (n[kind] is not JsonObject origin) continue; instance = origin.Text("Instance");
                    if (kind == "InboundOrigin") refs.Add(Key(instance, "Inbound", origin.Text("InboundId")));
                    if (kind == "ManagedOrigin") refs.Add(Key(instance, "Protocol", origin.Text("Role")));
                    if (kind == "ForwardedOrigin") { refs.Add(Key(instance, "TcpForward", origin.Text("RuleId"))); if (origin.Text("UdpRuleId") != "") refs.Add(Key(instance, "UdpForward", origin.Text("UdpRuleId"))); }
                }
                if (n["TcpChainOrigin"] != null) refs.Add(ChainKey(n.Text("TcpChainOrigin.Id")));
                if (n["GroupOrigin"] != null) refs.Add("group:" + n.Text("GroupOrigin.Id") + "#node:" + n.Text("GroupOrigin.MemberId"));
                result.Add(new(group ? "group:" + id + "#node:" + n.Text("Id") : NodeKey(id, n.Text("Id")), instance, group ? "ClientGroup" : "ClientNode", owner.Text("Name") + " / " + n.Text("Name"), "Recorded", "Archive", null, null,
                    group ? "复用组成员；引用变化需先预览同步。" : "已保存方案节点；资源变化后需重新核对来源、校验并导出。", "Clients", id, refs.Distinct(StringComparer.Ordinal).ToArray()));
            }
        }
    }
}
