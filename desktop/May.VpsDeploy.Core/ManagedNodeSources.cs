using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

// A node depends on its connection, not on health timestamps or encrypted bytes.
public static class ManagedNodeSources
{
    public static string Fingerprint(ClientProfiles.NodePair node)
    {
        var clash = node.Clash.DeepClone().AsObject(); clash.Remove("name");
        var sing = node.SingBox.DeepClone().AsObject(); sing.Remove("tag");
        var identity = new JsonObject { ["Clash"] = clash, ["SingBox"] = sing };
        if (node.ServerRouteFingerprint != "") identity["ServerRoute"] = node.ServerRouteFingerprint;
        return ArchiveStore.Fingerprint(identity);
    }
    public static JsonObject Origin(string instance, ClientProfiles.NodePair node) => new()
    {
        ["Instance"] = instance, ["Role"] = node.Role, ["Family"] = node.Family,
        ["EgressFamily"] = node.EgressFamily, ["Backup"] = node.IsBackup, ["Fingerprint"] = Fingerprint(node)
    };
    public static ClientProfiles.NodePair? Resolve(JsonObject origin, JsonObject plan, JsonObject secrets) => ClientProfiles.Nodes(plan, secrets).SingleOrDefault(n => n.Role == origin.Text("Role") && n.Family == origin.Text("Family") && n.EgressFamily == origin.Text("EgressFamily", "IPv4") && n.IsBackup == origin.Flag("Backup"));
    public static void Verify(ArchiveStore store, JsonArray origins)
    {
        foreach (var origin in origins.OfType<JsonObject>())
        {
            var directory = store.Paths.Instance(origin.Text("Instance"));
            var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"));
            var lifecycle = InstanceLifecycle.Read(store, origin.Text("Instance"), plan);
            if (!lifecycle.Managed || lifecycle.NeedsRecovery) throw new OperationException("节点来源正在部署或恢复，请先完成该实例的任务。");
            var secrets = store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"));
            try
            {
                var node = Resolve(origin, plan, secrets);
                if (node == null || Fingerprint(node) != origin.Text("Fingerprint")) throw new OperationException("受管节点的连接或凭据已变化，请在“添加受管节点”中重新选择此节点更新来源。");
            }
            finally { secrets.Clear(); }
        }
    }
}
