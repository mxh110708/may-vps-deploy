using System.Text.Json;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ServerOutboundSourceStatus(string Code, string Message, bool Matches);

public static partial class ServerOutboundRouting
{
    public static string SourcesSummary(ArchiveStore store, JsonObject metadata) => "默认落地：" + SourceStatus(store, metadata).Message + string.Concat(MetadataHops(metadata).OfType<JsonObject>().Select(h => "\n" + h.Text("Name") + "：" + SourceStatus(store, h).Message));
    // On-demand local inspection only; never follows subscription URLs or changes the server.
    public static ServerOutboundSourceStatus SourceStatus(ArchiveStore store, JsonObject metadata)
    {
        if (metadata.Text("SchemeId") == "" || metadata.Text("NodeId") == "") return new("Unlinked", "此配置没有来源引用；服务器继续使用已审阅快照。", false);
        try
        {
            var path = SchemeFile(store.Paths, metadata.Text("SchemeId"));
            if (!File.Exists(path)) return new("Missing", "来源方案已删除；服务器仍使用原快照，可重新选择下一跳或移除链路。", false);
            var scheme = store.ReadSecret(path);
            try
            {
                var nodes = (scheme["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(n => n.Text("Id") == metadata.Text("NodeId")).ToArray() ?? [];
                if (nodes.Length == 0) return new("Missing", "来源节点已删除；服务器仍使用原快照。", false);
                if (nodes.Length != 1) return new("Ambiguous", "来源身份有歧义，请在配置设计中核对。", false);
                if (ArchiveStore.Fingerprint(nodes[0]) != metadata.Text("NodeFingerprint")) return new("Changed", "来源名称、参数或出口标注已变化；服务器未同步，需重新审阅更新。", false);
                if (nodes[0]["ManagedOrigin"] is JsonObject origin)
                {
                    try { ManagedNodeSources.Verify(store, new JsonArray(origin.DeepClone())); }
                    catch (OperationException) { return new("ManagedChanged", "来源受管实例的连接、凭据或状态已变化；先重新提取来源，再审阅更新。", false); }
                }
                try { InboundSources.VerifyNodes(store, nodes); }
                catch (OperationException) { return new("ManagedChanged", "来源独立入站、用户、证书、出站或验收已变化；先更新来源，再重新审阅。", false); }
                return new("Matches", "来源与已审阅快照一致。", true);
            }
            finally { scheme.Clear(); }
        }
        catch (Exception error) when (error is OperationException or IOException or UnauthorizedAccessException or JsonException)
        { return new("Unreadable", "来源无法安全读取，请核对本地方案；服务器配置未自动修改。", false); }
    }
}
