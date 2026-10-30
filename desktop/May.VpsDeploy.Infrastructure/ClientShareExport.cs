using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class ClientShareExport(ArchiveStore store)
{
    public string Generate(JsonObject scheme, ClientSharePreview preview, IReadOnlyList<string> selected, string format)
    {
        new ClientNodeGroupStore(store).Verify(scheme);
        var text = ClientShareLinks.Generate(scheme, preview, selected, format);
        var chosen = selected.ToHashSet(StringComparer.Ordinal);
        ManagedNodeSources.Verify(store, new JsonArray(scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => chosen.Contains(n.Text("Id")) && n["ManagedOrigin"] != null).Select(n => n["ManagedOrigin"]!.DeepClone()).ToArray()));
        ForwardedNodeSources.VerifyNodes(store, scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => chosen.Contains(n.Text("Id"))));
        TcpChains.VerifyOrigins(store, new JsonArray(scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => chosen.Contains(n.Text("Id")) && n["TcpChainOrigin"] != null).Select(n => n["TcpChainOrigin"]!.DeepClone()).ToArray()));
        InboundSources.VerifyOrigins(store, new JsonArray(scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => chosen.Contains(n.Text("Id")) && n["InboundOrigin"] != null).Select(n => n["InboundOrigin"]!.DeepClone()).ToArray()));
        return text;
    }
    public void SaveNew(JsonObject scheme, ClientSharePreview preview, IReadOnlyList<string> selected, string format, string target)
    {
        ClientSchemes.ValidatePublishPath(store.Paths, target); SafePath.CheckLinks(target); target = Path.GetFullPath(target);
        if (Path.GetExtension(target) != ".txt" || File.Exists(target) || Directory.Exists(target)) throw new OperationException("请使用新的 .txt 文件；分享导出不覆盖已有文件。");
        var parent = Path.GetDirectoryName(target)!; SafePath.CheckLinks(parent); if (!Directory.Exists(parent)) throw new OperationException("请选择已存在的导出文件夹。");
        var text = Generate(scheme, preview, selected, format); var temporary = Path.Combine(parent, ".may-share-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { var bytes = new UTF8Encoding(false, true).GetBytes(text); try { stream.Write(bytes); stream.Flush(true); } finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); } }
            // Recheck source identities immediately before the atomic, non-overwriting move.
            Generate(scheme, preview, selected, format); ClientSchemes.ValidatePublishPath(store.Paths, target); SafePath.CheckLinks(target); File.Move(temporary, target, false);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
