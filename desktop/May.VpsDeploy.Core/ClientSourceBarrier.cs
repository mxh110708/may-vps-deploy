using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

// All consumers, including server-side operations, refuse a source involved in
// an unresolved controller-side batch. Reading for recovery remains possible.
public static class ClientSourceBarrier
{
    public static void RequireAvailable(ArchiveStore store,string kind,string id)
        =>Check(store,kind,id);
    public static void RequireNoPending(ArchiveStore store)=>Check(store,null,null);
    private static void Check(ArchiveStore store,string? kind,string? id)
    {
        var root=store.Paths.Resolve("private/client-source-sync/transactions");if(!Directory.Exists(root))return;
        SafePath.CheckTree(root);
        foreach(var file in Directory.EnumerateFiles(root,"*.dotnet.private.json"))
        {
            var journal=store.ReadSecret(file);
            if(journal.Number("Schema")!=1||!Guid.TryParseExact(journal.Text("Id"),"N",out _)||Path.GetFileName(file)!=journal.Text("Id")+".dotnet.private.json")throw new OperationException("来源同步事务格式不受支持，请先核对。");
            if(journal.Text("Phase") is "Completed" or "RolledBack")continue;
            if(journal.Text("Phase") is not ("Applying" or "NeedsRecovery")||journal["Items"] is not JsonArray items||items.Count is <1 or >100||items.Any(i=>i is not JsonObject||i.Text("Kind") is not ("Scheme" or "Group")||!Guid.TryParseExact(i.Text("Id"),"N",out _)||i["Before"] is not JsonObject||i["After"] is not JsonObject||i.Text("Id")!=i["Before"]!.Text("Id")||i.Text("Id")!=i["After"]!.Text("Id"))||items.Select(i=>i!.Text("Kind")+":"+i.Text("Id")).Distinct().Count()!=items.Count)throw new OperationException("来源同步事务状态不明，请先恢复。");
            if(kind==null||items.Any(i=>i!.Text("Kind")==kind&&i.Text("Id")==id))throw new OperationException("来源正在批量同步或尚待恢复，请先恢复后再使用来源或迁移归档。",true,"SourceSyncNeedsRecovery");
        }
    }
}
