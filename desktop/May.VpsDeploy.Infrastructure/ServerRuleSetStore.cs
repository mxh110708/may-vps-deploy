using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed record ServerRuleSetPreview(string BeforeFingerprint,JsonObject Snapshot,IReadOnlyList<ClientSourceChange> Changes);

public sealed class ServerRuleSetStore(ArchiveStore store,IClientSourceFetch? fetch=null)
{
    private string FileName(string id)=>store.Paths.Resolve("private/server-rule-sets/"+ServerRuleSets.Id(id)+".dotnet.private.json");
    public JsonObject Read(string id)
    {
        var record=store.ReadSecret(FileName(id));
        if(record.Number("Schema")!=1||record.Text("Id")!=id||record["Versions"] is not JsonArray versions||versions.Count is <1 or >32||versions.Any(v=>v is not JsonObject))throw new OperationException("规则库归档格式无效。");
        var revisions=new HashSet<string>(StringComparer.Ordinal);var digests=new HashSet<string>(StringComparer.Ordinal);
        foreach(var item in versions.OfType<JsonObject>())
        {
            var set=ServerRuleSets.Normalize(item["Snapshot"]);if(set.Text("Id")!=id||item.Text("Digest")!=ServerRuleSets.Digest(set)||!revisions.Add(set.Text("Revision"))||!digests.Add(item.Text("Digest")))throw new OperationException("规则库版本身份或摘要不同。");
        }
        if(!digests.Contains(record.Text("Current")))throw new OperationException("当前规则集版本缺失。");
        if(record["Source"] is JsonObject source)ClientSubscriptions.Validate(source);
        return record;
    }
    public IReadOnlyList<JsonObject> List()
    {
        var root=store.Paths.Resolve("private/server-rule-sets");if(!Directory.Exists(root))return [];
        SafePath.CheckTree(root);return Directory.EnumerateFiles(root,"*.dotnet.private.json").Select(f=>Read(Path.GetFileName(f).Split('.')[0])).ToArray();
    }
    public static JsonObject Current(JsonObject record)=>record["Versions"]!.AsArray().Single(v=>v!.Text("Digest")==record.Text("Current"))!["Snapshot"]!.DeepClone().AsObject();
    public void EnsureBuiltins()
    {
        foreach(var set in ServerRuleSets.Builtins(store.Paths))
        {
            if(File.Exists(FileName(set.Text("Id"))))continue;
            Apply(Preview(set));
        }
    }
    public ServerRuleSetPreview Preview(JsonObject set)
    {
        var snapshot=ServerRuleSets.Normalize(set);var file=FileName(snapshot.Text("Id"));var previous=File.Exists(file)?Read(snapshot.Text("Id")):null;
        var same=(previous?["Versions"] as JsonArray??[]).FirstOrDefault(v=>v!.Text("Snapshot.Revision")==snapshot.Text("Revision"));
        if(same!=null&&same.Text("Digest")!=ServerRuleSets.Digest(snapshot))throw new OperationException("同一规则集版本不能对应两份内容；请发布新版本号，不能覆盖旧版本。");
        if(same==null&&(previous?["Versions"] as JsonArray??[]).Count>=32)throw new OperationException("规则库已保留 32 个版本，请先单独归档后使用新规则集身份。");
        var old=previous==null?[]:Current(previous)["Rules"]!.AsArray().OfType<JsonObject>().Select(r=>r.Text("Kind")+":"+r.Text("Value")).ToHashSet(StringComparer.Ordinal);
        var current=snapshot["Rules"]!.AsArray().OfType<JsonObject>().Select(r=>r.Text("Kind")+":"+r.Text("Value")).ToHashSet(StringComparer.Ordinal);
        var changes=current.Except(old).Select(v=>new ClientSourceChange("Added",v,"新增匹配项")).Concat(old.Except(current).Select(v=>new ClientSourceChange("Removed",v,"删除匹配项"))).ToArray();
        return new(previous==null?"Absent":ArchiveStore.Fingerprint(previous),snapshot,changes);
    }
    public static JsonObject Parse(string content)
    {
        if(Encoding.UTF8.GetByteCount(content)>524288)throw new OperationException("规则集 JSON 超过 512 KiB。");
        try{return ServerRuleSets.Normalize(JsonNode.Parse(content));}catch(Exception error)when(error is System.Text.Json.JsonException or ArgumentException or InvalidOperationException){throw new OperationException("规则集不是有效 JSON，原规则库保留。");}
    }
    public void Apply(ServerRuleSetPreview reviewed)
    {
        var snapshot=ServerRuleSets.Normalize(reviewed.Snapshot);var file=FileName(snapshot.Text("Id"));using var held=ClientSourceSync.LockFile(file);
        var current=Preview(snapshot);if(current.BeforeFingerprint!=reviewed.BeforeFingerprint||ServerRuleSets.Digest(current.Snapshot)!=ServerRuleSets.Digest(reviewed.Snapshot))throw new OperationException("规则库在审阅后变化，请重新预览。");
        var record=File.Exists(file)?Read(snapshot.Text("Id")):new JsonObject{["Schema"]=1,["Id"]=snapshot.Text("Id"),["Versions"]=new JsonArray()};var digest=ServerRuleSets.Digest(snapshot);
        if(!record["Versions"]!.AsArray().Any(v=>v!.Text("Digest")==digest))record["Versions"]!.AsArray().Add(new JsonObject{["Digest"]=digest,["Snapshot"]=snapshot.DeepClone(),["AddedAt"]=DateTimeOffset.UtcNow});
        record["Current"]=digest;store.WriteSecret(file,record);
    }
    public void SelectVersion(string id,string digest,string expectedFingerprint)
    {
        var file=FileName(id);using var held=ClientSourceSync.LockFile(file);var record=Read(id);
        if(ArchiveStore.Fingerprint(record)!=expectedFingerprint||!record["Versions"]!.AsArray().Any(v=>v!.Text("Digest")==digest))throw new OperationException("规则库或选中的历史版本已变化。");
        record["Current"]=digest;store.WriteSecret(file,record);
    }
    public void ConfigureSource(string id,JsonObject source,string expectedFingerprint)
    {
        ClientSubscriptions.Validate(source);var file=FileName(id);using var held=ClientSourceSync.LockFile(file);var record=Read(id);
        if(ArchiveStore.Fingerprint(record)!=expectedFingerprint)throw new OperationException("规则库已变化，请重新配置来源。");record["Source"]=source.DeepClone();store.WriteSecret(file,record);
    }
    public async Task<ServerRuleSetPreview> FetchAsync(string id,CancellationToken cancellationToken)
    {
        if(fetch==null)throw new OperationException("规则集下载器不可用。");var record=Read(id);var definition=record["Source"] as JsonObject??throw new OperationException("请先配置这个规则集的 HTTPS 来源。");
        var fingerprint=ArchiveStore.Fingerprint(record);var content=await fetch.FetchAsync(definition,cancellationToken);cancellationToken.ThrowIfCancellationRequested();var snapshot=Parse(content);
        if(snapshot.Text("Id")!=id||ArchiveStore.Fingerprint(Read(id))!=fingerprint)throw new OperationException("规则集来源身份不同或获取期间归档变化，原库保留。");return Preview(snapshot);
    }
}
