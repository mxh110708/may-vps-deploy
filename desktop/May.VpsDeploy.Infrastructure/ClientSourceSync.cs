using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public interface IClientSourceFetch
{
    Task<string> FetchAsync(JsonObject source, CancellationToken cancellationToken);
}

public sealed record ClientSourceBatchItem(string Kind, string Id, string Name, string BeforeFingerprint, JsonObject After, IReadOnlyList<ClientSourceChange> Changes, IReadOnlyList<string> Errors);
public sealed record ClientSourceBatch(string SourceId, string Revision, IReadOnlyList<string> SchemeIds, IReadOnlyList<string> GroupIds, IReadOnlyList<ClientSourceBatchItem> Items, int OtherGroupConsumers)
{
    public bool Ready => Items.Count > 0 && Items.All(i => i.Errors.Count == 0);
    public string Fingerprint => ArchiveStore.Fingerprint(new JsonObject { ["Source"] = SourceId, ["Revision"] = Revision,
        ["Items"] = new JsonArray(Items.Select(i => (JsonNode?)new JsonObject { ["Kind"] = i.Kind, ["Id"] = i.Id, ["Before"] = i.BeforeFingerprint, ["After"] = i.After.DeepClone() }).ToArray()) });
}

// Downloads stage encrypted snapshots only. Multi-file application requires an
// explicit review and has its own recoverable local transaction, not a server task.
public sealed class ClientSourceSync(ArchiveStore store, IClientSourceFetch? fetch = null)
{
    private const string Root = "private/client-source-sync/";
    private static string Id(string id) => Regex.IsMatch(id,"^[a-f0-9]{32}$") ? id : throw new OperationException("来源同步身份无效。");
    public static string SourceId(JsonObject source)
    {
        var uri=ClientSubscriptions.Validate(source);
        return ArchiveStore.Fingerprint(new JsonObject { ["Url"]=uri.AbsoluteUri,["Network"]=source.Text("Network","System"),["Proxy"]=source.Text("Network")=="Proxy"?source.Text("Proxy"):"" })[..32];
    }
    private string SourceFile(string id) => store.Paths.Resolve(Root+"sources/"+Id(id)+".dotnet.private.json");
    private string EntityFile(string kind,string id) => kind switch
    {
        "Scheme" => store.Paths.Resolve("private/client-schemes/"+Id(id)+".dotnet.private.json"),
        "Group" => store.Paths.Resolve("private/client-node-groups/"+Id(id)+".dotnet.private.json"),
        _ => throw new OperationException("来源同步对象类型无效。")
    };
    public static FileStream LockFile(string file)
    {
        SafePath.CheckLinks(file+".lock");Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        try{return new FileStream(file+".lock",FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);}
        catch(IOException){throw new OperationException("来源或方案正在使用，请稍后重新预览。");}
    }
    public IReadOnlyList<JsonObject> Sources()
    {
        var root=store.Paths.Resolve(Root+"sources");if(!Directory.Exists(root))return [];
        SafePath.CheckTree(root);return Directory.EnumerateFiles(root,"*.dotnet.private.json").Select(f=>Read(Path.GetFileName(f).Split('.')[0])).ToArray();
    }
    public JsonObject Read(string id)
    {
        var record=store.ReadSecret(SourceFile(id));
        if(record.Number("Schema")!=1||record.Text("Id")!=id||record["Definition"] is not JsonObject definition||SourceId(definition)!=id)throw new OperationException("来源缓存归档身份无效。");
        _=Schedule(record["Schedule"] as JsonObject??new());
        if(record["Content"]!=null&&(record["Content"] is not JsonValue text||!text.TryGetValue<string>(out var content)||Encoding.UTF8.GetByteCount(content)>ClientSubscriptionDownload.MaximumBytes||record.Text("Revision")!=ArchiveStore.Digest(Encoding.UTF8.GetBytes(content))))throw new OperationException("来源缓存摘要或大小无效。");
        return record;
    }
    public JsonObject Register(JsonObject definition)
    {
        var id=SourceId(definition);using var held=LockFile(SourceFile(id));
        if(File.Exists(SourceFile(id)))return Read(id);
        var record=new JsonObject { ["Schema"]=1,["Id"]=id,["Definition"]=definition.DeepClone(),["Schedule"]=new JsonObject { ["Enabled"]=false,["IntervalMinutes"]=60 } };
        store.WriteSecret(SourceFile(id),record);return record;
    }
    public static JsonObject Schedule(JsonObject value)
    {
        if(value.Count!=2||value.Any(p=>p.Key is not ("Enabled" or "IntervalMinutes"))||value["Enabled"] is not JsonValue enabled||!enabled.TryGetValue<bool>(out _)||value["IntervalMinutes"] is not JsonValue minutes||!minutes.TryGetValue<int>(out var interval)||interval is <15 or >1440)throw new OperationException("定时刷新须明确启用状态，间隔为 15–1440 分钟。");
        return value;
    }
    public void Configure(string id, bool enabled, int minutes)
    {
        using var held=LockFile(SourceFile(id));using var indexLock=LockFile(ScheduleFile);var previous=Read(id);var record=previous.DeepClone().AsObject();record["Schedule"]=Schedule(new(){["Enabled"]=enabled,["IntervalMinutes"]=minutes});var index=ScheduleIndex();SetSchedule(index,record);
        store.WriteSecret(SourceFile(id),record);try{ArchiveStore.WriteJson(ScheduleFile,index);}catch{store.WriteSecret(SourceFile(id),previous);throw;}
    }
    private string ScheduleFile=>store.Paths.Resolve(Root+"schedule.json");
    private JsonObject ScheduleIndex()
    {
        if(File.Exists(ScheduleFile)&&new FileInfo(ScheduleFile).Length>65536)throw new OperationException("来源定时索引大小无效。");
        JsonObject index;try{index=File.Exists(ScheduleFile)?ArchiveStore.ReadJson(ScheduleFile):new JsonObject();}catch(Exception error)when(error is System.Text.Json.JsonException or InvalidOperationException){throw new OperationException("来源定时索引格式无效。");}
        if(index.Count>100||index.Any(p=>!Regex.IsMatch(p.Key,"^[a-f0-9]{32}$")||p.Value is not JsonObject))throw new OperationException("来源定时索引格式无效。");
        foreach(var item in index.Select(p=>p.Value!.AsObject()))_=Schedule(new(){["Enabled"]=item["Enabled"]?.DeepClone(),["IntervalMinutes"]=item["IntervalMinutes"]?.DeepClone()});
        return index;
    }
    public bool HasSchedules()=>ScheduleIndex().Any(p=>p.Value.Flag("Enabled"));
    private void UpdateSchedule(JsonObject record)
    {
        using var held=LockFile(ScheduleFile);var index=ScheduleIndex();SetSchedule(index,record);ArchiveStore.WriteJson(ScheduleFile,index);
    }
    private static void SetSchedule(JsonObject index,JsonObject record)
    {
        var id=record.Text("Id");
        if(record.Flag("Schedule.Enabled")){if(index.Count>=100&&!index.ContainsKey(id))throw new OperationException("最多同时启用 100 个定时来源。");var entry=record["Schedule"]!.DeepClone().AsObject();entry["LastAttemptAt"]=record["LastAttemptAt"]?.DeepClone();index[id]=entry;}else index.Remove(id);
    }
    public async Task<bool> FetchAsync(string id,CancellationToken cancellationToken,DateTimeOffset? now=null)
    {
        if(fetch==null)throw new OperationException("来源下载器不可用。");
        using var held=LockFile(SourceFile(id));var record=Read(id);var at=now??DateTimeOffset.UtcNow;
        try
        {
            var content=await fetch.FetchAsync(record["Definition"]!.AsObject(),cancellationToken);cancellationToken.ThrowIfCancellationRequested();
            if(Encoding.UTF8.GetByteCount(content)>ClientSubscriptionDownload.MaximumBytes)throw new OperationException("来源响应超过缓存上限。");
            // Parse before replacing the last good cache. A successful HTTP error
            // page, malformed list or empty result never becomes a valid revision.
            var probe=ClientSchemes.New(store.Paths);var definition=record["Definition"]!.DeepClone().AsObject();
            probe["Layout"]!["region_groups"]=new JsonArray(definition.Text("Region"));
            var parsed=ClientSubscriptions.Preview(probe,definition,content);if(!parsed.Ready)throw new OperationException("来源内容无法完整解析，保留上次有效缓存。");
            var revision=ArchiveStore.Digest(Encoding.UTF8.GetBytes(content));var changed=record.Text("Revision")!=revision;
            record["Content"]=content;record["Revision"]=revision;record["LastFetchedAt"]=at;record["LastAttemptAt"]=at;record["LastStatus"]=changed?"Changed":"Unchanged";record.Remove("LastError");store.WriteSecret(SourceFile(id),record);UpdateSchedule(record);return changed;
        }
        catch(OperationCanceledException)when(cancellationToken.IsCancellationRequested){throw;}
        catch(Exception error)when(error is OperationException or IOException)
        {
            record["LastAttemptAt"]=at;record["LastStatus"]="Failed";record["LastError"]="本次获取失败，上次缓存与所有方案保持原样。";store.WriteSecret(SourceFile(id),record);UpdateSchedule(record);throw new OperationException(record.Text("LastError"));
        }
    }
    public async Task<int> FetchDueAsync(DateTimeOffset now,CancellationToken cancellationToken)
    {
        if(Pending().Count>0)return 0;
        var changed=0;var due=ScheduleIndex().Where(p=>p.Value.Flag("Enabled")&&(!DateTimeOffset.TryParse(p.Value.Text("LastAttemptAt"),out var last)||now-last>=TimeSpan.FromMinutes(p.Value.Number("IntervalMinutes")))).Take(4).ToArray();if(due.Length==0)return 0;
        var used=Entities("Scheme").Concat(Entities("Group")).SelectMany(e=>(e["NodeSources"] as JsonArray??[]).OfType<JsonObject>()).Select(SourceId).ToHashSet(StringComparer.Ordinal);
        foreach(var item in due)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if(!used.Contains(item.Key)){Configure(item.Key,false,item.Value.Number("IntervalMinutes"));continue;}
            try{var record=Read(item.Key);if(record.Flag("Schedule.Enabled")&&(!DateTimeOffset.TryParse(record.Text("LastAttemptAt"),out var last)||now-last>=TimeSpan.FromMinutes(record.Number("Schedule.IntervalMinutes")))&&await FetchAsync(item.Key,cancellationToken,now))changed++;}catch(OperationException){}
        }
        return changed;
    }
    private IReadOnlyList<JsonObject> Entities(string kind)
    {
        var root=store.Paths.Resolve(kind=="Scheme"?"private/client-schemes":"private/client-node-groups");if(!Directory.Exists(root))return [];
        SafePath.CheckTree(root);return Directory.EnumerateFiles(root,"*.dotnet.private.json").Select(store.ReadSecret).ToArray();
    }
    public void Discover()
    {
        foreach(var entity in Entities("Scheme").Concat(Entities("Group")))foreach(var source in (entity["NodeSources"] as JsonArray??[]).OfType<JsonObject>())Register(source);
    }
    public IReadOnlyList<(string Kind,string Id,string Name)> Consumers(string id)
    {
        _=Id(id);return new[]{"Scheme","Group"}.SelectMany(kind=>Entities(kind).Where(e=>(e["NodeSources"] as JsonArray??[]).OfType<JsonObject>().Any(s=>SourceId(s)==id)).Select(e=>(kind,e.Text("Id"),e.Text("Name")))).ToArray();
    }
    public ClientSourceBatch Preview(string id,IReadOnlyList<string> schemes,IReadOnlyList<string> groups)
    {
        if(schemes.Count+groups.Count is <1 or >100||schemes.Distinct().Count()!=schemes.Count||groups.Distinct().Count()!=groups.Count)throw new OperationException("请选择 1–100 个不重复的同步对象。");
        var cache=Read(id);if(cache.Text("Revision")==""||cache["Content"]==null)throw new OperationException("请先获取有效来源缓存。");
        var content=cache.Text("Content");var fetchedAt=cache.Text("LastFetchedAt");var items=new List<ClientSourceBatchItem>();var proposedGroups=new Dictionary<string,JsonObject>();
        foreach(var groupId in groups)
        {
            var group=store.ReadSecret(EntityFile("Group",groupId));ClientNodeGroups.Validate(group);var draft=ClientSchemes.New(store.Paths);draft["Id"]=group.Text("Id");draft["Nodes"]=group["Nodes"]!.DeepClone();draft["NodeSources"]=group["NodeSources"]?.DeepClone()??new JsonArray();
            draft["Layout"]!["region_groups"]=new JsonArray(group["Nodes"]!.AsArray().Select(n=>n!.Text(n.Text("kind")=="entry"?"region_group":"transit_group")).Concat((group["NodeSources"] as JsonArray??[]).Select(s=>s!.Text("Region"))).Distinct().Select(v=>(JsonNode?)JsonValue.Create(v)).ToArray());
            var preview=PreviewSource(draft,id,content,fetchedAt);var errors=preview.Errors.ToList();if(preview.Ready)ClientSubscriptions.Apply(draft,preview);
            var after=group.DeepClone().AsObject();after["Nodes"]=draft["Nodes"]!.DeepClone();
            // Fetch timestamps alone must not create a new reusable-group revision.
            if(!JsonNode.DeepEquals(after["Nodes"],group["Nodes"]))after["NodeSources"]=draft["NodeSources"]!.DeepClone();
            try{ClientNodeGroups.Validate(after);}catch(OperationException e){errors.Add(e.Message);}
            proposedGroups[groupId]=after;items.Add(new("Group",groupId,group.Text("Name"),ArchiveStore.Fingerprint(group),after,preview.Changes,errors));
        }
        foreach(var schemeId in schemes)
        {
            var original=store.ReadSecret(EntityFile("Scheme",schemeId));var after=original.DeepClone().AsObject();var changes=new List<ClientSourceChange>();var errors=new List<string>();var touched=false;
            foreach(var group in proposedGroups.Values.Where(g=>(after["GroupReferences"] as JsonArray??[]).Any(r=>r!.Text("Id")==g.Text("Id"))))
            {
                touched=true;var preview=ClientNodeGroups.Preview(after,group);changes.AddRange(preview.Changes);errors.AddRange(preview.Errors);if(preview.Ready)
                {
                    ClientNodeGroups.Apply(after,group,preview);
                    foreach(var node in after["Nodes"]!.AsArray().OfType<JsonObject>().Where(n=>n.Text("GroupOrigin.Id")==group.Text("Id")))
                        if(!original["Nodes"]!.AsArray().Any(n=>n!.Text("GroupOrigin.Id")==group.Text("Id")&&n.Text("GroupOrigin.MemberId")==node.Text("GroupOrigin.MemberId")))node["Id"]=ArchiveStore.Digest(Encoding.UTF8.GetBytes("GroupSync:"+schemeId+":"+group.Text("Id")+":"+node.Text("GroupOrigin.MemberId")))[..32];
                }
            }
            if((after["NodeSources"] as JsonArray??[]).OfType<JsonObject>().Any(s=>SourceId(s)==id))
            {
                touched=true;var preview=PreviewSource(after,id,content,fetchedAt);changes.AddRange(preview.Changes);errors.AddRange(preview.Errors);if(preview.Ready)ClientSubscriptions.Apply(after,preview);
            }
            if(!touched)errors.Add("该方案没有所选来源或所选节点组引用。");
            if((after["Nodes"] as JsonArray??[]).OfType<JsonObject>().Any(n=>n.Text("Source.Kind")=="Subscription"&&n["GroupOrigin"]!=null&&(after["NodeSources"] as JsonArray??[]).OfType<JsonObject>().Any(s=>s.Text("Id")==n.Text("Source.Id")&&SourceId(s)==id)))errors.Add("节点同时由订阅和节点组管理，请先解除一种关联。");
            items.Add(new("Scheme",schemeId,original.Text("Name"),ArchiveStore.Fingerprint(original),after,changes,errors));
        }
        var others=Entities("Scheme").Count(s=>!schemes.Contains(s.Text("Id"))&&(s["GroupReferences"] as JsonArray??[]).Any(r=>groups.Contains(r!.Text("Id"))));
        return new(id,cache.Text("Revision"),schemes.ToArray(),groups.ToArray(),items,others);
    }
    private static ClientSourcePreview PreviewSource(JsonObject scheme,string id,string content,string fetchedAt)
    {
        var definitions=(scheme["NodeSources"] as JsonArray??[]).OfType<JsonObject>().Where(s=>SourceId(s)==id).ToArray();
        if(definitions.Length!=1)throw new OperationException("同步对象的来源定义缺失或重复，请先核对来源。");
        var preview=ClientSubscriptions.Preview(scheme,definitions[0],content);preview.Source["LastFetchedAt"]=fetchedAt;
        var ids=scheme["Nodes"]!.AsArray().Select(n=>n!.Text("Id")).ToHashSet(StringComparer.Ordinal);
        foreach(var node in preview.Nodes.OfType<JsonObject>().Where(n=>n.Text("Source.Id")==definitions[0].Text("Id")&&!ids.Contains(n.Text("Id"))))
        {
            node["Id"]=ArchiveStore.Digest(Encoding.UTF8.GetBytes("SubscriptionSync:"+scheme.Text("Id")+":"+definitions[0].Text("Id")+":"+node.Text("Source.Fingerprint")+":"+node.Text("Source.OriginalName")))[..32];node["Source"]!["ImportedAt"]=fetchedAt;
        }
        return preview;
    }
    public IReadOnlyList<string> Pending()
    {
        var root=store.Paths.Resolve(Root+"transactions");if(!Directory.Exists(root))return [];
        SafePath.CheckTree(root);var pending=new List<string>();
        foreach(var file in Directory.EnumerateFiles(root,"*.dotnet.private.json"))
        {
            var journal=store.ReadSecret(file);var id=Path.GetFileName(file).Split('.')[0];
            if(journal.Number("Schema")!=1||journal.Text("Id")!=Id(id)||journal.Text("Phase") is not ("Applying" or "NeedsRecovery" or "Completed" or "RolledBack"))throw new OperationException("来源同步事务格式或状态不受支持，保留材料，请先核对。");
            if(journal.Text("Phase") is not ("Completed" or "RolledBack")){ValidateJournal(journal,id);pending.Add(id);}
        }
        return pending;
    }
    public void GuardPending(string kind,string id)
    {
        foreach(var pending in Pending())
        {
            var journal=store.ReadSecret(store.Paths.Resolve(Root+"transactions/"+Id(pending)+".dotnet.private.json"));ValidateJournal(journal,pending);
            if(journal["Items"]!.AsArray().Any(i=>i!.Text("Kind")==kind&&i.Text("Id")==id))throw new OperationException("此对象有未完成的来源批量同步，请先在来源中心恢复。",true,"SourceSyncNeedsRecovery");
        }
    }
    public void Apply(ClientSourceBatch reviewed,CancellationToken cancellationToken=default)
    {
        using var global=LockFile(store.Paths.Resolve(Root+"batch"));if(Pending().Count>0)throw new OperationException("存在未完成的本地批量同步，请先恢复。");
        var locks=new List<FileStream>();
        try
        {
            locks.Add(LockFile(SourceFile(reviewed.SourceId)));
            foreach(var entityFile in reviewed.Items.Select(i=>EntityFile(i.Kind,i.Id)).Order(StringComparer.Ordinal))locks.Add(LockFile(entityFile));
            var current=Preview(reviewed.SourceId,reviewed.SchemeIds,reviewed.GroupIds);
            if(!reviewed.Ready||!current.Ready||current.Revision!=reviewed.Revision||current.Fingerprint!=reviewed.Fingerprint)throw new OperationException("批量预览有冲突、来源或方案已变化，请重新预览。");
            cancellationToken.ThrowIfCancellationRequested();
            var id=Guid.NewGuid().ToString("N");var file=store.Paths.Resolve(Root+"transactions/"+id+".dotnet.private.json");
            var journal=new JsonObject { ["Schema"]=1,["Id"]=id,["Phase"]="Applying",["Items"]=new JsonArray(current.Items.Select(i=>(JsonNode?)new JsonObject{["Kind"]=i.Kind,["Id"]=i.Id,["Before"]=store.ReadSecret(EntityFile(i.Kind,i.Id)),["After"]=i.After.DeepClone()}).ToArray()) };
            store.WriteSecret(file,journal);
            try
            {
                foreach(var item in current.Items){cancellationToken.ThrowIfCancellationRequested();store.WriteSecret(EntityFile(item.Kind,item.Id),item.After);}
                var completed=journal.DeepClone().AsObject();completed["Phase"]="Completed";Compact(completed);store.WriteSecret(file,completed);
            }
            catch
            {
                Restore(journal,file);throw;
            }
        }
        finally{foreach(var held in locks.AsEnumerable().Reverse())held.Dispose();}
    }
    public void Recover(string id)
    {
        using var global=LockFile(store.Paths.Resolve(Root+"batch"));var file=store.Paths.Resolve(Root+"transactions/"+Id(id)+".dotnet.private.json");var journal=store.ReadSecret(file);
        if(journal.Number("Schema")==1&&journal.Text("Id")==id&&journal.Text("Phase") is "Completed" or "RolledBack")throw new OperationException("此批量同步已经结束。");ValidateJournal(journal,id);
        var locks=new List<FileStream>();try{foreach(var item in journal["Items"]!.AsArray().OfType<JsonObject>().OrderBy(i=>EntityFile(i.Text("Kind"),i.Text("Id")),StringComparer.Ordinal))locks.Add(LockFile(EntityFile(item.Text("Kind"),item.Text("Id"))));Restore(journal,file);}finally{foreach(var held in locks.AsEnumerable().Reverse())held.Dispose();}
    }
    private void ValidateJournal(JsonObject journal,string id)
    {
        if(journal.Number("Schema")!=1||journal.Text("Id")!=id||journal.Text("Phase") is not ("Applying" or "NeedsRecovery" or "Completed" or "RolledBack")||journal["Items"] is not JsonArray items||items.Count is <1 or >100||items.Any(i=>i is not JsonObject||i["Before"] is not JsonObject||i["After"] is not JsonObject)||items.Select(i=>i!.Text("Kind")+":"+i.Text("Id")).Distinct().Count()!=items.Count)throw new OperationException("批量同步事务格式不受支持，保留材料，不执行恢复。");
        foreach(var item in items.OfType<JsonObject>()){_=EntityFile(item.Text("Kind"),item.Text("Id"));if(item.Text("Id")!=item["Before"]!.Text("Id")||item.Text("Id")!=item["After"]!.Text("Id"))throw new OperationException("批量同步归属不一致。");}
    }
    private void Restore(JsonObject journal,string file)
    {
        ValidateJournal(journal,journal.Text("Id"));var items=journal["Items"]!.AsArray().OfType<JsonObject>().ToArray();
        try
        {
            // Check every current identity before restoring any file.
            foreach(var item in items){var value=store.ReadSecret(EntityFile(item.Text("Kind"),item.Text("Id")));if(!JsonNode.DeepEquals(value,item["Before"])&&!JsonNode.DeepEquals(value,item["After"]))throw new OperationException("同步对象出现其他修改，不覆盖新数据；保留待恢复事务。");}
            foreach(var item in items.Reverse())store.WriteSecret(EntityFile(item.Text("Kind"),item.Text("Id")),item["Before"]!.AsObject());
            var completed=journal.DeepClone().AsObject();completed["Phase"]="RolledBack";Compact(completed);store.WriteSecret(file,completed);
        }
        catch{journal["Phase"]="NeedsRecovery";store.WriteSecret(file,journal);throw new OperationException("本地批量同步仍待恢复；方案或节点组归属变化，未自动重放应用。",true,"SourceSyncNeedsRecovery");}
    }
    private static void Compact(JsonObject journal)
    {
        journal["Summary"]=new JsonArray(journal["Items"]!.AsArray().OfType<JsonObject>().Select(i=>(JsonNode?)new JsonObject{["Kind"]=i.Text("Kind"),["Id"]=i.Text("Id"),["Before"]=ArchiveStore.Fingerprint(i["Before"]!),["After"]=ArchiveStore.Fingerprint(i["After"]!)}).ToArray());journal.Remove("Items");
    }
}
