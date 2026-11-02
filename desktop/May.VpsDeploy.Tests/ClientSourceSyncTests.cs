using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunSourceSyncTests()
    {
        await SourceSyncExperience();
        await SourceSyncDownloadExperience();
        Console.WriteLine($"PASS: {assertions} scheduled source cache, multi-scheme/group preview, conflicts and local recovery assertions; no public subscriptions.");
    }
    private async Task SourceSyncDownloadExperience()
    {
        using var f=new Fixture(repository);await using var server=new SubscriptionServer();var source=ClientSubscriptions.New("US-West-LA Entry");source["Network"]="Direct";source["Url"]=server.Address+"/redirect";var service=new ClientSourceSync(f.Store,new ClientSubscriptionDownload());var id=service.Register(source).Text("Id");
        Check(await service.FetchAsync(id,default)&&service.Read(id).Text("Content")==server.Body&&server.Requests.Count==2,"real source cache did not use bounded downloader");var revision=service.Read(id).Text("Revision");server.Body="<html>error</html>";await RefusesAsync(()=>service.FetchAsync(id,default),"HTTP success with invalid content replaced cache");Check(service.Read(id).Text("Revision")==revision,"failed real download parse erased good revision");
        server.Body="anytls://synthetic-proxy-source@entry.example.test:443?sni=entry.example.test#Proxy";source["Network"]="Proxy";source["Proxy"]=server.Address;source["Url"]="http://127.0.0.1:9/proxy-proof";id=service.Register(source).Text("Id");Check(await service.FetchAsync(id,default)&&server.Requests.Last().StartsWith("GET http://127.0.0.1:9/proxy-proof ",StringComparison.Ordinal),"source center ignored its selected proxy");
    }
    private async Task SourceSyncExperience()
    {
        using var f=new Fixture(repository);var assets=new ValidationAssets(new AppPaths(repository),"windows-amd64");var workbench=new ClientWorkbench(f.Store,new ExternalToolRunner(),assets,"python");
        var definition=ClientSubscriptions.New("US-West-LA Entry");definition["Url"]="https://subscription.example.test/list?token=synthetic-source-only";definition["Network"]="Direct";
        const string a="anytls://synthetic-a@a.example.test:443?sni=a.example.test#A";
        const string b="anytls://synthetic-b@b.example.test:443?sni=b.example.test#B";
        const string c="anytls://synthetic-c@c.example.test:443?sni=c.example.test#C";
        var first=ClientSchemes.New(f.Paths);first["Name"]="First";ClientSubscriptions.Apply(first,ClientSubscriptions.Preview(first,definition,a+"\n"+b));first["Layout"]!["business_groups"]![0]!["default"]="A";workbench.Save(first);
        var second=ClientSchemes.New(f.Paths);second["Name"]="Second";ClientSubscriptions.Apply(second,ClientSubscriptions.Preview(second,definition,a+"\n"+b));workbench.Save(second);
        var group=ClientNodeGroups.Capture(first,"Shared source group",first["Nodes"]!.AsArray().Select(n=>n!.Text("Id")).ToArray());var groups=new ClientNodeGroupStore(f.Store);groups.Save(group);
        var third=ClientSchemes.New(f.Paths);third["Name"]="Group consumer";ClientNodeGroups.Apply(third,group,ClientNodeGroups.Preview(third,group));workbench.Save(third);
        var fetch=new SourceSyncFetch{Content=a+"\n"+b};var service=new ClientSourceSync(f.Store,fetch);service.Discover();var id=ClientSourceSync.SourceId(definition);
        Check(service.Sources().Count==1&&service.Consumers(id).Count==3,"equal fetch definitions were not shared across schemes and groups");
        Check(!service.HasSchedules(),"source discovery enabled network work without an explicit schedule");
        var before=workbench.List().ToDictionary(s=>s.Text("Id"),ArchiveStore.Fingerprint);var now=DateTimeOffset.UtcNow;
        Check(await service.FetchDueAsync(now,default)==0&&fetch.Calls==0,"disabled schedules fetched a source");service.Configure(id,true,15);
        Check(service.HasSchedules()&&await service.FetchDueAsync(now,default)==1&&fetch.Calls==1,"enabled due source was not fetched once");
        Check(await service.FetchDueAsync(now.AddMinutes(14),default)==0&&fetch.Calls==1,"schedule ran before its interval");
        foreach(var s in workbench.List())Check(before[s.Text("Id")]==ArchiveStore.Fingerprint(s),"background fetch modified a saved scheme");
        Refuses(()=>service.Configure(id,true,1),"unbounded scheduling interval accepted");
        fetch.Content=a.Replace("#A","#RenamedA")+"\n"+b+"\n"+c;Check(await service.FetchDueAsync(now.AddMinutes(15),default)==1,"new source not staged");
        var ids=new[]{first.Text("Id"),second.Text("Id"),third.Text("Id")};var groupIds=new[]{group.Text("Id")};
        var preview=service.Preview(id,ids,groupIds);Check(preview.Ready&&preview.Items.Count==4&&preview.OtherGroupConsumers==0,"cross-scheme and group preview incomplete: "+string.Join(";",preview.Items.SelectMany(i=>i.Errors)));
        Check(preview.Fingerprint==service.Preview(id,ids,groupIds).Fingerprint,"new node identities or timestamps make batch preview unstable");
        Check(preview.Items.Any(i=>i.Changes.Any(c=>c.Kind=="Added"))&&preview.Items.Any(i=>i.Changes.Any(c=>c.Kind=="Renamed")),"add/rename diff absent");
        var publicDiff=string.Join("\n",preview.Items.SelectMany(i=>i.Changes).Select(c=>c.Detail));Check(!publicDiff.Contains("synthetic-a")&&!publicDiff.Contains("token="),"diff disclosed auth or subscription URL");
        var oldId=first["Nodes"]![0]!.Text("Id");service.Apply(preview);
        first=workbench.List().Single(s=>s.Text("Id")==first.Text("Id"));second=workbench.List().Single(s=>s.Text("Id")==second.Text("Id"));third=workbench.List().Single(s=>s.Text("Id")==third.Text("Id"));
        Check(first["Nodes"]!.AsArray().Count==3&&first["Nodes"]![0]!.Text("Id")==oldId&&first["Layout"]!["business_groups"]![0]!.Text("default")=="RenamedA","batch rename lost stable identity or default reference");
        Check(second["Nodes"]!.AsArray().Count==3&&third["Nodes"]!.AsArray().Count==3,"not all selected schemes synchronized");groups.Verify(third);
        Check(service.Pending().Count==0,"successful batch retained an unresolved journal");
        var cache=service.Read(id);var good=cache.Text("Revision");fetch.Content="<html>error</html>";await RefusesAsync(()=>service.FetchAsync(id,default),"invalid content replaced good cache");Check(service.Read(id).Text("Revision")==good&&service.Read(id).Text("LastStatus")=="Failed","failed fetch erased last good revision");
        fetch.Content=a.Replace("#A","#RenamedA")+"\n"+c;await service.FetchAsync(id,default);
        var stale=service.Preview(id,ids,groupIds);var savedSecond=second.DeepClone().AsObject();second["Name"]="edited after review";workbench.Save(second);Refuses(()=>service.Apply(stale),"stale saved scheme accepted by batch");workbench.Save(savedSecond);second=savedSecond;
        var altered=second.DeepClone().AsObject();altered["Nodes"]![1]!["sing_box"]!["password"]="synthetic-local-only";workbench.Save(altered);
        var conflict=service.Preview(id,ids,groupIds);Check(!conflict.Ready&&conflict.Items.Any(i=>i.Errors.Count>0),"upstream deletion overwrote a local edit");Refuses(()=>service.Apply(conflict),"one conflicting scheme did not block the batch");workbench.Save(second);
        var removed=service.Preview(id,ids,groupIds);Check(removed.Ready&&removed.Items.Any(i=>i.Changes.Any(c=>c.Kind=="Removed")),"removal diff not produced");service.Apply(removed);
        foreach(var s in workbench.List())Check(s["Nodes"]!.AsArray().Count==2,"batch removal incomplete");
        foreach(var fault in new[]{"write","commit-write","cancel","crash","foreign"})
        {
            fetch.Content=a.Replace("#A","#RenamedA")+"\n"+b+"\n"+c;await service.FetchAsync(id,default);var reviewed=service.Preview(id,ids,groupIds);var originals=reviewed.Items.ToDictionary(i=>i.Kind+":"+i.Id,i=>f.Store.ReadSecret(EntityPath(i.Kind,i.Id)));
            string EntityPath(string kind,string entityId)=>f.Paths.Resolve("private/"+(kind=="Group"?"client-node-groups/":"client-schemes/")+entityId+".dotnet.private.json");
            if(fault is "write" or "commit-write" or "cancel")
            {
                using var cancellation=new CancellationTokenSource();var protector=new SourceSyncProtector{FailAt=fault=="write"?3:fault=="commit-write"?reviewed.Items.Count+2:0,CancelAt=fault=="cancel"?2:0,Cancellation=cancellation};var faultStore=new ArchiveStore(f.Paths,protector);var failing=new ClientSourceSync(faultStore);
                var rejected=false;try{failing.Apply(reviewed,cancellation.Token);}catch(Exception e)when(e is OperationException or IOException or OperationCanceledException){rejected=true;}
                Check(rejected&&failing.Pending().Count==0,"local write/cancel did not restore completed writes");
            }
            else
            {
                var transaction=Guid.NewGuid().ToString("N");var journal=new JsonObject{["Schema"]=1,["Id"]=transaction,["Phase"]="Applying",["Items"]=new JsonArray(reviewed.Items.Select(i=>(JsonNode?)new JsonObject{["Kind"]=i.Kind,["Id"]=i.Id,["Before"]=originals[i.Kind+":"+i.Id].DeepClone(),["After"]=i.After.DeepClone()}).ToArray())};
                var journalFile=f.Paths.Resolve("private/client-source-sync/transactions/"+transaction+".dotnet.private.json");f.Store.WriteSecret(journalFile,journal);var written=reviewed.Items[0];f.Store.WriteSecret(EntityPath(written.Kind,written.Id),written.After);
                Refuses(()=>service.Apply(reviewed),"pending local transaction allowed another batch");Refuses(()=>groups.Verify(third),"pending node-group transaction allowed export provenance");
                Refuses(()=>new PrivateDirectory(f.Store).Review(f.Paths.Root+"-unused-destination"),"archive relocation allowed an unresolved source batch");
                if(fault=="foreign")
                {
                    var entity=reviewed.Items[1];var foreign=originals[entity.Kind+":"+entity.Id].DeepClone().AsObject();foreign["Name"]="new independent edit";f.Store.WriteSecret(EntityPath(entity.Kind,entity.Id),foreign);
                    Refuses(()=>service.Recover(transaction),"recovery overwrote a foreign edit");Check(JsonNode.DeepEquals(f.Store.ReadSecret(EntityPath(written.Kind,written.Id)),written.After),"recovery partially wrote before discovering a foreign edit");f.Store.WriteSecret(EntityPath(entity.Kind,entity.Id),originals[entity.Kind+":"+entity.Id]);
                }
                service.Recover(transaction);Check(service.Pending().Count==0,"crash recovery did not finish");
            }
            foreach(var item in reviewed.Items)Check(JsonNode.DeepEquals(originals[item.Kind+":"+item.Id],f.Store.ReadSecret(EntityPath(item.Kind,item.Id))),"batch recovery changed original object");
        }
        using(var held=ClientSourceSync.LockFile(f.Paths.Resolve("private/client-schemes/"+first.Text("Id")+".dotnet.private.json")))Refuses(()=>workbench.Save(first),"scheme writer ignored batch lock");
        using(var cancelled=new CancellationTokenSource()){cancelled.Cancel();var last=service.Read(id).Text("Revision");var stopped=false;try{await service.FetchAsync(id,cancelled.Token);}catch(OperationCanceledException){stopped=true;}Check(stopped,"cancelled fetch ignored token");Check(service.Read(id).Text("Revision")==last,"cancelled fetch changed good cache");}
        service.Configure(id,false,60);Check(!service.HasSchedules(),"disabled policy continued scheduling");
        var scheduleFile=f.Paths.Resolve("private/client-source-sync/schedule.json");var full=new JsonObject();for(var i=0;i<100;i++)full[i.ToString("x32")]=new JsonObject{["Enabled"]=true,["IntervalMinutes"]=60};ArchiveStore.WriteJson(scheduleFile,full);Refuses(()=>service.Configure(id,true,15),"schedule limit accepted another source");Check(!service.Read(id).Flag("Schedule.Enabled"),"refused schedule left cache enabled without an index entry");ArchiveStore.WriteJson(scheduleFile,new JsonObject());
        var orphan=definition.DeepClone().AsObject();orphan["Url"]="https://unused.example.test/list";var orphanId=service.Register(orphan).Text("Id");service.Configure(orphanId,true,15);var calls=fetch.Calls;Check(await service.FetchDueAsync(now.AddHours(2),default)==0&&fetch.Calls==calls&&!service.Read(orphanId).Flag("Schedule.Enabled"),"unused source was fetched after all consumers disappeared");
        var file=f.Paths.Resolve("private/client-source-sync/sources/"+id+".dotnet.private.json");Check(!File.ReadAllText(file).Contains("synthetic-source-only"),"cached URL stored in plain text");
        var unknownId=Guid.NewGuid().ToString("N");var unknownFile=f.Paths.Resolve("private/client-source-sync/transactions/"+unknownId+".dotnet.private.json");f.Store.WriteSecret(unknownFile,new JsonObject{["Schema"]=2,["Id"]=unknownId,["Phase"]="Completed"});Refuses(()=>service.Pending(),"unknown completed transaction bypassed version guard");Refuses(()=>ClientSourceBarrier.RequireAvailable(f.Store,"Scheme",first.Text("Id")),"server consumer ignored unknown local transaction");
    }
    private sealed class SourceSyncFetch:IClientSourceFetch
    {
        public string Content{get;set;}="";public int Calls{get;private set;}
        public Task<string> FetchAsync(JsonObject source,CancellationToken ct){ct.ThrowIfCancellationRequested();Calls++;return Task.FromResult(Content);}
    }
    private sealed class SourceSyncProtector:ISecretProtector
    {
        public string Format=>"TEST-ONLY";public int FailAt{get;init;}public int CancelAt{get;init;}public CancellationTokenSource? Cancellation{get;init;}private int calls;
        public byte[] Protect(ReadOnlySpan<byte> data){calls++;if(calls==FailAt)throw new IOException("synthetic second write failure");if(calls==CancelAt)Cancellation!.Cancel();return Xor(data);}
        public byte[] Unprotect(ReadOnlySpan<byte> data)=>Xor(data);private static byte[] Xor(ReadOnlySpan<byte> data)=>data.ToArray().Select(b=>(byte)(b^0x73)).ToArray();
    }
}
