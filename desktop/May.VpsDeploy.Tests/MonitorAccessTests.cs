using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunMonitorAccessTests()
    { using var f = new Fixture(repository); await MonitorAccessExperience(f); Console.WriteLine($"PASS: {assertions} access planning, origin identity, pilot readiness and stale/cancel assertions; inert SSH and scoped snapshots only."); }

    private async Task MonitorAccessExperience(Fixture f)
    {
        var serverPlan = f.Plan("May-server-access"); serverPlan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(serverPlan);
        var nodePlan = f.Plan("May-agent-pilot"); nodePlan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(nodePlan);
        var serverRelative = f.Relative(serverPlan); var nodeRelative = f.Relative(nodePlan);
        var serverFile = SafePath.Resolve(f.Paths.Instance(serverRelative), "deployment-state.json"); var nodeFile = SafePath.Resolve(f.Paths.Instance(nodeRelative), "deployment-state.json");
        var origin = Guid.NewGuid().ToString("D"); var nodeId = Guid.NewGuid().ToString("D");
        var server = new JsonObject { ["Installed"] = true, ["Active"] = true, ["Hash"] = new string('a',64), ["Configuration"] = new JsonObject { ["Port"] = 25775, ["Username"] = "admin", ["InstanceId"] = origin } };
        var agent = new JsonObject { ["Installed"] = true, ["Active"] = true, ["Hash"] = new string('b',64), ["Configuration"] = new JsonObject { ["Endpoint"] = "https://may.example/", ["ClientUUID"] = nodeId } };
        var state = ArchiveStore.ReadJson(serverFile); state["MayMonitorServer"] = server; state["KomariSentinel"] = "retained"; ArchiveStore.WriteJson(serverFile,state);
        state = ArchiveStore.ReadJson(nodeFile); state["MayMonitorAgent"] = agent; state["KomariSentinel"] = "retained"; ArchiveStore.WriteJson(nodeFile,state);
        var connection = new MonitorReadConnection("https://may.example/",MonitorReadConnection.NewToken(), new Dictionary<string,string> { [nodeRelative] = nodeId }, origin);
        var source = new MonitorReadArchive(f.Store); source.Save(connection);
        foreach (var value in new[] { "http://may.example/", "https://may.example/path", "https://user:pass@may.example/", "https://may.example/?token=x", "https://127.0.0.1/" }) Refuses(() => MayMonitorAccess.SavePlan(f.Store,serverRelative,value),"unsafe publication plan accepted");
        var legacyPlan = f.Plan("Legacy-monitor"); legacyPlan.Put("Cloudflared.PublicUrl",JsonValue.Create("https://old.example/")); f.SaveInstance(legacyPlan);
        var legacyPlanBytes = File.ReadAllBytes(SafePath.Resolve(f.Store.Paths.Instance(serverRelative), "deployment-plan.json"));
        Check(MayMonitorAccess.SavePlan(f.Store,serverRelative,"https://old.example/").Text("PublicUrl")=="https://old.example/","existing HTTPS origin cannot be planned for replacement");
        Check(File.ReadAllBytes(SafePath.Resolve(f.Store.Paths.Instance(serverRelative), "deployment-plan.json")).SequenceEqual(legacyPlanBytes),"saving HTTPS plan changed legacy service configuration");
        var plan = MayMonitorAccess.SavePlan(f.Store,serverRelative,connection.Endpoint.AbsoluteUri);
        Check(plan.Text("ServerInstanceId") == origin && MayMonitorAccess.Guidance(plan).Contains("http://127.0.0.1:25775"),"origin plan lost local service or identity");
        var planFile = MayMonitorAccess.PlanFile(f.Store,serverRelative); var savedPlan = File.ReadAllBytes(planFile); MayMonitorAccess.SavePlan(f.Store,serverRelative,"https://may.example"); Check(File.ReadAllBytes(planFile).SequenceEqual(savedPlan),"unchanged plan rewrote archive");
        var remote = new MonitorAccessRemote(server.DeepClone().AsObject(), new JsonObject { ["ClientUUID"] = nodeId, ["ServerInstanceId"] = origin, ["Endpoint"] = connection.Endpoint.AbsoluteUri, ["StateHash"] = agent.Text("Hash") });
        var mode = "valid"; var reads = 0; var first = DateTimeOffset.UtcNow; CancellationTokenSource? userCancel = null;
        var probe = new AccessProbe((value, ct) =>
        {
            reads++; Check(value.Identity == connection.Identity,"probe changed scoped source");
            if (mode == "network-failure") throw new OperationException("synthetic safe network failure");
            if (mode == "source-change") source.Save(new("https://changed.example/",connection.Token,connection.Bindings,origin));
            if (mode == "cancel") userCancel!.Cancel();
            var now = DateTimeOffset.UtcNow;
            var at = mode == "stalled" ? first : mode == "stale" ? now.AddMinutes(-2) : now;
            var sample = new MonitorReadNode(nodeId,mode != "offline",at,new(3.5,128,1024,1,2,3,4));
            return Task.FromResult(new MonitorReadSnapshot(now,now,"0.1.0-rc.3",new Dictionary<string,MonitorReadNode> { [nodeId] = sample },mode == "wrong-origin" ? Guid.NewGuid().ToString("D") : mode == "missing-origin" ? null : origin));
        });
        var engine = new WorkflowEngine(f.Store,remote,new FakeKeys(),new FakeUser(),new FakeValidation(),monitorRead:probe);
        var coordinator = new TaskCoordinator(f.Store,engine);
        OperationRequest Request(string action="VerifyHttps") => new(OperationKind.MayMonitorAccess,serverRelative,new JsonObject { ["Action"] = action,["ConnectionIdentity"] = connection.Identity });
        OperationRequest Pilot() { var request=Request("PilotCheck"); request.Options["NodeInstance"] = nodeRelative; return request; }
        async Task<TaskRecord> Run(OperationRequest request,CancellationToken token=default) => await coordinator.ExecuteAsync(coordinator.Review(request),request,new InlineProgress<TaskProgress>(_=>{}),token);
        var malformed = Request(); malformed.Options["Token"] = connection.Token; Refuses(()=>MayMonitorAccess.Validate(malformed),"raw credential accepted in options");
        malformed=Pilot(); malformed.Options["NodeInstance"]="../escape"; Refuses(()=>MayMonitorAccess.Validate(malformed),"pilot target escaped archive");
        var review=coordinator.Review(Request()); Check(review.Summary.Contains(origin) && !review.Summary.Contains(connection.Token),"review lost identity or leaked token");
        File.AppendAllText(planFile," "); await RefusesAsync(()=>coordinator.ExecuteAsync(review,review.Request,new InlineProgress<TaskProgress>(_=>{}),default),"changed plan passed old review"); ArchiveStore.AtomicWrite(planFile,savedPlan);
        Check(remote.Calls.Count==0,"stale review contacted SSH");
        Check((await Run(Request())).Outcome==TaskOutcome.Completed,"HTTPS origin verification failed");
        Check(MayMonitorAccess.EvidenceLabel(f.Store,serverRelative).Contains("HTTPS"),"successful HTTPS evidence missing");
        foreach(var failure in new[]{"wrong-origin","missing-origin","network-failure","source-change"})
        {
            mode=failure; var outcome=await Run(Request()); Check(outcome.Outcome==TaskOutcome.Failed && MayMonitorAccess.State(f.Store,serverRelative).Text("MayMonitorAccess.Status")=="Failed","invalid origin/source remained healthy"); source.Save(connection);
        }
        mode="valid"; reads=0; Check((await Run(Pilot())).Outcome==TaskOutcome.Completed && reads==3,"pilot did not require three scoped samples");
        Check(MayMonitorAccess.EvidenceLabel(f.Store,serverRelative).Contains("节点接入"),"node readiness evidence missing");
        var managementPlanFile=SafePath.Resolve(f.Paths.Instance(nodeRelative),"deployment-plan.json"); var changedManagement=nodePlan.DeepClone().AsObject(); changedManagement.Put("Server.IPv4",JsonValue.Create("192.0.2.11")); ArchiveStore.WriteJson(managementPlanFile,changedManagement);
        Check(MayMonitorAccess.EvidenceLabel(f.Store,serverRelative).Contains("已变化"),"changed management target retained readiness"); ArchiveStore.WriteJson(managementPlanFile,nodePlan);
        Check(MayMonitorAccess.State(f.Store,serverRelative).Text("KomariSentinel")=="retained" && MayMonitorAccess.State(f.Store,nodeRelative).Text("KomariSentinel")=="retained","pilot changed legacy data");
        remote.Agent["Endpoint"]="https://unexpected.example/"; Check((await Run(Pilot())).Outcome==TaskOutcome.Failed,"unarchived agent endpoint was accepted");
        state=ArchiveStore.ReadJson(nodeFile); state.Put("MayMonitorAgent.Configuration.Endpoint",JsonValue.Create("http://127.0.0.1:25775/")); ArchiveStore.WriteJson(nodeFile,state); remote.Agent["Endpoint"]="http://127.0.0.1:25775/";
        Check((await Run(Pilot())).Outcome==TaskOutcome.Completed,"cohost loopback agent rejected despite matching server identity");
        state=ArchiveStore.ReadJson(nodeFile); state.Put("MayMonitorAgent.Configuration.Endpoint",JsonValue.Create(connection.Endpoint.AbsoluteUri)); ArchiveStore.WriteJson(nodeFile,state); remote.Agent["Endpoint"]=connection.Endpoint.AbsoluteUri;
        state=ArchiveStore.ReadJson(nodeFile); state.Put("MayMonitorAgent.Hash",JsonValue.Create(new string('c',64))); ArchiveStore.WriteJson(nodeFile,state);
        Check(MayMonitorAccess.EvidenceLabel(f.Store,serverRelative).Contains("已变化"),"changed agent retained readiness"); state.Put("MayMonitorAgent.Hash",JsonValue.Create(new string('b',64))); ArchiveStore.WriteJson(nodeFile,state);
        remote.Agent["ServerInstanceId"] = Guid.NewGuid().ToString("D"); Check((await Run(Pilot())).Outcome==TaskOutcome.Failed,"agent attached to another server was accepted"); remote.Agent["ServerInstanceId"]=origin;
        var nodePlanFile=SafePath.Resolve(f.Paths.Instance(nodeRelative),"deployment-plan.json"); var wrongPlan=nodePlan.DeepClone().AsObject(); wrongPlan["Instance"]="Another-instance"; ArchiveStore.WriteJson(nodePlanFile,wrongPlan);
        var beforeMismatch=remote.Calls.Count; Check((await Run(Pilot())).Outcome==TaskOutcome.Failed && !remote.Calls.Skip(beforeMismatch).Contains("VerifyAgent"),"mismatched node archive contacted its SSH target"); ArchiveStore.WriteJson(nodePlanFile,nodePlan);
        foreach(var failure in new[]{"offline","stale","stalled"}) { mode=failure; first=DateTimeOffset.UtcNow; Check((await Run(Pilot())).Outcome==TaskOutcome.Failed,"unusable or stalled telemetry accepted"); }
        mode="cancel"; using(var cancel=new CancellationTokenSource()) { userCancel=cancel; Check((await Run(Pilot(),cancel.Token)).Outcome==TaskOutcome.Cancelled,"cancelled readiness did not stop"); }
        Check(MayMonitorAccess.State(f.Store,serverRelative).Text("MayMonitorAccess.Status")=="Cancelled","cancel retained a ready result");
        Check(remote.Mutations==0 && remote.Calls.All(value=>value is "Check" or "VerifyAgent"),"readiness changed a remote service");
        Check(!File.ReadAllText(planFile).Contains(connection.Token) && !File.ReadAllText(serverFile).Contains(connection.Token),"plan/evidence leaked read token");
        await MonitorOriginParsing(f, nodeId,origin);
        await MonitorAccessTls(f,nodeRelative,nodeId,origin);
    }

    private Task MonitorOriginParsing(Fixture f,string node,string origin)
    {
        var sample = MonitorSample(node); sample["server_instance_id"]=origin;
        Check(MonitorReadSnapshot.Parse(Encoding.UTF8.GetBytes(sample.ToJsonString()),DateTimeOffset.UtcNow).ServerInstanceId==origin,"snapshot origin missing");
        foreach(var value in new[]{"not-a-uuid",Guid.Empty.ToString("D"),origin.ToUpperInvariant()}) { sample["server_instance_id"]=value; Refuses(()=>MonitorReadSnapshot.Parse(Encoding.UTF8.GetBytes(sample.ToJsonString()),DateTimeOffset.UtcNow),"malformed origin accepted"); }
        return Task.CompletedTask;
    }
}

internal sealed class AccessProbe(Func<MonitorReadConnection,CancellationToken,Task<MonitorReadSnapshot>> read) : IMonitorReadProbe
{ public Task<MonitorReadSnapshot> FetchAsync(MonitorReadConnection connection,CancellationToken ct)=>read(connection,ct); }

internal sealed class MonitorAccessRemote(JsonObject server,JsonObject agent) : IRemoteSessionFactory,IRemoteSession
{
    internal readonly List<string> Calls=[]; internal int Mutations; internal JsonObject Agent=>agent;
    private readonly FakeRemote other=new();
    public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint,IUserInteraction user,CancellationToken ct)=>Task.FromResult<IRemoteSession>(this);
    public Task<CommandResult> RunAsync(string command,TimeSpan timeout,CancellationToken ct)=>other.RunAsync(command,timeout,ct);
    public Task<byte[]> ReadFileAsync(string path,CancellationToken ct)=>other.ReadFileAsync(path,ct);
    public Task DownloadAsync(string path,string destination,CancellationToken ct)=>other.DownloadAsync(path,destination,ct);
    public Task<CommandResult> RunScriptAsync(string payload,TimeSpan timeout,bool mutating,CancellationToken ct)
    {
        if(mutating) { Mutations++; throw new Exception("Readiness attempted mutation"); }
        if(!payload.StartsWith("# MXH asset: may-monitor-lifecycle.sh\n")) return other.RunScriptAsync(payload,timeout,mutating,ct);
        var match=Regex.Match(payload,"export VPS_PARAM_ACTION=.+?'([A-Za-z0-9+/=]*)' "); var action=Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)); Calls.Add(action);
        var result=action=="VerifyAgent"?agent:server;
        return Task.FromResult(new CommandResult(0,"VPSDEPLOY_MAY_MONITOR_RESULT_B64="+Convert.ToBase64String(Encoding.UTF8.GetBytes(result.ToJsonString()))+"\n",""));
    }
    public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
}
