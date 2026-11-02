using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private static JsonObject RuleSetFixture(string revision="1.0.0")=>new(){["Schema"]=1,["Id"]="research-fixture",["Name"]="Research fixture",["Revision"]=revision,["Rules"]=new JsonArray(new JsonObject{["Kind"]="Domain",["Value"]="dataset.example.test"},new JsonObject{["Kind"]="Suffix",["Value"]="papers.example.test"})};
    public async Task RunServerRuleSetTests(bool modelOnly=false)
    {
        await ServerRuleSetExperience();
        if(!modelOnly)
        {
            using(var f=new Fixture(repository))await ServerOutboundLoopback(f,true,withRuleSets:true);
            using(var f=new Fixture(repository))await ServerOutboundLoopback(f,withHops:true,withRuleSets:true);
            using(var f=new Fixture(repository))await RealityOutboundLoopback(f,true,withRuleSets:true);
            using(var f=new Fixture(repository))await RealityOutboundLoopback(f,withHops:true,withRuleSets:true);
        }
        Console.WriteLine($"PASS: {assertions} versioned server rule-set classification, immutable snapshots, update/restore and path assertions; modelOnly={modelOnly}.");
    }
    private async Task ServerRuleSetExperience()
    {
        using var f=new Fixture(repository);var library=new ServerRuleSetStore(f.Store);library.EnsureBuiltins();var builtins=ServerRuleSets.Builtins(f.Paths);
        Check(builtins.Count==4&&library.List().Count==4,"builtin categories missing");
        var academic=builtins.Single(s=>s.Text("Id")=="academic-research");var campus=builtins.Single(s=>s.Text("Id")=="campus-academic-cn");var ai=builtins.Single(s=>s.Text("Id")=="google-ai-services");
        var classified=new JsonArray(ServerRuleSets.Rule(campus,"Direct"),ServerRuleSets.Rule(academic,"NextHop"),ServerRuleSets.Rule(ai,"Reject"));
        Check(ServerDestinationRules.Decide(classified,"sysu.co.cnki.net")=="Direct"&&ServerDestinationRules.Decide(classified,"library.example.edu.cn")=="Direct","campus classification boundary wrong");
        Check(ServerDestinationRules.Decide(new JsonArray(ServerRuleSets.Rule(academic,"Reject")),"huggingface.co")=="Reject"&&ServerDestinationRules.Decide(new JsonArray(ServerRuleSets.Rule(ai,"Reject")),"huggingface.co")=="NextHop","datasets incorrectly classified as AI service");
        Check(ServerDestinationRules.Decide(new JsonArray(ServerRuleSets.Rule(ai,"Reject")),"deepmind.google")=="NextHop"&&ServerDestinationRules.Decide(new JsonArray(ServerRuleSets.Rule(academic,"Reject")),"scholar.google.com.hk")=="Reject","research override lost from server categories");
        var original=RuleSetFixture();var policy=ServerDestinationRules.Normalize(new JsonArray(ServerRuleSets.Rule(original,"Direct")));
        Check(ServerDestinationRules.Decide(policy,"x.papers.example.test")=="Direct"&&ServerDestinationRules.Decide(policy,"badpapers.example.test")=="NextHop"&&ServerDestinationRules.Decide(policy,"sub.dataset.example.test")=="NextHop","rule-set domain/suffix semantics wrong");
        Check(ServerDestinationRules.Decide(policy,"dataset.example.test","udp")=="NextHop","classification changed UDP session behavior");
        foreach(var role in ServerOutboundRouting.Roles)
        {
            var rendered=ServerDestinationRules.Render(role,policy,["fixture-in"]);Check(rendered.Count==2&&rendered.All(r=>r!.Text("network")=="tcp"),"category not rendered as bounded TCP primitives");
        }
        var version1=library.Preview(original);library.Apply(version1);var initial=library.Read(original.Text("Id"));var digest1=initial.Text("Current");
        var next=RuleSetFixture("2.0.0");next["Rules"]!.AsArray().RemoveAt(0);next["Rules"]!.AsArray().Add(new JsonObject{["Kind"]="Suffix",["Value"]="books.example.test"});var changed=library.Preview(next);
        Check(changed.Changes.Any(c=>c.Kind=="Added")&&changed.Changes.Any(c=>c.Kind=="Removed"),"rule-set revision diff missing");library.Apply(changed);
        var latest=library.Read(next.Text("Id"));Check(latest["Versions"]!.AsArray().Count==2&&ServerRuleSetStore.Current(latest).Text("Revision")=="2.0.0","new version did not preserve old snapshot");
        Check(ServerDestinationRules.Decide(policy,"dataset.example.test")=="Direct","library head update changed already pinned rule");
        var forged=original.DeepClone().AsObject();forged["Rules"]![0]!["Value"]="different.example.test";Refuses(()=>library.Preview(forged),"same version overwritten with different content");
        Refuses(()=>library.Apply(version1),"stale rule-library review accepted");library.SelectVersion(next.Text("Id"),digest1,ArchiveStore.Fingerprint(latest));Check(ServerRuleSetStore.Current(library.Read(next.Text("Id"))).Text("Revision")=="1.0.0","history selection failed");
        var bad=original.DeepClone().AsObject();bad["Rules"]![0]!["Action"]="Direct";Refuses(()=>ServerRuleSets.Normalize(bad),"rule-set action injection accepted");
        bad=original.DeepClone().AsObject();bad["Rules"]![0]!["Kind"]="RuleSet";Refuses(()=>ServerRuleSets.Normalize(bad),"nested rule set accepted");
        bad=original.DeepClone().AsObject();bad["Rules"]!.AsArray().Add(bad["Rules"]![0]!.DeepClone());Refuses(()=>ServerRuleSets.Normalize(bad),"duplicate normalized terms accepted");
        bad=original.DeepClone().AsObject();bad["Schema"]=2;Refuses(()=>ServerRuleSets.Normalize(bad),"unknown rule-set schema accepted");
        bad=original.DeepClone().AsObject();bad["Id"]="../outside";Refuses(()=>ServerRuleSets.Normalize(bad),"rule-set path injection accepted");
        var malformed=ServerRuleSets.Rule(original);malformed["Value"]="another-set";Refuses(()=>ServerDestinationRules.Normalize(new JsonArray(malformed)),"mismatched embedded set identity accepted");
        var blockedProbe=RuleSetFixture();blockedProbe["Rules"]=new JsonArray(new JsonObject{["Kind"]="Suffix",["Value"]="ipify.org"});Refuses(()=>ServerDestinationRules.ValidatePath(new JsonArray(ServerRuleSets.Rule(blockedProbe,"Direct")),"IPv4",true),"category bypassed default next-hop acceptance");
        var v6=RuleSetFixture();v6["Rules"]=new JsonArray(new JsonObject{["Kind"]="Cidr",["Value"]="2001:db8::/32"});Refuses(()=>ServerDestinationRules.ValidatePath(new JsonArray(ServerRuleSets.Rule(v6)),"IPv4",false),"category bypassed egress family guard");
        var large=RuleSetFixture();large["Rules"]=new JsonArray(Enumerable.Range(0,2048).Select(i=>(JsonNode?)new JsonObject{["Kind"]="Domain",["Value"]="d"+i+"."+new string('a',60)+"."+new string('b',60)+"."+new string('c',60)+".example.test"}).ToArray());var secondLarge=large.DeepClone().AsObject();secondLarge["Id"]="second-large-fixture";var oversized=new JsonArray(ServerRuleSets.Rule(large),ServerRuleSets.Rule(secondLarge));
        foreach(var role in ServerOutboundRouting.Roles){var bounded=RealityFixture(f,"Bounded-set-"+role,true);var input=ArchiveStore.ReadJson(SafePath.Resolve(bounded.Directory,ServerOutboundRouting.ConfigRelative(role)));OperationException? sizeError=null;try{ServerOutboundRouting.Build(role,input,bounded.Plan.At("ServerOutbound."+role)!.AsObject(),bounded.Node,"198.51.100.20",bounded.Plan,destinationRules:oversized);}catch(OperationException e){sizeError=e;}Check(sizeError?.Message.Contains("1 MiB")==true,"rule-set expansion was not bounded before creating an unmaintainable archive");}
        var fetch=new SourceSyncFetch{Content=next.ToJsonString()};var networkLibrary=new ServerRuleSetStore(f.Store,fetch);var definition=ClientSubscriptions.New("");definition["Url"]="https://rules.example.test/policy?token=synthetic-rule-only";var record=library.Read(next.Text("Id"));library.ConfigureSource(next.Text("Id"),definition,ArchiveStore.Fingerprint(record));
        var fetched=await networkLibrary.FetchAsync(next.Text("Id"),default);Check(fetched.Snapshot.Text("Revision")=="2.0.0"&&ServerRuleSetStore.Current(library.Read(next.Text("Id"))).Text("Revision")=="1.0.0","fetch silently applied new server rules");
        fetch.Content=next.DeepClone().ToJsonString();var wrong=next.DeepClone().AsObject();wrong["Id"]="wrong-owner";fetch.Content=wrong.ToJsonString();await RefusesAsync(()=>networkLibrary.FetchAsync(next.Text("Id"),default),"remote rule set with wrong identity accepted");
        await using(var server=new SubscriptionServer{Body=next.ToJsonString()})
        {
            var actual=ClientSubscriptions.New("");actual["Network"]="Proxy";actual["Proxy"]=server.Address;actual["Url"]="http://127.0.0.1:9/proxy-proof";record=library.Read(next.Text("Id"));library.ConfigureSource(next.Text("Id"),actual,ArchiveStore.Fingerprint(record));var remoteLibrary=new ServerRuleSetStore(f.Store,new ClientSubscriptionDownload());var staged=await remoteLibrary.FetchAsync(next.Text("Id"),default);
            Check(staged.Snapshot.Text("Revision")=="2.0.0"&&server.Requests.Last().StartsWith("GET http://127.0.0.1:9/proxy-proof ",StringComparison.Ordinal)&&ServerRuleSetStore.Current(library.Read(next.Text("Id"))).Text("Revision")=="1.0.0","rule library ignored proxy or applied fetched snapshot without review");
        }
        foreach(var role in ServerOutboundRouting.Roles)
        {
            var data=RealityFixture(f,"RuleSet-model-"+role,true);var file=SafePath.Resolve(data.Directory,ServerOutboundRouting.ConfigRelative(role));SaveDestinationPolicy(f,data,role,policy);var before=ArchiveStore.ReadJson(file);var metadata=data.Plan.At("ServerOutbound."+role)!.AsObject();
            var v2Policy=new JsonArray(ServerRuleSets.Rule(next,"Reject"));var update=ServerOutboundRouting.Build(role,before,metadata,data.Node,"198.51.100.20",data.Plan,destinationRules:v2Policy);
            Check(update.Metadata!.At("DestinationRules")![0]!.Text("RuleSet.Revision")=="2.0.0"&&update.Summary.Contains("2.0.0")&&update.Summary.Contains(ServerRuleSets.Digest(next)[..8]),"review omitted fixed version/digest");
            var restored=ServerOutboundRouting.Build(role,update.Configuration,update.Metadata,data.Node,"198.51.100.20",data.Plan,destinationRules:policy);Check(JsonNode.DeepEquals(before,restored.Configuration),"previous set snapshot did not restore exact native policy");
            var drift=update.Metadata!.DeepClone().AsObject();drift["DestinationRules"]![0]!["RuleSet"]!["Rules"]![0]!["Value"]="tampered.example.test";Refuses(()=>ServerOutboundRouting.Build(role,update.Configuration,drift,null,"",data.Plan),"metadata snapshot drift was adopted");
        }
        foreach(var role in ServerOutboundRouting.Roles)foreach(var failure in new[]{"none","partial","apply-ack","commit-ack","cancel"})
        {
            var data=RealityFixture(f,"RuleSet-task-"+role+"-"+failure,true);SaveDestinationPolicy(f,data,role,policy);var remote=RoutingRemote(data);var originalBytes=remote.ProtocolConfigs[role].ToArray();var sibling=remote.ProtocolConfigs[role=="RealityEntry"?"AnyTlsEntry":"RealityEntry"].ToArray();var originalMetadata=ArchiveStore.Fingerprint(data.Plan["ServerOutbound"]!);
            remote.LoseOutboundApplyAcknowledgement=failure=="apply-ack";remote.LoseOutboundCommitAcknowledgement=failure=="commit-ack";var engine=new WorkflowEngine(f.Store,remote,new FakeKeys(),new FakeUser(),new RealityLifecycleValidation(failure));Exception? error=null;TaskOutcome? outcome=null;
            var changedPolicy=new JsonArray(ServerRuleSets.Rule(next,"Reject"));try{outcome=await engine.ExecuteAsync(new(OperationKind.ServerOutbound,data.Relative,ServerOutboundRouting.Options(data.State,role,"Apply",data.Scheme,data.Node,"198.51.100.20",changedPolicy)),Guid.NewGuid().ToString("N"),new InlineProgress<TaskProgress>(_=>{}),default);}catch(Exception e){error=e;}
            var after=ArchiveStore.ReadJson(SafePath.Resolve(data.Directory,"deployment-plan.json"));Check(remote.ProtocolConfigs[role=="RealityEntry"?"AnyTlsEntry":"RealityEntry"].SequenceEqual(sibling)&&remote.ArmedComponents==role&&remote.Commands.Count(c=>c=="server-outbound-apply.sh")==1,"rule-set update changed another component or replayed a mutation");
            if(failure is "none" or "commit-ack")Check(error==null&&outcome is TaskOutcome.Completed or TaskOutcome.CompletedWithWarnings&&after.At("ServerOutbound."+role+".DestinationRules")![0]!.Text("RuleSet.Revision")=="2.0.0","rule-set apply/reconcile failed");
            else Check(error!=null&&remote.ProtocolConfigs[role].SequenceEqual(originalBytes)&&ArchiveStore.Fingerprint(after["ServerOutbound"]!)==originalMetadata,"rule-set failure did not restore previous snapshot");
        }
    }
}
