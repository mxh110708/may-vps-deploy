using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunSharedChainTests()
    {
        await SharedChainCoverage();
        Console.WriteLine($"PASS: {assertions} shared-instance chain ownership, survivor validation, provenance, stale review and compensation assertions; synthetic only.");
    }

    private async Task SharedChainCoverage()
    {
        foreach (var family in new[] { "IPv4", "IPv6" })
            foreach (var protocol in new[] { "vless", "hysteria2", "tuic" })
                foreach (var layout in new[] { "both", "front", "relay", "roles", "landing" })
                    await SharedChainCase(family, protocol, layout, "none");
        foreach (var fault in new[] { "validation", "survivor", "cancel", "apply-ack", "commit-ack", "compensation-ack", "rollback", "owner" })
            await SharedChainCase("IPv6", "hysteria2", "both", fault);
        await SharedChainCase("IPv4", "vless", "both", "legacy");
        await SharedChainCase("IPv6", "tuic", "both", "wireguard");
        foreach(var family in new[]{"IPv4","IPv6"})await SharedChainCase(family,"vless","both","mixed");
    }

    private JsonObject SharedSource(Fixture f, JsonObject plan, ChainHost host, string family, string protocol)
    {
        var directory = f.Paths.Instance(f.Relative(plan)); var stateFile = SafePath.Resolve(directory, "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile);
        var credentials = f.Store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"));
        try
        {
            if (protocol == "vless")
            {
                var pair = ClientProfiles.Nodes(plan, credentials).First(p => p.Family == family);
                state.Put("ServerConfigHashes.RealityEntry", JsonValue.Create(ArchiveStore.Digest(host.Inner.ProtocolConfigs["RealityEntry"]))); ArchiveStore.WriteJson(stateFile, state);
                return new() { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = pair.Name, ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = pair.Clash.DeepClone(), ["sing_box"] = pair.SingBox.DeepClone(), ["ManagedOrigin"] = ManagedNodeSources.Origin(f.Relative(plan), pair) };
            }
            var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, secrets, protocol == "tuic" ? "TuicV5" : "Hysteria2"); var cert = InboundCertificate("shared.example.test");
            inbound["CertificateId"] = InboundCatalog.ImportCertificate(model, secrets, "shared TLS", cert.Certificate, cert.Key).Text("Id"); inbound["Options"]!["ServerName"] = "shared.example.test"; inbound["Listener"]!["Address"] = family == "IPv6" ? "::" : "0.0.0.0";
            model = InboundCatalog.Normalize(model, secrets); plan["InboundModel"] = model.DeepClone(); credentials["Inbounds"] = secrets.DeepClone();
            var payload = InboundRendering.Payload(f.Store, plan, model, secrets); var node = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).Single(n => n.Text("InboundOrigin.Family") == family);
            var validation = new TuicMockValidation(f.Store).ValidateAsync(plan, model, secrets, [inbound.Text("Id")], "unused", new InlineProgress<string>(_ => { }), default).GetAwaiter().GetResult();
            var runtime = new JsonObject { [inbound.Text("Id")] = new JsonObject { ["Active"] = true, ["Enabled"] = true } };
            state["Inbounds"] = new JsonObject { ["RemoteHash"] = ArchiveStore.Fingerprint(payload), ["ModelFingerprint"] = ArchiveStore.Fingerprint(model), ["Runtime"] = runtime.DeepClone(), ["ValidationById"] = new JsonObject { [inbound.Text("Id")] = validation } };
            host.InboundState = new JsonObject { ["Hash"] = state.Text("Inbounds.RemoteHash"), ["Registry"] = new JsonObject { ["Model"] = model.DeepClone() }, ["Runtime"] = runtime };
            ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(stateFile, state); f.Store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), credentials);
            return node;
        }
        finally { credentials.Clear(); }
    }

    private async Task SharedChainCase(string family, string protocol, string layout, string failure)
    {
        using var f = new Fixture(repository); var remote = new ChainRemote(); var plans = new List<JsonObject>(); var transport = protocol == "vless" ? "TCP" : "UDP";
        for (var i = 0; i < 5; i++)
        {
            var p = f.Plan("Shared25-" + i); p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); p.Put("Server.IPv4", JsonValue.Create("192.0.2." + (10+i))); p.Put("Server.IPv6", JsonValue.Create("2001:db8::" + (10+i))); f.SaveInstance(p); plans.Add(p);
            var h = new ChainHost(p.Text("Server.IPv4"), remote) { SplitTransports=failure=="mixed" }; h.Inner.SeedProtocols(p); h.Inner.ProtocolConfigs["RealityEntry"] = Encoding.UTF8.GetBytes("unchanged source " + i); remote.Hosts.Add(h.Address, h);
        }
        ChainHost Host(int i) => remote.Hosts[plans[i].Text("Server.IPv4")];
        var scheme = ClientSchemes.New(f.Paths); var nodes = new Dictionary<int,JsonObject>();
        foreach (var i in new[] { 2,3,4 }) { var n = SharedSource(f, plans[i], Host(i), family, protocol); nodes[i] = n; scheme["Nodes"]!.AsArray().Add(n.DeepClone()); }
        f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths, scheme.Text("Id")), scheme);
        JsonObject Chain(int front, int relay, int landing, int offset)
        {
            var c = TcpChains.New(f.Relative(plans[front])); c["Name"] = "共享线路 " + offset; c["Family"] = family; c["Transport"] = transport; c["RelayInstance"] = f.Relative(plans[relay]); c["LandingInstance"] = f.Relative(plans[landing]); c["FrontSourceAddress"] = plans[front].Text("Server." + family); c["FrontSources"] = new JsonArray(family == "IPv6" ? "2001:db8:1::/64" : "198.51.100.0/24"); c["FrontPort"] = 28443 + offset; c["RelayPort"] = 28444 + offset;
            c["Landing"] = new JsonObject { ["SchemeId"] = scheme.Text("Id"), ["NodeId"] = nodes[landing].Text("Id"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(nodes[landing]) }; return c;
        }
        var a = Chain(0,1,2,0); var b = layout switch { "front" => Chain(0,3,4,10), "relay" => Chain(3,1,4,10), "roles" => Chain(1,0,4,10), "landing" => Chain(3,4,2,10), _ => Chain(0,1,3,10) };
        if(failure=="mixed")
        {
            var n=SharedSource(f,plans[3],Host(3),family,"hysteria2");scheme["Nodes"]!.AsArray().Add(n.DeepClone());f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths,scheme.Text("Id")),scheme);
            b["Transport"]="UDP";b["Landing"]=new JsonObject{["SchemeId"]=scheme.Text("Id"),["NodeId"]=n.Text("Id"),["NodeFingerprint"]=ArchiveStore.Fingerprint(n)};
        }
        if (failure == "wireguard")
        {
            var tunnel = SeedChainUnderlay(f, plans, remote, a, "FrontRelay");
            b["WireGuard"] = TcpChainUnderlay.Reference(f.Store, ArchiveStore.ReadJson(WireGuardTunnels.FileName(f.Paths, tunnel.Text("Id"))), "FrontRelay");
        }
        var validation = new SharedChainValidation(remote); var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), tcpChains: validation)); var progress = new InlineProgress<TaskProgress>(_ => { });
        OperationRequest Request(JsonObject c, string action) => new(OperationKind.TcpChain,c.Text("FrontInstance"),new() { ["Action"] = action, ["Configuration"] = c.DeepClone() });
        async Task<TaskRecord> Execute(JsonObject c, string action) { var r = Request(c, action); return await coordinator.ExecuteAsync(coordinator.Review(r), r, progress, default); }
        var appliedA = await Execute(a,"Apply"); Check(appliedA.Outcome == TaskOutcome.Completed,"first shared chain failed: " + appliedA.SafeError);
        var projectedA = TcpChains.Project(f.Store,a,"US-West-LA Entry"); TcpChains.VerifyNodes(f.Store,[projectedA]);
        var af = TcpChains.FileName(f.Paths,a.Text("Id")); var beforeA = ArchiveStore.ReadJson(af);
        if (failure == "legacy")
        {
            beforeA.Remove("RuleFingerprints"); ArchiveStore.WriteJson(af,beforeA);
            foreach (var instance in TcpChains.Instances(a)) { var p = TcpChains.Plan(f.Store,instance); var binding=TcpChains.Bindings(p).Single().DeepClone(); p.Remove("TcpChains"); p["TcpChain"] = binding; ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(instance),"deployment-plan.json"),p); }
            var digest = ArchiveStore.Fingerprint(beforeA); TcpChains.VerifyNodes(f.Store,[projectedA]); Check(digest==ArchiveStore.Fingerprint(ArchiveStore.ReadJson(af)),"reading legacy chain rewrote archive");
        }
        if (failure == "none" && family=="IPv4" && protocol=="vless")
        {
            var incompatible=Request(b,"Apply"); incompatible.Options["Configuration"]!["FrontInstance"]=a.Text("LandingInstance");
            incompatible=incompatible with { InstanceRelativePath=a.Text("LandingInstance") };Refuses(()=>coordinator.Review(incompatible),"active proxy exit reused as another line's forwarder");
            var preview=TcpChains.Prepare(f.Store,Request(b,"Apply")); Check(preview.Summary.Contains(layout=="landing"?"每条线路":"共享线路 0"),"shared scope missing from review");
            var colliding=Request(b,"Apply"); colliding.Options["Configuration"]!["FrontPort"] = a.Number("FrontPort"); if (layout is "both" or "front") Refuses(()=>coordinator.Review(colliding),"shared listener collision accepted");
            var reviewed=coordinator.Review(Request(b,"Apply"));
            using(f.Store.LockInstance(a.Text("LandingInstance"))) if(layout!="landing") await RefusesAsync(()=>coordinator.ExecuteAsync(reviewed,Request(b,"Apply"),progress,default),"preserved participant was not locked");
            var changed=ArchiveStore.ReadJson(af);changed["SyntheticChanged"]=true;ArchiveStore.WriteJson(af,changed); await RefusesAsync(()=>coordinator.ExecuteAsync(reviewed,Request(b,"Apply"),progress,default),"shared record changed after review was accepted");ArchiveStore.WriteJson(af,beforeA);
            var p=TcpChains.Plan(f.Store,a.Text("FrontInstance"));var original=p.DeepClone();p.Remove("TcpChains");p.Remove("TcpChain");ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(a.Text("FrontInstance")),"deployment-plan.json"),p);
            Refuses(()=>new InstanceDeletion(f.Store).Review(a.Text("FrontInstance")),"missing binding allowed archive deletion");ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(a.Text("FrontInstance")),"deployment-plan.json"),original);
        }
        validation.Failure = failure is "validation" or "survivor" or "cancel" or "rollback" or "owner" ? failure : ""; validation.FailedId = failure == "survivor" ? a.Text("Id") : b.Text("Id");
        var relayHost=remote.Hosts[TcpChains.Plan(f.Store,b.Text("RelayInstance")).Text("Server.IPv4")];relayHost.Failure = failure;
        var aCalls=validation.Calls.GetValueOrDefault(a.Text("Id"));var beforeRules=remote.Hosts.ToDictionary(p=>p.Key,p=>p.Value.Configuration?.DeepClone());
        var result=await Execute(b,"Apply");var bf=TcpChains.FileName(f.Paths,b.Text("Id"));
        if (failure is "none" or "legacy" or "wireguard" or "mixed")
        {
            Check(result.Outcome==TaskOutcome.Completed,"shared chain apply failed "+layout+"/"+protocol+": "+result.SafeError);
            var projectedB=TcpChains.Project(f.Store,b,"US-West-LA Entry");TcpChains.VerifyNodes(f.Store,[projectedA,projectedB]);
            Check(layout=="landing" || validation.Calls.GetValueOrDefault(a.Text("Id"))>aCalls,"existing chain was not revalidated after shared mutation");
            var expected=TcpChains.Instances(a).Intersect(TcpChains.Instances(b)).ToArray();foreach(var instance in expected)Check(TcpChains.Bindings(TcpChains.Plan(f.Store,instance)).Length==2,"shared dependency overwritten");
            var aRecord=ArchiveStore.ReadJson(af);aRecord["LastCheck"]=new JsonObject{["Status"]="Failed"};ArchiveStore.WriteJson(af,aRecord);Refuses(()=>TcpChains.VerifyNodes(f.Store,[projectedA]),"failed line exported");TcpChains.VerifyNodes(f.Store,[projectedB]);aRecord.Remove("LastCheck");ArchiveStore.WriteJson(af,aRecord);
            Check((await Execute(b,"Check")).Outcome==TaskOutcome.Completed,"independent check failed");TcpChains.VerifyNodes(f.Store,[projectedA,projectedB]);
            foreach(var instance in TcpChains.Instances(b)[..2])
            {
                var state=ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(instance),"deployment-state.json"));var items=state.At(TcpChains.Component(b)+".Validation.Items")!.AsArray().OfType<JsonObject>().ToArray();
                Check(items.Select(i=>i.Text("Id")).Distinct().Count()==items.Length,"read-only check duplicated per-line evidence");
                if(failure!="mixed" && TcpChains.Instances(a)[..2].Contains(instance))Check(items.Length==2,"read-only check erased another line's evidence");
            }
            var beforeRemovingA=ArchiveStore.ReadJson(af);Check((await Execute(b,"Remove")).Outcome==TaskOutcome.Completed,"shared removal failed");TcpChains.VerifyNodes(f.Store,[projectedA]);Refuses(()=>TcpChains.VerifyNodes(f.Store,[projectedB]),"removed shared line exported");
            Check(JsonNode.DeepEquals(beforeRemovingA,ArchiveStore.ReadJson(af)),"removal rewrote unrelated line record");
            foreach(var instance in TcpChains.Instances(a)) Check(TcpChains.Bound(TcpChains.Plan(f.Store,instance),a),"surviving binding removed");
            var stale=TcpChains.Plan(f.Store,a.Text("FrontInstance"));var stateFile=SafePath.Resolve(f.Paths.Instance(a.Text("FrontInstance")),"deployment-state.json");var savedState=ArchiveStore.ReadJson(stateFile);var savedPlan=stale.DeepClone();
            stale[TcpChains.Component(a)]!["Rules"]![0]!["TargetPort"]=1;var altered=savedState.DeepClone().AsObject();altered.Put(TcpChains.Component(a)+".ConfigurationFingerprint",JsonValue.Create(ArchiveStore.Fingerprint(stale[TcpChains.Component(a)]!)));ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(a.Text("FrontInstance")),"deployment-plan.json"),stale);ArchiveStore.WriteJson(stateFile,altered);
            Refuses(()=>TcpChains.VerifyNodes(f.Store,[projectedA]),"per-rule drift bypassed source check after shared changes");ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(a.Text("FrontInstance")),"deployment-plan.json"),savedPlan);ArchiveStore.WriteJson(stateFile,savedState);
        }
        else
        {
            var pending=failure is "rollback" or "owner" or "compensation-ack";Check(result.Outcome==(pending?TaskOutcome.NeedsRecovery:failure=="cancel"?TaskOutcome.Cancelled:TaskOutcome.Failed),"wrong shared failure result: "+failure+" "+result.Outcome+" "+result.SafeError);
            if(pending)
            {
                Refuses(()=>TcpChains.VerifyNodes(f.Store,[projectedA]),"pending shared restore allowed old node export");Refuses(()=>coordinator.Review(Request(a,"Remove")),"pending sibling mutation allowed");relayHost.Failure="";relayHost.Inner.StatusTaskId=ArchiveStore.ReadJson(bf).Text("Transaction.TaskId");Check((await Execute(b,"Recover")).Outcome==TaskOutcome.Completed,"shared recovery did not resume");
            }
            foreach(var (address,configuration) in beforeRules)Check(JsonNode.DeepEquals(configuration,remote.Hosts[address].Configuration),"shared failure failed to preserve original rules");
            Check(JsonNode.DeepEquals(beforeA,ArchiveStore.ReadJson(af)),"failed new line changed previous line record");TcpChains.VerifyNodes(f.Store,[projectedA]);Check(ArchiveStore.ReadJson(bf).Text("Phase")=="RolledBack","failed line did not roll back");
        }
        validation.Failure="";validation.FailedId="";relayHost.Failure="";
        Check((await Execute(a,"Remove")).Outcome==TaskOutcome.Completed,"last line removal failed");
        foreach(var p in plans)Check(TcpChains.Bindings(TcpChains.Plan(f.Store,f.Relative(p))).Length==0,"retired multi-chain binding remained");
    }

    private sealed class SharedChainValidation(ChainRemote remote) : ITcpChainValidation
    {
        public string Failure {get;set;}="";public string FailedId {get;set;}="";public Dictionary<string,int> Calls {get;}=[];
        public Task<JsonObject> ValidateAsync(JsonObject node,string directory,IProgress<string> progress,CancellationToken ct)
        {
            var id=node.Text("TcpChainOrigin.Id");Calls[id]=Calls.GetValueOrDefault(id)+1;
            return new ChainValidation{Remote=remote,Failure=id==FailedId?(Failure=="survivor"?"validation":Failure):""}.ValidateAsync(node,directory,progress,ct);
        }
    }
}
