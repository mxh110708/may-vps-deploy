using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunChain24Tests()
    {
        await Chain24Coverage();
        Console.WriteLine($"PASS: {assertions} round 24 WireGuard dependency, dual-family TCP/QUIC, challenge, drift, source and compensation assertions; synthetic only.");
    }
    private async Task Chain24Coverage()
    {
        foreach (var segment in new[] { "FrontRelay", "RelayLanding" })
        {
            foreach (var family in new[] { "IPv4", "IPv6" })
            {
                await Chain21Case(family,"TCP","vless","none",segment);
                foreach (var protocol in new[] { "hysteria2", "tuic" }) await Chain21Case(family,"UDP",protocol,"none",segment);
            }
            foreach (var fault in new[] { "wg-drift", "wg-late-drift", "wg-stale", "wg-missing-udp", "arm-ack", "apply-ack", "validation", "missing-udp", "cancel", "commit-ack", "commit-front", "compensation-ack", "rollback", "owner" })
                await Chain21Case("IPv6","UDP","hysteria2",fault,segment);
        }
    }
    private JsonObject SeedChainUnderlay(Fixture f, List<JsonObject> plans, ChainRemote remote, JsonObject chain, string segment)
    {
        if (segment == "Both") return SeedChain30Underlays(f, plans, remote, chain);
        // Reverse the saved peer order for one segment: direction is determined
        // by instance identity, never by assumptions about First/Second.
        var indices = segment == "FrontRelay" ? new[] { 1,0 } : [1,2];
        var c=WireGuardTunnels.New(f.Relative(plans[indices[0]]));c["SecondInstance"]=f.Relative(plans[indices[1]]);c["Family"]=TcpChains.Family(chain)=="IPv4"?"IPv6":"IPv4";
        for(var i=0;i<2;i++)
        {
            var instance=f.Relative(plans[indices[i]]);var p=TcpChains.Plan(f.Store,instance);var other=TcpChains.Plan(f.Store,f.Relative(plans[indices[1-i]]));
            var peer=WireGuardTunnels.Peer(c,p,other,i==0);peer["PublicKey"]=Convert.ToBase64String(Enumerable.Repeat((byte)(i+1),32).ToArray());peer["PeerPublicKey"]=Convert.ToBase64String(Enumerable.Repeat((byte)(2-i),32).ToArray());
            p["WireGuardTunnel"]=peer;ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(instance),"deployment-plan.json"),p);
            var path=SafePath.Resolve(f.Paths.Instance(instance),"deployment-state.json");var state=ArchiveStore.ReadJson(path);
            state["WireGuardTunnel"]=new JsonObject{["RemoteHash"]=ArchiveStore.Fingerprint(peer),["ConfigurationFingerprint"]=ArchiveStore.Fingerprint(peer)};ArchiveStore.WriteJson(path,state);
            remote.Hosts[p.Text("Server.IPv4")].WireGuard=peer.DeepClone().AsObject();
        }
        var record=new JsonObject{["Version"]=1,["Configuration"]=c.DeepClone(),["Phase"]="Active",["Validation"]=new JsonObject{["Status"]="Passed",["Scope"]="BidirectionalWireGuardApplications",["ConfigurationFingerprint"]=ArchiveStore.Fingerprint(c)}};
        ArchiveStore.WriteJson(WireGuardTunnels.FileName(f.Paths,c.Text("Id")),record);chain["WireGuard"]=TcpChainUnderlay.Reference(f.Store,record,segment);return c;
    }
    private void CheckChainUnderlayPreview(Fixture f,List<JsonObject> plans,JsonObject chain,JsonObject tunnel,TcpChainPreview preview,TaskCoordinator coordinator,OperationRequest apply)
    {
        var front=preview.FrontConfiguration["Rules"]![0]!;var relay=preview.RelayConfiguration["Rules"]![0]!;
        Check(front.Text("TargetAddress")==TcpChainUnderlay.Target(f.Store,chain,true)&&relay.Text("TargetAddress")==TcpChainUnderlay.Target(f.Store,chain,false),"tunnel segment retained a public target");
        Check(preview.Summary.Contains("WireGuard") && !preview.Summary.Contains("PrivateKey"),"review omitted underlay or exposed key material");
        Check(TcpChainUnderlay.Choices(f.Store,chain).Single().Reference.Text("Fingerprint")==chain.Text("WireGuard.Fingerprint"),"existing pair missing from selector");
        foreach(var invalid in new JsonNode?[]{null,JsonValue.Create("unknown"),new JsonObject(),new JsonObject{["Id"]=tunnel.Text("Id"),["Segment"]="FrontLanding",["Fingerprint"]=new string('a',64)}})
        {var r=apply.Snapshot();r.Options["Configuration"]!["WireGuard"]=invalid?.DeepClone();Refuses(()=>coordinator.Review(r),"invalid underlay reference accepted");}
        var stale=apply.Snapshot();stale.Options["Configuration"]!["WireGuard"]!["Fingerprint"]=new string('f',64);Refuses(()=>coordinator.Review(stale),"stale tunnel peer identity accepted");
        var wrong=apply.Snapshot();wrong.Options["Configuration"]!["WireGuard"]!["Segment"]=chain.Text("WireGuard.Segment")=="FrontRelay"?"RelayLanding":"FrontRelay";Refuses(()=>coordinator.Review(wrong),"nonadjacent tunnel pair accepted");
    }
    private void CheckChainUnderlayActive(Fixture f,List<JsonObject> plans,JsonObject chain,JsonObject tunnel,JsonObject record,JsonObject projected,TaskCoordinator coordinator)
    {
        Check(record.Text("Validation.WireGuard.DependencyFingerprint")==chain.Text("WireGuard.Fingerprint") && record["Validation"]!["WireGuard"]!["Directions"]!.AsArray().Count==2,"chain committed without both tunnel directions");
        Refuses(()=>coordinator.Review(new(OperationKind.WireGuardTunnel,tunnel.Text("FirstInstance"),new(){["Action"]="Remove",["Configuration"]=tunnel.DeepClone()})),"chain dependency allowed tunnel removal");
        var file=WireGuardTunnels.FileName(f.Paths,tunnel.Text("Id"));var wg=ArchiveStore.ReadJson(file);var before=wg.DeepClone();wg["LastCheck"]=new JsonObject{["Status"]="Failed"};ArchiveStore.WriteJson(file,wg);
        Refuses(()=>TcpChains.VerifyNodes(f.Store,[projected]),"failed tunnel health retained export eligibility");ArchiveStore.WriteJson(file,before);
        var stateFile=SafePath.Resolve(f.Paths.Instance(tunnel.Text("FirstInstance")),"deployment-state.json");var state=ArchiveStore.ReadJson(stateFile);var original=state.DeepClone();state.Put("WireGuardTunnel.RemoteHash",JsonValue.Create(new string('e',64)));ArchiveStore.WriteJson(stateFile,state);
        Refuses(()=>TcpChains.VerifyNodes(f.Store,[projected]),"tunnel resource replacement retained export eligibility");ArchiveStore.WriteJson(stateFile,original);
        var incomplete=record["Validation"]!.DeepClone().AsObject();incomplete["WireGuard"]!["Directions"]!.AsArray().RemoveAt(0);Refuses(()=>TcpChains.RequireValidation(chain,projected,incomplete),"one-direction tunnel proof was accepted");
    }
}
