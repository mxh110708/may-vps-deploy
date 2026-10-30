using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunChain21VmTests(string manifestFile)
    {
        if (!Path.GetFullPath(manifestFile).Contains(Path.DirectorySeparatorChar + ".codex-tmp" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new Exception("Disposable fixture path required.");
        var manifest = ArchiveStore.ReadJson(manifestFile); if (!manifest.Flag("SyntheticOnly") || manifest["Nodes"] is not JsonObject nodes || nodes.Count != 3) throw new Exception("Three disposable guests required.");
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(9)); var ct = budget.Token; var user = new FakeUser(); var factory = new TcpChainVmFactory(f.Store, nodes); var plans = new List<JsonObject>();
        async Task<IRemoteSession> Connect(int index) => await factory.OpenAsync(new(nodes[index==0?"Front":index==1?"Relay":"Landing"]!.Text("Address"),22,"root",nodes[index==0?"Front":index==1?"Relay":"Landing"]!.Text("KeyFile")),user,ct);
        async Task<string> Read(int index,string command) { await using var session=await Connect(index);var r=await session.RunAsync(command,TimeSpan.FromSeconds(20),ct);r.RequireSuccess("Disposable chain observation failed.");return r.Output.Trim(); }
        foreach (var name in new[] { "Front", "Relay", "Landing" })
        {
            var host=nodes[name]!;var index=plans.Count;var proof=(await Read(index,"python3 -c \"from pathlib import Path; print(Path('/etc/may-tcp-chain-fixture').read_text().strip()); print(Path('/sys/class/dmi/id/product_uuid').read_text().strip())\"")).Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries);
            Check(proof.Length==2&&proof.All(s=>s.Equals(host.Text("FixtureId"),StringComparison.OrdinalIgnoreCase)),"marker/DMI mismatch; no guest mutation permitted");
            var p=f.Plan("Chain21VM-"+name);p["Role"]="MonitorOnly";p["Roles"]=new JsonArray("MonitorOnly");p["ActiveEntry"]="";p["AdminUser"]="root";p["ProtocolInventory"]=new JsonObject();foreach(var role in DeploymentPlans.Roles[..3])p["ProtocolInventory"]![role]=new JsonObject{["Installed"]=false,["Enabled"]=false};
            p.Put("Import.Status",JsonValue.Create("Completed"));p.Put("Import.SshAuthenticationPreserved",JsonValue.Create(true));p.Put("Server.IPv4",JsonValue.Create(host.Text("Address")));p.Put("Server.IPv6",JsonValue.Create(host.Text("IPv6")));p.Put("Ports.SshPrimary",JsonValue.Create(22));p.Put("Ports.SshRescue",JsonValue.Create(2222));p.Put("Server.BootstrapSshPort",JsonValue.Create(22));p.Put("SshKey.SourcePrivateKeyPath",JsonValue.Create(host.Text("KeyFile")));p.Put("Firewall.Mode",JsonValue.Create("ManagedNftables"));f.SaveInstance(p);plans.Add(p);
            await using var session=await Connect(index);(await session.RunScriptAsync(new RemoteAssets(f.Paths).Payload("nftables-apply.sh",new Dictionary<string,string>{{"TCP_PORTS","22,2222"},{"UDP_PORTS",""}}),TimeSpan.FromSeconds(20),true,ct)).RequireSuccess("Disposable firewall baseline failed.");
        }
        using var key=RSA.Create(2048);var csr=new CertificateRequest("CN=chain.example.test",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var san=new SubjectAlternativeNameBuilder();san.AddDnsName("chain.example.test");san.AddIpAddress(IPAddress.Loopback);csr.CertificateExtensions.Add(san.Build());csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));using var ca=csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(2));
        const string directory="/opt/may-tcp-chain-fixture";
        var web="import http.server,ssl,socket,threading\ndef dns():\n s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',5353))\n while True:\n  q,p=s.recvfrom(4096)\n  if len(q)>=17:s.sendto(q[:2]+b'\\x81\\x80'+q[4:6]+b'\\x00\\x01\\x00\\x00\\x00\\x00'+q[12:]+bytes.fromhex('c00c000100010000000000047f000001'),p)\nthreading.Thread(target=dns,daemon=True).start()\nclass Handler(http.server.BaseHTTPRequestHandler):\n def do_GET(self):\n  b=b'198.51.100.30';self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)\n def log_message(self,*args):pass\ns=http.server.HTTPServer(('127.0.0.1',9443),Handler)\nc=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain('"+directory+"/web.pem','"+directory+"/web.key');s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()\n";
        await using(var session=await Connect(2))
        {
            var core=InboundRendering.Core(f.Paths);var path=InboundRendering.CorePath(core);var hash=(await Read(2,"sha256sum "+directory+"/sing-box")).Split(' ')[0];Check(hash.Length==64,"fixture core digest unavailable");
            var metadata=new JsonObject{["Managed"]="MayInboundCore.v1",["Version"]=core.Text("Version"),["ArchiveSha256"]=core.Text("Sha256"),["BinarySha256"]=hash};
            var setup="set -euo pipefail\numask 077\ninstall -d -m 0755 "+Path.GetDirectoryName(path)!.Replace('\\','/')+"\ncp "+directory+"/sing-box "+path+"\nchmod 0755 "+path+"\n";
            foreach(var (name,content) in new[]{(directory+"/web.py",web),(directory+"/web.pem",ca.ExportCertificatePem()),(directory+"/web.key",key.ExportPkcs8PrivateKeyPem()),(Path.GetDirectoryName(path)!.Replace('\\','/')+"/core.json",metadata.ToJsonString())})setup+="printf '%s' '"+Convert.ToBase64String(Encoding.UTF8.GetBytes(content))+"' | base64 -d > "+name+"\n";
            setup+="chmod 0644 "+Path.GetDirectoryName(path)!.Replace('\\','/')+"/core.json\ncat > /etc/systemd/system/may-chain21-web.service <<'EOF'\n[Service]\nExecStart=/usr/bin/python3 "+directory+"/web.py\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload\nsystemctl enable --now may-chain21-web.service\nsystemctl restart may-chain21-web.service\n";
            (await session.RunScriptAsync(setup,TimeSpan.FromSeconds(25),true,ct)).RequireSuccess("Disposable pinned core/application setup failed.");
        }
        var assets=new ValidationAssets(new AppPaths(repository),"windows-amd64");var tools=new ExternalToolRunner();var target=new Uri("https://127.0.0.1:9443");var endpoints=new ClientDiagnosticEndpoints(target,target,target){Udp4=new(IPAddress.Loopback,5353)};var diagnostics=new ClientRouteDiagnostics(assets,tools,endpoints,ca);var results=new JsonArray();
        foreach(var (family,protocol) in new[]{("IPv6","Shadowsocks2022"),("IPv4","Hysteria2"),("IPv6","Hysteria2"),("IPv4","TuicV5"),("IPv6","TuicV5")})
        {
            var transport=protocol=="Shadowsocks2022"?"TCP":"UDP";Console.WriteLine("Chain21 actual case: "+family+" / "+protocol);
            JsonObject Host(string name){var h=nodes[name]!.DeepClone().AsObject();var ingress=h["Ingress"+family]!.AsObject();foreach(var (k,v) in ingress)h[k]=v!.DeepClone();h["Applications"]=new JsonObject{["18443"]=ingress["ApplicationPort"]!.DeepClone()};return h;}
            var sourceModel=InboundCatalog.Empty();var credentials=InboundCatalog.EmptyCredentials();var input=InboundCatalog.AddInbound(sourceModel,credentials,protocol);input["Listener"]!["Address"]=plans[2].Text("Server."+family);input["Listener"]!["Port"]=18443;
            if(transport=="UDP"){input["CertificateId"]=InboundCatalog.ImportCertificate(sourceModel,credentials,"Fixture TLS",ca.ExportCertificatePem(),key.ExportPkcs8PrivateKeyPem()).Text("Id");input["Options"]!["ServerName"]="chain.example.test";}
            var sourceValidator=new HysteriaVmValidation(f.Store,diagnostics,Host("Landing"));var chainValidator=new Chain21VmValidation(diagnostics,Host("Front"),ca.ExportCertificatePem(),transport=="UDP");
            var coordinator=new TaskCoordinator(f.Store,new WorkflowEngine(f.Store,factory,new FakeKeys(),user,new FakeValidation(),tcpChains:chainValidator,inboundValidation:sourceValidator));var last="";var progress=new InlineProgress<TaskProgress>(p=>{if(last!=p.Stage){last=p.Stage;Console.WriteLine("Chain21 stage: "+p.Stage);}});
            var stateFile=SafePath.Resolve(f.Paths.Instance(f.Relative(plans[2])),"deployment-state.json");var request=new OperationRequest(OperationKind.Inbounds,f.Relative(plans[2]),InboundCatalog.Options(ArchiveStore.ReadJson(stateFile),"Apply",sourceModel,credentials));
            Check((await coordinator.ExecuteAsync(coordinator.Review(request),request,progress,ct)).Outcome==TaskOutcome.Completed,"actual source inbound apply failed");plans[2]=TcpChains.Plan(f.Store,f.Relative(plans[2]));
            var node=InboundSources.Create(f.Store,f.Relative(plans[2]),input.Text("Id"),input.Strings("UserIds")[0],family);var scheme=ClientSchemes.New(f.Paths);scheme["Nodes"]!.AsArray().Add(node.DeepClone());f.Store.WriteSecret(ServerOutboundRouting.SchemeFile(f.Paths,scheme.Text("Id")),scheme);
            var config=TcpChains.New(f.Relative(plans[0]));config["Family"]=family;config["Transport"]=transport;config["RelayInstance"]=f.Relative(plans[1]);config["LandingInstance"]=f.Relative(plans[2]);config["FrontSourceAddress"]=plans[0].Text("Server."+family);config["FrontSources"]=new JsonArray(plans[0].Text("Server."+family)+(family=="IPv6"?"/128":"/32"));config["Landing"]=new JsonObject{["SchemeId"]=scheme.Text("Id"),["NodeId"]=node.Text("Id"),["NodeFingerprint"]=ArchiveStore.Fingerprint(node)};
            OperationRequest Chain(string action)=>new(OperationKind.TcpChain,f.Relative(plans[0]),new JsonObject{["Action"]=action,["Configuration"]=config.DeepClone()});
            async Task<TaskRecord> Execute(string action){var r=Chain(action);return await coordinator.ExecuteAsync(coordinator.Review(r),r,progress,ct);}
            var applied=await Execute("Apply");Check(applied.Outcome==TaskOutcome.Completed,"actual "+family+" "+protocol+" chain apply failed: "+applied.SafeError);var chainFile=TcpChains.FileName(f.Paths,config.Text("Id"));var record=ArchiveStore.ReadJson(chainFile);var projected=TcpChains.Project(f.Store,config,"US-West-LA Entry");TcpChains.VerifyNodes(f.Store,[projected]);
            Check(record["Validation"]!["Segments"]!.AsArray().Count==2&&record["Validation"]!["Segments"]!.AsArray().All(s=>s!.Text("Scope")== (transport=="UDP"?"UdpRouteOnly":"TcpConnectOnly")),"segment evidence conflated routing with reachability");
            Check(transport!="UDP"||record.Flag("Validation.Result.UdpValidation.ResponseMatched"),"UDP chain committed without actual application response");
            var export=ClientSchemes.New(f.Paths);ForwardedNodeSources.Apply(f.Store,export,[projected],"US-West-LA Entry");var wb=new ClientWorkbench(f.Store,tools,assets,Environment.GetEnvironmentVariable("MAY_TEST_PYTHON")??"python");await wb.BuildAsync(export,ct);await wb.ValidateAsync(export,ct);Check(export.Text("Candidate.ValidationStatus")=="Passed","actual chain dual-client projection failed core validation");
            Check((await Execute("Check")).Outcome==TaskOutcome.Completed,"actual whole-chain read-only check failed");
            Check((await Execute("Remove")).Outcome==TaskOutcome.Completed,"actual chain remove failed");Refuses(()=>TcpChains.VerifyNodes(f.Store,[projected]),"removed actual chain retained export eligibility");
            if(protocol=="TuicV5"&&family=="IPv6")
            {
                factory.Fault="relay-commit-ack";config["Id"]=Guid.NewGuid().ToString("N");Check((await Execute("Apply")).Outcome==TaskOutcome.Failed&&factory.LostAcknowledgements==1,"real UDP commit loss was replayed or not compensated");
            }
            foreach(var index in new[]{0,1})Check(await Read(index,"test ! -e /etc/may-"+(transport=="UDP"?"udp":"tcp")+"-forward/config.json && test ! -e /var/lib/may-vps-deploy/transaction.owner && ! systemctl is-active --quiet mxh-protocol-migration-rollback.timer && printf CLEAN")=="CLEAN","actual cleanup retained forwarding, owner or timer");
            results.Add(new JsonObject{["Family"]=family,["Protocol"]=protocol,["Transport"]=transport,["Evidence"]=record["Validation"]!.DeepClone(),["DualCoreCandidate"]=true,["RemovedAndClean"]=true});
        }
        await Read(2,"systemctl disable --now may-chain21-web.service");
        ArchiveStore.WriteJson(Path.Combine(Path.GetDirectoryName(manifestFile)!,"round21-result.json"),new JsonObject{["Status"]="Passed",["Assertions"]=assertions,["Cases"]=results,["LostCommitAcknowledgements"]=factory.LostAcknowledgements,["HostRoutesChanged"]=false,["ProductionTargets"]=false});
        Console.WriteLine($"PASS: {assertions} actual three-guest IPv6 TCP and dual-family Hysteria2/TUIC orchestration assertions.");
    }
    private sealed class Chain21VmValidation(ClientRouteDiagnostics diagnostics,JsonObject host,string ca,bool udp):ITcpChainValidation
    {
        public async Task<JsonObject> ValidateAsync(JsonObject node,string directory,IProgress<string> progress,CancellationToken ct)
        {
            await using var tunnel=udp?await HysteriaVmTunnel.Start(host,18443,ct):null;var port=udp?tunnel!.Port:host.Number("ApplicationPort");var copy=node.DeepClone().AsObject();copy["sing_box"]!["server"]="127.0.0.1";copy["sing_box"]!["server_port"]=port;copy["clash"]!["server"]="127.0.0.1";copy["clash"]!["port"]=port;if(udp)copy["sing_box"]!["tls"]!["certificate"]=new JsonArray(ca);
            var result=await new TcpChainValidation(diagnostics).ValidateAsync(copy,directory,progress,ct);result["ConnectionFingerprint"]=ClientNodeImport.ConnectionFingerprint(node);if(result.Text("Status")!="Passed")Console.WriteLine("Chain21 diagnostic stages: "+result["Result"]?["Stages"]?.ToJsonString());return result;
        }
    }
}
