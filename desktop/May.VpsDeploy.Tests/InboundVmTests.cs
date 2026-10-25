using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunInboundVmTests(string manifestFile)
    {
        if (!Path.GetFullPath(manifestFile).Contains(Path.DirectorySeparatorChar + ".codex-tmp" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new Exception("Use the explicitly created disposable inbound fixture.");
        var host = ArchiveStore.ReadJson(manifestFile);
        if (host.Number("Version") != 1 || !host.Flag("SyntheticOnly") || host.Number("Debian") is not (12 or 13) || host.Text("Address") != "10.0.2.15" || host.Text("Name") != "Inbound") throw new Exception("Unsupported disposable fixture identity.");
        var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(15)); var ct = budget.Token; var user = new FakeUser();
        Console.WriteLine("Disposable inbound controller evidence: " + f.Root);
        var factory = new TcpChainVmFactory(f.Store, new JsonObject { ["Inbound"] = host.DeepClone() });
        var plan = f.Plan("InboundVM-Debian" + host.Number("Debian")); plan["Role"] = "MonitorOnly"; plan["Roles"] = new JsonArray("MonitorOnly"); plan["ActiveEntry"] = ""; plan["AdminUser"] = "root";
        plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Import.SshAuthenticationPreserved", JsonValue.Create(true)); plan.Put("Server.IPv4", JsonValue.Create(host.Text("Address"))); plan.Put("Server.IPv6", JsonValue.Create("")); plan.Put("Ports.SshPrimary", JsonValue.Create(22)); plan.Put("Ports.SshRescue", JsonValue.Create(2222)); plan.Put("Server.BootstrapSshPort", JsonValue.Create(22)); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); plan.Put("SshKey.SourcePrivateKeyPath", JsonValue.Create(host.Text("KeyFile"))); plan["ProtocolInventory"] = new JsonObject();
        foreach (var protocol in DeploymentPlans.Roles[..3]) plan["ProtocolInventory"]![protocol] = new JsonObject { ["Installed"] = false, ["Enabled"] = false, ["Active"] = false };
        f.SaveInstance(plan);
        async Task<IRemoteSession> Connect() => await factory.OpenAsync(new(host.Text("Address"),22,"root",host.Text("KeyFile")),user,ct);
        async Task<string> Read(string command) { await using var remote = await Connect(); var result = await remote.RunAsync(command,TimeSpan.FromSeconds(20),ct); result.RequireSuccess("Disposable observation failed."); return result.Output.Trim(); }
        var proof = await Read("python3 -c \"from pathlib import Path; print(Path('/etc/may-inbound-fixture').read_text().strip()); print(Path('/sys/class/dmi/id/product_uuid').read_text().strip())\""); Check(proof.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).Length == 2 && proof.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).All(v=>v.Equals(host.Text("FixtureId"),StringComparison.OrdinalIgnoreCase)),"disposable DMI and marker differ before mutations");
        using var key = RSA.Create(2048); var request = new CertificateRequest("CN=inbound.example.com",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("inbound.example.com"); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build()); request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        using var authority = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(2)); var pem = authority.ExportCertificatePem(); var privatePem = key.ExportPkcs8PrivateKeyPem();
        var core = InboundRendering.Core(f.Paths); var fixture = "/opt/may-inbound-fixture";
        var target = new JsonObject { ["log"] = new JsonObject { ["level"] = "warn" }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "anytls", ["listen"] = "127.0.0.1", ["listen_port"] = 19443, ["users"] = new JsonArray(new JsonObject { ["password"] = "synthetic-reality-target-only" }), ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "inbound.example.com", ["min_version"] = "1.3", ["alpn"] = new JsonArray("h2"), ["certificate_path"] = fixture+"/https.pem", ["key_path"] = fixture+"/https.key" } }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct" }) };
        var https = "import http.server,ssl\nclass Response(http.server.BaseHTTPRequestHandler):\n def do_GET(self):\n  body=b'198.51.100.22'\n  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)\n def log_message(self,*args):pass\nserver=http.server.HTTPServer(('127.0.0.1',9443),Response)\ncontext=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('"+fixture+"/https.pem','"+fixture+"/https.key')\nserver.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()\n";
        await using (var remote = await Connect())
        {
            var setup="set -euo pipefail\numask 077\ninstall -d -m 0700 "+fixture+"\nprintf '\\n127.0.0.1 inbound-target.test\\n' >> /etc/hosts\n";
            foreach(var (name,value) in new[]{("https.py",https),("https.pem",pem),("https.key",privatePem),("target.json",target.ToJsonString())}) setup+="printf '%s' '"+Convert.ToBase64String(Encoding.UTF8.GetBytes(value))+"' | base64 -d > "+fixture+"/"+name+"\n";
            foreach(var (name,command) in new[]{("https","/usr/bin/python3 "+fixture+"/https.py"),("target",InboundRendering.CorePath(core)+" run -c "+fixture+"/target.json")}) setup+="cat > /etc/systemd/system/may-round13-fixture-"+name+".service <<'MAY_FIXTURE'\n[Service]\nExecStart="+command+"\n[Install]\nWantedBy=multi-user.target\nMAY_FIXTURE\n";
            setup+="systemctl daemon-reload\nsystemctl enable --now may-round13-fixture-https.service may-round13-fixture-target.service\nsystemctl restart may-round13-fixture-https.service may-round13-fixture-target.service\n";
            (await remote.RunScriptAsync(setup,TimeSpan.FromSeconds(25),true,ct)).RequireSuccess("Disposable TLS/HTTPS setup failed.");
        }
        var (model,secrets)=InboundModel();var inbounds=InboundCatalog.Items(model,"Inbounds").ToArray(); var extra=InboundCatalog.AddUser(model,secrets,"second SS user","SS128");inbounds[0]["UserIds"]!.AsArray().Add(extra.Text("Id"));
        var cert=InboundCatalog.ImportCertificate(model,secrets,"fixture TLS",pem,privatePem);var tls=InboundCatalog.AddInbound(model,secrets,"AnyTLS");tls["CertificateId"]=cert.Text("Id");tls["Options"]!["ServerName"]="inbound.example.com";
        var assets=new ValidationAssets(new AppPaths(repository),"windows-amd64");var tools=new ExternalToolRunner();var reality=InboundCatalog.AddInbound(model,secrets,"Reality");var pair=await InboundKeyGeneration.RealityAsync(assets,tools,ct);secrets["Inbounds"]![reality.Text("Id")]!["RealityPrivateKey"]=pair.Text("PrivateKey");reality["Options"]!["PublicKey"]=pair.Text("PublicKey");pair.Clear();reality["Options"]!["ServerName"]="inbound.example.com";reality["Options"]!["HandshakeServer"]="inbound-target.test";reality["Options"]!["HandshakePort"]=19443;
        var endpoints=new ClientDiagnosticEndpoints(new("https://127.0.0.1:9443"),new("https://127.0.0.1:9443"),new("https://127.0.0.1:9443"));var validator=new InboundVmValidation(f.Store,new ClientRouteDiagnostics(assets,tools,endpoints,authority),host["Applications"]!.AsObject(),pem);
        var coordinator=new TaskCoordinator(f.Store,new WorkflowEngine(f.Store,factory,new FakeKeys(),user,new FakeValidation(),inboundValidation:validator));var directory=f.Paths.Instance(f.Relative(plan));var stateFile=SafePath.Resolve(directory,"deployment-state.json");
        var previousStage="";var progress=new InlineProgress<TaskProgress>(p=>{if(previousStage!=p.Stage){Console.WriteLine("VM inbound stage: "+p.Stage);previousStage=p.Stage;}});
        OperationRequest Operation(string action="Apply")=>new(OperationKind.Inbounds,f.Relative(plan),InboundCatalog.Options(ArchiveStore.ReadJson(stateFile),action,model,secrets));
        async Task<TaskRecord> Execute(string action="Apply"){await Task.Delay(1100,ct);var operation=Operation(action);return await coordinator.ExecuteAsync(coordinator.Review(operation),operation,progress,ct);}
        var applied=await Execute();Check(applied.Outcome==TaskOutcome.Completed,"real inbound application failed: "+applied.SafeError);
        Check(ArchiveStore.ReadJson(stateFile)["Inbounds"]!["ValidationById"]!.AsObject().Count==4,"actual per-inbound validation missing");
        async Task<string> ServiceIdentity(string id)=>await Read("systemctl show "+InboundRendering.Unit(id)+" -p InvocationID --value");
        var untouchedId=inbounds[1].Text("Id");var untouched=await ServiceIdentity(untouchedId);var secretKey=secrets.Text("Inbounds."+inbounds[0].Text("Id")+".ServerKey");secrets["Inbounds"]![inbounds[0].Text("Id")]!["ServerKey"]=ServerConfigurations.RandomKey(16);
        Check((await Execute()).Outcome==TaskOutcome.Completed,"one inbound key rotation failed");Check(await ServiceIdentity(untouchedId)==untouched,"another inbound restarted during one-key rotation");
        validator.Fail=true;var before=await Read("sha256sum /etc/may-inbounds/model.json");secrets["Inbounds"]![inbounds[0].Text("Id")]!["ServerKey"]=secretKey;
        var rolled=await Execute();Check(rolled.Outcome==TaskOutcome.Failed,"actual validation failure was not scoped and rolled back: "+rolled.SafeError);Check(await Read("sha256sum /etc/may-inbounds/model.json")==before && await ServiceIdentity(untouchedId)==untouched,"actual rollback altered unrelated resource or failed to restore registry");
        secrets=f.Store.ReadSecret(SafePath.Resolve(directory,"secrets.dotnet.private.json"))["Inbounds"]!.DeepClone().AsObject();validator.Fail=false;
        factory.Fault="inbound-commit-ack";var display=inbounds[0].Text("Name");inbounds[0]["Name"]=display+" renamed";var acknowledged=await Execute();Check(acknowledged.Outcome==TaskOutcome.CompletedWithWarnings && factory.LostAcknowledgements==1,"actual lost commit acknowledgement was replayed or not reconciled");Check(await ServiceIdentity(untouchedId)==untouched,"metadata-only update restarted another service");
        var boot=await Read("cat /proc/sys/kernel/random/boot_id");await using(var remote=await Connect()){try{await remote.RunAsync("systemctl reboot",TimeSpan.FromSeconds(5),ct);}catch(IOException){}}
        var rebooted=false;for(var attempt=0;attempt<100;attempt++){await Task.Delay(1500,ct);try{if(await Read("cat /proc/sys/kernel/random/boot_id")!=boot){rebooted=true;break;}}catch(Exception error)when(error is IOException or OperationException or Renci.SshNet.Common.SshException or System.Net.Sockets.SocketException){}}
        Check(rebooted,"disposable guest did not reboot");Check((await Execute("Check")).Outcome==TaskOutcome.Completed,"real enabled multi-inbound services did not recover after reboot");
        var exported=InboundSources.Create(f.Store,f.Relative(plan),tls.Text("Id"),tls.Strings("UserIds")[0],"IPv4");InboundSources.VerifyNodes(f.Store,[exported]);Check(exported.Text("sing_box.tls.server_name")=="inbound.example.com" && !exported.Flag("sing_box.tls.insecure"),"AnyTLS export lost SNI or relaxed trust");
        var export=ClientSchemes.New(f.Paths);foreach(var i in InboundCatalog.Items(model,"Inbounds"))foreach(var uid in i.Strings("UserIds"))ForwardedNodeSources.Apply(f.Store,export,[InboundSources.Create(f.Store,f.Relative(plan),i.Text("Id"),uid,"IPv4")],"US-West-LA Entry");
        var workbench=new ClientWorkbench(f.Store,tools,assets,Environment.GetEnvironmentVariable("MAY_TEST_PYTHON")??"python");await workbench.BuildAsync(export,ct);await workbench.ValidateAsync(export,ct);Check(export.Text("Candidate.ValidationStatus")=="Passed" && export["Nodes"]!.AsArray().Count==5,"generic per-user dual-client output rejected by fixed cores");
        foreach(var item in InboundCatalog.Items(model,"Inbounds").ToArray())InboundCatalog.RemoveEntity(model,secrets,"Inbounds",item.Text("Id"));
        Check((await Execute()).Outcome==TaskOutcome.Completed,"real inbound removal failed");
        Check(await Read("test -z \"$(find /etc/systemd/system -maxdepth 1 -name 'may-inbound-????????????????????????????????.service' -print -quit)\" && test ! -e /var/lib/may-vps-deploy/transaction.owner && printf CLEAN")=="CLEAN","removal left service or pending ownership");
        ArchiveStore.WriteJson(Path.Combine(Path.GetDirectoryName(manifestFile)!,"core-result.json"),new JsonObject{["Debian"]=host.Number("Debian"),["Assertions"]=assertions,["EvidenceDirectory"]=f.Root,["Status"]="Passed",["SyntheticOnly"]=true,["At"]=DateTimeOffset.UtcNow});secrets.Clear();
        Console.WriteLine($"PASS: {assertions} real Debian {host.Number("Debian")} multi-inbound, multi-user SS2022, AnyTLS, Reality, HTTPS, scoped restart/rollback, reboot, provenance and lost-commit assertions.");
    }
    private sealed class InboundVmValidation(ArchiveStore store,ClientRouteDiagnostics diagnostics,JsonObject ports,string certificate):IInboundValidation
    {
        public bool Fail{get;set;}
        public async Task<JsonObject> ValidateAsync(JsonObject plan,JsonObject model,JsonObject credentials,string[] ids,string directory,IProgress<string> progress,CancellationToken ct)
        {
            if(Fail)throw new OperationException("Disposable post-apply validation interruption.");var items=new JsonArray();
            foreach(var node in InboundRendering.Nodes(store,plan.Text("Provider")+"/"+plan.Text("Instance")+"/May-VPS-Deploy",plan,model,credentials).Where(n=>ids.Contains(n.Text("InboundOrigin.InboundId"))))
            {
                var copy=node.DeepClone().AsObject();var port=ports.Number(node.Number("sing_box.server_port").ToString());copy["clash"]!["server"]="127.0.0.1";copy["clash"]!["port"]=port;copy["sing_box"]!["server"]="127.0.0.1";copy["sing_box"]!["server_port"]=port;
                if(copy.Text("sing_box.type")=="anytls"){copy["sing_box"]!["tls"]!["certificate"]=new JsonArray(certificate);copy["clash"]!["ca-str"]=certificate;}
                Console.WriteLine("VM validating protocol: "+node.Text("sing_box.type"));var scheme=new JsonObject{["Nodes"]=new JsonArray(copy),["Layout"]=new JsonObject{["region_groups"]=new JsonArray(copy.Text("region_group"))}};JsonObject result=new();var repeats=node.Text("sing_box.type")=="vless"?5:1;var passed=0;
                for(var probe=0;probe<repeats;probe++){result=await diagnostics.RunAsync(ClientTopology.DiagnosticRoute(scheme,copy.Text("name")),directory,progress,ct);if(result.Text("Status")!="Reachable")break;passed++;}
                result["ConsecutivePassed"]=passed;ArchiveStore.WriteJson(SafePath.Resolve(directory,"vm-result-"+node.Text("Id")+".json"),result);
                if(result.Text("Status")!="Reachable")foreach(var stage in (result["Stages"] as JsonArray??[]))Console.WriteLine("VM inbound diagnostic: "+stage.Text("Id")+" "+stage.Text("Status")+" "+stage.Text("Detail"));
                items.Add(new JsonObject{["InboundId"]=node.Text("InboundOrigin.InboundId"),["UserId"]=node.Text("InboundOrigin.UserId"),["Family"]=node.Text("InboundOrigin.Family"),["ConnectionFingerprint"]=ClientNodeImport.ConnectionFingerprint(node),["Status"]=result.Text("Status")=="Reachable"?"Passed":"Incomplete",["From"]="Controller",["Scope"]="ProxyHttps",["Udp"]="NotMeasured",["Result"]=result});
            }
            return new JsonObject{["Status"]=items.All(i=>i!.Text("Status")=="Passed")?"Passed":"Incomplete",["Items"]=items};
        }
    }
}
