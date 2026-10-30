using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunHysteriaVmTests(string manifestFile, bool hopping = false, bool tuic = false)
    {
        if(!Path.GetFullPath(manifestFile).Contains(Path.DirectorySeparatorChar+".codex-tmp"+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new Exception("Disposable fixture path required.");var host=ArchiveStore.ReadJson(manifestFile);
        if(!host.Flag("SyntheticOnly")||host.Text("Name")!="Inbound"||host.Number("Debian") is not (12 or 13)||host.Text("UdpAddress")==""||host["UdpApplications"] is not JsonObject)throw new Exception("Disposable QUIC fixture required.");
        if(tuic&&hopping)throw new Exception("TUIC does not use Hysteria port hopping.");var f=new Fixture(repository);using var budget=new CancellationTokenSource(TimeSpan.FromMinutes(12));var ct=budget.Token;var user=new FakeUser();var factory=new TcpChainVmFactory(f.Store,new JsonObject{["Inbound"]=host.DeepClone()});
        Console.WriteLine("Hysteria VM evidence: "+f.Root);async Task<IRemoteSession> Connect()=>await factory.OpenAsync(new(host.Text("Address"),22,"root",host.Text("KeyFile")),user,ct);
        async Task<string> Read(string command){await using var remote=await Connect();var result=await remote.RunAsync(command,TimeSpan.FromSeconds(20),ct);result.RequireSuccess("Disposable Hysteria observation failed.");return result.Output.Trim();}
        var proof=await Read("python3 -c \"from pathlib import Path; print(Path('/etc/may-inbound-fixture').read_text().strip()); print(Path('/sys/class/dmi/id/product_uuid').read_text().strip())\"");Check(proof.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).Length==2&&proof.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries).All(v=>v.Equals(host.Text("FixtureId"),StringComparison.OrdinalIgnoreCase)),"DMI/marker identity mismatch");
        var plan=f.Plan("HysteriaVM-Debian"+host.Number("Debian"));plan["Role"]="MonitorOnly";plan["Roles"]=new JsonArray("MonitorOnly");plan["AdminUser"]="root";plan["ActiveEntry"]="";plan.Put("Import.Status",JsonValue.Create("Completed"));plan.Put("Import.SshAuthenticationPreserved",JsonValue.Create(true));plan.Put("Server.IPv4",JsonValue.Create(host.Text("Address")));plan.Put("Server.IPv6",JsonValue.Create(""));plan.Put("Ports.SshPrimary",JsonValue.Create(22));plan.Put("Ports.SshRescue",JsonValue.Create(2222));plan.Put("Server.BootstrapSshPort",JsonValue.Create(22));plan.Put("SshKey.SourcePrivateKeyPath",JsonValue.Create(host.Text("KeyFile")));plan.Put("Firewall.Mode",JsonValue.Create("ManagedNftables"));plan["ProtocolInventory"]=new JsonObject();foreach(var role in DeploymentPlans.Roles[..3])plan["ProtocolInventory"]![role]=new JsonObject{["Installed"]=false,["Enabled"]=false,["Active"]=false};f.SaveInstance(plan);
        using var key=RSA.Create(2048);var csr=new CertificateRequest("CN=hysteria.example.test",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var san=new SubjectAlternativeNameBuilder();san.AddDnsName("hysteria.example.test");san.AddIpAddress(IPAddress.Loopback);csr.CertificateExtensions.Add(san.Build());csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));using var ca=csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(2));
        var fixture="/opt/may-hysteria-fixture";var https="import http.server,ssl\nclass Handler(http.server.BaseHTTPRequestHandler):\n def do_GET(self):\n  body=b'198.51.100.22';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)\n def log_message(self,*args):pass\ns=http.server.HTTPServer(('127.0.0.1',9443),Handler)\nc=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain('"+fixture+"/https.pem','"+fixture+"/key.pem');s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()\n";
        if(tuic)
        {
            var dns="import socket,threading\ndef dns_loop():\n sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',5353))\n while True:\n  query,peer=sock.recvfrom(4096)\n  if len(query)<17:continue\n  answer=bytearray(query);answer[2]=129;answer[3]=128;answer[7]=1;answer.extend(bytes.fromhex('c00c000100010000000000047f000001'));sock.sendto(answer,peer)\nthreading.Thread(target=dns_loop,daemon=True).start()\n";
            https=dns+https;
        }
        await using(var remote=await Connect())
        {
            var setup="set -euo pipefail\numask 077\ninstall -d -m 0700 "+fixture+"\n";foreach(var (name,content) in new[]{("https.py",https),("https.pem",ca.ExportCertificatePem()),("key.pem",key.ExportPkcs8PrivateKeyPem())})setup+="printf '%s' '"+Convert.ToBase64String(Encoding.UTF8.GetBytes(content))+"' | base64 -d > "+fixture+"/"+name+"\n";
            setup+="cat > /etc/systemd/system/may-round14-https.service <<'MAY_TEST'\n[Service]\nExecStart=/usr/bin/python3 "+fixture+"/https.py\n[Install]\nWantedBy=multi-user.target\nMAY_TEST\nsystemctl daemon-reload\nsystemctl enable --now may-round14-https.service\n";(await remote.RunScriptAsync(setup,TimeSpan.FromSeconds(25),true,ct)).RequireSuccess("Disposable HTTPS setup failed.");
            // This is a new marker-checked guest. Establish the normal managed
            // firewall baseline before testing component transactions against it.
            (await remote.RunScriptAsync(new RemoteAssets(f.Paths).Payload("nftables-apply.sh",new Dictionary<string,string>{{"TCP_PORTS","22,2222"},{"UDP_PORTS",""}}),TimeSpan.FromSeconds(30),true,ct)).RequireSuccess("Disposable managed firewall baseline failed.");
        }
        var model=InboundCatalog.Empty();var credentials=InboundCatalog.EmptyCredentials();var sibling=InboundCatalog.AddInbound(model,credentials,"Shadowsocks2022");var hy=InboundCatalog.AddInbound(model,credentials,tuic?"TuicV5":"Hysteria2");var obfs=InboundCatalog.AddInbound(model,credentials,tuic?"TuicV5":"Hysteria2");var cert=InboundCatalog.ImportCertificate(model,credentials,"TLS identity",ca.ExportCertificatePem(),key.ExportPkcs8PrivateKeyPem());foreach(var item in new[]{hy,obfs}){item["CertificateId"]=cert.Text("Id");item["Options"]!["ServerName"]="hysteria.example.test";}
        if(tuic){obfs["Options"]!["UdpRelayMode"]="quic";obfs["Options"]!["CongestionControl"]="bbr";}else{obfs["Options"]!["ObfsEnabled"]=true;obfs["Options"]!["UploadMbps"]=10;obfs["Options"]!["DownloadMbps"]=30;}
        var second=InboundCatalog.AddUser(model,credentials,"second authenticated user",tuic?"TuicV5":"Password");hy["UserIds"]!.AsArray().Add(second.Text("Id"));
        if(hopping){obfs["Listener"]!["Port"]=22004;hy["Listener"]!["Address"]=host.Text("Address");hy["Options"]!["HopPorts"]="22001-22003";hy["Options"]!["HopIntervalSeconds"]=5;}
        var assets=new ValidationAssets(new AppPaths(repository),"windows-amd64");var tools=new ExternalToolRunner();var target=new Uri("https://127.0.0.1:9443");var endpoints=new ClientDiagnosticEndpoints(target,target,target){Udp4=new(IPAddress.Loopback,5353)};var validator=new HysteriaVmValidation(f.Store,new ClientRouteDiagnostics(assets,tools,endpoints,ca),host);var coordinator=new TaskCoordinator(f.Store,new WorkflowEngine(f.Store,factory,new FakeKeys(),user,new FakeValidation(),inboundValidation:validator));
        var directory=f.Paths.Instance(f.Relative(plan));var stateFile=SafePath.Resolve(directory,"deployment-state.json");var phase="";var progress=new InlineProgress<TaskProgress>(p=>{if(phase!=p.Stage){Console.WriteLine("Hysteria VM: "+p.Stage);phase=p.Stage;}});
        OperationRequest Operation(string action="Apply")=>new(OperationKind.Inbounds,f.Relative(plan),InboundCatalog.Options(ArchiveStore.ReadJson(stateFile),action,model,credentials));async Task<TaskRecord> Execute(string action="Apply"){await Task.Delay(1100,ct);var r=Operation(action);return await coordinator.ExecuteAsync(coordinator.Review(r),r,progress,ct);}
        var applied=await Execute();Check(applied.Outcome==TaskOutcome.Completed,"real managed Hysteria installation failed: "+applied.SafeError);
        var state=ArchiveStore.ReadJson(stateFile);Check(state["Inbounds"]!["ValidationById"]!.AsObject().Count==3,"not every inbound has actual evidence");var ports=new[]{hy.Number("Listener.Port"),obfs.Number("Listener.Port")};
        foreach(var p in ports)Check(await Read("ss -H -ltn 'sport = :"+p+"'")=="","Hysteria unexpectedly exposed a TCP listener");
        var rules=await Read("nft list chain inet filter input");Check(ports.All(p=>rules.Split('\n').Any(l=>l.Contains("udp dport")&&l.Contains(p.ToString())))&&ports.All(p=>!rules.Split('\n').Any(l=>l.Contains("tcp dport")&&l.Contains(p.ToString()))),"managed firewall opened the wrong transport");
        if(hopping)
        {
            var redirect=await Read("nft list chain inet filter may_hysteria_hopping");Check(redirect.Contains("22002, 22003")&&redirect.Contains("dnat ip to "+host.Text("Address")+":22001"),"real nftables redirect did not preserve the specific listener and full port set");
            Check(await Read("ss -H -lun 'sport = :22002 or sport = :22003'")=="","hopping added a second service socket");
            await Read("nft -c -f /etc/nftables.conf && systemctl restart nftables");Check((await Execute("Check")).Outcome==TaskOutcome.Completed,"persistent hopping firewall differed from runtime after reload");
        }
        async Task<string> Invocation(string id)=>await Read("systemctl show "+InboundRendering.Unit(id)+" -p InvocationID --value");var siblingIdentity=await Invocation(sibling.Text("Id"));var oldUser=credentials.Text("Users."+hy.Strings("UserIds")[0]+".Value");credentials["Users"]![hy.Strings("UserIds")[0]]!["Value"]=ServerConfigurations.RandomKey(32);Check((await Execute()).Outcome==TaskOutcome.Completed&&await Invocation(sibling.Text("Id"))==siblingIdentity,"user rotation restarted an unrelated inbound");
        validator.Fail=true;var previousRegistry=await Read("sha256sum /etc/may-inbounds/model.json");var previousFirewall=await Read("sha256sum /etc/nftables.conf");credentials["Users"]![hy.Strings("UserIds")[0]]!["Value"]=oldUser;var failed=await Execute();Check(failed.Outcome==TaskOutcome.Failed&&await Read("sha256sum /etc/may-inbounds/model.json")==previousRegistry&&await Read("sha256sum /etc/nftables.conf")==previousFirewall&&await Invocation(sibling.Text("Id"))==siblingIdentity,"failure did not restore exact inbound/firewall scope");
        credentials=f.Store.ReadSecret(SafePath.Resolve(directory,"secrets.dotnet.private.json"))["Inbounds"]!.DeepClone().AsObject();validator.Fail=false;
        if(tuic)
        {
            credentials["Users"]![hy.Strings("UserIds")[0]]!["Uuid"]=Guid.NewGuid().ToString();Check((await Execute()).Outcome==TaskOutcome.Completed&&await Invocation(sibling.Text("Id"))==siblingIdentity,"TUIC UUID rotation restarted an unrelated service");
            var before=await Read("sha256sum /etc/may-inbounds/model.json");await Read("nft add table inet may_fixture_udp_block; nft 'add chain inet may_fixture_udp_block out { type filter hook output priority -110; policy accept; }'; nft add rule inet may_fixture_udp_block out udp dport 5353 drop");
            try{credentials["Users"]![hy.Strings("UserIds")[0]]!["Value"]=ServerConfigurations.RandomKey(32);Check((await Execute()).Outcome==TaskOutcome.Failed&&await Read("sha256sum /etc/may-inbounds/model.json")==before,"TUIC HTTPS-only success masked blocked application UDP or failed to recover");}
            finally{await Read("nft delete table inet may_fixture_udp_block");}
            credentials=f.Store.ReadSecret(SafePath.Resolve(directory,"secrets.dotnet.private.json"))["Inbounds"]!.DeepClone().AsObject();Check((await Execute("Check")).Outcome==TaskOutcome.Completed,"TUIC UDP did not recover after test-only interruption");
        }
        if(hopping)
        {
            var before=await Read("sha256sum /etc/nftables.conf");
            await Read("nft add table inet may_fixture_block; nft 'add chain inet may_fixture_block pre { type filter hook prerouting priority -110; policy accept; }'; nft add rule inet may_fixture_block pre udp dport 22003 drop");
            try{credentials["Users"]![hy.Strings("UserIds")[0]]!["Value"]=ServerConfigurations.RandomKey(32);Check((await Execute()).Outcome==TaskOutcome.Failed&&await Read("sha256sum /etc/nftables.conf")==before&&await Invocation(sibling.Text("Id"))==siblingIdentity,"one blocked alias did not fail validation and restore only its scope");}
            finally{await Read("nft delete table inet may_fixture_block");}
            credentials=f.Store.ReadSecret(SafePath.Resolve(directory,"secrets.dotnet.private.json"))["Inbounds"]!.DeepClone().AsObject();Check((await Execute("Check")).Outcome==TaskOutcome.Completed,"restored hopping ports failed after removing the test-only interruption");
        }
        hy["Enabled"]=false;Check((await Execute()).Outcome==TaskOutcome.Completed,"disable failed");if(hopping)Check(await Read("nft list table inet filter | grep -c may_hysteria_hopping || true")=="0","disabled hopping left its redirect chain");Refuses(()=>InboundSources.Create(f.Store,f.Relative(plan),hy.Text("Id"),hy.Strings("UserIds")[0],"IPv4"),"disabled Hysteria source remained exportable");hy["Enabled"]=true;Check((await Execute()).Outcome==TaskOutcome.Completed,"re-enable failed");
        var replacement=InboundCertificate("hysteria.example.test");InboundCatalog.ReplaceCertificate(cert,credentials,replacement.Certificate,replacement.Key);Check((await Execute()).Outcome==TaskOutcome.Completed&&await Invocation(sibling.Text("Id"))==siblingIdentity,"certificate replacement affected unrelated service");
        factory.Fault="inbound-commit-ack";hy["Name"]="renamed Hysteria";Check((await Execute()).Outcome==TaskOutcome.CompletedWithWarnings&&factory.LostAcknowledgements==1,"lost commit acknowledgement was not reconciled");
        var boot=await Read("cat /proc/sys/kernel/random/boot_id");await using(var remote=await Connect()){try{await remote.RunAsync("systemctl reboot",TimeSpan.FromSeconds(5),ct);}catch(IOException){}}
        var rebooted=false;for(var i=0;i<90;i++){await Task.Delay(1500,ct);try{if(await Read("cat /proc/sys/kernel/random/boot_id")!=boot){rebooted=true;break;}}catch(Exception e)when(e is IOException or OperationException or Renci.SshNet.Common.SshException or System.Net.Sockets.SocketException){}}
        Check(rebooted&&(await Execute("Check")).Outcome==TaskOutcome.Completed,"Hysteria service did not recover after reboot");
        var export=ClientSchemes.New(f.Paths);foreach(var node in InboundRendering.Nodes(f.Store,f.Relative(plan),plan,model,credentials))ForwardedNodeSources.Apply(f.Store,export,[InboundSources.Create(f.Store,f.Relative(plan),node.Text("InboundOrigin.InboundId"),node.Text("InboundOrigin.UserId"),"IPv4")],"US-West-LA Entry");var workbench=new ClientWorkbench(f.Store,tools,assets,Environment.GetEnvironmentVariable("MAY_TEST_PYTHON")??"python");await workbench.BuildAsync(export,ct);await workbench.ValidateAsync(export,ct);Check(export.Text("Candidate.ValidationStatus")=="Passed"&&export["Nodes"]!.AsArray().Count==4,"real per-user dual-client generation failed");
        foreach(var item in InboundCatalog.Items(model,"Inbounds").ToArray())InboundCatalog.RemoveEntity(model,credentials,"Inbounds",item.Text("Id"));Check((await Execute()).Outcome==TaskOutcome.Completed,"Hysteria removal failed");Check(await Read("test ! -e /var/lib/may-vps-deploy/transaction.owner && printf CLEAN")=="CLEAN","removal left transaction ownership");credentials.Clear();
        ArchiveStore.WriteJson(Path.Combine(Path.GetDirectoryName(manifestFile)!,tuic?"tuic-result.json":"hysteria-result.json"),new JsonObject{["Status"]="Passed",["Assertions"]=assertions,["Debian"]=host.Number("Debian"),["Protocol"]=tuic?"TuicV5":"Hysteria2",["Hopping"]=hopping,["EvidenceDirectory"]=f.Root,["SyntheticOnly"]=true,["At"]=DateTimeOffset.UtcNow});Console.WriteLine($"PASS: {assertions} real Debian {host.Number("Debian")} {(tuic?"TUIC v5":"Hysteria2")} QUIC, two users, firewall, hopping={hopping}, rotation, disable/enable, certificate, rollback, reboot and dual-client assertions.");
    }
    private sealed class HysteriaVmValidation(ArchiveStore store,ClientRouteDiagnostics diagnostics,JsonObject host):IInboundValidation
    {
        public bool Fail{get;set;}
        public async Task<JsonObject> ValidateAsync(JsonObject plan,JsonObject model,JsonObject credentials,string[] ids,string directory,IProgress<string> progress,CancellationToken ct)
        {
            if(Fail)throw new OperationException("Disposable post-apply Hysteria interruption.");var items=new JsonArray();foreach(var original in InboundRendering.Nodes(store,plan.Text("Provider")+"/"+plan.Text("Instance")+"/May-VPS-Deploy",plan,model,credentials).Where(n=>ids.Contains(n.Text("InboundOrigin.InboundId"))))
            {
                var quic=original.Text("sing_box.type") is "hysteria2" or "tuic";var udpRequired=InboundRendering.RequiresApplicationUdp(store,plan.Text("Provider")+"/"+plan.Text("Instance")+"/May-VPS-Deploy",model,original.Text("InboundOrigin.InboundId"));var datagram=original.Text("sing_box.type")=="shadowsocks"&&udpRequired;var ports=Hysteria2Ports.ValidationPorts(original);var passed=new List<int>();JsonObject result=new();
                foreach(var guestPort in ports.Length>0?ports:[original.Number("sing_box.server_port")])
                {
                    var node=original.DeepClone().AsObject();await using var tunnel=quic||datagram?await HysteriaVmTunnel.Start(host,guestPort,ct):null;await using var tcpBridge=datagram?new HysteriaVmTcpBridge(tunnel!.Port,host.Number("Applications."+guestPort)):null;var port=quic||datagram?tunnel!.Port:host.Number("Applications."+guestPort);node["sing_box"]!["server"]="127.0.0.1";node["sing_box"]!["server_port"]=port;var native=node["sing_box"]!.AsObject();native.Remove("server_ports");native.Remove("hop_interval");
                    if(quic||original.Text("sing_box.type")=="anytls"){var inbound=InboundCatalog.Items(model,"Inbounds").Single(i=>i.Text("Id")==original.Text("InboundOrigin.InboundId"));node["sing_box"]!["tls"]!["certificate"]=new JsonArray(credentials.Text("Certificates."+inbound.Text("CertificateId")+".CertificatePem"));}
                    var scheme=new JsonObject{["Nodes"]=new JsonArray(node),["Layout"]=new JsonObject{["region_groups"]=new JsonArray(node.Text("region_group"))}};var route=ClientTopology.DiagnosticRoute(scheme,node.Text("name")) with {RequiresApplicationUdp=InboundRendering.RequiresApplicationUdp(store,plan.Text("Provider")+"/"+plan.Text("Instance")+"/May-VPS-Deploy",model,original.Text("InboundOrigin.InboundId"))};result=await diagnostics.RunAsync(route,directory,progress,ct);ArchiveStore.WriteJson(SafePath.Resolve(directory,"hysteria-result-"+original.Text("Id")+"-"+guestPort+".json"),result);if(result.Text("Status")!="Reachable"){Console.WriteLine("Hysteria VM diagnostic: "+result["Stages"]!.ToJsonString());break;}passed.Add(guestPort);
                }
                var item=new JsonObject{["InboundId"]=original.Text("InboundOrigin.InboundId"),["UserId"]=original.Text("InboundOrigin.UserId"),["Family"]=original.Text("InboundOrigin.Family"),["ConnectionFingerprint"]=ClientNodeImport.ConnectionFingerprint(original),["Status"]=result.Text("Status")=="Reachable"?"Passed":"Incomplete",["From"]="Controller",["Scope"]="ProxyHttps",["Udp"]=result.Flag("UdpValidation.ResponseMatched")?"Passed":"NotMeasured",["Result"]=result};if(ports.Length>0)item["HopPorts"]=new JsonArray(passed.Select(p=>(JsonNode?)JsonValue.Create(p)).ToArray());items.Add(item);
            }
            return new JsonObject{["Status"]=items.All(i=>i!.Text("Status")=="Passed")?"Passed":"Incomplete",["Items"]=items};
        }
    }
    // SS uses one endpoint for TCP and UDP. Use an owned loopback TCP bridge
    // alongside the UDP fixture socket instead of binding a WSL-reserved port.
    private sealed class HysteriaVmTcpBridge : IAsyncDisposable
    {
        private readonly TcpListener listener; private readonly CancellationTokenSource stop = new(); private readonly List<Task> clients = new(); private readonly Task worker;
        public HysteriaVmTcpBridge(int port, int target)
        {
            listener = new(IPAddress.Loopback, port); listener.Start();
            worker = Task.Run(async () => { try { while (!stop.IsCancellationRequested) { var client = await listener.AcceptTcpClientAsync(stop.Token); clients.Add(Forward(client, target)); } } catch (Exception error) when (error is OperationCanceledException or SocketException or ObjectDisposedException) { } });
        }
        private async Task Forward(TcpClient client, int target)
        {
            using (client) using (var upstream = new TcpClient())
            {
                try { client.NoDelay = true; upstream.NoDelay = true; await upstream.ConnectAsync(IPAddress.Loopback, target, stop.Token); var send = client.GetStream().CopyToAsync(upstream.GetStream(), stop.Token); var receive = upstream.GetStream().CopyToAsync(client.GetStream(), stop.Token); await Task.WhenAny(send, receive); upstream.Dispose(); client.Dispose(); try { await Task.WhenAll(send, receive); } catch (IOException) { } }
                catch (Exception error) when (error is OperationCanceledException or IOException or SocketException or ObjectDisposedException) { }
            }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await worker; await Task.WhenAll(clients).WaitAsync(TimeSpan.FromSeconds(5)); stop.Dispose(); }
    }
    private sealed class HysteriaVmTunnel: IAsyncDisposable
    {
        private readonly TcpClient tcp=new();private readonly UdpClient udp;private readonly CancellationTokenSource stop=new();private Task worker=Task.CompletedTask;public int Port=>((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        private HysteriaVmTunnel(int localPort){udp=new(new IPEndPoint(IPAddress.Loopback,localPort));}
        public static async Task<HysteriaVmTunnel> Start(JsonObject host,int port,CancellationToken ct,int localPort=0)
        {
            var tunnel=new HysteriaVmTunnel(localPort);try{await tunnel.tcp.ConnectAsync(IPAddress.Loopback,host.Number("DatagramTunnelPort"),ct);var stream=tunnel.tcp.GetStream();var hello=Encoding.UTF8.GetBytes(new JsonObject{["Token"]=host.Text("DatagramTunnelToken"),["Port"]=port}.ToJsonString(System.Text.Json.JsonSerializerOptions.Default)+"\n");await stream.WriteAsync(hello,ct);tunnel.worker=tunnel.Forward(stream);return tunnel;}catch{await tunnel.DisposeAsync();throw;}
        }
        private async Task Forward(NetworkStream stream)
        {
            IPEndPoint? source=null;
            async Task Send(){while(!stop.IsCancellationRequested){try{var p=await udp.ReceiveAsync(stop.Token);source=p.RemoteEndPoint;var h=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(h,checked((ushort)p.Buffer.Length));await stream.WriteAsync(h,stop.Token);await stream.WriteAsync(p.Buffer,stop.Token);}catch(SocketException e)when(e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused){}}}
            async Task Receive(){while(!stop.IsCancellationRequested){var h=new byte[2];await stream.ReadExactlyAsync(h,stop.Token);var size=BinaryPrimitives.ReadUInt16BigEndian(h);if(size==0||size>65507)throw new IOException("Invalid fixture datagram.");var data=new byte[size];await stream.ReadExactlyAsync(data,stop.Token);if(source!=null)await udp.SendAsync(data,source,stop.Token);}}
            try{await Task.WhenAll(Send(),Receive());}catch(Exception e)when(e is IOException or SocketException or OperationCanceledException or ObjectDisposedException){}
        }
        public async ValueTask DisposeAsync(){stop.Cancel();tcp.Dispose();udp.Dispose();await worker;stop.Dispose();}
    }
}
