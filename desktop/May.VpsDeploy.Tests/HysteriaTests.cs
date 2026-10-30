using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunHysteriaTests()
    {
        await HysteriaModelBoundary();
        await HysteriaLoopback();
        Console.WriteLine($"PASS: {assertions} real UDP-only Hysteria2 authentication, HTTPS, UDP echo and negative-path assertions; loopback only.");
    }
    private async Task HysteriaModelBoundary()
    {
        using var f=new Fixture(repository);var plan=f.Plan("Hysteria-model");plan.Put("Import.Status",JsonValue.Create("Completed"));plan.Put("Firewall.Mode",JsonValue.Create("PreserveExisting"));f.SaveInstance(plan);
        var model=InboundCatalog.Empty();var credentials=InboundCatalog.EmptyCredentials();var inbound=InboundCatalog.AddInbound(model,credentials,"Hysteria2");var id=inbound.Text("Id");
        Refuses(()=>InboundCatalog.Normalize(model,credentials),"Hysteria2 accepted absent TLS certificate");var pem=InboundCertificate("hysteria.example.test");var certificate=InboundCatalog.ImportCertificate(model,credentials,"certificate",pem.Certificate,pem.Key);inbound["CertificateId"]=certificate.Text("Id");inbound["Options"]!["ServerName"]="hysteria.example.test";
        _=InboundCatalog.Normalize(model,credentials);Check(InboundCatalog.UserKind(inbound)=="Password"&&InboundCatalog.UdpOnly(inbound)&&InboundCatalog.UsesUdp(inbound),"Hysteria2 identity/transport metadata incorrect");
        var config=InboundRendering.Configuration(f.Store,plan,model,credentials,inbound);Check(config["inbounds"]![0]!.Text("type")=="hysteria2"&&config["inbounds"]![0]!.Flag("ignore_client_bandwidth")&&!config["inbounds"]![0]!.AsObject().ContainsKey("up_mbps"),"default adaptive control was not rendered");
        var bad=model.DeepClone().AsObject();bad["Inbounds"]![0]!["Options"]!["UploadMbps"]=10;Refuses(()=>InboundCatalog.Normalize(bad,credentials),"half specified bandwidth accepted");bad["Inbounds"]![0]!["Options"]!["DownloadMbps"]=-1;Refuses(()=>InboundCatalog.Normalize(bad,credentials),"negative bandwidth accepted");
        bad=model.DeepClone().AsObject();bad["Inbounds"]![0]!["Options"]!["ServerName"]="wrong.example.test";Refuses(()=>InboundCatalog.Normalize(bad,credentials),"Hysteria2 accepted unmatched SNI");
        inbound["Options"]!["UploadMbps"]=20;inbound["Options"]!["DownloadMbps"]=80;inbound["Options"]!["ObfsEnabled"]=true;config=InboundRendering.Configuration(f.Store,plan,model,credentials,inbound);Check(config["inbounds"]![0]!.Number("up_mbps")==80&&config["inbounds"]![0]!.Number("down_mbps")==20,"server bandwidth did not reverse client perspective");
        var node=InboundRendering.Nodes(f.Store,f.Relative(plan),plan,model,credentials).Single();Check(node.Number("sing_box.up_mbps")==20&&node.Number("sing_box.down_mbps")==80&&node.Text("clash.up")=="20 Mbps"&&node.Text("clash.obfs")=="salamander"&&node.Text("sing_box.obfs.password")==credentials.Text("Inbounds."+id+".ObfsPassword"),"dual-client fields diverged");
        var assets=new ValidationAssets(new AppPaths(repository),"windows-amd64");var tools=new ExternalToolRunner();
        if(OperatingSystem.IsWindows()){var file=f.Paths.Resolve("private/hysteria-render.json");ArchiveStore.WriteJson(file,config);(await tools.RunAsync(assets.ResolveCore("sing-box"),["check","-c",file],null,TimeSpan.FromSeconds(10),default)).RequireSuccess("Hysteria2 rendered server config invalid.");Check(true,"server core rejected configuration");}
        else Console.WriteLine("SKIP: bundled Hysteria2 executable checks require Windows; model and transaction assertions still run.");
        var stateFile=SafePath.Resolve(f.Paths.Instance(f.Relative(plan)),"deployment-state.json");var remote=new InboundTestRemote();remote.Inner.SeedProtocols(plan);var validator=new HysteriaMockValidation(f.Store);var coordinator=new TaskCoordinator(f.Store,new WorkflowEngine(f.Store,remote,new FakeKeys(),new FakeUser(),new FakeValidation(),inboundValidation:validator));
        OperationRequest Operation()=>new(OperationKind.Inbounds,f.Relative(plan),InboundCatalog.Options(ArchiveStore.ReadJson(stateFile),"Apply",model,credentials));
        validator.Typed=false;var rejected=await coordinator.ExecuteAsync(coordinator.Review(Operation()),Operation(),new InlineProgress<TaskProgress>(_=>{}),default);Check(rejected.Outcome==TaskOutcome.Failed&&remote.Current==null,"generic HTTPS-only evidence was accepted for Hysteria2");validator.Typed=true;
        Check((await coordinator.ExecuteAsync(coordinator.Review(Operation()),Operation(),new InlineProgress<TaskProgress>(_=>{}),default)).Outcome==TaskOutcome.Completed,"typed Hysteria2 workflow failed");var selected=InboundSources.Create(f.Store,f.Relative(plan),id,inbound.Strings("UserIds")[0],"IPv4");var scheme=ClientSchemes.New(f.Paths);ForwardedNodeSources.Apply(f.Store,scheme,[selected],"US-West-LA Entry");
        var python=Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
        if(OperatingSystem.IsWindows()&&!string.IsNullOrEmpty(python)){var workbench=new ClientWorkbench(f.Store,tools,assets,python);await workbench.BuildAsync(scheme,default);await workbench.ValidateAsync(scheme,default);Check(scheme.Text("Candidate.ValidationStatus")=="Passed","dual-client Hysteria2 builder/core validation failed");}
        else Console.WriteLine("SKIP: dual-client Hysteria2 builder/core check requires Windows and MAY_TEST_PYTHON with pinned YAML dependencies.");
        var reviewed=coordinator.Review(Operation());var password=credentials.Text("Users."+inbound.Strings("UserIds")[0]+".Value");Check(!reviewed.Summary.Contains(password)&&!reviewed.Summary.Contains(credentials.Text("Inbounds."+id+".ObfsPassword")),"review exposed authentication material");
        OperationRequest Upgrade()=>new(OperationKind.Inbounds,f.Relative(plan),InboundCatalog.Options(ArchiveStore.ReadJson(stateFile),"UpgradeSingBox",model,credentials));Refuses(()=>coordinator.Review(Upgrade()),"same pinned core was treated as an upgrade");var oldCore=ArchiveStore.ReadJson(stateFile)["Inbounds"]!["Core"]!.DeepClone();var versions=f.Versions;versions.Put("sing_box.version",JsonValue.Create("1.14.3"));versions.Put("sing_box.assets.amd64.name",JsonValue.Create("sing-box-1.14.3-linux-amd64.tar.gz"));versions.Put("sing_box.assets.amd64.sha256",JsonValue.Create(new string('f',64)));ArchiveStore.WriteJson(f.Paths.Resolve("config/versions.json"),versions);
        var upgradePreview=InboundCatalog.Prepare(f.Store,Upgrade());Check(upgradePreview.Affected.SequenceEqual(new[]{id})&&JsonNode.DeepEquals(upgradePreview.Payload["Core"]!["Reality"],oldCore["Reality"]),"core update lost affected scope or changed the Xray pin");validator.Typed=false;Check((await coordinator.ExecuteAsync(coordinator.Review(Upgrade()),Upgrade(),new InlineProgress<TaskProgress>(_=>{}),default)).Outcome==TaskOutcome.Failed&&JsonNode.DeepEquals(ArchiveStore.ReadJson(stateFile)["Inbounds"]!["Core"],oldCore),"failed core update did not restore the old pin");validator.Typed=true;Check((await coordinator.ExecuteAsync(coordinator.Review(Upgrade()),Upgrade(),new InlineProgress<TaskProgress>(_=>{}),default)).Outcome==TaskOutcome.Completed&&ArchiveStore.ReadJson(stateFile).Text("Inbounds.Core.Version")=="1.14.3","explicit pinned core update failed");Refuses(()=>InboundSources.VerifyNodes(f.Store,[selected]),"upgraded core retained an obsolete client resource fingerprint");credentials.Clear();
    }
    private sealed class HysteriaMockValidation(ArchiveStore store):IInboundValidation
    {
        public bool Typed{get;set;}=true;
        public Task<JsonObject> ValidateAsync(JsonObject plan,JsonObject model,JsonObject credentials,string[] ids,string directory,IProgress<string> progress,CancellationToken ct)
        {
            var items=new JsonArray();foreach(var node in InboundRendering.Nodes(store,plan.Text("Provider")+"/"+plan.Text("Instance")+"/May-VPS-Deploy",plan,model,credentials).Where(n=>ids.Contains(n.Text("InboundOrigin.InboundId"))))
            {
                var item=new JsonObject{["InboundId"]=node.Text("InboundOrigin.InboundId"),["UserId"]=node.Text("InboundOrigin.UserId"),["Family"]=node.Text("InboundOrigin.Family"),["ConnectionFingerprint"]=ClientNodeImport.ConnectionFingerprint(node),["Status"]="Passed",["From"]="Controller",["Scope"]="ProxyHttps",["Result"]=new JsonObject{["Status"]="Reachable",["ValidatedProtocol"]=Typed?"hysteria2":"tcp"}};
                if(Hysteria2Ports.ValidationPorts(node) is { Length: > 0 } ports)item["HopPorts"]=new JsonArray(ports.Select(p=>(JsonNode?)JsonValue.Create(p)).ToArray());items.Add(item);
            }
            return Task.FromResult(new JsonObject{["Status"]="Passed",["Items"]=items});
        }
    }
    private async Task HysteriaLoopback()
    {
        if(!OperatingSystem.IsWindows()){Console.WriteLine("SKIP: native Hysteria2 loopback requires the bundled Windows core; Debian runtime is verified by the disposable VM suite.");return;}
        using var f = new Fixture(repository); using var budget = new CancellationTokenSource(TimeSpan.FromMinutes(3)); var ct = budget.Token;
        var assets = new ValidationAssets(new AppPaths(repository), OperatingSystem.IsWindows() ? "windows-amd64" : "linux-amd64"); var tools = new ExternalToolRunner(); var core = assets.ResolveCore("sing-box");
        using var key = RSA.Create(2048); var csr = new CertificateRequest("CN=hysteria.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("hysteria.example.test"); san.AddIpAddress(IPAddress.Loopback); csr.CertificateExtensions.Add(san.Build()); csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        await using var https = await HysteriaHttpsTarget.Start(repository, f, certificate, key, ct); await using var echo = new HysteriaEchoTarget();
        var plan = f.Plan("Hysteria-loopback"); f.SaveInstance(plan); var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, secrets, "Hysteria2"); var cert = InboundCatalog.ImportCertificate(model, secrets, "test certificate", certificate.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()); inbound["CertificateId"] = cert.Text("Id"); inbound["Options"]!["ServerName"] = "hysteria.example.test";
        inbound["Listener"]!["Port"] = UdpPort(); var extra = InboundCatalog.AddUser(model, secrets, "second authenticated user", "Password"); inbound["UserIds"]!.AsArray().Add(extra.Text("Id")); _ = InboundCatalog.Normalize(model, secrets);
        var serverConfig = InboundRendering.Configuration(f.Store, plan, model, secrets, inbound); serverConfig["inbounds"]![0]!["listen"] = "127.0.0.1";
        var directory = f.Paths.Resolve("private/hysteria-runtime"); Directory.CreateDirectory(directory);
        await using var server = await HysteriaCore.Start(core, tools, serverConfig, directory, "server", ct);
        await using var relay = new HysteriaUdpRelay(inbound.Number("Listener.Port"));
        using (var tcp = new TcpClient()) { var refused = false; try { await tcp.ConnectAsync(IPAddress.Loopback, relay.Port, ct); } catch (SocketException) { refused = true; } Check(refused, "UDP-only fixture accidentally had a TCP listener"); }
        var nodes = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).ToArray();
        async Task<bool> Probe(JsonObject original, bool trust = true, bool udp = false)
        {
            var node = original.DeepClone().AsObject(); node["sing_box"]!["server"] = "127.0.0.1"; node["sing_box"]!["server_port"] = relay.Port; if (trust) node["sing_box"]!["tls"]!["certificate"] = new JsonArray(certificate.ExportCertificatePem());
            if (!udp)
            {
                var selected=new JsonObject { ["Nodes"]=new JsonArray(node), ["Layout"]=new JsonObject { ["region_groups"]=new JsonArray(node.Text("region_group")) } }; var target=new Uri("https://127.0.0.1:"+https.Port);
                var diagnostics=new ClientRouteDiagnostics(assets,tools,new(target,target,target),certificate);var result=await diagnostics.RunAsync(ClientTopology.DiagnosticRoute(selected,node.Text("name")),directory,new InlineProgress<string>(_=>{}),ct);
                if(Environment.GetEnvironmentVariable("MAY_HYSTERIA_TRACE")=="1"&&result.Text("Status")!="Reachable")Console.WriteLine("Hysteria diagnostic stages: "+result["Stages"]!.ToJsonString());
                return result.Text("Status")=="Reachable"&&result.Text("ValidatedProtocol")=="hysteria2"&&result["Stages"]!.AsArray().All(s=>s!.Text("Id")!="Tcp");
            }
            var mixed = TcpPort(); var chain = TcpPort(); while(chain==mixed)chain=TcpPort(); var datagram = UdpPort(); var scheme = new JsonObject { ["Nodes"] = new JsonArray(node), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray(node.Text("region_group")) } }; var config = ClientTopology.DiagnosticConfiguration(ClientTopology.DiagnosticRoute(scheme, node.Text("name")), mixed, chain);
            config["inbounds"]!.AsArray().Add(new JsonObject { ["type"] = "direct", ["tag"] = "udp-echo", ["listen"] = "127.0.0.1", ["listen_port"] = datagram, ["network"] = "udp", ["override_address"] = "127.0.0.1", ["override_port"] = echo.Port }); config["route"]!["rules"]!.AsArray().Add(new JsonObject { ["inbound"] = new JsonArray("udp-echo"), ["outbound"] = "diagnostic-entry" });
            await using var client = await HysteriaCore.Start(core, tools, config, directory, "client-" + Guid.NewGuid().ToString("N"), ct);
            using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var nonce = RandomNumberGenerator.GetBytes(47); await socket.SendAsync(nonce, new IPEndPoint(IPAddress.Loopback, datagram), ct);
            try { var packet = await socket.ReceiveAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(3), ct); return packet.Buffer.AsSpan().SequenceEqual(nonce); } catch (TimeoutException) { return false; }
        }
        foreach (var node in nodes) Check(await Probe(node), "real QUIC-authenticated per-user HTTPS did not reach the controlled target");
        Check(await Probe(nodes[0], udp: true) && relay.Forwarded > 0 && echo.Packets == 1, "application UDP echo did not traverse encrypted Hysteria2");
        var before = https.Requests; var wrong = nodes[0].DeepClone().AsObject(); wrong["sing_box"]!["password"] = "wrong-synthetic-authentication"; Check(!await Probe(wrong) && https.Requests == before, "incorrect user password reached HTTPS target");
        Check(!await Probe(nodes[0], trust: false) && https.Requests == before, "untrusted Hysteria2 certificate was accepted");
        relay.Drop = true; using (var decoy = new TcpListener(IPAddress.Loopback, relay.Port)) { decoy.Start(); using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, relay.Port, ct); Check(!await Probe(nodes[0]) && https.Requests == before, "open TCP port masked blocked UDP/QUIC"); }
        relay.Drop = false; Check(await Probe(nodes[0]), "QUIC path did not recover after UDP block removal");
        inbound["Options"]!["ObfsEnabled"] = true; var obfuscated = InboundRendering.Configuration(f.Store, plan, model, secrets, inbound); obfuscated["inbounds"]![0]!["listen"] = "127.0.0.1"; await server.Stop();
        await using var obfsServer = await HysteriaCore.Start(core, tools, obfuscated, directory, "obfuscated-server", ct); var obfsNode = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).First();
        Check(await Probe(obfsNode) && await Probe(obfsNode, udp: true), "Salamander HTTPS or application UDP failed"); before = https.Requests; var wrongObfs = obfsNode.DeepClone().AsObject(); wrongObfs["sing_box"]!["obfs"]!["password"] = "wrong-synthetic-obfuscation"; Check(!await Probe(wrongObfs) && https.Requests == before, "wrong Salamander credential reached the target"); secrets.Clear();
    }
    private static int TcpPort() { using var socket = new TcpListener(IPAddress.Loopback, 0); socket.Start(); return ((IPEndPoint)socket.LocalEndpoint).Port; }
    private static int UdpPort() { using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)socket.Client.LocalEndPoint!).Port; }
    private sealed class HysteriaCore(Process process, Task<string> output, Task<string> error) : IAsyncDisposable
    {
        public Process Process => process;
        public static async Task<HysteriaCore> Start(string executable, IExternalToolRunner tools, JsonObject config, string directory, string name, CancellationToken ct)
        {
            var file = SafePath.Resolve(directory, name + ".private.json"); config["log"] = new JsonObject { ["disabled"] = true }; ArchiveStore.WriteJson(file, config); (await tools.RunAsync(executable, ["check", "-c", file], null, TimeSpan.FromSeconds(10), ct)).RequireSuccess("Fixed core rejected Hysteria2 fixture.");
            var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var arg in new[] { "run", "-c", file }) start.ArgumentList.Add(arg); var child = Process.Start(start)!; var running=new HysteriaCore(child, child.StandardOutput.ReadToEndAsync(), child.StandardError.ReadToEndAsync());
            // Wait for the configured local UDP sockets, not a fixed sleep. This
            // only gates fixture startup; protocol success still needs a reply.
            var ports=config["inbounds"]!.AsArray().Where(i=>i!.Text("type") is "hysteria2" or "tuic"||i!.Text("network")=="udp").Select(i=>i!.Number("listen_port")).ToArray();var deadline=Stopwatch.StartNew();
            try
            {
                while(true)
                {
                    ct.ThrowIfCancellationRequested();if(child.HasExited)throw new IOException("Hysteria2 fixture core exited before its UDP listener was ready.");
                    var listeners=IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();if(ports.All(p=>listeners.Any(e=>e.Address.Equals(IPAddress.Loopback)&&e.Port==p)))return running;
                    if(deadline.Elapsed>TimeSpan.FromSeconds(8))throw new TimeoutException("Hysteria2 fixture UDP listener did not become ready.");await Task.Delay(25,ct);
                }
            }
            catch{await running.DisposeAsync();throw;}
        }
        public async Task Stop() { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); await Task.WhenAll(output,error); }
        public async ValueTask DisposeAsync() { await Stop(); process.Dispose(); }
    }
    private sealed class HysteriaUdpRelay : IAsyncDisposable
    {
        private readonly UdpClient socket = new(new IPEndPoint(IPAddress.Loopback, 0)); private readonly CancellationTokenSource stop = new(); private readonly Task worker; public volatile bool Drop; public int Forwarded; public int Port => ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
        public HysteriaUdpRelay(int serverPort)
        {
            worker=Task.Run(async()=>{IPEndPoint? client=null;var server=new IPEndPoint(IPAddress.Loopback,serverPort);
                try{while(!stop.IsCancellationRequested){try{var p=await socket.ReceiveAsync(stop.Token);if(Drop)continue;var fromServer=p.RemoteEndPoint.Equals(server);if(!fromServer)client=p.RemoteEndPoint;var target=fromServer?client:server;if(target!=null){await socket.SendAsync(p.Buffer,target,stop.Token);Interlocked.Increment(ref Forwarded);}}
                    // Windows reports late ICMP errors from disposed test clients
                    // on the next receive. They must not terminate the relay.
                    catch(SocketException e)when(e.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused){}}}
                catch(Exception e)when(e is OperationCanceledException or SocketException or ObjectDisposedException){}
            });
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); socket.Dispose(); await worker; stop.Dispose(); }
    }
    private sealed class HysteriaEchoTarget : IAsyncDisposable
    {
        private readonly UdpClient socket = new(new IPEndPoint(IPAddress.Loopback, 0)); private readonly CancellationTokenSource stop = new(); private readonly Task worker; public int Packets; public int Port => ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
        public HysteriaEchoTarget() { worker = Task.Run(async () => { try { while (!stop.IsCancellationRequested) { try { var p = await socket.ReceiveAsync(stop.Token); Interlocked.Increment(ref Packets); await socket.SendAsync(p.Buffer, p.RemoteEndPoint, stop.Token); } catch(SocketException error)when(error.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused) { } } } catch (Exception error) when (error is OperationCanceledException or SocketException or ObjectDisposedException) { } }); }
        public async ValueTask DisposeAsync() { stop.Cancel(); socket.Dispose(); await worker; stop.Dispose(); }
    }
    private sealed class HysteriaHttpsTarget : IAsyncDisposable
    {
        private readonly Process process; private readonly Task worker; private readonly Task<string> error; public int Requests; public int Port { get; }
        private HysteriaHttpsTarget(Process process, int port)
        {
            this.process=process;Port=port;error=process.StandardError.ReadToEndAsync();worker=Task.Run(async()=>{while(await process.StandardOutput.ReadLineAsync() is {} line)if(line=="REQUEST")Interlocked.Increment(ref Requests);});
        }
        public static async Task<HysteriaHttpsTarget> Start(string repository,Fixture f,X509Certificate2 certificate,RSA key,CancellationToken ct)
        {
            var directory=f.Paths.Resolve("private/hysteria-https");Directory.CreateDirectory(directory);var cert=SafePath.Resolve(directory,"certificate.pem");var pem=SafePath.Resolve(directory,"key.private.pem");File.WriteAllText(cert,certificate.ExportCertificatePem());File.WriteAllText(pem,key.ExportPkcs8PrivateKeyPem());
            var start=new ProcessStartInfo(Environment.GetEnvironmentVariable("MAY_TEST_PYTHON")??"python"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};foreach(var a in new[]{Path.Combine(repository,"tests/hysteria-https-fixture.py"),cert,pem})start.ArgumentList.Add(a);var process=Process.Start(start)!;
            try{var line=await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(6),ct);return new(process,int.Parse(line!));}catch{if(!process.HasExited)process.Kill(true);process.Dispose();throw;}
        }
        public async ValueTask DisposeAsync() { if(!process.HasExited)process.Kill(true);await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));await worker;await error;process.Dispose(); }
    }
}
