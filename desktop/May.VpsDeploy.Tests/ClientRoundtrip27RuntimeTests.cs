using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task ClientRoundtrip27Runtime()
    {
        if(!OperatingSystem.IsWindows()){Console.WriteLine("SKIP: round27 native Windows loopback; model and builder run cross-platform.");return;}
        using var f=new Fixture(repository);using var budget=new CancellationTokenSource(TimeSpan.FromMinutes(3));var ct=budget.Token;var assets=new ValidationAssets(new AppPaths(repository),"windows-amd64");var tools=new ExternalToolRunner();var directory=f.Paths.Resolve("private/client-roundtrip-27");Directory.CreateDirectory(directory);
        using var key=RSA.Create(2048);var request=new CertificateRequest("CN=stream.example.test",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var san=new SubjectAlternativeNameBuilder();san.AddDnsName("stream.example.test");san.AddIpAddress(IPAddress.Loopback);request.CertificateExtensions.Add(san.Build());request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));using var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));var certFile=Path.Combine(directory,"certificate.pem");var keyFile=Path.Combine(directory,"key.pem");File.WriteAllText(certFile,cert.ExportCertificatePem());File.WriteAllText(keyFile,key.ExportPkcs8PrivateKeyPem());
        await using var target=await HysteriaHttpsTarget.Start(repository,f,cert,key,ct);await using var dns=new TuicDnsTarget();var cases=new JsonArray();var processes=new List<int>();
        foreach(var protocol in new[]{"vless","trojan","tuic"})
        foreach(var congestion in protocol=="tuic"?new[]{"cubic","new_reno","bbr"}:new[]{"cubic"})
        foreach(var mode in protocol=="tuic"?new[]{"native","quic"}:new[]{"native"})
        {
            var port=protocol=="tuic"?UdpPort():TcpPort();var scheme=ClientSchemes.New(f.Paths);var region=scheme["Layout"]!.Strings("region_groups")[0];ClientNodeImport.Apply(scheme,ClientNodeImport.Preview(Link27(protocol,"127.0.0.1",port,mode,congestion),scheme,region,"entry"));
            var native=scheme["Nodes"]![0]!["sing_box"]!;var user=new JsonObject();if(protocol!="trojan")user["uuid"]=native.Text("uuid");if(protocol!="vless")user["password"]=native.Text("password");var inbound=new JsonObject{["type"]=protocol,["tag"]="round27-entry",["listen"]="127.0.0.1",["listen_port"]=port,["users"]=new JsonArray(user),["tls"]=new JsonObject{["enabled"]=true,["certificate_path"]=certFile,["key_path"]=keyFile,["alpn"]=new JsonArray(protocol=="tuic"?"h3":"http/1.1")}};
            if(protocol=="tuic"){inbound["congestion_control"]=congestion;inbound["zero_rtt_handshake"]=false;}
            var configuration=new JsonObject{["log"]=new JsonObject{["level"]="error"},["inbounds"]=new JsonArray(inbound),["outbounds"]=new JsonArray(new JsonObject{["type"]="direct",["tag"]="controlled-targets"})};await using var server=await HysteriaCore.Start(assets.ResolveCore("sing-box"),tools,configuration,directory,"server-"+protocol+"-"+congestion+"-"+mode,ct);processes.Add(server.Process.Id);
            foreach(var core in new[]{"sing-box","mihomo"})
            {
                var preview=ClientShareLinks.Preview(scheme);var serialized=ClientShareLinks.Generate(scheme,preview,preview.Rows.Select(r=>r.Id).ToArray(),core=="sing-box"?"Plain":"Base64");var restored=ClientNodeImport.Preview(serialized,ClientSchemes.New(f.Paths),region,"entry").Rows.Single().Node!;
                await using(var client=await Round15Client.Start(core,assets.ResolveCore(core),restored,cert,directory,ct))
                {
                    processes.Add(client.Process.Id);using var http=TuicHttp(client.Port,cert);var before=dns.Packets;Check(await http.GetStringAsync("https://127.0.0.1:"+target.Port,ct)=="198.51.100.22",core+" roundtrip HTTPS failed for "+protocol);Check((await ClientProxyUdp.ProbeAsync(client.Port,new(IPAddress.Loopback,dns.Port),ct)).Flag("ResponseMatched")&&dns.Packets>before,core+" roundtrip UDP failed for "+protocol);
                }
                if(congestion=="cubic"&&mode=="native")
                {
                    var bad=restored.DeepClone().AsObject();if(protocol=="vless"){bad["sing_box"]!["uuid"]=Guid.NewGuid().ToString();bad["clash"]!["uuid"]=bad["sing_box"]!["uuid"]!.DeepClone();}else{bad["sing_box"]!["password"]="wrong-synthetic";bad["clash"]!["password"]="wrong-synthetic";}
                    await using var client=await Round15Client.Start(core,assets.ResolveCore(core),bad,cert,directory,ct);processes.Add(client.Process.Id);using var http=TuicHttp(client.Port,cert);using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(2));var blocked=false;try{await http.GetStringAsync("https://127.0.0.1:"+target.Port,deadline.Token);}catch(Exception e)when(e is HttpRequestException or OperationCanceledException){blocked=true;}Check(blocked,"wrong credentials accepted after roundtrip");
                }
                cases.Add(new JsonObject{["Protocol"]=protocol,["Core"]=core,["Mode"]=mode,["Congestion"]=congestion,["Https"]=true,["Udp"]=true});
            }
            Console.WriteLine("Round27: "+protocol+" / "+congestion+" / "+mode+" dual-client share/import HTTPS + UDP passed.");
        }
        Check(processes.All(id=>{try{using var p=System.Diagnostics.Process.GetProcessById(id);return p.HasExited;}catch(ArgumentException){return true;}}),"round27 left an owned core running");
        if(Environment.GetEnvironmentVariable("MAY_R27_EVIDENCE") is {} proof)ArchiveStore.WriteJson(Path.GetFullPath(proof),new JsonObject{["SyntheticOnly"]=true,["Cases"]=cases,["OwnedCoresStopped"]=true});
    }
}
