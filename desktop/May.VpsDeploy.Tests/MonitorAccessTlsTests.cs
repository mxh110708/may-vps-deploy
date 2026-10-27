using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task MonitorAccessTls(Fixture f,string relative,string node,string origin)
    {
        using var rootKey=RSA.Create(2048); using var leafKey=RSA.Create(2048);
        var caRequest=new CertificateRequest("CN=May disposable fixture CA",rootKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        caRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caRequest.PublicKey,false));
        using var ca=caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));
        var leafRequest=new CertificateRequest("CN=may.example",leafKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var names=new SubjectAlternativeNameBuilder(); names.AddDnsName("may.example"); leafRequest.CertificateExtensions.Add(names.Build());
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature|X509KeyUsageFlags.KeyEncipherment,true));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},false));
        leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca,true,false));
        using var leaf=leafRequest.Create(ca,DateTimeOffset.UtcNow.AddMinutes(-2),DateTimeOffset.UtcNow.AddHours(1),RandomNumberGenerator.GetBytes(16));
        var directory=f.Paths.Resolve("private/monitor-access-tls"); Directory.CreateDirectory(directory);
        var cert=SafePath.Resolve(directory,"certificate.pem"); var key=SafePath.Resolve(directory,"key.private.pem"); var input=SafePath.Resolve(directory,"fixture.private.json"); var hits=SafePath.Resolve(directory,"hits.json");
        File.WriteAllText(cert,leaf.ExportCertificatePem()+"\n"+ca.ExportCertificatePem()); File.WriteAllText(key,leafKey.ExportPkcs8PrivateKeyPem());
        var token=MonitorReadConnection.NewToken(); ArchiveStore.WriteJson(input,new JsonObject{["Token"]=token,["Node"]=node,["Origin"]=origin});
        var start=new ProcessStartInfo(Environment.GetEnvironmentVariable("MAY_TEST_PYTHON")??"python"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var argument in new[]{Path.Combine(repository,"tests/monitor-access-tls-fixture.py"),cert,key,input,hits}) start.ArgumentList.Add(argument);
        using var process=Process.Start(start)??throw new Exception("TLS fixture did not start"); var errors=process.StandardError.ReadToEndAsync();
        try
        {
            var ready=await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(8)); var port=int.Parse(ready??throw new Exception("TLS fixture readiness missing"));
            SocketsHttpHandler Handler(bool trustFixture)
            {
                var handler=new SocketsHttpHandler{UseProxy=false,UseCookies=false,AllowAutoRedirect=false};
                handler.ConnectCallback=async(_,ct)=>{var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);try{await socket.ConnectAsync(IPAddress.Loopback,port,ct);return new NetworkStream(socket,true);}catch{socket.Dispose();throw;}};
                if(trustFixture) handler.SslOptions.RemoteCertificateValidationCallback=(_,certificate,_,policy)=>
                {
                    if(certificate==null || (policy&SslPolicyErrors.RemoteCertificateNameMismatch)!=0)return false;
                    using var chain=new X509Chain();chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;chain.ChainPolicy.CustomTrustStore.Add(ca);chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
                    using var candidate=new X509Certificate2(certificate);return chain.Build(candidate);
                };
                return handler;
            }
            var bindings=new Dictionary<string,string>{[relative]=node};
            using(var client=new MonitorReadClient(Handler(true))) {var snapshot=await client.FetchAsync(new("https://may.example/",token,bindings,origin),default);Check(snapshot.ServerInstanceId==origin&&snapshot.Nodes.ContainsKey(node),"real TLS snapshot lost authenticated origin");}
            using(var client=new MonitorReadClient(Handler(true)))await RefusesAsync(()=>client.FetchAsync(new("https://wrong.example/",token,bindings,origin),default),"TLS hostname mismatch accepted");
            using(var client=new MonitorReadClient(Handler(false)))await RefusesAsync(()=>client.FetchAsync(new("https://may.example/",token,bindings,origin),default),"untrusted TLS issuer accepted");
            Check(ArchiveStore.ReadJson(hits).Number("Requests")==1,"credentials sent after TLS validation failed");
        }
        finally {if(!process.HasExited)process.Kill(true);await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));await errors;}
    }
}
