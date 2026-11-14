using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunInboundPolicy28ProbeTests() { await InboundPolicy28ProbeRuntime(); Console.WriteLine($"PASS: {assertions} native Python policy probe, egress failure and cleanup assertions."); }
    private async Task InboundPolicy28ProbeRuntime(bool applicationUdp = false)
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(python)) { Console.WriteLine("SKIP: round28 Python/core probe runtime needs Windows fixed cores and MAY_TEST_PYTHON."); return; }
        using var f = new Fixture(repository); using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(applicationUdp ? 2 : 1)); var ct = deadline.Token;
        await using var dns = applicationUdp ? new TuicDnsTarget(IPAddress.Loopback) : null;
        var work = f.Paths.Resolve("private/policy28-probe"); Directory.CreateDirectory(work); var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64");
        using var key = RSA.Create(2048); var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build()); request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-3), DateTimeOffset.UtcNow.AddDays(1));
        await using var target = await HysteriaHttpsTarget.Start(repository, f, certificate, key, ct); var trust = SafePath.Resolve(work, "synthetic-trust.pem"); File.WriteAllText(trust, certificate.ExportCertificatePem());
        var port = MixedPort(); var password = ServerConfigurations.RandomKey(32);
        var landing = new JsonObject { ["log"] = new JsonObject { ["disabled"] = true }, ["inbounds"] = new JsonArray(new JsonObject { ["type"] = "shadowsocks", ["listen"] = "127.0.0.1", ["listen_port"] = port, ["method"] = "chacha20-ietf-poly1305", ["password"] = password }), ["outbounds"] = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" }) };
        await using var server = await Policy28Core.Start(assets.ResolveCore("sing-box"), landing, work, false, port, false, ct);
        var wrapper = SafePath.Resolve(work, "probe.py");
        File.WriteAllText(wrapper, """
import importlib.util,json,os,subprocess,sys
from pathlib import Path
values=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig'))
space={'__name__':'isolated_probe'}
exec(Path(values['Host']).read_text(encoding='utf-8-sig').split('\nif __name__==',1)[0],space)
exec(Path(values['UdpProgram']).read_text(encoding='utf-8-sig'),space)
exec(Path(values['Program']).read_text(encoding='utf-8-sig'),space)
space['POLICY_HOSTS']={name:'127.0.0.1' for name in ('IPv4','IPv6','Auto')};space['POLICY_PORT']=values['Port']
owned=[];original=subprocess.Popen
def spawn(*args,**kwargs):
    kwargs['stdout']=subprocess.PIPE;kwargs['stderr']=subprocess.PIPE
    child=original(*args,**kwargs);owned.append(child);return child
subprocess.Popen=spawn
passed=0
modes=('independent','fixed') if values['ApplicationUdp'] else ('independent',)
for mode in modes:
    fixed = mode=='fixed'
    if fixed:
        code=Path(values['FixedProgram']).read_text(encoding='utf-8-sig').split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
        space={'__name__':'isolated_fixed_probe'};exec(code,space)
        space['PROBE_HOST_V4']='127.0.0.1';space['PROBE_HOST_V6']='127.0.0.1';space['PROBE_PORT']=values['Port']
        os.environ['VPS_APPLICATION_UDP_PROGRAM']=Path(values['UdpProgram']).read_text(encoding='utf-8-sig')
    for failure in (('none','egress','udp') if values['ApplicationUdp'] else ('none','egress')):
        original_query=space['query' if fixed else 'policy_query'];queries=[]
        def observed_query(*args):
            result=original_query(*args);queries.append(result);return result
        query_name='query' if fixed else 'policy_query';space[query_name]=observed_query
        if values['ApplicationUdp']:
            # Only this explicit fixture changes fixed resolver endpoints.
            udp_source=Path(values['UdpProgram']).read_text(encoding='utf-8-sig')
            udp_source += "\nAPPLICATION_UDP_RESOLVERS['IPv4']=('127.0.0.1',"+str(values['BlockedPort'] if failure=='udp' else values['DnsPort'])+")\n"
            if fixed:os.environ['VPS_APPLICATION_UDP_PROGRAM']=udp_source
            else:exec(udp_source,space)
        path={'Id':'fixture','Family':'IPv4','ExpectedAddress':'198.51.100.99' if failure=='egress' else '198.51.100.22','OutboundFingerprint':'a'*64}
        if values['ApplicationUdp']:path['UdpRequired']=True
        try:
            if fixed:
                output=values['Outbound'].copy();output['tag']='may-hop-'+'a'*16
                item={'Id':'a'*16,'ExpectedAddress':path['ExpectedAddress'],'Outbound':output,'UdpRequired':True}
                space['validate']([item], 'RealityEntry' if values['Xray'] else 'AnyTlsEntry')
                result=space['run_probe'](values['Binary'],'RealityEntry' if values['Xray'] else 'AnyTlsEntry',item)
            else:result=space['probe_path'](values['Binary'],values['Xray'],values['Outbound'],path)
            assert failure=='none' and result['Egress']=='198.51.100.22'
            if values['ApplicationUdp']:assert result['UdpValidation']['ResponseMatched'] and result['UdpValidation']['Transport']=='UDP'
            passed+=1
        except ValueError:
            if failure=='none':
                for child in owned:
                    output,error=child.communicate(timeout=2);sys.stderr.write('owned probe exit='+str(child.returncode)+' xray='+str(values['Xray'])+'\n'+output.decode(errors='replace')[-1200:]+error.decode(errors='replace')[-1200:])
                raise
            assert queries==['198.51.100.22'], 'Failure was not the planned post-HTTPS validation'
            passed+=1
        finally:space[query_name]=original_query
    if fixed:
        direct={'tag':'direct','protocol':'freedom','settings':{'domainStrategy':'ForceIPv4'}} if values['Xray'] else {'tag':'direct','type':'direct','domain_resolver':{'server':'local','strategy':'ipv4_only'}}
        item={'Id':'direct','ExpectedAddress':'','Family':'IPv4','Outbound':direct,'UdpRequired':True}
        os.environ['VPS_APPLICATION_UDP_PROGRAM']=Path(values['UdpProgram']).read_text(encoding='utf-8-sig')+"\nAPPLICATION_UDP_RESOLVERS['IPv4']=('127.0.0.1',"+str(values['DnsPort'])+")\n"
        space['validate']([item], 'RealityEntry' if values['Xray'] else 'AnyTlsEntry')
        result=space['run_probe'](values['Binary'],'RealityEntry' if values['Xray'] else 'AnyTlsEntry',item)
        assert result['UdpValidation']['ResponseMatched'];passed+=1

assert all(child.poll() is not None for child in owned)
assert not list(Path(os.environ['TEMP']).glob('may-inbound-policy-*'))
print(json.dumps({'Passed':passed,'Stopped':True,'Children':len(owned)}))
""");
        foreach (var isXray in new[] { false, true })
        {
            var binary = isXray ? Environment.GetEnvironmentVariable("MAY_TEST_XRAY") : assets.ResolveCore("sing-box"); if (string.IsNullOrEmpty(binary)) continue;
            var native = new JsonObject { ["type"] = "shadowsocks", ["tag"] = "egress", ["server"] = "192.0.2.28", ["server_port"] = port, ["method"] = "chacha20-ietf-poly1305", ["password"] = password };
            var output = isXray ? ServerOutboundRouting.XrayNextHop(native) : native;
            if (isXray) output["settings"]!["servers"]![0]!["address"] = "127.0.0.1"; else output["server"] = "127.0.0.1";
            var input = SafePath.Resolve(work, "request.private.json"); ArchiveStore.WriteJson(input, new JsonObject { ["ApplicationUdp"] = applicationUdp, ["DnsPort"] = dns?.Port ?? 0, ["BlockedPort"] = MixedPort(), ["UdpProgram"] = Path.Combine(repository, "scripts/application-udp-probe.py"), ["FixedProgram"] = Path.Combine(repository, "assets/remote/server-hop-probe.sh"), ["Host"] = Path.Combine(repository, "scripts/inbound-host.py"), ["Program"] = Path.Combine(repository, "scripts/inbound-policy-probe.py"), ["Port"] = target.Port, ["Binary"] = binary, ["Xray"] = isXray, ["Outbound"] = output });
            var start = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; start.ArgumentList.Add(wrapper); start.ArgumentList.Add(input); start.Environment["SSL_CERT_FILE"] = trust; start.Environment["TEMP"] = work; start.Environment["TMP"] = work; start.Environment["TMPDIR"] = work;
            using var process = Process.Start(start)!; var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            try
            {
                await process.WaitForExitAsync(ct); var text = await stdout; var error = await stderr;
                Check(process.ExitCode == 0 && !text.Contains(password) && !error.Contains(password), "round28 actual Python/core outbound probe failed or exposed credentials: " + error);
                var proof = JsonNode.Parse(text)!.AsObject(); Check(proof.Number("Passed") == (applicationUdp ? 7 : 2) && proof.Flag("Stopped") && proof.Number("Children") == (applicationUdp ? 7 : 2), "native probe did not reject wrong egress or stop owned children");
            }
            finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } }
        }
    }
}
