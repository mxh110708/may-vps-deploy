using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    private async Task Xhttp35RemoteProbe(JsonObject source, X509Certificate2 certificate, int targetPort, int dnsPort, string directory, CancellationToken ct)
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON"); if (string.IsNullOrEmpty(python)) { Console.WriteLine("SKIP: round35 actual Python probe needs MAY_TEST_PYTHON."); return; }
        var native = ServerOutboundRouting.XrayNextHop(ServerOutboundRouting.NextHop(source)); native["tag"] = ServerOutboundRouting.HopTag(HopA); native["settings"]!["vnext"]![0]!["address"] = "127.0.0.1";
        var work = SafePath.Resolve(directory, "xhttp-probes-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work); var wrapper = SafePath.Resolve(work, "probe.py"); var input = SafePath.Resolve(work, "input.private.json"); var trust = SafePath.Resolve(work, "trust.pem"); File.WriteAllText(trust, certificate.ExportCertificatePem());
        var expected = ServerOutboundRouting.XhttpProof(native);
        File.WriteAllText(wrapper, """
import base64,copy,json,os,sys,tempfile
from pathlib import Path
values=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8-sig'))
root=Path(values['Root']);binary=values['Binary'];helper=(root/'scripts/server-xhttp.py').read_text(encoding='utf-8-sig')
udp=(root/'scripts/application-udp-probe.py').read_text(encoding='utf-8-sig')
udp+="\nAPPLICATION_UDP_RESOLVERS['IPv4']=('127.0.0.2',"+str(values['DnsPort'])+")\n"
os.environ['VPS_APPLICATION_UDP_PROGRAM']=helper+'\n'+udp
script=(root/'assets/remote/server-hop-probe.sh').read_text(encoding='utf-8-sig').split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
fixed={};exec(script.split('\nif __name__ ==',1)[0],fixed)
fixed['PROBE_HOST_V4']='127.0.0.1';fixed['PROBE_PORT']=values['HttpsPort']
item={'Id':values['Id'],'ExpectedAddress':'198.51.100.22','Outbound':values['Outbound'],'UdpRequired':True}
fixed['validate']([item],'RealityEntry');result=fixed['run_probe'](binary,'RealityEntry',item)
assert result['XhttpFingerprint']==values['Expected']['XhttpFingerprint'] and result['UdpValidation']['ResponseMatched']
assert result['UdpValidation']['ResolverPort']==values['DnsPort']
namespace={};exec(helper+'\n'+(root/'scripts/inbound-host.py').read_text(encoding='utf-8-sig').split('\nif __name__ ==',1)[0],namespace)
exec(udp+'\n'+(root/'scripts/inbound-policy-probe.py').read_text(encoding='utf-8-sig').split('\nif __name__ ==',1)[0],namespace)
namespace['POLICY_HOSTS']={'IPv4':'127.0.0.1','IPv6':'::1','Auto':'127.0.0.1'};namespace['POLICY_PORT']=values['HttpsPort']
identifier='a'*32;outbound_id='b'*32
outbound=copy.deepcopy(values['Outbound']);outbound['tag']='egress'
configuration={'outbounds':[outbound]};data=json.dumps(configuration,ensure_ascii=False).encode();filename=Path(os.environ['TEMP'])/'installed.private.json';filename.write_bytes(data)
inbound={'Id':identifier,'Protocol':'Reality','Enabled':True,'OutboundId':outbound_id}
xray={'Engine':'xray','Version':'26.3.27','Artifact':'Xray-linux-64.zip','Sha256':'c'*64}
core={'Engine':'sing-box','Version':'1.14.2','Artifact':'sing-box-1.14.2-linux-amd64.tar.gz','Sha256':'d'*64,'Reality':xray}
sha=namespace['digest'](data)
state={'Hash':'e'*64,'Runtime':{identifier:{'Active':True,'Enabled':True}},'Registry':{'Core':core,'Model':{'Inbounds':[inbound],'Outbounds':[{'Id':outbound_id,'Family':'IPv4','ExpectedAddress':'198.51.100.22'}]},'Bindings':[{'Id':identifier,'Sha256':sha}]}}
paths=namespace['policy_paths'](state['Registry']['Model'],inbound,configuration)
assert paths[0]['UdpRequired'] and paths[0]['Xhttp']==values['Expected']
paths[0]['OutboundFingerprint']='f'*64
request={'InboundId':identifier,'ConfigurationSha256':sha,'PolicyFingerprint':'1'*64,'Paths':paths}
class Host:
    def read(self):return copy.deepcopy(state)
    def regular(self,path):
        if path==namespace['config_path'](identifier):return filename
        if path==namespace['core_path'](xray):return Path(binary)
        raise ValueError('Unexpected fixture path')
report=namespace['run_policy'](Host(),request)
proof=report['Items'][0]
assert proof['Xhttp']==values['Expected'] and proof['UdpValidation']['ResponseMatched'] and proof['UdpValidation']['ResolverPort']==values['DnsPort']
stale=copy.deepcopy(request);stale['ConfigurationSha256']='0'*64
try:namespace['run_policy'](Host(),stale)
except ValueError:pass
else:raise AssertionError('Stale configuration accepted')
assert not list(Path(os.environ['TEMP']).glob('may-hop-probe-*')) and not list(Path(os.environ['TEMP']).glob('may-inbound-policy-*'))
print(json.dumps({'FixedXhttp':True,'IndependentDefaultXhttp':True,'ActualUdp':True,'StaleRejected':True,'TemporaryCoresStopped':True}))
""");
        ArchiveStore.WriteJson(input, new JsonObject { ["Root"] = repository, ["Binary"] = Environment.GetEnvironmentVariable("MAY_TEST_XRAY"), ["Id"] = HopA, ["Outbound"] = native, ["Expected"] = expected, ["HttpsPort"] = targetPort, ["DnsPort"] = dnsPort });
        var start = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; start.ArgumentList.Add(wrapper); start.ArgumentList.Add(input); start.Environment["SSL_CERT_FILE"] = trust; start.Environment["TEMP"] = work; start.Environment["TMP"] = work; start.Environment["TMPDIR"] = work;
        using var process = Process.Start(start)!; var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync(ct); var text = await stdout; var error = await stderr;
            Check(process.ExitCode == 0 && !text.Contains(source.Text("sing_box.uuid")) && !error.Contains(source.Text("sing_box.uuid")), "round35 actual fixed/independent Python probe failed: " + error);
            var proof = JsonNode.Parse(text)!.AsObject(); Check(proof.Flag("FixedXhttp") && proof.Flag("IndependentDefaultXhttp") && proof.Flag("ActualUdp") && proof.Flag("StaleRejected") && proof.Flag("TemporaryCoresStopped"), "XHTTP probe evidence or cleanup incomplete");
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } }
    }
}
