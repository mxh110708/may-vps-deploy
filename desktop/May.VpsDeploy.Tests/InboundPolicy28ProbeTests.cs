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
    private async Task InboundPolicy28ProbeRuntime()
    {
        var python = Environment.GetEnvironmentVariable("MAY_TEST_PYTHON");
        if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(python)) { Console.WriteLine("SKIP: round28 Python/core probe runtime needs Windows fixed cores and MAY_TEST_PYTHON."); return; }
        using var f = new Fixture(repository); using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(1)); var ct = deadline.Token;
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
exec(Path(values['Program']).read_text(encoding='utf-8-sig'),space)
space['POLICY_HOSTS']={name:'127.0.0.1' for name in ('IPv4','IPv6','Auto')};space['POLICY_PORT']=values['Port']
owned=[];original=subprocess.Popen
def spawn(*args,**kwargs):
    kwargs['stdout']=subprocess.PIPE;kwargs['stderr']=subprocess.PIPE
    child=original(*args,**kwargs);owned.append(child);return child
subprocess.Popen=spawn
passed=0
for wrong in (False,True):
    path={'Id':'fixture','Family':'IPv4','ExpectedAddress':'198.51.100.99' if wrong else '198.51.100.22','OutboundFingerprint':'a'*64}
    try:
        result=space['probe_path'](values['Binary'],values['Xray'],values['Outbound'],path)
        assert not wrong and result['Scope']=='NativeOutboundHttps' and result['Egress']=='198.51.100.22'
        passed+=1
    except ValueError:
        if not wrong:
            for child in owned:
                output,error=child.communicate(timeout=2);sys.stderr.write('owned probe exit='+str(child.returncode)+' xray='+str(values['Xray'])+'\n'+output.decode(errors='replace')[-1200:]+error.decode(errors='replace')[-1200:])
            raise
        passed+=1
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
            var input = SafePath.Resolve(work, "request.private.json"); ArchiveStore.WriteJson(input, new JsonObject { ["Host"] = Path.Combine(repository, "scripts/inbound-host.py"), ["Program"] = Path.Combine(repository, "scripts/inbound-policy-probe.py"), ["Port"] = target.Port, ["Binary"] = binary, ["Xray"] = isXray, ["Outbound"] = output });
            var start = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; start.ArgumentList.Add(wrapper); start.ArgumentList.Add(input); start.Environment["SSL_CERT_FILE"] = trust; start.Environment["TEMP"] = work; start.Environment["TMP"] = work; start.Environment["TMPDIR"] = work;
            using var process = Process.Start(start)!; var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            try
            {
                await process.WaitForExitAsync(ct); var text = await stdout; var error = await stderr;
                Check(process.ExitCode == 0 && !text.Contains(password) && !error.Contains(password), "round28 actual Python/core outbound probe failed or exposed credentials: " + error);
                var proof = JsonNode.Parse(text)!.AsObject(); Check(proof.Number("Passed") == 2 && proof.Flag("Stopped") && proof.Number("Children") == 2, "native probe did not reject wrong egress or stop owned children");
            }
            finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } }
        }
    }
}
