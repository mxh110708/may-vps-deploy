using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task<JsonObject> Proxy30VmAcceptance(Fixture f, JsonObject nodes, IRemoteSessionFactory factory, IUserInteraction user, ClientRouteDiagnostics diagnostics, X509Certificate2 ca, RSA key, CancellationToken ct)
    {
        var front = nodes["Front"]!.AsObject(); var plan = TcpChains.Plan(f.Store, f.Store.ListInstances().Single(i => i.Plan.Text("Instance") == "Chain21VM-Front").RelativePath);
        var relative = f.Relative(plan); var directory = f.Paths.Instance(relative);
        async Task<CommandResult> Remote(string script)
        {
            await using var session = await factory.OpenAsync(new(front.Text("Address"),22,"root",front.Text("KeyFile")),user,ct);
            var result = await session.RunScriptAsync(script,TimeSpan.FromSeconds(30),true,ct); result.RequireSuccess("Disposable PROXY target operation failed."); return result;
        }
        const string root = "/opt/may-tcp-chain-fixture";
        var server = "import socket,ssl,struct,threading,json\nfrom pathlib import Path\nroot=Path('"+root+"')\nctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(root/'proxy30.pem',root/'proxy30.key')\n" +
            "def exact(c,n):\n b=b''\n while len(b)<n:\n  v=c.recv(n-len(b))\n  if not v:raise ValueError('closed header')\n  b+=v\n return b\n" +
            "def serve(c):\n try:\n  c.settimeout(8);prefix=exact(c,6)\n  if prefix==b'PROXY ':\n   header=prefix\n   while not header.endswith(b'\\r\\n') and len(header)<108:header+=exact(c,1)\n   fields=header.decode().strip().split(' ');assert len(fields)==6 and fields[1]=='TCP4';version='v1'\n  else:\n   header=prefix+exact(c,10);assert header[:12]==b'\\r\\n\\r\\n\\0\\r\\nQUIT\\n' and header[12:14]==b'\\x21\\x11' and struct.unpack('!H',header[14:])[0]==12;exact(c,12);version='v2'\n  with ctx.wrap_socket(c,server_side=True) as tls:\n   with (root/'proxy30-proofs.jsonl').open('a') as out:out.write(json.dumps({'Version':version,'CertificateHandshake':True})+'\\n')\n   try:tls.recv(1024)\n   except OSError:pass\n except (OSError,ValueError,AssertionError):pass\n finally:c.close()\n" +
            "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',18844));s.listen()\nwhile True:\n c,p=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()\n";
        var setup = "set -euo pipefail\numask 077\n";
        foreach (var (name, content) in new[] { ("proxy30.py",server), ("proxy30.pem",ca.ExportCertificatePem()), ("proxy30.key",key.ExportPkcs8PrivateKeyPem()) })
            setup += "printf '%s' '"+Convert.ToBase64String(Encoding.UTF8.GetBytes(content))+"' | base64 -d > "+root+"/"+name+"\n";
        setup += "cat > /etc/systemd/system/may-proxy30-target.service <<'EOF'\n[Service]\nExecStart=/usr/bin/python3 "+root+"/proxy30.py\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload\nsystemctl start may-proxy30-target.service\n";
        await Remote(setup);
        var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store,factory,new FakeKeys(),user,new FakeValidation(),tcpForwarding:new Proxy30VmValidator(f.Store,diagnostics,front,ca)));
        var config = TcpForwarding.Empty(); var rule = TcpForwarding.NewRule(); rule["Name"] = "Disposable explicit PROXY"; rule["ListenPort"] = 18443; rule["TargetAddress"] = "127.0.0.1"; rule["TargetPort"] = 18844; rule["AllowedSources"] = new JsonArray(front.Text("Address") + "/32"); rule["Validation"]!["ServerName"] = "chain.example.test"; config["Rules"]!.AsArray().Add(rule);
        async Task<TaskRecord> Execute(string action, JsonObject candidate)
        {
            var state = ArchiveStore.ReadJson(SafePath.Resolve(directory,"deployment-state.json")); var request = new OperationRequest(OperationKind.TcpForward,relative,TcpForwarding.Options(state,action,candidate));
            return await coordinator.ExecuteAsync(coordinator.Review(request),request,new InlineProgress<TaskProgress>(_=>{}),ct);
        }
        var versions = new JsonArray();
        try
        {
            foreach (var version in new[] { "v1", "v2" })
            {
                rule["ProxyProtocol"] = version;
                var result = await Execute("Apply",config);
                Check(result.Outcome == TaskOutcome.Completed,"actual Debian PROXY "+version+" apply/TLS acceptance failed: "+result.SafeError);
                Check((await Execute("Check",config)).Outcome == TaskOutcome.Completed,"actual PROXY read-only acceptance failed");
                var observed = ArchiveStore.ReadJson(SafePath.Resolve(directory,"deployment-state.json"));
                Check(observed.At("TcpForwarding.Validation.Items")!.AsArray()[0]!.At("Checks")!.AsArray()[0]!.Text("ProxyProtocol") == version,"actual PROXY mode lost from scoped evidence");
                versions.Add(version);
            }
            var savedHash = ArchiveStore.ReadJson(SafePath.Resolve(directory,"deployment-state.json")).Text("TcpForwarding.RemoteHash");
            var invalid = config.DeepClone().AsObject(); invalid["Rules"]![0]!["Validation"]!["ServerName"] = "wrong.example.test";
            Check((await Execute("Apply",invalid)).Outcome == TaskOutcome.Failed,"PROXY TLS hostname mismatch was committed");
            Check(ArchiveStore.ReadJson(SafePath.Resolve(directory,"deployment-state.json")).Text("TcpForwarding.RemoteHash") == savedHash,"PROXY failure did not restore the previous component hash");
            Check((await Execute("Check",config)).Outcome == TaskOutcome.Completed,"previous PROXY path unusable after actual rollback");
            var proof = await Remote("set -euo pipefail\ncat "+root+"/proxy30-proofs.jsonl\n");
            var records = proof.Output.Split('\n',StringSplitOptions.RemoveEmptyEntries).Select(s=>JsonNode.Parse(s)!.AsObject()).ToArray();
            Check(versions.All(v=>records.Count(p=>p.Text("Version")==v!.GetValue<string>()&&p.Flag("CertificateHandshake"))>=2),"target did not parse both real headers before TLS");
            Check((await Execute("Remove",TcpForwarding.Empty())).Outcome == TaskOutcome.Completed,"actual PROXY component removal failed");
            await Remote("set -euo pipefail\ntest ! -e /etc/may-tcp-forward/config.json\ntest ! -e /etc/may-tcp-forward/proxy-worker.py\ntest ! -e /var/lib/may-vps-deploy/transaction.owner\n");
            Check(true,"actual PROXY files/transaction owner leaked");
            return new JsonObject { ["Status"]="Passed", ["Versions"]=versions, ["TlsCertificateValidated"]=true, ["WrongSniRolledBack"]=true, ["PreviousPathRechecked"]=true, ["OwnedComponentRemoved"]=true };
        }
        finally
        {
            await Remote("set -euo pipefail\nsystemctl stop may-proxy30-target.service\nrm -f /etc/systemd/system/may-proxy30-target.service "+root+"/proxy30.py "+root+"/proxy30.pem "+root+"/proxy30.key "+root+"/proxy30-proofs.jsonl\nsystemctl daemon-reload\n");
        }
    }
    private sealed class Proxy30VmValidator(ArchiveStore store, ClientRouteDiagnostics diagnostics, JsonObject host, X509Certificate2 ca) : ITcpForwardValidation
    {
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject configuration, string directory, IProgress<string> progress, CancellationToken ct)
        {
            // Controller -> the fixture's owned QEMU ingress -> the real socket
            // activated product worker. This mapping changes only the test's dial.
            var ingress = host["IngressIPv4"]!.AsObject(); var copy = configuration.DeepClone().AsObject();
            foreach (var rule in TcpForwarding.Rules(copy)) rule["ListenPort"] = ingress.Number("ApplicationPort");
            return new TcpForwardValidation(store,diagnostics,ca).ValidateAsync(new JsonObject { ["Server"] = new JsonObject { ["IPv4"]="127.0.0.1" } },copy,directory,progress,ct);
        }
    }
}
