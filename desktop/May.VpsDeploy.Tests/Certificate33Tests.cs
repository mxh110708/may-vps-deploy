using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

internal sealed partial class BoundaryTests
{
    public async Task RunCertificate33Tests() { await Certificate33Coverage(); Console.WriteLine($"PASS {assertions} certificate lifecycle assertions"); }
    private async Task Certificate33Coverage()
    {
        var policy = ManagedCertificates.Policy("example.com", "operator@example.com", ["inbound.example.com", "*.example.com"]);
        foreach (var change in new (string Field, JsonNode Value)[] { ("Provider", JsonValue.Create("Aliyun")!), ("Zone", JsonValue.Create("../example.com")!), ("Domains", new JsonArray("elsewhere.test")), ("Domains", new JsonArray("inbound.example.com", "inbound.example.com")), ("PropagationSeconds", JsonValue.Create(true)!) })
        { var bad = policy.DeepClone().AsObject(); bad[change.Field] = change.Value.DeepClone(); Refuses(() => ManagedCertificates.ValidatePolicy(bad), "invalid managed policy accepted: " + change.Field); }
        using var f = new Fixture(repository); var plan = f.Plan("Certificate33"); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
        var directory = f.Paths.Instance(f.Relative(plan)); var stateFile = SafePath.Resolve(directory, "deployment-state.json"); var token = SafePath.Resolve(directory, "certificate-token.private.txt"); File.WriteAllText(token, new string('x', 40));
        var id = Guid.NewGuid().ToString("N");
        OperationRequest Request(string action = "Issue", JsonObject? current = null) => new(OperationKind.ManagedCertificate, f.Relative(plan), ManagedCertificates.Options(current ?? ArchiveStore.ReadJson(stateFile), action, id, "Shared certificate", policy, action is "Issue" or "RotateToken" ? token : ""));
        var executed = false; var workflow = new FakeWorkflow(_ => { executed = true; return Task.FromResult(TaskOutcome.Completed); }); var coordinator = new TaskCoordinator(f.Store, workflow);
        var request = Request(); var review = coordinator.Review(request);
        Check(review.Summary.Contains("Cloudflare") && !review.Summary.Contains(new string('x', 40)) && review.Summary.Contains("无"), "certificate review leaked credential or lacked impact");
        File.WriteAllText(token, new string('y', 40));
        try { await coordinator.ExecuteAsync(review, request, new InlineProgress<TaskProgress>(_ => { }), default); throw new Exception("changed token accepted"); }
        catch (OperationException) { Check(!executed, "review did not bind token contents"); }
        File.WriteAllText(token, new string('x', 40));
        var materials = InboundCertificate("inbound.example.com"); var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials();
        var certificate = InboundCatalog.ImportCertificate(model, secrets, "Shared certificate", materials.Certificate, materials.Key);
        Check(InboundCatalog.Items(InboundCatalog.Normalize(model, secrets),"Certificates").Single()["Managed"]==null,"existing manual certificate schema rejected");
        var agedModel = InboundCatalog.Empty(); var agedSecrets = InboundCatalog.EmptyCredentials();
        var agedMaterial = InboundCertificate("inbound.example.com", expired: true);
        var agedCertificate = InboundCatalog.ImportCertificate(agedModel, agedSecrets, "Initial certificate", agedMaterial.Certificate, agedMaterial.Key);
        var agedInbound = InboundCatalog.AddInbound(agedModel, agedSecrets, "AnyTLS"); agedInbound["CertificateId"] = agedCertificate.Text("Id"); agedInbound["Options"]!["ServerName"] = "inbound.example.com";
        Refuses(() => InboundCatalog.Normalize(agedModel, agedSecrets), "expired manual certificate accepted");
        agedCertificate["Managed"] = policy.DeepClone();
        var agedPayload = InboundRendering.Payload(f.Store, plan, InboundCatalog.Normalize(agedModel, agedSecrets), agedSecrets);
        Check(!Encoding.UTF8.GetString(Convert.FromBase64String(agedPayload["Configurations"]!.Text(agedInbound.Text("Id")))).Contains("BEGIN CERTIFICATE"), "expired initial snapshot blocked or replaced live managed material");
        agedPayload["Configurations"]!.AsObject().Clear(); agedSecrets.Clear();
        var generated = certificate.Text("Id"); secrets["Certificates"]![id] = secrets["Certificates"]![generated]!.DeepClone(); secrets["Certificates"]!.AsObject().Remove(generated); certificate["Id"] = id; certificate["Managed"] = policy.DeepClone();
        var first = InboundCatalog.AddInbound(model, secrets, "AnyTLS"); first["CertificateId"] = id; first["Options"]!["ServerName"] = "inbound.example.com";
        var second = InboundCatalog.AddInbound(model, secrets, "Hysteria2"); second["CertificateId"] = id; second["Options"]!["ServerName"] = "inbound.example.com"; second["Enabled"] = false;
        ManagedCertificates.RequireCertificate(secrets["Certificates"]![id]!.AsObject(), policy);
        var normalized = InboundCatalog.Normalize(model, secrets); var payload = InboundRendering.Payload(f.Store, plan, normalized, secrets);
        var actual = JsonNode.Parse(Convert.FromBase64String(payload["Configurations"]!.Text(first.Text("Id"))))!.AsObject();
        Check(!actual.ToJsonString().Contains("BEGIN PRIVATE KEY"), "managed runtime retained inline key");
        var tls = actual["inbounds"]![0]!["tls"]!;
        Check(tls.Text("certificate_path") == ManagedCertificates.Credential(first.Text("Id"), "certificate.pem") && tls["certificate"] == null && tls["key"] == null, "managed credential path or inline removal differs");
        Refuses(() => InboundCatalog.RemoveEntity(model, secrets, "Certificates", id), "generic remove orphaned managed timer");
        Refuses(() => InboundCatalog.ReplaceCertificate(certificate, secrets, materials.Certificate, materials.Key), "manual edit replaced managed certificate");
        var badSni = model.DeepClone().AsObject(); badSni["Inbounds"]![0]!["Options"]!["ServerName"] = "outside.test";
        Refuses(() => InboundRendering.Payload(f.Store, plan, badSni, secrets), "managed certificate accepted unlisted SNI");
        var xhttp = InboundCatalog.AddInbound(model, secrets, "VLESS"); xhttp["CertificateId"] = id; xhttp["Options"]!["ServerName"] = "inbound.example.com";
        var xray = InboundRendering.Configuration(f.Store, plan, model, secrets, xhttp);
        Check(xray["inbounds"]![0]!["streamSettings"]!["tlsSettings"]!["certificates"]![0]!.Text("keyFile") == ManagedCertificates.Credential(xhttp.Text("Id"), "certificate.key"), "Xray credential identity not rendered");
        plan["InboundModel"] = model.DeepClone(); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
        var state = ArchiveStore.ReadJson(stateFile); state.Put("Inbounds.RemoteHash", JsonValue.Create(new string('a', 64))); state.Put("Certificates." + id + ".RemoteHash", JsonValue.Create(new string('b', 64))); ArchiveStore.WriteJson(stateFile, state);
        Check(ManagedCertificates.Prepare(f.Store, Request("Check")).Contains(first.Text("Name")) && ManagedCertificates.Prepare(f.Store, Request("Check")).Contains(second.Text("Name")), "review omitted a shared or disabled consumer");
        Refuses(() => ManagedCertificates.Prepare(f.Store, Request("Remove")), "remove allowed disabled consumer");
        var assets = new RemoteAssets(f.Paths); var script = assets.Payload("managed-certificate-apply.sh", new Dictionary<string,string> { ["CERTIFICATE_DOCUMENT"] = request.Options.ToJsonString(), ["EXPECTED_TRANSACTION"] = "/root/vps-deploy-backups/20261112-010203/protocol-lifecycle" });
        Check(script.Contains("VPS_CERTIFICATE_PROGRAM") && script.Contains("vps_begin_mutation") && !script.Contains(new string('x',40)), "certificate program or transaction guard missing");
        Check(OperationSteps.Create(Request(), plan).Select(s => s.Id).SequenceEqual(new[] { "certificate-preflight", "certificate-backup", "certificate-apply", "certificate-validation", "certificate-commit" }), "certificate steps incomplete");
        Check(OperationSteps.Create(Request("Check"), plan).Count == 2, "check planned a mutation");
        payload["Configurations"]!.AsObject().Clear(); secrets.Clear();
        foreach (var failure in new[] { "none", "apply-ack", "arm-ack", "commit-ack", "cancel" })
        {
            using var operation = new Fixture(repository); var p = operation.Plan("Cert33-" + failure); p.Put("Import.Status", JsonValue.Create("Completed")); p.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); operation.SaveInstance(p);
            var location = operation.Paths.Instance(operation.Relative(p)); var tokenFile = SafePath.Resolve(location,"cf.private.txt"); File.WriteAllText(tokenFile,new string('x',40));
            var exact = ManagedCertificates.Policy("example.com","operator@example.com",["inbound.example.com"]);
            var options = ManagedCertificates.Options(ArchiveStore.ReadJson(SafePath.Resolve(location,"deployment-state.json")),"Issue",Guid.NewGuid().ToString("N"),"New managed certificate",exact,tokenFile);
            var remote = new CertificateRemote(materials.Certificate,materials.Key) { Failure=failure }; remote.Inbounds.Inner.SeedProtocols(p);
            var engine = new WorkflowEngine(operation.Store,remote,new FakeKeys(),new FakeUser(),new FakeValidation(),inboundValidation:new InboundTestValidation(operation.Store));
            var tasks = new TaskCoordinator(operation.Store,engine); var operationRequest = new OperationRequest(OperationKind.ManagedCertificate,operation.Relative(p),options);
            var result = await tasks.ExecuteAsync(tasks.Review(operationRequest),operationRequest,new InlineProgress<TaskProgress>(_=>{}),default);
            Check(result.Outcome==(failure is "none"?TaskOutcome.Completed:failure is "commit-ack"?TaskOutcome.CompletedWithWarnings:failure=="cancel"?TaskOutcome.Cancelled:TaskOutcome.Failed),"certificate workflow failed "+failure+": "+result.Outcome+" "+result.SafeError);
            Check(remote.Applies<=1,"lost certificate acknowledgement replayed mutation");
            if(failure is "none" or "commit-ack")
            {
                var committed=ArchiveStore.ReadJson(SafePath.Resolve(location,"deployment-plan.json")); var managed=InboundCatalog.Items(committed["InboundModel"]!.AsObject(),"Certificates").Single();
                Check(ManagedCertificates.Managed(managed)&&managed.Text("Id")==options.Text("CertificateId"),"issued certificate lost its resource identity");
                var secret=operation.Store.ReadSecret(SafePath.Resolve(location,"secrets.dotnet.private.json"));Check(secret["Inbounds"]!["Certificates"]![managed.Text("Id")]!.Text("PrivateKeyPem")==materials.Key,"certificate private material not encrypted in archive");secret.Clear();
                var stateResult=ArchiveStore.ReadJson(SafePath.Resolve(location,"deployment-state.json"));Check(stateResult.Text("Certificates."+managed.Text("Id")+".RemoteHash")!="","certificate observation missing");
                Check(remote.Inbounds.Inner.ArmedComponents=="Inbounds,Certificates","certificate recovery scope included unrelated components");
            }
            else Check(ArchiveStore.ReadJson(SafePath.Resolve(location,"deployment-plan.json"))["InboundModel"]==null&&remote.Observation.Text("Hash")=="Absent","failed issue left partial local or remote ownership");
        }
    }
    private sealed class CertificateRemote(string pem,string key) : IRemoteSessionFactory, IRemoteSession
    {
        public InboundTestRemote Inbounds { get; }=new(); public string Failure {get;set;}=""; public int Applies {get;private set;}
        public JsonObject Observation {get;private set;}=new(){["Hash"]="Absent",["State"]=null};
        public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint,IUserInteraction user,CancellationToken ct)=>Task.FromResult<IRemoteSession>(this);
        public Task<CommandResult> RunAsync(string command,TimeSpan timeout,CancellationToken ct)=>Inbounds.RunAsync(command,timeout,ct);
        public async Task<CommandResult> RunScriptAsync(string payload,TimeSpan timeout,bool mutating,CancellationToken ct)
        {
            var asset=payload.Split('\n')[0].Replace("# MXH asset: ","");
            if(asset=="managed-certificate-prepare.sh")return new(0,"VPSDEPLOY_CERTIFICATE_PREPARED\n","");
            if(asset.StartsWith("managed-certificate-",StringComparison.Ordinal))
            {
                var result=new JsonObject{["Observation"]=Observation.DeepClone()};
                if(asset=="managed-certificate-apply.sh")
                {
                    Applies++; var match=Regex.Match(payload,"export VPS_PARAM_CERTIFICATE_DOCUMENT=.+?'([A-Za-z0-9+/=]*)' ");var document=JsonNode.Parse(Convert.FromBase64String(match.Groups[1].Value))!.AsObject();
                    Observation=new(){["Hash"]=new string('c',64),["Policy"]=document["Policy"]!.DeepClone(),["State"]=new JsonObject{["Enabled"]=true,["Sha256"]=new string('d',64),["NotAfter"]=DateTimeOffset.UtcNow.AddDays(60).ToString("O"),["ProgramSha256"]=new string('e',64),["LastSuccess"]=DateTimeOffset.UtcNow.ToString("O"),["LastAttempt"]=DateTimeOffset.UtcNow.ToString("O"),["ErrorCode"]=""}};
                    if(Failure=="apply-ack")throw new IOException("synthetic lost certificate acknowledgement");if(Failure=="cancel")throw new OperationCanceledException();
                    result["Observation"]=Observation.DeepClone();result["Material"]=new JsonObject{["CertificatePem"]=pem,["PrivateKeyPem"]=key};
                }
                return new(0,"VPSDEPLOY_CERTIFICATE_RESULT_B64="+Convert.ToBase64String(Encoding.UTF8.GetBytes(result.ToJsonString()))+"\nVPSDEPLOY_"+(asset.EndsWith("apply.sh",StringComparison.Ordinal)?"CERTIFICATE_APPLIED":"CERTIFICATE_READ")+"\n","");
            }
            Inbounds.Failure=Failure is "arm-ack" or "commit-ack"?Failure:"";
            var output=await Inbounds.RunScriptAsync(payload,timeout,mutating,ct);
            if(asset=="protocol-migration-trigger-rollback.sh")Observation=new(){["Hash"]="Absent",["State"]=null};
            if(asset=="inbound-read.sh"&&Inbounds.Current!=null)
            {
                var data=JsonNode.Parse(RemoteAssets.Marker(output.Output,"INBOUND_STATE"))!.AsObject();data["Registry"]!["Core"]=Inbounds.Current["Core"]!.DeepClone();
                output=output with{Output="VPSDEPLOY_INBOUND_STATE_B64="+Convert.ToBase64String(Encoding.UTF8.GetBytes(data.ToJsonString()))+"\nVPSDEPLOY_INBOUND_READ\n"};
            }
            return output;
        }
        public Task DownloadAsync(string remote,string local,CancellationToken ct)=>Inbounds.DownloadAsync(remote,local,ct);
        public Task<byte[]> ReadFileAsync(string remote,CancellationToken ct)=>Inbounds.ReadFileAsync(remote,ct);
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
    }
}
