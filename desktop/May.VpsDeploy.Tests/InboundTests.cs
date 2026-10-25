using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunInboundTests()
    {
        await InboundExperience();
        Console.WriteLine($"PASS: {assertions} inbound identity, shared resource, rendered core, source, transaction and recovery assertions; no production connections.");
    }
    private static (JsonObject Model, JsonObject Credentials) InboundModel()
    {
        var model = InboundCatalog.Empty(); var secrets = InboundCatalog.EmptyCredentials();
        var first = InboundCatalog.AddInbound(model, secrets, "Shadowsocks2022");
        var second = InboundCatalog.AddInbound(model, secrets, "Shadowsocks2022");
        second["UserIds"] = first["UserIds"]!.DeepClone();
        return (model, secrets);
    }
    private static (string Certificate, string Key) InboundCertificate(string name)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName(name); request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));
        return (certificate.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
    }
    private async Task InboundExperience()
    {
        using (var f = new Fixture(repository))
        {
            var plan = f.Plan("Inbound-model"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
            var (model, secrets) = InboundModel(); var first = InboundCatalog.Items(model, "Inbounds").First(); var second = InboundCatalog.Items(model, "Inbounds").Last();
            var normalized = InboundCatalog.Normalize(model, secrets); Check(JsonNode.DeepEquals(model, normalized), "normalization changed a valid identity");
            Refuses(() => InboundCatalog.RemoveEntity(model, secrets, "Users", first.Strings("UserIds").Single()), "referenced user could be removed");
            Refuses(() => InboundCatalog.RemoveEntity(model, secrets, "Outbounds", first.Text("OutboundId")), "referenced outbound could be removed");
            var duplicate = model.DeepClone().AsObject(); duplicate["Inbounds"]![1]!["Listener"]!["Port"] = first.Number("Listener.Port"); Refuses(() => InboundCatalog.Normalize(duplicate, secrets), "disabled/shared listener collision accepted");
            duplicate = model.DeepClone().AsObject(); duplicate["Inbounds"]![0]!["Listener"]!["Address"] = "127.0.0.1"; Refuses(() => InboundCatalog.Normalize(duplicate, secrets), "unverifiable loopback listener accepted");
            duplicate = model.DeepClone().AsObject(); duplicate["Users"]![0]!["Kind"] = "Password"; Refuses(() => InboundCatalog.Normalize(duplicate, secrets), "incompatible shared authentication accepted");
            var extra = secrets.DeepClone().AsObject(); extra["Users"]![Guid.NewGuid().ToString("N")] = new JsonObject { ["Value"] = "orphan" }; Refuses(() => InboundCatalog.Normalize(model, extra), "orphaned credential retained");
            var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json"); var state = ArchiveStore.ReadJson(stateFile);
            var options = InboundCatalog.Options(state, "Apply", model, secrets); var preview = InboundCatalog.Prepare(f.Store, new(OperationKind.Inbounds, f.Relative(plan), options));
            Check(preview.Affected.Length == 2 && !preview.Summary.Contains(secrets.Text("Users." + first.Strings("UserIds")[0] + ".Value")), "review missing scope or leaked password");
            var installed = plan.DeepClone().AsObject(); installed["InboundModel"] = model.DeepClone(); ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-plan.json"), installed);
            var allSecrets = f.Store.ReadSecret(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "secrets.dotnet.private.json")); allSecrets["Inbounds"] = secrets.DeepClone(); f.Store.WriteSecret(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "secrets.dotnet.private.json"), allSecrets); allSecrets.Clear();
            state["Inbounds"] = new JsonObject { ["RemoteHash"] = new string('e', 64), ["ModelFingerprint"] = ArchiveStore.Fingerprint(model), ["Core"] = preview.Payload["Core"]!.DeepClone(), ["Bindings"] = preview.Payload["Bindings"]!.DeepClone(), ["Runtime"] = new JsonObject() }; ArchiveStore.WriteJson(stateFile, state);
            OperationRequest Changed(JsonObject m, JsonObject s) => new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(state, "Apply", m, s));
            var named = model.DeepClone().AsObject(); named["Inbounds"]![0]!["Name"] = "new presentation name";
            Check(InboundCatalog.Prepare(f.Store, Changed(named, secrets)).Affected.Length == 0, "display name restarted a runtime");
            var rotated = secrets.DeepClone().AsObject(); rotated["Users"]![first.Strings("UserIds")[0]]!["Value"] = ServerConfigurations.RandomKey(16);
            Check(InboundCatalog.Prepare(f.Store, Changed(model, rotated)).Affected.Length == 2, "shared user rotation omitted a consumer");
            var own = secrets.DeepClone().AsObject(); own["Inbounds"]![first.Text("Id")]!["ServerKey"] = ServerConfigurations.RandomKey(16);
            Check(InboundCatalog.Prepare(f.Store, Changed(model, own)).Affected.SequenceEqual(new[] { first.Text("Id") }), "one inbound credential expanded the restart scope");
            var destination = model.DeepClone().AsObject(); destination["Outbounds"]![0]!["ExpectedAddress"] = "192.0.2.99";
            Check(InboundCatalog.Prepare(f.Store, Changed(destination, secrets)).Affected.Length == 2, "expected egress change bypassed actual validation");
            Refuses(() => new InstanceDeletion(f.Store).Review(f.Relative(plan)), "active inbound ownership archive could be deleted");
            var forward = ForwardConfig(first.Number("Listener.Port")); Refuses(() => TcpForwarding.Prepare(f.Store, new(OperationKind.TcpForward, f.Relative(plan), TcpForwarding.Options(state, "Apply", forward))), "TCP stole a reserved inbound port");
            var udp = new JsonObject { ["Version"] = 1, ["Rules"] = new JsonArray(UdpForwarding.NewRule()) }; udp["Rules"]![0]!["ListenPort"] = first.Number("Listener.Port"); udp["Rules"]![0]!["TargetAddress"] = "192.0.2.100"; udp["Rules"]![0]!["AllowedSources"] = new JsonArray("198.51.100.0/24"); udp["Rules"]![0]!["Validation"] = new JsonObject { ["Type"] = "Echo" };
            Refuses(() => UdpForwarding.Prepare(f.Store, new(OperationKind.UdpForward, f.Relative(plan), UdpForwarding.Options(state, "Apply", udp))), "UDP stole a reserved inbound port");
            var cert = InboundCertificate("inbound.example.com"); var certificate = InboundCatalog.ImportCertificate(model, secrets, "test certificate", cert.Certificate, cert.Key);
            var tls1 = InboundCatalog.AddInbound(model, secrets, "AnyTLS"); tls1["CertificateId"] = certificate.Text("Id"); tls1["Options"]!["ServerName"] = "inbound.example.com";
            var tls2 = InboundCatalog.AddInbound(model, secrets, "AnyTLS"); tls2["CertificateId"] = certificate.Text("Id"); tls2["Options"]!["ServerName"] = "inbound.example.com";
            Refuses(() => InboundCatalog.RemoveEntity(model, secrets, "Certificates", certificate.Text("Id")), "referenced certificate could be removed");
            var badTls = model.DeepClone().AsObject(); badTls["Inbounds"]![2]!["Options"]!["ServerName"] = "different.example.com"; Refuses(() => InboundCatalog.Normalize(badTls, secrets), "SNI mismatch accepted");
            if(OperatingSystem.IsWindows())
            {
            var reality = InboundCatalog.AddInbound(model, secrets, "Reality"); var tools = new ExternalToolRunner(); var assets = new ValidationAssets(new AppPaths(repository), "windows-amd64");
            var keys = await InboundKeyGeneration.RealityAsync(assets, tools, default); secrets["Inbounds"]![reality.Text("Id")]!["RealityPrivateKey"] = keys.Text("PrivateKey"); reality["Options"]!["PublicKey"] = keys.Text("PublicKey"); reality["Options"]!["ServerName"] = "www.example.com"; reality["Options"]!["HandshakeServer"] = "www.example.com"; keys.Clear();
            var ech = await InboundKeyGeneration.EchAsync(assets, tools, "inbound.example.com", default); tls2["Options"]!["EchEnabled"] = true; secrets["Inbounds"]![tls2.Text("Id")] = new JsonObject { ["EchKey"] = ech.Text("Key"), ["EchConfig"] = ech.Text("Config") }; ech.Clear();
            _ = InboundCatalog.Normalize(model, secrets);
            foreach (var inbound in InboundCatalog.Items(model, "Inbounds"))
            {
                var file = f.Paths.Resolve("render-" + inbound.Text("Id") + ".json"); ArchiveStore.WriteJson(file, InboundRendering.Configuration(f.Store, plan, model, secrets, inbound));
                var isReality = inbound.Text("Protocol") == "Reality"; var xray = Environment.GetEnvironmentVariable("MAY_TEST_XRAY");
                if (isReality && string.IsNullOrEmpty(xray)) { Console.WriteLine("SKIP: actual independent Reality config check requires MAY_TEST_XRAY; model and transaction assertions still run."); continue; }
                if (isReality && OperatingSystem.IsWindows()) Check(ArchiveStore.Digest(File.ReadAllBytes(xray!)) == "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1", "independent Reality test core is not the fixed Xray");
                var result = await tools.RunAsync(isReality ? xray! : assets.ResolveCore("sing-box"), isReality ? ["run", "-test", "-config", file] : ["check", "-c", file], null, TimeSpan.FromSeconds(15), default); result.RequireSuccess("Generic rendered inbound did not pass the pinned core."); Check(result.ExitCode == 0, "rendered protocol config invalid");
            }
            }
            else Console.WriteLine("SKIP: independent inbound key generation and executable checks require bundled Windows cores; model/source/transaction assertions still run.");
            _ = InboundCatalog.Normalize(model, secrets);
            var nodes = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, secrets).ToArray(); Check(nodes.Length == (OperatingSystem.IsWindows()?5:4) && nodes.All(n => n.Text("InboundOrigin.InboundId").Length == 32), "independent user/client projection incomplete");
            var evidence = await new InboundTestValidation(f.Store).ValidateAsync(plan, model, secrets, InboundCatalog.Items(model, "Inbounds").Select(i => i.Text("Id")).ToArray(), "unused", new InlineProgress<string>(_ => { }), default);
            InboundSources.RequireValidation(f.Store, plan, model, secrets, InboundCatalog.Items(model, "Inbounds").Select(i => i.Text("Id")).ToArray(), evidence); evidence["Items"]!.AsArray().RemoveAt(0);
            Refuses(() => InboundSources.RequireValidation(f.Store, plan, model, secrets, InboundCatalog.Items(model, "Inbounds").Select(i => i.Text("Id")).ToArray(), evidence), "one successful probe substituted for all users");
            void CommitModelForReview(JsonObject current)
            {
                var content = InboundRendering.Payload(f.Store, plan, current, secrets); installed["InboundModel"] = current.DeepClone(); ArchiveStore.WriteJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-plan.json"), installed);
                state.Put("Inbounds.ModelFingerprint", JsonValue.Create(ArchiveStore.Fingerprint(current))); state.Put("Inbounds.Bindings", content["Bindings"]!.DeepClone()); ArchiveStore.WriteJson(stateFile, state);
                var bundle = f.Store.ReadSecret(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "secrets.dotnet.private.json")); bundle["Inbounds"] = secrets.DeepClone(); f.Store.WriteSecret(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "secrets.dotnet.private.json"), bundle); bundle.Clear();
            }
            CommitModelForReview(model); var replacement = InboundCertificate("inbound.example.com"); var changedCerts = secrets.DeepClone().AsObject(); var certModel = model.DeepClone().AsObject(); InboundCatalog.ReplaceCertificate(InboundCatalog.Items(certModel, "Certificates").Single(), changedCerts, replacement.Certificate, replacement.Key);
            Check(InboundCatalog.Prepare(f.Store, Changed(certModel, changedCerts)).Affected.Order().SequenceEqual(new[] { tls1.Text("Id"), tls2.Text("Id") }.Order()), "shared certificate replacement included unrelated inbounds or missed a consumer");
            var expectedModel = model.DeepClone().AsObject(); expectedModel["Outbounds"]![0]!["ExpectedAddress"] = "192.0.2.88";
            Check(InboundRendering.BindingFingerprint(plan, model, secrets, first, f.Store) != InboundRendering.BindingFingerprint(plan, expectedModel, secrets, expectedModel["Inbounds"]![0]!.AsObject(), f.Store), "old client provenance ignored changed egress expectation");
            var sourceScheme = ClientSchemes.New(f.Paths); var native = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "external exit", ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = new JsonObject { ["type"] = "ss", ["server"] = "192.0.2.55", ["port"] = 34443, ["cipher"] = "chacha20-ietf-poly1305", ["password"] = "synthetic-exit-password" }, ["sing_box"] = new JsonObject { ["type"] = "shadowsocks", ["server"] = "192.0.2.55", ["server_port"] = 34443, ["method"] = "chacha20-ietf-poly1305", ["password"] = "synthetic-exit-password" } }; sourceScheme["Nodes"]!.AsArray().Add(native);
            var sourceFile = ServerOutboundRouting.SchemeFile(f.Paths, sourceScheme.Text("Id")); f.Store.WriteSecret(sourceFile, sourceScheme); var proxy = InboundCatalog.AddDirect(model, "independent proxy"); proxy["Kind"] = "Proxy"; proxy["Source"] = new JsonObject { ["SchemeId"] = sourceScheme.Text("Id"), ["NodeId"] = native.Text("Id"), ["Fingerprint"] = ArchiveStore.Fingerprint(native) }; first["OutboundId"] = proxy.Text("Id");
            var proxied = InboundRendering.Configuration(f.Store, plan, model, secrets, first); Check(proxied["outbounds"]![0]!.Text("password") == native.Text("sing_box.password") && proxied.Text("route.final") == "egress", "proxy outbound dropped auth or added a direct fallback");
            CommitModelForReview(model); native["sing_box"]!["password"] = "changed-synthetic-source"; f.Store.WriteSecret(sourceFile, sourceScheme); Refuses(() => InboundCatalog.Prepare(f.Store, Changed(model, secrets)), "changed source accepted without review");
            var removing = model.DeepClone().AsObject(); var removingSecrets = secrets.DeepClone().AsObject(); InboundCatalog.RemoveEntity(removing, removingSecrets, "Inbounds", first.Text("Id"));
            Check(InboundCatalog.Prepare(f.Store, Changed(removing, removingSecrets)).Affected.SequenceEqual(new[] { first.Text("Id") }), "removing a stale upstream required resolving obsolete auth"); secrets.Clear();
        }
        foreach (var failure in new[] { "none", "arm-ack", "apply-ack", "validation", "incomplete", "cancel", "commit-ack", "rollback", "drift" })
        {
            using var f = new Fixture(repository); var plan = f.Plan("Inbound-" + failure); plan.Put("Import.Status", JsonValue.Create("Completed")); plan.Put("Firewall.Mode", JsonValue.Create("PreserveExisting")); f.SaveInstance(plan);
            var (model, secrets) = InboundModel(); var remote = new InboundTestRemote { Failure = failure }; remote.Inner.SeedProtocols(plan);
            var validator = new InboundTestValidation(f.Store) { Failure = failure }; var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: validator));
            var directory = f.Paths.Instance(f.Relative(plan)); var stateFile = SafePath.Resolve(directory, "deployment-state.json");
            OperationRequest Request(string action = "Apply") => new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), action, model, secrets));
            var review = coordinator.Review(Request()); var records = new List<TaskProgress>(); var result = await coordinator.ExecuteAsync(review, Request(), new InlineProgress<TaskProgress>(records.Add), default);
            if (failure is "none" or "commit-ack")
            {
                Check(result.Outcome == (failure == "none" ? TaskOutcome.Completed : TaskOutcome.CompletedWithWarnings), "inbound commit failed: " + result.SafeError);
                var id = InboundCatalog.Items(model, "Inbounds").First(); var node = InboundSources.Create(f.Store, f.Relative(plan), id.Text("Id"), id.Strings("UserIds")[0], "IPv4");
                InboundSources.VerifyNodes(f.Store, [node]); Check(node.Text("sing_box.type") == "shadowsocks", "committed source unavailable");
                var publicFiles = Directory.EnumerateFiles(directory, "*.json", SearchOption.AllDirectories).Where(p => !p.EndsWith(".private.json"));
                var password = secrets.Text("Users." + id.Strings("UserIds")[0] + ".Value"); Check(publicFiles.All(p => !File.ReadAllText(p).Contains(password)), "public task/archive contains inbound credential");
                Check(remote.ApplyCalls == 1 && remote.Inner.ArmedComponents == "Inbounds", "wrong recovery scope or ACK replay");
                if (failure == "none")
                {
                    validator.Failure = "validation"; var checkedResult = await coordinator.ExecuteAsync(coordinator.Review(Request("Check")), Request("Check"), new InlineProgress<TaskProgress>(_ => { }), default);
                    Check(checkedResult.Outcome == TaskOutcome.Failed && remote.ApplyCalls == 1, "read-only failure made a mutation"); Refuses(() => InboundSources.VerifyNodes(f.Store, [node]), "failed recheck retained exportable success"); validator.Failure = "";
                    Check((await coordinator.ExecuteAsync(coordinator.Review(Request("Check")), Request("Check"), new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Completed, "successful recheck not promoted");
                    var changed = secrets.DeepClone().AsObject(); changed["Inbounds"]![id.Text("Id")]!["ServerKey"] = ServerConfigurations.RandomKey(16); var edit = new OperationRequest(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "Apply", model, changed));
                    Check((await coordinator.ExecuteAsync(coordinator.Review(edit), edit, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Completed, "scoped second update failed"); Check(remote.LastAffected.SequenceEqual(new[] { id.Text("Id") }), "second update included another inbound"); Refuses(() => InboundSources.VerifyNodes(f.Store, [node]), "rotated credential source remained usable");
                }
            }
            else
            {
                Check(result.Outcome == (failure == "rollback" ? TaskOutcome.NeedsRecovery : failure == "cancel" ? TaskOutcome.Cancelled : TaskOutcome.Failed), "unexpected inbound failure " + failure + ": " + result.Outcome + " " + result.SafeError);
                Check(remote.ApplyCalls <= 1, "lost apply acknowledgement replayed");
                if (failure != "rollback") { Check(ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"))["InboundModel"] == null && remote.Current == null, "failed task left partial ownership"); }
            }
            secrets.Clear();
        }
    }
    private sealed class InboundTestValidation(ArchiveStore store) : IInboundValidation
    {
        public string Failure { get; set; } = "";
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject model, JsonObject credentials, string[] ids, string directory, IProgress<string> progress, CancellationToken cancellationToken)
        {
            if (Failure is "validation" or "rollback") throw new OperationException("synthetic HTTPS validation failure"); if (Failure == "cancel") throw new OperationCanceledException();
            var items = new JsonArray();
            foreach (var node in InboundRendering.Nodes(store, plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy", plan, model, credentials).Where(n => ids.Contains(n.Text("InboundOrigin.InboundId")))) items.Add(new JsonObject { ["InboundId"] = node.Text("InboundOrigin.InboundId"), ["UserId"] = node.Text("InboundOrigin.UserId"), ["Family"] = node.Text("InboundOrigin.Family"), ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(node), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "ProxyHttps", ["Result"] = new JsonObject { ["Status"] = "Reachable" } });
            if (Failure == "incomplete") items.RemoveAt(0); return Task.FromResult(new JsonObject { ["Status"] = "Passed", ["Items"] = items });
        }
    }
    private sealed class InboundTestRemote : IRemoteSessionFactory, IRemoteSession
    {
        public FakeRemote Inner { get; } = new(); public string Failure { get; set; } = ""; public JsonObject? Current { get; private set; } private JsonObject? original;
        public int ApplyCalls { get; private set; } public string[] LastAffected { get; private set; } = [];
        public Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction user, CancellationToken cancellationToken) => Task.FromResult<IRemoteSession>(this);
        public Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken ct) => Inner.RunAsync(command, timeout, ct);
        private static string Parameter(string payload, string name) { var match = Regex.Match(payload, "export VPS_PARAM_" + name + "=.+?'([A-Za-z0-9+/=]*)' "); return match.Success ? Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[1].Value)) : ""; }
        public async Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken ct)
        {
            var asset = payload.Split('\n')[0].Replace("# MXH asset: ", "");
            if (asset == "inbound-read.sh")
            {
                var state = new JsonObject { ["Hash"] = Failure == "drift" ? new string('f', 64) : Current == null ? "Absent" : ArchiveStore.Fingerprint(Current), ["Registry"] = Current == null ? null : new JsonObject { ["Model"] = Current["Model"]!.DeepClone(), ["Bindings"] = Current["Bindings"]!.DeepClone() }, ["Runtime"] = new JsonObject() };
                if (Current != null) foreach (var b in Current["Bindings"]!.AsArray()) state["Runtime"]![b!.Text("Id")] = new JsonObject { ["Enabled"] = b.Flag("Enabled"), ["Active"] = b.Flag("Enabled") };
                return new(0, "VPSDEPLOY_INBOUND_STATE_B64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(state.ToJsonString())) + "\nVPSDEPLOY_INBOUND_READ\n", "");
            }
            if (asset == "protocol-migration-arm-rollback.sh") { original = Current?.DeepClone().AsObject(); Inner.StatusTaskId = Parameter(payload, "CONTROL_TASK_ID"); var armed = await Inner.RunScriptAsync(payload, timeout, mutating, ct); Inner.StatusPhase = "Armed"; if (Failure == "arm-ack") throw new IOException("synthetic lost arm acknowledgement"); return armed; }
            if (asset == "inbound-apply.sh")
            {
                ApplyCalls++; var document = Regex.Match(payload, @"(?m)^([A-Za-z0-9+/=]+)\nMAY_INBOUND_DOCUMENT_B64$").Groups[1].Value; Current = JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(document)))!.AsObject(); LastAffected = JsonNode.Parse(Parameter(payload, "INBOUND_AFFECTED"))!.AsArray().Select(n => n!.ToString()).ToArray();
                if (Failure == "apply-ack") throw new IOException("synthetic lost apply acknowledgement"); return new(0, "VPSDEPLOY_INBOUND_APPLIED\n", "");
            }
            if (asset == "maintenance-transaction-commit.sh" && Failure == "commit-ack") { Inner.StatusPhase = "Committed"; throw new IOException("synthetic lost commit acknowledgement"); }
            if (asset == "protocol-migration-trigger-rollback.sh") { if (Failure == "rollback") throw new IOException("synthetic rollback disconnected"); Current = original?.DeepClone().AsObject(); }
            return await Inner.RunScriptAsync(payload, timeout, mutating, ct);
        }
        public Task DownloadAsync(string remotePath, string localPath, CancellationToken ct) => Inner.DownloadAsync(remotePath, localPath, ct);
        public Task<byte[]> ReadFileAsync(string remotePath, CancellationToken ct) => Inner.ReadFileAsync(remotePath, ct);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
