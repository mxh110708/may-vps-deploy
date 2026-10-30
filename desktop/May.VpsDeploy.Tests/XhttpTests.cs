using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task XhttpModel()
    {
        using var f = new Fixture(repository); var plan = f.Plan("Xhttp-model"); plan.Put("Import.Status", JsonValue.Create("Completed")); f.SaveInstance(plan);
        var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var sibling = InboundCatalog.AddInbound(model, credentials, "Shadowsocks2022"); var tls = InboundCatalog.AddInbound(model, credentials, "VLESS"); var reality = InboundCatalog.AddInbound(model, credentials, "VLESS");
        var cert = InboundCertificate("xhttp.example.test"); var certificate = InboundCatalog.ImportCertificate(model, credentials, "TLS", cert.Certificate, cert.Key); tls["CertificateId"] = certificate.Text("Id");
        foreach (var item in new[] { tls, reality }) { item["Options"]!["ServerName"] = "xhttp.example.test"; item["Options"]!["Transport"]!["Host"] = "front.example.test"; }
        reality["Options"]!["Security"] = "Reality"; reality["Options"]!["Reality"] = VlessXhttp.RealityOptions(); reality["Options"]!["Reality"]!["HandshakeServer"] = "target.example.test"; reality["Options"]!["Reality"]!["PublicKey"] = new string('A', 43); credentials["Inbounds"]![reality.Text("Id")]!["RealityPrivateKey"] = new string('A', 43);
        Check(JsonNode.DeepEquals(model, InboundCatalog.Normalize(model, credentials)), "XHTTP normalization changed identities");
        var payload = InboundRendering.Payload(f.Store, plan, model, credentials); var tlsConfig = InboundRendering.Configuration(f.Store, plan, model, credentials, tls); var realityConfig = InboundRendering.Configuration(f.Store, plan, model, credentials, reality);
        Check(tlsConfig["inbounds"]![0]!.Text("protocol") == "vless" && tlsConfig["inbounds"]![0]!.Text("streamSettings.network") == "xhttp" && tlsConfig["inbounds"]![0]!.Text("streamSettings.security") == "tls" && tlsConfig["inbounds"]![0]!["streamSettings"]!["tlsSettings"]!["alpn"]![0]!.ToString() == "h2", "TLS XHTTP rendering lost protocol or h2");
        Check(realityConfig["inbounds"]![0]!.Text("streamSettings.security") == "reality" && realityConfig["inbounds"]![0]!.At("streamSettings.tlsSettings") == null && !realityConfig.ToJsonString().Contains("xtls-rprx-vision"), "Reality XHTTP gained a TLS certificate or Vision flow");
        Check(payload["Bindings"]!.AsArray().Where(b => b!.Text("Id") != sibling.Text("Id")).All(b => !b!.Flag("Udp")), "XHTTP opened a UDP transport listener instead of encapsulated application UDP");
        var nodes = InboundRendering.Nodes(f.Store, f.Relative(plan), plan, model, credentials).Where(VlessXhttp.IsNode).ToArray();
        Check(nodes.Length == 2 && nodes.All(n => n.Text("sing_box.transport.type") == "xhttp" && n.Text("clash.network") == "xhttp"), "XHTTP lost either native client projection");
        foreach (var node in nodes) { _ = VlessXhttp.RequireClash(node); _=VlessXhttp.RequireNative(node); var scheme = ClientSchemes.New(f.Paths); scheme["Nodes"] = new JsonArray(node.DeepClone()); Check(ClientCapabilities.Inspect(scheme).All(r=>r.Ready), "XHTTP missing May Core/Mihomo capability"); Check(ClientShareLinks.Preview(scheme).Rows[0].Ready, "XHTTP share URI cannot round-trip its parameters"); var route = ClientTopology.DiagnosticRoute(scheme, node.Text("name")); Check(ClientTopology.DiagnosticConfiguration(route,14001,14002)["outbounds"]![0]!.Text("transport.type")=="xhttp","XHTTP native diagnostic dropped transport"); }
        foreach (var edit in new Action<JsonObject>[] { i => i["Options"]!["Security"] = "none", i => i["Options"]!["Transport"]!["Type"] = "ws", i => i["Options"]!["Transport"]!["Mode"] = "unknown", i => i["Options"]!["Transport"]!["Path"] = "/bad\npath", i => i["Options"]!["Transport"]!["Extra"] = new JsonObject{["unknown"]=true}, i => i["Options"]!["Transport"]!["Host"] = "bad\nheader", i => i["Options"]!["extra"] = new JsonObject(), i => i["Options"]!["Reality"]!["PublicKey"] = "unused" })
        { var m = model.DeepClone().AsObject(); edit(m["Inbounds"]![1]!.AsObject()); Refuses(() => InboundCatalog.Normalize(m, credentials), "XHTTP silently accepted unsupported model option"); }
        var invalid = model.DeepClone().AsObject(); invalid["Inbounds"]![2]!["CertificateId"] = certificate.Text("Id"); Refuses(() => InboundCatalog.Normalize(invalid, credentials), "Reality XHTTP consumed TLS certificate reference");
        invalid = model.DeepClone().AsObject(); invalid["Inbounds"]![1]!["Options"]!["ServerName"] = "wrong.example.test"; Refuses(() => InboundCatalog.Normalize(invalid, credentials), "TLS XHTTP accepted certificate identity mismatch");
        Refuses(() => InboundCatalog.RemoveEntity(model, credentials, "Certificates", certificate.Text("Id")), "XHTTP referenced certificate could be removed");
        var stateFile = SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-state.json"); var remote = new InboundTestRemote(); remote.Inner.SeedProtocols(plan); var validator = new XhttpModelValidation(f.Store); var coordinator = new TaskCoordinator(f.Store, new WorkflowEngine(f.Store, remote, new FakeKeys(), new FakeUser(), new FakeValidation(), inboundValidation: validator));
        OperationRequest Operation(string action = "Apply") => new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), action, model, credentials));
        async Task<TaskRecord> Execute() { var r = Operation(); return await coordinator.ExecuteAsync(coordinator.Review(r), r, new InlineProgress<TaskProgress>(_ => { }), default); }
        Check((await Execute()).Outcome == TaskOutcome.Completed, "XHTTP model workflow did not commit");
        var current = InboundSources.Create(f.Store, f.Relative(plan), tls.Text("Id"), tls.Strings("UserIds")[0], "IPv4"); Check(current["sing_box"] != null, "provenance lost native May Core source");
        var both = ClientSchemes.New(f.Paths);ForwardedNodeSources.Apply(f.Store, both, [current], "US-West-LA Entry"); Check(both["Nodes"]![0]!.Text("Id") == current.Text("Id"), "XHTTP source lost stable user identity");
        var before = ArchiveStore.ReadJson(stateFile).Text("Inbounds.RemoteHash"); validator.BadEvidence = true; tls["Options"]!["Transport"]!["Path"] = "/changed/";
        Check((await Execute()).Outcome == TaskOutcome.Failed && ArchiveStore.ReadJson(stateFile).Text("Inbounds.RemoteHash") == before, "HTTPS-only evidence committed XHTTP or failed scoped restoration"); validator.BadEvidence = false; tls["Options"]!["Transport"]!["Path"] = "/updated/";
        var preview = InboundCatalog.Prepare(f.Store, Operation()); Check(preview.Affected.SequenceEqual([tls.Text("Id")]) && preview.Summary.Contains("XHTTP") && !preview.Summary.Contains(credentials.Text("Users." + tls.Strings("UserIds")[0] + ".Value")), "path change widened scope or review leaked UUID");
        Check((await Execute()).Outcome == TaskOutcome.Completed, "XHTTP path update failed after restoring typed evidence"); Refuses(() => InboundSources.VerifyNodes(f.Store, [current]), "changed path retained old source qualification");
        var m2 = model.DeepClone().AsObject(); var s2 = credentials.DeepClone().AsObject(); InboundCatalog.ReplaceCertificate(InboundCatalog.Items(m2, "Certificates").Single(), s2, cert.Certificate, cert.Key);
        var changed = InboundCertificate("xhttp.example.test"); InboundCatalog.ReplaceCertificate(InboundCatalog.Items(m2, "Certificates").Single(), s2, changed.Certificate, changed.Key);
        Check(InboundCatalog.Prepare(f.Store, new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "Apply", m2, s2))).Affected.SequenceEqual([tls.Text("Id")]), "TLS rotation restarted Reality or sibling inbound");
        reality["Options"]!["Reality"]!["ShortId"] = "abcd5678"; Check(InboundCatalog.Prepare(f.Store, Operation()).Affected.SequenceEqual([reality.Text("Id")]), "Reality identity rotation restarted TLS or sibling inbound"); reality["Options"]!["Reality"]!["ShortId"] = InboundCatalog.Items(ArchiveStore.ReadJson(SafePath.Resolve(f.Paths.Instance(f.Relative(plan)), "deployment-plan.json"))["InboundModel"]!.AsObject(), "Inbounds").Single(i => i.Text("Id") == reality.Text("Id")).Text("Options.Reality.ShortId");
        if (Environment.GetEnvironmentVariable("MAY_TEST_PYTHON") is {} python)
        {
            var wb = new ClientWorkbench(f.Store, new ExternalToolRunner(), new ValidationAssets(new AppPaths(repository), "windows-amd64"), python); var node = InboundSources.Create(f.Store, f.Relative(plan), tls.Text("Id"), tls.Strings("UserIds")[0], "IPv4"); both["Nodes"] = new JsonArray(node);
            await wb.BuildAsync(both, default); await wb.ValidateAsync(both, default); Check(both.Text("Candidate.ValidationStatus") == "Passed" && both.Text("Candidate.SingBox") != "" && both.Text("Candidate.Clash") != "", "XHTTP dual candidate was not validated with matching native cores");
            var read = await wb.ReadSourcesAsync(both.Text("Candidate.Clash"), both.Text("Candidate.SingBox"), default); Check(read.Count == 1 && read[0]!.Text("clash.network") == "xhttp" && read[0]!.Text("sing_box.transport.type") == "xhttp", "XHTTP lost native data when reading the dual source");
            var mayOnly=both.DeepClone().AsObject();mayOnly["OutputClients"]="SingBox";
            await wb.BuildAsync(mayOnly,default);await wb.ValidateAsync(mayOnly,default);Check(mayOnly.Text("Candidate.ValidationStatus")=="Passed"&&mayOnly["Candidate"]!["Clash"]==null,"May-only XHTTP candidate required Mihomo output");
        }
        OperationRequest Upgrade() => new(OperationKind.Inbounds, f.Relative(plan), InboundCatalog.Options(ArchiveStore.ReadJson(stateFile), "UpgradeXray", model, credentials));
        Refuses(() => coordinator.Review(Upgrade()), "same Xray pin was accepted as an upgrade"); var priorCore = ArchiveStore.ReadJson(stateFile)["Inbounds"]!["Core"]!.DeepClone(); var versions = f.Versions; versions.Put("xray.assets.amd64.sha256", JsonValue.Create(new string('f', 64))); ArchiveStore.WriteJson(f.Paths.Resolve("config/versions.json"), versions);
        Refuses(() => coordinator.Review(Upgrade()), "same-version Xray replacement was accepted"); versions.Put("xray.version", JsonValue.Create("26.4.1")); ArchiveStore.WriteJson(f.Paths.Resolve("config/versions.json"), versions);
        var upgraded = InboundCatalog.Prepare(f.Store, Upgrade()); var expectedAffected = new[] { tls.Text("Id"), reality.Text("Id") }.Order(StringComparer.Ordinal);
        Check(upgraded.Affected.SequenceEqual(expectedAffected) && upgraded.Payload.Text("Core.Version") == priorCore.Text("Version") && upgraded.Payload.Text("Core.Sha256") == priorCore.Text("Sha256"), "Xray upgrade touched sing-box or omitted an XHTTP inbound");
        validator.BadEvidence = true; var upgrade = Upgrade(); Check((await coordinator.ExecuteAsync(coordinator.Review(upgrade), upgrade, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Failed && JsonNode.DeepEquals(ArchiveStore.ReadJson(stateFile)["Inbounds"]!["Core"], priorCore), "failed Xray upgrade did not restore prior core pins");
        validator.BadEvidence = false; upgrade = Upgrade(); Check((await coordinator.ExecuteAsync(coordinator.Review(upgrade), upgrade, new InlineProgress<TaskProgress>(_ => { }), default)).Outcome == TaskOutcome.Completed && ArchiveStore.ReadJson(stateFile).Text("Inbounds.Core.Reality.Version") == "26.4.1", "explicit Xray pin upgrade did not commit");
        credentials.Clear();
    }
    private static JsonObject XhttpTestResult(JsonObject node) => new() { ["Status"] = "Reachable", ["ValidatedProtocol"] = "vless", ["Transport"] = "xhttp", ["TransportSecurity"] = VlessXhttp.Security(node), ["TransportAlpn"] = "h2", ["ClientCore"] = "mihomo", ["UdpValidation"] = new JsonObject { ["ResponseMatched"] = true, ["Transport"] = "UDP" }, ["Stages"] = new JsonArray(new JsonObject { ["Id"] = "EntryHttps", ["Status"] = "Passed" }) };
    private sealed class XhttpModelValidation(ArchiveStore store) : IInboundValidation
    {
        public bool BadEvidence;
        public Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject model, JsonObject credentials, string[] ids, string directory, IProgress<string> progress, CancellationToken ct)
        {
            var nodes = InboundRendering.Nodes(store, plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy", plan, model, credentials).Where(n => ids.Contains(n.Text("InboundOrigin.InboundId")));
            var items = new JsonArray(nodes.Select(n => { var result = VlessXhttp.IsNode(n) ? XhttpTestResult(n) : new JsonObject { ["Status"] = "Reachable" }; if (BadEvidence) result.Remove("Transport"); return (JsonNode)new JsonObject { ["InboundId"] = n.Text("InboundOrigin.InboundId"), ["UserId"] = n.Text("InboundOrigin.UserId"), ["Family"] = n.Text("InboundOrigin.Family"), ["ConnectionFingerprint"] = ClientNodeImport.ConnectionFingerprint(n), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "ProxyHttps", ["Result"] = result }; }).ToArray());
            return Task.FromResult(new JsonObject { ["Status"] = "Passed", ["Items"] = items });
        }
    }
}
