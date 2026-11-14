using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task ConfigureCertificate(Context c)
    {
        _ = ManagedCertificates.Prepare(store, c.Request);
        var o = c.Request.Options; var id = o.Text("CertificateId"); var action = o.Text("Action");
        var model = (c.Plan["InboundModel"] ?? InboundCatalog.Empty()).DeepClone().AsObject();
        var credentials = (c.Secrets["Inbounds"] ?? InboundCatalog.EmptyCredentials()).DeepClone().AsObject();
        var document = o.DeepClone().AsObject(); document.Remove("TokenFile");
        async Task<JsonObject> ReadInbound()
        {
            var response = await c.Run("inbound-read.sh", timeout: 180, marker: "INBOUND_READ");
            return JsonNode.Parse(RemoteAssets.Marker(response.Output, "INBOUND_STATE"))!.AsObject();
        }
        async Task<JsonObject> ReadCertificate()
        {
            var response = await c.Run("managed-certificate-read.sh", new() { ["CERTIFICATE_DOCUMENT"] = document.ToJsonString() }, timeout: 60, marker: "CERTIFICATE_READ");
            var observation = JsonNode.Parse(RemoteAssets.Marker(response.Output, "CERTIFICATE_RESULT"))!["Observation"]!.AsObject();
            ManagedCertificates.RequireObservation(observation, o["Policy"]!.AsObject()); return observation;
        }
        try
        {
            var consumers = InboundCatalog.Items(model, "Inbounds").Where(i => i.Text("CertificateId") == id).Select(i => i.Text("Id")).ToArray();
            await c.TrackStep("certificate-preflight", async () =>
            {
                var audit = await c.Run("audit.sh"); Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
                await VerifyManagement(c);
                var inbound = await ReadInbound();
                if (inbound.Text("Hash") != o.Text("ExpectedHash") || inbound.Text("Hash") != "Absent" && !JsonNode.DeepEquals(inbound.At("Registry.Model"), model)) throw new OperationException("入站实际状态与归档不同，请先核对。", code: "InboundRemoteDrift");
                var observation = await ReadCertificate();
                if (action != "Check" && observation.Text("Hash") != o.Text("ExpectedCertificateHash")) throw new OperationException("证书已续期或状态已变化，请先检查证书，再重新审阅。", code: "CertificateRemoteDrift");
                if (action != "Issue" && (!JsonNode.DeepEquals(observation["Policy"], o["Policy"]) || observation.Text("Hash") == "Absent")) throw new OperationException("证书实际策略与归档不符。");
                if (action != "Check")
                {
                    var original = new OperationRequest(OperationKind.Inbounds, c.Request.InstanceRelativePath, InboundCatalog.Options(c.State, "Check", model, credentials));
                    c.InboundsPreview = InboundCatalog.Prepare(store, original);
                }
            });
            if (action != "Check")
            {
                await c.TrackStep("certificate-backup", () => Arm(c, ["Inbounds", "Certificates"]));
                await c.TrackStep("certificate-apply", async () =>
                {
                    if (action == "Issue") await c.Run("managed-certificate-prepare.sh", mutation: true, timeout: 600, marker: "CERTIFICATE_PREPARED");
                    if (action is "Issue" or "RotateToken") document["Token"] = ManagedCertificates.ReadToken(o.Text("TokenFile"));
                    var response = await c.Run("managed-certificate-apply.sh", new() { ["CERTIFICATE_DOCUMENT"] = document.ToJsonString() }, true, 900, "CERTIFICATE_APPLIED");
                    document.Remove("Token");
                    var result = JsonNode.Parse(RemoteAssets.Marker(response.Output, "CERTIFICATE_RESULT"))!.AsObject();
                    try
                    {
                        if (action == "Issue")
                        {
                            var material = result["Material"]!.AsObject(); ManagedCertificates.RequireCertificate(material, o["Policy"]!.AsObject());
                            var certificate = InboundCatalog.ImportCertificate(model, credentials, o.Text("Name"), material.Text("CertificatePem"), material.Text("PrivateKeyPem"));
                            var generated = certificate.Text("Id"); credentials["Certificates"]![id] = credentials["Certificates"]![generated]!.DeepClone(); credentials["Certificates"]!.AsObject().Remove(generated);
                            certificate["Id"] = id; certificate["Managed"] = o["Policy"]!.DeepClone();
                        }
                        if (action == "Remove")
                        {
                            var certificate = InboundCatalog.Items(model, "Certificates").Single(i => i.Text("Id") == id); model["Certificates"]!.AsArray().Remove(certificate); credentials["Certificates"]!.AsObject().Remove(id);
                        }
                        if (action is "Issue" or "Remove")
                        {
                            var payload = InboundRendering.Payload(store, c.Plan, InboundCatalog.Normalize(model, credentials), credentials, c.InboundsPreview!.Payload["Core"]!.AsObject());
                            c.Plan["InboundModel"] = model.DeepClone(); c.Secrets["Inbounds"] = credentials.DeepClone(); c.Save();
                            try { await c.Run("inbound-apply.sh", new() { ["INBOUND_DOCUMENT"] = payload.ToJsonString(), ["INBOUND_EXPECTED_HASH"] = o.Text("ExpectedHash"), ["INBOUND_AFFECTED"] = "[]" }, true, 180, "INBOUND_APPLIED"); }
                            finally { payload["Configurations"]!.AsObject().Clear(); }
                        }
                    }
                    finally { result.Clear(); }
                });
            }
            await c.TrackStep("certificate-validation", async () =>
            {
                var observation = await ReadCertificate();
                if (action == "Remove" ? observation.Text("Hash") != "Absent" : observation.Text("Hash") == "Absent" || !JsonNode.DeepEquals(observation["Policy"], o["Policy"])) throw new OperationException("证书操作后的状态未符合审阅。");
                if (action != "Remove" && consumers.Length > 0)
                {
                    if (inboundValidation == null) throw new OperationException("入站实际验收适配器不可用。");
                    var validationResult = await inboundValidation.ValidateAsync(c.Plan, model, credentials, consumers, c.File("certificate-validation/" + c.Id), new InlineProgress<string>(m => c.Report("证书代理验收", m)), c.Cancellation);
                    await ValidateInboundPolicies(c, model, credentials, consumers, validationResult);
                    InboundSources.RequireValidation(store, c.Plan, model, credentials, consumers, validationResult);
                }
                var after = await ReadInbound();
                if (!JsonNode.DeepEquals(after.At("Registry.Model"), model) && !(o.Text("ExpectedHash") == "Absent" && action == "Check")) throw new OperationException("证书操作后入站目录不符。");
                if (action is "Issue" or "Remove")
                {
                    c.State["Inbounds"] ??= new JsonObject();
                    c.State.Put("Inbounds.RemoteHash", JsonValue.Create(after.Text("Hash")));
                    c.State.Put("Inbounds.ModelFingerprint", JsonValue.Create(ArchiveStore.Fingerprint(model)));
                    c.State.Put("Inbounds.Core", after.At("Registry.Core")!.DeepClone());
                    c.State.Put("Inbounds.Bindings", after.At("Registry.Bindings")!.DeepClone());
                    c.State.Put("Inbounds.Runtime", after["Runtime"]!.DeepClone());
                }
                c.State["Certificates"] ??= new JsonObject();
                if (action == "Remove") c.State["Certificates"]!.AsObject().Remove(id);
                else c.State["Certificates"]![id] = new JsonObject { ["RemoteHash"] = observation.Text("Hash"), ["Observation"] = observation["State"]!.DeepClone(), ["LastCheck"] = "Passed", ["At"] = DateTimeOffset.UtcNow };
                await VerifyManagement(c); c.Save();
            });
            if (action != "Check") await c.TrackStep("certificate-commit", () => Commit(c));
        }
        catch when (action == "Check")
        {
            c.State.Put("Certificates." + id + ".LastCheck", JsonValue.Create("Failed"));
            var evidence = c.State.At("Inbounds.ValidationById") as JsonObject;
            foreach (var inbound in InboundCatalog.Items(model,"Inbounds").Where(i=>i.Text("CertificateId")==id)) evidence?.Remove(inbound.Text("Id"));
            c.Save(); throw;
        }
        finally { credentials.Clear(); document.Clear(); c.InboundsPreview?.Credentials.Clear(); c.InboundsPreview?.Payload["Configurations"]!.AsObject().Clear(); }
    }
}
