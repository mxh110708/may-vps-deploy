using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task ConfigureInbounds(Context c)
    {
        var preview = InboundCatalog.Prepare(store, c.Request); c.InboundsPreview = preview;
        var check = c.Request.Options.Text("Action") == "Check";
        async Task<JsonObject> Read(bool candidate = false)
        {
            var parameters = new Dictionary<string, string>();
            if (candidate) { parameters["INBOUND_DOCUMENT"] = preview.Payload.ToJsonString(); parameters["INBOUND_AFFECTED"] = new JsonArray(preview.Affected.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray()).ToJsonString(); }
            var response = await c.Run("inbound-read.sh", parameters, timeout: 180, marker: "INBOUND_READ");
            return JsonNode.Parse(RemoteAssets.Marker(response.Output, "INBOUND_STATE"))!.AsObject();
        }
        try
        {
            await c.TrackStep("inbound-preflight", async () =>
            {
                var audit = await c.Run("audit.sh"); Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
                await VerifyManagement(c); var observed = await Read(!check);
                if (observed.Text("Hash") != preview.ExpectedHash || preview.ExpectedHash != "Absent" && !JsonNode.DeepEquals(observed.At("Registry.Model"), c.Plan["InboundModel"])) throw new OperationException("实际入站资源或目录与归档不同，未修改远端。", code: "InboundRemoteDrift");
                if ((!check || Hysteria2Ports.Redirects(c.Plan).Count > 0) && c.Plan.Text("Firewall.Mode") != "PreserveExisting") await c.Run("firewall-preflight.sh", FirewallParameters(c.Plan, true), marker: "FIREWALL_SCOPE_OK");
            });
            if (!check)
            {
                await c.TrackStep("inbound-backup", () => Arm(c, c.Plan.Text("Firewall.Mode") == "PreserveExisting" ? ["Inbounds"] : ["Inbounds", "Firewall"]));
                await c.TrackStep("inbound-apply", async () =>
                {
                    c.Plan["InboundModel"] = preview.Model.DeepClone(); c.Secrets["Inbounds"] = preview.Credentials.DeepClone(); c.Save();
                    await c.Run("inbound-apply.sh", new() { ["INBOUND_DOCUMENT"] = preview.Payload.ToJsonString(), ["INBOUND_EXPECTED_HASH"] = preview.ExpectedHash, ["INBOUND_AFFECTED"] = new JsonArray(preview.Affected.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray()).ToJsonString() }, true, 300, "INBOUND_APPLIED");
                    await Firewall(c, true);
                });
            }
            await c.TrackStep("inbound-validation", async () =>
            {
                var observed = await Read();
                if (!JsonNode.DeepEquals(observed.At("Registry.Model"), preview.Model) && !(preview.ExpectedHash == "Absent" && check && !InboundCatalog.Items(preview.Model, "Inbounds").Any())) throw new OperationException("实际入站目录与审阅模型不同。");
                var ids = check ? InboundCatalog.Items(preview.Model, "Inbounds").Select(i => i.Text("Id")).ToArray() : preview.Affected;
                var running = InboundCatalog.Items(preview.Model, "Inbounds").Where(i => ids.Contains(i.Text("Id")) && i.Flag("Enabled")).ToArray();
                var mismatch = InboundCatalog.Items(preview.Model, "Inbounds").Where(i => ids.Contains(i.Text("Id"))).Any(i => observed.Flag("Runtime." + i.Text("Id") + ".Active") != i.Flag("Enabled") || observed.Flag("Runtime." + i.Text("Id") + ".Enabled") != i.Flag("Enabled"));
                JsonObject result;
                if (mismatch && check) { result = new JsonObject { ["Status"] = "RuntimeMismatch", ["Items"] = new JsonArray() }; c.Warnings = true; c.Report("入站运行状态不符", "已保存实际启停状态；请重新审阅保存，按明确影响范围恢复运行。"); }
                else
                {
                    if (mismatch) throw new OperationException("本次启用的入站未全部正常运行，恢复本次范围。");
                    if (inboundValidation == null && running.Length > 0) throw new OperationException("通用入站实际验收适配器不可用。");
                    result = running.Length == 0 ? new JsonObject { ["Status"] = "Passed", ["Items"] = new JsonArray() } : await inboundValidation!.ValidateAsync(c.Plan, preview.Model, preview.Credentials, ids, c.File("inbound-validation/" + c.Id), new InlineProgress<string>(m => c.Report("入站代理 HTTPS 验收", m)), c.Cancellation);
                    InboundSources.RequireValidation(store, c.Plan, preview.Model, preview.Credentials, ids, result);
                }
                var after = await Read(); if (after.Text("Hash") != observed.Text("Hash")) throw new OperationException("验收期间入站资源发生变化，未提交。");
                var previous = (c.State.At("Inbounds.ValidationById")?.DeepClone() ?? new JsonObject()).AsObject();
                foreach (var id in ids) previous.Remove(id);
                foreach (var group in (result["Items"] as JsonArray ?? []).OfType<JsonObject>().GroupBy(i => i.Text("InboundId"))) previous[group.Key] = new JsonObject { ["Status"] = "Passed", ["Items"] = new JsonArray(group.Select(i => i.DeepClone()).ToArray()), ["At"] = DateTimeOffset.UtcNow };
                foreach (var id in previous.Select(p => p.Key).Where(id => !InboundCatalog.Items(preview.Model, "Inbounds").Any(i => i.Text("Id") == id)).ToArray()) previous.Remove(id);
                c.State["Inbounds"] = new JsonObject { ["RemoteHash"] = observed.Text("Hash"), ["ModelFingerprint"] = ArchiveStore.Fingerprint(preview.Model), ["Core"] = preview.Payload["Core"]!.DeepClone(), ["Bindings"] = observed.At("Registry.Bindings")?.DeepClone() ?? new JsonArray(), ["Runtime"] = observed["Runtime"]!.DeepClone(), ["ValidationById"] = previous, ["LastCheck"] = mismatch ? "RuntimeMismatch" : "Passed", ["At"] = DateTimeOffset.UtcNow };
                await VerifyManagement(c); c.Save();
            });
            if (!check) await c.TrackStep("inbound-commit", () => Commit(c));
        }
        catch when (check)
        {
            c.State.Put("Inbounds.LastCheck", JsonValue.Create("Failed"));
            c.State.Put("Inbounds.ValidationById", new JsonObject()); c.Save(); throw;
        }
        finally { preview.Credentials.Clear(); preview.Payload["Configurations"]!.AsObject().Clear(); }
    }
}
