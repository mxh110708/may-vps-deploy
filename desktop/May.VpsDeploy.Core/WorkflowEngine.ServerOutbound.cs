using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private static void RestoreRoleChild(JsonObject target, JsonObject old, string parent, string role)
    {
        if (old[parent] is JsonObject previous && previous[role] != null) target.Put(parent + "." + role, previous[role]!.DeepClone());
        else if (target[parent] is JsonObject current) { current.Remove(role); if (current.Count == 0) target.Remove(parent); }
    }
    private async Task VerifyCurrentServerOutbound(Context c, string role)
    {
        if (!ServerOutboundRouting.Roles.Contains(role) || c.Plan.At("ServerOutbound." + role) == null) return;
        var read = await c.Run("server-outbound-read.sh", new() { ["ROLE"] = role }, marker: "SERVER_OUTBOUND_READ");
        if (RemoteAssets.Marker(read.Output, "SERVER_CONFIG_SHA256") != c.State.Text("ServerConfigHashes." + role)) throw new OperationException("服务器固定链路的实际配置已变化，请先核对漂移，未开始维护。", code: "ServerOutboundRemoteDrift");
        ServerOutboundRouting.VerifyManaged(role, JsonNode.Parse(RemoteAssets.Marker(read.Output, "SERVER_CONFIG"))!.AsObject(), c.Plan);
    }
    private static void RequireMaintainedRouteValidation(Context c, JsonObject result)
    {
        if (result.Text("Status") == "Passed") return;
        var roles = ServerOutboundRouting.Roles.Where(role => c.Plan.At("ServerOutbound." + role) != null && Enabled(c.Plan, role) && (c.Request.Kind == OperationKind.Restore || c.Request.Options.Text("Protocol") == role)).ToArray();
        if (roles.Length == 0) return;
        var names = ClientProfiles.Nodes(c.Plan, c.Secrets, true).Where(n => roles.Contains(n.Role)).Select(n => n.Name).ToArray();
        var items = (result["Items"] as JsonArray)?.OfType<JsonObject>().ToArray() ?? [];
        if (names.Length == 0 || names.Any(name => !items.Any(i => i.Text("Node") == name) || items.Any(i => i.Text("Node") == name && i.Text("Status") != "Passed"))) throw new OperationException("本次维护涉及服务器固定链路，但实际代理验收未全部完成，恢复本次范围。", code: "ServerOutboundValidationIncomplete");
    }
    private async Task<JsonObject?> ValidateAdditionalHops(Context c, string role)
    {
        if (c.Plan.At("ServerOutbound." + role + ".AdditionalHops") is not JsonArray hops || hops.Count == 0) return null;
        var observed = await c.Run("server-outbound-read.sh", new() { ["ROLE"] = role }, marker: "SERVER_OUTBOUND_READ");
        var configuration = JsonNode.Parse(RemoteAssets.Marker(observed.Output, "SERVER_CONFIG"))!.AsObject();
        var requests = ServerOutboundRouting.ProbeRequests(role, configuration, c.Plan);
        var response = await c.Run("server-hop-probe.sh", new() { ["ROLE"] = role, ["PROBES_JSON"] = requests.ToJsonString() }, timeout: 240, marker: "SERVER_HOPS_PASSED");
        var result = JsonNode.Parse(RemoteAssets.Marker(response.Output, "HOP_VALIDATION"))!.AsObject(); ServerOutboundRouting.RequireHopValidation(requests, result);
        c.State.Put("ServerOutboundValidation." + role + ".AdditionalHops", result.DeepClone()); return result;
    }
    private async Task ConfigureServerOutbound(Context c)
    {
        OperationPolicy.Validate(c.Request);
        var role = c.Request.Options.Text("Protocol");
        var preview = ServerOutboundRouting.Prepare(store, c.Request);
        CommandResult? observed = null;
        await c.TrackStep("outbound-preflight", async () =>
        {
            var audit = await c.Run("audit.sh");
            Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
            await VerifyManagement(c);
            observed = await c.Run("server-outbound-read.sh", new() { ["ROLE"] = role }, marker: "SERVER_OUTBOUND_READ");
            if (RemoteAssets.Marker(observed.Output, "SERVER_CONFIG_SHA256") != c.Request.Options.Text("ConfigSha256")) throw new OperationException("远端配置与审阅时的归档不同，未建立变更或覆盖服务器。", code: "ServerOutboundRemoteDrift");
            var actual = JsonNode.Parse(RemoteAssets.Marker(observed.Output, "SERVER_CONFIG"))!.AsObject();
            // Validate the observed configuration, never replace it with a regenerated template.
            if (ArchiveStore.Fingerprint(actual) != ArchiveStore.Fingerprint(ArchiveStore.ReadJson(c.File(ServerOutboundRouting.ConfigRelative(role))))) throw new OperationException("远端配置与归档不一致。");
        });
        await c.TrackStep("outbound-backup", () => Arm(c, [role]));
        await c.TrackStep("outbound-apply", async () =>
        {
            c.Plan["ServerOutbound"] ??= new JsonObject();
            if (preview.Metadata == null) { c.Plan["ServerOutbound"]!.AsObject().Remove(role); if (c.Plan["ServerOutbound"]!.AsObject().Count == 0) c.Plan.Remove("ServerOutbound"); }
            else c.Plan["ServerOutbound"]![role] = preview.Metadata.DeepClone();
            c.Save();
            await c.Run("server-outbound-apply.sh", new() { ["ROLE"] = role, ["CONFIG_JSON"] = preview.Configuration.ToJsonString(), ["EXPECTED_CONFIG_SHA256"] = RemoteAssets.Marker(observed!.Output, "SERVER_CONFIG_SHA256") }, true, 120, "SERVER_OUTBOUND_APPLIED");
        });
        await c.TrackStep("outbound-validation", async () =>
        {
            var actual = await c.Run("server-outbound-read.sh", new() { ["ROLE"] = role }, marker: "SERVER_OUTBOUND_READ");
            if (ArchiveStore.Fingerprint(JsonNode.Parse(RemoteAssets.Marker(actual.Output, "SERVER_CONFIG"))!) != ArchiveStore.Fingerprint(preview.Configuration)) throw new OperationException("应用后的服务器配置未按审阅结果生效，恢复本次范围。");
            await VerifyManagement(c);
            var focused = c.Plan.DeepClone().AsObject();
            foreach (var component in DeploymentPlans.Roles[..3]) focused.Put("ProtocolInventory." + component + ".Enabled", JsonValue.Create(component == role));
            var result = await validation.ValidateAsync(focused, c.Secrets, c.File("server-outbound-validation/" + c.Id), user, new InlineProgress<string>(message => c.Report("服务器出站验收", message)), c.Cancellation);
            // A user-skipped/partial validation cannot commit a routing change.
            if (result.Text("Status") != "Passed") throw new OperationException("服务器出站验收不完整，未提交，恢复原配置。", code: "ServerOutboundValidationIncomplete");
            c.State.Put("ServerOutboundValidation." + role, result.DeepClone());
            c.State.Put("ServerOutboundValidation." + role + ".At", JsonValue.Create(DateTimeOffset.UtcNow));
            await ValidateAdditionalHops(c, role);
        });
        await c.TrackStep("outbound-archive", async () =>
        {
            await ArchiveConfigs(c, role);
            if (ArchiveStore.Fingerprint(ArchiveStore.ReadJson(c.File(ServerOutboundRouting.ConfigRelative(role)))) != ArchiveStore.Fingerprint(preview.Configuration)) throw new OperationException("归档前发现服务器配置再次变化，未提交。");
            c.Save();
        });
        await c.TrackStep("outbound-commit", () => Commit(c));
    }
}
