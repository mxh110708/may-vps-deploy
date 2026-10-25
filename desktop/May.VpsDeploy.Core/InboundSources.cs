using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class InboundSources
{
    private static readonly AsyncLocal<HashSet<string>?> Resolving = new();
    public static void RequireValidation(ArchiveStore store, JsonObject plan, JsonObject model, JsonObject credentials, string[] ids, JsonObject result)
    {
        var instance = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy";
        var nodes = InboundRendering.Nodes(store, instance, plan, model, credentials).Where(n => ids.Contains(n.Text("InboundOrigin.InboundId"))).ToArray();
        var items = (result["Items"] as JsonArray)?.OfType<JsonObject>().ToArray() ?? [];
        if (result.Text("Status") != "Passed" || items.Length != nodes.Length) throw new OperationException("入站、用户及地址族的实际代理验收未全部完成。");
        foreach (var node in nodes)
        {
            if (node.Text("sing_box.type") == "hysteria2" && !items.Any(i => i.Text("InboundId") == node.Text("InboundOrigin.InboundId") && i.Text("UserId") == node.Text("InboundOrigin.UserId") && i.Text("Family") == node.Text("InboundOrigin.Family") && i.Text("Result.ValidatedProtocol") == "hysteria2")) throw new OperationException("Hysteria2 验收缺少对应用户和地址族的真实协议请求结果。");
            if (items.Count(i => i.Text("InboundId") == node.Text("InboundOrigin.InboundId") && i.Text("UserId") == node.Text("InboundOrigin.UserId") && i.Text("Family") == node.Text("InboundOrigin.Family") && i.Text("ConnectionFingerprint") == ClientNodeImport.ConnectionFingerprint(node) && i.Text("Status") == "Passed" && i.Text("From") == "Controller" && i.Text("Scope") == "ProxyHttps" && i.Text("Result.Status") == "Reachable") != 1) throw new OperationException("入站验收证据缺少对应用户或地址族。");
        }
    }
    public static JsonObject Create(ArchiveStore store, string instance, string inboundId, string userId, string family)
    {
        _ = InboundCatalog.Id(inboundId); _ = InboundCatalog.Id(userId); if (family is not ("IPv4" or "IPv6")) throw new OperationException("入站来源地址族无效。");
        var key = instance + ":" + inboundId + ":" + userId + ":" + family; var resolving = Resolving.Value ??= new HashSet<string>(StringComparer.Ordinal);
        if (resolving.Count >= 8 || !resolving.Add(key)) throw new OperationException("入站出站来源形成循环或超过核对深度，请简化连接关系。");
        try
        {
            var plan = TcpChains.Plan(store, instance); var status = InstanceLifecycle.Read(store, instance, plan);
            if (!status.Managed || status.NeedsRecovery) throw new OperationException("入站来源尚未完成或正在恢复。");
            var directory = store.Paths.Instance(instance); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); var secrets = store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"));
            try
            {
                var model = InboundCatalog.Normalize(plan["InboundModel"]?.AsObject() ?? InboundCatalog.Empty(), (secrets["Inbounds"] ?? InboundCatalog.EmptyCredentials()).AsObject());
                if (state.Text("Inbounds.ModelFingerprint") != ArchiveStore.Fingerprint(model) || state.Text("Inbounds.RemoteHash") is "" or "Absent" || state.Text("Inbounds.LastCheck") == "Failed") throw new OperationException("入站模型尚未应用、最近核对失败或缺少匹配归档。");
                var node = InboundRendering.Nodes(store, instance, plan, model, secrets["Inbounds"]!.AsObject()).SingleOrDefault(n => n.Text("InboundOrigin.InboundId") == inboundId && n.Text("InboundOrigin.UserId") == userId && n.Text("InboundOrigin.Family") == family) ?? throw new OperationException("入站或用户已移除、解绑或停用。");
                if (!state.Flag("Inbounds.Runtime." + inboundId + ".Active") || !state.Flag("Inbounds.Runtime." + inboundId + ".Enabled")) throw new OperationException("入站最近核对的运行状态不符，请先重新检查。");
                var validation = state.At("Inbounds.ValidationById." + inboundId) as JsonObject;
                if (validation?.Text("Status") != "Passed" || !(validation["Items"] as JsonArray ?? []).Any(i => i!.Text("UserId") == userId && i.Text("Family") == family && i.Text("ConnectionFingerprint") == ClientNodeImport.ConnectionFingerprint(node) && i.Text("Status") == "Passed")) throw new OperationException("该入站用户缺少当前连接的实际验收，请先检查已保存入站。");
                return node;
            }
            finally { secrets.Clear(); }
        }
        finally { resolving.Remove(key); if (resolving.Count == 0) Resolving.Value = null; }
    }
    public static void VerifyOrigins(ArchiveStore store, JsonArray origins)
    {
        if (origins.Any(n => n is not JsonObject)) throw new OperationException("入站来源记录无效。");
        foreach (var origin in origins.OfType<JsonObject>())
        {
            var node = Create(store, origin.Text("Instance"), origin.Text("InboundId"), origin.Text("UserId"), origin.Text("Family"));
            try { if (!JsonNode.DeepEquals(origin, node["InboundOrigin"])) throw new OperationException("入站、用户、证书或出站已变化，请重新选择更新节点。"); }
            finally { node.Clear(); }
        }
    }
    public static void VerifyNodes(ArchiveStore store, IEnumerable<JsonObject> nodes)
    {
        foreach (var node in nodes.Where(n => n["InboundOrigin"] != null))
        {
            if (node.Text("InboundOrigin.ConnectionFingerprint") != ClientNodeImport.ConnectionFingerprint(node)) throw new OperationException("受管入站连接已被修改，请重新选择来源。");
            VerifyOrigins(store, new JsonArray(node["InboundOrigin"]!.DeepClone()));
        }
    }
    public static IEnumerable<(string Instance, JsonObject? Node, string Label, string Detail)> Choices(ArchiveStore store)
    {
        foreach (var instance in store.ListInstances())
        {
            if (instance.Plan["InboundModel"] is not JsonObject model) continue;
            List<(string Instance, JsonObject? Node, string Label, string Detail)> choices;
            try { choices = InstanceChoices(store, instance.RelativePath, instance.Plan); }
            catch (Exception error) when (error is OperationException or IOException or UnauthorizedAccessException)
            {
                choices = [(instance.RelativePath, null, instance.Plan.Text("NodeName") + " / 独立入站", error is OperationException ? error.Message : "入站来源无法安全读取。")];
            }
            foreach (var choice in choices) yield return choice;
        }
    }
    private static List<(string Instance, JsonObject? Node, string Label, string Detail)> InstanceChoices(ArchiveStore store, string instance, JsonObject plan)
    {
        var lifecycle = InstanceLifecycle.Read(store, instance, plan); if (!lifecycle.Managed || lifecycle.NeedsRecovery) throw new OperationException("入站来源尚未完成或正在恢复。");
        var directory = store.Paths.Instance(instance); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")); var secrets = store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"));
        try
        {
            var credentials = secrets["Inbounds"]?.AsObject() ?? InboundCatalog.EmptyCredentials(); var model = InboundCatalog.Normalize(plan["InboundModel"]!.AsObject(), credentials);
            if (state.Text("Inbounds.ModelFingerprint") != ArchiveStore.Fingerprint(model) || state.Text("Inbounds.RemoteHash") is "" or "Absent" || state.Text("Inbounds.LastCheck") == "Failed") throw new OperationException("入站模型未应用或最近核对失败，请先检查。");
            var result = new List<(string, JsonObject?, string, string)>();
            // Decode each instance once and render each inbound once. Enumerating
            // choices must not repeat a full catalogue render for every user.
            foreach (var node in InboundRendering.Nodes(store, instance, plan, model, credentials))
            {
                var id = node.Text("InboundOrigin.InboundId"); var user = node.Text("InboundOrigin.UserId"); var family = node.Text("InboundOrigin.Family"); var validation = state.At("Inbounds.ValidationById." + id);
                var valid = state.Flag("Inbounds.Runtime." + id + ".Active") && state.Flag("Inbounds.Runtime." + id + ".Enabled") && validation.Text("Status") == "Passed" && (validation?["Items"] as JsonArray ?? []).Any(i => i!.Text("UserId") == user && i.Text("Family") == family && i.Text("ConnectionFingerprint") == ClientNodeImport.ConnectionFingerprint(node) && i.Text("Status") == "Passed");
                var label = plan.Text("NodeName") + " / " + node.Text("name"); result.Add((instance, valid ? node : null, label, valid ? "独立入站 · 已完成用户与代理 HTTPS 验收" : "运行状态或当前用户验收不符，请先检查已保存入站。")); if (!valid) node.Clear();
            }
            foreach (var disabled in InboundCatalog.Items(model, "Inbounds").Where(i => !i.Flag("Enabled"))) result.Add((instance, null, plan.Text("NodeName") + " / " + disabled.Text("Name"), "入站已停用。"));
            return result;
        }
        finally { secrets.Clear(); }
    }
    // Existing role services remain explicit inventory entries; inspecting this
    // view never adopts their files or silently recreates them under new paths.
    public static JsonArray ExistingRoles(JsonObject plan)
    {
        var instance = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var result = new JsonArray();
        foreach (var role in DeploymentPlans.Roles[..3].Where(r => plan.Flag("ProtocolInventory." + r + ".Installed", DeploymentPlans.Uses(plan, r))))
            result.Add(new JsonObject { ["Id"] = ArchiveStore.Digest(System.Text.Encoding.UTF8.GetBytes(instance + ":existing:" + role))[..32], ["Name"] = ComponentInstallations.Label(role), ["Source"] = "ExistingRole", ["Role"] = role, ["Enabled"] = plan.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.Uses(plan, role)), ["RecoveryScope"] = role });
        return result;
    }
}
