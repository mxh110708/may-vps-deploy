using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static class MayMonitorAccess
{
    public static bool CanonicalId(string? value) => Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty && id.ToString("D") == value;
    public static string PlanFile(ArchiveStore store, string relative) => SafePath.Resolve(store.Paths.Instance(relative), "may-monitor-access.json");
    public static string NormalizeUrl(string value) => TunnelAccess.NormalizeUrl(value) + "/";
    public static JsonObject State(ArchiveStore store, string relative)
    { var file = SafePath.Resolve(store.Paths.Instance(relative), "deployment-state.json"); return File.Exists(file) ? ArchiveStore.ReadJson(file) : new(); }
    public static MonitorReadConnection Connection(ArchiveStore store)
    {
        var data = store.ReadSecret(store.Paths.Resolve("private/monitor-read.private.json"));
        try { return MonitorReadConnection.FromJson(data); }
        finally { data.Clear(); }
    }
    public static JsonObject SavePlan(ArchiveStore store, string relative, string publicUrl)
    {
        OperationPolicy.Validate(new(OperationKind.HealthAudit, relative, new()));
        var endpoint = NormalizeUrl(publicUrl); var state = State(store, relative); var server = state["MayMonitorServer"];
        if (server == null || !server.Flag("Installed") || server.Number("Configuration.Port") is < 1024 or > 65535 || !CanonicalId(server.Text("Configuration.InstanceId"))) throw new OperationException("先安装并核对这台 May 服务端及安装身份，再保存接入计划。");
        // Saving a local plan does not switch an origin. An operator may reuse
        // an existing HTTPS entry during a deliberate replacement; the later
        // SSH/HTTPS identity comparison still has to confirm this May server.
        var plan = new JsonObject { ["SchemaVersion"] = 1, ["ServerInstance"] = relative, ["PublicUrl"] = endpoint, ["Port"] = server.Number("Configuration.Port"), ["ServerInstanceId"] = server.Text("Configuration.InstanceId") };
        var file = PlanFile(store, relative);
        if (!File.Exists(file) || !JsonNode.DeepEquals(ArchiveStore.ReadJson(file), plan)) ArchiveStore.WriteJson(file, plan);
        return plan;
    }
    public static JsonObject ReadPlan(ArchiveStore store, string relative)
    {
        var file = PlanFile(store, relative);
        if (!File.Exists(file)) throw new OperationException("先保存 May HTTPS 接入计划。");
        var plan = ArchiveStore.ReadJson(file);
        if (plan.Count != 5 || plan.Number("SchemaVersion") != 1 || plan.Text("ServerInstance") != relative || NormalizeUrl(plan.Text("PublicUrl")) != plan.Text("PublicUrl") || plan.Number("Port") is < 1024 or > 65535 || !CanonicalId(plan.Text("ServerInstanceId"))) throw new OperationException("May 接入计划无效，请重新核对目标实例和网址。");
        return plan;
    }
    public static void Validate(OperationRequest request)
    {
        if (request.Options.Text("Action") is not ("VerifyHttps" or "PilotCheck") || request.Options.Any(p => !new[] { "Action", "ConnectionIdentity", "NodeInstance" }.Contains(p.Key)) || !System.Text.RegularExpressions.Regex.IsMatch(request.Options.Text("ConnectionIdentity"), "^[a-f0-9]{64}$")) throw new OperationException("May 接入检查参数无效。");
        if (request.Options.Text("Action") == "PilotCheck") OperationPolicy.Validate(new(OperationKind.HealthAudit, request.Options.Text("NodeInstance"), new()));
        else if (request.Options.ContainsKey("NodeInstance")) throw new OperationException("HTTPS 核验不能混入节点迁移参数。");
    }
    public static string Guidance(JsonObject plan) => "May HTTPS 入口：" + plan.Text("PublicUrl") + "\n同机连接器的服务地址：http://127.0.0.1:" + plan.Number("Port") + "\n可使用独立主机名，或在明确替换旧监控时复用现有入口。复用原监听地址不需要修改 Tunnel 路由；切换前须备份原服务并准备恢复。\n保留 Authorization、WebSocket 升级和原始请求路径；API 不缓存。若 Access 返回登录页／重定向，检查会停止，不会绕过策略。\n保存计划只修改本机归档；本入口不修改 Cloudflare、DNS、连接器或旧监控服务。";
    public static string EvidenceFingerprint(ArchiveStore store, string relative, string? node)
    {
        var value = new JsonObject { ["Plan"] = ReadPlan(store, relative), ["Connection"] = Connection(store).Identity, ["Server"] = State(store, relative)["MayMonitorServer"]?.DeepClone(), ["ServerPlan"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(store.Paths.Instance(relative), "deployment-plan.json")) };
        if (node != null) { value["NodeInstance"] = node; value["Agent"] = State(store, node)["MayMonitorAgent"]?.DeepClone(); value["NodePlan"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(store.Paths.Instance(node), "deployment-plan.json")); }
        return ArchiveStore.Fingerprint(value);
    }
    public static string EvidenceLabel(ArchiveStore store, string relative)
    {
        var evidence = State(store, relative)["MayMonitorAccess"];
        if (evidence == null) return "尚未核验";
        if (evidence.Text("Status") is not ("HttpsVerified" or "ReadyForTrial")) return evidence.Text("Status") switch { "Cancelled" => "检查已取消", "Checking" => "上次检查未完成", _ => "上次检查未通过" };
        try
        {
            var node = evidence.Text("NodeInstance");
            if (evidence.Text("Fingerprint") != EvidenceFingerprint(store, relative, node == "" ? null : node)) return "接入来源或配置已变化，需重新核验";
            if (!DateTimeOffset.TryParse(evidence.Text("At"), out var at) || DateTimeOffset.UtcNow - at > TimeSpan.FromMinutes(10)) return "上次核验已过期";
            return evidence.Text("Status") == "ReadyForTrial" ? "最近节点接入检查通过" : "最近 HTTPS 身份核验通过";
        }
        catch (Exception error) when (error is OperationException or IOException or System.Text.Json.JsonException) { return "接入记录需重新核对"; }
    }
    public static string Summary(ArchiveStore store, OperationRequest request)
    {
        Validate(request); var plan = ReadPlan(store, request.InstanceRelativePath);
        return "May Monitor · " + (request.Options.Text("Action") == "PilotCheck" ? "节点接入验收" : "HTTPS 身份核验") + "\n目标 " + plan.Text("PublicUrl") + "\nMay 身份 " + plan.Text("ServerInstanceId") + (request.Options.Text("NodeInstance") is { Length: > 0 } node ? "\n验收节点 " + node : "") + "\n只读核对 SSH 归属、HTTPS、服务身份及实时上报，结果保存在本机。不会安装、重启、停止旧监控、修改云端路由或发送管理员凭据。";
    }
}
