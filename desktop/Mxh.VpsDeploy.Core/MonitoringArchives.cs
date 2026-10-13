using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public static class MonitoringArchives
{
    public static string NormalizeEndpoint(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || uri.UserInfo != "" || uri.Fragment != "" || endpoint.Any(char.IsControl))
            throw new OperationException("Komari 地址需要完整的 HTTP/HTTPS URL，不包含登录凭据或片段。");
        return endpoint.TrimEnd('/');
    }
    public static void ApplyHealth(JsonObject plan, JsonObject state, JsonObject audit)
    {
        if (audit.Number("SchemaVersion") != 2 || audit["ChecksIncomplete"] is not JsonArray incomplete || incomplete.Count != 0 ||
            !DateTimeOffset.TryParse(audit.Text("CollectedAt"), out var collected))
            throw new OperationException("监控核对未取得完整证据，保留原归档状态。请核对连接和健康检查结果后重试。", code: "MonitoringAuditIncomplete");
        if (DateTimeOffset.TryParse(state.Text("MonitoringInventory.VerifiedAt"), out var previous) && collected < previous)
            throw new OperationException("监控核对早于现有归档证据，未覆盖较新的状态。", code: "MonitoringAuditStale");
        foreach (var name in new[] { "KomariController", "Cloudflared" })
            if (state[name] != null && state[name] is not JsonObject) throw new OperationException("原监控归档结构无法识别，未覆盖。", code: "MonitoringArchiveInvalid");
        var inventory = new JsonObject { ["SchemaVersion"] = 1, ["VerifiedAt"] = collected, ["Source"] = "HealthAudit" };
        foreach (var name in new[] { "KomariAgent", "KomariController", "Cloudflared" })
        {
            var service = audit.At("Services." + name) as JsonObject;
            if (service == null || new[] { "Installed", "Enabled", "Active", "SupportedLayout" }.Any(field => service[field] is not JsonValue value || !value.TryGetValue<bool>(out _)))
                throw new OperationException("监控服务证据缺失，保留原归档状态。", code: "MonitoringAuditIncomplete");
            if (!service.Flag("Installed") && (service.Flag("Enabled") || service.Flag("Active")))
                throw new OperationException("监控服务与安装文件状态不一致，保留原归档并人工核对。", code: "MonitoringLayoutChanged");
            var item = service.DeepClone().AsObject();
            var version = audit.Text("Versions." + name);
            if (version.Length is > 0 and <= 160) item["Version"] = version;
            inventory[name] = item;
        }
        // Validate every component before changing any archive field. Historical evidence stays intact.
        state["MonitoringInventory"] = inventory;
        state["KomariInstalled"] = inventory.Flag("KomariAgent.Installed");
        foreach (var name in new[] { "KomariController", "Cloudflared" })
        {
            state[name] ??= new JsonObject();
            foreach (var (key, value) in inventory[name]!.AsObject()) state[name]![key] = value?.DeepClone();
        }
        plan.Put("Komari.Enabled", JsonValue.Create(inventory.Flag("KomariAgent.Installed") && inventory.Flag("KomariAgent.Enabled")));
        if (inventory.Flag("KomariAgent.Installed") && inventory.Text("KomariAgent.Version") != "")
            plan.Put("Komari.AgentVersion", JsonValue.Create(inventory.Text("KomariAgent.Version")));
        foreach (var name in new[] { "KomariController", "Cloudflared" })
        {
            var actual = inventory.Text(name + ".Version");
            if (actual == "" || !inventory.Flag(name + ".Installed") || !inventory.Flag(name + ".SupportedLayout")) continue;
            plan.Put(name + ".Version", JsonValue.Create(actual));
            if (state["ComponentUpgrades"] is JsonObject upgrades && upgrades.Text(name + ".Version") != actual) upgrades.Remove(name);
            var component = name == "KomariController" ? "komari_controller" : "cloudflared";
            if (state["InstalledProgramVersions"] is JsonObject programs && programs.Text(component + ".Version") != actual) programs.Remove(component);
        }
    }

    public static bool SupplementAgent(JsonObject plan, JsonObject secrets, JsonObject configuration)
    {
        var endpoint = configuration.Text("endpoint"); var token = configuration.Text("token");
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || string.IsNullOrEmpty(token) || token.Any(char.IsControl))
            throw new OperationException("Agent 连接配置不完整，未更新监控归档。", code: "AgentConfigurationIncomplete");
        var previousEndpoint = plan.Text("Komari.Endpoint"); var previousToken = secrets.Text("KomariAgent.Token");
        endpoint = NormalizeEndpoint(endpoint);
        if (previousEndpoint != "" && NormalizeEndpoint(previousEndpoint) != endpoint || previousToken != "" && previousToken != token) return false;
        plan.Put("Komari.Endpoint", JsonValue.Create(endpoint));
        secrets["KomariAgent"] ??= new JsonObject();
        secrets.Put("KomariAgent.Token", JsonValue.Create(token));
        secrets.Put("KomariAgent.Endpoint", JsonValue.Create(endpoint));
        secrets["KomariAgent"]!["Config"] ??= configuration.DeepClone();
        return true;
    }
}
