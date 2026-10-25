using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static class MayMonitorLifecycle
{
    public static readonly string[] Roles = ["Server", "Agent"];
    public static readonly string[] Actions = ["Check", "Install", "Upgrade", "ConfigureRead", "Backup", "Restore", "Enable", "Disable", "Remove"];
    public static string Section(string role) => Roles.Contains(role) ? "MayMonitor" + role : throw new OperationException("未知 May Monitor 组件。");
    public static string Label(string role) => role == "Server" ? "May Monitor 服务端" : "May Monitor Agent";
    public static string FileSha256(string path) { SafePath.CheckLinks(path); using var stream = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    public static bool TaskId(string value) => Regex.IsMatch(value, "^[a-f0-9]{32}$");
    public static string BackupPath(string task) => TaskId(task) ? "/root/vps-deploy-backups/may-monitor-" + task : throw new OperationException("May Monitor 事务标识无效。");

    public static void Validate(JsonObject options)
    {
        var role = options.Text("Role"); var action = options.Text("Action");
        if (!Roles.Contains(role) || !Actions.Contains(action) || options.Any(p => !new[] { "Role", "Action", "Configuration", "ReadSourceIdentity" }.Contains(p.Key)) || options["Configuration"] is not JsonObject configuration)
            throw new OperationException("请选择明确的 May Monitor 组件和操作。");
        string[] fields = action switch { "Install" or "Upgrade" => role == "Server" ? ["Port", "Username"] : ["Endpoint"], "ConfigureRead" when role == "Server" => ["ReadAuthorization"], "Restore" => ["RestoreTask", "RestoreSha256"], _ => [] };
        if (configuration.Count != fields.Length || fields.Any(f => !configuration.ContainsKey(f))) throw new OperationException("May Monitor 参数不属于所选组件与操作。");
        if (action is "Install" or "Upgrade")
        {
            if (role == "Server" && (configuration.Number("Port") is < 1024 or > 65535 || !Regex.IsMatch(configuration.Text("Username"), "^[A-Za-z0-9_.-]{1,64}$"))) throw new OperationException("请填写有效的回环监听端口与管理员名称。");
            if (role == "Agent") MonitorReadConnection.ValidateEndpoint(configuration.Text("Endpoint"));
        }
        if (action == "Restore" && (!TaskId(configuration.Text("RestoreTask")) || !Regex.IsMatch(configuration.Text("RestoreSha256"), "^[a-f0-9]{64}$"))) throw new OperationException("请选择已归档的 May Monitor 一致性备份。");
        if (action == "ConfigureRead")
        {
            if (role != "Server" || configuration["ReadAuthorization"] is not JsonObject authorization || authorization.Count != 3 || !Regex.IsMatch(authorization.Text("Sha256"), "^[a-f0-9]{64}$") || !DateTimeOffset.TryParse(authorization.Text("ExpiresAt"), out var expiry) || expiry <= DateTimeOffset.UtcNow || expiry > DateTimeOffset.UtcNow.AddDays(90))
                throw new OperationException("只读授权范围、摘要或有效期无效。");
            var clients = authorization.Strings("Clients");
            if (clients.Length is < 1 or > 100 || clients.Distinct(StringComparer.Ordinal).Count() != clients.Length || clients.Any(id => !Guid.TryParseExact(id, "D", out var uuid) || uuid == Guid.Empty || uuid.ToString("D") != id) || !Regex.IsMatch(options.Text("ReadSourceIdentity"), "^[a-f0-9]{64}$")) throw new OperationException("只读授权必须来自当前已保存、明确绑定节点的连接。");
        }
        else if (options.ContainsKey("ReadSourceIdentity")) throw new OperationException("该操作不能混入只读授权来源。");
    }

    public static JsonObject Asset(AppPaths paths, string role)
    {
        var file = paths.Resolve("config/may-monitor.json");
        if (!File.Exists(file)) throw new OperationException("缺少 May Monitor 配套资产清单，请核对完整应用包。");
        var catalog = ArchiveStore.ReadJson(file);
        if (catalog.Number("SchemaVersion") != 1 || catalog[role] is not JsonObject asset) throw new OperationException("缺少固定的 May Monitor 配套发行。");
        var name = role == "Server" ? "may-monitor-server-linux-amd64.tar.gz" : "may-monitor-agent-linux-amd64";
        var expected = "https://github.com/mxh110708/may-monitor-" + role.ToLowerInvariant() + "/releases/download/v" + asset.Text("Version") + "/" + name;
        if (asset.Count != 5 || !Regex.IsMatch(asset.Text("Version"), @"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$") || !Regex.IsMatch(asset.Text("Sha256"), "^[a-f0-9]{64}$") || asset.Number("Bytes") is < 1 or > 134217728 || asset.Text("Name") != name || asset.Text("Url") != expected) throw new OperationException("May Monitor 固定资产或摘要无效。");
        return asset.DeepClone().AsObject();
    }

    public static IReadOnlyList<JsonObject> Backups(ArchiveStore store, string relative, string role)
    {
        var directory = SafePath.Resolve(store.Paths.Instance(relative), "maintenance-backups");
        if (!Directory.Exists(directory)) return [];
        var results = new List<JsonObject>();
        foreach (var folder in Directory.EnumerateDirectories(directory).Where(p => TaskId(Path.GetFileName(p))))
        {
            SafePath.CheckLinks(folder); var file = SafePath.Resolve(folder, "may-monitor.json");
            if (!File.Exists(file)) continue;
            var value = ArchiveStore.ReadJson(file);
            if (value.Number("SchemaVersion") == 1 && value.Text("Role") == role && value.Flag("BeforeInstalled") && value.Text("TaskId") == Path.GetFileName(folder) && Regex.IsMatch(value.Text("Sha256"), "^[a-f0-9]{64}$") && File.Exists(SafePath.Resolve(folder, "may-files.tar.gz"))) results.Add(value);
        }
        return results;
    }

    public static string Summary(OperationRequest request, AppPaths? paths = null)
    {
        Validate(request.Options);
        var action = request.Options.Text("Action"); var role = request.Options.Text("Role"); var configuration = request.Options["Configuration"]!;
        var details = "";
        if (action is "Install" or "Upgrade" && paths != null)
        {
            var asset = Asset(paths, role); details = "\n固定版本 " + asset.Text("Version") + "\nSHA-256 " + asset.Text("Sha256") + (role == "Server" ? "\n回环监听 127.0.0.1:" + configuration.Number("Port") + " · 管理员 " + configuration.Text("Username") : "\nMay 服务端 " + configuration.Text("Endpoint"));
        }
        if (action == "ConfigureRead") details = "\n只读范围 " + configuration["ReadAuthorization"]!.Strings("Clients").Length + " 个节点\n到期 " + configuration.Text("ReadAuthorization.ExpiresAt") + "\n令牌摘要 " + configuration.Text("ReadAuthorization.Sha256");
        if (action == "Restore") details = "\n恢复点 " + configuration.Text("RestoreTask") + "\n备份 SHA-256 " + configuration.Text("RestoreSha256");
        return Label(role) + " · " + action + details + "\n只处理该 May 组件的程序、配置、专用服务和数据；不修改 Komari、Cloudflare Tunnel、代理协议、SSH 或防火墙。\n" +
            (request.Options.Text("Action") == "Check" ? "只读检查归属及状态，不重启。" : "先核对归属并做一致性备份，失败或取消按同一组件恢复；回复不明时只核对事务，不重复原变更。") +
            (request.Options.Text("Action") == "Remove" ? "\n移除程序和服务，保留私有数据及专用无登录账号。" : "") +
            (request.Options.Text("Role") == "Server" ? "\n服务端默认只监听本机回环；HTTPS 发布路径另行配置与核验。" : "\n新 Agent 与现有 Komari Agent 独立；不会自动注册节点或移除旧 Agent。");
    }
}
