using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record TcpForwardPreview(JsonObject Configuration, string ExpectedHash, string Summary);
public interface ITcpForwardValidation
{
    Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject configuration, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken);
}

public static class TcpForwarding
{
    public const int MaximumRules = 16;
    public static JsonObject Empty() => new() { ["Version"] = 1, ["Rules"] = new JsonArray() };
    public static JsonObject NewRule() => new()
    {
        ["Id"] = Guid.NewGuid().ToString("N"), ["Name"] = "TCP 转发", ["Enabled"] = true,
        ["ListenFamily"] = "IPv4", ["ListenPort"] = 0, ["TargetAddress"] = "", ["TargetPort"] = 0,
        ["AllowedSources"] = new JsonArray(), ["Validation"] = new JsonObject { ["Type"] = "Tls", ["ServerName"] = "" }
    };
    private static void Fields(JsonObject value, params string[] fields)
    {
        if (value.Any(p => !fields.Contains(p.Key))) throw new OperationException("TCP 转发包含未知字段，请重新编辑。");
    }
    private static int Port(JsonObject value, string key)
    {
        if (value[key] is not JsonValue number || !number.TryGetValue<int>(out var port) || port is < 1 or > 65535) throw new OperationException("TCP 转发端口必须为 1–65535 的整数。");
        return port;
    }
    public static string Address(string value)
    {
        if (!IPAddress.TryParse(value, out var address) || address.IsIPv4MappedToIPv6 || value.Contains('%') || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.IsIPv6Multicast || address.GetAddressBytes()[0] is >= 224 && address.AddressFamily == AddressFamily.InterNetwork) throw new OperationException("转发目标需要明确的单播 IPv4 或 IPv6 地址。");
        return address.ToString();
    }
    public static string Source(string value)
    {
        var parts = value.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address) || address.IsIPv4MappedToIPv6 || value.Contains('%')) throw new OperationException("允许来源应为 IPv4／IPv6 地址或 CIDR。");
        var bytes = address.GetAddressBytes(); var bits = bytes.Length * 8;
        var prefix = parts.Length == 1 ? bits : int.TryParse(parts[1], out var n) && n >= 0 && n <= bits ? n : throw new OperationException("来源 CIDR 前缀无效。");
        for (var i = 0; i < bytes.Length; i++) bytes[i] &= (byte)(0xff << Math.Clamp(8 - (prefix - i * 8), 0, 8));
        return new IPAddress(bytes) + "/" + prefix;
    }
    public static JsonObject Normalize(JsonObject value)
    {
        Fields(value, "Version", "Rules");
        if (value.Number("Version") != 1 || value["Rules"] is not JsonArray rules || rules.Count > MaximumRules) throw new OperationException("TCP 转发配置版本无效，或超过 16 条规则。");
        var normalized = new JsonArray(); var ids = new HashSet<string>(StringComparer.Ordinal); var ports = new HashSet<int>();
        foreach (var item in rules)
        {
            if (item is not JsonObject rule) throw new OperationException("转发规则格式无效。");
            Fields(rule, "Id", "Name", "Enabled", "ListenFamily", "ListenPort", "TargetAddress", "TargetPort", "AllowedSources", "Validation");
            if (!Regex.IsMatch(rule.Text("Id"), "^[a-f0-9]{32}$") || !ids.Add(rule.Text("Id"))) throw new OperationException("转发规则身份缺失或重复。");
            var name = rule.Text("Name").Trim();
            if (name.Length is < 1 or > 80 || name.Any(char.IsControl)) throw new OperationException("转发名称应为 1–80 个可打印字符。");
            if (rule["Enabled"] is not JsonValue enabledValue || !enabledValue.TryGetValue<bool>(out var enabled)) throw new OperationException("请明确设置规则启用状态。");
            var family = rule.Text("ListenFamily");
            if (family is not ("IPv4" or "IPv6" or "DualStack")) throw new OperationException("请选择 IPv4、IPv6 或双栈监听。");
            var port = Port(rule, "ListenPort"); if (!ports.Add(port)) throw new OperationException("转发监听端口重复，请为每条规则选择独立端口。");
            if (rule["AllowedSources"] is not JsonArray sources || sources.Count is < 1 or > 32 || sources.Any(s => s is not JsonValue v || !v.TryGetValue<string>(out _))) throw new OperationException("每条转发须填写 1–32 个允许来源地址或网段。");
            var allowed = sources.Select(s => Source(s!.GetValue<string>().Trim())).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            if (rule["Validation"] is not JsonObject validation) throw new OperationException("请选择实际转发验收方式。");
            var check = validation.DeepClone().AsObject(); var kind = check.Text("Type");
            if (kind == "Tls") { Fields(check, "Type", "ServerName"); DeploymentPlans.Domain(check.Text("ServerName")); }
            else if (kind == "Ssh") Fields(check, "Type");
            else if (kind == "Proxy")
            {
                Fields(check, "Type", "SchemeId", "NodeId", "NodeFingerprint");
                if (!Regex.IsMatch(check.Text("SchemeId"), "^[a-f0-9]{32}$") || !Regex.IsMatch(check.Text("NodeId"), "^[a-f0-9]{32}$") || !Regex.IsMatch(check.Text("NodeFingerprint"), "^[a-f0-9]{64}$")) throw new OperationException("请重新选择代理验收来源。");
            }
            else throw new OperationException("实际转发验收支持 TLS、SSH 响应或已保存的代理节点。");
            normalized.Add(new JsonObject { ["Id"] = rule.Text("Id"), ["Name"] = name, ["Enabled"] = enabled, ["ListenFamily"] = family, ["ListenPort"] = port, ["TargetAddress"] = Address(rule.Text("TargetAddress")), ["TargetPort"] = Port(rule, "TargetPort"), ["AllowedSources"] = new JsonArray(allowed.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()), ["Validation"] = check });
        }
        return new() { ["Version"] = 1, ["Rules"] = normalized };
    }
    public static IEnumerable<JsonObject> Rules(JsonObject? configuration) => (configuration?["Rules"] as JsonArray)?.OfType<JsonObject>() ?? [];
    public static string ProbeAddress(JsonObject plan, JsonObject rule)
    {
        var address = plan.Text(rule.Text("ListenFamily") == "IPv6" ? "Server.IPv6" : "Server.IPv4");
        if (!IPAddress.TryParse(address, out _)) throw new OperationException("此监听地址族缺少已归档的实例地址。"); return address;
    }
    public static string[] ProbeAddresses(JsonObject plan, JsonObject rule)
    {
        if (rule.Text("ListenFamily") != "DualStack") return [ProbeAddress(plan, rule)];
        if (!IPAddress.TryParse(plan.Text("Server.IPv6"), out var address) || address.AddressFamily != AddressFamily.InterNetworkV6) throw new OperationException("双栈转发需要已归档的实例 IPv6 地址。");
        return [plan.Text("Server.IPv4"), address.ToString()];
    }
    public static JsonObject ProxyNode(ArchiveStore store, JsonObject rule, string? changingInstance = null)
    {
        var source = rule["Validation"]!.AsObject(); var scheme = store.ReadSecret(ServerOutboundRouting.SchemeFile(store.Paths, source.Text("SchemeId")));
        var node = (scheme["Nodes"] as JsonArray)?.OfType<JsonObject>().SingleOrDefault(n => n.Text("Id") == source.Text("NodeId")) ?? throw new OperationException("代理验收来源已移除，请重新选择。");
        if (ArchiveStore.Fingerprint(node) != source.Text("NodeFingerprint")) throw new OperationException("代理验收来源已变化，请重新选择并审阅。");
        if (node["ManagedOrigin"] is JsonObject origin)
        {
            if (origin.Text("Instance") != changingInstance) ManagedNodeSources.Verify(store, new JsonArray(origin.DeepClone()));
            else
            {
                var directory = store.Paths.Instance(origin.Text("Instance")); var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"));
                var secrets = store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"));
                try { var actual = ManagedNodeSources.Resolve(origin, plan, secrets); if (actual == null || ManagedNodeSources.Fingerprint(actual) != origin.Text("Fingerprint")) throw new OperationException("受管代理验收来源已变化。"); }
                finally { secrets.Clear(); }
            }
        }
        if (Address(node.Text("sing_box.server")) != rule.Text("TargetAddress") || node.Number("sing_box.server_port") != rule.Number("TargetPort")) throw new OperationException("代理验收来源与转发目标不同。");
        var copy = node.DeepClone().AsObject(); copy["kind"] = "entry"; copy["region_group"] = "Forward validation";
        var testScheme = new JsonObject { ["Nodes"] = new JsonArray(copy), ["Layout"] = new JsonObject { ["region_groups"] = new JsonArray("Forward validation") } };
        _ = ClientTopology.DiagnosticRoute(testScheme, copy.Text("name")); return copy;
    }
    public static JsonObject Options(JsonObject state, string action, JsonObject? configuration = null) => new()
    {
        ["Action"] = action, ["ExpectedHash"] = state.Text("TcpForwarding.RemoteHash", "Absent"), ["Configuration"] = (configuration ?? Empty()).DeepClone()
    };
    public static void ValidateOptions(JsonObject options)
    {
        Fields(options, "Action", "ExpectedHash", "Configuration");
        if (options.Text("Action") is not ("Apply" or "Remove" or "Check") || options.Text("ExpectedHash") != "Absent" && !Regex.IsMatch(options.Text("ExpectedHash"), "^[a-f0-9]{64}$")) throw new OperationException("TCP 转发操作或归档摘要无效。");
        if (options["Configuration"] is not JsonObject configuration) throw new OperationException("缺少转发配置。");
        var normalized = Normalize(configuration);
        if (options.Text("Action") == "Apply" && !Rules(normalized).Any()) throw new OperationException("请添加规则，移除组件请使用单独的移除操作。");
        if (options.Text("Action") == "Remove" && Rules(normalized).Any()) throw new OperationException("移除操作不能混入新规则。");
    }
    public static TcpForwardPreview Prepare(ArchiveStore store, OperationRequest request)
    {
        ValidateOptions(request.Options); var directory = store.Paths.Instance(request.InstanceRelativePath);
        var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json")); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        var lifecycle = InstanceLifecycle.Read(store, request.InstanceRelativePath, plan);
        if (!lifecycle.Managed || lifecycle.NeedsRecovery) throw new OperationException("请先完成实例部署、接入或待恢复事务。");
        var expected = state.Text("TcpForwarding.RemoteHash", "Absent");
        if (expected != request.Options.Text("ExpectedHash") || (plan["TcpForwarding"] == null) != (expected == "Absent")) throw new OperationException("转发归档不完整或已变化，请重新读取并审阅。");
        if (expected == "Absent" && request.Options.Text("Action") != "Apply") throw new OperationException("此实例尚未配置受管 TCP 转发。");
        var config = Normalize(request.Options["Configuration"]!.AsObject());
        if (request.Options.Text("Action") == "Check" && ArchiveStore.Fingerprint(config) != ArchiveStore.Fingerprint(plan["TcpForwarding"] ?? Empty())) throw new OperationException("只读检查只能核对已保存的转发配置。");
        var reserved = new HashSet<int> { plan.Number("Ports.SshPrimary"), plan.Number("Ports.SshRescue"), plan.Number("Server.BootstrapSshPort") };
        foreach (var (role, fields) in new[] { ("RealityEntry", new[] { "Ports.XrayPrimary", "Ports.XrayBackup" }), ("AnyTlsEntry", new[] { "Ports.AnyTlsPrimary" }), ("ShadowsocksLanding", new[] { "Ports.LandingShadowsocks" }) })
            if (plan.Flag("ProtocolInventory." + role + ".Installed", DeploymentPlans.Uses(plan, role))) foreach (var field in fields) reserved.Add(plan.Number(field));
        if (plan.Text("Reality.TargetMode") == "LocalOwnedTls") reserved.Add(plan.Number("Reality.LocalHttpsPort"));
        if (state.Flag("KomariController.Installed")) reserved.Add(plan.Number("KomariController.Port", 25774));
        if (state.Flag("Cloudflared.Installed")) reserved.Add(plan.Number("Cloudflared.MetricsPort", 20241));
        var ports = Rules(config).Select(r => r.Number("ListenPort")).ToHashSet();
        foreach (var rule in Rules(config))
        {
            if (reserved.Contains(rule.Number("ListenPort"))) throw new OperationException("转发监听与管理或已安装组件的端口冲突。");
            _ = ProbeAddresses(plan, rule);
            var target = IPAddress.Parse(rule.Text("TargetAddress"));
            if (ports.Contains(rule.Number("TargetPort")) && (IPAddress.IsLoopback(target) || new[] { plan.Text("Server.IPv4"), plan.Text("Server.IPv6") }.Contains(target.ToString()))) throw new OperationException("转发目标指向本组件监听，可能形成环路。");
            if (rule.Flag("Enabled") && rule.Text("Validation.Type") == "Proxy") _ = ProxyNode(store, rule);
        }
        var action = request.Options.Text("Action");
        var summary = action == "Remove" ? "移除当前实例全部受管 TCP 转发、独立白名单和相关端口放行。" : action == "Check" ? "只读核对实际配置、监听和白名单，并经转发执行已保存的验收。" : string.Join("\n", Rules(config).Select(r => r.Text("Name") + " · " + (r.Flag("Enabled") ? "启用" : "停用") + " · " + r.Text("ListenFamily") + ":" + r.Number("ListenPort") + " → " + new IPEndPoint(IPAddress.Parse(r.Text("TargetAddress")), r.Number("TargetPort")) + "\n允许来源：" + string.Join("，", r.Strings("AllowedSources")) + "；验收：" + r.Text("Validation.Type")));
        summary += "\n\n仅 TCP；不传递真实客户端 IP，不改变代理入站、SSH 或监控。转发使用系统自带程序，无连接 60 秒后工作进程退出，监听仍保持可用。";
        if (action != "Check") summary += "\n本次会重建当前组件的转发监听，已有转发连接中断。" + (plan.Text("Firewall.Mode") == "PreserveExisting" ? "保留既有防火墙，所需端口须已放行。" : "同步受管防火墙的转发端口。") + "失败或取消恢复本组件及本次防火墙范围。";
        return new(config, expected, summary);
    }
    public static void RequireValidation(JsonObject configuration, JsonObject result)
    {
        var ids = Rules(configuration).Where(r => r.Flag("Enabled")).Select(r => r.Text("Id")).ToArray();
        var items = (result["Items"] as JsonArray)?.OfType<JsonObject>().ToArray() ?? [];
        if (result.Text("Status") != "Passed" || items.Length != ids.Length || ids.Any(id => items.Count(i => i.Text("Id") == id && i.Text("Status") == "Passed" && i.Text("From") == "Controller" && i.Text("Scope") == "ForwardedApplication") != 1)) throw new OperationException("实际转发验收未全部通过，不能提交本次变更。", code: "TcpForwardValidationIncomplete");
        foreach (var rule in Rules(configuration).Where(r => r.Flag("Enabled")))
        {
            var checks = (items.Single(i => i.Text("Id") == rule.Text("Id"))["Checks"] as JsonArray)?.OfType<JsonObject>().ToArray() ?? [];
            if (checks.Length != (rule.Text("ListenFamily") == "DualStack" ? 2 : 1) || checks.Select(i => i.Text("Address")).Distinct().Count() != checks.Length || checks.Any(i => i.Text("Status") != "Passed" || i.Text("Type") != rule.Text("Validation.Type"))) throw new OperationException("转发验收缺少所选地址族或应用协议的结果。", code: "TcpForwardValidationIncomplete");
        }
    }
}
