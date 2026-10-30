using System.Net;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record WireGuardPreview(JsonObject Configuration, JsonObject? Record, string Summary);

// A single authenticated point-to-point underlay per host, with /32 peer routes.
// Private keys are generated on the hosts and never enter operation options.
public static class WireGuardTunnels
{
    public static string FileName(AppPaths paths, string id) => paths.Resolve("private/wireguard-tunnels/" + TcpChains.Id(id) + ".json");
    public static string[] Instances(JsonObject c) => [c.Text("FirstInstance"), c.Text("SecondInstance")];
    public static bool Pending(JsonObject r) => r.Text("Phase") is not ("Active" or "Removed" or "RolledBack");
    public static IEnumerable<JsonObject> List(ArchiveStore store)
    {
        var directory = store.Paths.Resolve("private/wireguard-tunnels");
        if (!Directory.Exists(directory)) yield break;
        SafePath.CheckTree(directory);
        foreach (var path in Directory.EnumerateFiles(directory, "*.json").Order(StringComparer.Ordinal))
        {
            var record = ArchiveStore.ReadJson(path);
            if (record.Number("Version") != 1 || Path.GetFileNameWithoutExtension(path) != TcpChains.Id(record.Text("Configuration.Id"))) throw new OperationException("WireGuard 隧道记录无效。");
            yield return record;
        }
    }
    public static JsonObject New(string first) => new()
    {
        ["Version"] = 1, ["Id"] = Guid.NewGuid().ToString("N"), ["Name"] = "实例间加密通道",
        ["FirstInstance"] = first, ["SecondInstance"] = "", ["Family"] = "IPv4",
        ["FirstPort"] = 51820, ["SecondPort"] = 51820,
        ["FirstAddress"] = "10.203.0.1", ["SecondAddress"] = "10.203.0.2", ["Mtu"] = 1380, ["KeepaliveSeconds"] = 0
    };
    public static string InnerAddress(string text)
    {
        if (!IPAddress.TryParse(text, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) throw new OperationException("隧道内地址须为 RFC1918 IPv4 单播地址。");
        var b = ip.GetAddressBytes();
        if (!(b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168) || text != ip.ToString()) throw new OperationException("隧道内地址须为规范的 RFC1918 IPv4 地址。");
        return text;
    }
    public static void Validate(OperationRequest request)
    {
        if (request.Options.Count != 2 || request.Options["Configuration"] is not JsonObject c || !request.Options.ContainsKey("Action") || request.Options.Text("Action") is not ("Apply" or "Check" or "Remove" or "Recover")) throw new OperationException("隧道操作无效。");
        string[] fields = ["Version", "Id", "Name", "FirstInstance", "SecondInstance", "Family", "FirstPort", "SecondPort", "FirstAddress", "SecondAddress", "Mtu", "KeepaliveSeconds"];
        foreach (var field in new[] { "Id", "Name", "FirstInstance", "SecondInstance", "Family", "FirstAddress", "SecondAddress" })
            if (c[field] is not JsonValue text || !text.TryGetValue<string>(out _)) throw new OperationException("隧道文本字段类型无效。");
        if (c.Count != fields.Length || c.Any(v => !fields.Contains(v.Key)) || c["Version"] is not JsonValue version || !version.TryGetValue<int>(out var schema) || schema != 1 || c.Text("Name").Length is < 1 or > 60 || c.Text("Name").Any(char.IsControl)) throw new OperationException("隧道字段、版本或名称无效。");
        _ = TcpChains.Id(c.Text("Id"));
        if (c["Family"] is not JsonValue family || !family.TryGetValue<string>(out var f) || f is not ("IPv4" or "IPv6")) throw new OperationException("请选择 IPv4 或 IPv6 外层地址族。");
        foreach (var (key, min, max) in new[] { ("FirstPort", 1024, 65535), ("SecondPort", 1024, 65535), ("Mtu", 1280, 1420), ("KeepaliveSeconds", 0, 120) })
            if (c[key] is not JsonValue value || !value.TryGetValue<int>(out var n) || n < min || n > max || key == "KeepaliveSeconds" && n is > 0 and < 15) throw new OperationException("隧道端口、MTU 或保活范围无效（保活关闭或 15–120 秒）。");
        foreach (var instance in Instances(c)) OperationPolicy.Validate(new(OperationKind.HealthAudit, instance, new()));
        if (Instances(c).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 2 || request.InstanceRelativePath != c.Text("FirstInstance")) throw new OperationException("请选择不同的两台实例，并从第一台统一管理。");
        if (InnerAddress(c.Text("FirstAddress")) == InnerAddress(c.Text("SecondAddress"))) throw new OperationException("两端的隧道内地址不能相同。");
    }
    public static JsonObject Peer(JsonObject c, JsonObject local, JsonObject peer, bool first) => new()
    {
        ["Version"] = 1, ["Id"] = c.Text("Id"), ["Family"] = c.Text("Family"),
        ["Endpoint"] = TcpChains.Address(peer.Text("Server." + c.Text("Family")), c.Text("Family")),
        ["SourceAddress"] = TcpChains.Address(local.Text("Server." + c.Text("Family")), c.Text("Family")),
        ["ListenPort"] = c.Number(first ? "FirstPort" : "SecondPort"), ["EndpointPort"] = c.Number(first ? "SecondPort" : "FirstPort"),
        ["LocalAddress"] = c.Text(first ? "FirstAddress" : "SecondAddress"), ["PeerAddress"] = c.Text(first ? "SecondAddress" : "FirstAddress"),
        ["Mtu"] = c.Number("Mtu"), ["KeepaliveSeconds"] = c.Number("KeepaliveSeconds")
    };
    public static WireGuardPreview Prepare(ArchiveStore store, OperationRequest request)
    {
        Validate(request); var c = request.Options["Configuration"]!.DeepClone().AsObject(); var action = request.Options.Text("Action");
        var path = FileName(store.Paths, c.Text("Id")); var record = File.Exists(path) ? ArchiveStore.ReadJson(path) : null;
        if (record != null && !JsonNode.DeepEquals(record["Configuration"], c)) throw new OperationException("隧道记录与审阅不符，请重新读取。");
        if (action == "Apply" && record != null || action != "Apply" && record == null) throw new OperationException("隧道操作与当前记录不符；修改参数须先移除旧隧道。");
        if (action == "Recover" ? record == null || !Pending(record) : record != null && (Pending(record) || record.Text("Phase") != "Active")) throw new OperationException("请先完成待恢复的隧道事务。");
        var plans = Instances(c).Select(i => TcpChains.Plan(store, i)).ToArray();
        foreach (var (instance, index) in Instances(c).Select((v, i) => (v, i)))
        {
            var plan = plans[index]; var state = ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(instance), "deployment-state.json"));
            var lifecycle = InstanceLifecycle.Read(store, instance, plan);
            if (!lifecycle.Managed || action != "Recover" && lifecycle.NeedsRecovery) throw new OperationException("参与实例尚未接入或有其他待恢复事务。");
            if (action != "Recover" && state["WireGuardTunnelTransaction"] != null) throw new OperationException("参与实例存在待恢复的隧道事务。");
            foreach (var other in List(store).Where(r => r.Text("Configuration.Id") != c.Text("Id") && (Pending(r) || r.Text("Phase") == "Active")))
                if (Instances(other["Configuration"]!.AsObject()).Contains(instance, StringComparer.OrdinalIgnoreCase)) throw new OperationException("每台实例限参与一条活动或待恢复的 WireGuard 隧道。");
            var port = c.Number(index == 0 ? "FirstPort" : "SecondPort");
            if (action == "Apply" && (plan["WireGuardTunnel"] != null || state.Text("WireGuardTunnel.RemoteHash", "Absent") != "Absent")) throw new OperationException("该实例已有隧道组件，请先核对或移除。");
            if (action == "Apply" && (UdpForwarding.Rules(plan["UdpForwarding"] as JsonObject).Any(r => r.Number("ListenPort") == port) || InboundCatalog.Items(plan["InboundModel"] as JsonObject ?? InboundCatalog.Empty(), "Inbounds").Where(InboundCatalog.UsesUdp).SelectMany(Hysteria2Ports.ListenerPorts).Contains(port) || plan.Flag("ProtocolInventory.ShadowsocksLanding.Installed", DeploymentPlans.Uses(plan, "ShadowsocksLanding")) && plan.Number("Ports.LandingShadowsocks") == port)) throw new OperationException("WireGuard UDP 端口与已有组件冲突。");
            var peer = Peer(c, plan, plans[1 - index], index == 0);
            if (action == "Remove" && new[] { "TcpForwarding", "UdpForwarding" }.SelectMany(component => TcpForwarding.Rules(plan[component] as JsonObject)).Any(r => r.Text("TargetAddress") == peer.Text("PeerAddress"))) throw new OperationException("此隧道仍被转发规则使用，请先移除这些规则，再移除隧道。");
            if (new[] { peer.Text("LocalAddress"), peer.Text("PeerAddress") }.Any(a => plans.Any(p => a == p.Text("Server.IPv4")))) throw new OperationException("隧道内地址不能覆盖管理地址或外层地址。");
            if (action != "Apply" && action != "Recover" && (plan.Text("WireGuardTunnel.Id") != c.Text("Id") || state.Text("WireGuardTunnel.RemoteHash").Length != 64)) throw new OperationException("参与实例的隧道归档身份不完整。");
        }
        var scope = string.Join("\n", plans.Select((p, i) => Instances(c)[i] + " · " + c.Number(i == 0 ? "FirstPort" : "SecondPort") + "/UDP · " + c.Text(i == 0 ? "FirstAddress" : "SecondAddress") + "/32 · " + (p.Text("Firewall.Mode") == "PreserveExisting" ? "外部防火墙须已放行" : "精确更新受管防火墙")));
        return new(c, record, "WireGuard 实例间加密通道 · " + action + "\n" + scope + "\n外层 " + c.Text("Family") + "；内层 IPv4 对端主机路由；MTU " + c.Number("Mtu") + "；保活 " + c.Number("KeepaliveSeconds") + " 秒。\n缺少时按服务器现有 APT 源安装 wireguard-tools，移除隧道不卸载共享系统工具。隧道对端可访问本机已有监听服务，只选择可信实例。私钥仅留在两端。双向 TCP 与 UDP 随机挑战、配置与管理连接全部核对后提交。仅恢复本次隧道及涉及的受管防火墙。不会修改默认路由、DNS、转发开关或现有代理。");
    }
    public static void GuardOperation(ArchiveStore store, OperationRequest request)
    {
        if (request.Kind == OperationKind.WireGuardTunnel) return;
        var stateFile = SafePath.Resolve(store.Paths.Instance(request.InstanceRelativePath), "deployment-state.json");
        if (request.Kind != OperationKind.HealthAudit && File.Exists(stateFile) && ArchiveStore.ReadJson(stateFile)["WireGuardTunnelTransaction"] != null)
            throw new OperationException("此实例有未完成的双端隧道事务，请从 WireGuard 隧道统一恢复；记录缺失时保留材料，不执行单机恢复。", true, "WireGuardNeedsRecovery");
        foreach (var record in List(store).Where(r => (Pending(r) || r.Text("Phase") == "Active") && Instances(r["Configuration"]!.AsObject()).Contains(request.InstanceRelativePath, StringComparer.OrdinalIgnoreCase)))
        {
            if (request.Kind == OperationKind.HealthAudit) continue;
            if (Pending(record)) throw new OperationException("此实例有待恢复的隧道，请从 WireGuard 隧道统一恢复。");
            if (request.Kind is OperationKind.Decommission or OperationKind.Restore or OperationKind.ConnectExisting or OperationKind.Deploy or OperationKind.ResumeImport || request.Kind == OperationKind.Recover)
                throw new OperationException("请先移除该实例的 WireGuard 隧道，再执行恢复、退役或重新接入。");
        }
    }
}
