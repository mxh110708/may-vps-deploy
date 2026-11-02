using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record WireGuardChainChoice(string Key, string Label, JsonObject Reference);

// A chain borrows an already accepted pair. Its transaction never owns the
// tunnel, its keys, its routes or its lifecycle.
public static class TcpChainUnderlay
{
    public static bool Selected(JsonObject chain) => chain.ContainsKey("WireGuard");
    public static void Validate(JsonObject chain)
    {
        if (!Selected(chain)) return;
        if (chain["WireGuard"] is not JsonObject r || r.Count != 3 || r.Any(p => p.Key is not ("Id" or "Segment" or "Fingerprint")) ||
            r.Any(p => p.Value is not JsonValue value || !value.TryGetValue<string>(out _)) ||
            r.Text("Segment") is not ("FrontRelay" or "RelayLanding") || !Regex.IsMatch(r.Text("Fingerprint"), "^[a-f0-9]{64}$"))
            throw new OperationException("请选择一段连接和已验收的 WireGuard 隧道。");
        _ = TcpChains.Id(r.Text("Id"));
    }
    public static string[] Participants(JsonObject chain) => chain.Text("WireGuard.Segment") == "FrontRelay"
        ? [chain.Text("FrontInstance"), chain.Text("RelayInstance")] : [chain.Text("RelayInstance"), chain.Text("LandingInstance")];
    private static JsonObject Material(ArchiveStore store, JsonObject configuration)
    {
        var peers = new JsonArray();
        foreach (var instance in WireGuardTunnels.Instances(configuration))
        {
            var plan = TcpChains.Plan(store, instance);
            var state = ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(instance), "deployment-state.json"));
            if (plan["WireGuardTunnel"] is not JsonObject peer || peer.Text("Id") != configuration.Text("Id") ||
                !Regex.IsMatch(state.Text("WireGuardTunnel.RemoteHash"), "^[a-f0-9]{64}$") ||
                state.Text("WireGuardTunnel.ConfigurationFingerprint") != ArchiveStore.Fingerprint(peer) || state["WireGuardTunnelTransaction"] != null)
                throw new OperationException("隧道参与实例的配置、身份或事务已变化，请先核对隧道。");
            var first = instance == configuration.Text("FirstInstance");
            if (peer.Text("LocalAddress") != configuration.Text(first ? "FirstAddress" : "SecondAddress") || peer.Text("PeerAddress") != configuration.Text(first ? "SecondAddress" : "FirstAddress"))
                throw new OperationException("隧道内地址与已验收的双端配置不同。");
            peers.Add(new JsonObject { ["Instance"] = instance, ["Peer"] = peer.DeepClone(), ["RemoteHash"] = state.Text("WireGuardTunnel.RemoteHash") });
        }
        return new JsonObject { ["Configuration"] = configuration.DeepClone(), ["Peers"] = peers };
    }
    public static JsonObject Reference(ArchiveStore store, JsonObject record, string segment) => new()
    {
        ["Id"] = record.Text("Configuration.Id"), ["Segment"] = segment,
        ["Fingerprint"] = ArchiveStore.Fingerprint(Material(store, record["Configuration"]!.AsObject()))
    };
    public static IEnumerable<WireGuardChainChoice> Choices(ArchiveStore store, JsonObject chain)
    {
        foreach (var record in WireGuardTunnels.List(store).Where(r => r.Text("Phase") == "Active"))
            foreach (var segment in new[] { "FrontRelay", "RelayLanding" })
            {
                var candidate = chain.DeepClone().AsObject();
                var pair = segment == "FrontRelay" ? new[] { chain.Text("FrontInstance"), chain.Text("RelayInstance") } : [chain.Text("RelayInstance"), chain.Text("LandingInstance")];
                if (!WireGuardTunnels.Instances(record["Configuration"]!.AsObject()).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(pair)) continue;
                JsonObject reference;
                try { reference = Reference(store, record, segment); candidate["WireGuard"] = reference.DeepClone(); _ = Resolve(store, candidate); }
                catch (OperationException) { continue; }
                yield return new(record.Text("Configuration.Id") + ":" + segment, (segment == "FrontRelay" ? "前置 → 中转" : "中转 → 落地") + " · " + record.Text("Configuration.Name") + " · 外层 " + record.Text("Configuration.Family"), reference);
            }
    }
    public static JsonObject? Resolve(ArchiveStore store, JsonObject chain)
    {
        Validate(chain); if (!Selected(chain)) return null;
        var record = ArchiveStore.ReadJson(WireGuardTunnels.FileName(store.Paths, chain.Text("WireGuard.Id")));
        if (record.Number("Version") != 1 || record["Configuration"] is not JsonObject c || c.Text("Id") != chain.Text("WireGuard.Id") || record.Text("Phase") != "Active")
            throw new OperationException("所选 WireGuard 隧道尚未完成、已移除或正在恢复。");
        WireGuardTunnels.Validate(new(OperationKind.WireGuardTunnel, c.Text("FirstInstance"), new() { ["Action"] = "Check", ["Configuration"] = c.DeepClone() }));
        if (!WireGuardTunnels.Instances(c).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(Participants(chain)))
            throw new OperationException("所选隧道必须连接本线路中相邻的两台实例。");
        if (record.Text("Validation.Status") != "Passed" || record.Text("Validation.Scope") != "BidirectionalWireGuardApplications" || record.Text("Validation.ConfigurationFingerprint") != ArchiveStore.Fingerprint(c) || record.Text("LastCheck.Status") == "Failed")
            throw new OperationException("所选隧道尚未通过双向验收或最近检查失败，请先检查隧道。");
        if (ArchiveStore.Fingerprint(Material(store, c)) != chain.Text("WireGuard.Fingerprint"))
            throw new OperationException("隧道的双端配置、密钥身份或资源摘要已变化，请重新选择并审阅。");
        return c.DeepClone().AsObject();
    }
    public static string Inner(JsonObject tunnel, string instance) => instance == tunnel.Text("FirstInstance") ? tunnel.Text("FirstAddress")
        : instance == tunnel.Text("SecondInstance") ? tunnel.Text("SecondAddress") : throw new OperationException("实例不属于所选隧道。");
    public static string Target(ArchiveStore store, JsonObject chain, bool fromFront)
    {
        var target = chain.Text(fromFront ? "RelayInstance" : "LandingInstance");
        var tunnel = Resolve(store, chain);
        if (tunnel != null && chain.Text("WireGuard.Segment") == (fromFront ? "FrontRelay" : "RelayLanding")) return Inner(tunnel, target);
        return TcpChains.ServerAddress(TcpChains.Plan(store, target), chain);
    }
    public static JsonObject Rule(ArchiveStore store, JsonObject chain, bool front, int port)
    {
        var rule = TcpChains.Rule(chain, front, Target(store, chain, front), port);
        if (!front && chain.Text("WireGuard.Segment") == "FrontRelay")
        {
            var tunnel = Resolve(store, chain)!;
            rule["ListenFamily"] = "IPv4";
            rule["AllowedSources"] = new JsonArray(Inner(tunnel, chain.Text("FrontInstance")) + "/32");
        }
        return rule;
    }
    public static void GuardRemoval(ArchiveStore store, string id)
    {
        if (TcpChains.List(store).Any(r => (TcpChains.Pending(r) || r.Text("Phase") == "Active") && r.Text("Configuration.WireGuard.Id") == id))
            throw new OperationException("此隧道仍被跨实例线路依赖，请先从线路页移除线路；线路移除不会删除隧道。");
    }
    public static string RelaySourceDescription(JsonObject chain) => chain.Text("WireGuard.Segment") == "FrontRelay"
        ? "WireGuard 前置对端的隧道内 IPv4 /32 地址" : chain.Text("FrontSourceAddress") + TcpChains.Prefix(chain);
    public static string Summary(JsonObject chain) => !Selected(chain) ? "实例间连接：原生直连。" :
        "WireGuard 加密段：" + (chain.Text("WireGuard.Segment") == "FrontRelay" ? "前置 → 中转" : "中转 → 落地") +
        "；沿用已验收的两端隧道与 IPv4 /32 内地址。另一段与客户端入口沿用所选地址族。不会回退到公网连接；线路移除与恢复只处理转发，不重建、删除或恢复隧道。";
}
