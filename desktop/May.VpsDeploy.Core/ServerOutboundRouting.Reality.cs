using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class ServerOutboundRouting
{
    private static ServerOutboundPreview BuildReality(JsonObject current, JsonObject? previous, JsonObject? node, string expectedAddress, JsonObject plan, JsonObject? source, JsonArray? destinationRules, IReadOnlyList<ServerOutboundHop>? additionalHops)
    {
        if (current["inbounds"] is not JsonArray inputs || inputs.Count == 0 || current["outbounds"] is not JsonArray || current["routing"] is not JsonObject) throw new OperationException("Reality 配置布局不完整，未重写服务器。");
        var expected = new Dictionary<string, (int Port, string Address)>(StringComparer.Ordinal);
        foreach (var (part, port) in new[] { ("primary", plan.Number("Ports.XrayPrimary")), ("backup", plan.Number("Ports.XrayBackup")) })
        {
            if (port <= 0) continue;
            expected.Add("reality-" + part + "-ipv4", (port, "0.0.0.0"));
            if (plan.Text("Server.IPv6") != "") expected.Add("reality-" + part + "-ipv6", (port, plan.Text("Server.IPv6")));
        }
        var tags = inputs.Select(n => n!.Text("tag")).ToArray();
        if (tags.Length != expected.Count || tags.Distinct(StringComparer.Ordinal).Count() != tags.Length || inputs.Any(n => n is not JsonObject inbound || !expected.TryGetValue(inbound.Text("tag"), out var listener) || inbound.Number("port") != listener.Port || inbound.Text("listen") != listener.Address || inbound.Text("protocol") != "vless" || inbound.Text("streamSettings.security") != "reality" || inbound.Text("streamSettings.network") is not ("raw" or "tcp") || inbound.At("settings.clients") is not JsonArray users || users.Count != 1 || users[0]?.Text("flow") != "xtls-rprx-vision")) throw new OperationException("本轮只支持归档中 Reality 主／备用、IPv4／IPv6 监听的完整受管布局；不会接管额外入站或折叠监听。");
        var result = current.DeepClone().AsObject(); var outputs = result["outbounds"]!.AsArray(); var route = result["routing"]!.AsObject();
        if (route["rules"] is not JsonArray rules || route.Text("domainStrategy") != "AsIs" || route.Any(p => p.Key is not ("rules" or "domainStrategy"))) throw new OperationException("Reality 具有自定义分流，未改写原规则。");
        var ownedOutput = outputs.OfType<JsonObject>().Where(o => o.Text("tag") == Tag).ToArray();
        var ownedRules = rules.OfType<JsonObject>().Where(r => r.Strings("inboundTag").Intersect(tags, StringComparer.Ordinal).Any()).ToArray();
        RemoveNamedHops(outputs, previous);
        if (previous == null)
        {
            if (ownedOutput.Length > 0 || ownedRules.Length > 0) throw new OperationException("发现无本地归属的 Reality 出站规则，未接管。");
        }
        else
        {
            if (previous.Number("Version") != 1 || ownedOutput.Length != 1 || ArchiveStore.Fingerprint(ownedOutput[0]) != previous.Text("OutboundFingerprint") || !OwnedRulesMatch("RealityEntry", ownedRules, previous, tags, plan)) throw new OperationException("受管 Reality 出站已漂移，未覆盖或删除。", code: "ServerOutboundDrift");
            outputs.Remove(ownedOutput[0]); foreach (var rule in ownedRules) rules.Remove(rule);
        }
        if (outputs.Count != 2 || outputs[0]?.Text("tag") != "direct" || outputs[0]?.Text("protocol") != "freedom" || outputs[1]?.Text("tag") != "block" || outputs[1]?.Text("protocol") != "blackhole" || rules.Count > 1 || rules.Any(r => r is not JsonObject o || o.Count != 3 || o.Text("type") != "field" || o.Text("outboundTag") != "block" || !o.Strings("ip").SequenceEqual(["::/0"]))) throw new OperationException("Reality 原有出站或规则超出受支持范围，保留原配置。");
        JsonObject? metadata = null;
        if (node == null)
        {
            if (previous == null) throw new OperationException("当前 Reality 没有受管固定下一跳。");
        }
        else
        {
            var native = NextHop(node); var endpoint = Address(native.Text("server")); var egress = Address(expectedAddress);
            if (new[] { plan.Text("Server.IPv4"), plan.Text("Server.IPv6") }.Any(s => IPAddress.TryParse(s, out var address) && address.Equals(endpoint))) throw new OperationException("服务器下一跳不能指回当前实例的地址。");
            var next = ToOutbound("RealityEntry", native, Tag);
            var family = egress.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
            var policy = ServerDestinationRules.Normalize(destinationRules);
            outputs.Add(next); var named = AddNamedHops("RealityEntry", outputs, additionalHops, node, plan);
            var added = AddedRules("RealityEntry", policy, tags, family, plan, named);
            for (var i = added.Count - 1; i >= 0; i--) rules.Insert(0, added[i]!.DeepClone());
            metadata = new JsonObject { ["Version"] = 1, ["Name"] = node.Text("name"), ["Endpoint"] = new IPEndPoint(endpoint, native.Number("server_port")).ToString(), ["ExpectedAddress"] = egress.ToString(), ["EgressFamily"] = family, ["OutboundFingerprint"] = ArchiveStore.Fingerprint(next), ["RulesFingerprint"] = ArchiveStore.Fingerprint(added), ["SchemeId"] = source?.Text("SchemeId"), ["NodeId"] = source?.Text("NodeId"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
            if (policy.Count > 0) { metadata["DestinationRules"] = policy; metadata["DestinationRulesNetwork"] = "tcp"; }
            if (named.Count > 0) metadata["AdditionalHops"] = named;
        }
        return new(result, metadata, Summary("RealityEntry", string.Join("、", tags) + "（主／备用与双栈监听共同使用此出口）", previous, metadata));
    }
}
