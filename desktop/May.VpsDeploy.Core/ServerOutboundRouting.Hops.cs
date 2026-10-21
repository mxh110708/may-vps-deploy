using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record ServerOutboundHop(string Id, JsonObject Node, string ExpectedAddress, JsonObject? Source = null);

public static partial class ServerOutboundRouting
{
    public const int MaximumAdditionalHops = 7;
    private const string HopTagPrefix = "may-hop-";
    public static string HopId(string value) => Regex.IsMatch(value, "^[a-f0-9]{16}$") ? value : throw new OperationException("附加落地标识无效。");
    public static string HopTag(string id) => HopTagPrefix + HopId(id);
    private static string Family(string address) => Address(address).AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
    public static JsonObject HopReference(string id, JsonObject scheme, JsonObject node, string expectedAddress) => new()
    {
        ["Id"] = HopId(id), ["SchemeId"] = Id(scheme.Text("Id")), ["NodeId"] = Id(node.Text("Id")),
        ["NodeFingerprint"] = ArchiveStore.Fingerprint(node), ["ExpectedAddress"] = Address(expectedAddress).ToString()
    };
    public static JsonArray HopReferences(JsonNode? value)
    {
        if (value == null) return new();
        if (value is not JsonArray list || list.Count > MaximumAdditionalHops) throw new OperationException("每个入站最多添加 7 个 TCP 落地。");
        var ids = new HashSet<string>(StringComparer.Ordinal); var sources = new HashSet<string>(StringComparer.Ordinal); var result = new JsonArray();
        foreach (var item in list)
        {
            if (item is not JsonObject reference || reference.Count != 5 || reference.Any(p => p.Key is not ("Id" or "SchemeId" or "NodeId" or "NodeFingerprint" or "ExpectedAddress") || p.Value is not JsonValue text || !text.TryGetValue<string>(out _))) throw new OperationException("附加落地引用字段无效。");
            if (!ids.Add(HopId(reference.Text("Id"))) || !sources.Add(Id(reference.Text("SchemeId")) + ":" + Id(reference.Text("NodeId")))) throw new OperationException("附加落地标识或来源重复，请复用已有落地。");
            if (!Regex.IsMatch(reference.Text("NodeFingerprint"), "^[a-f0-9]{64}$")) throw new OperationException("缺少附加落地的来源摘要。");
            var copy = reference.DeepClone().AsObject(); copy["ExpectedAddress"] = Address(reference.Text("ExpectedAddress")).ToString(); result.Add(copy);
        }
        return result;
    }
    public static IReadOnlyDictionary<string, string> HopFamilies(JsonNode? value) => HopReferences(value).OfType<JsonObject>().ToDictionary(h => h.Text("Id"), h => Family(h.Text("ExpectedAddress")), StringComparer.Ordinal);
    private static JsonObject ReadHopNode(ArchiveStore store, string instance, JsonObject reference)
    {
        var source = store.ReadSecret(SchemeFile(store.Paths, reference.Text("SchemeId")));
        try
        {
            var found = (source["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(n => n.Text("Id") == reference.Text("NodeId")).ToArray() ?? [];
            if (found.Length != 1 || ArchiveStore.Fingerprint(found[0]) != reference.Text("NodeFingerprint")) throw new OperationException("落地来源在审阅后已变化，请重新选择。", code: "ServerOutboundSourceChanged");
            var node = found[0].DeepClone().AsObject();
            if (node["ManagedOrigin"] is JsonObject origin)
            {
                if (origin.Text("Instance") == instance) throw new OperationException("服务器下一跳不能指回当前实例。");
                ManagedNodeSources.Verify(store, new JsonArray(origin.DeepClone()));
            }
            return node;
        }
        finally { source.Clear(); }
    }
    private static JsonObject ToOutbound(string role, JsonObject native, string tag)
    {
        if (role == "AnyTlsEntry") { var result = native.DeepClone().AsObject(); result["tag"] = tag; return result; }
        return new JsonObject { ["tag"] = tag, ["protocol"] = "shadowsocks", ["settings"] = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["address"] = native.Text("server"), ["port"] = native.Number("server_port"), ["method"] = native.Text("method"), ["password"] = native.Text("password") }) } };
    }
    private static JsonArray MetadataHops(JsonObject? metadata)
    {
        if (metadata?["AdditionalHops"] == null) return new();
        if (metadata["AdditionalHops"] is not JsonArray list || list.Count > MaximumAdditionalHops) throw new OperationException("服务器多落地归属记录不完整。");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in list)
        {
            if (item is not JsonObject hop || !ids.Add(HopId(hop.Text("Id"))) || hop.Number("Version") != 1 || !Regex.IsMatch(hop.Text("OutboundFingerprint"), "^[a-f0-9]{64}$") || hop.Text("EgressFamily") != Family(hop.Text("ExpectedAddress"))) throw new OperationException("服务器多落地归属记录无效。");
        }
        return list;
    }
    private static JsonArray AddNamedHops(string role, JsonArray outputs, IReadOnlyList<ServerOutboundHop>? hops, JsonObject defaultNode, JsonObject plan)
    {
        if (hops == null) return new();
        if (hops.Count > MaximumAdditionalHops) throw new OperationException("每个入站最多添加 7 个 TCP 落地。");
        var ids = new HashSet<string>(StringComparer.Ordinal); var connections = new HashSet<string>(StringComparer.Ordinal) { Connection(defaultNode) }; var metadata = new JsonArray();
        foreach (var hop in hops)
        {
            if (!ids.Add(HopId(hop.Id)) || !connections.Add(Connection(hop.Node))) throw new OperationException("落地标识或连接参数重复，请复用已有落地。");
            var native = NextHop(hop.Node); var endpoint = Address(native.Text("server")); var expected = Address(hop.ExpectedAddress);
            if (new[] { plan.Text("Server.IPv4"), plan.Text("Server.IPv6") }.Any(s => IPAddress.TryParse(s, out var address) && address.Equals(endpoint))) throw new OperationException("附加落地不能指回当前实例。");
            var outbound = ToOutbound(role, native, HopTag(hop.Id)); outputs.Add(outbound);
            metadata.Add(new JsonObject { ["Version"] = 1, ["Id"] = hop.Id, ["Name"] = hop.Node.Text("name"), ["Endpoint"] = new IPEndPoint(endpoint, native.Number("server_port")).ToString(), ["ExpectedAddress"] = expected.ToString(), ["EgressFamily"] = Family(hop.ExpectedAddress), ["OutboundFingerprint"] = ArchiveStore.Fingerprint(outbound), ["SchemeId"] = hop.Source?.Text("SchemeId"), ["NodeId"] = hop.Source?.Text("NodeId"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(hop.Node) });
        }
        return metadata;
        static string Connection(JsonObject node) { var native = NextHop(node); native.Remove("tag"); return ArchiveStore.Fingerprint(native); }
    }
    private static void RemoveNamedHops(JsonArray outputs, JsonObject? previous)
    {
        var expected = MetadataHops(previous).OfType<JsonObject>().ToArray(); var actual = outputs.OfType<JsonObject>().Where(o => o.Text("tag").StartsWith(HopTagPrefix, StringComparison.Ordinal)).ToArray();
        if (actual.Length != expected.Length || expected.Any(h => actual.Count(o => HopTag(h.Text("Id")) == o.Text("tag") && h.Text("OutboundFingerprint") == ArchiveStore.Fingerprint(o)) != 1)) throw new OperationException("发现无归属、缺失或被修改的附加落地，未覆盖。", code: "ServerOutboundDrift");
        foreach (var outbound in actual) outputs.Remove(outbound);
    }
    private static string RulesSummary(JsonObject metadata) => ServerDestinationRules.Summary(metadata["DestinationRules"], MetadataHops(metadata).OfType<JsonObject>().ToDictionary(h => h.Text("Id"), h => h.Text("Name"), StringComparer.Ordinal));
    private static string NamedHopsSummary(JsonObject metadata) => string.Join('\n', MetadataHops(metadata).OfType<JsonObject>().Select(h => "附加 TCP 落地：" + h.Text("Name") + " · " + h.Text("Endpoint") + " · 预期出口 " + h.Text("ExpectedAddress") + "（" + h.Text("EgressFamily") + "）"));
    public static JsonArray ProbeRequests(string role, JsonObject configuration, JsonObject plan)
    {
        VerifyManaged(role, configuration, plan); var result = new JsonArray(); var metadata = plan.At("ServerOutbound." + role) as JsonObject;
        foreach (var hop in MetadataHops(metadata).OfType<JsonObject>())
        {
            var outbound = configuration["outbounds"]!.AsArray().OfType<JsonObject>().Single(o => o.Text("tag") == HopTag(hop.Text("Id")));
            result.Add(new JsonObject { ["Id"] = hop.Text("Id"), ["ExpectedAddress"] = hop.Text("ExpectedAddress"), ["Outbound"] = outbound.DeepClone() });
        }
        return result;
    }
    public static void RequireHopValidation(JsonArray requests, JsonObject result)
    {
        var items = (result["Items"] as JsonArray)?.OfType<JsonObject>().ToArray() ?? [];
        if (result.Text("Status") != "Passed" || items.Length != requests.Count || requests.OfType<JsonObject>().Any(request => items.Count(item => item.Text("Id") == request.Text("Id") && item.Text("Status") == "Passed" && item.Text("From") == "EntryServer" && item.Text("Network") == "TCP" && IPAddress.TryParse(item.Text("Egress"), out var egress) && egress.Equals(Address(request.Text("ExpectedAddress")))) != 1)) throw new OperationException("附加落地的 TCP、TLS 或实际出口验收未全部完成，恢复本次范围。", code: "ServerHopValidationIncomplete");
    }
}
