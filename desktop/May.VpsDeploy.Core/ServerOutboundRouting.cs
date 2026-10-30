using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record ServerOutboundPreview(JsonObject Configuration, JsonObject? Metadata, string Summary);

// Fixed server-side routing is deliberately separate from client detour/region rules.
public static partial class ServerOutboundRouting
{
    public static readonly string[] Roles = ["RealityEntry", "AnyTlsEntry"];
    public const string Tag = "may-fixed-next-hop";
    public static string ConfigRelative(string role) => role switch { "RealityEntry" => "server-configs/xray-config.private.json", "AnyTlsEntry" => "server-configs/sing-box-anytls-config.private.json", _ => throw new OperationException("请选择 Reality 或 AnyTLS 入站。") };
    public static string Label(string role) => role switch { "RealityEntry" => "Xray Reality", "AnyTlsEntry" => "sing-box AnyTLS", _ => throw new OperationException("请选择 Reality 或 AnyTLS 入站。") };
    private static readonly string[] Methods = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];
    private static string Id(string value) => Regex.IsMatch(value, "^[a-f0-9]{32}$") ? value : throw new OperationException("节点或方案标识无效。");
    public static string SchemeFile(AppPaths paths, string id) => paths.Resolve("private/client-schemes/" + Id(id) + ".dotnet.private.json");
    public static string EgressAddress(JsonObject plan, string role, string fallback) => Roles.Contains(role) && plan.At("ServerOutbound." + role) is JsonObject route ? route.Text("ExpectedAddress") : fallback;
    public static string EgressFamily(JsonObject plan, string role, string fallback) => Roles.Contains(role) && plan.At("ServerOutbound." + role) is JsonObject route ? route.Text("EgressFamily") : fallback;
    public static void ValidateOptions(JsonObject options)
    {
        var apply = options.Text("Action") == "Apply";
        if (options.Text("Action") is not ("Apply" or "Remove") || !Roles.Contains(options.Text("Protocol"))) throw new OperationException("请选择 Reality 或 AnyTLS 入站的固定下一跳。");
        var fields = apply ? new[] { "Action", "Protocol", "ConfigSha256", "SchemeId", "NodeId", "NodeFingerprint", "ExpectedAddress" } : new[] { "Action", "Protocol", "ConfigSha256" };
        var hasRules = apply && options.ContainsKey("DestinationRules");
        var hasHops = apply && options.ContainsKey("AdditionalHops");
        if (options.Count != fields.Length + (hasRules ? 1 : 0) + (hasHops ? 1 : 0) || options.Any(p => !fields.Contains(p.Key) && !(hasRules && p.Key == "DestinationRules") && !(hasHops && p.Key == "AdditionalHops"))) throw new OperationException("服务器出站计划字段无效，请重新审阅。");
        if (!Regex.IsMatch(options.Text("ConfigSha256"), "^[a-f0-9]{64}$")) throw new OperationException("缺少服务器配置摘要，请先接入并归档配置。");
        if (apply)
        {
            Id(options.Text("SchemeId")); Id(options.Text("NodeId"));
            if (!Regex.IsMatch(options.Text("NodeFingerprint"), "^[a-f0-9]{64}$")) throw new OperationException("缺少下一跳身份摘要。");
            var address = Address(options.Text("ExpectedAddress"));
            var rules = ServerDestinationRules.Normalize(options["DestinationRules"]);
            ServerDestinationRules.ValidatePath(rules, address.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4", false, HopFamilies(options["AdditionalHops"]));
        }
    }
    public static JsonObject Options(JsonObject state, string role, string action, JsonObject? scheme = null, JsonObject? node = null, string expectedAddress = "", JsonArray? destinationRules = null, JsonArray? additionalHops = null)
    {
        var result = new JsonObject { ["Action"] = action, ["Protocol"] = role, ["ConfigSha256"] = state.Text("ServerConfigHashes." + role) };
        if (action == "Apply")
        {
            if (scheme == null || node == null) throw new OperationException("请先保存方案并选择下一跳。");
            result["SchemeId"] = scheme.Text("Id"); result["NodeId"] = node.Text("Id"); result["NodeFingerprint"] = ArchiveStore.Fingerprint(node); result["ExpectedAddress"] = Address(expectedAddress).ToString();
            var rules = ServerDestinationRules.Normalize(destinationRules); if (rules.Count > 0) result["DestinationRules"] = rules;
            var hops = HopReferences(additionalHops); if (hops.Count > 0) result["AdditionalHops"] = hops;
        }
        ValidateOptions(result); return result;
    }
    public static ServerOutboundPreview Prepare(ArchiveStore store, OperationRequest request)
    {
        ValidateOptions(request.Options);
        var role = request.Options.Text("Protocol");
        var directory = store.Paths.Instance(request.InstanceRelativePath);
        var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"));
        var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        var lifecycle = InstanceLifecycle.Read(store, request.InstanceRelativePath, plan);
        if (!lifecycle.Managed || lifecycle.NeedsRecovery) throw new OperationException("请先完成该实例的接入、部署或待恢复事务。");
        if (!plan.Flag("ProtocolInventory." + role + ".Installed", DeploymentPlans.Uses(plan, role)) || !plan.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.InitiallyEnabled(plan, role))) throw new OperationException("请先启用已纳管的 " + Label(role) + " 入站，再配置并验收服务器出站。");
        var file = SafePath.Resolve(directory, ConfigRelative(role)); SafePath.CheckLinks(file);
        if (!File.Exists(file) || new FileInfo(file).Length > 1048576 || ClientSchemes.SourceFingerprint(file) != request.Options.Text("ConfigSha256") || state.Text("ServerConfigHashes." + role) != request.Options.Text("ConfigSha256")) throw new OperationException("服务器配置归档已变化或不完整，请重新接入、核对并审阅。", code: "ServerOutboundArchiveChanged");
        JsonObject? node = null; var hops = new List<ServerOutboundHop>();
        if (request.Options.Text("Action") == "Apply")
        {
            node = ReadHopNode(store, request.InstanceRelativePath, request.Options);
            foreach (var reference in HopReferences(request.Options["AdditionalHops"]).OfType<JsonObject>()) hops.Add(new(reference.Text("Id"), ReadHopNode(store, request.InstanceRelativePath, reference), reference.Text("ExpectedAddress"), reference));
        }
        return Build(role, ArchiveStore.ReadJson(file), plan["ServerOutbound"]?[role] as JsonObject, node, request.Options.Text("ExpectedAddress"), plan, request.Options, request.Options["DestinationRules"] as JsonArray, hops);
    }
    public static bool SupportedNode(JsonObject node)
    {
        try { Id(node.Text("Id")); NextHop(node); return true; } catch (OperationException) { return false; }
    }
    public static JsonObject NextHop(JsonObject node)
    {
        if (node["ForwardedOrigin"] != null) throw new OperationException("本轮服务器落地须选择原始代理节点，不能引用转发节点。");
        if (node["sing_box"] is not JsonObject native) throw new OperationException("下一跳缺少完整 sing-box 原生参数。");
        if (IsQuic(native)) QuicParameters(native);
        else if (native.Text("type") != "shadowsocks" || native.Any(p => !new[] { "type", "tag", "server", "server_port", "method", "password" }.Contains(p.Key)) || !Methods.Contains(native.Text("method"))) throw new OperationException("下一跳支持完整 Shadowsocks、Hysteria2 或 TUIC v5；不接受插件、客户端 detour 或未支持的参数。");
        if (native.Number("server_port") is < 1 or > 65535 || native.Text("password").Length is < 1 or > 4096 || native.Text("password").Any(char.IsControl)) throw new OperationException("下一跳的端口或鉴权参数无效。");
        Address(native.Text("server"));
        var name = node.Text("name"); if (name.Length is < 1 or > 120 || name.Any(char.IsControl)) throw new OperationException("下一跳名称无效。");
        var result = native.DeepClone().AsObject(); result["tag"] = Tag; result["server"] = Address(native.Text("server")).ToString();
        if (result.Text("type") == "hysteria2" && result["server_ports"] != null) result["server_ports"] = Hysteria2Ports.Native(Hysteria2Ports.FromNative(result["server_ports"]));
        return result;
    }
    public static ServerOutboundPreview Build(string role, JsonObject current, JsonObject? previous, JsonObject? node, string expectedAddress, JsonObject plan, JsonObject? source = null, JsonArray? destinationRules = null, IReadOnlyList<ServerOutboundHop>? additionalHops = null)
    {
        if (role == "RealityEntry") return BuildReality(current, previous, node, expectedAddress, plan, source, destinationRules, additionalHops);
        if (role != "AnyTlsEntry") throw new OperationException("请选择受支持的入站组件。");
        if (current["inbounds"] is not JsonArray inputs || inputs.Count != 1 || inputs[0]?.Text("type") != "anytls" || inputs[0]?.Text("tag") != "anytls-in" || current["outbounds"] is not JsonArray || current["route"] is not JsonObject) throw new OperationException("当前 AnyTLS 入站不是本轮支持的单入站布局，未重写配置。");
        var result = current.DeepClone().AsObject(); var outputs = result["outbounds"]!.AsArray(); var route = result["route"]!.AsObject();
        if (route["rules"] is not JsonArray rules || route.Text("final") != "direct" || route.Any(p => p.Key is not ("final" or "rules"))) throw new OperationException("当前服务器具有自定义分流，不能自动改成固定下一跳。");
        var ownedOutput = outputs.OfType<JsonObject>().Where(n => n.Text("tag") == Tag).ToArray();
        var ownedRules = rules.OfType<JsonObject>().Where(n => n.Strings("inbound").Contains("anytls-in")).ToArray();
        RemoveNamedHops(outputs, previous);
        if (previous == null)
        {
            if (ownedOutput.Length > 0 || ownedRules.Length > 0) throw new OperationException("发现无本地归属的服务器出站规则，未接管或覆盖。");
        }
        else
        {
            if (previous.Number("Version") != 1 || ownedOutput.Length != 1 || ArchiveStore.Fingerprint(ownedOutput[0]) != previous.Text("OutboundFingerprint") || !OwnedRulesMatch(role, ownedRules, previous, ["anytls-in"], plan)) throw new OperationException("受管服务器出站已漂移，未覆盖或删除。", code: "ServerOutboundDrift");
            outputs.Remove(ownedOutput[0]); foreach (var rule in ownedRules) rules.Remove(rule);
        }
        if (outputs.Count != 1 || outputs[0]?.Text("tag") != "direct" || outputs[0]?.Text("type") != "direct" || rules.Count > 1 || rules.Any(r => r is not JsonObject o || o.Count != 2 || o.Number("ip_version") != 6 || o.Text("action") != "reject")) throw new OperationException("当前服务器出口或规则超出受支持布局，保留原配置。");
        JsonObject? metadata = null;
        if (node == null)
        {
            if (previous == null) throw new OperationException("当前没有本应用管理的固定下一跳。");
        }
        else
        {
            var next = NextHop(node); var endpoint = Address(next.Text("server")); var expected = Address(expectedAddress);
            if (new[] { plan.Text("Server.IPv4"), plan.Text("Server.IPv6") }.Any(s => IPAddress.TryParse(s, out var address) && address.Equals(endpoint))) throw new OperationException("服务器下一跳不能指回当前实例的地址。");
            var family = expected.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
            var policy = ServerDestinationRules.Normalize(destinationRules);
            outputs.Add(next); var named = AddNamedHops(role, outputs, additionalHops, node, plan);
            var added = AddedRules(role, policy, ["anytls-in"], family, plan, named);
            for (var i = added.Count - 1; i >= 0; i--) rules.Insert(0, added[i]!.DeepClone());
            metadata = new JsonObject { ["Version"] = 1, ["Name"] = node.Text("name"), ["Endpoint"] = new IPEndPoint(endpoint, next.Number("server_port")).ToString(), ["ExpectedAddress"] = expected.ToString(), ["EgressFamily"] = family, ["OutboundFingerprint"] = ArchiveStore.Fingerprint(next), ["RulesFingerprint"] = ArchiveStore.Fingerprint(added), ["SchemeId"] = source?.Text("SchemeId"), ["NodeId"] = source?.Text("NodeId"), ["NodeFingerprint"] = ArchiveStore.Fingerprint(node) };
            if (policy.Count > 0) { metadata["DestinationRules"] = policy; metadata["DestinationRulesNetwork"] = "tcp"; }
            if (named.Count > 0) metadata["AdditionalHops"] = named;
        }
        return new(result, metadata, Summary(role, "anytls-in", previous, metadata));
    }
    public static void VerifyManaged(string role, JsonObject configuration, JsonObject plan)
    {
        if (Roles.Contains(role) && plan.At("ServerOutbound." + role) is JsonObject metadata) Build(role, configuration, metadata, null, "", plan);
    }
    private static string Summary(string role, string inbounds, JsonObject? previous, JsonObject? metadata) =>
        "入站：" + Label(role) + " / " + inbounds + "（全部用户，TCP 与 UDP）\n" + (previous == null ? "原策略：此入站原有出口策略。\n" : "原下一跳：" + previous.Text("Name") + " · " + previous.Text("Endpoint") + "\n") +
        (metadata == null ? "操作：移除受管固定下一跳、附加落地及分流例外，恢复原 " + (role == "RealityEntry" ? "Reality" : "AnyTLS") + " 出口策略。" : "默认下一跳：" + metadata.Text("Name") + " · " + metadata.Text("Endpoint") + "\n预期网站出口（默认落地）：" + metadata.Text("ExpectedAddress") + "（" + metadata.Text("EgressFamily") + "）\nIP 网段按对应落地的预期出口地址族核对；域名出口由落地处理。落地失败不会回退直连或其他落地。\n" + NamedHopsSummary(metadata) + "\n" + RulesSummary(metadata)) +
        (previous?["DestinationRules"] == null ? "" : "\n\n原分流例外：\n" + NamedHopsSummary(previous) + "\n" + RulesSummary(previous)) +
        "\n\n只重启当前 " + Label(role) + " 服务，现有连接会短暂断开。保留监听、入站凭据、Reality / TLS / ECH、防火墙、SSH、其他协议与监控。\n先核对实际配置摘要和服务状态，建立该组件专用恢复点，再应用并独立验证默认入口的 HTTPS、出口地址及 UDP。附加 TCP 落地从入口机逐一核验 TLS 与预期出口；业务规则命中仍需实际业务核对。验收不完整、失败或取消均恢复本次范围；回复不明先核对事务，不重放写入。\n下一跳凭据按本次审阅快照配置；方案后续刷新不会自动修改服务器。";
    private static IPAddress Address(string text)
    {
        if (!IPAddress.TryParse(text, out var address) || address.IsIPv4MappedToIPv6 || IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.IsIPv6LinkLocal || address.IsIPv6Multicast || text.Contains('%') || address.AddressFamily == AddressFamily.InterNetwork && (address.GetAddressBytes()[0] is 0 or >= 224 || address.GetAddressBytes()[0] == 169 && address.GetAddressBytes()[1] == 254)) throw new OperationException("本轮需要明确的非回环、非链路本地 IP 地址；域名下一跳后续补充。");
        return address;
    }
}
