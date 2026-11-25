using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record AddressChangePreview(JsonObject Document, string Fingerprint, string Summary);

// Discovery is local and keyed by canonical instance identities. Address text is
// replaced only in connection/source fields, never in names or TLS identities.
public static partial class InstanceAddressChanges
{
    internal static readonly AsyncLocal<string?> Owner = new();
    internal static readonly AsyncLocal<bool> Preparing = new();
    public static bool Pending(JsonObject state) => state.ContainsKey("AddressChangeTransaction") && !(state["AddressChangeTransaction"] is JsonObject t && Regex.IsMatch(t.Text("Id"), "^[a-f0-9]{32}$") && t.Text("Id") == Owner.Value);
    public static string RecordFile(AppPaths paths, string id) => paths.Resolve("private/address-changes/" + TcpChains.Id(id) + ".private.json");
    public static JsonObject Options(JsonObject plan) => new() { ["Action"] = "Apply", ["IPv4"] = plan.Text("Server.IPv4"), ["IPv6"] = plan.Text("Server.IPv6") };
    public static void Validate(OperationRequest request)
    {
        var o = request.Options;
        if (o.Text("Action") == "Recover")
        {
            if (o.Count != 2) throw new OperationException("换址恢复只接受原事务身份。");
            _ = TcpChains.Id(o.Text("Id")); return;
        }
        if (o.Count != 3 || o.Text("Action") != "Apply") throw new OperationException("换址参数无效。");
        _ = Address(o.Text("IPv4"), 4); if (o.Text("IPv6") != "") _ = Address(o.Text("IPv6"), 6);
    }
    private static string Address(string value, int family)
    {
        if (!IPAddress.TryParse(value, out var a) || a.ToString() != value || a.IsIPv4MappedToIPv6 || a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && a.ScopeId != 0 || IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any) || a.IsIPv6Multicast || a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && a.GetAddressBytes()[0] >= 224 || (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 4 : 6) != family) throw new OperationException("请填写规范的 IPv4／IPv6 单播地址。");
        return value;
    }
    public static string Pin(ArchiveStore store, string host)
    {
        var file = store.Paths.Resolve("private/ssh-hosts.dotnet.json");
        var pin = File.Exists(file) ? ArchiveStore.ReadJson(file).Text(ArchiveStore.Digest(Encoding.UTF8.GetBytes(host))) : "";
        if (!Regex.IsMatch(pin, @"^SHA256:[A-Za-z0-9+/]{43}$")) throw new OperationException("原管理地址没有已保存的 SSH 主机身份。先独立核对原身份；换址不会接受未知主机密钥。");
        return pin;
    }
    public static void GuardOperation(ArchiveStore store, OperationRequest request)
    {
        var file = SafePath.Resolve(store.Paths.Instance(request.InstanceRelativePath), "deployment-state.json");
        if (!File.Exists(file)) return;
        var state = ArchiveStore.ReadJson(file);
        if (!Pending(state)) return;
        if (request.Kind == OperationKind.InstanceAddress && request.Options.Text("Action") == "Recover" && request.Options.Text("Id") == state.Text("AddressChangeTransaction.Id")) return;
        throw new OperationException("此实例参与尚未完成的换址事务，请从“恢复换址”统一核对。", true, "AddressChangePending");
    }
    public static string[] Participants(ArchiveStore store, OperationRequest request) => Prepare(store, request).Document["Hosts"]!.AsArray().Select(h => h!.Text("Instance")).ToArray();
    public static AddressChangePreview Prepare(ArchiveStore store, OperationRequest request)
    {
        Validate(request);
        if (request.Options.Text("Action") == "Recover")
        {
            var r = store.ReadSecret(RecordFile(store.Paths, request.Options.Text("Id")));
            if (r.Number("Version") != 1 || r.Text("Instance") != request.InstanceRelativePath || r.Text("Phase") is "Committed" or "RolledBack") throw new OperationException("没有匹配的待恢复换址事务。");
            ValidateRecovery(store, request, r);
            var recoveredDocument = r["Document"]!.DeepClone().AsObject();
            return new(recoveredDocument, ClientSchemes.SourceFingerprint(RecordFile(store.Paths, request.Options.Text("Id"))), "恢复换址 · " + recoveredDocument["Hosts"]!.AsArray().Count + " 台参与实例\n只恢复原事务记录的资源；主机身份、远端或本地内容不符时停止，不重新执行换址。");
        }
        var instances = store.ListInstances().ToArray();
        var target = instances.SingleOrDefault(i => i.RelativePath == request.InstanceRelativePath);
        if (target.Plan == null || !InstanceLifecycle.Read(store, target.RelativePath, target.Plan).Managed) throw new OperationException("请先完成实例接入。");
        if (request.Options.Text("IPv6") == "" && target.Plan.Text("Server.IPv6") != "") throw new OperationException("本轮不删除已有 IPv6；保留当前值或填写替换地址。");
        var map = new JsonObject();
        foreach (var family in new[] { "IPv4", "IPv6" })
        {
            var old = target.Plan.Text("Server." + family); var next = request.Options.Text(family);
            if (old == next) continue;
            if (old == "") throw new OperationException("本轮只替换已有地址；新增地址族须单独接入并验收。");
            if (instances.Any(i => i.RelativePath != target.RelativePath && new[] { i.Plan.Text("Server.IPv4"), i.Plan.Text("Server.IPv6") }.Contains(old)) || instances.Any(i => i.RelativePath != target.RelativePath && new[] { i.Plan.Text("Server.IPv4"), i.Plan.Text("Server.IPv6") }.Contains(next))) throw new OperationException("地址归属不唯一或新地址已被另一实例使用，未推断依赖。");
            map[old] = next;
        }
        if (map.Count == 0) throw new OperationException("地址没有变化。");
        var hosts = new JsonArray(); var files = new JsonArray(); var notices = new JsonArray();
        void FileChange(string path, JsonObject before, JsonObject after, bool secret)
        {
            if (JsonNode.DeepEquals(before, after)) return;
            files.Add(new JsonObject { ["Path"] = Path.GetRelativePath(store.Paths.Private, path).Replace('\\', '/'), ["Secret"] = secret, ["Before"] = before.DeepClone(), ["After"] = after.DeepClone(), ["Hash"] = ClientSchemes.SourceFingerprint(path) });
        }
        foreach (var (relative, original) in instances)
        {
            var after = original.DeepClone().AsObject();
            if (relative == target.RelativePath) { after.Put("Server.IPv4", request.Options["IPv4"]!.DeepClone()); after.Put("Server.IPv6", request.Options["IPv6"]!.DeepClone()); }
            foreach (var key in new[] { "Shadowsocks", "TcpForwarding", "UdpForwarding", "WireGuardTunnel", "WireGuardTunnel2", "InboundModel", "ServerOutbound" })
                if (after[key] is JsonObject part) Rewrite(part, map);
            if (JsonNode.DeepEquals(original, after)) continue;
            if (InstanceLifecycle.Read(store, relative, original).NeedsRecovery) throw new OperationException("受影响实例已有未完成事务，先完成恢复。");
            var directory = store.Paths.Instance(relative); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
            var resources = new JsonArray();
            void Resource(string kind, string component, JsonNode? before, JsonNode? next, string hash)
            {
                if (before == null || next == null || JsonNode.DeepEquals(before, next)) return;
                if (hash is "" or "Absent") throw new OperationException("受影响组件缺少当前受管摘要，请先检查组件。");
                resources.Add(new JsonObject { ["Kind"] = kind, ["Component"] = component, ["ExpectedHash"] = hash, ["Before"] = before.DeepClone(), ["After"] = next.DeepClone() });
            }
            foreach (var component in new[] { "TcpForwarding", "UdpForwarding", "WireGuardTunnel", "WireGuardTunnel2" }) Resource(component, component, original[component], after[component], state.Text(component + ".RemoteHash"));
            foreach (var (role, name) in ProtocolFiles)
            {
                var config = SafePath.Resolve(directory, "server-configs/" + name);
                if (!File.Exists(config)) { if (original.At("ServerOutbound." + role) != null) throw new OperationException("受影响下一跳缺少服务器配置归档。"); continue; }
                var before = ArchiveStore.ReadJson(config); var next = before.DeepClone().AsObject(); Rewrite(next, map);
                Resource(role, role, before, next, state.Text("ServerConfigHashes." + role));
                FileChange(config, before, next, false);
            }
            if (!JsonNode.DeepEquals(original["InboundModel"], after["InboundModel"]) || relative == target.RelativePath && original["InboundModel"] is JsonObject m && InboundCatalog.Items(m, "Inbounds").Any())
                resources.Add(new JsonObject { ["Kind"] = "Inbounds", ["Component"] = "Inbounds", ["ExpectedHash"] = state.Text("Inbounds.RemoteHash"), ["Before"] = original["InboundModel"]!.DeepClone(), ["After"] = after["InboundModel"]!.DeepClone() });
            var firewallChanged = !JsonNode.DeepEquals(original["Shadowsocks"], after["Shadowsocks"]) || WireGuardTunnels.Components.Any(c => !JsonNode.DeepEquals(original[c], after[c]));
            if (firewallChanged)
            {
                if (original.Text("Firewall.Mode") == "PreserveExisting" && !JsonNode.DeepEquals(original["Shadowsocks"], after["Shadowsocks"])) throw new OperationException("受影响落地使用非受管防火墙，先由维护者同步规则后再核对；没有自动改写它。");
                if (original.Text("Firewall.Mode") != "PreserveExisting") resources.Insert(0, new JsonObject { ["Kind"] = "Firewall", ["Component"] = "Firewall", ["Before"] = new JsonObject(), ["After"] = new JsonObject(), ["ExpectedHash"] = "Managed" });
            }
            hosts.Add(new JsonObject { ["Instance"] = relative, ["Before"] = original.DeepClone(), ["After"] = after, ["State"] = state.DeepClone(), ["Pin"] = Pin(store, original.Text("Server.IPv4")), ["Resources"] = resources, ["Hashes"] = new JsonObject { ["Plan"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "deployment-plan.json")), ["State"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "deployment-state.json")), ["Secrets"] = ClientSchemes.SourceFingerprint(SafePath.Resolve(directory, "secrets.dotnet.private.json")) } });
        }
        foreach (var group in new[] { "client-schemes", "client-node-groups" })
        {
            var dir = store.Paths.Resolve("private/" + group); if (!Directory.Exists(dir)) continue; SafePath.CheckTree(dir);
            foreach (var path in Directory.EnumerateFiles(dir, "*.json"))
            {
                var before = store.ReadSecret(path); var next = before.DeepClone().AsObject();
                foreach (var node in (next["Nodes"] as JsonArray ?? []).OfType<JsonObject>())
                {
                    var origin = (node["ManagedOrigin"] ?? node["InboundOrigin"] ?? node["ForwardedOrigin"]) as JsonObject;
                    if (origin != null && hosts.Any(h => h!.Text("Instance") == origin.Text("Instance")) || node["TcpChainOrigin"] != null)
                    { RewriteNode(node, map); next.Remove("Candidate"); }
                    else if (HasAddress(node, map)) notices.Add("外部节点仅报告影响：" + node.Text("name"));
                }
                FileChange(path, before, next, true); before.Clear();
            }
        }
        foreach (var group in new[] { "tcp-chains", "wireguard-tunnels" })
        {
            var dir = store.Paths.Resolve("private/" + group); if (!Directory.Exists(dir)) continue; SafePath.CheckTree(dir);
            foreach (var path in Directory.EnumerateFiles(dir, "*.json")) { var before = ArchiveStore.ReadJson(path); var next = before.DeepClone().AsObject(); Rewrite(next, map); FileChange(path, before, next, false); }
        }
        var document = new JsonObject { ["Version"] = 1, ["Instance"] = target.RelativePath, ["ProgramSha256"] = ArchiveStore.Digest(Encoding.UTF8.GetBytes(new RemoteAssets(store.Paths).AddressProgram())), ["Addresses"] = map, ["Hosts"] = hosts, ["Files"] = files, ["Notices"] = notices };
        CompleteReferences(store, document, instances);
        foreach (var host in hosts.OfType<JsonObject>())
            if (!InstanceLifecycle.Read(store, host.Text("Instance"), host["Before"]!.AsObject()).Managed) throw new OperationException("受影响依赖尚未完成接入，请先独立核对其归属。" );
        var fingerprint = ArchiveStore.Fingerprint(document);
        var summary = "实例换址 · " + target.Plan.Text("NodeName") + "\n" + string.Join("\n", map.Select(p => p.Key + " → " + p.Value)) + "\n受影响实例 " + hosts.Count + " 台，受管组件 " + hosts.Sum(h => h!["Resources"]!.AsArray().Count) + " 项，本地来源 " + files.Count + " 份。\n先核对原 SSH 身份，再备份；先同时放行新旧来源，再同步目标并验收 TCP／UDP，最后移除旧来源。\n外部配置保留导出审阅；本操作不重载客户端、不变更服务商网络和 Cloudflare，也不接受重装后的新 SSH 身份。" + string.Concat(notices.Select(n => "\n" + n));
        summary += "\n\n参与实例与范围：";
        foreach (var host in hosts.OfType<JsonObject>())
        {
            var labels = host["Resources"]!.AsArray().Select(r => r!.Text("Kind") switch
            {
                "Firewall" => "运行与持久白名单", "Inbounds" => "独立入站", "TcpForwarding" => "TCP 转发", "UdpForwarding" => "UDP 转发",
                "WireGuardTunnel" => "WireGuard 槽位 1", "WireGuardTunnel2" => "WireGuard 槽位 2", "RealityEntry" => "Reality 入口",
                "AnyTlsEntry" => "AnyTLS 入口", "ShadowsocksLanding" => "SS2022 落地", _ => throw new OperationException("未知换址资源。")
            }).ToArray();
            summary += "\n• " + host.Text("Before.NodeName") + "（" + host.Text("Instance") + "）：" + (labels.Length == 0 ? "身份、来源及整链验收" : string.Join("、", labels));
        }
        if (files.Count > 0) summary += "\n\n本地同步范围：" + string.Concat(files.OfType<JsonObject>().GroupBy(f => f.Text("Path").Split('/')[0]).Select(g => "\n• " + (g.Key switch { "client-schemes" => "客户端方案", "client-node-groups" => "节点组", "tcp-chains" => "跨实例线路", "wireguard-tunnels" => "双端隧道记录", _ => "受管服务器配置归档" }) + " " + g.Count() + " 份"));
        return new(document, fingerprint, summary);
    }
    internal static readonly (string Role, string File)[] ProtocolFiles = [("RealityEntry", "xray-config.private.json"), ("AnyTlsEntry", "sing-box-anytls-config.private.json"), ("ShadowsocksLanding", "sing-box-config.private.json")];
    private static readonly HashSet<string> ConnectionFields = new(StringComparer.Ordinal) { "IPv4", "IPv6", "Endpoint", "SourceAddress", "FrontSourceAddress", "TargetAddress", "BackupAddress", "ExpectedAddress", "ProbeDestination", "PrimaryExit", "BackupExit", "Address", "EndpointAddress", "LandingAddress", "FrontAddress", "RelayAddress", "server", "address", "listen", "sendThrough", "bind_address", "inet4_bind_address", "inet6_bind_address" };
    private static readonly HashSet<string> SourceLists = new(StringComparer.Ordinal) { "TrustedEntryIPv4s", "TrustedEntryIPv6s", "AllowedSources", "FrontSources", "TrustedSources" };
    public static void Rewrite(JsonNode node, JsonObject map, bool bridge = false)
    {
        if (node is JsonObject o)
        {
            foreach (var (key, value) in o.ToArray())
            {
                if (ConnectionFields.Contains(key) && value is JsonValue v && v.TryGetValue<string>(out var s)) o[key] = ReplaceAddress(s, map);
                else if (key == "ExpectedExits" && value is JsonObject exits)
                {
                    foreach (var (id, exit) in exits.ToArray()) if (exit is JsonValue text && text.TryGetValue<string>(out var address)) exits[id] = ReplaceAddress(address, map);
                }
                else if (SourceLists.Contains(key) && value is JsonArray a)
                {
                    var items = a.Select(x => x!.ToString()).SelectMany(s => bridge && ReplaceAddress(s, map) != s ? new[] { s, ReplaceAddress(s, map) } : new[] { ReplaceAddress(s, map) }).Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray(); o[key] = new JsonArray(items);
                }
                else if (value is JsonObject or JsonArray) Rewrite(value, map, bridge);
            }
        }
        else if (node is JsonArray array) foreach (var child in array.Where(x => x != null)) Rewrite(child!, map, bridge);
    }
    internal static string ReplaceAddress(string value, JsonObject map)
    {
        if (map[value] != null) return map[value]!.ToString();
        foreach (var item in map)
        {
            var old = item.Key; var next = item.Value!.ToString();
            if (value == old + (old.Contains(':') ? "/128" : "/32")) return next + (old.Contains(':') ? "/128" : "/32");
            if (value.StartsWith("[" + old + "]:", StringComparison.Ordinal)) return "[" + next + "]:" + value[(old.Length + 3)..];
            if (!old.Contains(':') && value.StartsWith(old + ":", StringComparison.Ordinal) && int.TryParse(value[(old.Length + 1)..], out _)) return next + value[old.Length..];
        }
        return value;
    }
    private static bool HasAddress(JsonObject node, JsonObject map) => (node["clash"] is JsonObject c && map[c.Text("server")] != null) || (node["sing_box"] is JsonObject s && map[s.Text("server")] != null);
    private static void RewriteNode(JsonObject node, JsonObject map) { foreach (var key in new[] { "clash", "sing_box", "Egress" }) if (node[key] is JsonObject part) Rewrite(part, map); }
}
