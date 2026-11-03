using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record OperationsResource(string Key, string Instance, string Kind, string Name, string Status,
    string Evidence, DateTimeOffset? ObservedAt, DateTimeOffset? NotAfter, string Detail,
    string Maintenance, string Target, IReadOnlyList<string> References);
public sealed record ResourceInstance(string RelativePath, JsonObject Plan, JsonObject State, bool CanMaintain);
public sealed record OperationsResourceOverview(IReadOnlyList<OperationsResource> Items, IReadOnlyList<string> Issues)
{
    public IReadOnlySet<string> RelatedKeys(string instance)
    {
        var edges = Items.SelectMany(i => i.References.Select(r => (From: i.Key, To: r))).ToArray();
        var graph = edges.Concat(edges.Select(e => (From: e.To, To: e.From))).ToLookup(e => e.From, e => e.To, StringComparer.Ordinal);
        var seen = Items.Where(i => i.Instance == instance).Select(i => i.Key).ToHashSet(StringComparer.Ordinal); var queue = new Queue<string>(seen);
        while (queue.TryDequeue(out var key)) foreach (var next in graph[key]) if (seen.Add(next)) queue.Enqueue(next);
        return seen;
    }
    // Reverse traversal includes disabled consumers and is cycle-safe. The graph
    // describes impact; it never grants permission to edit or remove a consumer.
    public IReadOnlyList<OperationsResource> Consumers(string key, bool transitive = true)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal) { key }; var queue = new Queue<string>(); queue.Enqueue(key);
        var reverse = Items.SelectMany(i => i.References.Select(r => (Reference: r, Item: i))).ToLookup(i => i.Reference, StringComparer.Ordinal);
        var result = new List<OperationsResource>();
        while (queue.TryDequeue(out var current))
            foreach (var item in reverse[current].Select(p => p.Item))
                if (seen.Add(item.Key)) { result.Add(item); if (transitive) queue.Enqueue(item.Key); }
        return result.OrderBy(i => i.Instance, StringComparer.Ordinal).ThenBy(i => i.Name, StringComparer.Ordinal).ToArray();
    }
}

public static partial class OperationsResources
{
    public const int FreshHours = 24;
    public static string Key(string instance, string kind, string id) => instance + "#" + kind + ":" + id;
    public static string NodeKey(string scheme, string node) => "scheme:" + scheme + "#node:" + node;
    public static string TunnelKey(string id) => "wireguard:" + id;
    public static string ChainKey(string id) => "chain:" + id;
    public static string StatusLabel(string status) => status switch
    {
        "Expired" => "已到期", "Expiring" => "14 天内到期", "DueSoon" => "30 天内到期", "NotYetValid" => "尚未生效",
        "Valid" => "有效期正常", "Drift" => "与归档不符", "Missing" => "远端缺失", "Unreadable" => "无法核验",
        "Pending" => "待恢复", "Disabled" => "已停用（保留引用）", "Recorded" => "已归档", _ => "待核对"
    };
    public static string KindLabel(string kind) => kind switch
    {
        "Certificate" => "证书", "Inbound" => "独立入站", "User" => "入站用户", "Outbound" => "入站出站",
        "Core" => "代理核心", "Protocol" => "固定协议", "TcpForward" => "TCP 转发", "UdpForward" => "UDP 转发",
        "WireGuard" => "WireGuard", "Chain" => "跨实例线路", "ServerRoute" => "服务器分流", "Monitor" => "监控与访问",
        "Authorization" => "监控授权", "ClientNode" => "客户端节点", "ClientGroup" => "复用节点组", "Recovery" => "恢复范围", _ => kind
    };
    public static bool NeedsAttention(OperationsResource item) => item.Status is "Expired" or "Expiring" or "DueSoon" or "NotYetValid" or "Drift" or "Missing" or "Unreadable" or "Pending" or "Unknown" || item.Evidence is "Stale" or "Changed" or "Failed" or "Unverified";
    public static string EvidenceLabel(string evidence) => evidence switch
    {
        "Observed" => "最近远端只读核验（24 小时内）", "Stale" => "远端核验已超过 24 小时", "Changed" => "归档已变化，旧核验失效",
        "Failed" => "最近核验未完成", _ => "本地归档，尚无匹配远端核验"
    };
    private static DateTimeOffset? Date(string value)
    {
        // In-memory JsonValue<DateTimeOffset> formats as a JSON string including
        // quotes; persisted JSON values expose plain text. Accept both forms.
        if (value.StartsWith('"')) { try { value = JsonSerializer.Deserialize<string>(value) ?? ""; } catch (JsonException) { return null; } }
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) ? parsed.ToUniversalTime() : null;
    }
    public static string Expiry(string notBefore, string notAfter, DateTimeOffset now)
    {
        var end = Date(notAfter); var begin = Date(notBefore);
        if (end == null || notBefore != "" && begin == null || begin >= end) return "Unknown";
        if (end <= now) return "Expired";
        if (begin > now) return "NotYetValid";
        return end <= now.AddDays(14) ? "Expiring" : end <= now.AddDays(30) ? "DueSoon" : "Valid";
    }
    public static JsonObject CertificateRequest(JsonObject plan)
    {
        var items = new JsonArray();
        void Add(string key, params string[] names) => items.Add(new JsonObject { ["Key"] = key, ["ServerNames"] = new JsonArray(names.Where(s => s != "").Distinct(StringComparer.Ordinal).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()) });
        if (ComponentInstallations.ProtocolInstalled(plan, "AnyTlsEntry")) Add("anytls", plan.Text("AnyTls.ServerName"), plan.Text("AnyTls.EchPublicName"));
        if (ComponentInstallations.ProtocolInstalled(plan, "RealityEntry") && plan.Text("Reality.TargetMode") == "LocalOwnedTls") Add("reality", plan.Text("Reality.ServerName"));
        foreach (var inbound in InboundCatalog.Items(plan["InboundModel"] as JsonObject ?? InboundCatalog.Empty(), "Inbounds").Where(i => i.Text("CertificateId") != ""))
            Add("inbound:" + InboundCatalog.Id(inbound.Text("Id")), inbound.Text("Options.ServerName"));
        return new() { ["Version"] = 1, ["Items"] = items };
    }
    public static JsonObject ValidateCertificates(JsonObject request, JsonObject response, DateTimeOffset now)
    {
        if (response.Count != 3 || response.Number("Version") != 1 || response["Items"] is not JsonArray array || array.Count != (request["Items"] as JsonArray)!.Count || Date(response.Text("CollectedAt")) is not DateTimeOffset at || at > now.AddMinutes(5) || at < now.AddMinutes(-10)) throw new OperationException("证书只读核验结果不完整或时间不符。");
        var required = request["Items"]!.AsArray().Select(v => v!.Text("Key")).ToHashSet(StringComparer.Ordinal); var clean = new JsonArray();
        foreach (var entry in array)
        {
            if (entry is not JsonObject item || !required.Remove(item.Text("Key")) || item.Text("Status") is not ("Observed" or "Missing" or "Unreadable")) throw new OperationException("证书核验身份、数量或状态不符。");
            if (item.Text("Status") != "Observed") { if (item.Count != 2) throw new OperationException("证书核验包含非公开字段。"); }
            else if (item.Count != 6 || !Regex.IsMatch(item.Text("Sha256"), "^[a-f0-9]{64}$") || Date(item.Text("NotBefore")) == null || Date(item.Text("NotAfter")) == null || item["HostnameMatches"] is not JsonValue flag || !flag.TryGetValue<bool>(out _)) throw new OperationException("证书元数据缺失或含未知字段。");
            clean.Add(item.DeepClone());
        }
        return new() { ["Version"] = 1, ["CollectedAt"] = at.ToString("O"), ["Items"] = clean };
    }
    public static string ObservationIdentity(JsonObject plan, JsonObject state) => ArchiveStore.Fingerprint(new JsonObject
    {
        ["Plan"] = plan.DeepClone(), ["ServerConfigHashes"] = state["ServerConfigHashes"]?.DeepClone(),
        ["InboundHash"] = state.At("Inbounds.RemoteHash")?.DeepClone(),
        ["TcpHash"] = state.At("TcpForwarding.RemoteHash")?.DeepClone(), ["UdpHash"] = state.At("UdpForwarding.RemoteHash")?.DeepClone(),
        ["Wg0Hash"] = state.At("WireGuardTunnel.RemoteHash")?.DeepClone(), ["Wg1Hash"] = state.At("WireGuardTunnel2.RemoteHash")?.DeepClone()
    });
    public static JsonObject Observation(JsonObject plan, JsonObject state, JsonObject audit, JsonObject? certificates, DateTimeOffset now) => new()
    {
        ["Version"] = 1, ["At"] = now.ToString("O"), ["Identity"] = ObservationIdentity(plan, state), ["Certificates"] = certificates?.DeepClone(),
        ["Services"] = audit["Services"]?.DeepClone(), ["Inbounds"] = audit["Inbounds"]?.DeepClone(), ["Timers"] = audit["Timers"]?.DeepClone(),
        ["TcpForwarding"] = audit["TcpForwarding"]?.DeepClone(), ["UdpForwarding"] = audit["UdpForwarding"]?.DeepClone(),
        ["WireGuardTunnel"] = audit["WireGuardTunnel"]?.DeepClone(), ["WireGuardTunnel2"] = audit["WireGuardTunnel2"]?.DeepClone()
    };

    public static OperationsResourceOverview Build(IEnumerable<ResourceInstance> instances, DateTimeOffset now,
        IEnumerable<JsonObject>? chains = null, IEnumerable<JsonObject>? tunnels = null, IEnumerable<JsonObject>? clients = null, IEnumerable<string>? issues = null)
    {
        var result = new List<OperationsResource>(); var notes = new List<string>(issues ?? []);
        foreach (var instance in instances) AddInstance(result, instance, now);
        AddConnections(result, chains ?? [], tunnels ?? [], clients ?? []);
        var duplicates = result.GroupBy(i => i.Key, StringComparer.Ordinal).Where(g => g.Count() > 1).ToArray();
        if (duplicates.Length > 0) throw new OperationException("运维资源存在重复身份，请核对归档。");
        var known = result.Select(r => r.Key).ToHashSet(StringComparer.Ordinal);
        foreach (var item in result.Where(i => i.References.Any(r => !known.Contains(r)))) notes.Add(item.Name + " 存在未读取或已移除的引用；变更影响可能不完整。");
        return new(result.OrderBy(i => NeedsAttention(i) ? 0 : 1).ThenBy(i => i.NotAfter ?? DateTimeOffset.MaxValue).ThenBy(i => i.Instance, StringComparer.Ordinal).ThenBy(i => i.Name, StringComparer.Ordinal).ToArray(), notes.Distinct(StringComparer.Ordinal).ToArray());
    }
    private static void AddInstance(List<OperationsResource> result, ResourceInstance instance, DateTimeOffset now)
    {
        var p = instance.Plan; var state = instance.State; var relative = instance.RelativePath; var snapshot = state["ResourceObservation"] as JsonObject;
        var observed = Date(snapshot.Text("At"));
        var evidence = snapshot?.Number("Version") != 1 || observed == null || observed > now.AddMinutes(5) ? "Archive"
            : snapshot.Text("Identity") != ObservationIdentity(p, state) ? "Changed" : observed < now.AddHours(-FreshHours) ? "Stale" : "Observed";
        if (state.Text("LastTask.Kind") == "HealthAudit" && state.Text("LastTask.Outcome") is "Failed" or "Cancelled" && Date(state.Text("LastTask.StartedAt")) is DateTimeOffset attempt && (observed == null || attempt >= observed)) evidence = "Failed";
        var maintenance = instance.CanMaintain;
        var certs = snapshot?.At("Certificates.Items") as JsonArray ?? [];
        JsonObject? Cert(string key) { var matches = certs.OfType<JsonObject>().Where(c => c.Text("Key") == key).ToArray(); return matches.Length == 1 ? matches[0] : null; }
        string K(string kind, string id) => Key(relative, kind, id);
        void Add(string kind, string id, string name, string status, string detail, string action, string target = "", IEnumerable<string>? uses = null, DateTimeOffset? end = null, string? proof = null)
        {
            var source = proof ?? evidence;
            result.Add(new(K(kind, id), relative, kind, name, status, source, source is "Archive" or "Unverified" ? null : observed, end, detail, maintenance ? action : "Instance", target, (uses ?? []).Distinct(StringComparer.Ordinal).ToArray()));
        }
        void Certificate(string id, string name, string expectedHash, string archivedEnd, IEnumerable<string> requestKeys, string action, string target)
        {
            var keys = requestKeys.ToArray(); var checks = keys.Select(Cert).ToArray();
            var current = evidence == "Observed" && checks.Length > 0 && checks.All(c => c != null);
            var known = checks.Length > 0 && checks.All(c => c?.Text("Status") == "Observed");
            var readable = current && known;
            var sample = known && evidence != "Changed" ? checks[0] : null;
            var end = sample?.Text("NotAfter") ?? archivedEnd;
            var status = Expiry(sample?.Text("NotBefore") ?? "", end, now);
            if (current && checks.Any(c => c!.Text("Status") == "Missing")) status = "Missing";
            else if (current && !readable) status = "Unreadable";
            else if (readable && (checks.Any(c => !c!.Flag("HostnameMatches") || c.Text("Sha256") != sample!.Text("Sha256")) || expectedHash != "" && sample!.Text("Sha256") != expectedHash)) status = "Drift";
            var proof = keys.Length == 0 ? "Archive" : evidence == "Observed" && !current ? "Failed" : evidence == "Archive" ? "Unverified" : evidence;
            Add("Certificate", id, name, status,
                "到期 " + (end == "" ? "未记录" : end) + (expectedHash == "" ? "" : "\n归档 SHA-256 " + expectedHash) +
                (sample == null ? "" : "\n远端 SHA-256 " + sample.Text("Sha256")) +
                (keys.Length == 0 ? "\n尚无引用；有效期来自导入归档。" : "\n核对使用者 " + keys.Length + " 项；停用入站仍计入。"), action, target, end: Date(end), proof: proof);
        }
        foreach (var role in DeploymentPlans.Roles[..3].Where(r => ComponentInstallations.ProtocolInstalled(p, r)))
        {
            var enabled = p.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.InitiallyEnabled(p, role));
            var service = snapshot?.At("Services." + role); var uses = new List<string> { K("Core", role) };
            if (role == "AnyTlsEntry") { Certificate("anytls", "AnyTLS / ECH 证书", "", "", ["anytls"], "CertificateFixed", role); uses.Add(K("Certificate", "anytls")); }
            if (role == "RealityEntry" && p.Text("Reality.TargetMode") == "LocalOwnedTls") { Certificate("reality", "Reality 本机 HTTPS 目标证书", "", "", ["reality"], "CertificateFixed", role); uses.Add(K("Certificate", "reality")); }
            if (p.At("ServerOutbound." + role) != null) uses.Add(K("ServerRoute", role));
            var drift = evidence == "Observed" && (service == null || !service.Flag("Installed") || service.Flag("Active") != enabled || service.Flag("Enabled") != enabled);
            Add("Protocol", role, ComponentInstallations.Label(role), drift ? "Drift" : enabled ? "Recorded" : "Disabled", "监听 " + string.Join(", ", ComponentInstallations.ListeningPorts(p, role)), "Protocol", role, uses);
            Add("Core", role, role == "RealityEntry" ? "Xray · 固定协议" : "sing-box · " + ComponentInstallations.Label(role), "Recorded", "归档版本 " + p.Text(role == "RealityEntry" ? "Reality.XrayVersion" : role == "AnyTlsEntry" ? "AnyTls.SingBoxVersion" : "Shadowsocks.SingBoxVersion", "未记录"), "Upgrade", role, proof: "Archive");
        }
        var model = p["InboundModel"] as JsonObject ?? InboundCatalog.Empty();
        foreach (var xray in InboundCatalog.Items(model, "Inbounds").Select(InboundCatalog.UsesXray).Distinct())
        {
            var core = xray ? state.At("Inbounds.Core.Reality") : state.At("Inbounds.Core");
            Add("Core", xray ? "independent-xray" : "independent-sing-box", xray ? "Xray · 独立入站" : "sing-box · 独立入站", "Recorded", "归档版本 " + core.Text("Version", "未记录") + "；更新会核对引用该核心的全部入站。", "InboundCore", xray ? "UpgradeXray" : "UpgradeSingBox", proof: "Archive");
        }
        foreach (var cert in InboundCatalog.Items(model, "Certificates")) Certificate(cert.Text("Id"), cert.Text("Name"), cert.Text("Sha256"), cert.Text("NotAfter"), InboundCatalog.Items(model, "Inbounds").Where(i => i.Text("CertificateId") == cert.Text("Id")).Select(i => "inbound:" + i.Text("Id")), "Certificates", cert.Text("Id"));
        foreach (var user in InboundCatalog.Items(model, "Users")) Add("User", user.Text("Id"), user.Text("Name"), "Recorded", "认证类型 " + user.Text("Kind") + "；凭据保留在加密归档。", "Users", user.Text("Id"), proof: "Archive");
        foreach (var outbound in InboundCatalog.Items(model, "Outbounds")) Add("Outbound", outbound.Text("Id"), outbound.Text("Name"), "Recorded", outbound.Text("Kind") + " · " + outbound.Text("Family"), "Outbounds", outbound.Text("Id"), outbound.Text("Kind") == "Proxy" ? [NodeKey(outbound.Text("Source.SchemeId"), outbound.Text("Source.NodeId"))] : [], proof: "Archive");
        foreach (var inbound in InboundCatalog.Items(model, "Inbounds"))
        {
            var uses = inbound.Strings("UserIds").Select(id => K("User", id)).Concat(InboundRoutingPolicy.References(inbound).Select(id => K("Outbound", id))).ToList();
            if (inbound.Text("CertificateId") != "") uses.Add(K("Certificate", inbound.Text("CertificateId")));
            uses.Add(K("Core", InboundCatalog.UsesXray(inbound) ? "independent-xray" : "independent-sing-box"));
            var drift = evidence == "Observed" && !snapshot.Flag("Inbounds.MatchesArchive");
            Add("Inbound", inbound.Text("Id"), inbound.Text("Name"), drift ? "Drift" : inbound.Flag("Enabled") ? "Recorded" : "Disabled", InboundCatalog.Label(inbound.Text("Protocol")) + " · " + inbound.Text("Listener.Address") + ":" + inbound.Number("Listener.Port"), "Inbounds", inbound.Text("Id"), uses);
        }
        foreach (var role in ServerOutboundRouting.Roles.Where(r => p.At("ServerOutbound." + r) is JsonObject))
        {
            var route = p["ServerOutbound"]![role]!; var refs = new List<string>();
            foreach (var hop in new[] { route }.Concat((route["AdditionalHops"] as JsonArray ?? []).OfType<JsonObject>()))
                if (hop.Text("SchemeId") != "") refs.Add(NodeKey(hop.Text("SchemeId"), hop.Text("NodeId")));
            Add("ServerRoute", role, ComponentInstallations.Label(role) + "分流", "Recorded", route.Text("Name") + "；包含分类例外与下一跳引用。", "ServerRoute", role, refs, proof: "Archive");
        }
        foreach (var (component, kind, action) in new[] { ("TcpForwarding", "TcpForward", "TcpForward"), ("UdpForwarding", "UdpForward", "UdpForward") })
            foreach (var rule in (p.At(component + ".Rules") as JsonArray ?? []).OfType<JsonObject>())
                Add(kind, rule.Text("Id"), rule.Text("Name"), evidence == "Observed" && !snapshot.Flag(component + ".MatchesArchive") ? "Drift" : rule.Flag("Enabled") ? "Recorded" : "Disabled", "监听 " + rule.Number("ListenPort") + " → " + rule.Text("TargetAddress") + ":" + rule.Number("TargetPort") + (rule.Text("ProxyProtocol") == "" ? "" : " · PROXY " + rule.Text("ProxyProtocol")), action, rule.Text("Id"), rule.Text("Validation.SchemeId") != "" ? [NodeKey(rule.Text("Validation.SchemeId"), rule.Text("Validation.NodeId"))] : []);
        foreach (var component in WireGuardTunnels.Components.Where(c => p[c] is JsonObject))
        {
            var peer = p[component]!;
            Add("WireGuard", component, "WireGuard · " + (component == "WireGuardTunnel" ? "maywg0" : "maywg1"), evidence == "Observed" && !snapshot.Flag(component + ".MatchesArchive") ? "Drift" : "Recorded", "通道 " + peer.Text("Id") + "；仅反映已保存的接口／路由检查，完整双向业务另行验收。", "WireGuard", peer.Text("Id"), [TunnelKey(peer.Text("Id"))]);
        }
        foreach (var role in MayMonitorLifecycle.Roles)
        {
            var section = MayMonitorLifecycle.Section(role); var known = state[section];
            if (!known.Flag("Installed") && p[section] == null) continue;
            Add("Monitor", section, MayMonitorLifecycle.Label(role), known.Flag("Installed") ? known.Flag("Enabled") ? "Recorded" : "Disabled" : "Unknown", "归档版本 " + known.Text("Version", "未记录") + "；从组件维护入口核对当前状态。", "MayMonitor", role, proof: "Archive");
            var authorization = known?.At("Configuration.ReadAuthorization");
            if (role == "Server" && authorization != null) Add("Authorization", section, "May Monitor 只读授权", Expiry("", authorization.Text("ExpiresAt"), now), "授权 " + authorization.Strings("Clients").Length + " 个节点；总览不展示 Token。", "MayMonitor", role, [K("Monitor", section)], Date(authorization.Text("ExpiresAt")), "Archive");
        }
        foreach (var target in MaintenanceTargets.Monitoring(p, state).Where(t => t.Installed || t.RequiresVerification)) Add("Monitor", target.Scope, target.Name, target.RequiresVerification ? "Unknown" : "Recorded", target.Status, "Monitoring", target.Scope, proof: "Archive");
        if (!instance.CanMaintain) Add("Recovery", "instance", "实例归档／待恢复范围", "Pending", "草稿或未确认事务不开放组件维护；先从实例页核对。", "Instance", proof: "Archive");
    }
}
