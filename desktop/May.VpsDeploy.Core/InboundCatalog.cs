using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed record InboundPreview(JsonObject Model, JsonObject Credentials, JsonObject Payload, string[] Affected, string ExpectedHash, string Summary);
public interface IInboundValidation
{
    Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject model, JsonObject credentials, string[] ids, string directory, IProgress<string> progress, CancellationToken cancellationToken);
}

// The catalogue owns references. Runtime files belong to inbound identities,
// credentials to user/certificate identities; names never determine file paths.
public static class InboundCatalog
{
    public const int MaximumInbounds = 16;
    public static string[] Protocols => ["Reality", "AnyTLS", "Shadowsocks2022", "Hysteria2", "TuicV5", "VLESS"];
    public static bool UsesXray(JsonObject inbound) => inbound.Text("Protocol") is "Reality" or "VLESS";
    public static bool UdpOnly(JsonObject inbound) => inbound.Text("Protocol") is "Hysteria2" or "TuicV5";
    public static bool UsesUdp(JsonObject inbound) => inbound.Text("Protocol") is "Shadowsocks2022" or "Hysteria2" or "TuicV5" || inbound.Text("Protocol")=="VLESS"&&inbound.Text("Options.Transport.HTTPVersion")=="3";
    public static string UserKind(JsonObject inbound) => inbound.Text("Protocol") switch { "Reality" or "VLESS" => "Uuid", "TuicV5" => "TuicV5", "AnyTLS" or "Hysteria2" => "Password", _ => inbound.Text("Options.Method") == "2022-blake3-aes-256-gcm" ? "SS256" : "SS128" };
    public static string Id(string value) => Regex.IsMatch(value, "^[a-f0-9]{32}$") ? value : throw new OperationException("入站资源身份无效。");
    public static IEnumerable<JsonObject> Items(JsonObject model, string group) => (model[group] as JsonArray)?.OfType<JsonObject>() ?? [];
    public static JsonObject Empty() => new() { ["Version"] = 1, ["Inbounds"] = new JsonArray(), ["Users"] = new JsonArray(), ["Certificates"] = new JsonArray(), ["Outbounds"] = new JsonArray() };
    public static JsonObject EmptyCredentials() => new() { ["Users"] = new JsonObject(), ["Certificates"] = new JsonObject(), ["Inbounds"] = new JsonObject() };
    public static string NewId() => Guid.NewGuid().ToString("N");
    public static void ServerName(string name) => DeploymentPlans.Domain(name);
    public static void ReplaceCertificate(JsonObject certificate, JsonObject credentials, string certificatePem, string keyPem)
    {
        try
        {
            using var cert = X509Certificate2.CreateFromPem(certificatePem, keyPem);
            certificate["Sha256"] = ArchiveStore.Digest(cert.RawData); certificate["NotAfter"] = new DateTimeOffset(cert.NotAfter.ToUniversalTime()).ToString("O");
            credentials["Certificates"]![certificate.Text("Id")] = new JsonObject { ["CertificatePem"] = certificatePem, ["PrivateKeyPem"] = keyPem };
        }
        catch (CryptographicException) { throw new OperationException("证书或私钥格式不正确，或二者不匹配。"); }
    }
    public static string Label(string protocol) => protocol switch { "Reality" => "VLESS / Reality", "VLESS" => "VLESS / XHTTP", "AnyTLS" => "AnyTLS", "Shadowsocks2022" => "Shadowsocks 2022", "Hysteria2" => "Hysteria2 / QUIC", "TuicV5" => "TUIC v5 / QUIC", _ => protocol };
    private static string HysteriaSummary(JsonObject inbound) => inbound.Text("Protocol") != "Hysteria2" ? "" : " · UDP/QUIC · " + (inbound.Number("Options.UploadMbps") == 0 ? "自适应 BBR" : "客户端上行 " + inbound.Number("Options.UploadMbps") + " Mbps / 下行 " + inbound.Number("Options.DownloadMbps") + " Mbps") + " · Salamander " + (inbound.Flag("Options.ObfsEnabled") ? "已启用" : "未启用") + " · SNI " + inbound.Text("Options.ServerName") + (inbound.Text("Options.HopPorts") == "" ? "" : " · 跳跃端口 " + inbound.Text("Options.HopPorts") + " / " + inbound.Number("Options.HopIntervalSeconds") + " 秒（主机受管 UDP 重定向；服务商须放行完整端口集）");
    private static void Fields(JsonObject value, params string[] fields)
    { if (value.Count != fields.Length || value.Any(p => !fields.Contains(p.Key))) throw new OperationException("入站模型包含未知或缺少的字段。"); }
    private static void Name(JsonObject value)
    { _ = Id(value.Text("Id")); var name = value.Text("Name"); if (name.Length is < 1 or > 60 || name.Any(char.IsControl)) throw new OperationException("资源名称须为 1–60 个可打印字符。"); }
    private static int Port(JsonObject value, string key)
    { if (value[key] is not JsonValue v || !v.TryGetValue<int>(out var n) || n is < 1 or > 65535) throw new OperationException("监听和目标端口须为 1–65535 的整数。"); return n; }
    private static bool Flag(JsonObject value, string key)
    { if (value[key] is not JsonValue v || !v.TryGetValue<bool>(out var b)) throw new OperationException("启用状态须为明确的布尔值。"); return b; }
    private static void Key(string text, int size, bool url = false)
    {
        try { var value = url ? text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4) : text; if (Convert.FromBase64String(value).Length == size) return; }
        catch (FormatException) { }
        throw new OperationException("密钥的格式或长度不正确。");
    }
    public static JsonObject Normalize(JsonObject source, JsonObject credentials)
    {
        var m = source.DeepClone().AsObject(); Fields(m, "Version", "Inbounds", "Users", "Certificates", "Outbounds");
        if (m["Version"] is not JsonValue version || !version.TryGetValue<int>(out var n) || n != 1) throw new OperationException("入站模型版本不受支持。");
        Fields(credentials, "Users", "Certificates", "Inbounds");
        if (new[] { "Users", "Certificates", "Inbounds" }.Any(g => credentials[g] is not JsonObject)) throw new OperationException("凭据资源结构无效。");
        foreach (var group in new[] { "Inbounds", "Users", "Certificates", "Outbounds" })
        {
            if (m[group] is not JsonArray array || array.Any(v => v is not JsonObject) || array.Count > (group == "Inbounds" ? MaximumInbounds : 64)) throw new OperationException("入站或关联资源数量超过限制。");
            foreach (var item in array.OfType<JsonObject>()) Name(item);
            if (array.Select(v => v!.Text("Id")).Distinct().Count() != array.Count) throw new OperationException("资源身份重复。");
        }
        foreach (var user in Items(m, "Users"))
        {
            Fields(user, "Id", "Name", "Kind"); var secret = credentials["Users"]?[user.Text("Id")] as JsonObject ?? throw new OperationException("用户凭据缺失。");
            if (user.Text("Kind") == "TuicV5") Fields(secret, "Value", "Uuid"); else Fields(secret, "Value"); var value = secret.Text("Value");
            switch (user.Text("Kind"))
            {
                case "Uuid": if (!Guid.TryParseExact(value, "D", out var id) || id == Guid.Empty) throw new OperationException("VLESS 用户 UUID 无效。"); break;
                case "Password": if (value.Length is < 16 or > 256 || value.Any(char.IsControl)) throw new OperationException("AnyTLS 密码须为 16–256 个可打印字符。"); break;
                case "TuicV5":
                    if (!Guid.TryParseExact(secret.Text("Uuid"), "D", out var tuicId) || tuicId == Guid.Empty || value.Length is < 16 or > 256 || value.Any(char.IsControl)) throw new OperationException("TUIC v5 用户须有有效 UUID 和 16–256 个可打印字符的密码。");
                    break;
                case "SS128": Key(value, 16); break;
                case "SS256": Key(value, 32); break;
                default: throw new OperationException("用户认证类型不受支持。");
            }
        }
        foreach (var certificate in Items(m, "Certificates"))
        {
            Fields(certificate, "Id", "Name", "Sha256", "NotAfter");
            var secret = credentials["Certificates"]?[certificate.Text("Id")] as JsonObject ?? throw new OperationException("证书材料缺失。"); Fields(secret, "CertificatePem", "PrivateKeyPem");
            try
            {
                using var cert = X509Certificate2.CreateFromPem(secret.Text("CertificatePem"), secret.Text("PrivateKeyPem"));
                if (!cert.HasPrivateKey || ArchiveStore.Digest(cert.RawData) != certificate.Text("Sha256") || new DateTimeOffset(cert.NotAfter.ToUniversalTime()).ToString("O") != certificate.Text("NotAfter")) throw new OperationException("证书身份与私钥材料不匹配，请重新导入。");
            }
            catch (CryptographicException) { throw new OperationException("证书或私钥无法读取，或者二者不匹配。"); }
        }
        foreach (var outbound in Items(m, "Outbounds"))
        {
            Fields(outbound, "Id", "Name", "Kind", "Family", "ExpectedAddress", "Source");
            if (outbound.Text("Kind") is not ("Direct" or "Proxy") || outbound.Text("Family") is not ("IPv4" or "IPv6" or "Auto")) throw new OperationException("出站类型或出口地址族无效。");
            if (outbound.Text("ExpectedAddress") != "" && (!IPAddress.TryParse(outbound.Text("ExpectedAddress"), out var address) || IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || outbound.Text("Family") == "IPv4" && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || outbound.Text("Family") == "IPv6" && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)) throw new OperationException("预期出口地址与地址族不符。");
            var reference = outbound["Source"] as JsonObject ?? throw new OperationException("出站来源无效。");
            if (outbound.Text("Kind") == "Direct") Fields(reference);
            else { Fields(reference, "SchemeId", "NodeId", "Fingerprint"); _ = Id(reference.Text("SchemeId")); _ = Id(reference.Text("NodeId")); if (!Regex.IsMatch(reference.Text("Fingerprint"), "^[a-f0-9]{64}$")) throw new OperationException("出站来源摘要无效。"); }
        }
        var ports = new HashSet<int>();
        foreach (var inbound in Items(m, "Inbounds"))
        {
            Fields(inbound, "Id", "Name", "Protocol", "Enabled", "Listener", "UserIds", "CertificateId", "OutboundId", "Options");
            _ = Flag(inbound, "Enabled"); if (!Protocols.Contains(inbound.Text("Protocol"))) throw new OperationException("入站协议不受支持。");
            var listener = inbound["Listener"] as JsonObject ?? throw new OperationException("入站监听缺失。"); Fields(listener, "Address", "Port"); var port = Port(listener, "Port");
            if (!ports.Add(port)) throw new OperationException("不同入站的监听端口不能重复；停用的入站仍保留端口。");
            if (!IPAddress.TryParse(listener.Text("Address"), out var ip) || IPAddress.IsLoopback(ip) || ip.IsIPv4MappedToIPv6 || ip.ScopeIdIfV6() != 0 || ip.GetAddressBytes()[0] >= 224 && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork || ip.IsIPv6Multicast) throw new OperationException("监听地址须为可从控制端验收的 IPv4/IPv6 地址或通配地址，不能使用回环地址。");
            listener["Address"] = ip.ToString();
            if (inbound["UserIds"] is not JsonArray users || users.Count is < 1 or > 32 || users.Any(v => v is not JsonValue j || !j.TryGetValue<string>(out _)) || users.Select(v => v!.ToString()).Distinct().Count() != users.Count) throw new OperationException("入站须引用 1–32 个不重复的用户身份。");
            var options = inbound["Options"] as JsonObject ?? throw new OperationException("协议参数缺失。");
            var kind = UserKind(inbound);
            foreach (var userId in inbound.Strings("UserIds"))
                if (Items(m, "Users").SingleOrDefault(u => u.Text("Id") == userId)?.Text("Kind") != kind) throw new OperationException("引用的用户不存在或认证类型与协议不匹配。");
            if (!Items(m, "Outbounds").Any(o => o.Text("Id") == inbound.Text("OutboundId"))) throw new OperationException("入站引用的出站不存在。");
            if (inbound.Text("Protocol") is "AnyTLS" or "Hysteria2" or "TuicV5" or "VLESS")
            {
                if (inbound.Text("Protocol") == "AnyTLS") { Fields(options, "ServerName", "EchEnabled"); _ = Flag(options, "EchEnabled"); }
                else if (inbound.Text("Protocol") == "VLESS")
                {
                    VlessXhttp.Validate(options, credentials["Inbounds"]![inbound.Text("Id")]!);
                    if (Items(m, "Outbounds").Single(o => o.Text("Id") == inbound.Text("OutboundId")).Text("Kind") != "Direct") throw new OperationException("本轮 XHTTP 仅验收直连出站，不叠加服务器下一跳。");
                }
                else if (inbound.Text("Protocol") == "TuicV5")
                {
                    TuicV5.Validate(options);
                    var identities = inbound.Strings("UserIds").Select(id => Guid.Parse(credentials.Text("Users." + id + ".Uuid"))).ToArray();
                    if (identities.Distinct().Count() != identities.Length) throw new OperationException("同一 TUIC 入站不能绑定重复的用户 UUID。");
                }
                else
                {
                    if (options.ContainsKey("HopPorts") || options.ContainsKey("HopIntervalSeconds"))
                    {
                        Fields(options, "ServerName", "UploadMbps", "DownloadMbps", "ObfsEnabled", "HopPorts", "HopIntervalSeconds");
                        if (options["HopPorts"] is not JsonValue hopValue || !hopValue.TryGetValue<string>(out var hopText)) throw new OperationException("跳跃端口须为文本格式。");
                        var hops = Hysteria2Ports.Expand(hopText);
                        if (hops.Length < 2 || !hops.Contains(port)) throw new OperationException("跳跃端口至少包含两个端口，并须包含当前监听端口。");
                        foreach (var hop in hops.Where(p => p != port)) if (!ports.Add(hop)) throw new OperationException("跳跃端口与其他独立入站端口冲突；停用入站仍保留端口。");
                        options["HopPorts"] = Hysteria2Ports.Normalize(hopText); _ = Hysteria2Ports.Interval(options);
                    }
                    else Fields(options, "ServerName", "UploadMbps", "DownloadMbps", "ObfsEnabled");
                    _ = Flag(options, "ObfsEnabled");
                    foreach (var field in new[] { "UploadMbps", "DownloadMbps" }) if (options[field] is not JsonValue bandwidth || !bandwidth.TryGetValue<int>(out var rate) || rate is < 0 or > 100000) throw new OperationException("Hysteria2 带宽须为 0–100000 Mbps 的整数；两项为 0 时使用自适应拥塞控制。");
                    if ((options.Number("UploadMbps") == 0) != (options.Number("DownloadMbps") == 0)) throw new OperationException("自适应模式请将上、下行同时设为 0；固定带宽请同时填写正数。");
                    var obfs = credentials.Text("Inbounds." + inbound.Text("Id") + ".ObfsPassword");
                    if (options.Flag("ObfsEnabled") && (obfs.Length is < 16 or > 256 || obfs.Any(char.IsControl))) throw new OperationException("Salamander 密码须为 16–256 个可打印字符。");
                }
                DeploymentPlans.Domain(options.Text("ServerName"));
                if (inbound.Text("Protocol") == "VLESS" && options.Text("Security") == "Reality") { if (inbound.Text("CertificateId") != "") throw new OperationException("Reality XHTTP 不使用证书引用，请清空后审阅。"); continue; }
                var cert = Items(m, "Certificates").SingleOrDefault(c => c.Text("Id") == inbound.Text("CertificateId")) ?? throw new OperationException("TLS 入站须引用独立证书。");
                var material = credentials["Certificates"]![cert.Text("Id")]!;
                using var x509 = X509Certificate2.CreateFromPem(material.Text("CertificatePem"));
                if (!x509.MatchesHostname(options.Text("ServerName")) || inbound.Flag("Enabled") && (x509.NotBefore.ToUniversalTime() > DateTime.UtcNow || x509.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddHours(1))) throw new OperationException("证书尚未生效、即将过期或不能覆盖所填 SNI。");
                if (options.Flag("EchEnabled") && (credentials.Text("Inbounds." + inbound.Text("Id") + ".EchKey") == "" || credentials.Text("Inbounds." + inbound.Text("Id") + ".EchConfig") == "")) throw new OperationException("启用 ECH 时须同时提供服务端密钥和客户端配置。");
            }
            else
            {
                if (inbound.Text("CertificateId") != "") throw new OperationException("该协议不使用证书引用。");
                if (inbound.Text("Protocol") == "Reality")
                {
                    Fields(options, "ServerName", "HandshakeServer", "HandshakePort", "PublicKey", "ShortId"); DeploymentPlans.Domain(options.Text("ServerName")); DeploymentPlans.Domain(options.Text("HandshakeServer")); _ = Port(options, "HandshakePort"); Key(options.Text("PublicKey"), 32, true); Key(credentials.Text("Inbounds." + inbound.Text("Id") + ".RealityPrivateKey"), 32, true);
                    if (!Regex.IsMatch(options.Text("ShortId"), "^(?:[a-f0-9]{2}){1,8}$")) throw new OperationException("Reality short ID 无效。");
                }
                else { Fields(options, "Method"); if (options.Text("Method") is not ("2022-blake3-aes-128-gcm" or "2022-blake3-aes-256-gcm")) throw new OperationException("本轮 Shadowsocks 多用户仅支持 AES-128/256 的 2022 方法。"); Key(credentials.Text("Inbounds." + inbound.Text("Id") + ".ServerKey"), kind == "SS128" ? 16 : 32); }
            }
        }
        // Extra secrets are not silently retained after deleting their entities.
        foreach (var group in new[] { "Users", "Certificates", "Inbounds" })
            if (credentials[group] is not JsonObject secretGroup || secretGroup.Any(p => !Items(m, group).Any(e => e.Text("Id") == p.Key))) throw new OperationException("凭据含有不属于当前资源模型的身份，请明确删除或恢复引用。");
        return m;
    }
    private static long ScopeIdIfV6(this IPAddress address) => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? address.ScopeId : 0;
    public static JsonObject AddUser(JsonObject model, JsonObject credentials, string name, string kind)
    {
        var user = new JsonObject { ["Id"] = NewId(), ["Name"] = name, ["Kind"] = kind }; model["Users"]!.AsArray().Add(user);
        credentials["Users"]![user.Text("Id")] = new JsonObject { ["Value"] = kind == "Uuid" ? Guid.NewGuid().ToString() : ServerConfigurations.RandomKey(kind == "SS128" ? 16 : 32) };
        if (kind == "TuicV5") credentials["Users"]![user.Text("Id")]!["Uuid"] = Guid.NewGuid().ToString(); return user;
    }
    public static JsonObject ImportCertificate(JsonObject model, JsonObject credentials, string name, string certificatePem, string keyPem)
    {
        try
        {
            using var cert = X509Certificate2.CreateFromPem(certificatePem, keyPem);
            var item = new JsonObject { ["Id"] = NewId(), ["Name"] = name, ["Sha256"] = ArchiveStore.Digest(cert.RawData), ["NotAfter"] = new DateTimeOffset(cert.NotAfter.ToUniversalTime()).ToString("O") };
            model["Certificates"]!.AsArray().Add(item); credentials["Certificates"]![item.Text("Id")] = new JsonObject { ["CertificatePem"] = certificatePem, ["PrivateKeyPem"] = keyPem }; return item;
        }
        catch (CryptographicException) { throw new OperationException("证书或私钥格式不正确，或二者不匹配。"); }
    }
    public static JsonObject AddDirect(JsonObject model, string name, string family = "IPv4")
    { var outbound = new JsonObject { ["Id"] = NewId(), ["Name"] = name, ["Kind"] = "Direct", ["Family"] = family, ["ExpectedAddress"] = "", ["Source"] = new JsonObject() }; model["Outbounds"]!.AsArray().Add(outbound); return outbound; }
    public static JsonObject AddInbound(JsonObject model, JsonObject credentials, string protocol)
    {
        if (!Protocols.Contains(protocol)) throw new OperationException("请选择支持的协议。");
        var id = NewId(); var user = AddUser(model, credentials, "用户 " + (Items(model, "Users").Count() + 1), protocol is "Reality" or "VLESS" ? "Uuid" : protocol == "TuicV5" ? "TuicV5" : protocol is "AnyTLS" or "Hysteria2" ? "Password" : "SS128");
        var outbound = Items(model, "Outbounds").FirstOrDefault() ?? AddDirect(model, "默认直连");
        var used = Items(model, "Inbounds").SelectMany(Hysteria2Ports.ListenerPorts).ToHashSet(); var port = 22000; while (used.Contains(port)) port++;
        var inbound = new JsonObject { ["Id"] = id, ["Name"] = Label(protocol) + " " + (Items(model, "Inbounds").Count() + 1), ["Protocol"] = protocol, ["Enabled"] = true,
            ["Listener"] = new JsonObject { ["Address"] = "0.0.0.0", ["Port"] = port }, ["UserIds"] = new JsonArray(user.Text("Id")), ["CertificateId"] = "", ["OutboundId"] = outbound.Text("Id"),
            ["Options"] = protocol == "VLESS" ? VlessXhttp.Options() : protocol == "Reality" ? new JsonObject { ["ServerName"] = "", ["HandshakeServer"] = "", ["HandshakePort"] = 443, ["PublicKey"] = "", ["ShortId"] = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)) } : protocol == "AnyTLS" ? new JsonObject { ["ServerName"] = "", ["EchEnabled"] = false } : protocol == "TuicV5" ? TuicV5.Options() : protocol == "Hysteria2" ? new JsonObject { ["ServerName"] = "", ["UploadMbps"] = 0, ["DownloadMbps"] = 0, ["ObfsEnabled"] = false } : new JsonObject { ["Method"] = "2022-blake3-aes-128-gcm" } };
        credentials["Inbounds"]![id] = protocol == "Shadowsocks2022" ? new JsonObject { ["ServerKey"] = ServerConfigurations.RandomKey(16) } : protocol == "Hysteria2" ? new JsonObject { ["ObfsPassword"] = ServerConfigurations.RandomKey(32) } : new JsonObject(); model["Inbounds"]!.AsArray().Add(inbound); return inbound;
    }
    public static void RemoveEntity(JsonObject model, JsonObject credentials, string group, string id)
    {
        _ = Id(id); if (group is not ("Inbounds" or "Users" or "Certificates" or "Outbounds")) throw new OperationException("资源类别不受支持。");
        if (group != "Inbounds" && Items(model, "Inbounds").Any(i => group == "Users" ? i.Strings("UserIds").Contains(id) : i.Text(group == "Certificates" ? "CertificateId" : "OutboundId") == id)) throw new OperationException("该资源仍被入站引用，请先解绑或替换，不能级联删除。");
        var item = Items(model, group).SingleOrDefault(e => e.Text("Id") == id) ?? throw new OperationException("资源已不存在。"); model[group]!.AsArray().Remove(item); if (group != "Outbounds") credentials[group]!.AsObject().Remove(id);
    }
    public static void ValidateOptions(JsonObject options)
    {
        Fields(options, "Action", "Model", "Credentials", "ExpectedHash");
        if (options.Text("Action") is not ("Apply" or "Check" or "UpgradeSingBox" or "UpgradeXray") || options.Text("ExpectedHash") != "Absent" && !Regex.IsMatch(options.Text("ExpectedHash"), "^[a-f0-9]{64}$") || options["Model"] is not JsonObject || options["Credentials"] is not JsonObject) throw new OperationException("通用入站任务无效。");
        _ = Normalize(options["Model"]!.AsObject(), options["Credentials"]!.AsObject());
    }
    public static JsonObject Options(JsonObject state, string action, JsonObject model, JsonObject credentials) => new() { ["Action"] = action, ["Model"] = model.DeepClone(), ["Credentials"] = credentials.DeepClone(), ["ExpectedHash"] = state.Text("Inbounds.RemoteHash", "Absent") };
    public static InboundPreview Prepare(ArchiveStore store, OperationRequest request)
    {
        ValidateOptions(request.Options); var directory = store.Paths.Instance(request.InstanceRelativePath); var plan = TcpChains.Plan(store, request.InstanceRelativePath); var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
        var status = InstanceLifecycle.Read(store, request.InstanceRelativePath, plan); if (!status.Managed || status.NeedsRecovery) throw new OperationException("请先完成此实例的部署、接入或恢复事务。");
        var expected = state.Text("Inbounds.RemoteHash", "Absent"); if (expected != request.Options.Text("ExpectedHash") || expected == "Absent" && plan["InboundModel"] != null) throw new OperationException("入站归档摘要已变化或不完整，请重新读取审阅。");
        var model = Normalize(request.Options["Model"]!.AsObject(), request.Options["Credentials"]!.AsObject()); var credentials = request.Options["Credentials"]!.DeepClone().AsObject();
        var oldCredentials = store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"));
        try
        {
            var old = (plan["InboundModel"] ?? Empty()).AsObject();
            if (request.Options.Text("Action") != "Apply" && (!JsonNode.DeepEquals(model, old) || !JsonNode.DeepEquals(credentials, oldCredentials["Inbounds"] ?? EmptyCredentials()))) throw new OperationException("检查或核心更新只能使用已保存的模型与凭据。");
            foreach (var item in Items(model, "Inbounds"))
            {
                var previous = Items(old, "Inbounds").SingleOrDefault(i => i.Text("Id") == item.Text("Id"));
                if (previous != null && previous.Text("Protocol") != item.Text("Protocol")) throw new OperationException("入站身份不能原地改成另一种协议，请新建身份后再移除旧入站。");
            }
            var core = state["Inbounds"]?["Core"] as JsonObject;
            if(request.Options.Text("Action")=="UpgradeSingBox")
            {
                if(core==null||!Items(old,"Inbounds").Any(i=>!UsesXray(i)))throw new OperationException("此实例没有已应用的 sing-box 独立入站。");
                var current=InboundRendering.Core(store.Paths);if(core.Text("Sha256")==current.Text("Sha256")&&core.Text("Version")==current.Text("Version"))throw new OperationException("独立入站已经使用当前包内固定核心。");
                if(!Version.TryParse(core.Text("Version"),out var previousVersion)||!Version.TryParse(current.Text("Version"),out var nextVersion)||nextVersion<=previousVersion)throw new OperationException("核心更新只接受更高的固定版本，不覆盖同版本差异或降级。");
                current["Reality"]=core["Reality"]?.DeepClone();core=current;
            }
            if (request.Options.Text("Action") == "UpgradeXray")
            {
                if (core?["Reality"] is not JsonObject previousCore || !Items(old, "Inbounds").Any(UsesXray)) throw new OperationException("此实例没有已应用的 Xray 独立入站。");
                var nextCore = InboundRendering.Core(store.Paths)["Reality"]!.DeepClone().AsObject();
                if (previousCore.Text("Sha256") == nextCore.Text("Sha256") && previousCore.Text("Version") == nextCore.Text("Version")) throw new OperationException("独立 Xray 入站已使用包内固定核心。");
                if (!Version.TryParse(previousCore.Text("Version"), out var oldVersion) || !Version.TryParse(nextCore.Text("Version"), out var newVersion) || newVersion <= oldVersion) throw new OperationException("Xray 核心更新只接受更高的固定版本。");
                core = core.DeepClone().AsObject(); core["Reality"] = nextCore;
            }
            var payload = InboundRendering.Payload(store, plan, model, credentials, core);
            // Use the committed hashes rather than rendering obsolete credentials or
            // resolving a removed upstream. The remote preflight verifies these files.
            var oldBindings = state.At("Inbounds.Bindings") as JsonArray ?? new JsonArray();
            if (expected != "Absent" && (state.Text("Inbounds.ModelFingerprint") != ArchiveStore.Fingerprint(old) || oldBindings.Count != Items(old, "Inbounds").Count() || !oldBindings.OfType<JsonObject>().Select(b => b.Text("Id")).Order().SequenceEqual(Items(old, "Inbounds").Select(i => i.Text("Id")).Order()))) throw new OperationException("已保存的入站资源身份或摘要不完整，请先核对归档。");
            var affected = Items(payload, "Bindings").Select(b => b.Text("Id")).Concat(oldBindings.OfType<JsonObject>().Select(b => b.Text("Id"))).Distinct().Where(id =>
            {
                var before = oldBindings.OfType<JsonObject>().SingleOrDefault(b => b.Text("Id") == id); var after = Items(payload, "Bindings").SingleOrDefault(b => b.Text("Id") == id);
                return !JsonNode.DeepEquals(before, after) || after != null && state.At("Inbounds.Runtime") is JsonObject runtime && runtime[id] is JsonObject actual && (actual.Flag("Enabled") != after.Flag("Enabled") || actual.Flag("Active") != after.Flag("Enabled"));
            }).Order(StringComparer.Ordinal).ToArray();
            InboundRendering.ValidatePorts(plan, state, model);
            if (plan.Text("Firewall.Mode") == "PreserveExisting" && Items(model, "Inbounds").Any(i => i.Text("Options.HopPorts") != "")) throw new OperationException("端口跳跃需要本应用受管的 nftables 防火墙；保留现有防火墙模式不会自动写入重定向规则。");
            var summary = "通用入站 · " + (request.Options.Text("Action") == "Check" ? "只读检查" : "保存资源模型") + "\n" + string.Join("\n", Items(model, "Inbounds").Select(i => i.Text("Name") + " · " + Label(i.Text("Protocol")) + HysteriaSummary(i) + TuicV5.Summary(i) + VlessXhttp.Summary(i) + " · " + i.Text("Listener.Address") + ":" + i.Number("Listener.Port") + " · " + (i.Flag("Enabled") ? "启用" : "停用") + "\n用户：" + string.Join("，", i.Strings("UserIds").Select(id => Items(model, "Users").Single(u => u.Text("Id") == id).Text("Name"))) + "；证书：" + (Items(model, "Certificates").SingleOrDefault(c => c.Text("Id") == i.Text("CertificateId"))?.Text("Name") ?? "无") + "；出站：" + Items(model, "Outbounds").Single(o => o.Text("Id") == i.Text("OutboundId")).Text("Name")));
            summary += "\n\n本次影响：" + (affected.Length == 0 ? "仅目录信息，运行配置不变" : string.Join("，", affected.Select(id => Items(model, "Inbounds").Concat(Items(old, "Inbounds")).First(i => i.Text("Id") == id).Text("Name")))) + "。共享用户、证书或出站变化时，引用它们的入站会一并纳入范围。\n每个入站独立服务与配置；仅重启受影响入站，失败按同一范围恢复。原有固定角色服务保留。新入站监听对可达来源开放，访问由原协议用户鉴权控制；须确认服务商防火墙与监听范围。";
            if(request.Options.Text("Action")=="UpgradeSingBox")summary="更新独立入站固定 sing-box 核心："+state.Text("Inbounds.Core.Version")+" → "+core!.Text("Version")+"\n涉及共享核心的 Hysteria2、TUIC v5、AnyTLS、SS2022；Xray 固定版本保留。\n"+summary;
            if (request.Options.Text("Action") == "UpgradeXray") summary = "更新独立入站固定 Xray 核心：" + state.Text("Inbounds.Core.Reality.Version") + " → " + core!.Text("Reality.Version") + "\n重新验收所有受影响 Reality / XHTTP 入站，sing-box 核心保持原版本。\n" + summary;
            return new(model, credentials, payload, affected, expected, summary);
        }
        finally { oldCredentials.Clear(); }
    }
}
