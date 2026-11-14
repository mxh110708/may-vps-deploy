using System.Net.Mail;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static class ManagedCertificates
{
    public static string Directory(string id) => "/etc/may-certificates/" + InboundCatalog.Id(id);
    public static string Credential(string inbound, string leaf) => "/run/credentials/" + InboundRendering.Unit(inbound) + "/" + leaf;
    public static bool Managed(JsonObject certificate) => certificate["Managed"] is JsonObject;
    public static JsonObject Policy(string zone, string email, IEnumerable<string> domains, int propagation = 30)
    {
        var value = new JsonObject { ["Provider"] = "Cloudflare", ["Zone"] = zone.Trim().ToLowerInvariant(), ["Email"] = email.Trim(),
            ["Domains"] = new JsonArray(domains.Select(d => (JsonNode?)JsonValue.Create(d.Trim().ToLowerInvariant())).ToArray()), ["PropagationSeconds"] = propagation };
        ValidatePolicy(value); return value;
    }
    public static void ValidatePolicy(JsonObject value)
    {
        if (value.Count != 5 || value.Text("Provider") != "Cloudflare" || !MailAddress.TryCreate(value.Text("Email"), out var mail) || mail.Address != value.Text("Email") || value.Text("Email").Length > 254 || value.Text("Email").Any(char.IsControl)) throw new OperationException("请选择 Cloudflare 并填写有效的联系邮箱。");
        Domain(value.Text("Zone"));
        if (value["Domains"] is not JsonArray array || array.Count is < 1 or > 8 || array.Any(v => v is not JsonValue s || !s.TryGetValue<string>(out _))) throw new OperationException("证书须包含 1–8 个同一区域的域名。");
        var names = value.Strings("Domains");
        if (names.Distinct().Count() != names.Length || value["PropagationSeconds"] is not JsonValue p || !p.TryGetValue<int>(out var seconds) || seconds is < 10 or > 300) throw new OperationException("域名不可重复；DNS 等待时间须为 10–300 秒。");
        foreach (var name in names) { var host = name.StartsWith("*.", StringComparison.Ordinal) ? name[2..] : name; Domain(host); if (host != value.Text("Zone") && !host.EndsWith("." + value.Text("Zone"), StringComparison.Ordinal)) throw new OperationException("全部证书域名须属于所填 Cloudflare 区域。"); }
    }
    private static void Domain(string value)
    {
        if (value.Length is < 3 or > 253 || !value.Contains('.') || !Regex.IsMatch(value, @"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z")) throw new OperationException("域名须为规范的小写 DNS 名称，国际域名请使用 ASCII 编码。");
    }
    public static void Validate(OperationRequest request)
    {
        var o = request.Options;
        if (o.Count != 7 || o.Any(p => !new[] { "Action", "CertificateId", "Name", "Policy", "TokenFile", "ExpectedHash", "ExpectedCertificateHash" }.Contains(p.Key)) || o.Text("Action") is not ("Issue" or "Renew" or "Check" or "Disable" or "Enable" or "RotateToken" or "Remove")) throw new OperationException("证书自动化任务无效。");
        _ = InboundCatalog.Id(o.Text("CertificateId"));
        if (o.Text("Name").Length is < 1 or > 60 || o.Text("Name").Any(char.IsControl) || o["Policy"] is not JsonObject policy) throw new OperationException("证书名称或申请参数无效。");
        ValidatePolicy(policy);
        foreach (var field in new[] { "ExpectedHash", "ExpectedCertificateHash" }) if (o.Text(field) != "Absent" && !Regex.IsMatch(o.Text(field), "\\A[a-f0-9]{64}\\z")) throw new OperationException("证书或入站摘要无效，请重新核对。");
        if (o.Text("Action") is "Issue" or "RotateToken") _ = ReadToken(o.Text("TokenFile"));
        else if (o.Text("TokenFile") != "") throw new OperationException("此操作不接受新 Token。");
    }
    public static string ReadToken(string file)
    {
        try { var token = CloudflareCredentials.ReadToken(file); if (token.Length < 20) throw new OperationException("Cloudflare Token 长度不符合要求。"); return token; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { throw new OperationException("无法读取 Cloudflare Token 私密文件，请核对文件路径与访问权限。"); }
    }
    public static JsonObject Options(JsonObject state, string action, string id, string name, JsonObject policy, string tokenFile = "") => new()
    {
        ["Action"] = action, ["CertificateId"] = id, ["Name"] = name, ["Policy"] = policy.DeepClone(), ["TokenFile"] = tokenFile,
        ["ExpectedHash"] = state.Text("Inbounds.RemoteHash", "Absent"), ["ExpectedCertificateHash"] = state.Text("Certificates." + id + ".RemoteHash", "Absent")
    };
    public static string Prepare(ArchiveStore store, OperationRequest request)
    {
        Validate(request); var plan = TcpChains.Plan(store, request.InstanceRelativePath); var state = ArchiveStore.ReadJson(SafePath.Resolve(store.Paths.Instance(request.InstanceRelativePath), "deployment-state.json"));
        var status = InstanceLifecycle.Read(store, request.InstanceRelativePath, plan);
        if (!status.Managed || status.NeedsRecovery) throw new OperationException("请先完成实例接入或恢复。");
        var o = request.Options; var id = o.Text("CertificateId"); var model = plan["InboundModel"] as JsonObject ?? InboundCatalog.Empty();
        var cert = InboundCatalog.Items(model, "Certificates").SingleOrDefault(c => c.Text("Id") == id);
        if (o.Text("ExpectedHash") != state.Text("Inbounds.RemoteHash", "Absent") || o.Text("ExpectedCertificateHash") != state.Text("Certificates." + id + ".RemoteHash", "Absent")) throw new OperationException("证书归档已变化，请重新审阅。");
        if (o.Text("Action") == "Issue" ? cert != null || o.Text("ExpectedCertificateHash") != "Absent" : cert == null || !Managed(cert) || !JsonNode.DeepEquals(cert["Managed"], o["Policy"]) || cert.Text("Name") != o.Text("Name")) throw new OperationException("证书身份或申请策略与归档不符。");
        var users = InboundCatalog.Items(model, "Inbounds").Where(i => i.Text("CertificateId") == id).ToArray();
        if (o.Text("Action") == "Remove" && users.Length > 0) throw new OperationException("证书仍被入站引用，包含停用入站；请先解绑。");
        var label = o.Text("Action") switch { "Issue" => "申请并启用续期", "Renew" => "到期续期与部署", "Check" => "检查", "Enable" => "启用续期", "Disable" => "停用续期", "RotateToken" => "替换授权", _ => "移除无引用证书" };
        return "Cloudflare 托管证书 · " + label + "\n证书：" + o.Text("Name") + "\n域名：" + string.Join("，", o["Policy"]!.Strings("Domains")) + "\n引用入站：" + (users.Length == 0 ? "无" : string.Join("，", users.Select(i => i.Text("Name")))) + "\nDNS-01 仅创建与清理验证 TXT；使用既有 Debian Certbot 插件。独立定时器在 VPS 运行，30天内到期时申请并验证新证书，只重启当前启用的引用入站。失败恢复原证书和本次服务；停用入站保持停用。停用续期保留现有证书，移除仅限无引用资源。申请行为不能撤回 CA 已签发记录。";
    }
    public static void RequireCertificate(JsonObject material, JsonObject policy)
    {
        if (material.Count != 2 || material.Any(p => p.Key is not ("CertificatePem" or "PrivateKeyPem")) || material.Text("CertificatePem").Length is < 1 or > 262144 || material.Text("PrivateKeyPem").Length is < 1 or > 262144) throw new OperationException("证书材料结构或大小无效。");
        try
        {
            using var cert = X509Certificate2.CreateFromPem(material.Text("CertificatePem"), material.Text("PrivateKeyPem"));
            if (!cert.HasPrivateKey || cert.NotBefore.ToUniversalTime() > DateTime.UtcNow.AddMinutes(5) || cert.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddDays(2)) throw new OperationException("新证书有效期或私钥不符合要求。");
            foreach (var domain in policy.Strings("Domains").Where(d => !d.StartsWith("*.", StringComparison.Ordinal))) if (!cert.MatchesHostname(domain, allowWildcards: true, allowCommonName: false)) throw new OperationException("签发证书未覆盖所需域名。");
        }
        catch (System.Security.Cryptography.CryptographicException) { throw new OperationException("远端证书材料无效或私钥不匹配。"); }
    }
    public static void RequireObservation(JsonObject value, JsonObject policy)
    {
        if (value.Text("Hash") == "Absent") { if (value.Count != 2 || value["State"] != null) throw new OperationException("证书空状态无效。"); return; }
        if (value.Count != 3 || !Regex.IsMatch(value.Text("Hash"), "\\A[a-f0-9]{64}\\z") || !JsonNode.DeepEquals(value["Policy"], policy) || value["State"] is not JsonObject state || state.Count != 7 || state.Any(p => !new[] { "Enabled", "Sha256", "NotAfter", "LastSuccess", "LastAttempt", "ErrorCode", "ProgramSha256" }.Contains(p.Key)) || state["Enabled"] is not JsonValue flag || !flag.TryGetValue<bool>(out _) || state.Text("ErrorCode") is not ("" or "RenewalFailed" or "PendingRenewalRecovery")) throw new OperationException("证书观察返回了未知或不完整字段。");
        foreach (var name in new[] { "Sha256", "ProgramSha256" }) if (!Regex.IsMatch(state.Text(name), "\\A[a-f0-9]{64}\\z")) throw new OperationException("证书观察缺少有效摘要。");
        foreach (var name in new[] { "NotAfter", "LastSuccess", "LastAttempt" }) if (!DateTimeOffset.TryParse(state.Text(name), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out _)) throw new OperationException("证书观察的时间无效。");
    }
}
