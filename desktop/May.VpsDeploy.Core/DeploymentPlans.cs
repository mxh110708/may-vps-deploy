using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static class DeploymentPlans
{
    public static readonly string[] Roles = ["RealityEntry", "AnyTlsEntry", "ShadowsocksLanding", "MonitorOnly"];
    public static string[] Purposes(JsonObject plan) => plan["Roles"] is JsonArray ? plan.Strings("Roles") : [plan.Text("Role", "MonitorOnly")];
    public static bool Uses(JsonObject plan, string role) => Purposes(plan).Contains(role);
    public static bool InitiallyEnabled(JsonObject plan, string role) => Uses(plan, role) && (role == "ShadowsocksLanding" || role == plan.Text("ActiveEntry", plan.Text("Role")));
    public static JsonObject Create(JsonObject form, JsonObject versions, AppPaths paths, bool existing)
    {
        var provider = AppPaths.Segment(form.Text("Provider")); var instance = AppPaths.Segment(form.Text("Instance"));
        var relative = provider + "/" + instance + "/May-VPS-Deploy";
        var bootstrap = form.Number("SshPort", 22);
        var primary = existing || bootstrap >= 1024 ? bootstrap : RandomNumberGenerator.GetInt32(20000, 30000);
        var rescue = existing ? primary : RandomNumberGenerator.GetInt32(30000, 40000);
        var purposes = existing ? new[] { "MonitorOnly" } : form["Roles"] is JsonArray ? form.Strings("Roles") : new[] { form.Text("Role", "RealityEntry") };
        if (purposes.Length == 0) purposes = ["MonitorOnly"];
        if (purposes.Distinct().Count() != purposes.Length || purposes.Any(p => !Roles.Contains(p)) || purposes.Length > 1 && purposes.Contains("MonitorOnly")) throw new OperationException("实例用途组合无效。");
        var entries = purposes.Where(p => p is "RealityEntry" or "AnyTlsEntry").ToArray();
        var activeEntry = form.Text("ActiveEntry", entries.FirstOrDefault() ?? "");
        if (entries.Length != 0 && !entries.Contains(activeEntry)) throw new OperationException("请选择已勾选的默认入口。");
        var role = entries.Length == 0 ? purposes[0] : activeEntry;
        var trusted = Regex.Split(form.Text("TrustedEntries"), @"[,;\s]+").Where(x => x != "").Distinct().Select(value => IPAddress.TryParse(value, out var address) ? address : throw new OperationException("可信入口地址无效。")).ToArray();
        var plan = new JsonObject
        {
            ["SchemaVersion"] = 3, ["CreatedAt"] = DateTimeOffset.UtcNow, ["Provider"] = provider, ["Instance"] = instance, ["NodeName"] = form.Text("NodeName") == "" ? DeploymentNaming.Suggest(provider, instance) : form.Text("NodeName"), ["Role"] = role, ["Roles"] = new JsonArray(purposes.Select(p => (JsonNode?)JsonValue.Create(p)).ToArray()), ["ActiveEntry"] = entries.Length == 0 ? "" : activeEntry,
            ["Server"] = new JsonObject { ["IPv4"] = form.Text("IPv4"), ["IPv6"] = form.Text("IPv6"), ["BootstrapUser"] = "root", ["BootstrapSshPort"] = bootstrap, ["BootstrapAuth"] = form.Text("KeyPath") == "" ? "Password" : "ExistingKey", ["BootstrapKeyPath"] = form.Text("KeyPath") },
            ["SshKey"] = new JsonObject { ["Mode"] = form.Text("KeyPath") == "" ? "GenerateManaged" : "ReuseExisting", ["SourcePrivateKeyPath"] = form.Text("KeyPath"), ["ManagedFileName"] = "id_vps_management", ["PreserveSource"] = true },
            ["AdminUser"] = existing ? "root" : "admin",
            ["Ports"] = new JsonObject { ["SshPrimary"] = primary, ["SshRescue"] = rescue, ["XrayPrimary"] = form.Number("RealityPort", 443), ["XrayBackup"] = form.Number("RealityBackupPort", RandomNumberGenerator.GetInt32(40000, 45000)), ["AnyTlsPrimary"] = form.Number("AnyTlsPort", 443), ["LandingShadowsocks"] = form.Number("LandingPort", 45001) },
            ["Reality"] = new JsonObject { ["Target"] = form.Text("RealityTarget"), ["TargetMode"] = form.Flag("LocalTarget") ? "LocalOwnedTls" : "ExternalAudited", ["ServerName"] = form.Text("RealityTarget"), ["LocalHttpsPort"] = 8443, ["ForceIpv4Egress"] = true, ["TargetSamples"] = versions.Number("target_audit.samples", 20), ["TargetMaxMedianMs"] = versions.Number("target_audit.maximum_median_ms", 15), ["XrayVersion"] = versions.Text("xray.version"), ["XrayVersionChannel"] = "FixedVerified" },
            ["AnyTls"] = new JsonObject { ["ServerName"] = form.Text("AnyTlsName"), ["EchPublicName"] = form.Text("EchPublicName"), ["ForceIpv4Egress"] = true, ["PaddingSchemeMode"] = "OfficialDefault", ["SingBoxVersion"] = versions.Text("sing_box.version") },
            ["Shadowsocks"] = new JsonObject { ["Method"] = "2022-blake3-aes-128-gcm", ["TrustedEntryIPv4s"] = new JsonArray(trusted.Where(x => x.AddressFamily == AddressFamily.InterNetwork).Select(x => (JsonNode?)JsonValue.Create(x.ToString())).ToArray()), ["TrustedEntryIPv6s"] = new JsonArray(trusted.Where(x => x.AddressFamily == AddressFamily.InterNetworkV6).Select(x => (JsonNode?)JsonValue.Create(x.ToString())).ToArray()), ["ClientTransitTag"] = form.Text("TransitGroup", "US-West-LA Entry"), ["ClientPrimaryName"] = form.Text("LandingPrimaryName").Trim(), ["ClientSecondaryName"] = form.Text("LandingSecondaryName").Trim(), ["SecondaryIpv6Enabled"] = form.Flag("SecondaryIpv6Enabled"), ["SecondaryIpv6Address"] = form.Text("SecondaryIpv6Address"), ["SecondaryBindInterface"] = form.Text("SecondaryBindInterface"), ["SingBoxVersion"] = versions.Text("sing_box.version") },
            ["NetworkTuning"] = new JsonObject { ["Mode"] = "Manual", ["DeploymentPolicy"] = "ManualOnly", ["BandwidthMbps"] = 0, ["ReferenceRttMs"] = 0 },
            ["Komari"] = new JsonObject { ["Enabled"] = !existing && form.Flag("KomariEnabled"), ["Endpoint"] = !existing && form.Flag("KomariEnabled") ? form.Text("KomariEndpoint") : "", ["AgentVersion"] = versions.Text("komari_agent.version") },
            ["TrustedTls"] = new JsonObject { ["Enabled"] = purposes.Contains("AnyTlsEntry") || purposes.Contains("RealityEntry") && form.Flag("LocalTarget"), ["ZoneName"] = form.Text("ZoneName"), ["CertbotEmail"] = form.Text("CertbotEmail"), ["AnyTlsCertificateName"] = "mxh-anytls", ["RealityCertificateName"] = "mxh-reality-target", ["CloudflareTokenFile"] = form.Text("CloudflareTokenFile") },
            ["Paths"] = new JsonObject { ["Archive"] = paths.Instance(relative), ["KeyDirectory"] = SafePath.Resolve(paths.Instance(relative), "ssh") },
            ["Firewall"] = new JsonObject { ["Mode"] = existing ? "PreserveExisting" : "ManagedNftables" }
        };
        if (existing) plan["Import"] = new JsonObject { ["Status"] = "Pending", ["SshAuthenticationPreserved"] = true, ["EnforceKeyOnlySsh"] = false };
        else plan["DeploymentTransaction"] = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N") };
        Validate(plan, existing); return plan;
    }
    public static void Validate(JsonObject plan, bool existing = false)
    {
        AppPaths.Segment(plan.Text("Provider")); AppPaths.Segment(plan.Text("Instance"));
        if (!Roles.Contains(plan.Text("Role"))) throw new OperationException("请选择受支持的实例用途。");
        var purposes = Purposes(plan);
        if (purposes.Length == 0 || purposes.Distinct().Count() != purposes.Length || purposes.Any(p => !Roles.Contains(p)) || purposes.Length > 1 && purposes.Contains("MonitorOnly")) throw new OperationException("实例用途组合无效。");
        var entries = purposes.Where(p => p is "RealityEntry" or "AnyTlsEntry").ToArray();
        if (entries.Length > 0 && !entries.Contains(plan.Text("ActiveEntry", plan.Text("Role")))) throw new OperationException("默认入口必须属于所选用途。");
        if (!IPAddress.TryParse(plan.Text("Server.IPv4"), out var ip) || ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != plan.Text("Server.IPv4")) throw new OperationException("请填写标准 IPv4 地址。");
        if (plan.Text("Server.IPv6") != "" && (!IPAddress.TryParse(plan.Text("Server.IPv6"), out var ipv6) || ipv6.AddressFamily != AddressFamily.InterNetworkV6)) throw new OperationException("IPv6 地址无效。");
        foreach (var field in new[] { "Server.BootstrapSshPort", "Ports.SshPrimary", "Ports.SshRescue" }) if (plan.Number(field) is < 1 or > 65535) throw new OperationException("SSH 端口必须在 1–65535。");
        if (!existing && plan.Number("Ports.SshPrimary") == plan.Number("Ports.SshRescue")) throw new OperationException("新部署需要独立的主、救援 SSH 端口。");
        if (plan.Text("NodeName").Length is < 1 or > 120 || plan.Text("NodeName").Any(char.IsControl)) throw new OperationException("节点名称应为 1–120 个可打印字符。");
        DeploymentNaming.ValidateLandingNames(plan);
        if (existing) return;
        var listeners = new List<(string Role, int Port)>();
        if (Uses(plan, "RealityEntry")) { listeners.Add(("RealityEntry", plan.Number("Ports.XrayPrimary"))); if (plan.Number("Ports.XrayBackup") != 0) listeners.Add(("RealityEntry", plan.Number("Ports.XrayBackup"))); }
        if (Uses(plan, "AnyTlsEntry")) listeners.Add(("AnyTlsEntry", plan.Number("Ports.AnyTlsPrimary")));
        if (Uses(plan, "ShadowsocksLanding")) listeners.Add(("ShadowsocksLanding", plan.Number("Ports.LandingShadowsocks")));
        if (listeners.Any(p => p.Port is < 1 or > 65535 || new[] { plan.Number("Ports.SshPrimary"), plan.Number("Ports.SshRescue"), plan.Number("Server.BootstrapSshPort") }.Contains(p.Port)) || listeners.GroupBy(p => p.Port).Any(g => g.Count() > 1 && (g.Count() != 2 || g.Select(p => p.Role).Distinct().Count() != 2 || g.Any(p => p.Role == "ShadowsocksLanding")))) throw new OperationException("协议端口无效或与管理入口、落地端口冲突。");
        if (Uses(plan, "RealityEntry")) Domain(plan.Text("Reality.ServerName"));
        if (Uses(plan, "RealityEntry") && plan.Text("Reality.TargetMode") == "LocalOwnedTls")
        {
            var port = plan.Number("Reality.LocalHttpsPort");
            if (port is < 1 or > 65535 || listeners.Any(listener => listener.Port == port) || new[] { plan.Number("Ports.SshPrimary"), plan.Number("Ports.SshRescue"), plan.Number("Server.BootstrapSshPort") }.Contains(port)) throw new OperationException("本机 HTTPS 目标端口与协议或管理入口冲突，请选择独立端口。");
            if (plan.Text("TrustedTls.RealityCertificateName") != "mxh-reality-target") throw new OperationException("本机 Reality 目标需要受管证书名称 mxh-reality-target，请重新创建部署计划。");
        }
        if (Uses(plan, "AnyTlsEntry")) { Domain(plan.Text("AnyTls.ServerName")); Domain(plan.Text("AnyTls.EchPublicName")); }
        if (plan.Flag("TrustedTls.Enabled") && (plan.Text("TrustedTls.ZoneName") == "" || plan.Text("TrustedTls.CertbotEmail") == "" || !File.Exists(plan.Text("TrustedTls.CloudflareTokenFile")))) throw new OperationException("可信证书需要区域、邮件与私人 Token 文件。");
        if (plan.Flag("TrustedTls.Enabled")) CloudflareCredentials.ReadToken(plan.Text("TrustedTls.CloudflareTokenFile"));
        if (Uses(plan, "ShadowsocksLanding") && plan.Strings("Shadowsocks.TrustedEntryIPv4s").Length + plan.Strings("Shadowsocks.TrustedEntryIPv6s").Length == 0) throw new OperationException("落地至少需要一个可信入口地址。");
        if (Uses(plan, "ShadowsocksLanding") && plan.Flag("Shadowsocks.SecondaryIpv6Enabled") && (!IPAddress.TryParse(plan.Text("Shadowsocks.SecondaryIpv6Address"), out var source6) || source6.AddressFamily != AddressFamily.InterNetworkV6)) throw new OperationException("IPv6 专用用户需要明确的 IPv6 源地址。");
        if (plan.Flag("Komari.Enabled")) plan.Put("Komari.Endpoint", JsonValue.Create(MonitoringArchives.NormalizeEndpoint(plan.Text("Komari.Endpoint"))));
    }
    internal static void Domain(string value)
    {
        if (value.Length is < 1 or > 253 || !value.Contains('.') || IPAddress.TryParse(value, out _) || value.Split('.').Any(label => !Regex.IsMatch(label, @"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"))) throw new OperationException("请填写有效域名。");
    }
    public static JsonObject Network(string role, long memoryKiB, int bandwidth, int rtt)
    {
        if (memoryKiB < 131072 || bandwidth is < 1 or > 100000 || rtt is < 0 or > 2000) throw new OperationException("网络调优输入无效。");
        var mb = memoryKiB / 1024; var tier = mb <= 512 ? "tiny" : mb <= 1024 ? "small" : mb <= 2048 ? "medium" : "standard";
        var cap = (mb <= 512 ? 4L : mb <= 1024 ? 8L : mb <= 2048 ? 16L : 32L) * 1048576;
        var adaptive = rtt > 0 && role != "MonitorOnly"; var bdp = adaptive ? (long)bandwidth * rtt * 125 : 0;
        var roleSlug = role == "ShadowsocksLanding" ? "landing" : role == "MonitorOnly" ? "monitor" : "entry";
        var bandwidthTier = bandwidth <= 100 ? "low" : bandwidth <= 500 ? "medium" : bandwidth <= 2000 ? "high" : "very-high";
        return new JsonObject { ["ROLE"] = role, ["MEMORY_KIB"] = memoryKiB, ["MODE"] = adaptive ? "AdaptiveConservative" : "BaselineOnly", ["BANDWIDTH_MBPS"] = bandwidth, ["REFERENCE_RTT_MS"] = adaptive ? rtt : 0, ["BUFFER_TARGET_BYTES"] = adaptive ? Math.Min(cap, Math.Max(roleSlug == "entry" ? 2097152L : 1048576L, bdp * 2)) : 0, ["BUFFER_CAP_BYTES"] = cap, ["QUEUE_FLOOR"] = Math.Max(roleSlug == "entry" ? 1024 : roleSlug == "landing" ? 2048 : 0, bandwidth <= 100 ? 512 : bandwidth <= 500 ? 1024 : bandwidth <= 2000 ? 2048 : 4096), ["PROFILE"] = $"{roleSlug}-{tier}-{bandwidthTier}-{(adaptive ? "adaptive" : "baseline")}" };
    }
}
