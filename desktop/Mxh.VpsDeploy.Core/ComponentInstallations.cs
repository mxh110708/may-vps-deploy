using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Mxh.VpsDeploy.Core;

public static class ComponentInstallations
{
    public static readonly string[] Components = ["RealityEntry", "AnyTlsEntry", "ShadowsocksLanding", "KomariAgent", "KomariController", "Tunnel"];
    private static readonly string[] InstallationOrder = ["RealityEntry", "AnyTlsEntry", "ShadowsocksLanding", "KomariController", "Tunnel", "KomariAgent"];
    public static string[] Selected(JsonObject options)
    {
        var selected = options["Components"] is JsonArray array
            ? array.Select(item => item is JsonValue value && value.TryGetValue<string>(out var name) ? name : "").ToArray()
            : new[] { options.Text("Component") };
        if (selected.Length == 0 || selected.Length > Components.Length || selected.Distinct().Count() != selected.Length || selected.Any(name => !Components.Contains(name))) throw new OperationException("请勾选至少一个尚未安装的组件，每个组件只能选择一次。");
        return InstallationOrder.Where(selected.Contains).ToArray();
    }
    public static JsonObject Settings(JsonObject options, string component) => options["Components"] != null ? options["Settings"]![component]!.AsObject() : options["Settings"]!.AsObject();
    public static string SelectionLabel(JsonObject options) => string.Join(" + ", Selected(options).Select(Label));
    public static string StepId(JsonObject options, string stage, string component) => Selected(options).Length == 1 ? stage : stage + "-" + component;
    public static string Label(string component) => component switch
    {
        "RealityEntry" => "Reality 入口", "AnyTlsEntry" => "AnyTLS / ECH 入口", "ShadowsocksLanding" => "Shadowsocks 落地",
        "KomariAgent" => "Komari Agent", "KomariController" => "Komari 主控", "Tunnel" => "Cloudflare Tunnel", _ => throw new OperationException("请选择明确的追加安装组件。")
    };
    public static bool ProtocolInstalled(JsonObject plan, string role) => plan.Flag("ProtocolInventory." + role + ".Installed", DeploymentPlans.Uses(plan, role));
    public static bool EntryPortsConflict(JsonObject plan) => new[] { plan.Number("Ports.XrayPrimary"), plan.Number("Ports.XrayBackup") }.Contains(plan.Number("Ports.AnyTlsPrimary"));
    public static void ValidateOptions(JsonObject options)
    {
        var selected = Selected(options);
        var batch = options.ContainsKey("Components");
        if (options["Settings"] is not JsonObject allSettings || options.Any(item => item.Key is not ("Component" or "Components" or "Settings" or "AssetPin" or "VersionSource" or "InstallationVersions")) || batch && (options["Components"] is not JsonArray || options.ContainsKey("Component")) || !Regex.IsMatch(options.Text("AssetPin"), "^[a-f0-9]{64}$")) throw new OperationException("追加安装只接受所选组件的参数与已审阅的版本清单。");
        if (batch && (allSettings.Count != selected.Length || allSettings.Any(item => !selected.Contains(item.Key) || item.Value is not JsonObject))) throw new OperationException("组件选择与填写参数不一致，请重新审阅。");
        foreach (var component in selected)
        {
            var allowed = component switch
            {
                "RealityEntry" => new[] { "RealityTarget", "RealityPort", "RealityBackupPort" },
                "AnyTlsEntry" => ["AnyTlsName", "EchPublicName", "AnyTlsPort", "ZoneName", "CertbotEmail", "CloudflareTokenFile"],
                "ShadowsocksLanding" => ["LandingPort", "TrustedEntries", "TransitGroup", "SecondaryIpv6Enabled", "SecondaryIpv6Address", "SecondaryBindInterface"],
                "KomariAgent" => ["KomariEndpoint"], "KomariController" => ["ControllerPort"], _ => ["PublicUrl"]
            };
            if (Settings(options, component).Any(item => !allowed.Contains(item.Key))) throw new OperationException("追加安装参数包含其他组件或连接设置，请重新审阅。");
        }
    }
    public static int[] ListeningPorts(JsonObject plan, string component) => component switch
    {
        "RealityEntry" => new[] { plan.Number("Ports.XrayPrimary"), plan.Number("Ports.XrayBackup") }.Where(p => p != 0).ToArray(),
        "AnyTlsEntry" => [plan.Number("Ports.AnyTlsPrimary")], "ShadowsocksLanding" => [plan.Number("Ports.LandingShadowsocks")],
        "KomariController" => [plan.Number("KomariController.Port")], "Tunnel" => [plan.Number("Cloudflared.MetricsPort", 20241)], _ => []
    };
    public static JsonObject Prepare(JsonObject current, JsonObject state, JsonObject options, JsonObject versions)
    {
        ValidateOptions(options);
        if (ArchiveStore.Fingerprint(versions) != options.Text("AssetPin")) throw new OperationException("组件版本清单在填写或审阅后发生变化，请重新打开安装表单并审阅。", code: "InstallationVersionsChanged");
        versions = InstallationVersions.Additional(options, versions);
        if (!InstanceLifecycle.Describe(current, state, null).Managed) throw new OperationException("请先完成部署或接入，再追加安装。");
        var prepared = current.DeepClone().AsObject();
        foreach (var component in Selected(options)) prepared = PrepareOne(prepared, state, component, Settings(options, component), versions);
        return prepared;
    }
    private static JsonObject PrepareOne(JsonObject current, JsonObject state, string component, JsonObject settings, JsonObject versions)
    {
        if (DeploymentPlans.Roles[..3].Contains(component))
        {
            if (ProtocolInstalled(current, component)) throw new OperationException("此协议已安装，请从协议管理维护。", code: "ComponentAlreadyInstalled");
        }
        else
        {
            var target = MaintenanceTargets.Monitoring(current, state).Single(target => target.Scope == component);
            var inventoryName = component == "Tunnel" ? "Cloudflared" : component;
            if (target.Installed || state.Flag("MonitoringInventory." + inventoryName + ".Installed")) throw new OperationException("远端组件已有安装记录，请核对并纳管后维护，不能覆盖安装。", code: "ComponentAlreadyInstalled");
            if (target.RequiresVerification) throw new OperationException("此组件有历史记录，先进行只读健康核对，再选择安装或维护。", code: "ComponentVerificationRequired");
        }
        var plan = current.DeepClone().AsObject();
        switch (component)
        {
            case "RealityEntry":
                DeploymentPlans.Domain(settings.Text("RealityTarget"));
                plan["Reality"] = new JsonObject { ["Target"] = settings.Text("RealityTarget"), ["ServerName"] = settings.Text("RealityTarget"), ["TargetMode"] = "ExternalAudited", ["ForceIpv4Egress"] = true, ["TargetSamples"] = versions.Number("target_audit.samples", 20), ["TargetMaxMedianMs"] = versions.Number("target_audit.maximum_median_ms", 15), ["XrayVersion"] = versions.Text("xray.version"), ["XrayVersionChannel"] = "FixedVerified" };
                plan.Put("Ports.XrayPrimary", JsonValue.Create(settings.Number("RealityPort", 443))); plan.Put("Ports.XrayBackup", JsonValue.Create(settings.Number("RealityBackupPort")));
                break;
            case "AnyTlsEntry":
                DeploymentPlans.Domain(settings.Text("AnyTlsName")); DeploymentPlans.Domain(settings.Text("EchPublicName")); DeploymentPlans.Domain(settings.Text("ZoneName"));
                if (!System.Net.Mail.MailAddress.TryCreate(settings.Text("CertbotEmail"), out _) || !File.Exists(settings.Text("CloudflareTokenFile"))) throw new OperationException("AnyTLS 可信证书需要有效联系邮件与私人 Token 文件。");
                CloudflareCredentials.ReadToken(settings.Text("CloudflareTokenFile"));
                plan["AnyTls"] = new JsonObject { ["ServerName"] = settings.Text("AnyTlsName"), ["EchPublicName"] = settings.Text("EchPublicName"), ["ForceIpv4Egress"] = true, ["PaddingSchemeMode"] = "OfficialDefault", ["SingBoxVersion"] = versions.Text("sing_box.version") };
                plan.Put("Ports.AnyTlsPrimary", JsonValue.Create(settings.Number("AnyTlsPort", 8443)));
                plan.Put("TrustedTls.Enabled", JsonValue.Create(true)); plan.Put("TrustedTls.ZoneName", JsonValue.Create(settings.Text("ZoneName"))); plan.Put("TrustedTls.CertbotEmail", JsonValue.Create(settings.Text("CertbotEmail"))); plan.Put("TrustedTls.CloudflareTokenFile", JsonValue.Create(settings.Text("CloudflareTokenFile"))); plan.Put("TrustedTls.AnyTlsCertificateName", JsonValue.Create("mxh-anytls"));
                break;
            case "ShadowsocksLanding":
                var trusted = Regex.Split(settings.Text("TrustedEntries"), @"[,;\s]+").Where(s => s != "").Distinct().Select(value => IPAddress.TryParse(value, out var address) ? address : throw new OperationException("可信入口地址无效。")).ToArray();
                if (trusted.Length == 0) throw new OperationException("落地至少需要一个可信入口地址。");
                if (settings.Flag("SecondaryIpv6Enabled") && (!IPAddress.TryParse(settings.Text("SecondaryIpv6Address"), out var source) || source.AddressFamily != AddressFamily.InterNetworkV6)) throw new OperationException("IPv6 专用用户需要明确的 IPv6 源地址。");
                plan["Shadowsocks"] = new JsonObject { ["Method"] = "2022-blake3-aes-128-gcm", ["TrustedEntryIPv4s"] = new JsonArray(trusted.Where(ip => ip.AddressFamily == AddressFamily.InterNetwork).Select(ip => (JsonNode?)JsonValue.Create(ip.ToString())).ToArray()), ["TrustedEntryIPv6s"] = new JsonArray(trusted.Where(ip => ip.AddressFamily == AddressFamily.InterNetworkV6).Select(ip => (JsonNode?)JsonValue.Create(ip.ToString())).ToArray()), ["ClientTransitTag"] = settings.Text("TransitGroup", "US-West Entry"), ["SecondaryIpv6Enabled"] = settings.Flag("SecondaryIpv6Enabled"), ["SecondaryIpv6Address"] = settings.Text("SecondaryIpv6Address"), ["SecondaryBindInterface"] = settings.Text("SecondaryBindInterface"), ["SingBoxVersion"] = versions.Text("sing_box.version") };
                if (plan.Text("Shadowsocks.SecondaryBindInterface") != "" && !Regex.IsMatch(plan.Text("Shadowsocks.SecondaryBindInterface"), "^[a-zA-Z0-9_.:-]{1,15}$")) throw new OperationException("网卡名称无效。");
                plan.Put("Ports.LandingShadowsocks", JsonValue.Create(settings.Number("LandingPort", 45001))); break;
            case "KomariAgent":
                HttpUrl(settings.Text("KomariEndpoint")); plan["Komari"] = new JsonObject { ["Enabled"] = true, ["Endpoint"] = settings.Text("KomariEndpoint"), ["AgentVersion"] = versions.Text("komari_agent.version") }; break;
            case "KomariController": plan["KomariController"] = new JsonObject { ["Port"] = settings.Number("ControllerPort", 25774), ["ListenAddress"] = "127.0.0.1", ["Version"] = versions.Text("komari_controller.version") }; break;
            case "Tunnel":
                if (settings.Text("PublicUrl") != "") HttpUrl(settings.Text("PublicUrl"));
                plan["Cloudflared"] = new JsonObject { ["PublicUrl"] = settings.Text("PublicUrl"), ["Version"] = versions.Text("cloudflared.version"), ["TokenFile"] = "/etc/cloudflared/mxh-token", ["MetricsPort"] = 20241 }; break;
        }
        var ports = ListeningPorts(plan, component);
        var occupied = DeploymentPlans.Roles[..3].Where(role => ProtocolInstalled(current, role)).SelectMany(role => ListeningPorts(current, role)).Concat(new[] { current.Number("Ports.SshPrimary"), current.Number("Ports.SshRescue"), current.Number("Server.BootstrapSshPort"), state.Number("CurrentManagementPort"), current.Number("KomariController.Port"), current.Number("Cloudflared.MetricsPort"), current.Text("Reality.TargetMode") == "LocalOwnedTls" ? current.Number("Reality.LocalHttpsPort") : 0 });
        if (ports.Any(port => port is < 1 or > 65535 || occupied.Contains(port)) || ports.Distinct().Count() != ports.Length) throw new OperationException("新组件端口无效或与既有入口冲突，请选择独立端口。", code: "InstallationPortConflict");
        if (DeploymentPlans.Roles[..3].Contains(component))
        {
            plan["Roles"] = new JsonArray(DeploymentPlans.Roles[..3].Where(role => role == component || ProtocolInstalled(current, role)).Select(role => (JsonNode?)JsonValue.Create(role)).ToArray());
            plan.Put("ProtocolInventory." + component, new JsonObject { ["Installed"] = true, ["Enabled"] = true, ["Active"] = true });
            if (!DeploymentPlans.Roles[..3].Contains(current.Text("Role"))) plan["Role"] = component;
            if (component is "RealityEntry" or "AnyTlsEntry" && !new[] { "RealityEntry", "AnyTlsEntry" }.Any(role => ProtocolInstalled(current, role))) plan["ActiveEntry"] = component;
        }
        return plan;
    }
    private static void HttpUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || uri.UserInfo != "" || uri.Fragment != "") throw new OperationException("请填写完整的 HTTP/HTTPS 地址，不包含登录凭据或片段。");
    }
}
