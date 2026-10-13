using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public static class HealthReports
{
    public static JsonObject Build(JsonObject plan, JsonObject state, JsonObject audit)
    {
        var checks = new JsonArray();
        void Check(string name, bool passed, string issue) => checks.Add(new JsonObject { ["Name"] = name, ["Status"] = passed ? "Passed" : "Warning", ["Message"] = passed ? "核对通过" : issue });
        bool Booleans(JsonNode? node, params string[] fields) => fields.All(field => node?[field] is JsonValue value && value.TryGetValue<bool>(out _));
        Check("健康检查证据", audit.Number("SchemaVersion") == 2 && DateTimeOffset.TryParse(audit.Text("CollectedAt"), out _) && audit["ChecksIncomplete"] is JsonArray, "健康检查结构或采集时间不完整，请重新核对。");
        if (audit["Ssh"] != null)
        {
            Check("SSH 配置", Booleans(audit["Ssh"], "Valid") && audit.Flag("Ssh.Valid"), "SSH 配置检查失败或证据缺失。");
            var ports = audit.At("Ssh.Ports") as JsonArray;
            Check("SSH 管理入口", ports != null && new[] { plan.Number("Ports.SshPrimary"), plan.Number("Ports.SshRescue") }.Distinct().All(port => ports.Any(p => p!.ToString() == port.ToString())), "当前 SSH 端口与管理归档不同。");
            if (!plan.Flag("Import.SshAuthenticationPreserved")) Check("SSH 密钥认证", audit.Text("Ssh.PubkeyAuthentication") == "yes", "受管入口的公钥认证未开启。");
        }
        else Check("SSH 检查", false, "未取得 SSH 检查证据。");
        foreach (var role in DeploymentPlans.Roles[..3])
        {
            var service = audit.At("Services." + role);
            var installed = ComponentInstallations.ProtocolInstalled(plan, role);
            var enabled = plan.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.InitiallyEnabled(plan, role));
            Check(ComponentInstallations.Label(role), Booleans(service, "Installed", "Enabled", "Active") && service.Flag("Installed") == installed && service.Flag("Enabled") == enabled && service.Flag("Active") == enabled && (!enabled || service.Flag("ProcessMatchesBinary")), "协议文件、启停状态或运行程序与归档不同，或检查证据缺失。");
            var key = role == "RealityEntry" ? "Xray" : role == "AnyTlsEntry" ? "AnyTls" : "Shadowsocks";
            if (installed && state.Text("ServerConfigHashes." + role) != "") Check(ComponentInstallations.Label(role) + "配置", state.Text("ServerConfigHashes." + role) == audit.Text("Hashes." + key), "协议配置在归档后发生变化，请核对漂移。");
        }
        Check("防火墙配置", Booleans(audit["Nftables"], "Valid") && audit.Flag("Nftables.Valid"), "防火墙配置校验失败或证据缺失。");
        foreach (var name in new[] { "KomariAgent", "KomariController", "Cloudflared" })
        {
            var service = audit.At("Services." + name);
            var expectedInstalled = name == "KomariAgent" ? state.Flag("KomariInstalled", plan.Flag("Komari.Enabled")) : state.Flag(name + ".Installed");
            Check(ComponentInstallations.Label(name == "Cloudflared" ? "Tunnel" : name), Booleans(service, "Installed", "Enabled", "Active", "SupportedLayout") && (!expectedInstalled || service.Flag("Installed")) && (!service.Flag("Installed") || service.Flag("SupportedLayout") && (!service.Flag("Enabled") || service.Flag("Active")) && (!service.Flag("Active") || service.Flag("ProcessMatchesBinary"))), "监控组件缺失，或布局、运行状态、程序身份未通过检查。");
        }
        if (ComponentInstallations.ProtocolInstalled(plan, "AnyTlsEntry")) Check("AnyTLS 证书", audit.Flag("Certificates.AnyTls.Present") && audit.Number("Certificates.AnyTls.DaysRemaining", -1) >= 14, "AnyTLS 证书缺失、已过期或将在 14 天内到期。");
        foreach (var check in audit.Strings("ChecksIncomplete")) Check("未完成检查", false, check + " 未取得完整证据。");
        return new JsonObject { ["At"] = audit["CollectedAt"]?.DeepClone(), ["Status"] = checks.Any(c => c!.Text("Status") != "Passed") ? "Warnings" : "Passed", ["Checks"] = checks };
    }
}
