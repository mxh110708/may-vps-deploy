using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private readonly DeploymentNaming deploymentNaming = new();
    private void Deployment()
    {
        var existing = deploymentForm.Flag("Existing");
        deploymentForm["NodeName"] = deploymentNaming.Update(deploymentForm.Text("Provider"), deploymentForm.Text("Instance"), deploymentForm.Text("NodeName"));
        var provider = Field("服务商", deploymentForm, "Provider"); var instance = Field("实例名称", deploymentForm, "Instance"); var nodeName = Field("节点名称", deploymentForm, "NodeName");
        void SuggestName() { nodeName.Text = deploymentNaming.Update(deploymentForm.Text("Provider"), deploymentForm.Text("Instance"), nodeName.Text); }
        provider.TextChanged += (_, _) => SuggestName(); instance.TextChanged += (_, _) => SuggestName();
        nodeName.LostFocus += (_, _) => { if (nodeName.Text.Trim() == "") SuggestName(); };
        page.Children.Add(Row(Action("部署新 VPS", () => { deploymentForm["Existing"] = false; Navigate("deploy"); return Task.CompletedTask; }, !existing), Action("接入已有 VPS", () => { deploymentForm["Existing"] = true; Navigate("deploy"); return Task.CompletedTask; }, existing), Action("已有实例追加安装", ChooseExistingInstallation)));
        page.Children.Add(Card(Column(SectionHeading("连接信息", Symbol.World, existing ? "读取已有配置，并建立本地受管归档。" : "填写实例信息，执行时再输入连接凭据。"),
            Fields(provider, instance, nodeName, Field("当前 root SSH 端口", deploymentForm, "SshPort", "22", true), Field("IPv4", deploymentForm, "IPv4"), Field("IPv6（可选）", deploymentForm, "IPv6")), Text("节点名根据服务商和实例生成；修改后保留你的命名。SSH 端口填写现在已能登录的端口。", 14, true), FileField("SSH 私钥（可选，留空使用密码）", deploymentForm, "KeyPath"))));
        if (!existing)
        {
            var roles = deploymentForm["Roles"] is JsonArray ? deploymentForm.Strings("Roles") : new[] { deploymentForm.Text("Role", "RealityEntry") };
            var selection = new List<UIElement>();
            foreach (var role in DeploymentPlans.Roles[..3])
            {
                var box = DesktopTypography.Mark(new CheckBox { Content = RoleLabel(role), IsChecked = roles.Contains(role), Tag = "Purpose." + role }, TypeRole.Body, 14);
                void Change(bool enabled)
                {
                    var updated = roles.Where(r => r != role && r != "MonitorOnly").ToList(); if (enabled) updated.Add(role);
                    deploymentForm["Roles"] = new JsonArray(DeploymentPlans.Roles[..3].Where(updated.Contains).Select(r => (JsonNode?)JsonValue.Create(r)).ToArray());
                    var entries = updated.Where(r => r is "RealityEntry" or "AnyTlsEntry").ToArray();
                    if (!entries.Contains(deploymentForm.Text("ActiveEntry"))) deploymentForm["ActiveEntry"] = entries.FirstOrDefault() ?? "";
                    Navigate("deploy");
                }
                box.Checked += (_, _) => Change(true); box.Unchecked += (_, _) => Change(false); selection.Add(box);
            }
            var monitor = Flag("Komari 监控 Agent", deploymentForm, "KomariEnabled"); monitor.Checked += (_, _) => Navigate("deploy"); monitor.Unchecked += (_, _) => Navigate("deploy"); selection.Add(monitor);
            page.Children.Add(Card(Column(SectionHeading("用途组合", Symbol.Setting, "可以同时选择入口、落地与监控；不选代理协议时只做基础维护。"), Fields(selection.Cast<FrameworkElement>().ToArray()))));
            page.Children.Add(Card(InstallationVersionFields(deploymentForm, "InstallationSource")));
            if (roles.Contains("RealityEntry") && roles.Contains("AnyTlsEntry"))
                page.Children.Add(Card(Column(Choice("默认启用的入口", deploymentForm, "ActiveEntry", [("RealityEntry", "Reality"), ("AnyTlsEntry", "AnyTLS / ECH")]), Text("两个入口都会安装并归档。当前只启用所选入口，之后可在实例页切换。", 14, true))));
            if (roles.Contains("RealityEntry"))
            {
                var local = Flag("使用自己的域名与本机 HTTPS 目标", deploymentForm, "LocalTarget"); local.Checked += (_, _) => Navigate("deploy"); local.Unchecked += (_, _) => Navigate("deploy");
                page.Children.Add(Card(Column(SectionHeading("Reality 入口", Symbol.Link), Field("目标域名 / SNI", deploymentForm, "RealityTarget"), local,
                    Details("Reality 端口", Fields(Field("主入口端口", deploymentForm, "RealityPort", "443", true), Field("备用端口（空为自动，0 为关闭）", deploymentForm, "RealityBackupPort", numeric: true))))));
            }
            if (roles.Contains("AnyTlsEntry")) page.Children.Add(Card(Column(SectionHeading("AnyTLS / ECH 入口", Symbol.Link), Fields(Field("服务器名称", deploymentForm, "AnyTlsName"), Field("ECH public name", deploymentForm, "EchPublicName")), Field("入口端口", deploymentForm, "AnyTlsPort", "443", true))));
            if (roles.Contains("ShadowsocksLanding")) page.Children.Add(Card(Column(SectionHeading("Shadowsocks 落地", Symbol.Link), Field("可信入口地址（逗号分隔）", deploymentForm, "TrustedEntries"),
                Fields(Field("落地 TCP / UDP 端口", deploymentForm, "LandingPort", "45001", true), Field("入口组", deploymentForm, "TransitGroup", "US-West-LA Entry")),
                Fields(Field("IPv4 出口节点名（可选）", deploymentForm, "LandingPrimaryName"), Field("IPv6 出口节点名（可选）", deploymentForm, "LandingSecondaryName")),
                Text("美国西部入口使用 US-West-LA / US-West-SF；SF 统一表示旧金山湾区（含 San Jose）。出口按实际位置命名，可分别填写 LA IPv4 与 SF ATT IPv6；留空沿用实例名。", 14, true),
                Details("IPv6 专用出口用户", Column(Flag("启用第二用户", deploymentForm, "SecondaryIpv6Enabled"), Fields(Field("IPv6 源地址", deploymentForm, "SecondaryIpv6Address"), Field("绑定网卡（可选）", deploymentForm, "SecondaryBindInterface")))))));
            if (roles.Contains("AnyTlsEntry") || roles.Contains("RealityEntry") && deploymentForm.Flag("LocalTarget")) page.Children.Add(Card(Column(SectionHeading("可信证书", Symbol.Permissions), Fields(Field("Cloudflare 区域", deploymentForm, "ZoneName"), Field("证书联系邮件", deploymentForm, "CertbotEmail")), FileField("证书 Token 私人文件", deploymentForm, "CloudflareTokenFile"))));
            if (deploymentForm.Flag("KomariEnabled")) page.Children.Add(Card(Column(SectionHeading("监控连接", Symbol.World), Field("Komari 主控地址", deploymentForm, "KomariEndpoint"), Text("填写完整的 HTTP/HTTPS 主控地址；Agent Token 在执行时单独输入。", 14, true))));
        }
        else page.Children.Add(Card(SectionHeading("接入已有实例", Symbol.Library, "连接后读取远端配置，生成应用内归档，并保留现有 SSH、服务与防火墙。")));
        page.Children.Add(Text("网络调优已独立到左侧入口，部署和接入均不自动修改网络参数。", 14, true));
        pageAction.Content = Action("审阅计划", async () =>
        {
            var plan = DeploymentPlans.Create(deploymentForm, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")), paths, existing);
            if (!existing)
            {
                var components = InstallationVersions.DeploymentComponents(plan);
                var selection = await SelectInstallationVersions(deploymentForm.Text("InstallationSource", "Fixed"), components);
                plan["InstallationVersions"] = selection;
                InstallationVersions.ApplyPlan(plan, InstallationVersions.Resolve(selection, components, ArchiveStore.ReadJson(paths.Resolve("config/versions.json"))), components, selection.Text("Source"));
            }
            var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/MXH-VPS-Deploy";
            await Submit(new(existing ? OperationKind.ConnectExisting : OperationKind.Deploy, relative, new JsonObject { ["Plan"] = plan }));
        }, true);
    }

}
