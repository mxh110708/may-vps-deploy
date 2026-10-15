#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task ChooseExistingInstallation()
    {
        var instances = store.ListInstances().Where(instance => { var status = InstanceLifecycle.Read(store, instance.RelativePath, instance.Plan); return status.Managed && !status.NeedsRecovery; }).ToArray();
        if (instances.Length == 0) { Show("先完成新机部署或接入已有 VPS，然后可在同一实例追加安装。", InfoBarSeverity.Warning); return; }
        var selection = new JsonObject();
        var dialog = OperationDialog("在已有实例追加安装", Column(Text("选择已完成部署或接入的实例。连接参数沿用归档。", 14, true), Choice("实例", selection, "Instance", instances.Select(instance => (instance.RelativePath, instance.Plan.Text("Provider") + " / " + instance.Plan.Text("Instance"))))), "选择组件");
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        selectedInstance = selection.Text("Instance"); await ChooseInstallation(instances.Single(instance => instance.RelativePath == selectedInstance).Plan, false);
    }
    private async Task ChooseInstallation(JsonObject plan, bool protocolsOnly = true)
    {
        var (dialog, selection) = BuildInstallationSelection(plan, protocolsOnly);
        if (await ShowDialog(dialog) == ContentDialogResult.Primary) await InstallationDialog(plan, ComponentInstallations.Components.Where(component => selection.Flag(component)).ToArray());
    }
    private (ContentDialog Dialog, JsonObject Selection) BuildInstallationSelection(JsonObject plan, bool protocolsOnly)
    {
        var state = InstanceState(selectedInstance!);
        var targets = MaintenanceTargets.Monitoring(plan, state);
        var selection = new JsonObject();
        var panel = Column(Text(plan.Text("Provider") + " / " + plan.Text("Instance"), 17), Text("勾选本轮要追加的组件，可同时选择多个。统一填写参数、审阅和备份，再按顺序安装。", 14, true));
        var boxes = new List<CheckBox>();
        foreach (var component in ComponentInstallations.Components.Where(component => !protocolsOnly || DeploymentPlans.Roles[..3].Contains(component)))
        {
            var protocol = DeploymentPlans.Roles[..3].Contains(component);
            var target = protocol ? null : targets.Single(target => target.Scope == component);
            var installed = protocol ? ComponentInstallations.ProtocolInstalled(plan, component) : target!.Installed || state.Flag("MonitoringInventory." + (component == "Tunnel" ? "Cloudflared" : component) + ".Installed");
            var verify = !protocol && target!.RequiresVerification;
            var box = Flag(ComponentInstallations.Label(component), selection, component); box.IsEnabled = !installed && !verify; boxes.Add(box);
            panel.Children.Add(Row(box, Text(installed ? "已安装 · 从维护入口管理" : verify ? "历史状态待核验 · 先运行健康检查" : "可追加", 13, true)));
        }
        panel.Children.Add(Text("新协议使用独立端口；监控按主控、Tunnel、Agent 的顺序安装所选组件。Agent 的主控地址和 Token、Tunnel 的连接 Token 各自填写。", 14, true));
        var dialog = OperationDialog(protocolsOnly ? "添加代理协议" : "追加安装组件", DialogScroll(panel), "填写参数");
        dialog.IsPrimaryButtonEnabled = false;
        foreach (var box in boxes) { box.Checked += (_, _) => dialog.IsPrimaryButtonEnabled = boxes.Any(item => item.IsEnabled && item.IsChecked == true); box.Unchecked += (_, _) => dialog.IsPrimaryButtonEnabled = boxes.Any(item => item.IsEnabled && item.IsChecked == true); }
        return (dialog, selection);
    }
    private Task InstallationDialog(JsonObject plan, string component) => InstallationDialog(plan, [component]);
    private async Task InstallationDialog(JsonObject plan, string[] components)
    {
        var relative = selectedInstance!;
        var (dialog, options) = BuildInstallationDialog(plan, relative, components);
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        var fixedVersions = ArchiveStore.ReadJson(paths.Resolve("config/versions.json"));
        var validation = options.DeepClone().AsObject(); validation["VersionSource"] = "Fixed";
        ComponentInstallations.Prepare(plan, InstanceState(relative), validation, fixedVersions);
        options["InstallationVersions"] = await SelectInstallationVersions(options.Text("VersionSource", "Fixed"), InstallationVersions.AdditionalComponents(options));
        ComponentInstallations.Prepare(plan, InstanceState(relative), options, fixedVersions);
        await Submit(new(OperationKind.InstallComponent, relative, options));
    }
    private (ContentDialog Dialog, JsonObject Options) BuildInstallationDialog(JsonObject plan, string relative, string component) => BuildInstallationDialog(plan, relative, [component]);
    private (ContentDialog Dialog, JsonObject Options) BuildInstallationDialog(JsonObject plan, string relative, string[] components)
    {
        var allSettings = new JsonObject();
        var options = new JsonObject { ["Components"] = new JsonArray(components.Select(component => (JsonNode?)JsonValue.Create(component)).ToArray()), ["Settings"] = allSettings, ["AssetPin"] = ArchiveStore.Fingerprint(ArchiveStore.ReadJson(paths.Resolve("config/versions.json"))) };
        var panel = Column(SectionHeading(plan.Text("NodeName"), Symbol.World, plan.Text("Provider") + " / " + plan.Text("Instance")),
            Text("沿用管理连接：" + plan.Text("Server.IPv4") + " · SSH " + InstanceState(relative).Number("CurrentManagementPort", plan.Number("Ports.SshPrimary")), 14, true));
        panel.Children.Add(InstallationVersionFields(options, "VersionSource"));
        var usedPorts = DeploymentPlans.Roles[..3].Where(role => ComponentInstallations.ProtocolInstalled(plan, role)).SelectMany(role => ComponentInstallations.ListeningPorts(plan, role)).Concat(new[] { plan.Number("Ports.SshPrimary"), plan.Number("Ports.SshRescue"), plan.Number("Server.BootstrapSshPort"), plan.Number("KomariController.Port"), plan.Number("Cloudflared.MetricsPort"), plan.Text("Reality.TargetMode") == "LocalOwnedTls" ? plan.Number("Reality.LocalHttpsPort") : 0 }).ToHashSet();
        int Port(int preferred) { while (usedPorts.Contains(preferred)) preferred = preferred == 443 ? 8443 : preferred + 1; usedPorts.Add(preferred); return preferred; }
        foreach (var component in ComponentInstallations.Selected(options))
        {
            var settings = new JsonObject(); allSettings[component] = settings;
            panel.Children.Add(GroupLabel(ComponentInstallations.Label(component)));
            switch (component)
            {
                case "RealityEntry":
                    settings["RealityPort"] = Port(443);
                    settings["RealityBackupPort"] = 0;
                    panel.Children.Add(Field("目标域名 / SNI", settings, "RealityTarget"));
                    panel.Children.Add(Fields(Field("主入口端口", settings, "RealityPort", numeric: true), Field("备用端口（0 为关闭）", settings, "RealityBackupPort", numeric: true)));
                    panel.Children.Add(Text("使用外部 TLS 目标；执行时审计目标。新入口使用独立端口，不停用已有 AnyTLS。", 14, true)); break;
                case "AnyTlsEntry":
                    settings["AnyTlsPort"] = Port(443);
                    panel.Children.Add(Fields(Field("服务器名称", settings, "AnyTlsName"), Field("ECH public name", settings, "EchPublicName")));
                    panel.Children.Add(Field("新 AnyTLS 入口端口", settings, "AnyTlsPort", numeric: true));
                    panel.Children.Add(Fields(Field("Cloudflare 区域", settings, "ZoneName"), Field("证书联系邮件", settings, "CertbotEmail")));
                    panel.Children.Add(FileField("证书 Token 私人文件", settings, "CloudflareTokenFile"));
                    panel.Children.Add(Text("两个名称使用受支持的 DNS 验证证书。独立端口可与 Reality 同时运行；保留原 Reality 配置和凭据。", 14, true)); break;
                case "ShadowsocksLanding":
                    settings["LandingPort"] = Port(45001); settings["TransitGroup"] = "US-West Entry";
                    panel.Children.Add(Field("可信入口 IP（逗号分隔）", settings, "TrustedEntries"));
                    panel.Children.Add(Fields(Field("新落地 TCP / UDP 端口", settings, "LandingPort", numeric: true), Field("客户端入口组", settings, "TransitGroup")));
                    panel.Children.Add(Flag("启用 IPv6 专用第二用户", settings, "SecondaryIpv6Enabled"));
                    panel.Children.Add(Fields(Field("IPv6 源地址（启用第二用户时填写）", settings, "SecondaryIpv6Address"), Field("绑定网卡（可选）", settings, "SecondaryBindInterface")));
                    panel.Children.Add(Text("仅允许所填可信入口连接落地。已有入口继续运行。", 14, true)); break;
                case "KomariAgent":
                    panel.Children.Add(Field("Komari 主控完整地址", settings, "KomariEndpoint"));
                    panel.Children.Add(Text(components.Contains("KomariController") ? "Agent 采集本机指标并发送到主控。先填写计划使用的主控地址；本轮主控安装完成后再创建节点，该节点的 Agent Token 届时输入。" : "Agent 采集本机指标并发送到主控。请先在主控创建节点；该节点的 Agent Token 在执行时输入。", 14, true)); break;
                case "KomariController":
                    settings["ControllerPort"] = Port(25774); panel.Children.Add(Field("主控本机 HTTP 端口", settings, "ControllerPort", numeric: true));
                    panel.Children.Add(Text("主控独立保存监控数据。安装后监听 127.0.0.1，可经 SSH 转发或另行安装 Tunnel 访问。管理员用户名为 admin，密码在执行时输入，并验证登录。", 14, true)); break;
                case "Tunnel":
                    panel.Children.Add(Field("公开访问网址（可选，用于归档）", settings, "PublicUrl"));
                    panel.Children.Add(Text("第一步：在 Cloudflare 创建 Tunnel 并取得 Token，先在这里安装连接器。连接成功后，Cloudflare 才能继续配置公开路由。公开网址现在可以留空；安装后在实例页完成路由配置与访问验证。", 14, true));
                    var controllerPort = allSettings.Number("KomariController.ControllerPort", plan.Number("KomariController.Port"));
                    if (controllerPort > 0) panel.Children.Add(Text("主控服务地址：http://127.0.0.1:" + controllerPort, 14));
                    panel.Children.Add(Text("本次验收连接器已连接 Cloudflare；这不表示公开主控已经可访问。公开网址的路由和 Access 规则在 Cloudflare 控制台配置。", 14, true)); break;
            }
        }
        var dialog = OperationDialog(components.Length == 1 ? "安装 " + ComponentInstallations.Label(components[0]) : "填写追加安装参数", DialogScroll(panel), "审阅安装");
        return (dialog, options);
    }
    private UIElement InstallationReview(OperationRequest request)
    {
        var plan = ArchiveStore.ReadJson(SafePath.Resolve(paths.Instance(request.InstanceRelativePath), "deployment-plan.json"));
        var prepared = ComponentInstallations.Prepare(plan, InstanceState(request.InstanceRelativePath), request.Options, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")));
        var selected = ComponentInstallations.Selected(request.Options); var versions = InstallationVersions.Additional(request.Options, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")));
        var panel = Column(Card(Column(Text(plan.Text("Provider") + " / " + plan.Text("Instance"), 17), Text("本轮新增：" + ComponentInstallations.SelectionLabel(request.Options)), Text("管理连接：" + plan.Text("Server.IPv4") + " · SSH " + InstanceState(request.InstanceRelativePath).Number("CurrentManagementPort", plan.Number("Ports.SshPrimary"))))));
        if (request.Options["InstallationVersions"] is JsonObject selection) panel.Children.Add(Card(Column(Text("本轮安装版本", 17), Text(InstallationVersions.Summary(selection, InstallationVersions.AdditionalComponents(request.Options)), 14, true))));
        var labels = new Dictionary<string, string> { ["RealityTarget"] = "Reality 目标 / SNI", ["RealityPort"] = "主入口端口", ["RealityBackupPort"] = "备用端口", ["AnyTlsName"] = "AnyTLS 服务器名称", ["EchPublicName"] = "ECH public name", ["AnyTlsPort"] = "新入口端口", ["ZoneName"] = "证书区域", ["CertbotEmail"] = "证书联系邮件", ["CloudflareTokenFile"] = "证书 Token 文件", ["LandingPort"] = "落地端口", ["TrustedEntries"] = "可信入口", ["TransitGroup"] = "客户端入口组", ["SecondaryIpv6Enabled"] = "IPv6 第二用户", ["SecondaryIpv6Address"] = "IPv6 源地址", ["SecondaryBindInterface"] = "绑定网卡", ["KomariEndpoint"] = "Agent 主控地址", ["ControllerPort"] = "主控本机端口", ["PublicUrl"] = "公开访问网址" };
        foreach (var component in selected)
        {
            var version = versions.Text(component == "RealityEntry" ? "xray.version" : component is "AnyTlsEntry" or "ShadowsocksLanding" ? "sing_box.version" : component == "KomariAgent" ? "komari_agent.version" : component == "KomariController" ? "komari_controller.version" : "cloudflared.version");
            var card = Column(Text(ComponentInstallations.Label(component), 17), Text("固定版本：" + version), Text("新监听端口：" + (ComponentInstallations.ListeningPorts(prepared, component).Length == 0 ? "无入站监听" : string.Join("、", ComponentInstallations.ListeningPorts(prepared, component)))));
            foreach (var item in ComponentInstallations.Settings(request.Options, component).Where(item => item.Value?.ToString() != "")) card.Children.Add(Text(labels[item.Key] + "：" + item.Value));
            panel.Children.Add(Card(card));
        }
        var protocols = selected.Any(DeploymentPlans.Roles[..3].Contains);
        var firewallBoundary = !protocols ? "监控与访问组件保留既有防火墙。主控和 Tunnel 指标端口仅监听本机回环地址。" : prepared.Text("Firewall.Mode") == "PreserveExisting" ? "既有防火墙由你放行新端口，应用保留该防火墙。" : "保留既有防火墙规则，一次追加本轮新协议放行规则。";
        panel.Children.Add(Card(Column(Text("操作边界", 17), Text("保留已有协议、凭据、SSH 认证与端口、网络参数。本轮组件统一备份、逐项安装、统一验收；任一项失败或取消，一并恢复本轮新增内容。"), Text(selected.Contains("AnyTlsEntry") ? "快照包含本轮所选组件、AnyTLS 证书与续期设置，以及受管防火墙增量。已有证书与 DNS Token 保留。" : "快照仅包含本轮所选组件及必要的受管防火墙增量。", 14, true), Text(firewallBoundary, 14, true))));
        panel.Children.Add(Card(Column(Text("执行顺序", 17), Text(string.Join(" → ", OperationSteps.Create(request, plan).Select(step => step.Title)), 14, true))));
        return DialogScroll(panel);
    }
}
