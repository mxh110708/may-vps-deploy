using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task InstallComponent(Context c)
    {
        var selected = ComponentInstallations.Selected(c.Request.Options);
        var versions = Versions;
        var prepared = ComponentInstallations.Prepare(c.Plan, c.State, c.Request.Options, versions);
        var protocols = selected.Where(DeploymentPlans.Roles[..3].Contains).ToArray();
        var before = new JsonObject();
        Dictionary<string, string> PreflightParameters(bool verify) => new()
        {
            ["COMPONENTS"] = string.Join(',', selected), ["PORTS"] = string.Join(',', selected.SelectMany(component => ComponentInstallations.ListeningPorts(prepared, component))),
            ["VERIFY_ONLY"] = Bool(verify), ["BEFORE_JSON"] = verify ? before.ToJsonString() : "{}"
        };
        await c.TrackStep("installation-preflight", async () =>
        {
            var result = await c.Run("audit.sh");
            Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(result.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(result.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(result.Output, "ARCH") });
            await VerifyManagement(c);
            var inventoryResult = await c.Run("protocol-lifecycle-status.sh", marker: "PROTOCOL_STATUS_OK");
            var inventory = JsonNode.Parse(RemoteAssets.Marker(inventoryResult.Output, "PROTOCOL_INVENTORY"))!.AsObject();
            foreach (var role in DeploymentPlans.Roles[..3])
                if (inventory.Flag(role + ".Installed") != ComponentInstallations.ProtocolInstalled(c.Plan, role) || inventory.Flag(role + ".Enabled") != Enabled(c.Plan, role) || inventory.Flag(role + ".Active") != Enabled(c.Plan, role))
                    throw new OperationException("远端协议状态与归档不同。先进行健康检查并核对漂移，再追加安装。", code: "InstallationStateDrift");
            var check = await c.Run("component-install-preflight.sh", PreflightParameters(false));
            before = JsonNode.Parse(RemoteAssets.Marker(check.Output, "INSTALLATION_CHECK"))!.AsObject();
            RequireInstallationCheck(before);
            if (protocols.Length > 0 && prepared.Text("Firewall.Mode") == "PreserveExisting")
                if (!await user.ConfirmAsync(new("既有防火墙放行", "此实例保留既有防火墙。请先放行：" + string.Join("；", protocols.Select(component => ComponentInstallations.Label(component) + " " + string.Join("、", ComponentInstallations.ListeningPorts(prepared, component)) + (component == "ShadowsocksLanding" ? " TCP / UDP，仅允许所填可信入口" : " TCP"))) + "。应用不会接管既有防火墙。"), c.Cancellation)) throw new OperationCanceledException();
        });
        var components = selected.Select(component => component == "Tunnel" ? "Cloudflared" : component).ToList();
        if (selected.Contains("AnyTlsEntry")) components.Add("TrustedTls");
        if (protocols.Length > 0 && prepared.Text("Firewall.Mode") != "PreserveExisting") components.Add("Firewall");
        await c.TrackStep("installation-backup", () => Arm(c, components.ToArray()));
        // Merge only after the old plan and private data have been saved in the scoped transaction.
        c.Plan.Clear(); foreach (var field in prepared) c.Plan[field.Key] = field.Value?.DeepClone(); c.Save();
        foreach (var component in selected)
        {
            var protocol = protocols.Contains(component);
            string Step(string stage) => ComponentInstallations.StepId(c.Request.Options, stage, component);
            if (component == "RealityEntry") await c.TrackStep(Step("target-audit"), async () =>
            {
                var result = await c.Run("target-audit.sh", new() { ["TARGET"] = c.Plan.Text("Reality.Target"), ["SAMPLES"] = c.Plan.Text("Reality.TargetSamples"), ["MAX_MEDIAN_MS"] = c.Plan.Text("Reality.TargetMaxMedianMs") }, timeout: 900);
                var audit = JsonNode.Parse(RemoteAssets.Marker(result.Output, "TARGET_JSON"))!.AsObject();
                if (!audit.Flag("automatic_pass")) throw new OperationException("Reality 目标未通过审计，新增协议已停止。");
                ArchiveStore.WriteJson(c.File("target-audits/" + c.Id + ".json"), audit);
            });
            if (component == "AnyTlsEntry") await c.TrackStep(Step("certbot-dns"), async () =>
            {
                var token = CloudflareCredentials.ReadToken(c.Plan.Text("TrustedTls.CloudflareTokenFile"));
                await c.Run("certbot-dns-setup.sh", new() { ["CLOUDFLARE_TOKEN"] = token, ["ZONE_NAME"] = c.Plan.Text("TrustedTls.ZoneName"), ["EMAIL"] = c.Plan.Text("TrustedTls.CertbotEmail"), ["PROPAGATION_SECONDS"] = "30", ["ANYTLS_ENABLED"] = "true", ["ANYTLS_CERT_NAME"] = "mxh-anytls", ["ANYTLS_DOMAINS"] = c.Plan.Text("AnyTls.ServerName") + "," + c.Plan.Text("AnyTls.EchPublicName"), ["REALITY_ENABLED"] = "false", ["PRESERVE_EXISTING_CREDENTIALS"] = "true" }, true, 1800, "CERTBOT_DNS_OK");
            });
            await c.TrackStep(Step("component-install"), async () =>
            {
                if (protocol) { c.Secrets.Remove(component == "RealityEntry" ? "Xray" : component == "AnyTlsEntry" ? "AnyTls" : "Shadowsocks"); await InstallProtocol(c, component, false, versions); }
                else if (component == "KomariAgent")
                {
                    if (selected.Contains("KomariController") && selected.Contains("Tunnel") && !await user.ConfirmAsync(new("准备 Agent 连接", "本轮主控已初始化，Tunnel 已连接 Cloudflare。Agent 计划连接地址：" + c.Plan.Text("Komari.Endpoint") + "。若 Agent 连接此主控，请先在 Cloudflare 添加已发布应用程序路由：填写计划使用的公开主机名，服务 URL 填 " + TunnelAccess.ServiceUrl(c.Plan) + "，路径留空。打开公开主控，以 admin 和刚设置的密码登录并创建节点，取得 Agent Token 后继续。若连接其他已有主控，请从该主控取得节点 Token。"), c.Cancellation)) throw new OperationCanceledException();
                    var token = await user.SecretAsync("Komari Agent Token（从主控中创建节点后取得）", c.Cancellation) ?? throw new OperationCanceledException();
                    if (token == "" || token.Any(char.IsWhiteSpace)) throw new OperationException("Agent Token 不能为空或含空白。");
                    var v = versions;
                    await c.Run("komari-agent.sh", new() { ["ENDPOINT"] = c.Plan.Text("Komari.Endpoint"), ["TOKEN"] = token, ["NODE_NAME"] = c.Plan.Text("NodeName"), ["VERSION"] = v.Text("komari_agent.version"), ["ASSET_NAME"] = v.Text("komari_agent.assets.amd64.name"), ["SHA256"] = v.Text("komari_agent.assets.amd64.sha256"), ["INSTALL_COMPONENT"] = component }, true, 1200);
                    c.Secrets["KomariAgent"] = new JsonObject { ["Token"] = token, ["Endpoint"] = c.Plan.Text("Komari.Endpoint") }; c.State["KomariInstalled"] = true;
                }
                else
                {
                    var v = versions; var prefix = component == "KomariController" ? "komari_controller" : "cloudflared";
                    var secret = await user.SecretAsync(component == "KomariController" ? "新 Komari 主控管理员密码（用户名 admin，至少 12 位）" : "Cloudflare Tunnel 连接 Token（在 Cloudflare 创建 Tunnel 后取得）", c.Cancellation) ?? throw new OperationCanceledException();
                    if (component == "KomariController" ? secret.Length is < 12 or > 256 || secret.Any(char.IsControl) || !secret.Any(char.IsUpper) || !secret.Any(char.IsLower) || !secret.Any(char.IsDigit) : secret == "" || secret.Any(char.IsWhiteSpace)) throw new OperationException("主控密码需要 12–256 位，包含大写、小写字母和数字；Tunnel Token 不能为空或含空白。");
                    await c.Run("monitoring-component-install.sh", new() { ["COMPONENT"] = component, ["INSTALL_COMPONENT"] = component, ["VERSION"] = v.Text(prefix + ".version"), ["ASSET_NAME"] = v.Text(prefix + ".assets.amd64.name"), ["SHA256"] = v.Text(prefix + ".assets.amd64.sha256"), ["PORT"] = component == "KomariController" ? c.Plan.Text("KomariController.Port") : "20241", ["PORTS"] = string.Join(',', ComponentInstallations.ListeningPorts(c.Plan, component)), ["SECRET"] = secret }, true, 1200, "MONITORING_INSTALLED");
                    c.Secrets[component == "KomariController" ? "KomariController" : "Cloudflared"] = component == "KomariController" ? new JsonObject { ["Username"] = "admin", ["Password"] = secret } : new JsonObject { ["Token"] = secret };
                }
            });
        }
        if (protocols.Length > 0) await c.TrackStep("installation-firewall", async () =>
        {
            if (c.Plan.Text("Firewall.Mode") == "PreserveExisting") { c.Report("installation-firewall", "沿用既有防火墙，由你确认新端口已经放行。"); return; }
            var rules = new JsonArray(protocols.Select(component => (JsonNode?)new JsonObject { ["Component"] = component, ["Ports"] = new JsonArray(ComponentInstallations.ListeningPorts(c.Plan, component).Select(port => (JsonNode?)JsonValue.Create(port)).ToArray()) }).ToArray());
            await c.Run("component-firewall-add.sh", new() { ["COMPONENTS_JSON"] = rules.ToJsonString(), ["ALLOWED_IPV4S"] = string.Join(',', c.Plan.Strings("Shadowsocks.TrustedEntryIPv4s")), ["ALLOWED_IPV6S"] = string.Join(',', c.Plan.Strings("Shadowsocks.TrustedEntryIPv6s")), ["EXPECTED_SHA256"] = before.Text("NftablesSha256") }, true, marker: "COMPONENT_FIREWALL_OK");
        });
        await c.TrackStep("installation-validation", async () =>
        {
            var check = await c.Run("component-install-preflight.sh", PreflightParameters(true));
            RequireInstallationCheck(JsonNode.Parse(RemoteAssets.Marker(check.Output, "INSTALLATION_CHECK"))!.AsObject());
            await VerifyManagement(c);
            if (protocols.Length > 0) { await RefreshInventory(c); await ServerGate(c); await ValidateProtocols(c); }
            if (selected.Except(protocols).Any())
            {
                await Health(c);
                foreach (var component in selected.Except(protocols))
                    if (!MaintenanceTargets.Monitoring(c.Plan, c.State).Single(target => target.Scope == component).Installed) throw new OperationException(ComponentInstallations.Label(component) + "的受管布局或连接配置未通过核对，未提交安装。", code: "InstallationLayoutUnconfirmed");
            }
        });
        await c.TrackStep("installation-archive", async () =>
        {
            if (protocols.Length > 0) { await ArchiveConfigs(c); validation.Export(c.Plan, c.Secrets, c.File("client-exports")); }
            c.State["LastComponentInstallation"] = new JsonObject { ["Components"] = new JsonArray(selected.Select(component => (JsonNode?)JsonValue.Create(component)).ToArray()), ["TaskId"] = c.Id, ["At"] = DateTimeOffset.UtcNow }; c.Save();
        });
        await c.TrackStep("installation-commit", () => Commit(c));
    }
    private static void RequireInstallationCheck(JsonObject result)
    {
        if (result.Flag("Allowed")) return;
        var code = result.Text("Code");
        throw new OperationException(code switch
        {
            "ComponentExists" => "远端已有该组件或残留文件，请先核对并纳管，未覆盖安装。",
            "PortBusy" => "新组件端口已被远端服务占用，请更换独立端口。",
            "ExistingComponentChanged" => "既有服务、配置或启停状态发生变化，追加安装未通过保留检查。",
            "ComponentNotRunning" => "新增组件未通过安装和运行检查。",
            _ => "未取得完整的组件安装核对结果，操作已停止。"
        }, code: code == "" ? "InstallationCheckIncomplete" : code);
    }
}
