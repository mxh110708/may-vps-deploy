using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Mxh.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private static void Supported(JsonObject audit)
    {
        if (audit.Text("OsId") != "debian" || audit.Text("OsVersion") is not ("12" or "13") || audit.Text("Architecture") != "x86_64") throw new OperationException("目前只支持 Debian 12/13 amd64 目标。");
    }
    private async Task Import(Context c)
    {
        var result = await c.Run("existing-vps-import-audit.sh", marker: "EXISTING_IMPORT_OK", bootstrap: true);
        var audit = JsonNode.Parse(RemoteAssets.Marker(result.Output, "IMPORT_AUDIT"))!.AsObject();
        var privateData = JsonNode.Parse(RemoteAssets.Marker(result.Output, "IMPORT_PRIVATE"))!.AsObject(); Supported(audit);
        if (audit.Text("PubkeyAuthentication") != "yes") throw new OperationException("远端未启用公钥认证，不能自动纳管；现有策略未修改。");
        c.Plan["ProtocolInventory"] = audit["ProtocolInventory"]!.DeepClone();
        c.Plan["Role"] = DeploymentPlans.Roles.FirstOrDefault(role => c.Plan.Flag("ProtocolInventory." + role + ".Enabled")) ?? "MonitorOnly";
        c.Plan["Roles"] = new JsonArray(DeploymentPlans.Roles[..3].Where(role => c.Plan.Flag("ProtocolInventory." + role + ".Installed")).DefaultIfEmpty("MonitorOnly").Select(role => (JsonNode?)JsonValue.Create(role)).ToArray());
        c.Plan["ActiveEntry"] = DeploymentPlans.Roles[..2].FirstOrDefault(role => c.Plan.Flag("ProtocolInventory." + role + ".Enabled")) ?? "";
        c.Plan["AdminUser"] = audit.Text("AdminUser", "root");
        var current = c.Plan.Number("Server.BootstrapSshPort");
        var ports = audit.Strings("SshPorts").Select(int.Parse).ToArray();
        if (!ports.Contains(current)) throw new OperationException("当前连接端口不在有效 SSH 配置中。");
        c.Plan.Put("Ports.SshPrimary", JsonValue.Create(current)); c.Plan.Put("Ports.SshRescue", JsonValue.Create(ports.FirstOrDefault(p => p != current, current)));
        foreach (var (role, setting, portName) in new[] { ("RealityEntry", "Reality", "XrayPrimary"), ("AnyTlsEntry", "AnyTls", "AnyTlsPrimary"), ("ShadowsocksLanding", "Shadowsocks", "LandingShadowsocks") })
        {
            if (!c.Plan.Flag("ProtocolInventory." + role + ".Installed")) continue;
            var data = privateData.At("Protocols." + role)?.AsObject() ?? throw new OperationException("已安装协议缺少完整受支持配置。");
            c.Plan.Put("Ports." + portName, JsonValue.Create(data.Number(role == "RealityEntry" ? "PrimaryPort" : "Port")));
            var target = c.Plan[setting]!.AsObject();
            foreach (var field in new[] { "TargetMode", "ServerName", "TargetAddress", "LocalHttpsPort", "ForceIpv4Egress", "XrayVersion", "EchPublicName", "PaddingScheme", "SingBoxVersion", "Method", "SecondaryIpv6Enabled", "SecondaryIpv6Address", "SecondaryBindInterface" }) if (data.ContainsKey(field)) target[field] = data[field]?.DeepClone();
            if (role == "RealityEntry") { target["Target"] = data.Text("TargetHost"); c.Plan.Put("Ports.XrayBackup", data["BackupPort"]?.DeepClone()); }
            if (data["Secrets"] != null) c.Secrets[role == "RealityEntry" ? "Xray" : setting] = data["Secrets"]!.DeepClone();
        }
        c.Plan.Put("Import.SshAuthenticationPreserved", JsonValue.Create(true));
        c.State["Audit"] = audit.DeepClone(); c.State["ProtocolInventory"] = c.Plan["ProtocolInventory"]!.DeepClone();
        c.State["CurrentManagementPort"] = current; c.State["Engine"] = "dotnet-v1";
        c.State["KomariController"] = audit.At("Komari.Controller")?.DeepClone(); c.State["Cloudflared"] = audit.At("Komari.Cloudflared")?.DeepClone();
        if (privateData["KomariAgent"] != null) { c.Secrets["KomariAgent"] = privateData["KomariAgent"]!.DeepClone(); c.Plan["Komari"]!["Enabled"] = audit.Flag("Komari.Agent.Active"); c.Plan["Komari"]!["Endpoint"] = privateData.Text("KomariAgent.Endpoint"); c.State["KomariInstalled"] = audit.Flag("Komari.Agent.Installed"); }
        if (c.Plan.Text("Server.BootstrapKeyPath") != "") keys.Prepare(c.File("ssh"), c.Plan.Text("Server.BootstrapKeyPath"), c.KeyPassphrase);
        ArchiveStore.WriteJson(c.File("existing-import-audit.json"), audit); c.Save();
        await ArchiveConfigs(c); validation.Export(c.Plan, c.Secrets, c.File("client-exports"));
        c.Plan.Put("Import.Status", JsonValue.Create("Completed")); c.Plan.Put("Import.CompletedAt", JsonValue.Create(DateTimeOffset.UtcNow)); c.Save();
        c.Report("接入完成", "已归档受支持配置，保留现有 SSH、服务和防火墙。");
    }
    private async Task Deploy(Context c)
    {
        var selection = c.Plan["InstallationVersions"] as JsonObject;
        var components = InstallationVersions.DeploymentComponents(c.Plan);
        var accepted = c.Request.Kind == OperationKind.Resume && selection != null && c.State.Text("InstallationVersionPin") == ArchiveStore.Fingerprint(selection);
        var versions = InstallationVersions.Resolve(selection, components, Versions, accepted);
        if (selection != null)
        {
            if (c.Request.Kind == OperationKind.Resume && c.State.Text("InstallationVersionPin") != "" && !accepted) throw new OperationException("草稿的已锁定安装版本发生变化，不能继续部署。", code: "InstallationVersionsChanged");
            InstallationVersions.ApplyPlan(c.Plan, versions, components, selection.Text("Source"));
            c.State["InstallationVersionPin"] = ArchiveStore.Fingerprint(selection);
        }
        if (c.Request.Kind == OperationKind.Resume && c.State.Text("Engine") != "dotnet-v1") throw new OperationException("旧驱动的未完成计划需由维护者核对转换，不能直接重放。");
        if (c.Request.Kind == OperationKind.Resume && InstanceLifecycle.Describe(c.Plan, c.State, c.Pending).Managed) throw new OperationException("该实例已完成部署或接入，不能作为草稿重放。", code: "DeploymentAlreadyComplete", nextAction: "在实例页选择具体维护操作。");
        if (c.Request.Kind == OperationKind.Resume && c.State.Text("DeploymentTransaction.Status") == "RolledBack")
        {
            // The restored baseline retains its rollback marker. A new attempt needs a new identity.
            c.Plan.Put("DeploymentTransaction.Id", JsonValue.Create(Guid.NewGuid().ToString("N")));
            c.State["Modules"] = new JsonObject();
        }
        if (c.Request.Kind == OperationKind.Resume) c.State.Put("Modules.audit", null);
        c.State["Engine"] = "dotnet-v1"; c.Save();
        async Task Step(string id, Func<Task> action)
        {
            c.Cancellation.ThrowIfCancellationRequested();
            if (c.State.Text("Modules." + id + ".Status") == "Success") { await c.TrackStep(id, () => Task.CompletedTask, true); return; }
            c.State.Put("Modules." + id, new JsonObject { ["Status"] = "Running", ["StartedAt"] = DateTimeOffset.UtcNow }); c.Save();
            try { await c.TrackStep(id, async () => { await action(); c.State.Put("Modules." + id, new JsonObject { ["Status"] = "Success", ["FinishedAt"] = DateTimeOffset.UtcNow }); c.Save(); }); }
            catch (Exception error)
            {
                var safe = error is OperationCanceledException ? null : SafeFailures.Describe(error);
                c.State.Put("Modules." + id + ".Status", JsonValue.Create(c.HasPending() ? "NeedsRecovery" : error is OperationCanceledException ? "Cancelled" : "Failed"));
                c.State.Put("Modules." + id + ".FinishedAt", JsonValue.Create(DateTimeOffset.UtcNow));
                if (safe != null) { c.State.Put("Modules." + id + ".SafeError", JsonValue.Create(safe.Message)); c.State.Put("Modules." + id + ".ErrorCode", JsonValue.Create(safe.Code)); }
                c.Save(); throw;
            }
        }
        await Step("audit", async () =>
        {
            var r = await c.Run("audit.sh", bootstrap: true);
            var audit = new JsonObject { ["OsId"] = RemoteAssets.Marker(r.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(r.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(r.Output, "ARCH"), ["MemoryKiB"] = long.Parse(RemoteAssets.Marker(r.Output, "MEMORY_KIB")), ["ExistingServices"] = RemoteAssets.Marker(r.Output, "EXISTING_SERVICES", false), ["NftRuleLines"] = int.Parse(RemoteAssets.Marker(r.Output, "NFT_LINES")) };
            Supported(audit);
            if (audit.Text("ExistingServices") != "" || audit.Number("NftRuleLines") != 0) throw new OperationException("检测到已有服务或防火墙，新机流程已停止，未覆盖。");
            c.State["Audit"] = audit; ArchiveStore.WriteJson(c.File("initial-audit.json"), audit);
        });
        var managementKey = "";
        await c.TrackStep("management-key", () => { managementKey = keys.Prepare(c.File("ssh"), c.Plan.Text("Server.BootstrapKeyPath"), c.KeyPassphrase); return Task.CompletedTask; });
        await Step("deployment-baseline", async () =>
        {
            if (!Regex.IsMatch(c.Plan.Text("DeploymentTransaction.Id"), "^[a-f0-9]{32}$")) throw new OperationException("部署事务身份无效。");
            c.State["DeploymentTransaction"] = new JsonObject { ["Status"] = "Arming", ["RemoteBaselineDirectory"] = "/root/vps-deploy-transaction-baselines/" + c.Plan.Text("DeploymentTransaction.Id") }; c.Save();
            var r = await c.Run("deployment-baseline-arm.sh", new() { ["TRANSACTION_ID"] = c.Plan.Text("DeploymentTransaction.Id"), ["ADMIN_USER"] = c.Plan.Text("AdminUser") }, true, marker: "DEPLOYMENT_BASELINE_OK", bootstrap: true);
            if (RemoteAssets.Marker(r.Output, "BASELINE_DIR") != c.State.Text("DeploymentTransaction.RemoteBaselineDirectory")) throw new OperationException("部署基线身份不一致。", true);
            c.State.Put("DeploymentTransaction.Status", JsonValue.Create("Armed")); c.Save();
        });
        await Step("bootstrap-access", async () =>
        {
            var publicKey = File.ReadAllText(managementKey + ".pub").Trim();
            await c.Run("bootstrap-access.sh", new() { ["PUBLIC_KEY"] = publicKey }, true, bootstrap: true);
            await c.VerifySsh(c.Plan.Number("Server.BootstrapSshPort"), "root");
        });
        await Step("base-system", async () =>
        {
            c.Secrets["AdminPassword"] ??= ServerConfigurations.RandomKey(32); c.Save();
            await c.Run("base-system.sh", new() { ["ADMIN_USER"] = c.Plan.Text("AdminUser"), ["ADMIN_PASSWORD"] = c.Secrets.Text("AdminPassword"), ["PUBLIC_KEY"] = File.ReadAllText(c.File("ssh/id_vps_management.pub")).Trim() }, true, 1200, "BASE_OK");
            await c.VerifySsh(c.Port, "root"); await c.VerifySsh(c.Port, c.Plan.Text("AdminUser"), true);
        });
        await Step("ssh-transition", async () =>
        {
            if (!await user.ConfirmAsync(new("服务商安全组", "请确认所选主、救援 SSH 端口已在服务商安全组放行。"), c.Cancellation)) throw new OperationCanceledException();
            await c.Run("ssh-transition.sh", new() { ["BOOTSTRAP_PORT"] = c.Plan.Text("Server.BootstrapSshPort"), ["SSH_PRIMARY"] = c.Plan.Text("Ports.SshPrimary"), ["SSH_RESCUE"] = c.Plan.Text("Ports.SshRescue") }, true);
            await VerifyManagement(c); c.State["CurrentManagementPort"] = c.Plan.Number("Ports.SshPrimary");
        });
        if (DeploymentPlans.Uses(c.Plan, "RealityEntry") && c.Plan.Text("Reality.TargetMode") != "LocalOwnedTls") await Step("target-audit", async () =>
        {
            var r = await c.Run("target-audit.sh", new() { ["TARGET"] = c.Plan.Text("Reality.Target"), ["SAMPLES"] = c.Plan.Text("Reality.TargetSamples"), ["MAX_MEDIAN_MS"] = c.Plan.Text("Reality.TargetMaxMedianMs") }, timeout: 900);
            var audit = JsonNode.Parse(RemoteAssets.Marker(r.Output, "TARGET_JSON"))!.AsObject(); ArchiveStore.WriteJson(c.File("target-audit.json"), audit);
            if (!audit.Flag("automatic_pass")) throw new OperationException("Reality 目标未通过自动审计，请修改计划并重新审阅。");
        });
        if (c.Plan.Flag("TrustedTls.Enabled")) await Step("certbot-dns", async () =>
        {
            var token = CloudflareCredentials.ReadToken(c.Plan.Text("TrustedTls.CloudflareTokenFile"));
            var anyTls = DeploymentPlans.Uses(c.Plan, "AnyTlsEntry"); var localReality = DeploymentPlans.Uses(c.Plan, "RealityEntry") && c.Plan.Text("Reality.TargetMode") == "LocalOwnedTls";
            await c.Run("certbot-dns-setup.sh", new() { ["CLOUDFLARE_TOKEN"] = token, ["ZONE_NAME"] = c.Plan.Text("TrustedTls.ZoneName"), ["EMAIL"] = c.Plan.Text("TrustedTls.CertbotEmail"), ["PROPAGATION_SECONDS"] = "30", ["ANYTLS_ENABLED"] = Bool(anyTls), ["ANYTLS_CERT_NAME"] = c.Plan.Text("TrustedTls.AnyTlsCertificateName"), ["ANYTLS_DOMAINS"] = anyTls ? c.Plan.Text("AnyTls.ServerName") + "," + c.Plan.Text("AnyTls.EchPublicName") : "", ["REALITY_ENABLED"] = Bool(localReality), ["REALITY_CERT_NAME"] = c.Plan.Text("TrustedTls.RealityCertificateName"), ["REALITY_DOMAINS"] = localReality ? c.Plan.Text("Reality.ServerName") : "" }, true, 1800, "CERTBOT_DNS_OK");
        });
        if (DeploymentPlans.Uses(c.Plan, "RealityEntry") && c.Plan.Text("Reality.TargetMode") == "LocalOwnedTls") await Step("local-https-target", async () => { await c.Run("local-https-target.sh", new() { ["DOMAIN"] = c.Plan.Text("Reality.ServerName"), ["PORT"] = c.Plan.Text("Reality.LocalHttpsPort"), ["CERT_NAME"] = c.Plan.Text("TrustedTls.RealityCertificateName") }, true, 1200, "LOCAL_HTTPS_OK"); });
        // AnyTLS configuration temporarily stops Xray; always install it after Reality.
        foreach (var role in DeploymentPlans.Roles[..3].Where(r => DeploymentPlans.Uses(c.Plan, r)))
            await Step(c.Plan["Roles"] == null ? "protocol-install" : "protocol-install-" + role, () => InstallProtocol(c, role, false, versions));
        if (DeploymentPlans.Purposes(c.Plan).Count(r => r != "MonitorOnly") > 1) await Step("protocol-selection", async () =>
        {
            foreach (var role in DeploymentPlans.Purposes(c.Plan).Where(r => r != "MonitorOnly")) c.Plan.Put("ProtocolInventory." + role, new JsonObject { ["Installed"] = true, ["Enabled"] = DeploymentPlans.InitiallyEnabled(c.Plan, role) });
            await ApplyProtocolState(c);
        });
        if (c.State.Text("Modules.network-tuning.Status") != "Success") c.State.Put("Modules.network-tuning", new JsonObject { ["Status"] = "Skipped", ["Reason"] = "ManualOnly" });
        await Step("nftables-transition", () => Firewall(c, false));
        if (c.Plan.Flag("Komari.Enabled")) await Step("komari-agent", async () =>
        {
            var token = await user.SecretAsync("Komari Agent Token", c.Cancellation) ?? throw new OperationCanceledException();
            var version = versions;
            var parameters = new Dictionary<string, string> { ["ENDPOINT"] = c.Plan.Text("Komari.Endpoint"), ["TOKEN"] = token, ["NODE_NAME"] = c.Plan.Text("NodeName"), ["VERSION"] = version.Text("komari_agent.version"), ["ASSET_NAME"] = version.Text("komari_agent.assets.amd64.name"), ["SHA256"] = version.Text("komari_agent.assets.amd64.sha256") };
            if (version.Text("komari_agent.assets.amd64.url") != "") parameters["DOWNLOAD_URL"] = version.Text("komari_agent.assets.amd64.url");
            await c.Run("komari-agent.sh", parameters, true, 900, "KOMARI_OK");
            RecordInstalledProgram(c, "komari_agent", versions);
            c.Secrets["KomariAgent"] = new JsonObject { ["Token"] = token }; c.State["KomariInstalled"] = true;
        });
        await Step("final-validation", async () => { await RefreshInventory(c); await ServerGate(c); await VerifyManagement(c); await ValidateProtocols(c); });
        await Step("ssh-cutover", async () =>
        {
            if (c.Plan.Number("Server.BootstrapSshPort") != c.Plan.Number("Ports.SshPrimary"))
            {
                if (!await user.ConfirmAsync(new("收口初始 SSH 入口", "主、救援入口均已验证。现在移除初始入口，远端保留自动恢复保护。"), c.Cancellation)) throw new OperationCanceledException();
                await c.Run("ssh-cutover.sh", new() { ["SSH_PRIMARY"] = c.Plan.Text("Ports.SshPrimary"), ["SSH_RESCUE"] = c.Plan.Text("Ports.SshRescue") }, true, marker: "CUTOVER_PENDING");
                await VerifyManagement(c); await c.Run("ssh-cutover-confirm.sh", mutation: true, marker: "CUTOVER_CONFIRMED"); await Firewall(c, true);
            }
        });
        await Step("private-archive", async () => { validation.Export(c.Plan, c.Secrets, c.File("client-exports")); await ArchiveConfigs(c); });
        await Step("deployment-commit", async () =>
        {
            c.State.Put("DeploymentTransaction.Status", JsonValue.Create("LocalPrepared")); c.Save();
            await c.Run("deployment-snapshot-delete.sh", new() { ["SNAPSHOT_DIR"] = c.State.Text("DeploymentTransaction.RemoteBaselineDirectory"), ["KIND"] = "deployment-committed" }, true, 180, "SNAPSHOT_DELETE_OK");
            c.State.Put("DeploymentTransaction.Status", JsonValue.Create("Committed"));
        });
    }
    private static string Bool(bool value) => value ? "true" : "false";
    private async Task VerifyManagement(Context c)
    {
        foreach (var port in new[] { c.Plan.Number("Ports.SshPrimary"), c.Plan.Number("Ports.SshRescue") }.Distinct())
        {
            await c.VerifySsh(port, "root"); if (c.Plan.Text("AdminUser") != "root") await c.VerifySsh(port, c.Plan.Text("AdminUser"), !c.Plan.Flag("Import.SshAuthenticationPreserved"));
        }
    }
    private async Task Firewall(Context c, bool final)
    {
        if (c.Plan.Text("Firewall.Mode") == "PreserveExisting") return;
        var tcp = new List<int> { c.Plan.Number("Ports.SshPrimary"), c.Plan.Number("Ports.SshRescue") };
        if (!final) tcp.Add(c.Plan.Number("Server.BootstrapSshPort"));
        if (Enabled(c.Plan, "RealityEntry")) { tcp.Add(c.Plan.Number("Ports.XrayPrimary")); if (c.Plan.Number("Ports.XrayBackup") > 0) tcp.Add(c.Plan.Number("Ports.XrayBackup")); }
        if (Enabled(c.Plan, "AnyTlsEntry")) tcp.Add(c.Plan.Number("Ports.AnyTlsPrimary"));
        var ss = Enabled(c.Plan, "ShadowsocksLanding");
        await c.Run("nftables-apply.sh", new() { ["TCP_PORTS"] = string.Join(',', tcp.Distinct()), ["RESTRICTED_PORT"] = ss ? c.Plan.Text("Ports.LandingShadowsocks") : "", ["ALLOWED_IPV4S"] = ss ? string.Join(',', c.Plan.Strings("Shadowsocks.TrustedEntryIPv4s")) : "", ["ALLOWED_IPV6S"] = ss ? string.Join(',', c.Plan.Strings("Shadowsocks.TrustedEntryIPv6s")) : "" }, true);
        await VerifyManagement(c);
    }
    private static bool Enabled(JsonObject plan, string role) => plan.At("ProtocolInventory." + role) == null ? DeploymentPlans.InitiallyEnabled(plan, role) : plan.Flag("ProtocolInventory." + role + ".Enabled");
    private async Task ArchiveConfigs(Context c)
    {
        await using var session = await c.Session();
        foreach (var (role, remote, name) in new[] { ("RealityEntry", "/usr/local/etc/xray/config.json", "xray-config.private.json"), ("AnyTlsEntry", "/etc/sing-box-anytls/config.json", "sing-box-anytls-config.private.json"), ("ShadowsocksLanding", "/etc/sing-box/config.json", "sing-box-config.private.json") })
        {
            if (!Enabled(c.Plan, role) && !c.Plan.Flag("ProtocolInventory." + role + ".Installed")) continue;
            ArchiveStore.AtomicWrite(c.File("server-configs/" + name), await session.ReadFileAsync(remote, c.Cancellation));
        }
    }
    private async Task ValidateProtocols(Context c)
    {
        var result = await validation.ValidateAsync(c.Plan, c.Secrets, c.File("client-validation"), user, new InlineProgress<string>(m => c.Report("协议验收", m)), c.Cancellation);
        ArchiveStore.WriteJson(c.File("protocol-validation.dotnet.json"), result); c.State["ProtocolValidation"] = result;
        c.Warnings |= result.Text("Status") is not ("Passed" or "NoEnabledProtocols");
    }
    private async Task ServerGate(Context c)
    {
        var reality = Enabled(c.Plan, "RealityEntry"); var anyTls = Enabled(c.Plan, "AnyTlsEntry"); var ss = Enabled(c.Plan, "ShadowsocksLanding");
        var result = await c.Run("final-validate.sh", new() { ["ROLE"] = c.Plan.Text("Role"), ["SSH_PRIMARY"] = c.Plan.Text("Ports.SshPrimary"), ["SSH_RESCUE"] = c.Plan.Text("Ports.SshRescue"), ["XRAY_PRIMARY"] = reality ? c.Plan.Text("Ports.XrayPrimary") : "", ["XRAY_BACKUP"] = reality ? c.Plan.Text("Ports.XrayBackup") : "", ["ANYTLS_PORT"] = anyTls ? c.Plan.Text("Ports.AnyTlsPrimary") : "", ["ANYTLS_SERVER_NAME"] = anyTls ? c.Plan.Text("AnyTls.ServerName") : "", ["REALITY_TARGET_MODE"] = reality ? c.Plan.Text("Reality.TargetMode", "ExternalAudited") : "ExternalAudited", ["REALITY_SERVER_NAME"] = reality ? c.Plan.Text("Reality.ServerName") : "", ["LOCAL_HTTPS_PORT"] = reality ? c.Plan.Text("Reality.LocalHttpsPort") : "", ["LANDING_PORT"] = ss ? c.Plan.Text("Ports.LandingShadowsocks") : "", ["TRUSTED_ADDRESSES"] = ss ? string.Join(',', c.Plan.Strings("Shadowsocks.TrustedEntryIPv4s").Concat(c.Plan.Strings("Shadowsocks.TrustedEntryIPv6s"))) : "", ["REALITY_ENABLED"] = Bool(reality), ["ANYTLS_ENABLED"] = Bool(anyTls), ["SHADOWSOCKS_ENABLED"] = Bool(ss), ["FIREWALL_MODE"] = c.Plan.Text("Firewall.Mode", "PreserveExisting"), ["KOMARI_ENABLED"] = Bool(c.Plan.Flag("Komari.Enabled")), ["PRESERVE_SSH_AUTH"] = Bool(c.Plan.Flag("Import.SshAuthenticationPreserved")) }, marker: "FINAL_OK");
        c.Warnings |= RemoteAssets.Marker(result.Output, "TIME_SYNC", false) != "yes";
    }
    private async Task RefreshInventory(Context c)
    {
        var previousEntry = c.Plan.Text("ActiveEntry");
        var result = await c.Run("protocol-lifecycle-status.sh", marker: "PROTOCOL_STATUS_OK");
        var inventory = JsonNode.Parse(RemoteAssets.Marker(result.Output, "PROTOCOL_INVENTORY"))!.AsObject();
        c.Plan["ProtocolInventory"] = inventory; c.State["ProtocolInventory"] = inventory.DeepClone();
        c.Plan["Role"] = DeploymentPlans.Roles[..2].Contains(previousEntry) && inventory.Flag(previousEntry + ".Enabled") ? previousEntry : DeploymentPlans.Roles[..3].FirstOrDefault(role => inventory.Flag(role + ".Enabled")) ?? "MonitorOnly";
        c.Plan["Roles"] = new JsonArray(DeploymentPlans.Roles[..3].Where(role => inventory.Flag(role + ".Installed")).DefaultIfEmpty("MonitorOnly").Select(role => (JsonNode?)JsonValue.Create(role)).ToArray());
        c.Plan["ActiveEntry"] = DeploymentPlans.Roles[..2].Contains(previousEntry) && inventory.Flag(previousEntry + ".Enabled") ? previousEntry : DeploymentPlans.Roles[..2].FirstOrDefault(role => inventory.Flag(role + ".Enabled")) ?? "";
    }
}
