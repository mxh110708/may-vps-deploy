using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Mxh.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task Health(Context c)
    {
        var version = Versions;
        var releases = new JsonObject { [version.Text("komari_agent.assets.amd64.sha256")] = version.Text("komari_agent.version") };
        var installedAgent = c.State.At("InstalledProgramVersions.komari_agent");
        if (installedAgent?.Text("Sha256").Length == 64) releases[installedAgent.Text("Sha256")] = installedAgent.Text("Version");
        var agentUpgrade = c.State.At("ComponentUpgrades.KomariAgent");
        if (Regex.IsMatch(agentUpgrade.Text("Sha256"), "^[a-f0-9]{64}$") && Regex.IsMatch(agentUpgrade.Text("Version"), @"^[0-9]+\.[0-9]+\.[0-9]+$")) releases[agentUpgrade.Text("Sha256")] = agentUpgrade.Text("Version");
        var r = await c.Run("maintenance-health-audit.sh", new() { ["AGENT_RELEASES_JSON"] = releases.ToJsonString() }, timeout: 300);
        var audit = JsonNode.Parse(RemoteAssets.Marker(r.Output, "HEALTH_AUDIT"))!.AsObject();
        ArchiveStore.WriteJson(c.File("health-audits/" + c.Id + ".json"), audit);
        // Copies prevent an incomplete audit or unreadable config from partially promoting an archive.
        var plan = c.Plan.DeepClone().AsObject(); var state = c.State.DeepClone().AsObject();
        MonitoringArchives.ApplyHealth(plan, state, audit);
        if (audit.Flag("Services.KomariAgent.Installed") && audit.Flag("Services.KomariAgent.SupportedLayout"))
        {
            await using var session = await c.Session();
            var bytes = await session.ReadFileAsync("/etc/komari-agent/config.json", c.Cancellation);
            try
            {
                var configuration = JsonNode.Parse(bytes)?.AsObject() ?? throw new OperationException("Agent 配置无法识别，未更新归档。");
                if (!MonitoringArchives.SupplementAgent(plan, c.Secrets, configuration))
                {
                    state.Put("MonitoringInventory.KomariAgent.ConnectionConfigMatchesArchive", JsonValue.Create(false));
                    c.Warnings = true; c.Report("监控配置漂移", "Agent 连接配置与旧归档不同，已保留原凭据，请维护者核对。");
                }
                else state.Put("MonitoringInventory.KomariAgent.ConnectionConfigMatchesArchive", JsonValue.Create(true));
                configuration.Clear();
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
        }
        c.Plan["Komari"] = plan["Komari"]!.DeepClone();
        foreach (var field in new[] { "MonitoringInventory", "KomariInstalled", "KomariController", "Cloudflared" }) c.State[field] = state[field]!.DeepClone();
        c.State["LastHealthAudit"] = new JsonObject { ["At"] = DateTimeOffset.UtcNow, ["File"] = "health-audits/" + c.Id + ".json" };
        c.Save(); c.Report("健康审计完成", "远端证据及监控组件状态已归档；任务完成表示读取完成，不代表全部检查健康。");
    }
    private async Task Arm(Context c, string[] components)
    {
        var backup = c.File("maintenance-backups/" + c.Id); System.IO.Directory.CreateDirectory(backup);
        c.Pending = new JsonObject { ["TaskId"] = c.Id, ["Kind"] = c.Request.Kind.ToString(), ["Phase"] = "Arming", ["Components"] = new JsonArray(components.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()), ["LocalBackup"] = "maintenance-backups/" + c.Id, ["OldPlan"] = c.Plan.DeepClone(), ["OldState"] = c.State.DeepClone() };
        store.WriteSecret(SafePath.Resolve(backup, "secrets.dotnet.private.json"), c.Secrets); c.Save();
        var role = DeploymentPlans.Roles.Contains(c.Plan.Text("Role")) ? c.Plan.Text("Role") : "MonitorOnly";
        var result = await c.Run("protocol-migration-arm-rollback.sh", new() { ["SOURCE_ROLE"] = role, ["TARGET_ROLE"] = role, ["TIMEOUT_MINUTES"] = c.Request.Kind == OperationKind.InstallComponent ? "60" : "20", ["QUIESCE_KOMARI_CONTROLLER"] = Bool(components.Contains("KomariController")), ["COMPONENTS"] = string.Join(',', components), ["CONTROL_TASK_ID"] = c.Id, ["NETWORK_SNAPSHOT"] = Bool(c.Request.Kind == OperationKind.TuneNetwork) }, true, 600);
        c.Pending["RemoteBackup"] = RemoteAssets.Marker(result.Output, "BACKUP_DIR"); c.Pending["Phase"] = "Armed"; c.Save();
        if (!Regex.IsMatch(c.Pending.Text("RemoteBackup"), @"^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle$")) throw new OperationException("远端恢复目录异常。", true);
        await using var session = await c.Session();
        await session.DownloadAsync(c.Pending.Text("RemoteBackup") + "/protocol-files.tar.gz", SafePath.Resolve(backup, "remote-files.tar.gz"), c.Cancellation);
        c.Pending["BackupSha256"] = ArchiveStore.Digest(File.ReadAllBytes(SafePath.Resolve(backup, "remote-files.tar.gz")));
        await VerifyRemoteArchive(c, c.Pending.Text("RemoteBackup") + "/protocol-files.tar.gz", c.Pending.Text("BackupSha256")); c.Save();
        ArchiveStore.WriteJson(SafePath.Resolve(backup, "restore-metadata.json"), new JsonObject { ["RemoteBackup"] = c.Pending.Text("RemoteBackup"), ["BackupSha256"] = c.Pending.Text("BackupSha256"), ["CreatedAt"] = DateTimeOffset.UtcNow, ["SshPorts"] = c.Plan.Text("Ports.SshPrimary") + "," + c.Plan.Text("Ports.SshRescue"), ["OldPlan"] = c.Plan.DeepClone(), ["OldState"] = c.State.DeepClone(), ["SecretsRelativePath"] = "maintenance-backups/" + c.Id + "/secrets.dotnet.private.json", ["Components"] = c.Pending["Components"]!.DeepClone() });
    }
    private async Task Commit(Context c)
    {
        c.Cancellation.ThrowIfCancellationRequested();
        c.Pending!["Phase"] = "LocalPrepared"; c.Save();
        await c.Run("maintenance-transaction-commit.sh", new() { ["EXPECTED_BACKUP"] = c.Pending.Text("RemoteBackup") }, true, marker: "MAINTENANCE_COMMITTED");
        c.Pending["Phase"] = "Committed"; c.Pending["CompletedAt"] = DateTimeOffset.UtcNow; c.Save();
    }
    private async Task Rollback(Context c)
    {
        var originalToken = c.Cancellation; c.Cancellation = CancellationToken.None;
        try
        {
            if (c.Pending == null) throw new OperationException("缺少本地恢复记录。", true);
            var parameters = new Dictionary<string, string> { ["ACTION"] = "Status" };
            if (c.Pending.Text("RemoteBackup") != "") parameters["EXPECTED_BACKUP"] = c.Pending.Text("RemoteBackup");
            var result = await c.Run("maintenance-transaction-status.sh", parameters);
            var remote = RemoteAssets.Marker(result.Output, "TRANSACTION_BACKUP");
            var task = RemoteAssets.Marker(result.Output, "CONTROL_TASK_ID", false);
            var phase = RemoteAssets.Marker(result.Output, "TRANSACTION_PHASE");
            if (c.Pending.Text("Phase") == "Arming" && c.Pending.Text("RemoteBackup") == "" && remote == "" && task == "" && phase == "None")
            {
                // The snapshot command may fail before it acquires a remote owner.
                // Verify absence under the remote lock; never replay or release another transaction.
                await c.Run("maintenance-transaction-status.sh", new() { ["ACTION"] = "VerifyUnowned" }, marker: "UNOWNED_TRANSACTION_CLEAR");
                ApplyLocalRollback(c);
                await c.VerifySsh(c.Port, "root");
                c.Pending["Phase"] = "RolledBack"; c.Pending["CompletedAt"] = DateTimeOffset.UtcNow; c.Save();
                c.Report("恢复核对", "远端没有本次快照或活动回滚任务，本地未建立的事务已核对关闭。"); return;
            }
            if (remote == "" || task != c.Pending.Text("TaskId")) throw new OperationException("远端事务与本地任务身份不匹配，未自动恢复。", true);
            if (phase == "Committed")
            {
                if (c.Pending.Text("Phase") != "LocalPrepared") throw new OperationException("远端提交与本地记录不一致。", true);
                c.Pending["Phase"] = "Committed"; c.Save(); return;
            }
            if (phase == "Preparing") throw new OperationException("远端快照尚未完成，请保留记录核对，未擅自清除锁。", true);
            await c.Run("protocol-migration-trigger-rollback.sh", new() { ["EXPECTED_BACKUP"] = remote, ["SOURCE_ROLE"] = c.Pending.Text("OldPlan.Role", "MonitorOnly") }, true, 300, "MIGRATION_ROLLBACK_OK");
            ApplyLocalRollback(c);
            await c.VerifySsh(c.Port, "root");
            c.Pending["Phase"] = "RolledBack"; c.Pending["CompletedAt"] = DateTimeOffset.UtcNow; c.Save();
        }
        finally { c.Cancellation = originalToken; }
    }
    private void ApplyLocalRollback(Context c)
    {
        var oldPlan = c.Pending!["OldPlan"]!.AsObject(); var oldState = c.Pending["OldState"]!.AsObject();
        var oldSecrets = store.ReadSecret(c.File(c.Pending.Text("LocalBackup") + "/secrets.dotnet.private.json"));
        var components = c.Pending.Strings("Components");
        RestoreComponentState(c, oldPlan, oldState, oldSecrets, components); oldSecrets.Clear();
    }
    private void RestoreComponentState(Context c, JsonObject oldPlan, JsonObject oldState, JsonObject oldSecrets, string[] components)
    {
        void Restore(JsonObject target, JsonObject old, string key) { if (old.ContainsKey(key)) target[key] = old[key]?.DeepClone(); else target.Remove(key); }
        foreach (var scope in new[] { "RealityEntry", "AnyTlsEntry", "ShadowsocksLanding", "KomariAgent", "KomariController", "Tunnel" })
        {
            if (!(components.Contains(scope) || scope == "Tunnel" && components.Contains("Cloudflared") || DeploymentPlans.Roles[..3].Contains(scope) && components.Contains("Protocols"))) continue;
            if (c.State["ComponentUpgrades"] is JsonObject upgrades)
            {
                if (oldState["ComponentUpgrades"] is JsonObject oldUpgrades && oldUpgrades.ContainsKey(scope)) upgrades[scope] = oldUpgrades[scope]?.DeepClone();
                else upgrades.Remove(scope);
            }
            if (c.State["InstalledProgramVersions"] is JsonObject installed)
            {
                var key = scope switch { "KomariAgent" => "komari_agent", "KomariController" => "komari_controller", "Tunnel" => "cloudflared", _ => scope };
                if (oldState["InstalledProgramVersions"] is JsonObject oldInstalled && oldInstalled.ContainsKey(key)) installed[key] = oldInstalled[key]?.DeepClone();
                else installed.Remove(key);
            }
        }
        if (components.Contains("Protocols"))
        {
            foreach (var key in new[] { "Role", "Roles", "ActiveEntry", "Reality", "AnyTls", "Shadowsocks", "ProtocolInventory", "TrustedTls" }) Restore(c.Plan, oldPlan, key);
            foreach (var key in new[] { "Xray", "AnyTls", "Shadowsocks" }) Restore(c.Secrets, oldSecrets, key);
            foreach (var key in new[] { "ProtocolInventory", "ProtocolValidation", "XrayVersion", "SingBoxVersion", "AnyTls" }) Restore(c.State, oldState, key);
            foreach (var key in new[] { "XrayPrimary", "XrayBackup", "AnyTlsPrimary", "LandingShadowsocks" }) c.Plan.Put("Ports." + key, oldPlan.At("Ports." + key)?.DeepClone());
            validation.Export(c.Plan, c.Secrets, c.File("client-exports"));
        }
        if (components.Contains("Network")) { Restore(c.Plan, oldPlan, "NetworkTuning"); Restore(c.State, oldState, "NetworkTuning"); }
        if (components.Contains("Firewall")) Restore(c.Plan, oldPlan, "Firewall");
        if (components.Contains("KomariAgent")) { Restore(c.Plan, oldPlan, "Komari"); Restore(c.Secrets, oldSecrets, "KomariAgent"); Restore(c.State, oldState, "KomariInstalled"); }
        if (components.Contains("KomariController")) Restore(c.State, oldState, "KomariController");
        if (components.Contains("Cloudflared")) { Restore(c.State, oldState, "Cloudflared"); Restore(c.Secrets, oldSecrets, "Cloudflared"); }
        foreach (var role in DeploymentPlans.Roles[..3].Where(components.Contains))
        {
            var section = role == "RealityEntry" ? "Reality" : role == "AnyTlsEntry" ? "AnyTls" : "Shadowsocks";
            Restore(c.Plan, oldPlan, section); Restore(c.Secrets, oldSecrets, role == "RealityEntry" ? "Xray" : section);
            foreach (var key in new[] { "Role", "Roles", "ActiveEntry" }) Restore(c.Plan, oldPlan, key);
            foreach (var port in role == "RealityEntry" ? new[] { "XrayPrimary", "XrayBackup" } : role == "AnyTlsEntry" ? new[] { "AnyTlsPrimary" } : new[] { "LandingShadowsocks" }) c.Plan.Put("Ports." + port, oldPlan.At("Ports." + port)?.DeepClone());
            Restore(c.Plan, oldPlan, "ProtocolInventory"); Restore(c.State, oldState, "ProtocolInventory");
            Restore(c.State, oldState, "ProtocolValidation"); validation.Export(c.Plan, c.Secrets, c.File("client-exports"));
        }
        if (components.Contains("TrustedTls")) Restore(c.Plan, oldPlan, "TrustedTls");
        foreach (var name in new[] { "KomariAgent", "KomariController", "Cloudflared" }.Where(components.Contains))
        {
            if (c.State["MonitoringInventory"] is JsonObject inventory)
            {
                if (oldState["MonitoringInventory"] is JsonObject oldInventory && oldInventory.ContainsKey(name)) inventory[name] = oldInventory[name]?.DeepClone();
                else inventory.Remove(name);
            }
        }
        if (components.Contains("KomariController")) { Restore(c.Plan, oldPlan, "KomariController"); Restore(c.Secrets, oldSecrets, "KomariController"); }
        if (components.Contains("Cloudflared")) Restore(c.Plan, oldPlan, "Cloudflared");
        if (c.Pending?.Text("Kind") == OperationKind.InstallComponent.ToString()) Restore(c.State, oldState, "LastComponentInstallation");
    }
    private async Task Recover(Context c)
    {
        if (!c.HasPending() && InstanceLifecycle.Describe(c.Plan, c.State, c.Pending).CanContinue)
        {
            c.Report("无需回滚", "当前只有未完成草稿，尚无待恢复事务。请选择继续部署或继续接入。"); return;
        }
        if (c.Pending != null && c.Pending.Text("Phase") is not ("Committed" or "RolledBack")) { await Rollback(c); return; }
        if (c.State.Text("DeploymentTransaction.Status") is "Arming" or "Armed" or "LocalPrepared")
        {
            // A local key may exist even though bootstrap access never reached the VPS.
            // Until that step is verified, reconcile with the original login and port.
            var bootstrap = c.State.Text("DeploymentTransaction.Status") == "Arming" || c.State.Text("Modules.bootstrap-access.Status") != "Success";
            var port = bootstrap ? c.Plan.Number("Server.BootstrapSshPort") : (int?)null;
            var baselineStatus = await c.Run("deployment-baseline-status.sh", new() { ["TRANSACTION_ID"] = c.Plan.Text("DeploymentTransaction.Id") }, bootstrap: bootstrap, port: port);
            var remotePhase = RemoteAssets.Marker(baselineStatus.Output, "DEPLOYMENT_BASELINE_STATUS");
            if (remotePhase == "None" && c.State.Text("DeploymentTransaction.Status") == "LocalPrepared") { await ServerGate(c); await VerifyManagement(c); c.State.Put("DeploymentTransaction.Status", JsonValue.Create("Committed")); c.Save(); return; }
            if (remotePhase == "None" && c.State.Text("DeploymentTransaction.Status") == "Arming") { c.State.Put("DeploymentTransaction.Status", JsonValue.Create("RolledBack")); c.State["Modules"] = new JsonObject(); c.Save(); return; }
            if (remotePhase is not ("Ready" or "RolledBack")) throw new OperationException("远端部署基线不完整或已变化，请维护者核对，未清除记录。", true);
            if (!await user.ConfirmAsync(new("恢复部署前基线", "恢复本次新机部署前受管文件与 SSH，保留已安装系统包。", "RESTORE-DEPLOYMENT"), c.Cancellation)) throw new OperationCanceledException();
            if (remotePhase != "RolledBack") await c.Run("deployment-baseline-rollback.sh", new() { ["BASELINE_DIR"] = c.State.Text("DeploymentTransaction.RemoteBaselineDirectory"), ["ADMIN_USER"] = c.Plan.Text("AdminUser") }, true, marker: "DEPLOYMENT_ROLLBACK_OK", bootstrap: bootstrap, port: port);
            await using (var restored = await c.Session(c.Plan.Number("Server.BootstrapSshPort"), bootstrap: true)) { var check = await restored.RunScriptAsync("printf 'VPSDEPLOY_SSH_OK\\n'\n", TimeSpan.FromSeconds(60), false, c.Cancellation); RemoteAssets.RequireMarker(check, "SSH_OK"); }
            c.State["CurrentManagementPort"] = c.Plan.Number("Server.BootstrapSshPort"); c.State.Put("DeploymentTransaction.Status", JsonValue.Create("RolledBack")); c.State["Modules"] = new JsonObject(); c.Save(); return;
        }
        var status = await c.Run("maintenance-transaction-status.sh", new() { ["ACTION"] = "Status" });
        var phase = RemoteAssets.Marker(status.Output, "TRANSACTION_PHASE");
        if (phase is not ("None" or "Committed" or "RolledBack")) throw new OperationException("发现其他驱动或未知来源的事务，请由维护者核对，未解除锁。", true);
        c.Report("恢复核对", "没有与本应用匹配的待恢复事务。");
    }
    private async Task Maintain(Context c)
    {
        var kind = c.Request.Kind; var option = c.Request.Options;
        OperationPolicy.Validate(c.Request); ValidateMaintenance(c);
        var upgrade = kind == OperationKind.Upgrade || kind == OperationKind.Komari && option.Text("Action") == "Upgrade";
        var versions = upgrade ? ComponentUpdates.Versions(store.Paths, c.Request.InstanceRelativePath, c.Request, Versions) : Versions;
        MaintenanceTargets.Validate(c.Request, c.Plan, c.State, versions);
        if (upgrade && option.Text("Source", "Fixed") == "Latest")
        {
            var current = kind == OperationKind.Upgrade ? MaintenanceTargets.ProxyCores(c.Plan, versions).Single(t => t.Protocol == option.Text("Protocol")).ArchivedVersion : ComponentUpdates.MonitoringVersion(c.Plan, c.State, option.Text("Scope"));
            if (current == option.Text("TargetVersion")) throw new OperationException("归档已是查询到的最新稳定版，无需重复升级。可先通过健康检查核对实际状态。", code: "ComponentAlreadyCurrent");
            if (ComponentUpdates.IsOlder(option.Text("TargetVersion"), current)) throw new OperationException("官方稳定版低于归档版本，自动降级已阻止。请核对实际版本。", code: "ComponentDowngradeRefused");
        }
        var auditResult = await c.Run("audit.sh");
        var audit = new JsonObject { ["OsId"] = RemoteAssets.Marker(auditResult.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(auditResult.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(auditResult.Output, "ARCH"), ["MemoryKiB"] = long.Parse(RemoteAssets.Marker(auditResult.Output, "MEMORY_KIB")) }; Supported(audit); c.State["Audit"] = audit;
        await VerifyManagement(c);
        if (kind is OperationKind.ProtocolState or OperationKind.RotateCredentials or OperationKind.Restore or OperationKind.Decommission || kind == OperationKind.Upgrade && option.Text("Scope") == "Protocol")
        {
            var inventoryResult = await c.Run("protocol-lifecycle-status.sh", marker: "PROTOCOL_STATUS_OK"); var inventory = JsonNode.Parse(RemoteAssets.Marker(inventoryResult.Output, "PROTOCOL_INVENTORY"))!.AsObject();
            foreach (var role in DeploymentPlans.Roles[..3]) if (inventory.Flag(role + ".Installed") != c.Plan.Flag("ProtocolInventory." + role + ".Installed", c.Plan.Text("Role") == role) || inventory.Flag(role + ".Enabled") != Enabled(c.Plan, role)) throw new OperationException("远端协议状态与归档不一致，请先只读核对漂移，未自动覆盖。");
        }
        var scope = option.Text("Scope", "Protocol");
        if (kind == OperationKind.Komari)
        {
            var status = await c.Run("maintenance-komari.sh", new() { ["ACTION"] = "Status" }, timeout: 60);
            var service = scope switch { "KomariAgent" => "komari-agent.service", "KomariController" => "komari.service", _ => "cloudflared.service" };
            var line = status.Output.Split('\n').SingleOrDefault(value => value.StartsWith(service + "=", StringComparison.Ordinal));
            if (line == null || !line[(service.Length + 1)..].StartsWith("true,", StringComparison.Ordinal)) throw new OperationException("远端没有对应的已安装组件，操作已停止。请重新接入并核对组件归档。", code: "ComponentMissing");
        }
        var components = scope switch { "Protocol" => new[] { "Protocols" }, "Network" => ["Network"], "Firewall" => ["Firewall"], "KomariAgent" => ["KomariAgent"], "KomariController" => ["KomariController"], "Tunnel" => ["Cloudflared"], "ManagedInstance" => ["Protocols", "KomariAgent", "Firewall"], _ => throw new OperationException("不受支持的组件范围。") };
        if (kind == OperationKind.TuneNetwork) components = ["Network"];
        if (kind == OperationKind.ProtocolState && c.Plan.Text("Firewall.Mode") != "PreserveExisting") components = ["Protocols", "Firewall"];
        if (scope == "KomariController") await c.Run("maintenance-komari.sh", new() { ["ACTION"] = "ControllerPreflight" }, timeout: 60);
        await Arm(c, components);
        switch (kind)
        {
            case OperationKind.ProtocolState: await ProtocolState(c); break;
            case OperationKind.RotateCredentials: await Rotate(c); break;
            case OperationKind.Upgrade: await Upgrade(c); break;
            case OperationKind.Komari: await Komari(c); break;
            case OperationKind.Restore: await Restore(c); break;
            case OperationKind.Decommission:
                if (scope != "ManagedInstance" || option.Text("Action") is not ("Disable" or "RemoveManaged")) throw new OperationException("退役必须明确选择整套受管协议与 Agent 的范围。");
                await c.Run("maintenance-decommission.sh", new() { ["SCOPE"] = option.Text("Action"), ["REMOVE_CONTROLLER"] = "false" }, true, marker: "DECOMMISSION_OK");
                foreach (var role in DeploymentPlans.Roles[..3]) { c.Plan.Put("ProtocolInventory." + role + ".Enabled", JsonValue.Create(false)); c.Plan.Put("ProtocolInventory." + role + ".Active", JsonValue.Create(false)); }
                c.Plan.Put("Komari.Enabled", JsonValue.Create(false)); c.State["KomariInstalled"] = option.Text("Action") != "RemoveManaged"; await RefreshInventory(c); await Firewall(c, true); await VerifyManagement(c); break;
            default: throw new OperationException("不受支持的任务类型。");
        }
        if (upgrade) RecordComponentUpgrade(c, versions);
        c.Save(); await Commit(c);
    }
    private static void ValidateMaintenance(Context c)
    {
        var options = c.Request.Options; var role = options.Text("Protocol");
        if (c.Request.Kind is OperationKind.ProtocolState or OperationKind.RotateCredentials || c.Request.Kind == OperationKind.Upgrade && options.Text("Scope") == "Protocol")
        {
            if (!DeploymentPlans.Roles[..3].Contains(role) || !c.Plan.Flag("ProtocolInventory." + role + ".Installed", c.Plan.Text("Role") == role)) throw new OperationException("请选择已安装的受管协议。");
            if (c.Request.Kind is OperationKind.RotateCredentials or OperationKind.Upgrade && !Enabled(c.Plan, role)) throw new OperationException("此项操作需要启用对应协议后独立验收。");
            if (c.Request.Kind == OperationKind.ProtocolState && options.Text("Action") == "Enable" && role is "RealityEntry" or "AnyTlsEntry" && Enabled(c.Plan, role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry") && ComponentInstallations.EntryPortsConflict(c.Plan)) throw new OperationException("共用端口的入口需要使用切换操作。");
        }
        if (c.Request.Kind == OperationKind.Restore && options.Text("RestoreMode") is not ("ConfigOnly" or "Full")) throw new OperationException("恢复范围无效。");
    }
    private async Task VerifyRemoteArchive(Context c, string file, string expected)
    {
        if (!Regex.IsMatch(file, @"^/root/(?:vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle/protocol-files\.tar\.gz|komari-controller-[0-9]{8}-[0-9]{6}\.tar\.gz)$") || !Regex.IsMatch(expected, "^[0-9a-f]{64}$")) throw new OperationException("归档身份或摘要无效。");
        await using var session = await c.Session(); var result = await session.RunAsync("sha256sum -- '" + file + "'", TimeSpan.FromSeconds(120), c.Cancellation); result.RequireSuccess("远端归档摘要无法读取。");
        if (result.Output.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.ToLowerInvariant() != expected) throw new OperationException("本地与远端归档摘要不一致，已停止。");
    }
    private async Task InstallProtocol(Context c, string role, bool upgrade, JsonObject? pinnedVersions = null)
    {
        var version = pinnedVersions ?? Versions;
        if (upgrade)
        {
            var component = ComponentUpdates.ProtocolComponent(role);
            var parameters = new Dictionary<string, string> { ["ROLE"] = role, ["VERSION"] = version.Text(component + ".version"), ["ASSET_NAME"] = version.Text(component + ".assets.amd64.name"), ["SHA256"] = version.Text(component + ".assets.amd64.sha256") };
            if (version.Text(component + ".assets.amd64.url") != "") parameters["DOWNLOAD_URL"] = version.Text(component + ".assets.amd64.url");
            await c.Run("proxy-core-upgrade.sh", parameters, true, 600, "PROXY_CORE_UPDATED");
            c.Plan.Put((role == "RealityEntry" ? "Reality.XrayVersion" : role == "AnyTlsEntry" ? "AnyTls.SingBoxVersion" : "Shadowsocks.SingBoxVersion"), JsonValue.Create(version.Text(component + ".version")));
            return;
        }
        Dictionary<string, string> InstallationGuard(Dictionary<string, string> parameters)
        {
            var component = ComponentUpdates.ProtocolComponent(role);
            if (version.Text(component + ".assets.amd64.url") != "") parameters["DOWNLOAD_URL"] = version.Text(component + ".assets.amd64.url");
            if (c.Request.Kind == OperationKind.InstallComponent) { parameters["INSTALL_COMPONENT"] = role; parameters["PORTS"] = string.Join(',', ComponentInstallations.ListeningPorts(c.Plan, role)); if (role == "AnyTlsEntry") parameters["CERTIFICATE_PREPARED"] = "true"; }
            return parameters;
        }
        if (role == "RealityEntry")
        {
            var parameters = new Dictionary<string, string> { ["VERSION"] = version.Text("xray.version"), ["INSTALLER_URL"] = version.Text("xray.installer_url"), ["INSTALLER_SHA256"] = version.Text("xray.installer_sha256") };
            if (version.Text("xray.assets.amd64.sha256") != "") { parameters["ASSET_NAME"] = version.Text("xray.assets.amd64.name"); parameters["SHA256"] = version.Text("xray.assets.amd64.sha256"); }
            await c.Run("xray-install.sh", InstallationGuard(parameters), true, 1200);
            c.Plan.Put("Reality.XrayVersion", JsonValue.Create(version.Text("xray.version")));
            if (c.Secrets.At("Xray") == null) c.Secrets["Xray"] = JsonNode.Parse(RemoteAssets.Marker((await c.Run("xray-generate-credentials.sh")).Output, "XRAY_SECRET"));
            c.Save(); var config = ServerConfigurations.Xray(c.Plan, c.Secrets);
            await c.Run("xray-apply-config.sh", new() { ["CONFIG_JSON"] = config.ToJsonString(), ["PRIMARY_PORT"] = c.Plan.Text("Ports.XrayPrimary"), ["BACKUP_PORT"] = c.Plan.Text("Ports.XrayBackup"), ["TARGET"] = c.Plan.Text("Reality.TargetMode") == "LocalOwnedTls" ? "127.0.0.1:" + c.Plan.Text("Reality.LocalHttpsPort") : c.Plan.Text("Reality.Target") + ":443" }, true);
        }
        else if (role is "AnyTlsEntry" or "ShadowsocksLanding")
        {
            await c.Run(role == "AnyTlsEntry" ? "sing-box-anytls-install.sh" : "sing-box-install.sh", InstallationGuard(new() { ["VERSION"] = version.Text("sing_box.version"), ["ASSET_NAME"] = version.Text("sing_box.assets.amd64.name"), ["SHA256"] = version.Text("sing_box.assets.amd64.sha256"), ["NEED_BIND_INTERFACE"] = Bool(c.Plan.Text("Shadowsocks.SecondaryBindInterface") != "") }), true, 1200);
            c.Plan.Put((role == "AnyTlsEntry" ? "AnyTls" : "Shadowsocks") + ".SingBoxVersion", JsonValue.Create(version.Text("sing_box.version")));
            if (role == "AnyTlsEntry")
            {
                c.Secrets["AnyTls"] ??= new JsonObject(); c.Secrets["AnyTls"]!["Password"] ??= ServerConfigurations.RandomKey(32);
                if (c.Secrets.Text("AnyTls.EchServerKeyPem") == "")
                {
                    var ech = await c.Run("anytls-generate-ech.sh", new() { ["PUBLIC_NAME"] = c.Plan.Text("AnyTls.EchPublicName") });
                    c.Secrets.Put("AnyTls.EchServerKeyPem", JsonValue.Create(RemoteAssets.Marker(ech.Output, "ECH_KEYS")));
                    c.Secrets.Put("AnyTls.EchClientConfigPem", JsonValue.Create(RemoteAssets.Marker(ech.Output, "ECH_CONFIG")));
                }
                c.Save(); await c.Run("anytls-apply-config.sh", new() { ["CONFIG_JSON"] = ServerConfigurations.AnyTls(c.Plan, c.Secrets).ToJsonString(), ["ECH_KEYS_PEM"] = c.Secrets.Text("AnyTls.EchServerKeyPem"), ["ECH_CONFIG_PEM"] = c.Secrets.Text("AnyTls.EchClientConfigPem"), ["PORT"] = c.Plan.Text("Ports.AnyTlsPrimary"), ["SERVER_NAME"] = c.Plan.Text("AnyTls.ServerName"), ["KEEP_OTHER_PROTOCOLS"] = Bool(c.Request.Kind == OperationKind.InstallComponent) }, true);
            }
            else
            {
                c.Secrets["Shadowsocks"] ??= new JsonObject();
                foreach (var key in new[] { "ServerKey", "PrimaryUserKey", "SecondaryUserKey" }) c.Secrets["Shadowsocks"]![key] ??= ServerConfigurations.RandomKey(c.Plan.Text("Shadowsocks.Method") == "2022-blake3-aes-128-gcm" ? 16 : 32);
                c.Save(); await c.Run("sing-box-apply-config.sh", new() { ["CONFIG_JSON"] = ServerConfigurations.Shadowsocks(c.Plan, c.Secrets).ToJsonString(), ["LANDING_PORT"] = c.Plan.Text("Ports.LandingShadowsocks") }, true);
            }
        }
        else throw new OperationException("不支持的协议。");
        RecordInstalledProgram(c, ComponentUpdates.ProtocolComponent(role), version, role);
    }
    private async Task ProtocolState(Context c)
    {
        var role = c.Request.Options.Text("Protocol"); if (!DeploymentPlans.Roles[..3].Contains(role)) throw new OperationException("请选择受管协议。");
        var action = c.Request.Options.Text("Action");
        if (!c.Plan.Flag("ProtocolInventory." + role + ".Installed", c.Plan.Text("Role") == role)) throw new OperationException("该协议尚未安装，请先完成对应部署配置。");
        if (action == "Uninstall")
        {
            await c.Run("protocol-lifecycle-uninstall.sh", new() { ["REMOVE_ROLE"] = role }, true);
            c.Plan.Put("ProtocolInventory." + role + ".Installed", JsonValue.Create(false));
        }
        c.Plan.Put("ProtocolInventory." + role + ".Enabled", JsonValue.Create(action is "Enable" or "Switch"));
        if (action == "Switch" && role is "RealityEntry" or "AnyTlsEntry") c.Plan.Put("ProtocolInventory." + (role == "RealityEntry" ? "AnyTlsEntry" : "RealityEntry") + ".Enabled", JsonValue.Create(false));
        if (Enabled(c.Plan, "RealityEntry") && Enabled(c.Plan, "AnyTlsEntry") && ComponentInstallations.EntryPortsConflict(c.Plan)) throw new OperationException("Reality 与 AnyTLS 共用监听端口，请使用明确切换操作。");
        await ApplyProtocolState(c); await RefreshInventory(c); await Firewall(c, true); await ServerGate(c); await ValidateProtocols(c); await ArchiveConfigs(c); validation.Export(c.Plan, c.Secrets, c.File("client-exports"));
    }
    private async Task ApplyProtocolState(Context c, string restart = "")
    {
        await c.Run("protocol-lifecycle-apply-state.sh", new() { ["REALITY_ENABLED"] = Bool(Enabled(c.Plan, "RealityEntry")), ["ANYTLS_ENABLED"] = Bool(Enabled(c.Plan, "AnyTlsEntry")), ["SHADOWSOCKS_ENABLED"] = Bool(Enabled(c.Plan, "ShadowsocksLanding")), ["RESTART_ROLE"] = restart }, true, marker: "PROTOCOL_STATE_APPLIED");
    }
    private async Task Upgrade(Context c)
    {
        var role = c.Request.Options.Text("Protocol");
        if (!DeploymentPlans.Roles[..3].Contains(role) || !Enabled(c.Plan, role)) throw new OperationException("升级前请先启用对应协议，以便完成真实连接验收。");
        var versions = ComponentUpdates.Versions(store.Paths, c.Request.InstanceRelativePath, c.Request, Versions);
        await InstallProtocol(c, role, true, versions); await ApplyProtocolState(c, role); await RefreshInventory(c); await ServerGate(c); await ValidateProtocols(c); await ArchiveConfigs(c); validation.Export(c.Plan, c.Secrets, c.File("client-exports"));
    }
    private async Task Rotate(Context c)
    {
        var role = c.Request.Options.Text("Protocol");
        if (!DeploymentPlans.Roles[..3].Contains(role) || !Enabled(c.Plan, role)) throw new OperationException("只能轮换正在运行的受管协议。");
        var current = await c.Run("maintenance-protocol-config-read.sh", new() { ["ROLE"] = role });
        var config = JsonNode.Parse(RemoteAssets.Marker(current.Output, "SERVER_CONFIG"))!.AsObject();
        if (role == "RealityEntry")
        {
            var fresh = JsonNode.Parse(RemoteAssets.Marker((await c.Run("xray-generate-credentials.sh")).Output, "XRAY_SECRET"))!.AsObject();
            var inbounds = config["inbounds"]!.AsArray().Where(n => n!.Text("protocol") == "vless" && n.Text("streamSettings.security") == "reality").ToArray();
            if (inbounds.Length == 0 || inbounds.Any(n => n!.At("settings.clients")!.AsArray().Count != 1 || n.At("settings.clients")!.AsArray()[0]!.Text("id") != c.Secrets.Text("Xray.Uuid") || n.Text("streamSettings.realitySettings.privateKey") != c.Secrets.Text("Xray.RealityPrivateKey"))) throw new OperationException("Reality 用户或密钥布局已经变化，停止轮换。");
            foreach (var node in inbounds) { node!.At("settings.clients")!.AsArray()[0]!["id"] = fresh.Text("Uuid"); node.At("streamSettings.realitySettings")!["privateKey"] = fresh.Text("RealityPrivateKey"); node.At("streamSettings.realitySettings")!["shortIds"] = new JsonArray(fresh.Text("ShortId")); }
            c.Secrets["Xray"] = fresh;
        }
        else
        {
            var entries = config["inbounds"]!.AsArray().Where(n => n!.Text("type") == (role == "AnyTlsEntry" ? "anytls" : "shadowsocks")).ToArray();
            if (entries.Length != 1) throw new OperationException("协议布局不明确，停止轮换。"); var inbound = entries[0]!.AsObject();
            var users = inbound["users"]!.AsArray();
            if (role == "AnyTlsEntry")
            {
                if (users.Count != 1 || users[0]!.Text("password") != c.Secrets.Text("AnyTls.Password")) throw new OperationException("AnyTLS 用户已变化，停止轮换。");
                var password = ServerConfigurations.RandomKey(32); users[0]!["password"] = password; c.Secrets.Put("AnyTls.Password", JsonValue.Create(password));
            }
            else
            {
                if (inbound.Text("password") != c.Secrets.Text("Shadowsocks.ServerKey") || users.Count == 0 || users.Any(n => n!.Text("name") is not ("ipv4-client" or "ipv6-client")) || users.Select(n => n!.Text("name")).Distinct().Count() != users.Count) throw new OperationException("Shadowsocks 用户或服务端密钥已变化，停止轮换。");
                foreach (var node in users.OfType<JsonObject>()) { var key = node.Text("name") == "ipv4-client" ? "PrimaryUserKey" : "SecondaryUserKey"; if (node.Text("password") != c.Secrets.Text("Shadowsocks." + key)) throw new OperationException("Shadowsocks 用户密钥已变化，停止轮换。"); var password = ServerConfigurations.RandomKey(c.Plan.Text("Shadowsocks.Method") == "2022-blake3-aes-128-gcm" ? 16 : 32); node["password"] = password; c.Secrets.Put("Shadowsocks." + key, JsonValue.Create(password)); }
            }
        }
        await c.Run("maintenance-protocol-config-apply.sh", new() { ["ROLE"] = role, ["CONFIG_JSON"] = config.ToJsonString(), ["WAS_ACTIVE"] = "true", ["EXPECTED_CONFIG_SHA256"] = RemoteAssets.Marker(current.Output, "SERVER_CONFIG_SHA256") }, true, marker: "CREDENTIAL_CONFIG_APPLIED");
        await ServerGate(c); await ValidateProtocols(c); await ArchiveConfigs(c); validation.Export(c.Plan, c.Secrets, c.File("client-exports"));
    }
    private async Task Komari(Context c)
    {
        var scope = c.Request.Options.Text("Scope"); var action = c.Request.Options.Text("Action");
        if (!(scope switch { "KomariAgent" => action is "Upgrade" or "Remove", "KomariController" => action is "Upgrade" or "Backup" or "Restore", "Tunnel" => action is "Upgrade" or "RotateToken", _ => false })) throw new OperationException("监控操作或组件范围无效。");
        var version = action == "Upgrade" ? ComponentUpdates.Versions(store.Paths, c.Request.InstanceRelativePath, c.Request, Versions) : Versions;
        var parameters = new Dictionary<string, string>();
        var controllerPort = c.Plan.Number("KomariController.Port", 25774).ToString();
        if (scope == "KomariController") parameters["CONTROLLER_PORT"] = controllerPort;
        var prefix = scope == "KomariAgent" ? "Agent" : scope == "KomariController" ? "Controller" : "Tunnel";
        parameters["ACTION"] = prefix + (action == "Remove" ? "Uninstall" : action == "RotateToken" ? "Rotate" : action);
        if (action is "Upgrade" or "Backup" or "Restore")
        {
            var component = ComponentUpdates.ScopeComponent(scope);
            parameters["VERSION"] = version.Text(component + ".version"); parameters["ASSET_NAME"] = version.Text(component + ".assets.amd64.name"); parameters["SHA256"] = version.Text(component + ".assets.amd64.sha256");
            if (version.Text(component + ".assets.amd64.url") != "") parameters["DOWNLOAD_URL"] = version.Text(component + ".assets.amd64.url");
            if (scope == "KomariController")
            {
                var backup = await c.Run("maintenance-komari.sh", new() { ["ACTION"] = "ControllerBackup", ["INCLUDE_TUNNEL"] = "false", ["CONTROLLER_PORT"] = controllerPort }, true, 600, "KOMARI_LIFECYCLE_OK");
                var remote = RemoteAssets.Marker(backup.Output, "KOMARI_BACKUP");
                var local = c.File("komari-backups/" + c.Id + ".tar.gz"); await using var session = await c.Session(); await session.DownloadAsync(remote, local, c.Cancellation);
                var hash = ArchiveStore.Digest(File.ReadAllBytes(local)); await VerifyRemoteArchive(c, remote, hash);
                ArchiveStore.WriteJson(c.File("komari-backups/" + c.Id + ".json"), new JsonObject { ["RemoteBackup"] = remote, ["Sha256"] = hash, ["IncludeTunnel"] = false, ["ControllerPort"] = int.Parse(controllerPort), ["At"] = DateTimeOffset.UtcNow });
                parameters["BACKUP_FILE"] = action == "Restore" ? c.Request.Options.Text("Backup") : remote;
                if (action == "Restore")
                {
                    var root = c.File("komari-backups"); SafePath.CheckTree(root);
                    var records = Directory.EnumerateFiles(root, "*.json").Select(ArchiveStore.ReadJson).Where(x => x.Text("RemoteBackup") == c.Request.Options.Text("Backup") && x.At("IncludeTunnel") != null && !x.Flag("IncludeTunnel")).ToArray();
                    if (records.Length != 1) throw new OperationException("缺少唯一的主控专用恢复归档。");
                    if (records[0].Number("ControllerPort", 25774).ToString() != controllerPort) throw new OperationException("主控恢复点与当前监听端口不同，请先核对服务与 Tunnel 路由，未自动替换连接设置。");
                    parameters["BACKUP_SHA256"] = records[0].Text("Sha256"); await VerifyRemoteArchive(c, parameters["BACKUP_FILE"], parameters["BACKUP_SHA256"]);
                    parameters["FINAL_ACTIVE"] = Bool(c.State.Flag("KomariController.Active"));
                }
                if (action == "Backup") return;
            }
        }
        if (action == "RotateToken")
        {
            var token = await user.SecretAsync("Tunnel Token", c.Cancellation) ?? throw new OperationCanceledException();
            if (token == "" || token.Any(char.IsWhiteSpace)) throw new OperationException("Tunnel Token 不能为空或含空白。");
            parameters["TUNNEL_TOKEN"] = token;
        }
        await c.Run("maintenance-komari.sh", parameters, true, 1200, "KOMARI_LIFECYCLE_OK");
        if (action == "RotateToken") c.Secrets.Put("Cloudflared.Token", JsonValue.Create(parameters["TUNNEL_TOKEN"]));
        if (scope == "KomariAgent" && action == "Upgrade") c.Plan.Put("Komari.AgentVersion", JsonValue.Create(version.Text("komari_agent.version")));
        if (scope == "KomariController" && action == "Upgrade") { c.Plan.Put("KomariController.Version", JsonValue.Create(version.Text("komari_controller.version"))); c.State.Put("KomariController.Version", JsonValue.Create(version.Text("komari_controller.version"))); }
        if (scope == "Tunnel" && action == "Upgrade") { c.Plan.Put("Cloudflared.Version", JsonValue.Create(version.Text("cloudflared.version"))); c.State.Put("Cloudflared.Version", JsonValue.Create(version.Text("cloudflared.version"))); }
        if (scope == "KomariAgent" && action == "Remove") { c.Plan.Put("Komari.Enabled", JsonValue.Create(false)); c.State["KomariInstalled"] = false; }
        if (scope == "KomariController" && action == "Upgrade")
        {
            var verify = await c.Run("maintenance-komari.sh", new() { ["ACTION"] = "ControllerVerify", ["VERSION"] = version.Text("komari_controller.version"), ["CONTROLLER_PORT"] = controllerPort });
            var migration = RemoteAssets.Marker(verify.Output, "KOMARI_MIGRATION_REQUIRED");
            if (migration == "true")
            {
                if (!await user.ConfirmAsync(new("完成数据库迁移", "请在主控后台完成数据库迁移，再确认继续。取消将恢复升级前完整数据。"), c.Cancellation)) throw new OperationCanceledException();
                verify = await c.Run("maintenance-komari.sh", new() { ["ACTION"] = "ControllerVerify", ["VERSION"] = version.Text("komari_controller.version"), ["CONTROLLER_PORT"] = controllerPort }); migration = RemoteAssets.Marker(verify.Output, "KOMARI_MIGRATION_REQUIRED");
            }
            if (migration is not ("false" or "deferred")) throw new OperationException("数据库迁移尚未确认，升级未提交。");
            c.Warnings |= migration == "deferred";
        }
        if (action == "Upgrade")
        {
            var inventoryScope = scope == "Tunnel" ? "Cloudflared" : scope;
            c.State.Put("MonitoringInventory." + inventoryScope + ".Version", JsonValue.Create(parameters["VERSION"]));
        }
    }
    private async Task Restore(Context c)
    {
        if (c.Request.Options.Text("Scope") != "Protocol") throw new OperationException("监控恢复请使用对应监控组件入口。");
        var backup = c.Request.Options.Text("Backup");
        if (!Regex.IsMatch(backup, @"^/root/vps-deploy-backups/[0-9]{8}-[0-9]{6}/protocol-lifecycle$")) throw new OperationException("恢复路径不是受管归档。");
        if (c.Request.Options.Text("RestoreMode") is not ("ConfigOnly" or "Full")) throw new OperationException("请选择配置恢复或完整协议恢复。");
        // The restore metadata must match the backup actually created by this engine.
        var metadata = store.Paths.Instance(c.Request.InstanceRelativePath);
        var root = SafePath.Resolve(metadata, "maintenance-backups"); SafePath.CheckTree(root);
        var matches = Directory.EnumerateFiles(root, "restore-metadata.json", SearchOption.AllDirectories).Select(ArchiveStore.ReadJson).Where(n => n.Text("RemoteBackup") == backup && n.Strings("Components").Contains("Protocols")).ToArray();
        if (matches.Length != 1 || matches[0].Text("SshPorts") != c.Plan.Text("Ports.SshPrimary") + "," + c.Plan.Text("Ports.SshRescue")) throw new OperationException("没有唯一、兼容当前管理入口的协议恢复记录。");
        var record = matches[0]; var oldPlan = record["OldPlan"]!.AsObject(); var oldState = record["OldState"]!.AsObject();
        if (c.Request.Options.Text("RestoreMode") == "ConfigOnly")
        {
            foreach (var role in DeploymentPlans.Roles[..3]) if (Enabled(c.Plan, role) != Enabled(oldPlan, role)) throw new OperationException("配置恢复需要相同的协议启用状态，请选择完整协议恢复。");
            foreach (var field in new[] { "Reality.XrayVersion", "AnyTls.SingBoxVersion", "Shadowsocks.SingBoxVersion", "Ports.XrayPrimary", "Ports.XrayBackup", "Ports.AnyTlsPrimary", "Ports.LandingShadowsocks" }) if (c.Plan.Text(field) != oldPlan.Text(field)) throw new OperationException("当前程序版本或监听端口与配置归档不兼容。");
        }
        await VerifyRemoteArchive(c, backup + "/protocol-files.tar.gz", record.Text("BackupSha256"));
        var oldSecrets = store.ReadSecret(c.File(record.Text("SecretsRelativePath")));
        try
        {
            await c.Run("maintenance-restore-apply.sh", new() { ["BACKUP_PATH"] = backup, ["SCOPE"] = c.Request.Options.Text("RestoreMode"), ["DESKTOP_PROTOCOL_ONLY"] = "true" }, true, marker: "MANUAL_RESTORE_APPLIED");
            RestoreComponentState(c, oldPlan, oldState, oldSecrets, ["Protocols"]); await RefreshInventory(c); await ServerGate(c); await ValidateProtocols(c); await VerifyManagement(c); await ArchiveConfigs(c);
        }
        finally { oldSecrets.Clear(); }
    }
}
