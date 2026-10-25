using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<JsonObject> MayCommand(Context c, string action, bool mutation = false, Dictionary<string, string>? extra = null)
    {
        var fields = extra ?? new(); fields["ACTION"] = action;
        var pending = c.Pending?.Text("Kind") == "MayMonitor" && (c.Request.Kind == OperationKind.Recover || c.Pending.Text("TaskId") == c.Id) ? c.Pending : null;
        fields["ROLE"] = pending?.Text("Role") is { Length: > 0 } pendingRole ? pendingRole : c.Request.Options.Text("Role");
        fields["TASK_ID"] = pending?.Text("TaskId") is { Length: > 0 } pendingId ? pendingId : c.Id;
        var response = await c.Run("may-monitor-lifecycle.sh", fields, mutation, 600);
        var result = JsonNode.Parse(RemoteAssets.Marker(response.Output, "MAY_MONITOR_RESULT"))!.AsObject();
        if (action == "Transaction" && (result.Text("TaskId") != fields["TASK_ID"] || result.Text("Role") != fields["ROLE"])) throw new OperationException("May Monitor 远端事务身份不一致，未重复变更。", true);
        return result;
    }

    private async Task ManageMayMonitor(Context c)
    {
        var options = c.Request.Options; MayMonitorLifecycle.Validate(options);
        var role = options.Text("Role"); var section = MayMonitorLifecycle.Section(role); var action = options.Text("Action");
        var configuration = options["Configuration"]!.DeepClone().AsObject();
        var expected = c.State.Text(section + ".Hash", "Absent"); JsonObject? before = null;
        JsonObject? asset = action is "Install" or "Upgrade" ? MayMonitorLifecycle.Asset(store.Paths, role) : null;
        await c.TrackStep("may-preflight", async () =>
        {
            var audit = await c.Run("audit.sh");
            Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
            await VerifyManagement(c);
            before = await MayCommand(c, "Check", extra: action == "Check" ? new() : new() { ["EXPECTED_HASH"] = expected });
            if (action == "Install" && before.Text("Hash") != "Absent" || action is not ("Install" or "Check" or "Restore") && !before.Flag("Installed")) throw new OperationException("May Monitor 实际安装状态与操作不匹配；保留数据的已移除组件请从备份恢复。");
            if (action == "ConfigureRead")
            {
                var file = store.Paths.Resolve("private/monitor-read.private.json"); var source = store.ReadSecret(file);
                try
                {
                    var connection = MonitorReadConnection.FromJson(source); var authorization = configuration["ReadAuthorization"]!;
                    var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(connection.Token)));
                    if (connection.Identity != options.Text("ReadSourceIdentity") || authorization.Text("Sha256") != sha || !authorization.Strings("Clients").Order(StringComparer.Ordinal).SequenceEqual(connection.Bindings.Values.Order(StringComparer.Ordinal))) throw new OperationException("只读授权与当前连接不一致，请重新审阅授权。");
                }
                finally { source.Clear(); }
            }
            if (action == "Restore")
            {
                var matches = MayMonitorLifecycle.Backups(store, c.Request.InstanceRelativePath, role).Where(v => v.Text("TaskId") == configuration.Text("RestoreTask") && v.Text("Sha256") == configuration.Text("RestoreSha256")).ToArray();
                if (matches.Length != 1) throw new OperationException("缺少唯一、同实例同 May 组件的恢复记录。");
                var restoreDirectory = c.File("maintenance-backups/" + configuration.Text("RestoreTask"));
                if (MayMonitorLifecycle.FileSha256(SafePath.Resolve(restoreDirectory, "may-files.tar.gz")) != configuration.Text("RestoreSha256")) throw new OperationException("本机 May 恢复档案摘要已变化。");
                store.ReadSecret(SafePath.Resolve(restoreDirectory, "may-secret.private.json")).Clear();
            }
        });
        if (action == "Check")
        {
            c.State[section] = before!.DeepClone(); c.Plan[section] = before["Configuration"]?.DeepClone(); c.Save(); return;
        }
        var oldSecret = c.Secrets[section]?.DeepClone();
        if (action == "Install")
        {
            c.Secrets[section] ??= new JsonObject();
            var key = role == "Server" ? "AdminPassword" : "AgentToken";
            if (c.Secrets.Text(section + "." + key) == "")
            {
                var secret = await user.SecretAsync(role == "Server" ? "May Monitor 新管理员密码（含大写、小写和数字）" : "May Monitor Agent Token（服务端已创建节点）", c.Cancellation) ?? throw new OperationCanceledException();
                if (secret.Length < (role == "Server" ? 8 : 12) || secret.Length > 256 || secret.Any(char.IsControl)) throw new OperationException("May Monitor 凭据格式不符合要求。");
                if (role == "Server" && (!secret.Any(char.IsUpper) || !secret.Any(char.IsLower) || !secret.Any(char.IsDigit))) throw new OperationException("May Monitor 管理员密码必须包含大写、小写和数字。");
                if (role == "Agent" && (secret.StartsWith("may_read_", StringComparison.Ordinal) || secret.Any(char.IsWhiteSpace))) throw new OperationException("请使用该节点的独立 Agent Token。");
                c.Secrets.Put(section + "." + key, JsonValue.Create(secret));
            }
            if (role == "Server" && c.Secrets.Text(section + ".SetupToken") == "") c.Secrets.Put(section + ".SetupToken", JsonValue.Create(ServerConfigurations.RandomKey(32).Replace('+', '-').Replace('/', '_').TrimEnd('=')));
        }
        await c.TrackStep("may-backup", async () =>
        {
            c.Pending = new JsonObject { ["Kind"] = "MayMonitor", ["TaskId"] = c.Id, ["Role"] = role, ["Phase"] = "Arming", ["OldPlan"] = c.Plan[section]?.DeepClone(), ["OldState"] = c.State[section]?.DeepClone() };
            var directory = c.File("maintenance-backups/" + c.Id); Directory.CreateDirectory(directory);
            store.WriteSecret(SafePath.Resolve(directory, "may-secret.private.json"), oldSecret as JsonObject ?? new JsonObject()); c.Save();
            var backup = await MayCommand(c, "Begin", true, new() { ["EXPECTED_HASH"] = expected });
            if (backup.Text("Backup") != MayMonitorLifecycle.BackupPath(c.Id) || !System.Text.RegularExpressions.Regex.IsMatch(backup.Text("Sha256"), "^[a-f0-9]{64}$")) throw new OperationException("May Monitor 备份身份未确认。", true);
            c.Pending["RemoteBackup"] = backup.Text("Backup"); c.Pending["Phase"] = "Armed"; c.Pending["BackupSha256"] = backup.Text("Sha256"); c.Save();
            await using var session = await c.Session();
            var archive = SafePath.Resolve(directory, "may-files.tar.gz"); await session.DownloadAsync(backup.Text("Backup") + "/files.tar.gz", archive, c.Cancellation);
            if (MayMonitorLifecycle.FileSha256(archive) != backup.Text("Sha256")) throw new OperationException("May Monitor 备份传输摘要不匹配。");
            ArchiveStore.WriteJson(SafePath.Resolve(directory, "may-monitor.json"), new JsonObject { ["SchemaVersion"] = 1, ["TaskId"] = c.Id, ["Role"] = role, ["Sha256"] = backup.Text("Sha256"), ["BeforeInstalled"] = before!.Flag("Installed"), ["CreatedAt"] = DateTimeOffset.UtcNow, ["OldPlan"] = c.Plan[section]?.DeepClone(), ["OldState"] = c.State[section]?.DeepClone() });
        });
        if (action != "Backup") await c.TrackStep("may-apply", async () =>
        {
            var fields = new Dictionary<string, string> { ["OPERATION"] = action, ["CONFIGURATION"] = configuration.ToJsonString(), ["PRIVATE"] = c.Secrets[section]?.ToJsonString() ?? "{}" };
            if (asset != null) fields["ASSET"] = asset.ToJsonString();
            var after = await MayCommand(c, "Apply", true, fields);
            c.State[section] = after; c.Plan[section] = after["Configuration"]?.DeepClone();
            if (action == "Restore")
            {
                var file = c.File("maintenance-backups/" + configuration.Text("RestoreTask") + "/may-secret.private.json");
                c.Secrets[section] = store.ReadSecret(file);
            }
            c.Save();
        });
        await c.TrackStep("may-verify", async () => { var after = await MayCommand(c, "Check"); c.State[section] = after; await VerifyManagement(c); c.Save(); });
        await c.TrackStep("may-commit", async () =>
        {
            c.Pending!["Phase"] = "LocalPrepared"; c.Save(); var result = await MayCommand(c, "Commit", true);
            if (result.Text("Phase") != "Committed") throw new OperationException("May Monitor 提交未确认。", true);
            c.Pending["Phase"] = "Committed"; c.Pending["CompletedAt"] = DateTimeOffset.UtcNow; c.Save();
        });
    }

    private async Task RecoverMayMonitor(Context c)
    {
        if (c.Pending?.Text("Kind") != "MayMonitor" || !MayMonitorLifecycle.TaskId(c.Pending.Text("TaskId")) || !MayMonitorLifecycle.Roles.Contains(c.Pending.Text("Role"))) throw new OperationException("未知 May Monitor 恢复记录，未操作远端。", true);
        var original = c.Cancellation; c.Cancellation = CancellationToken.None;
        try
        {
            var status = await MayCommand(c, "Transaction");
            if (status.Text("Phase") == "Committed") { c.Pending["Phase"] = "Committed"; c.Save(); return; }
            if (status.Text("Phase") != "RolledBack" && status.Text("Phase") != "None")
            {
                var restored = await MayCommand(c, "Rollback", true);
                if (restored.Text("Phase") != "RolledBack") throw new OperationException("May Monitor 回退未确认。", true);
            }
            var section = MayMonitorLifecycle.Section(c.Pending.Text("Role"));
            foreach (var (target, key) in new[] { (c.Plan, "OldPlan"), (c.State, "OldState") }) { if (c.Pending[key] != null) target[section] = c.Pending[key]!.DeepClone(); else target.Remove(section); }
            var secret = c.File("maintenance-backups/" + c.Pending.Text("TaskId") + "/may-secret.private.json");
            if (File.Exists(secret)) { var old = store.ReadSecret(secret); if (old.Count == 0) c.Secrets.Remove(section); else c.Secrets[section] = old; }
            c.Pending["Phase"] = "RolledBack"; c.Pending["CompletedAt"] = DateTimeOffset.UtcNow; c.Save(); await VerifyManagement(c);
        }
        finally { c.Cancellation = original; }
    }
}
