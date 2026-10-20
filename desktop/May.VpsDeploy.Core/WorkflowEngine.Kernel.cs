using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<JsonObject> KernelRun(Context c, string action, bool mutation = false, Dictionary<string, string>? parameters = null)
    {
        parameters ??= [];
        if (action != "audit") parameters["TRANSACTION"] = c.State.Text("KernelUpgrade.Id");
        if (action == "status") parameters["CATALOG"] = c.State["KernelUpgrade"]!["Catalog"]!.ToJsonString();
        var result = await c.Run("kernel-" + action + ".sh", parameters, mutation, 150);
        var remote = JsonNode.Parse(RemoteAssets.Marker(result.Output, "KERNEL_RESULT"))!.AsObject();
        if (action == "audit") { c.State["LastKernelCheck"] = remote.DeepClone(); c.State.Put("LastKernelCheck.At", JsonValue.Create(DateTimeOffset.UtcNow.ToString("O"))); }
        else
        {
            var expected = c.State["KernelUpgrade"]!.AsObject();
            if (remote.Number("SchemaVersion") != 2 || remote.Text("Owner") != BbrKernels.Owner || remote.Text("Id") != expected.Text("Id") || remote["Catalog"] is not JsonObject remoteCatalog || ArchiveStore.Fingerprint(remoteCatalog) != ArchiveStore.Fingerprint(expected["Catalog"]!.AsObject())) throw new OperationException("远端内核事务身份、源码提交或内置包指纹不一致，拒绝写入。", true, "KernelIdentityMismatch");
            if (remote.Flag("NoMutationConfirmed") && expected.Text("PreviousTransaction") != "")
            {
                var previous = ArchiveStore.ReadJson(c.File("kernel-history/" + expected.Text("PreviousTransaction") + ".json"));
                if (previous.Text("Id") != expected.Text("PreviousTransaction") || previous.Text("Owner") != BbrKernels.Owner) throw new OperationException("上一内核事务记录身份不一致。", true);
                c.State["KernelUpgrade"] = previous; remote = previous;
            }
            else c.State["KernelUpgrade"] = remote.DeepClone();
        }
        c.Save(); return remote;
    }
    private async Task<JsonObject> WaitKernel(Context c, bool reboot)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(reboot ? 210 : 900); JsonObject? status = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            c.Cancellation.ThrowIfCancellationRequested();
            try { status = await KernelRun(c, "status"); }
            catch (OperationException error) when (reboot && (error.Code is "SshTimeout" or "SshDisconnected" or "SshNetworkConnectionRefused" or "SshNetworkTimedOut" or "SshNetworkHostUnreachable" or "SshNetworkNetworkUnreachable" or "SshNetworkConnectionReset")) { status = null; }
            if (status != null && (reboot ? status.Text("Phase") is not ("BootRequested" or "RollbackRequested") : status.Text("Phase") != "Installing")) return status;
            c.Report("kernel-wait", reboot ? "等待 VPS 重启并重新建立已信任的 SSH 连接；不会重复发送重启。" : "内核安装由 VPS 独立任务继续执行；正在读取状态，不重复执行。");
            await Task.Delay(TimeSpan.FromSeconds(5), c.Cancellation);
        }
        throw new OperationException("内核任务尚未确认结束，事务和旧内核已保留。", true, "KernelAwaitingReconciliation", "重新打开网络调优，核对内核事务；若 VPS 未进入系统，从服务商控制台重启，单次启动后的默认项仍是旧内核。");
    }
    private async Task KernelAccept(Context c)
    {
        var status = await KernelRun(c, "status");
        if (status.Text("Phase") == "Committed") { await VerifyManagement(c); return; }
        if (status.Text("Phase") != "Booted" || status.Text("Runtime.Kernel") != status.Text("Catalog.Kernel") || status.Text("Runtime.BbrVersion") != "v3" || !status.Flag("ServicesHealthy")) throw new OperationException("新内核、BBR v3 或原服务未通过验收。旧内核仍是默认启动项。", true, "KernelAcceptanceFailed", "核对内核事务或审阅回退旧内核。");
        await VerifyManagement(c);
        try { await KernelRun(c, "confirm", true); }
        catch
        {
            var reconciled = await KernelRun(c, "status");
            if (reconciled.Text("Phase") != "Committed") throw;
            c.Warnings = true;
        }
    }
    private async Task ManageBbrKernel(Context c)
    {
        BbrKernels.Validate(c.Request.Options); var action = c.Request.Options.Text("Action");
        if (action == "Check")
        {
            await c.TrackStep("kernel-check", async () =>
            {
                await VerifyManagement(c); var audit = await KernelRun(c, "audit");
                if (!audit.Flag("Compatible")) throw new OperationException("内核兼容性检查未通过：" + string.Join("；", audit.Strings("Reasons")), code: "KernelIncompatible", nextAction: "查看内核与网络配置中的兼容性结果；先解决所列问题，再检查或安装内核。");
            }); return;
        }
        if (action == "Install")
        {
            var catalog = BbrKernels.Catalog(store.Paths);
            if (catalog.Text("Id") != c.Request.Options.Text("CatalogId") || catalog.Text("Sha256") != c.Request.Options.Text("CatalogSha256") || catalog.Text("Commit") != c.Request.Options.Text("SourceCommit")) throw new OperationException("官方源码提交或材料指纹变化，请重新审阅。");
            await c.TrackStep("kernel-check", async () =>
            {
                await VerifyManagement(c); var audit = await KernelRun(c, "audit");
                if (!audit.Flag("Compatible")) throw new OperationException("内核兼容性检查未通过：" + string.Join("；", audit.Strings("Reasons")));
                if (audit.Text("Kernel") != catalog.Text("Kernel") && !BbrKernels.CanUpgrade(c.State["KernelUpgrade"] as JsonObject, audit, catalog)) throw new OperationException("当前 v3 内核或事务不支持此升级目标。仅支持从已验收的受管版本升级到更新版本；降级请使用明确的回退操作。", code: "KernelUpgradeTargetRefused");
            });
            if (c.State.Text("LastKernelCheck.Kernel") == catalog.Text("Kernel")) { c.Report("kernel-ready", "目标内核已运行，无需重复安装或重启。"); return; }
            await c.TrackStep("kernel-install", async () =>
            {
                string? uploaded = null;
                IRemoteSession? transfer = null;
                try
                {
                    {
                        BbrKernels.ValidatePrebuilt(store.Paths, catalog);
                        c.Report("kernel-upload", "正在上传已校验的内置内核包；VPS 无需编译工具，安装前再次核对 SHA256。");
                        transfer = await c.Session();
                        var staged = await transfer.UploadTemporaryFileAsync(store.Paths.Resolve("assets/kernel/kernel.deb"), c.Cancellation);
                        if (!System.Text.RegularExpressions.Regex.IsMatch(staged, @"^/tmp/mxh-vps\.[A-Za-z0-9]{10}/kernel\.deb$")) throw new OperationException("内核上传返回的路径无效。");
                        uploaded = staged;
                    }
                    var previous = c.State["KernelUpgrade"] as JsonObject;
                    var previousId = previous?.Text("Id", "") ?? "";
                    if (previousId != "")
                    {
                        if (previous!.Text("Owner") != BbrKernels.Owner) throw new OperationException("不支持此来源的旧内核事务，未迁移或覆盖其记录。");
                        if (!System.Text.RegularExpressions.Regex.IsMatch(previousId, "^[a-f0-9]{32}$")) throw new OperationException("上一内核事务身份无效。");
                        ArchiveStore.WriteJson(c.File("kernel-history/" + previousId + ".json"), previous!);
                    }
                    c.State["KernelUpgrade"] = new JsonObject { ["SchemaVersion"] = 2, ["Owner"] = BbrKernels.Owner, ["Id"] = c.Id, ["Phase"] = "Preparing", ["Catalog"] = catalog.DeepClone(), ["PreviousTransaction"] = previousId }; c.Save();
                    var parameters = new Dictionary<string, string> { ["CATALOG"] = catalog.ToJsonString() };
                    if (uploaded != null) parameters["PACKAGE_PATH"] = uploaded;
                    if (previousId != "") parameters["PREVIOUS_TRANSACTION"] = previousId;
                    foreach (var name in BbrKernels.SourceNames) parameters["SOURCE_" + name.Replace('.', '_').ToUpperInvariant()] = Convert.ToBase64String(File.ReadAllBytes(store.Paths.Resolve("assets/kernel/" + name)));
                    await KernelRun(c, "prepare", true, parameters);
                    var installed = await WaitKernel(c, false);
                    if (installed.Text("Phase") != "Prepared") throw SafeFailures.Kernel(installed.Text("FailureCode"), true) ?? new OperationException("受管内核安装未通过验收。", true, "KernelInstallUnconfirmed", "核对内核事务后结束准备；不要重复安装。");
                }
                finally
                {
                    if (uploaded != null && transfer != null)
                    {
                        try
                        {
                            // The path has already passed the fixed /tmp upload grammar.
                            await transfer.RunAsync("rm -f -- '" + uploaded + "'; rmdir -- '" + uploaded[..uploaded.LastIndexOf('/')] + "'", TimeSpan.FromSeconds(30), CancellationToken.None);
                        }
                        catch { /* No replay on connection loss; reconcile the kernel transaction. */ }
                    }
                    if (transfer != null) await transfer.DisposeAsync();
                }
            });
            c.Report("kernel-ready", "内核安装完成。VPS 仍运行原内核，请在网络调优页审阅重启与验收。"); return;
        }
        if (c.State["KernelUpgrade"] == null) throw new OperationException("此实例没有受管内核事务。");
        if (c.State.Text("KernelUpgrade.Owner") != BbrKernels.Owner) throw new OperationException("此内核事务不是本应用的 Google 官方源码构建事务，拒绝处理。");
        await c.TrackStep("kernel-state", async () => { await KernelRun(c, "status"); });
        if (action == "Activate")
        {
            await c.TrackStep("kernel-reboot", async () => { c.State.Put("KernelUpgrade.Phase", JsonValue.Create("BootRequested")); c.Save(); await KernelRun(c, "boot", true); await WaitKernel(c, true); });
            await c.TrackStep("kernel-accept", () => KernelAccept(c)); return;
        }
        if (action is "Rollback" or "RollbackOriginal")
        {
            await c.TrackStep("kernel-rollback", async () =>
            {
                c.State.Put("KernelUpgrade.Phase", JsonValue.Create("RollbackRequested")); c.Save();
                await KernelRun(c, "rollback", true, new() { ["ROLLBACK_TARGET"] = action == "RollbackOriginal" ? "Original" : "Previous" });
                var status = c.State.Text("KernelUpgrade.Phase") == "RollbackRequested" ? await WaitKernel(c, true) : await KernelRun(c, "status");
                var target = action == "RollbackOriginal" ? status.Text("OriginalKernel", status.Text("OldKernel")) : status.Text("OldKernel");
                if (status.Text("Phase") is not ("RolledBack" or "Aborted") || status.Text("Runtime.Kernel") != target) throw new OperationException("所选回退内核尚未确认启动。", true, "KernelRollbackUnconfirmed");
                await VerifyManagement(c);
            }); return;
        }
        var phase = c.State.Text("KernelUpgrade.Phase");
        if (phase is "Installing" or "BootRequested" or "RollbackRequested") { await WaitKernel(c, phase != "Installing"); phase = c.State.Text("KernelUpgrade.Phase"); }
        if (phase == "InstallFailed" && SafeFailures.Kernel(c.State.Text("KernelUpgrade.FailureCode"), true) is { } failure) throw failure;
        if (phase == "Booted") await c.TrackStep("kernel-accept", () => KernelAccept(c));
        else if (phase is not ("Prepared" or "Committed" or "RolledBack" or "Aborted")) throw new OperationException("内核事务已读取，仍需按状态处理。", true, "KernelReconciledPending", "安装失败或自动回退后审阅回退旧内核，以结束本轮事务。");
        c.Report("kernel-state", BbrKernels.PhaseLabel(c.State.Text("KernelUpgrade.Phase")));
    }
}
