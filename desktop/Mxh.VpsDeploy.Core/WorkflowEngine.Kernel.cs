using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

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
            if (remote.Number("SchemaVersion") != 1 || remote.Text("Owner") != "mxh-dotnet-kernel-v1" || remote.Text("Id") != expected.Text("Id") || remote.Text("Catalog.Id") != expected.Text("Catalog.Id") || remote.Text("Catalog.Sha256") != expected.Text("Catalog.Sha256")) throw new OperationException("远端内核事务身份或版本不一致，拒绝写入。", true, "KernelIdentityMismatch");
            if (remote.Flag("NoMutationConfirmed") && expected.Text("PreviousTransaction") != "")
            {
                var previous = ArchiveStore.ReadJson(c.File("kernel-history/" + expected.Text("PreviousTransaction") + ".json"));
                if (previous.Text("Id") != expected.Text("PreviousTransaction") || previous.Text("Owner") != "mxh-dotnet-kernel-v1") throw new OperationException("上一内核事务记录身份不一致。", true);
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
            c.Report("kernel-wait", reboot ? "等待 VPS 重启并重新建立已信任的 SSH 连接；不会重复发送重启。" : "安装由 VPS 上的独立任务继续执行；正在读取状态，不重复安装。");
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
                if (c.Request.Options.Text("Source", "Fixed") == "Latest")
                {
                    var anchor = BbrKernels.Catalog(store.Paths);
                    var response = await c.Run("kernel-latest.sh", new() { ["CATALOG"] = anchor.ToJsonString(), ["KEY"] = Convert.ToBase64String(File.ReadAllBytes(store.Paths.Resolve("assets/kernel/xanmod.gpg"))) }, false, 100);
                    var candidate = JsonNode.Parse(RemoteAssets.Marker(response.Output, "KERNEL_RESULT"))!.AsObject();
                    BbrKernels.ValidateCandidate(candidate, anchor); ArchiveStore.WriteJson(c.File("kernel-latest-candidate.json"), candidate);
                    c.Report("kernel-latest", "官方签名已核验，最新兼容 LTS：" + candidate.Text("Catalog.Kernel") + "。安装前会锁定该包的版本和哈希。");
                }
            }); return;
        }
        if (action == "Install")
        {
            var candidate = BbrKernels.Candidate(store.Paths, c.Request.InstanceRelativePath, c.Request.Options.Text("Source", "Fixed"));
            var catalog = candidate["Catalog"]!.AsObject();
            if (catalog.Text("Id") != c.Request.Options.Text("CatalogId") || c.Request.Options.ContainsKey("CatalogSha256") && catalog.Text("Sha256") != c.Request.Options.Text("CatalogSha256")) throw new OperationException("受管内核版本或包哈希变化，请重新审阅。");
            await c.TrackStep("kernel-check", async () =>
            {
                await VerifyManagement(c); var audit = await KernelRun(c, "audit");
                if (!audit.Flag("Compatible")) throw new OperationException("内核兼容性检查未通过：" + string.Join("；", audit.Strings("Reasons")));
                if (audit.Text("Kernel") != catalog.Text("Kernel") && !BbrKernels.CanUpgrade(c.State["KernelUpgrade"] as JsonObject, audit, catalog)) throw new OperationException("当前 v3 内核或事务不支持此升级目标。仅支持从已验收的受管版本升级到更新版本；降级请使用明确的回退操作。", code: "KernelUpgradeTargetRefused");
            });
            if (c.State.Text("LastKernelCheck.Kernel") == catalog.Text("Kernel")) { c.Report("kernel-ready", "目标内核已运行，无需重复安装或重启。"); return; }
            await c.TrackStep("kernel-install", async () =>
            {
                var previous = c.State["KernelUpgrade"] as JsonObject;
                var previousId = previous?.Text("Id", "") ?? "";
                if (previousId != "")
                {
                    if (!System.Text.RegularExpressions.Regex.IsMatch(previousId, "^[a-f0-9]{32}$")) throw new OperationException("上一内核事务身份无效。");
                    ArchiveStore.WriteJson(c.File("kernel-history/" + previousId + ".json"), previous!);
                }
                c.State["KernelUpgrade"] = new JsonObject { ["SchemaVersion"] = 1, ["Owner"] = "mxh-dotnet-kernel-v1", ["Id"] = c.Id, ["Phase"] = "Preparing", ["Catalog"] = catalog.DeepClone(), ["PreviousTransaction"] = previousId }; c.Save();
                var parameters = new Dictionary<string, string> { ["CATALOG"] = catalog.ToJsonString() };
                if (previousId != "") parameters["PREVIOUS_TRANSACTION"] = previousId;
                foreach (var name in new[] { "xanmod.gpg", "InRelease", "Packages.gz" }) parameters["SOURCE_" + name.Replace('.', '_').ToUpperInvariant()] = candidate["Sources"] == null ? Convert.ToBase64String(File.ReadAllBytes(store.Paths.Resolve("assets/kernel/" + name))) : candidate["Sources"]![name]!.ToString();
                await KernelRun(c, "prepare", true, parameters);
                var installed = await WaitKernel(c, false);
                if (installed.Text("Phase") != "Prepared") throw new OperationException("受管内核安装未通过验收。", true, "KernelInstallUnconfirmed", "核对内核事务后结束准备；不要重复安装。");
            });
            c.Report("kernel-ready", "内核安装完成。VPS 仍运行原内核，请在网络调优页审阅重启与验收。"); return;
        }
        if (c.State["KernelUpgrade"] == null) throw new OperationException("此实例没有受管内核事务。");
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
        if (phase == "Booted") await c.TrackStep("kernel-accept", () => KernelAccept(c));
        else if (phase is not ("Prepared" or "Committed" or "RolledBack" or "Aborted")) throw new OperationException("内核事务已读取，仍需按状态处理。", true, "KernelReconciledPending", "安装失败或自动回退后审阅回退旧内核，以结束本轮事务。");
        c.Report("kernel-state", BbrKernels.PhaseLabel(c.State.Text("KernelUpgrade.Phase")));
    }
}
