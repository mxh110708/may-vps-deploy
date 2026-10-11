using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed record InstanceStatus(string Label, bool Managed, bool CanContinue, bool NeedsRecovery, OperationKind ContinueKind, string LastError, string NextAction);

public static class InstanceLifecycle
{
    public static bool HasPending(JsonObject state, JsonObject? pending) =>
        pending != null && pending.Text("Phase") is not ("Committed" or "RolledBack") ||
        state.Text("DeploymentTransaction.Status") is "Arming" or "Armed" or "LocalPrepared" ||
        state.At("MaintenanceTransaction") != null && !state.Flag("MaintenanceTransaction.Committed") ||
        state.Flag("Migration.RollbackArmed") && !state.Flag("Migration.Committed") || BbrKernels.Pending(state);

    public static InstanceStatus Read(ArchiveStore store, string relative, JsonObject plan)
    {
        var directory = store.Paths.Instance(relative);
        var stateFile = SafePath.Resolve(directory, "deployment-state.json");
        var state = File.Exists(stateFile) ? ArchiveStore.ReadJson(stateFile) : new JsonObject();
        var pendingFile = SafePath.Resolve(directory, "operation-pending.dotnet.json");
        var pending = File.Exists(pendingFile) ? ArchiveStore.ReadJson(pendingFile) : null;
        return Describe(plan, state, pending);
    }
    public static InstanceStatus Describe(JsonObject plan, JsonObject state, JsonObject? pending = null)
    {
        var recovery = HasPending(state, pending);
        var imported = plan.Text("Import.Status") == "Completed" || plan.Flag("DesktopImport.OfflineOnly");
        var completed = state.Text("Modules.deployment-commit.Status") == "Success" || state.Text("DeploymentTransaction.Status") == "Committed";
        var managed = imported || completed || state.Text("Engine") != "dotnet-v1" && state["Audit"] != null;
        var importDraft = plan.Text("Import.Status") == "Pending";
        var native = state.Text("Engine") == "dotnet-v1";
        var task = state["LastDeploymentTask"] ?? state["LastTask"];
        var outcome = task.Text("Outcome");
        var label = recovery ? "待恢复 · 存在未确认事务" : managed ? imported ? "已接入归档 · 运行状态需通过健康检查确认" : "已完成部署 · 运行状态需通过健康检查确认" :
            importDraft ? "接入草稿 · 尚未完成接入" : outcome == "Cancelled" ? "部署已取消 · 可继续草稿" : outcome == "Failed" ? "部署失败 · 可继续草稿" : "部署草稿 · 尚未完成部署";
        return new(label, managed, !managed && !recovery && (native || importDraft), recovery,
            importDraft ? OperationKind.ResumeImport : OperationKind.Resume,
            task.Text("SafeError"), task.Text("NextAction"));
    }
}
