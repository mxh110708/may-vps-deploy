using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed partial class WorkflowEngine(ArchiveStore store, IRemoteSessionFactory connections, IManagedKeyStore keys, IUserInteraction user, IProtocolValidation validation, INetworkMeasurement? network = null) : IOperationWorkflow
{
    private readonly RemoteAssets assets = new(store.Paths);
    private ArchiveStore Store => store;
    private IUserInteraction User => user;
    private IRemoteSessionFactory Connections => connections;
    private JsonObject Versions => ArchiveStore.ReadJson(store.Paths.Resolve("config/versions.json"));

    public async Task<TaskOutcome> ExecuteAsync(OperationRequest request, string taskId, IProgress<TaskProgress> progress, CancellationToken cancellationToken)
    {
        var directory = store.Paths.Instance(request.InstanceRelativePath);
        var planFile = SafePath.Resolve(directory, "deployment-plan.json");
        var initial = request.Kind is OperationKind.Deploy or OperationKind.ConnectExisting;
        if (initial && File.Exists(planFile)) throw new OperationException("此实例已有本地归档。未完成部署可继续草稿，或删除本地实例后重新创建。", code: "InstanceAlreadyExists", nextAction: "在实例页选择继续部署、继续接入或删除实例。");
        var plan = initial ? request.Options["Plan"]?.DeepClone().AsObject() ?? throw new OperationException("缺少部署计划。") : ArchiveStore.ReadJson(planFile);
        if (request.InstanceRelativePath != plan.Text("Provider") + "/" + plan.Text("Instance") + "/MXH-VPS-Deploy") throw new OperationException("所选实例与归档身份不一致。");
        if (initial) DeploymentPlans.Validate(plan, request.Kind == OperationKind.ConnectExisting);
        var stateFile = SafePath.Resolve(directory, "deployment-state.json");
        var state = File.Exists(stateFile) ? ArchiveStore.ReadJson(stateFile) : new JsonObject { ["SchemaVersion"] = 1, ["CurrentManagementPort"] = plan.Number("Server.BootstrapSshPort"), ["Modules"] = new JsonObject(), ["BackupDirectories"] = new JsonObject() };
        var secretsFile = SafePath.Resolve(directory, "secrets.dotnet.private.json");
        var secrets = File.Exists(secretsFile) ? store.ReadSecret(secretsFile) : File.Exists(SafePath.Resolve(directory, "deployment-secrets.private.json")) ? ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-secrets.private.json")) : new JsonObject();
        await using var context = new Context(this, request, taskId, directory, plan, state, secrets, progress, cancellationToken);
        var kernelRecovery = request.Kind == OperationKind.Recover && BbrKernels.Pending(state);
        var nonKernelState = state.DeepClone().AsObject(); nonKernelState.Remove("KernelUpgrade");
        var otherPending = InstanceLifecycle.HasPending(nonKernelState, context.Pending);
        if (kernelRecovery && otherPending) throw new OperationException("存在其他未完成事务，不能混合内核恢复范围。请先核对其他事务。", true, "PendingTransaction");
        if (request.Kind == OperationKind.BbrKernel && (otherPending || BbrKernels.Pending(state) && request.Options.Text("Action") == "Install")) throw new OperationException("存在未完成事务，请先核对；不能开始另一轮内核安装。", true, "PendingTransaction");
        if (request.Kind != OperationKind.Recover && request.Kind != OperationKind.BbrKernel && context.HasPending()) throw new OperationException("存在未完成事务，请先核对并恢复。", true, "PendingTransaction", "先在实例页核对事务状态，再按明确范围恢复。");
        if (initial) { context.State["Engine"] = "dotnet-v1"; context.Save(); }
        context.State["LastTask"] = new JsonObject { ["Id"] = taskId, ["Kind"] = request.Kind.ToString(), ["Outcome"] = "Running", ["StartedAt"] = DateTimeOffset.UtcNow };
        context.Save();
        try
        {
            context.StartSteps();
            switch (request.Kind)
            {
                case OperationKind.ConnectExisting: await Import(context); break;
                case OperationKind.ResumeImport:
                    if (plan.Text("Import.Status") != "Pending") throw new OperationException("该归档不是未完成的接入草稿。");
                    await Import(context); break;
                case OperationKind.Deploy:
                case OperationKind.Resume: await Deploy(context); break;
                case OperationKind.HealthAudit: await Health(context); break;
                case OperationKind.TunnelAccess: await VerifyTunnelAccess(context); break;
                case OperationKind.Recover:
                    if (kernelRecovery) { context.Request.Options["Action"] = "Reconcile"; await ManageBbrKernel(context); }
                    else await Recover(context); break;
                case OperationKind.BbrKernel: await ManageBbrKernel(context); break;
                case OperationKind.CheckComponentUpdate: await CheckComponentUpdate(context); break;
                case OperationKind.InstallComponent: await InstallComponent(context); break;
                case OperationKind.MeasureNetwork: await MeasureNetwork(context); break;
                case OperationKind.TuneNetwork: await TuneMeasuredNetwork(context); break;
                default: await Maintain(context); break;
            }
            var outcome = context.Warnings ? TaskOutcome.CompletedWithWarnings : TaskOutcome.Completed;
            context.Finish(outcome); return outcome;
        }
        catch (Exception failure)
        {
            var interruptedStage = context.CurrentStage;
            if (request.Kind == OperationKind.BbrKernel || kernelRecovery)
            {
                var kernelError = SafeFailures.Describe(failure, BbrKernels.Pending(context.State));
                context.Finish(kernelError.NeedsRecovery ? TaskOutcome.NeedsRecovery : failure is OperationCanceledException ? TaskOutcome.Cancelled : TaskOutcome.Failed, kernelError);
                throw kernelError;
            }
            var recovered = false;
            if (context.Pending != null && context.Pending.Text("Phase") is not ("Committed" or "RolledBack"))
            {
                context.Pending["InterruptedStage"] = interruptedStage;
                try { await Rollback(context); recovered = context.Pending.Text("Phase") == "RolledBack"; }
                catch { var uncertain = new OperationException("操作结果或回滚未确认，备份已保留。", true, "RollbackUnconfirmed", "先核对该实例的未完成事务，不能自动重复写入。"); context.Finish(TaskOutcome.NeedsRecovery, uncertain); throw uncertain; }
            }
            if (context.Pending?.Text("Phase") == "Committed" && context.Pending.Text("TaskId") == context.Id)
            {
                if (request.Kind == OperationKind.InstallComponent) context.ReconciledCompletion("installation-commit", "远端提交已按事务身份核对。原确认未收到，安装已完成，无需重复执行。");
                context.Finish(TaskOutcome.CompletedWithWarnings); return TaskOutcome.CompletedWithWarnings;
            }
            if (recovered) context.Report(interruptedStage, failure is OperationCanceledException ? "已取消，本次组件范围已恢复。" : "本次组件范围已恢复，记录保留原失败步骤。");
            if (context.State.Text("DeploymentTransaction.Status") is "Arming" or "Armed" or "LocalPrepared")
            {
                var safe = SafeFailures.Describe(failure);
                var uncertain = new OperationException("部署中断：" + safe.Message, true, safe.Code, "本次部署基线尚未确认结束。先核对事务状态，再选择恢复操作。");
                context.Finish(TaskOutcome.NeedsRecovery, uncertain); throw uncertain;
            }
            if (failure is OperationCanceledException) { context.Finish(TaskOutcome.Cancelled); throw; }
            var error = SafeFailures.Describe(failure, context.MutationStarted && context.Pending?.Text("Phase") != "RolledBack");
            if (request.Kind == OperationKind.TuneNetwork && recovered && error.NeedsRecovery)
                error = new OperationException(error.Message, false, error.Code, "本次网络运行参数、队列和管理连接已核对恢复；保留记录，重新采集并审阅后再执行。");
            context.Finish(error.NeedsRecovery ? TaskOutcome.NeedsRecovery : TaskOutcome.Failed, error); throw error;
        }
    }

    private sealed class Context(WorkflowEngine owner, OperationRequest request, string taskId, string directory, JsonObject plan, JsonObject state, JsonObject secrets, IProgress<TaskProgress> progress, CancellationToken cancellationToken) : IAsyncDisposable
    {
        public OperationRequest Request { get; } = request;
        public string Id { get; } = taskId;
        public string Directory { get; } = directory;
        public JsonObject Plan { get; } = plan;
        public JsonObject State { get; } = state;
        public JsonObject Secrets { get; } = secrets;
        public CancellationToken Cancellation { get; set; } = cancellationToken;
        public JsonObject? Pending { get; set; } = System.IO.File.Exists(SafePath.Resolve(directory, "operation-pending.dotnet.json")) ? ArchiveStore.ReadJson(SafePath.Resolve(directory, "operation-pending.dotnet.json")) : null;
        public bool Warnings { get; set; }
        public bool MutationStarted { get; set; }
        public string CurrentStage { get; private set; } = "准备";
        public int Port => State.Number("CurrentManagementPort", Plan.Number("Ports.SshPrimary", Plan.Number("Server.BootstrapSshPort")));
        private readonly Dictionary<string, string> passwords = new(StringComparer.Ordinal);
        private string? passphrase;
        public string? KeyPassphrase { get => passphrase; set => passphrase = value; }
        public JsonObject? RestoreRecord { get; set; }
        private int stage;
        private string? activeStep;
        private int completedSteps;
        private IReadOnlyList<PlannedTaskStep> plannedSteps = [];
        public string File(string relative) => SafePath.Resolve(Directory, relative);
        public void StartSteps() { plannedSteps = OperationSteps.Create(Request, Plan); if (plannedSteps.Count > 0) progress.Report(new(Id, "准备", 0, plannedSteps.Count, "正在准备执行计划。", Steps: plannedSteps)); }
        public void Report(string stageName, string message) { CurrentStage = stageName; progress.Report(new(Id, stageName, plannedSteps.Count == 0 ? ++stage : completedSteps, plannedSteps.Count, message, activeStep)); }
        public async Task TrackStep(string id, Func<Task> action, bool alreadyCompleted = false)
        {
            activeStep = id; CurrentStage = id;
            progress.Report(new(Id, id, completedSteps, plannedSteps.Count, alreadyCompleted ? "此步骤已在本次保留的部署事务中完成。" : "正在执行。", id, TaskStepState.Running));
            try
            {
                Cancellation.ThrowIfCancellationRequested(); if (!alreadyCompleted) await action();
                progress.Report(new(Id, id, ++completedSteps, plannedSteps.Count, alreadyCompleted ? "已完成，沿用保留结果。" : "已完成。", id, TaskStepState.Completed));
            }
            catch (Exception error)
            {
                var message = error is OperationCanceledException ? "已请求取消，正在核对恢复边界。" : SafeFailures.Describe(error).Message;
                progress.Report(new(Id, id, completedSteps, plannedSteps.Count, message, id, error is OperationCanceledException ? TaskStepState.Cancelled : TaskStepState.Failed)); throw;
            }
            finally { activeStep = null; }
        }
        public void ReconciledCompletion(string id, string message)
        {
            CurrentStage = id;
            progress.Report(new(Id, id, ++completedSteps, plannedSteps.Count, message, id, TaskStepState.Completed));
        }
        public bool HasPending() => InstanceLifecycle.HasPending(State, Pending);
        public void Finish(TaskOutcome outcome, OperationException? error = null)
        {
            State.Put("LastTask.Outcome", JsonValue.Create(outcome.ToString())); State.Put("LastTask.Stage", JsonValue.Create(CurrentStage));
            State.Put("LastTask.FinishedAt", JsonValue.Create(DateTimeOffset.UtcNow)); State.Put("LastTask.RemoteMutationStarted", JsonValue.Create(MutationStarted));
            State.Put("LastTask.SafeError", error?.Message == null ? null : JsonValue.Create(error.Message));
            State.Put("LastTask.ErrorCode", error?.Code == null ? null : JsonValue.Create(error.Code));
            State.Put("LastTask.NextAction", error?.NextAction == null ? null : JsonValue.Create(error.NextAction));
            if (Request.Kind is OperationKind.Deploy or OperationKind.Resume or OperationKind.ConnectExisting or OperationKind.ResumeImport) State["LastDeploymentTask"] = State["LastTask"]!.DeepClone();
            Save();
        }
        public void Save()
        {
            ArchiveStore.WriteJson(File("deployment-plan.json"), Plan);
            owner.Store.WriteSecret(File("secrets.dotnet.private.json"), Secrets);
            ArchiveStore.WriteJson(File("deployment-state.json"), State);
            if (Pending != null) ArchiveStore.WriteJson(File("operation-pending.dotnet.json"), Pending);
        }
        public async Task<IRemoteSession> Session(int? port = null, string username = "root", bool bootstrap = false)
        {
            var key = bootstrap ? Plan.Text("Server.BootstrapKeyPath") : File("ssh/" + AppPaths.Segment(Plan.Text("SshKey.ManagedFileName", "id_vps_management")));
            if (!System.IO.File.Exists(key)) key = Plan.Text("SshKey.SourcePrivateKeyPath", Plan.Text("Server.BootstrapKeyPath"));
            if (key == "" || !System.IO.File.Exists(key))
            {
                if (!passwords.TryGetValue(username, out var password))
                {
                    password = username == Plan.Text("AdminUser") ? Secrets.Text("AdminPassword") : "";
                    if (password.Length == 0) password = await owner.User.SecretAsync(username + " 的 SSH 登录密码", Cancellation) ?? throw new OperationCanceledException();
                    passwords[username] = password;
                }
                return await owner.Connections.OpenAsync(new(Plan.Text("Server.IPv4"), port ?? Port, username, null, password), owner.User, Cancellation);
            }
            try { return await owner.Connections.OpenAsync(new(Plan.Text("Server.IPv4"), port ?? Port, username, key, KeyPassphrase: passphrase), owner.User, Cancellation); }
            catch (KeyPassphraseRequiredException) when (passphrase == null)
            {
                // A retry is allowed only while opening authentication, before any command is sent.
                passphrase = await owner.User.SecretAsync("SSH 私钥口令（未加密可留空）", Cancellation) ?? throw new OperationCanceledException();
                return await owner.Connections.OpenAsync(new(Plan.Text("Server.IPv4"), port ?? Port, username, key, KeyPassphrase: passphrase), owner.User, Cancellation);
            }
        }
        public async Task<CommandResult> Run(string asset, Dictionary<string, string>? parameters = null, bool mutation = false, int timeout = 600, string? marker = null, int? port = null, bool bootstrap = false)
        {
            Cancellation.ThrowIfCancellationRequested(); parameters ??= [];
            if (mutation && !asset.StartsWith("kernel-", StringComparison.Ordinal) && asset is not ("protocol-migration-trigger-rollback.sh" or "maintenance-transaction-commit.sh" or "maintenance-transaction-status.sh") && Pending?.Text("RemoteBackup") is { Length: > 0 } backup) parameters["EXPECTED_TRANSACTION"] = backup;
            Report(asset[..^3], mutation ? "正在执行受管步骤，取消将在安全边界处理。" : "正在读取远端状态。");
            await using var session = await Session(port, bootstrap: bootstrap);
            if (mutation) { MutationStarted = true; if (Pending != null) { Pending["Stage"] = asset; Save(); } }
            var result = await session.RunScriptAsync(owner.assets.Payload(asset, parameters), TimeSpan.FromSeconds(timeout), mutation, Cancellation);
            if (marker != null) RemoteAssets.RequireMarker(result, marker); else result.RequireSuccess("远端步骤失败：" + asset);
            return result;
        }
        public async Task VerifySsh(int port, string username, bool sudo = false)
        {
            await using var session = await Session(port, username);
            if (sudo)
            {
                var nonInteractive = await session.RunScriptAsync("set -euo pipefail\nsudo -n true\nprintf 'VPSDEPLOY_SSH_OK\\n'\n", TimeSpan.FromSeconds(60), false, Cancellation);
                if (nonInteractive.ExitCode == 0) { RemoteAssets.RequireMarker(nonInteractive, "SSH_OK"); return; }
            }
            // Never put the actual sudo password into command arguments; upload via the private script channel.
            var sudoPassword = Secrets.Text("AdminPassword");
            if (sudo && sudoPassword.Length == 0 && !passwords.TryGetValue(username, out sudoPassword)) sudoPassword = await owner.User.SecretAsync(username + " 的 sudo 密码", Cancellation) ?? throw new OperationCanceledException();
            var script = sudo ? "set -euo pipefail\npw=$(printf '%s' '" + Convert.ToBase64String(Encoding.UTF8.GetBytes(sudoPassword)) + "' | base64 -d)\nprintf '%s\\n' \"$pw\" | sudo -S -p '' true\nprintf 'VPSDEPLOY_SSH_OK\\n'\n" : "printf 'VPSDEPLOY_SSH_OK\\n'\n";
            var result = await session.RunScriptAsync(script, TimeSpan.FromSeconds(60), false, Cancellation); RemoteAssets.RequireMarker(result, "SSH_OK");
        }
        public ValueTask DisposeAsync() { passwords.Clear(); passphrase = null; Secrets.Clear(); return ValueTask.CompletedTask; }
    }
}

public interface IProtocolValidation
{
    Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject secrets, string privateDirectory, IUserInteraction user, IProgress<string> progress, CancellationToken cancellationToken);
    void Export(JsonObject plan, JsonObject secrets, string directory);
}
