using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<TaskOutcome> ConfigureWireGuard(OperationRequest request, string taskId, IProgress<TaskProgress> progress, CancellationToken cancellation)
    {
        var preview = WireGuardTunnels.Prepare(store, request); var c = preview.Configuration; var action = request.Options.Text("Action");
        var file = WireGuardTunnels.FileName(store.Paths, c.Text("Id"));
        var record = preview.Record?.DeepClone().AsObject() ?? new JsonObject { ["Version"] = 1, ["Configuration"] = c.DeepClone(), ["Phase"] = "New" };
        var recovering = action == "Recover"; var ownerTask = recovering ? record.Text("Transaction.TaskId") : taskId; _ = TcpChains.Id(ownerTask);
        var steps = OperationSteps.Create(request, new()); var completed = 0; string? activeStep = null;
        progress.Report(new(taskId, "准备", 0, steps.Count, "准备两端 WireGuard 事务。", Steps: steps));
        void Begin(string id) { activeStep = id; progress.Report(new(taskId, id, completed, steps.Count, "正在执行。", id, TaskStepState.Running)); }
        void Done() { progress.Report(new(taskId, activeStep!, ++completed, steps.Count, "已完成。", activeStep, TaskStepState.Completed)); activeStep = null; }
        void SaveRecord() { record["UpdatedAt"] = DateTimeOffset.UtcNow; ArchiveStore.WriteJson(file, record); }
        var child = new InlineProgress<TaskProgress>(p => progress.Report(new(taskId, p.Stage, completed, steps.Count, p.Message, activeStep)));
        var contexts = new List<Context>();
        foreach (var instance in WireGuardTunnels.Instances(c))
        {
            var directory = store.Paths.Instance(instance);
            contexts.Add(new Context(this, new(OperationKind.WireGuardTunnel, instance, request.Options.DeepClone().AsObject()), ownerTask, directory, TcpChains.Plan(store, instance), ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json")), store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json")), child, cancellation));
        }
        var first = contexts[0]; var second = contexts[1];
        async Task<JsonObject> Read(Context context, JsonObject? candidate = null)
        {
            var parameters = new Dictionary<string, string> { ["WIREGUARD_EXPECTED_HASH"] = context.State.Text("WireGuardTunnel.RemoteHash", "Absent") }; if (candidate != null) parameters["CANDIDATE_JSON"] = candidate.ToJsonString();
            var response = await context.Run("wireguard-read.sh", parameters, timeout: 45, marker: "WIREGUARD_READ");
            return JsonNode.Parse(RemoteAssets.Marker(response.Output, "WIREGUARD_STATE"))!.AsObject();
        }
        void CloseLocal(bool restored)
        {
            foreach (var context in contexts)
            {
                if (context.State.Text("WireGuardTunnelTransaction.TaskId") == ownerTask) context.State.Remove("WireGuardTunnelTransaction");
                context.Save();
            }
            if (restored)
            {
                var before = record.At("Transaction.Before")?.DeepClone() as JsonObject; var transaction = record["Transaction"]!.DeepClone();
                record = before ?? new JsonObject { ["Version"] = 1, ["Configuration"] = c.DeepClone(), ["Phase"] = "RolledBack" };
                transaction!["Phase"] = "RolledBack"; transaction.AsObject().Remove("Before"); record["LastTransaction"] = transaction;
            }
            else { record["Phase"] = action == "Remove" ? "Removed" : "Active"; record["Transaction"]!["Phase"] = "Completed"; record["Transaction"]!.AsObject().Remove("Before"); }
            SaveRecord();
        }
        async Task RestoreAll()
        {
            record["Phase"] = "Recovering"; SaveRecord(); var errors = new List<Exception>();
            foreach (var context in contexts.AsEnumerable().Reverse())
            {
                context.Cancellation = CancellationToken.None;
                if (context.Pending?.Text("TaskId") != ownerTask)
                {
                    if (record.Strings("Transaction.Attempted").Contains(context.Request.InstanceRelativePath)) errors.Add(new OperationException("隧道参与事务记录丢失。", true));
                    continue;
                }
                try
                {
                    if (context.Pending.Text("WireGuardTunnelId") != c.Text("Id")) throw new OperationException("隧道本地事务归属不同。", true);
                    var parameters = new Dictionary<string, string> { ["ACTION"] = "Status" }; if (context.Pending.Text("RemoteBackup") != "") parameters["EXPECTED_BACKUP"] = context.Pending.Text("RemoteBackup");
                    var response = await context.Run("maintenance-transaction-status.sh", parameters);
                    var backup = RemoteAssets.Marker(response.Output, "TRANSACTION_BACKUP"); var phase = RemoteAssets.Marker(response.Output, "TRANSACTION_PHASE");
                    if (phase != "None" && RemoteAssets.Marker(response.Output, "CONTROL_TASK_ID", false) != ownerTask) throw new OperationException("远端隧道事务身份不同，未覆盖。", true);
                    if (phase == "Preparing" && context.Pending.Text("Phase") == "Arming")
                    {
                        if ((await Read(context)).Text("Hash") != context.Pending.Text("OldState.WireGuardTunnel.RemoteHash", "Absent")) throw new OperationException("未完成快照的组件已经变化。", true);
                        await context.Run("maintenance-transaction-status.sh", new() { ["ACTION"] = "ReleaseUnarmed", ["EXPECTED_BACKUP"] = backup }, true);
                        ApplyLocalRollback(context); context.Pending["Phase"] = "RolledBack"; context.Save();
                    }
                    else if (phase is "Committed" or "WireGuardCompensating")
                    {
                        await context.Run("wireguard-pair-rollback.sh", new() { ["EXPECTED_BACKUP"] = backup, ["CONTROL_TASK_ID"] = ownerTask, ["WIREGUARD_PAIR_ID"] = c.Text("Id") }, true, 240, "WIREGUARD_PAIR_ROLLED_BACK");
                        ApplyLocalRollback(context); context.Pending["Phase"] = "RolledBack"; context.Save();
                    }
                    else if (phase == "WireGuardRolledBack") { ApplyLocalRollback(context); context.Pending["Phase"] = "RolledBack"; context.Save(); }
                    else await Rollback(context);
                    if ((await Read(context)).Text("Hash") != context.State.Text("WireGuardTunnel.RemoteHash", "Absent")) throw new OperationException("隧道恢复后资源与原归档不同。", true);
                    await VerifyManagement(context);
                }
                catch (Exception error) { errors.Add(error); }
            }
            if (errors.Count > 0) { record["Phase"] = "NeedsRecovery"; SaveRecord(); throw new OperationException("隧道尚未全部恢复，已保留原任务及两端恢复点，请从 WireGuard 隧道继续恢复。", true, "WireGuardNeedsRecovery"); }
            CloseLocal(true);
        }
        async Task<JsonObject> Proof()
        {
            var results = new JsonArray();
            foreach (var (source, destination) in new[] { (first, second), (second, first) })
            {
                var nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)); var id = Guid.NewGuid().ToString("N");
                var parameters = new Dictionary<string, string> { ["PROOF_ID"] = id, ["PROOF_PORT"] = RandomNumberGenerator.GetInt32(40000, 60000).ToString(System.Globalization.CultureInfo.InvariantCulture), ["PROOF_NONCE"] = nonce };
                try
                {
                    await destination.Run("wireguard-proof.sh", new(parameters) { ["ACTION"] = "proof-start" }, timeout: 25, marker: "WIREGUARD_PROOF_DONE");
                    var response = await source.Run("wireguard-proof.sh", new(parameters) { ["ACTION"] = "proof" }, timeout: 25, marker: "WIREGUARD_PROOF_DONE");
                    var proof = JsonNode.Parse(RemoteAssets.Marker(response.Output, "WIREGUARD_PROOF"))!.AsObject();
                    if (proof.Text("Status") != "Passed" || !proof.Flag("TCP") || !proof.Flag("UDP") || !proof.Flag("ResponseMatched") || proof.Text("Scope") != "WireGuardPeerApplication" || proof.Text("ChallengeDigest") != ArchiveStore.Digest(Encoding.UTF8.GetBytes("may-wireguard:" + nonce))) throw new OperationException("隧道缺少匹配本次双向 TCP／UDP 业务证据。");
                    proof["FromInstance"] = source.Request.InstanceRelativePath; results.Add(proof);
                }
                finally
                {
                    var token = destination.Cancellation; destination.Cancellation = CancellationToken.None;
                    try { await destination.Run("wireguard-proof.sh", new(parameters) { ["ACTION"] = "proof-stop" }, timeout: 25, marker: "WIREGUARD_PROOF_DONE"); }
                    finally { destination.Cancellation = token; }
                }
            }
            return new() { ["Status"] = "Passed", ["Scope"] = "BidirectionalWireGuardApplications", ["At"] = DateTimeOffset.UtcNow, ["Directions"] = results, ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(c) };
        }
        try
        {
            if (recovering) { Begin("wg-recovery"); await RestoreAll(); Done(); return TaskOutcome.Completed; }
            Begin("wg-preflight");
            if (action != "Check")
            {
                record["Transaction"] = new JsonObject { ["TaskId"] = ownerTask, ["Action"] = action, ["Phase"] = "Preflight", ["Before"] = preview.Record?.DeepClone(), ["Attempted"] = new JsonArray() };
                record["Phase"] = action == "Remove" ? "Removing" : "Applying"; SaveRecord();
                foreach (var context in contexts) { context.State["WireGuardTunnelTransaction"] = new JsonObject { ["Id"] = c.Text("Id"), ["TaskId"] = ownerTask }; context.Save(); }
            }
            var identities = new HashSet<string>(StringComparer.Ordinal);
            foreach (var (context, index) in contexts.Select((v, i) => (v, i)))
            {
                var audit = await context.Run("audit.sh"); Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
                await VerifyManagement(context);
                await using var session = await context.Session(); var bytes = await session.ReadFileAsync("/etc/machine-id", context.Cancellation);
                try { var identity = Encoding.ASCII.GetString(bytes).Trim().ToLowerInvariant(); if (!System.Text.RegularExpressions.Regex.IsMatch(identity, "^[a-f0-9]{32}$") || !identities.Add(identity)) throw new OperationException("两份隧道归档并非两台独立机器。"); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
                var candidate = action == "Apply" ? WireGuardTunnels.Peer(c, context.Plan, contexts[1 - index].Plan, index == 0) : null;
                var observed = await Read(context, candidate);
                if (observed.Text("Hash") != context.State.Text("WireGuardTunnel.RemoteHash", "Absent") || !JsonNode.DeepEquals(observed["Configuration"], context.Plan["WireGuardTunnel"])) throw new OperationException("实际隧道与本地归档不同，未覆盖。", code: "WireGuardRemoteDrift");
                if (context.Plan.Text("Firewall.Mode") != "PreserveExisting") await context.Run("firewall-preflight.sh", FirewallParameters(context.Plan, true), marker: "FIREWALL_SCOPE_OK");
            }
            Done();
            if (action != "Check")
            {
                Begin("wg-backup");
                foreach (var context in contexts)
                {
                    record["Transaction"]!["Attempted"]!.AsArray().Add(context.Request.InstanceRelativePath); SaveRecord();
                    await Arm(context, context.Plan.Text("Firewall.Mode") == "PreserveExisting" ? ["WireGuardTunnel"] : ["WireGuardTunnel", "Firewall"]);
                }
                Done(); Begin("wg-apply");
                var publics = new string[2];
                if (action == "Apply")
                    foreach (var (context, index) in contexts.Select((v, i) => (v, i)))
                    {
                        await context.Run("wireguard-tools-install.sh", mutation: true, timeout: 180, marker: "WIREGUARD_TOOLS_READY");
                        var response = await context.Run("wireguard-key.sh", mutation: true, timeout: 25, marker: "WIREGUARD_KEY_READY"); publics[index] = RemoteAssets.Marker(response.Output, "WIREGUARD_PUBLIC");
                        if (Convert.FromBase64String(publics[index]).Length != 32) throw new OperationException("远端公钥无效。");
                    }
                foreach (var (context, index) in contexts.Select((v, i) => (v, i)))
                {
                    var peer = action == "Apply" ? WireGuardTunnels.Peer(c, context.Plan, contexts[1 - index].Plan, index == 0) : new JsonObject();
                    if (action == "Apply") { peer["PublicKey"] = publics[index]; peer["PeerPublicKey"] = publics[1 - index]; }
                    if (action == "Apply") context.Plan["WireGuardTunnel"] = peer.DeepClone(); else context.Plan.Remove("WireGuardTunnel"); context.Save();
                    await context.Run("wireguard-apply.sh", new() { ["ACTION"] = action, ["CONFIG_JSON"] = peer.ToJsonString(), ["WIREGUARD_EXPECTED_HASH"] = context.State.Text("WireGuardTunnel.RemoteHash", "Absent") }, true, 90, "WIREGUARD_APPLIED");
                    await Firewall(context, true);
                    var observed = await Read(context);
                    if (action == "Remove" ? observed.Text("Hash") != "Absent" : !JsonNode.DeepEquals(observed["Configuration"], peer) || !observed.Flag("Healthy")) throw new OperationException("实际隧道未完整应用或移除。");
                    if (action == "Remove") context.State.Remove("WireGuardTunnel");
                    else context.State["WireGuardTunnel"] = new JsonObject { ["RemoteHash"] = observed.Text("Hash"), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(peer) };
                    context.Save();
                }
                Done();
            }
            Begin("wg-validation");
            if (action != "Remove") record["Validation"] = await Proof();
            foreach (var context in contexts)
            {
                var observed = await Read(context);
                if (observed.Text("Hash") != context.State.Text("WireGuardTunnel.RemoteHash", "Absent") || action != "Remove" && !observed.Flag("Healthy")) throw new OperationException("验收期间隧道资源或启用状态发生变化。");
                await VerifyManagement(context);
            }
            Done();
            if (action == "Check") { record["LastCheckedAt"] = DateTimeOffset.UtcNow; record["LastCheck"] = new JsonObject { ["Status"] = "Passed" }; SaveRecord(); return TaskOutcome.Completed; }
            Begin("wg-commit"); foreach (var context in contexts) await Commit(context); CloseLocal(false); Done(); return TaskOutcome.Completed;
        }
        catch (Exception failure)
        {
            if (activeStep != null) progress.Report(new(taskId, activeStep, completed, steps.Count, SafeFailures.Describe(failure).Message, activeStep, failure is OperationCanceledException ? TaskStepState.Cancelled : TaskStepState.Failed));
            if (action == "Check") { record["LastCheck"] = new JsonObject { ["Status"] = "Failed", ["At"] = DateTimeOffset.UtcNow }; SaveRecord(); throw; }
            if (recovering) throw;
            await RestoreAll();
            if (failure is OperationCanceledException) throw;
            throw new OperationException("本次隧道操作未完成，两端已按本次范围恢复。" + SafeFailures.Describe(failure).Message, code: "WireGuardOperationFailed");
        }
        finally { foreach (var context in contexts) await context.DisposeAsync(); }
    }
}
