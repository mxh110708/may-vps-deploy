using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<TaskOutcome> ConfigureTcpChain(OperationRequest request, string taskId, IProgress<TaskProgress> progress, CancellationToken cancellation)
    {
        var preview = TcpChains.Prepare(store, request); var configuration = preview.Configuration; var action = request.Options.Text("Action");
        var file = TcpChains.FileName(store.Paths, configuration.Text("Id"));
        var record = preview.Record?.DeepClone().AsObject() ?? new JsonObject { ["Version"] = 1, ["Configuration"] = configuration.DeepClone(), ["Phase"] = "New" };
        if (action == "Apply") record["LandingPort"] = TcpForwarding.Rules(preview.RelayConfiguration).Single(r => r.Text("Validation.ChainId") == configuration.Text("Id")).Number("TargetPort");
        var recovering = action == "Recover";
        var ownerTask = recovering ? record.Text("Transaction.TaskId") : taskId;
        _ = TcpChains.Id(ownerTask);
        var steps = OperationSteps.Create(request, new JsonObject()); var completed = 0; string? activeStep = null;
        progress.Report(new(taskId, "准备", 0, steps.Count, "正在准备跨实例执行计划。", Steps: steps));
        void Begin(string id) { activeStep = id; progress.Report(new(taskId, id, completed, steps.Count, "正在执行。", id, TaskStepState.Running)); }
        void Done() { progress.Report(new(taskId, activeStep!, ++completed, steps.Count, "已完成。", activeStep, TaskStepState.Completed)); activeStep = null; }
        var childProgress = new InlineProgress<TaskProgress>(p => progress.Report(new(taskId, p.Stage, completed, steps.Count, p.Message, activeStep)));
        var contexts = new List<Context>();
        foreach (var instance in TcpChains.Instances(configuration))
        {
            var directory = store.Paths.Instance(instance); var plan = TcpChains.Plan(store, instance);
            var state = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-state.json"));
            var secrets = store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"));
            contexts.Add(new Context(this, new(OperationKind.TcpChain, instance, request.Options.DeepClone().AsObject()), ownerTask, directory, plan, state, secrets, childProgress, cancellation));
        }
        var front = contexts[0]; var relay = contexts[1]; var landing = contexts[2];
        void SaveRecord() { record["UpdatedAt"] = DateTimeOffset.UtcNow; ArchiveStore.WriteJson(file, record); }
        void Report(string stage, string message) => progress.Report(new(taskId, stage, completed, steps.Count, message, activeStep));
        async Task<JsonObject> Read(Context c, JsonObject? candidate = null)
        {
            var parameters = new Dictionary<string, string> { ["ARCHIVED_HASH"] = c.State.Text("TcpForwarding.RemoteHash", "Absent") };
            if (candidate != null) parameters["CANDIDATE_JSON"] = candidate.ToJsonString();
            var response = await c.Run("tcp-forward-read.sh", parameters, marker: "TCP_FORWARD_READ");
            return JsonNode.Parse(RemoteAssets.Marker(response.Output, "TCP_FORWARD_STATE"))!.AsObject();
        }
        async Task LandingGate()
        {
            var source = TcpChains.Source(store, configuration);
            try
            {
                var role = source.Text("ManagedOrigin.Role");
                var path = role switch { "RealityEntry" => "/usr/local/etc/xray/config.json", "AnyTlsEntry" => "/etc/sing-box-anytls/config.json", "ShadowsocksLanding" => "/etc/sing-box/config.json", _ => throw new OperationException("落地协议来源不受支持。") };
                var hash = landing.State.Text("ServerConfigHashes." + role);
                if (hash.Length != 64 || !landing.Plan.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.Uses(landing.Plan, role))) throw new OperationException("落地缺少已启用协议的配置摘要，请先接入并核对归档。");
                await using var session = await landing.Session(); var bytes = await session.ReadFileAsync(path, landing.Cancellation);
                try { if (ArchiveStore.Digest(bytes) != hash) throw new OperationException("落地实际协议配置与归档不同，未应用线路。", code: "TcpChainLandingDrift"); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            finally { source.Clear(); }
        }
        async Task ExistingValidation(Context c)
        {
            var ordinary = (c.Plan["TcpForwarding"]?.DeepClone() ?? TcpForwarding.Empty()).AsObject();
            foreach (var rule in ordinary["Rules"]!.AsArray().OfType<JsonObject>().Where(r => r.Text("Validation.Type") == "TcpChain").ToArray()) ordinary["Rules"]!.AsArray().Remove(rule);
            JsonObject result = new() { ["Status"] = "Passed", ["Items"] = new JsonArray() };
            if (TcpForwarding.Rules(ordinary).Any(r => r.Flag("Enabled")))
            {
                if (tcpForwarding == null) throw new OperationException("现有转发验收适配器不可用。");
                result = await tcpForwarding.ValidateAsync(c.Plan, ordinary, c.File("tcp-chain-validation/" + ownerTask), new InlineProgress<string>(m => Report("原有转发验收", m)), c.Cancellation);
                TcpForwarding.RequireValidation(ordinary, result);
            }
            if (c.State["TcpForwarding"] is JsonObject current) current["Validation"] = result;
        }
        async Task<JsonObject> ValidateChain()
        {
            Report("分段验收", "分别从中转连接落地、从前置连接中转；TCP 可连接结果与整链代理验收分别记录。");
            var evidence = new JsonArray();
            var source = TcpChains.Source(store, configuration);
            var targetPort = source.Number("sing_box.server_port"); source.Clear();
            foreach (var (c, host, port) in new[] { (relay, landing.Plan.Text("Server.IPv4"), targetPort), (front, relay.Plan.Text("Server.IPv4"), configuration.Number("RelayPort")) })
            {
                var response = await c.Run("tcp-chain-probe.sh", new() { ["ADDRESS"] = host, ["PORT"] = port.ToString(System.Globalization.CultureInfo.InvariantCulture) }, timeout: 20, marker: "TCP_CHAIN_PROBED");
                var probe = JsonNode.Parse(RemoteAssets.Marker(response.Output, "TCP_CHAIN_PROBE"))!.AsObject();
                if (probe.Text("Status") != "Connected" || probe.Text("Scope") != "TcpConnectOnly" || probe.Text("Address") != host || probe.Number("Port") != port) throw new OperationException("分段连接证据不完整。");
                probe["FromInstance"] = c.Request.InstanceRelativePath; evidence.Add(probe);
            }
            if (tcpChains == null) throw new OperationException("整条 TCP 代理线路验收适配器不可用，未提交变更。");
            var node = TcpChains.Project(store, configuration, "TCP chain validation");
            JsonObject result;
            try
            {
                result = await tcpChains.ValidateAsync(node, front.File("tcp-chain-validation/" + ownerTask), new InlineProgress<string>(m => Report("整链代理 HTTPS 验收", m)), front.Cancellation);
                result["Segments"] = evidence; result["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(configuration);
                ArchiveStore.WriteJson(front.File("tcp-chain-validation/" + ownerTask + "/whole-chain.json"), result);
                TcpChains.RequireValidation(configuration, node, result);
            }
            finally { node.Clear(); }
            result["Segments"] = evidence; result["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(configuration); return result;
        }
        void CloseLocal(bool rolledBack)
        {
            var before = record.At("Transaction.Before") as JsonObject;
            var active = rolledBack ? before?.Text("Phase") == "Active" : record.Text("Transaction.Action") != "Remove";
            foreach (var c in contexts)
            {
                if (active) c.Plan["TcpChain"] = new JsonObject { ["Id"] = configuration.Text("Id"), ["FrontInstance"] = configuration.Text("FrontInstance"), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(configuration) };
                else if (c.Plan.Text("TcpChain.Id") == configuration.Text("Id")) c.Plan.Remove("TcpChain");
                if (c.State.Text("TcpChainTransaction.TaskId") == ownerTask) c.State.Remove("TcpChainTransaction");
                c.Save();
            }
            if (rolledBack)
            {
                var transaction = record["Transaction"]!.DeepClone();
                record = before?.DeepClone().AsObject() ?? new JsonObject { ["Version"] = 1, ["Configuration"] = configuration.DeepClone(), ["Phase"] = "RolledBack" };
                transaction!["Phase"] = "RolledBack"; transaction.AsObject().Remove("Before"); record["LastTransaction"] = transaction;
            }
            else
            {
                record["Phase"] = active ? "Active" : "Removed";
                record["Transaction"]!["Phase"] = "Completed"; record["Transaction"]!.AsObject().Remove("Before");
            }
            SaveRecord();
        }
        async Task RestoreAll()
        {
            Report("恢复跨实例线路", "核对每台任务身份，恢复前置后恢复中转；已提交的参与实例也按同一快照范围补偿，不重放应用命令。");
            record["Phase"] = "Recovering"; SaveRecord(); var errors = new List<Exception>();
            foreach (var c in new[] { front, relay })
            {
                c.Cancellation = CancellationToken.None;
                if (c.Pending?.Text("TaskId") != ownerTask)
                {
                    if (record.At("Transaction.Attempted")?.Strings("Instances").Contains(c.Request.InstanceRelativePath) == true) errors.Add(new OperationException("参与实例的本地事务记录丢失或被其他任务替换。", true));
                    continue;
                }
                try
                {
                    if (c.Pending.Text("TcpChainId") != configuration.Text("Id")) throw new OperationException("本地参与事务不属于此线路。", true);
                    var parameters = new Dictionary<string, string> { ["ACTION"] = "Status" };
                    if (c.Pending.Text("RemoteBackup") != "") parameters["EXPECTED_BACKUP"] = c.Pending.Text("RemoteBackup");
                    var response = await c.Run("maintenance-transaction-status.sh", parameters);
                    var backup = RemoteAssets.Marker(response.Output, "TRANSACTION_BACKUP"); var phase = RemoteAssets.Marker(response.Output, "TRANSACTION_PHASE");
                    if (RemoteAssets.Marker(response.Output, "CONTROL_TASK_ID", false) != ownerTask && phase != "None") throw new OperationException("远端事务身份不同，未恢复其他任务的内容。", true);
                    if (phase == "Preparing" && c.Pending.Text("Phase") == "Arming")
                    {
                        var unchanged = await Read(c);
                        if (unchanged.Text("Hash") != c.Pending.Text("OldState.TcpForwarding.RemoteHash", "Absent")) throw new OperationException("尚未建立快照的实例资源已变化，未清除事务归属。", true);
                        await c.Run("maintenance-transaction-status.sh", new() { ["ACTION"] = "ReleaseUnarmed", ["EXPECTED_BACKUP"] = backup }, true);
                        ApplyLocalRollback(c); c.Pending["Phase"] = "RolledBack"; c.Save();
                    }
                    else if (phase is "Committed" or "Compensating")
                    {
                        await c.Run("tcp-chain-rollback.sh", new() { ["EXPECTED_BACKUP"] = backup, ["CONTROL_TASK_ID"] = ownerTask, ["TCP_CHAIN_ID"] = configuration.Text("Id") }, true, 360, "TCP_CHAIN_ROLLED_BACK");
                        ApplyLocalRollback(c); c.Pending["Phase"] = "RolledBack"; c.Save();
                    }
                    else if (phase == "ChainRolledBack") { ApplyLocalRollback(c); c.Pending["Phase"] = "RolledBack"; c.Save(); }
                    else await Rollback(c);
                    var observed = await Read(c);
                    if (observed.Text("Hash") != c.State.Text("TcpForwarding.RemoteHash", "Absent")) throw new OperationException("恢复后的实际转发与旧归档不同。", true);
                    await VerifyManagement(c);
                }
                catch (Exception error) { errors.Add(error); }
            }
            if (errors.Count > 0)
            {
                record["Phase"] = "NeedsRecovery"; SaveRecord();
                throw new OperationException("跨实例线路尚未全部恢复。已保留两台的原任务身份和快照，请从跨实例编排重新恢复；未写入其他任务的资源。", true, "TcpChainNeedsRecovery");
            }
            CloseLocal(true);
        }
        try
        {
            if (recovering) { Begin("chain-recovery"); await RestoreAll(); Done(); Report("跨实例恢复完成", "两台转发和管理连接已核对恢复，线路依赖记录已同步。"); return TaskOutcome.Completed; }
            Begin("chain-preflight");
            if (action != "Check")
            {
                var before = preview.Record?.DeepClone();
                record["Transaction"] = new JsonObject { ["TaskId"] = ownerTask, ["Action"] = action, ["Phase"] = "Preflight", ["Before"] = before, ["StartedAt"] = DateTimeOffset.UtcNow };
                record["Phase"] = action == "Remove" ? "Removing" : "Applying"; SaveRecord();
                foreach (var c in contexts)
                {
                    c.State["TcpChainTransaction"] = new JsonObject { ["Id"] = configuration.Text("Id"), ["TaskId"] = ownerTask, ["FrontInstance"] = configuration.Text("FrontInstance") }; c.Save();
                }
            }
            Report("核对全部参与实例", "先核对身份、SSH、已保存配置、端口与白名单，尚未修改远端。");
            var machineIdentities = new HashSet<string>(StringComparer.Ordinal);
            foreach (var c in action == "Remove" ? new[] { front, relay } : contexts.ToArray())
            {
                await using var session = await c.Session(); var bytes = await session.ReadFileAsync("/etc/machine-id", c.Cancellation);
                try
                {
                    var identity = System.Text.Encoding.ASCII.GetString(bytes).Trim();
                    if (!System.Text.RegularExpressions.Regex.IsMatch(identity, "^[a-fA-F0-9]{32}$") || !machineIdentities.Add(identity.ToLowerInvariant())) throw new OperationException("参与实例缺少独立机器身份，或多个归档实际指向同一台机器，未修改远端。");
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            foreach (var c in new[] { front, relay })
            {
                var audit = await c.Run("audit.sh");
                Supported(new JsonObject { ["OsId"] = RemoteAssets.Marker(audit.Output, "OS_ID"), ["OsVersion"] = RemoteAssets.Marker(audit.Output, "OS_VERSION"), ["Architecture"] = RemoteAssets.Marker(audit.Output, "ARCH") });
                await VerifyManagement(c);
                var observed = await Read(c, action == "Check" ? null : c == front ? preview.FrontConfiguration : preview.RelayConfiguration);
                if (observed.Text("Hash") != c.State.Text("TcpForwarding.RemoteHash", "Absent") || !JsonNode.DeepEquals(observed["Configuration"], c.Plan["TcpForwarding"])) throw new OperationException("线路参与实例的实际转发与归档不同，未继续应用。", code: "TcpChainRemoteDrift");
                if (action != "Check" && c.Plan.Text("Firewall.Mode") != "PreserveExisting") await c.Run("firewall-preflight.sh", FirewallParameters(c.Plan, true), marker: "FIREWALL_SCOPE_OK");
            }
            if (action != "Remove") { await VerifyManagement(landing); await LandingGate(); }
            Done();
            if (action != "Check")
            {
                Begin("chain-backup");
                Report("建立两台恢复点", "分别保存 TCP 转发与本次涉及的受管防火墙，启用远端限时回退。");
                record["Transaction"]!["Attempted"] = new JsonObject { ["Instances"] = new JsonArray() }; SaveRecord();
                foreach (var c in new[] { relay, front })
                {
                    record["Transaction"]!["Attempted"]!["Instances"]!.AsArray().Add(c.Request.InstanceRelativePath); SaveRecord();
                    await Arm(c, c.Plan.Text("Firewall.Mode") == "PreserveExisting" ? ["TcpForwarding"] : ["TcpForwarding", "Firewall"]);
                }
                record["Transaction"]!["Phase"] = "Armed"; SaveRecord();
                Done(); Begin("chain-apply");
                foreach (var c in action == "Remove" ? new[] { front, relay } : new[] { relay, front })
                {
                    var config = c == front ? preview.FrontConfiguration : preview.RelayConfiguration;
                    var remove = !TcpForwarding.Rules(config).Any(); var expected = c.State.Text("TcpForwarding.RemoteHash", "Absent");
                    if (remove) c.Plan.Remove("TcpForwarding"); else c.Plan["TcpForwarding"] = config.DeepClone(); c.Save();
                    await c.Run("tcp-forward-apply.sh", new() { ["ACTION"] = remove ? "Remove" : "Apply", ["CONFIG_JSON"] = config.ToJsonString(), ["EXPECTED_HASH"] = expected }, true, 120, "TCP_FORWARD_APPLIED");
                    await Firewall(c, true);
                    var observed = await Read(c);
                    if (remove ? observed.Text("Hash") != "Absent" : !JsonNode.DeepEquals(observed["Configuration"], config)) throw new OperationException("实际线路规则与审阅配置不同。");
                    if (remove) c.State.Remove("TcpForwarding");
                    else c.State["TcpForwarding"] = new JsonObject { ["RemoteHash"] = observed.Text("Hash"), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(config), ["TemplateCurrent"] = observed.Flag("TemplateCurrent", true) };
                    c.Save();
                }
                Done();
            }
            Begin("chain-validation");
            foreach (var c in new[] { front, relay }) await ExistingValidation(c);
            if (action != "Remove")
            {
                var result = await ValidateChain(); record["Validation"] = result;
                foreach (var c in new[] { front, relay })
                {
                    var rule = TcpForwarding.Rules(c.Plan["TcpForwarding"]!.AsObject()).Single(r => r.Text("Id") == TcpChains.RuleId(configuration, c == front));
                    c.State["TcpForwarding"]!["Validation"]!["Items"]!.AsArray().Add(new JsonObject { ["Id"] = rule.Text("Id"), ["Status"] = "Passed", ["From"] = "Controller", ["Scope"] = "TcpChainEndToEnd", ["Checks"] = new JsonArray(new JsonObject { ["Address"] = c.Plan.Text("Server.IPv4"), ["Type"] = "TcpChain", ["Status"] = "Passed", ["ChainId"] = configuration.Text("Id"), ["ConfigurationFingerprint"] = ArchiveStore.Fingerprint(configuration), ["Result"] = result.DeepClone() }) });
                }
                await LandingGate();
            }
            foreach (var c in new[] { front, relay })
            {
                var observed = await Read(c);
                if (observed.Text("Hash") != c.State.Text("TcpForwarding.RemoteHash", "Absent")) throw new OperationException("验收期间转发资源发生变化，未提交。");
                await VerifyManagement(c); c.Save();
            }
            Done();
            if (action == "Check") { record["LastCheckedAt"] = DateTimeOffset.UtcNow; record["LastCheck"] = new JsonObject { ["Status"] = "Passed", ["At"] = DateTimeOffset.UtcNow }; SaveRecord(); Report("线路检查完成", "分段 TCP 与整链代理 HTTPS 通过；未修改远端。"); return TaskOutcome.Completed; }
            record["Transaction"]!["Phase"] = "Validated"; SaveRecord();
            Begin("chain-commit");
            Report("提交两台参与实例", "整条线路验收通过，逐台核对提交。任何提交中断都进入协调恢复，不重放应用。");
            foreach (var c in new[] { relay, front }) await Commit(c);
            record["FrontHash"] = front.State.Text("TcpForwarding.RemoteHash", "Absent"); record["RelayHash"] = relay.State.Text("TcpForwarding.RemoteHash", "Absent");
            CloseLocal(false); Done(); Report("跨实例线路完成", action == "Remove" ? "已移除本条线路，原有转发及落地代理保留。" : "已完成前置、中转与落地的整链验收，可在配置设计中添加线路节点。"); return TaskOutcome.Completed;
        }
        catch (Exception failure)
        {
            if (activeStep != null) { progress.Report(new(taskId, activeStep, completed, steps.Count, failure is OperationCanceledException ? "已请求取消，正在核对恢复。" : SafeFailures.Describe(failure).Message, activeStep, failure is OperationCanceledException ? TaskStepState.Cancelled : TaskStepState.Failed)); activeStep = null; }
            if (action == "Check") { record["LastCheck"] = new JsonObject { ["Status"] = "Failed", ["At"] = DateTimeOffset.UtcNow, ["Code"] = SafeFailures.Describe(failure).Code }; SaveRecord(); throw; }
            if (recovering) throw;
            await RestoreAll();
            if (failure is OperationCanceledException) throw;
            var safe = SafeFailures.Describe(failure);
            throw new OperationException("本次跨实例操作未完成，已核对恢复两台转发。" + safe.Message, code: safe.Code);
        }
        finally { foreach (var c in contexts) await c.DisposeAsync(); }
    }
}
