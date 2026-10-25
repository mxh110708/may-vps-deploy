using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task VerifyMayMonitorAccess(Context c)
    {
        MayMonitorAccess.Validate(c.Request);
        if (monitorRead == null) throw new OperationException("当前控制端没有 May HTTPS 检查适配器。");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(c.Cancellation); deadline.CancelAfter(TimeSpan.FromSeconds(60));
        var original = c.Cancellation; c.Cancellation = deadline.Token;
        var pilot = c.Request.Options.Text("Action") == "PilotCheck"; var nodeRelative = pilot ? c.Request.Options.Text("NodeInstance") : null;
        var evidence = new JsonObject { ["Status"] = "Checking", ["At"] = DateTimeOffset.UtcNow, ["NodeInstance"] = nodeRelative ?? "" };
        c.State["MayMonitorAccess"] = evidence; c.Save();
        try
        {
            var plan = MayMonitorAccess.ReadPlan(store, c.Request.InstanceRelativePath); var connection = MayMonitorAccess.Connection(store);
            var fingerprint = MayMonitorAccess.EvidenceFingerprint(store, c.Request.InstanceRelativePath, nodeRelative);
            void SourceCurrent()
            {
                if (connection.Identity != c.Request.Options.Text("ConnectionIdentity") || connection.Identity != MayMonitorAccess.Connection(store).Identity || MayMonitorAccess.EvidenceFingerprint(store, c.Request.InstanceRelativePath, nodeRelative) != fingerprint) throw new OperationException("接入计划或只读来源已变化，未保留旧结果为通过。");
            }
            SourceCurrent();
            if (connection.Endpoint.AbsoluteUri != plan.Text("PublicUrl") || !MayMonitorAccess.CanonicalId(plan.Text("ServerInstanceId"))) throw new OperationException("请先升级并核对 May 服务身份，使用同一网址保存只读连接和接入计划。");
            c.Report("May 服务端归属", "正在经管理连接核对选定 May 服务端。");
            var serverResult = await c.Run("may-monitor-lifecycle.sh", new() { ["ACTION"] = "Check", ["ROLE"] = "Server", ["EXPECTED_HASH"] = c.State.Text("MayMonitorServer.Hash") }, timeout: 20);
            var server = JsonNode.Parse(RemoteAssets.Marker(serverResult.Output, "MAY_MONITOR_RESULT"))!.AsObject();
            if (!server.Flag("Installed") || !server.Flag("Active") || server.Text("Hash") != c.State.Text("MayMonitorServer.Hash") || server.Text("Configuration.InstanceId") != plan.Text("ServerInstanceId") || server.Number("Configuration.Port") != plan.Number("Port")) throw new OperationException("选定 May 服务端未运行，或身份／监听地址与接入计划不一致。");
            evidence["ServerOwned"] = true;
            async Task<MonitorReadSnapshot> Snapshot()
            {
                SourceCurrent(); var result = await monitorRead.FetchAsync(connection, c.Cancellation); SourceCurrent();
                if (result.ServerInstanceId != plan.Text("ServerInstanceId")) throw new OperationException("HTTPS 响应来自不同或未标识的 May 服务端；没有仅凭版本号判定成功。");
                if (result.Nodes.Keys.Any(id => !connection.Bindings.Values.Contains(id, StringComparer.Ordinal))) throw new OperationException("HTTPS 返回了授权绑定之外的节点。");
                return result;
            }
            c.Report("May HTTPS 身份", "正在通过正常 TLS 和专用只读凭据核验服务身份。");
            var snapshot = await Snapshot(); evidence["HttpsIdentity"] = true; evidence["ServerInstanceId"] = snapshot.ServerInstanceId;
            if (pilot)
            {
                if (!connection.Bindings.TryGetValue(nodeRelative!, out var id)) throw new OperationException("试用实例没有明确的只读 UUID 绑定。");
                var nodeDirectory = store.Paths.Instance(nodeRelative!); var nodePlan = ArchiveStore.ReadJson(SafePath.Resolve(nodeDirectory, "deployment-plan.json")); var nodeState = MayMonitorAccess.State(store, nodeRelative!);
                if (nodeRelative != nodePlan.Text("Provider") + "/" + nodePlan.Text("Instance") + "/May-VPS-Deploy") throw new OperationException("试用实例与归档身份不一致，未连接该节点。");
                if (!InstanceLifecycle.Read(store, nodeRelative!, nodePlan).Managed || InstanceLifecycle.Read(store, nodeRelative!, nodePlan).NeedsRecovery) throw new OperationException("试用实例未完成纳管或存在待恢复事务。");
                if (!nodeState.Flag("MayMonitorAgent.Installed") || !nodeState.Flag("MayMonitorAgent.Active")) throw new OperationException("试用实例的 May Agent 尚未安装或运行。");
                var nodeSecrets = store.ReadSecret(SafePath.Resolve(nodeDirectory, "secrets.dotnet.private.json"));
                await using (var node = new Context(this, c.Request with { InstanceRelativePath = nodeRelative! }, c.Id, nodeDirectory, nodePlan, nodeState, nodeSecrets, c.Progress, c.Cancellation))
                {
                    c.Report("May Agent 身份", "正在只读核验 Agent 实际凭据对应的节点和服务端。");
                    var response = await node.Run("may-monitor-lifecycle.sh", new() { ["ACTION"] = "VerifyAgent", ["ROLE"] = "Agent", ["EXPECTED_HASH"] = nodeState.Text("MayMonitorAgent.Hash") }, timeout: 20);
                    var confirmed = JsonNode.Parse(RemoteAssets.Marker(response.Output, "MAY_MONITOR_RESULT"))!;
                    if (confirmed.Text("StateHash") != nodeState.Text("MayMonitorAgent.Hash") || confirmed.Text("ClientUUID") != id || confirmed.Text("ServerInstanceId") != snapshot.ServerInstanceId || MonitorReadConnection.ValidateEndpoint(confirmed.Text("Endpoint")).AbsoluteUri != MonitorReadConnection.ValidateEndpoint(nodeState.Text("MayMonitorAgent.Configuration.Endpoint")).AbsoluteUri) throw new OperationException("Agent 凭据、服务端身份或地址与试用绑定不一致。");
                }
                evidence["AgentIdentity"] = true;
                var reports = new HashSet<DateTimeOffset>(); var samples = new JsonArray(); DateTimeOffset? previous = null;
                for (var index = 0; index < 3; index++)
                {
                    if (index > 0) { await Task.Delay(TimeSpan.FromSeconds(3), c.Cancellation); snapshot = await Snapshot(); }
                    if (!snapshot.Nodes.TryGetValue(id, out var sample) || sample.Status(DateTimeOffset.UtcNow, snapshot.ReceivedAt, false) != "在线" || sample.ReportAt == null || sample.Metrics == null) throw new OperationException("试用节点没有新鲜、有效的在线指标；未判定可迁移。");
                    if ((DateTimeOffset.UtcNow - snapshot.CapturedAt).Duration() > TimeSpan.FromSeconds(15) || snapshot.CapturedAt - sample.ReportAt.Value > TimeSpan.FromSeconds(15) || previous is { } last && sample.ReportAt.Value < last) throw new OperationException("试用上报过旧或时间倒退；未判定可迁移。");
                    reports.Add(sample.ReportAt.Value); samples.Add(new JsonObject { ["ReportAt"] = sample.ReportAt, ["CpuPercent"] = sample.Metrics.CpuPercent, ["MemoryUsed"] = sample.Metrics.MemoryUsed, ["MemoryTotal"] = sample.Metrics.MemoryTotal });
                    previous = sample.ReportAt;
                    c.Report("May 连续上报", "已读取第 " + (index + 1) + " 次有效快照。");
                }
                if (reports.Count < 2) throw new OperationException("节点上报没有推进；保留旧监控并继续检查。");
                evidence["Samples"] = samples; evidence["Status"] = "ReadyForTrial";
            }
            else evidence["Status"] = "HttpsVerified";
            SourceCurrent(); evidence["Fingerprint"] = fingerprint; evidence["At"] = DateTimeOffset.UtcNow; c.Save();
        }
        catch (Exception error)
        {
            evidence["Status"] = error is OperationCanceledException && original.IsCancellationRequested ? "Cancelled" : "Failed";
            evidence["At"] = DateTimeOffset.UtcNow; evidence.Remove("Samples"); c.Save();
            if (error is OperationCanceledException && !original.IsCancellationRequested) throw new OperationException("May 接入检查超时；旧监控没有变更。");
            throw;
        }
        finally { c.Cancellation = original; }
    }
}
