using System.Globalization;
using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<JsonObject> NetworkObservation(Context c, JsonObject? options = null, CancellationToken? token = null, NetworkMeasurementPath? path = null)
    {
        var port = options?.Text("Protocol") == "AnyTlsEntry" ? c.Plan.Number("Ports.AnyTlsPrimary") : options?.Text("Protocol") == "ShadowsocksLanding" ? c.Plan.Number("Ports.LandingShadowsocks") : c.Plan.Number("Ports.XrayPrimary");
        var parameters = new Dictionary<string, string> { ["ACTION"] = "Observe", ["TCP_PORT"] = port.ToString(CultureInfo.InvariantCulture) };
        if (options?.Text("Family") is "IPv4" or "IPv6") parameters["TCP_FAMILY"] = options.Text("Family");
        if (path?.ObservedInboundAddress is { Length: > 0 } peer) parameters["TCP_PEER_ADDRESS"] = peer;
        if (path?.Entry != null) { parameters["UPSTREAM_ADDRESS"] = path.Node.SingBox.Text("server"); parameters["UPSTREAM_PORT"] = path.Node.SingBox.Text("server_port"); }
        await using var session = await c.Session();
        var result = await session.RunScriptAsync(assets.Payload("network-audit.sh", parameters), TimeSpan.FromSeconds(30), false, token ?? c.Cancellation);
        result.RequireSuccess("网络只读采集失败。");
        return JsonNode.Parse(RemoteAssets.Marker(result.Output, "NETWORK_AUDIT"))!.AsObject();
    }
    private async Task<JsonObject> CaptureNetwork(Context c, JsonObject options, string id)
    {
        NetworkTuning.ValidateMeasurement(options);
        if (NetworkTuning.Families(options).Contains("IPv6") && c.Plan.Text("Server.IPv6") == "") throw new OperationException("实例没有 IPv6 地址，不能把双栈采集降为 IPv4 通过。");
        var started = DateTimeOffset.UtcNow; var records = new List<JsonObject>();
        var fingerprint = NetworkTuning.SelectionFingerprint(store, c.Plan, c.Secrets, options, c.Request.InstanceRelativePath);
        foreach (var selected in NetworkTuning.SelectedPaths(options))
        {
            c.Report("网络路径测量", NetworkTuning.PathLabel(selected) + " · 双向采集，共用本次总预算。");
            records.Add(await CaptureNetworkPath(c, selected, id));
        }
        if (fingerprint != NetworkTuning.SelectionFingerprint(store, c.Plan, c.Secrets, options, c.Request.InstanceRelativePath)) throw new OperationException("采集期间所选路径变化，请重新测量。");
        var report = records[0];
        if (records.Count > 1) report = new JsonObject
        {
            ["SchemaVersion"] = 2, ["Id"] = id, ["StartedAt"] = started.ToString("O"), ["At"] = DateTimeOffset.UtcNow.ToString("O"),
            ["SourceFingerprint"] = NetworkTuning.SourceFingerprint(c.Plan, c.Secrets), ["PathFingerprint"] = fingerprint, ["Options"] = options.DeepClone(),
            ["ServerBefore"] = records[0]["ServerBefore"]!.DeepClone(), ["ServerAfter"] = records[^1]["ServerAfter"]!.DeepClone(),
            ["Client"] = new JsonObject { ["Status"] = records.All(r => r.Text("Client.Status") == "Measured") ? "Measured" : "Incomplete", ["EvidencePolicy"] = NetworkTuning.EvidencePolicy,
                ["EgressVerified"] = records.All(r => r.Flag("Client.EgressVerified")), ["ReservedPayloadBytes"] = records.Sum(r => r.Long("Client.ReservedPayloadBytes")) },
            ["Paths"] = new JsonArray(records.Select(r => r.DeepClone()).ToArray())
        };
        report["Analysis"] = NetworkTuning.Analyze(report, NetworkTuning.History(c.Directory));
        ArchiveStore.WriteJson(c.File("network-measurements/" + id + ".json"), report);
        c.State["LastNetworkMeasurement"] = new JsonObject { ["Id"] = id, ["At"] = report["At"]!.DeepClone() };
        var preferences = options.DeepClone().AsObject(); preferences.Remove("Scheduled"); preferences.Remove("BudgetFamilyCount"); preferences["EvidencePolicy"] = NetworkTuning.EvidencePolicy; c.Plan["NetworkPreferences"] = preferences;
        c.Save(); return report;
    }
    private async Task<JsonObject> CaptureNetworkPath(Context c, JsonObject options, string id)
    {
        if (network == null) throw new OperationException("当前运行环境没有后台网络测量适配器。");
        NetworkTuning.ValidateMeasurement(options);
        var started = DateTimeOffset.UtcNow;
        if (!Enabled(c.Plan, options.Text("Protocol"))) throw new OperationException("请选择正在启用的代理协议。");
        if (NetworkTuning.Topology(options) is "Entry" or "Relay" && !NetworkTuning.IsEntry(c.Plan)) throw new OperationException("实例不具备入口用途。");
        if (options.Text("Family") == "IPv6" && c.Plan.Text("Server.IPv6") == "") throw new OperationException("实例没有 IPv6 地址。");
        using var path = NetworkTuning.ResolvePath(store, c.Plan, c.Secrets, options, c.Request.InstanceRelativePath);
        var before = await NetworkObservation(c, options, path: path);
        var outbound = new JsonObject(); JsonObject client;
        if (NetworkTuning.Topology(options) == "ForwardOnly") client = new JsonObject { ["Status"] = "NotMeasured", ["EvidencePolicy"] = NetworkTuning.EvidencePolicy, ["EgressVerified"] = false };
        else
        {
            var supplemental = await c.Run("network-audit.sh", new() { ["ACTION"] = "Outbound", ["BYTES"] = (Math.Min(NetworkTuning.PayloadBudget(options) / 8, 8388608) - 65536).ToString(CultureInfo.InvariantCulture) }, timeout: 60);
            outbound = JsonNode.Parse(RemoteAssets.Marker(supplemental.Output, "NETWORK_AUDIT"))!.AsObject();
            client = await network.MeasureAsync(path, options, c.Directory, t => NetworkObservation(c, options, t, path),
                new InlineProgress<string>(message => c.Report("网络路径测量", message)), c.Cancellation);
        }
        var after = client["ServerAfter"]?.DeepClone().AsObject() ?? await NetworkObservation(c, options, path: path);
        using var currentPath = NetworkTuning.ResolvePath(store, c.Plan, c.Secrets, options, c.Request.InstanceRelativePath);
        if (path.Fingerprint != currentPath.Fingerprint) throw new OperationException("测量途中路径归档变化，未将结果作为调优依据。");
        client.Remove("ServerAfter");
        var report = new JsonObject { ["SchemaVersion"] = 1, ["Id"] = NetworkTuning.Id(id), ["StartedAt"] = started.ToString("O"), ["At"] = DateTimeOffset.UtcNow.ToString("O"),
            ["SourceFingerprint"] = NetworkTuning.SourceFingerprint(c.Plan, c.Secrets), ["PathFingerprint"] = path.Fingerprint, ["Options"] = options.DeepClone(),
            ["ServerBefore"] = before, ["ServerAfter"] = after, ["Client"] = client, ["VpsOutbound"] = outbound };
        report["Analysis"] = NetworkTuning.Analyze(report, NetworkTuning.History(c.Directory));
        return report;
    }
    private async Task MeasureNetwork(Context c)
    {
        OperationPolicy.Validate(c.Request);
        await c.TrackStep("network-connection", () => c.VerifySsh(c.Port, "root"));
        JsonObject? report = null;
        await c.TrackStep("network-measurement", async () => report = await CaptureNetwork(c, c.Request.Options, c.Id));
        await c.TrackStep("network-analysis", () =>
        {
            c.Warnings = report!.Text("Client.Status") != "Measured";
            c.Report("网络建议已保存", report.Text("Analysis.Profile") == "EntryMeasured" ? "建议已生成；需审阅后才能应用，当前未修改网络参数。" : "信息不足以精细调优；保留自动缓冲，仅提供基础配置建议。");
            return Task.CompletedTask;
        });
    }
    private async Task TuneMeasuredNetwork(Context c)
    {
        OperationPolicy.Validate(c.Request);
        var profile = c.Request.Options.Text("Profile"); JsonObject? before = null; JsonObject? current = null;
        await c.TrackStep("network-preflight", async () =>
        {
            if (profile == "LandingBasic" && NetworkTuning.IsEntry(c.Plan) || profile != "LandingBasic" && !NetworkTuning.IsEntry(c.Plan)) throw new OperationException("实例用途已变化，请重新读取调优页面。");
            await VerifyManagement(c);
            if (profile == "EntryMeasured")
            {
                before = NetworkTuning.ReadReport(c.Directory, c.Request.Options.Text("MeasurementId"));
                if (ClientSchemes.SourceFingerprint(c.File("network-measurements/" + before.Text("Id") + ".json")) != c.Request.Options.Text("MeasurementSha256") || before.Text("SourceFingerprint") != NetworkTuning.SourceFingerprint(c.Plan, c.Secrets)) throw new OperationException("测量记录或实例协议已变化，请重新测速并审阅。");
                if (!DateTimeOffset.TryParse(before.Text("At"), out var at) || at > DateTimeOffset.UtcNow.AddMinutes(1) || at < DateTimeOffset.UtcNow.AddHours(-24)) throw new OperationException("测量结果超过 24 小时，请重新采集。");
                NetworkTuning.ValidateMeasurement(before["Options"]!.AsObject());
                var measuredPath = NetworkTuning.SelectionFingerprint(store, c.Plan, c.Secrets, before["Options"]!.AsObject(), c.Request.InstanceRelativePath);
                if (before.Text("PathFingerprint") != measuredPath || before.Text("Client.EvidencePolicy") != NetworkTuning.EvidencePolicy) throw new OperationException("路径证据来自旧版，或中转落地已变化，请重新采集。");
                var analysis = NetworkTuning.Analyze(before, NetworkTuning.History(c.Directory));
                if (analysis.Text("Profile") != "EntryMeasured") throw new OperationException("该记录不足以支持缓冲调整，请重新测量或选择基础配置。");
                before["Analysis"] = analysis;
            }
            current = await NetworkObservation(c, before?["Options"] as JsonObject);
            if (c.Request.Options.Text("BbrVersion", "Current") == "v3" && !BbrKernels.AcceptedRuntime(c.State, current)) throw new OperationException("所选 Google 源码 BBR v3 尚未完成受管安装和验收，不能仅凭运行版本认定来源。", code: "NetworkBbrSourceUnverified", nextAction: "先完成 Google 官方源码内核的构建、重启与验收；如需沿用 VPS 已有内核，请选择原有内核版本。");
            if (c.Request.Options.Text("BbrVersion", "Current") == "Current" && c.State["KernelUpgrade"] is JsonObject kernel && current.Text("Kernel") != kernel.Text("OriginalKernel", kernel.Text("OldKernel"))) throw new OperationException("已选择 VPS 原有内核版本，请先审阅回到 VPS 原有内核；当前运行的是升级后的内核。");
            if (before != null && (current.Text("Kernel") != before.Text("ServerAfter.Kernel") || current.Text("BootId") != before.Text("ServerAfter.BootId") || current.Long("MemoryKiB") != before.Long("ServerAfter.MemoryKiB") || ArchiveStore.Fingerprint(current["Sysctl"]!) != ArchiveStore.Fingerprint(before.At("ServerAfter.Sysctl")!) || NetworkTuning.QueueFingerprint(current) != NetworkTuning.QueueFingerprint(before["ServerAfter"]!.AsObject()))) throw new OperationException("远端内核、启动身份、参数或队列在测速后发生变化，或记录来自旧版采集，请重新采集。");
            await c.Run("network-preflight.sh", timeout: 60, marker: "NETWORK_PREFLIGHT_OK");
        });
        await c.TrackStep("network-backup", () => Arm(c, ["Network"]));
        await c.TrackStep("network-apply", async () =>
        {
            await c.Run("network-apply.sh", new() { ["PROFILE"] = profile,
                ["BUFFER_TARGET_BYTES"] = before?.Text("Analysis.BufferTargetBytes", "0") ?? "0", ["BUFFER_CAP_BYTES"] = before?.Text("Analysis.BufferCapBytes", "0") ?? "0" }, true, 120, "NETWORK_APPLIED");
            current = await NetworkObservation(c, before?["Options"] as JsonObject);
            if (c.Request.Options.Text("BbrVersion", "Current") == "v3" && !BbrKernels.AcceptedRuntime(c.State, current)) throw new OperationException("应用后未确认受管 Google 源码内核及 BBR v3 运行版本，请核对内核事务。");
            if (NetworkTuning.Sysctl(current, "net.core.default_qdisc") != "fq") throw new OperationException("默认队列未确认生效。");
            if (NetworkTuning.Sysctl(current, "net.ipv4.tcp_available_congestion_control").Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("bbr") && NetworkTuning.Sysctl(current, "net.ipv4.tcp_congestion_control") != "bbr") throw new OperationException("可用 BBR 未确认生效。");
            await VerifyManagement(c);
        });
        JsonObject? after = null; JsonObject? decision = null; var comparison = "BasicVerified";
        if (profile == "EntryMeasured") await c.TrackStep("network-retest", async () =>
        {
            after = await CaptureNetwork(c, before!["Options"]!.DeepClone().AsObject(), Guid.NewGuid().ToString("N"));
            decision = NetworkTuning.CompareDetailed(before, after); comparison = decision.Text("Result");
        });
        await c.TrackStep("network-completion", async () =>
        {
            var reverted = profile == "EntryMeasured" && comparison != "Improved";
            if (reverted) { await Rollback(c); current = await NetworkObservation(c, before?["Options"] as JsonObject); c.Warnings = true; }
            else
            {
                c.Plan["NetworkTuning"] = new JsonObject { ["Profile"] = profile, ["MeasurementId"] = before?.Text("Id"), ["At"] = DateTimeOffset.UtcNow.ToString("O") };
                c.State["NetworkTuning"] = new JsonObject { ["Profile"] = profile, ["At"] = DateTimeOffset.UtcNow.ToString("O"), ["AppliedRuntime"] = current!.DeepClone() };
                if (NetworkTuning.Sysctl(current!, "net.ipv4.tcp_congestion_control") != "bbr") c.Warnings = true;
                c.Save(); await Commit(c);
            }
            c.State["LastNetworkComparison"] = new JsonObject { ["At"] = DateTimeOffset.UtcNow.ToString("O"), ["BeforeId"] = before?.Text("Id"), ["AfterId"] = after?.Text("Id"), ["Result"] = comparison, ["Decision"] = decision, ["RestoredOriginal"] = reverted, ["VerifiedRuntime"] = current!.DeepClone() };
            c.Save(); c.Report("网络调优完成", reverted ? "复测未确认明确收益，原运行参数与队列已恢复，前后测量结果保留。" : NetworkTuning.Sysctl(current, "net.ipv4.tcp_congestion_control") == "bbr" ? "已核验实际 fq 队列、BBR 与管理连接，恢复点保留。" : "已核验 fq；当前内核没有可用 BBR，保留原拥塞控制。内核升级需另行维护。");
        });
    }
}
