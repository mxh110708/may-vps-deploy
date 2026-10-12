using System.Globalization;
using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public sealed partial class WorkflowEngine
{
    private async Task<JsonObject> NetworkObservation(Context c, JsonObject? options = null, CancellationToken? token = null)
    {
        var port = options?.Text("Protocol") == "AnyTlsEntry" ? c.Plan.Number("Ports.AnyTlsPrimary") : c.Plan.Number("Ports.XrayPrimary");
        await using var session = await c.Session();
        var result = await session.RunScriptAsync(assets.Payload("network-audit.sh", new Dictionary<string, string>
        { ["ACTION"] = "Observe", ["TCP_PORT"] = port.ToString(CultureInfo.InvariantCulture) }), TimeSpan.FromSeconds(30), false, token ?? c.Cancellation);
        result.RequireSuccess("网络只读采集失败。");
        return JsonNode.Parse(RemoteAssets.Marker(result.Output, "NETWORK_AUDIT"))!.AsObject();
    }
    private async Task<JsonObject> CaptureNetwork(Context c, JsonObject options, string id)
    {
        if (network == null) throw new OperationException("当前运行环境没有后台网络测量适配器。");
        NetworkTuning.ValidateMeasurement(options);
        if (!NetworkTuning.IsEntry(c.Plan) || !Enabled(c.Plan, options.Text("Protocol"))) throw new OperationException("请选择正在启用的入口协议；落地机无需精细测速。");
        if (options.Text("Family") == "IPv6" && c.Plan.Text("Server.IPv6") == "") throw new OperationException("实例没有 IPv6 地址。");
        var before = await NetworkObservation(c, options);
        var supplemental = await c.Run("network-audit.sh", new() { ["ACTION"] = "Outbound", ["BYTES"] = Math.Min(NetworkTuning.PayloadBudget(options) / 8, 8388608).ToString(CultureInfo.InvariantCulture) }, timeout: 30);
        var outbound = JsonNode.Parse(RemoteAssets.Marker(supplemental.Output, "NETWORK_AUDIT"))!.AsObject();
        var client = await network.MeasureAsync(c.Plan, c.Secrets, options, c.Directory, t => NetworkObservation(c, options, t),
            new InlineProgress<string>(message => c.Report("网络路径测量", message)), c.Cancellation);
        var after = client["ServerAfter"]?.DeepClone().AsObject() ?? await NetworkObservation(c, options);
        client.Remove("ServerAfter");
        var report = new JsonObject { ["SchemaVersion"] = 1, ["Id"] = NetworkTuning.Id(id), ["At"] = DateTimeOffset.UtcNow.ToString("O"),
            ["SourceFingerprint"] = NetworkTuning.SourceFingerprint(c.Plan, c.Secrets), ["Options"] = options.DeepClone(),
            ["ServerBefore"] = before, ["ServerAfter"] = after, ["Client"] = client, ["VpsOutbound"] = outbound };
        report["Analysis"] = NetworkTuning.Analyze(report, NetworkTuning.History(c.Directory));
        ArchiveStore.WriteJson(c.File("network-measurements/" + id + ".json"), report);
        c.State["LastNetworkMeasurement"] = new JsonObject { ["Id"] = id, ["At"] = report["At"]!.DeepClone() };
        var preferences = options.DeepClone().AsObject(); preferences.Remove("Scheduled"); c.Plan["NetworkPreferences"] = preferences;
        c.Save(); return report;
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
                var analysis = NetworkTuning.Analyze(before, NetworkTuning.History(c.Directory));
                if (analysis.Text("Profile") != "EntryMeasured") throw new OperationException("该记录不足以支持缓冲调整，请重新测量或选择基础配置。");
                before["Analysis"] = analysis;
            }
            current = await NetworkObservation(c, before?["Options"] as JsonObject);
            if (c.Request.Options.Text("BbrVersion", "Current") == "v3" && current.Text("BbrVersion") != "v3") throw new OperationException("已选择 BBR v3，但当前内核尚未确认支持。请先检查并完成 BBR v3 内核升级与验收。");
            if (c.Request.Options.Text("BbrVersion", "Current") == "Current" && c.State["KernelUpgrade"] is JsonObject kernel && current.Text("Kernel") != kernel.Text("OriginalKernel", kernel.Text("OldKernel"))) throw new OperationException("已选择 VPS 原有内核版本，请先审阅回到 VPS 原有内核；当前运行的是升级后的内核。");
            if (before != null && (current.Text("Kernel") != before.Text("ServerAfter.Kernel") || current.Long("MemoryKiB") != before.Long("ServerAfter.MemoryKiB") || ArchiveStore.Fingerprint(current["Sysctl"]!) != ArchiveStore.Fingerprint(before.At("ServerAfter.Sysctl")!) || NetworkTuning.QueueFingerprint(current) != NetworkTuning.QueueFingerprint(before["ServerAfter"]!.AsObject()))) throw new OperationException("远端内核、参数或队列在测速后发生变化，请重新采集。");
            await c.Run("network-preflight.sh", timeout: 60, marker: "NETWORK_PREFLIGHT_OK");
        });
        await c.TrackStep("network-backup", () => Arm(c, ["Network"]));
        await c.TrackStep("network-apply", async () =>
        {
            await c.Run("network-apply.sh", new() { ["PROFILE"] = profile,
                ["BUFFER_TARGET_BYTES"] = before?.Text("Analysis.BufferTargetBytes", "0") ?? "0", ["BUFFER_CAP_BYTES"] = before?.Text("Analysis.BufferCapBytes", "0") ?? "0" }, true, 120, "NETWORK_APPLIED");
            current = await NetworkObservation(c, before?["Options"] as JsonObject);
            if (c.Request.Options.Text("BbrVersion", "Current") == "v3" && current.Text("BbrVersion") != "v3") throw new OperationException("应用后未确认 BBR v3 运行版本，请核对内核事务。");
            if (NetworkTuning.Sysctl(current, "net.core.default_qdisc") != "fq") throw new OperationException("默认队列未确认生效。");
            if (NetworkTuning.Sysctl(current, "net.ipv4.tcp_available_congestion_control").Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("bbr") && NetworkTuning.Sysctl(current, "net.ipv4.tcp_congestion_control") != "bbr") throw new OperationException("可用 BBR 未确认生效。");
            await VerifyManagement(c);
        });
        JsonObject? after = null; var comparison = "BasicVerified";
        if (profile == "EntryMeasured") await c.TrackStep("network-retest", async () =>
        {
            after = await CaptureNetwork(c, before!["Options"]!.DeepClone().AsObject(), Guid.NewGuid().ToString("N"));
            comparison = NetworkTuning.Compare(before, after);
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
            c.State["LastNetworkComparison"] = new JsonObject { ["At"] = DateTimeOffset.UtcNow.ToString("O"), ["BeforeId"] = before?.Text("Id"), ["AfterId"] = after?.Text("Id"), ["Result"] = comparison, ["RestoredOriginal"] = reverted, ["VerifiedRuntime"] = current!.DeepClone() };
            c.Save(); c.Report("网络调优完成", reverted ? "复测未确认明确收益，原运行参数与队列已恢复，前后测量结果保留。" : NetworkTuning.Sysctl(current, "net.ipv4.tcp_congestion_control") == "bbr" ? "已核验实际 fq 队列、BBR 与管理连接，恢复点保留。" : "已核验 fq；当前内核没有可用 BBR，保留原拥塞控制。内核升级需另行维护。");
        });
    }
}
