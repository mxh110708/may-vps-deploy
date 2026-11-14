using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private readonly JsonObject diagnosticSelection = new() { ["Scheme"] = "", ["Entry"] = "", ["Landing"] = "", ["Segments"] = true, ["Monitor"] = true };
    private readonly IRouteSegmentProbe routeSegmentProbe;
    private Func<RouteDiagnosticPlan, CancellationToken, Task<JsonObject>>? diagnosticTestRun;
    private RouteDiagnosticHistory DiagnosticHistory => new(store);

    private void DiagnosticsPage()
    {
        page.Children.Add(Card(Column(Text("线路诊断工作台", 20), Text("选择具体路径进行一次有限检查。分段连接、协议与出口分别展示；历史不代表当前客户端选择或实时健康。没有周期探测。", 14, true))));
        var schemes = workbench.List().ToArray();
        if (schemes.Length == 0) { page.Children.Add(Card(Text("请先在配置设计中保存含入口节点的方案。"))); return; }
        if (!schemes.Any(s => s.Text("Id") == diagnosticSelection.Text("Scheme"))) diagnosticSelection["Scheme"] = schemes[0].Text("Id");
        var picker = Choice("诊断方案（已保存）", diagnosticSelection, "Scheme", schemes.Select(s => (s.Text("Id"), s.Text("Name")))); picker.Tag = "Diagnostics.Scheme";
        picker.SelectionChanged += (_, _) => { diagnosticSelection["Entry"] = ""; diagnosticSelection["Landing"] = ""; Navigate("diagnostics"); }; page.Children.Add(picker);
        var selected = schemes.Single(s => s.Text("Id") == diagnosticSelection.Text("Scheme")); var entries = ClientTopology.Regions(selected).SelectMany(r => r.Entries).ToArray();
        if (entries.Length == 0) { page.Children.Add(Card(Text("此方案尚无入口节点。"))); return; }
        if (!entries.Any(n => n.Text("Id") == diagnosticSelection.Text("Entry"))) diagnosticSelection["Entry"] = entries[0].Text("Id");
        var entry = entries.Single(n => n.Text("Id") == diagnosticSelection.Text("Entry"));
        var landings = selected["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => n.Text("kind") == "landing" && n.Text("transit_group") == entry.Text("region_group")).ToArray();
        if (!landings.Any(n => n.Text("Id") == diagnosticSelection.Text("Landing"))) diagnosticSelection["Landing"] = "";
        var entryPicker = Choice("具体入口", diagnosticSelection, "Entry", entries.Select(n => (n.Text("Id"), n.Text("region_group") + " / " + n.Text("name")))); entryPicker.Tag = "Diagnostics.Entry";
        entryPicker.SelectionChanged += (_, _) => { diagnosticSelection["Landing"] = ""; Navigate("diagnostics"); };
        var landingPicker = Choice("客户端落地", diagnosticSelection, "Landing", new[] { ("", "直接使用入口出口") }.Concat(landings.Select(n => (n.Text("Id"), n.Text("name"))))); landingPicker.Tag = "Diagnostics.Landing";
        var run = Action("审阅并诊断", () => ReviewRouteDiagnostic(selected, entry.Text("name"), landings.FirstOrDefault(n => n.Text("Id") == diagnosticSelection.Text("Landing"))?.Text("name")), true); run.Tag = "Diagnostics.Start";
        page.Children.Add(Card(Column(Fields(entryPicker, landingPicker), Flag("检查受管远端分段（需要 SSH 管理密钥）", diagnosticSelection, "Segments"), Flag("读取已配置的 May Monitor 旁证", diagnosticSelection, "Monitor"), run)));
        page.Children.Add(Card(Text("配置推断：拓扑由本地归档和显式节点参数生成。未独立测量的远端 RTT 保持未测量，不由两次握手耗时相减估算。分段 TCP 成功不等于代理鉴权成功；UDP 可选路由不等于有回程。", 13, true)));
        var reports = DiagnosticHistory.Read(selected.Text("Id"));
        var history = Column(Text("历史质量 · 最近 " + reports.Count + " / " + RouteDiagnosticHistory.MaximumRecords + " 次", 18), Text("仅合并相同配置、观测网络、目标及核心版本；显示成功样本的中位数、P95、峰值。短连接耗时含协议握手及网站响应，不是 ping。取消、来源变化和未测量项不计入质量样本。", 13, true));
        if (reports.Count > 0)
        {
            if (!reports.Any(r => r.Text("Id") == diagnosticSelection.Text("History"))) diagnosticSelection["History"] = reports[^1].Text("Id");
            var condition = Choice("统计条件（按历史记录选择）", diagnosticSelection, "History", reports.Reverse().Select(r => (r.Text("Id"), LocalTime(r.Text("At")) + " · " + r.Text("Path")))); condition.Tag = "Diagnostics.History";
            condition.SelectionChanged += (_, _) => Navigate("diagnostics"); history.Children.Add(condition);
            var latest = reports.Single(r => r.Text("Id") == diagnosticSelection.Text("History")); var quality = RouteDiagnostics.Quality(reports, latest);
            history.Children.Add(Text($"同条件完成样本 {quality.Number("Samples")} 次 · 业务路径通过 {quality.Number("Passed")} 次", 14));
            foreach (var item in quality["Stages"]!.AsArray().OfType<JsonObject>()) history.Children.Add(Text(item.Text("Label", RouteDiagnostics.StageLabel(item.Text("Id"))) + " · n=" + item.Number("Samples") + " · 中位数 " + item.Text("Median") + " ms · P95 " + item.Long("P95") + " ms · 峰值 " + item.Long("Peak") + " ms", 13, true));
            var clear = Action("清空此方案诊断历史", () => ClearDiagnosticHistory(selected.Text("Id"))); clear.Tag = "Diagnostics.Clear"; history.Children.Add(clear);
        }
        page.Children.Add(Card(history));
        foreach (var report in reports.Reverse().Take(12)) page.Children.Add(DiagnosticReportCard(selected, report));
        if (reports.Count > 12) page.Children.Add(Details("更早的诊断记录", Column(reports.Reverse().Skip(12).Select(r => DiagnosticReportCard(selected, r)).ToArray())));
        if (selected["Diagnostics"] is JsonArray legacy && legacy.Count > 0)
            page.Children.Add(Details("旧轻量诊断记录（不混入质量统计）", Column(legacy.OfType<JsonObject>().Reverse().Select(r => ClientDiagnosticCard(selected, r)).ToArray())));
    }

    private async Task ReviewRouteDiagnostic(JsonObject selected, string entry, string? landing)
    {
        var plan = RouteDiagnostics.Plan(store, selected, entry, landing);
        try
        {
            var panel = Column(Text(plan.Route.Label, 18), Text("本次主动短连接，整项最长150秒。不会修改 VPS、系统代理或 TUN；取消后保留已完成阶段。远端检查仅连接或路由，不是纯 RTT。", 14, true));
            foreach (var segment in plan.Segments) panel.Children.Add(Text(segment.Label + "\n" + segment.Instance + " → " + segment.Address + ":" + segment.Port + " / " + segment.Transport, 13));
            if (plan.Segments.Count == 0) panel.Children.Add(Text("此路径没有可独立探测的受管转发段；仅执行本机和整条业务路径检查。", 13, true));
            panel.Children.Add(Text("将请求 ipify HTTPS 出口检查；适用路径另检查有限 UDP DNS。May Monitor 若启用，仅使用已配置的专用只读接口。", 13, true));
            var dialog = OperationDialog("审阅线路诊断", panel, "开始诊断");
            if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
            await ExecuteRouteDiagnostic(selected, plan, diagnosticSelection.Flag("Segments"), diagnosticSelection.Flag("Monitor"));
        }
        finally { plan.Clear(); }
    }

    private async Task ExecuteRouteDiagnostic(JsonObject selected, RouteDiagnosticPlan plan, bool probeSegments, bool readMonitor)
    {
        if (testSession != null && diagnosticTestRun == null) throw new OperationException("隔离界面测试不执行公网诊断。");
        JsonObject? report = null;
        await RunBackground("线路诊断", async token =>
        {
            if (diagnosticTestRun != null && testSession != null) report = await diagnosticTestRun(plan, token);
            else
            {
                using var monitor = new MonitorReadClient();
                var runner = new RouteDiagnosticWorkbench(store, clientDiagnostics, routeSegmentProbe, monitor);
                report = await runner.RunAsync(plan, probeSegments, readMonitor, new Progress<string>(s => taskText.Text = s), token);
            }
            var current = false;
            try
            {
                var saved = store.ReadSecret(ServerOutboundRouting.SchemeFile(paths, plan.SchemeId));
                try { current = RouteDiagnostics.Current(store, saved, report!); }
                finally { saved.Clear(); }
            }
            catch (Exception e) when (e is OperationException or System.IO.IOException or UnauthorizedAccessException) { }
            if (!current) { report!["Status"] = "SourceChanged"; report["FailureStage"] = "Source"; }
            DiagnosticHistory.Append(plan.SchemeId, report!);
        });
        if (report != null) { diagnosticSelection["Scheme"] = plan.SchemeId; diagnosticSelection["History"] = report.Text("Id"); Navigate("diagnostics"); Show(RouteDiagnostics.StatusLabel(report.Text("Status")), report.Text("Status") == "Reachable" ? InfoBarSeverity.Success : InfoBarSeverity.Warning); }
    }

    private UIElement DiagnosticReportCard(JsonObject selected, JsonObject report)
    {
        var current = RouteDiagnostics.Current(store, selected, report);
        var card = Column(Text(RouteDiagnostics.StatusLabel(report.Text("Status")) + (current ? " · 历史记录" : " · 配置或来源已变化，需重测"), 18), Text(report.Text("Path"), 15), Text(LocalTime(report.Text("At")) + " · " + report.Text("Protocol"), 13, true), Text(report.Text("Scope"), 13, true));
        card.Tag = "Diagnostics.Report." + report.Text("Id");
        if (report.Text("FailureStage") != "") card.Children.Add(Text("中断／失败阶段：" + RouteDiagnostics.StageLabel(report.Text("FailureStage")) + "（" + report.Text("FailureStage") + "）；阶段定位不等于根因。", 14));
        foreach (var key in new[] { "Segments", "Stages" })
            foreach (var row in (report[key] as JsonArray ?? []).OfType<JsonObject>())
            {
                var kind = row.Text("Kind") switch { "Measured" => "实测", "RouteOnly" => "仅路由", _ => "未测量" };
                card.Children.Add(Text(row.Text("Label") + " · " + kind + (row.Text("Kind") == "NotMeasured" ? "" : " · " + RouteDiagnostics.EvidenceStatus(row.Text("Status"))) + (row["Milliseconds"] == null ? "" : " · " + row.Long("Milliseconds") + " ms") + (row.Text("Detail") == "" ? "" : "\n" + row.Text("Detail")), 14, row.Text("Kind") != "Measured"));
            }
        foreach (var key in new[] { "EntryEgress", "ChainEgress" })
            if (report[key] is JsonObject exit) card.Children.Add(Text((key == "EntryEgress" ? "入口出口" : "客户端落地出口") + " · " + exit.Text("Address") + " / " + exit.Text("Family") + (exit.Flag("Verified") ? " · 与预期一致" : " · 仅观测，未核验预期身份"), 14));
        foreach (var node in (report["Monitor"] as JsonArray ?? []).OfType<JsonObject>())
            card.Children.Add(Text("May Monitor 旁证 · " + string.Join(" / ", node.Text("Instance").Split('/').Take(2)) + "\n" + node.Text("Status") + " · 上报 " + (node.Text("ReportAt") == "" ? "无" : LocalTime(node.Text("ReportAt"))) + (node["CpuPercent"] == null ? "" : "\n最近快照 CPU " + node.Text("CpuPercent") + "% · 内存 " + MonitorBytes(node.Long("MemoryUsed"))) + "\n节点在线／负载不等于此线路质量或故障原因。", 13, true));
        return Card(card);
    }

    private async Task ClearDiagnosticHistory(string id)
    {
        var fingerprint = DiagnosticHistory.Fingerprint(id);
        if (await ShowDialog(OperationDialog("清空诊断历史", Text("仅清除此方案的本机诊断记录，保留方案、导出、实例及 May Monitor 数据。"), "清空历史")) != ContentDialogResult.Primary) return;
        DiagnosticHistory.Clear(id, fingerprint); Navigate("diagnostics");
    }
}
