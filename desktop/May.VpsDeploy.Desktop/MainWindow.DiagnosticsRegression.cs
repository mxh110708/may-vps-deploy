#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> DiagnosticsRegression(string output)
    {
        if (testSession == null || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("诊断界面回归仅允许合成后台会话。");
        var previous = scheme; var selection = diagnosticSelection.DeepClone().AsObject(); var beforeRunner = diagnosticTestRun;
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        static void Invoke(Button button) => ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke();
        async Task<ContentDialog> Wait()
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(5);
            while ((activeTestDialog == null || !Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
            Require(activeTestDialog != null, "诊断审阅未打开。"); shell.UpdateLayout(); return activeTestDialog!;
        }
        var proof = new JsonObject(); var sample = ClientSchemes.New(paths); sample["Name"] = "第37轮诊断合成方案";
        ClientNodeImport.Apply(sample, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic37-ui-only@192.0.2.10:443#US-West-LA%20Entry%20long%20display", sample, "US-West-LA Entry", "entry"));
        ClientNodeImport.Apply(sample, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic37-ui-only@[2001:db8::20]:8443#SF%20Landing%20long%20display", sample, "US-West-LA Entry", "landing"));
        var entryName = sample["Nodes"]![0]!.Text("name"); var landingName = sample["Nodes"]![1]!.Text("name");
        sample["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" }; workbench.Save(sample);
        var file = ServerOutboundRouting.SchemeFile(paths, sample.Text("Id")); var sourceFingerprint = ClientSchemes.SourceFingerprint(file);
        diagnosticSelection["Scheme"] = sample.Text("Id"); diagnosticSelection["Entry"] = sample["Nodes"]![0]!.Text("Id"); diagnosticSelection["Landing"] = sample["Nodes"]![1]!.Text("Id");
        try
        {
            diagnosticTestRun = (plan, token) => new RouteDiagnosticWorkbench(store, new UiDiagnostic37(), networkContext: () => new string('b', 64)).RunAsync(plan, false, false, new InlineProgress<string>(_ => { }), token);
            SelectPage("diagnostics");
            Require(Find<ComboBox>(page).Count(c => (c.Tag as string)?.StartsWith("Diagnostics.") == true) == 3, "诊断方案、入口或落地选择缺失。"); proof["explicit_scheme_entry_landing"] = true;
            Require(!monitorTimer.IsEnabled && !monitorExpiryTimer.IsEnabled && monitorCancellation == null, "诊断页面开启周期监测。"); proof["no_polling_on_navigation"] = true;
            var pending = ReviewRouteDiagnostic(sample, entryName, landingName); var dialog = await Wait();
            Require(Find<TextBlock>(dialog).Any(t => t.Text.Contains("最长150秒")) && Find<TextBlock>(dialog).Any(t => t.Text.Contains("没有可独立探测")), "审阅缺少范围及超时边界。");
            Invoke(Find<Button>(dialog).Single(b => b.Name == "CloseButton")); await pending;
            Require(DiagnosticHistory.Read(sample.Text("Id")).Count == 0 && taskCancellation == null, "取消审阅启动网络任务或写入历史。"); proof["cancel_review_no_task_no_report"] = true;
            pending = ReviewRouteDiagnostic(sample, entryName, landingName); dialog = await Wait(); Invoke(Find<Button>(dialog).Single(b => b.Name == "PrimaryButton")); await pending;
            Require(DiagnosticHistory.Read(sample.Text("Id")).Count == 1 && currentPage == "diagnostics", "已完成检查未独立保存并显示。"); proof["review_run_history_render"] = true;
            Require(ClientSchemes.SourceFingerprint(file) == sourceFingerprint && sample.Text("Candidate.ValidationStatus") == "Passed", "诊断改变方案或校验候选。"); proof["candidate_and_scheme_unchanged"] = true;
            Require(Find<TextBlock>(page).Any(t => t.Text.Contains("同条件完成样本 1 次")) && Find<TextBlock>(page).Any(t => t.Text.Contains("中位数 20")), "质量统计缺少独立样本及分位数。"); proof["quality_statistics_visible"] = true;
            Require(!Find<TextBlock>(page).Any(t => t.Text.Contains("synthetic37-ui-only")), "诊断页面泄露凭据。"); proof["credentials_not_rendered"] = true;
            var plan = RouteDiagnostics.Plan(store, sample, entryName, landingName);
            try
            {
                var report = await diagnosticTestRun(plan, default); report["Status"] = "Degraded";
                report["Segments"] = new JsonArray(new JsonObject { ["Id"] = "Entry.FrontRelay", ["Label"] = "前置 → 中转 · 跨实例长名称", ["Kind"] = "Measured", ["Status"] = "Failed", ["Detail"] = "仅分段管理连接失败，整链业务已通过；需要单独核对。" },
                    new JsonObject { ["Id"] = "Entry.RelayLanding", ["Label"] = "中转 → 落地", ["Kind"] = "RouteOnly", ["Status"] = "RouteAvailable", ["Detail"] = "仅可选路由，不是 UDP 回程或延迟。" });
                report["Monitor"] = new JsonArray(new JsonObject { ["Instance"] = "合成供应商/合成实例/May-VPS-Deploy", ["Status"] = "在线 · 上报已过期", ["CpuPercent"] = 10.5, ["MemoryUsed"] = 64000, ["ReportAt"] = DateTimeOffset.UtcNow.AddMinutes(-3) });
                DiagnosticHistory.Append(sample.Text("Id"), report);
            }
            finally { plan.Clear(); }
            Navigate("diagnostics"); shell.UpdateLayout();
            Require(Find<TextBlock>(page).Any(t => t.Text.Contains("分段有待核对")) && Find<TextBlock>(page).Any(t => t.Text.Contains("仅路由")), "分段错误或UDP路由被写成业务失败／实测时延。"); proof["segment_business_and_route_scope_distinct"] = true;
            Require(Find<TextBlock>(page).Any(t => t.Text.Contains("May Monitor 旁证") && t.Text.Contains("上报已过期")), "过期监测旁证缺失或显示为当前在线。"); proof["monitor_freshness_visible"] = true;
            await Capture(SafePath.Resolve(output, "diagnostic-workbench.png"));
            var newest = DiagnosticHistory.Read(sample.Text("Id")).Last();
            var reportVisual = Find<StackPanel>(page).Single(p => p.Tag as string == "Diagnostics.Report." + newest.Text("Id"));
            var offset = reportVisual.TransformToVisual(mainScroll).TransformPoint(new(0, 0)).Y + mainScroll!.VerticalOffset;
            mainScroll.ChangeView(null, Math.Max(0, offset - 26), null, true); await Task.Delay(100); shell.UpdateLayout();
            Require(reportVisual.ActualHeight > 200 && Find<TextBlock>(reportVisual).All(t => t.TextWrapping == TextWrapping.Wrap), "多段诊断卡片没有竖排延展或自动换行。");
            await Capture(SafePath.Resolve(output, "diagnostic-report.png")); proof["vertical_wrapped_report_capture"] = true;
            Navigate("diagnostics"); Require(diagnosticSelection.Text("Landing") == sample["Nodes"]![1]!.Text("Id"), "页面重开丢失显式落地选择。"); proof["selection_retained"] = true;
            sample["Nodes"]![1]!["sing_box"]!["password"] = "synthetic37-changed"; workbench.Save(sample); Navigate("diagnostics");
            Require(Find<TextBlock>(page).Any(t => t.Text.Contains("配置或来源已变化")), "变更后继续显示历史为当前实测。"); proof["changed_source_marked_stale"] = true;
            var count = DiagnosticHistory.Read(sample.Text("Id")).Count;
            diagnosticTestRun = (p, token) => new RouteDiagnosticWorkbench(store, new UiDiagnostic37(true), networkContext: () => new string('b', 64)).RunAsync(p, false, false, new InlineProgress<string>(_ => { }), token);
            pending = ReviewRouteDiagnostic(sample, entryName, landingName); dialog = await Wait(); Invoke(Find<Button>(dialog).Single(b => b.Name == "PrimaryButton"));
            var until = DateTimeOffset.UtcNow.AddSeconds(5); while (taskCancellation == null && DateTimeOffset.UtcNow < until) await Task.Delay(20);
            Require(taskCancellation != null, "取消测试未进入有限任务。"); Invoke(cancel); await pending;
            Require(DiagnosticHistory.Read(sample.Text("Id")).Count == count + 1 && DiagnosticHistory.Read(sample.Text("Id")).Last().Text("Status") == "Cancelled" && taskCancellation == null, "取消任务未保留阶段状态或未解除忙碌。"); proof["cancel_button_releases_task_and_records_cancel"] = true;
            var clear = ClearDiagnosticHistory(sample.Text("Id")); dialog = await Wait(); Invoke(Find<Button>(dialog).Single(b => b.Name == "CloseButton")); await clear;
            Require(DiagnosticHistory.Read(sample.Text("Id")).Count == count + 1, "取消清空仍删除历史。"); proof["clear_cancel_preserves_records"] = true;
            diagnosticTestRun = async (p, token) =>
            {
                var report = await new RouteDiagnosticWorkbench(store, new UiDiagnostic37(), networkContext: () => new string('b', 64)).RunAsync(p, false, false, new InlineProgress<string>(_ => { }), token);
                var saved = store.ReadSecret(file); saved["Nodes"]![0]!["sing_box"]!["password"] = "synthetic37-concurrent-update"; workbench.Save(saved); saved.Clear(); return report;
            };
            pending = ReviewRouteDiagnostic(sample, entryName, landingName); dialog = await Wait(); Invoke(Find<Button>(dialog).Single(b => b.Name == "PrimaryButton")); await pending;
            Require(DiagnosticHistory.Read(sample.Text("Id")).Last().Text("Status") == "SourceChanged", "诊断期间已保存参数变化仍报告当前成功。"); proof["concurrent_saved_change_not_current"] = true;
            return proof;
        }
        finally
        {
            diagnosticTestRun = beforeRunner; activeTestDialog?.Hide(); scheme = previous;
            diagnosticSelection.Clear(); foreach (var pair in selection) diagnosticSelection[pair.Key] = pair.Value?.DeepClone();
            SelectPage("overview");
        }
    }
    private sealed class UiDiagnostic37(bool wait = false) : IClientRouteDiagnostics
    {
        public async Task<JsonObject> RunAsync(ClientDiagnosticRoute route, string directory, IProgress<string> progress, CancellationToken token)
        {
            if (wait) await Task.Delay(Timeout.Infinite, token);
            return new() { ["Status"] = "Reachable", ["Profile"] = new string('c', 64), ["Stages"] = new JsonArray(new JsonObject { ["Id"] = "EntryHttps", ["Status"] = "Passed", ["Milliseconds"] = 20 }, new JsonObject { ["Id"] = "RemoteLeg", ["Status"] = "NotMeasured" }),
                ["EntryEgress"] = new JsonObject { ["Address"] = "192.0.2.123", ["Family"] = "IPv4", ["Verified"] = false } };
        }
    }
}
