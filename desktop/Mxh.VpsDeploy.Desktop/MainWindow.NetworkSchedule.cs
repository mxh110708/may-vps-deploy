using System.Text.Json.Nodes;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private DispatcherQueueTimer? networkTimer;
    private bool checkingNetworkJobs;
    private string NetworkJobFile(string directory) => SafePath.Resolve(directory, "network-schedule.json");
    private async Task ScheduleNetwork(string relative, JsonObject options)
    {
        if (taskCancellation != null) throw new OperationException("请等待当前任务完成。");
        var snapshot = options.DeepClone().AsObject(); snapshot["Scheduled"] = true;
        var directory = paths.Instance(relative); var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"));
        var secretFile = SafePath.Resolve(directory, "secrets.dotnet.private.json");
        var secrets = File.Exists(secretFile) ? store.ReadSecret(secretFile) : ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-secrets.private.json"));
        JsonObject job; try { job = NetworkSchedules.Create(relative, snapshot, NetworkTuning.SourceFingerprint(plan, secrets), DateTimeOffset.UtcNow); } finally { secrets.Clear(); }
        if (!await ConfirmAsync(new("安排一次晚高峰补测", "计划时间：" + NetworkTime(job.Text("DueAt")) + "（本机显示）\n\n" + OperationPolicy.Summary(new(OperationKind.MeasureNetwork, relative, snapshot)) + "\n\n请保持应用运行，可关闭到托盘。只执行一次测速，不自动应用调优。已信任的密钥连接才能后台运行；如需新身份或密码则停止。关闭应用错过时间会记为未执行，需重新安排。新安排会替换此实例原有的待测计划。"), CancellationToken.None)) return;
        ArchiveStore.WriteJson(NetworkJobFile(directory), job); SelectPage("network"); Show("已安排一次晚高峰补测，保持应用运行即可。", InfoBarSeverity.Success);
    }
    private void ShowNetworkSchedule(StackPanel panel, string directory)
    {
        var file = NetworkJobFile(directory); if (!File.Exists(file)) return;
        var job = ArchiveStore.ReadJson(file); var label = job.Text("Status") switch { "Waiting" => "等待晚高峰", "Running" => "正在采集", "Completed" => "已完成", "CompletedWithWarnings" => "已采集，含提示", "Cancelled" => "已取消", "Missed" => "错过时间，未执行", "Interrupted" => "应用退出中断，未重试", "SourceChanged" => "协议归档变化，未执行", _ => "未完成，请查看任务记录" };
        panel.Children.Add(Card(Column(Text("一次晚高峰补测 · " + label, 17), Text(NetworkTime(job.Text("DueAt")) + " · 应用需保持运行；不会自动应用调优。", 13, true), Action("取消此计划", () => { if (job.Text("Status") == "Running") throw new OperationException("此项已运行，请使用下方取消任务。"); job["Status"] = "Cancelled"; ArchiveStore.WriteJson(file, job); SelectPage("network"); return Task.CompletedTask; }))));
    }
    private void StartNetworkScheduler()
    {
        if (networkTimer != null) return;
        foreach (var instance in store.ListInstances())
        {
            try
            {
                var file = NetworkJobFile(paths.Instance(instance.RelativePath)); if (!File.Exists(file)) continue;
                var job = ArchiveStore.ReadJson(file); var state = NetworkSchedules.StatusAt(job, DateTimeOffset.UtcNow, true);
                if (state is "Interrupted" or "Missed" or "Invalid") { job["Status"] = state; ArchiveStore.WriteJson(file, job); }
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationException or System.Text.Json.JsonException)
            { taskText.Text = "部分晚高峰计划无法读取，未执行；请在网络调优页面核对。"; }
        }
        // Test sessions normalize startup state exactly as ordinary launches,
        // but only an explicit test command may dispatch a network job.
        if (testSession != null) return;
        networkTimer = DispatcherQueue.CreateTimer(); networkTimer.Interval = TimeSpan.FromSeconds(30);
        networkTimer.Tick += async (_, _) => await PollNetworkSchedules(); networkTimer.Start();
    }
    private void StopNetworkScheduler() { networkTimer?.Stop(); networkTimer = null; }
    private async Task PollNetworkSchedules()
    {
        if (checkingNetworkJobs || taskCancellation != null || activeTestDialog != null || closing || dialogs.CurrentCount == 0) return;
        checkingNetworkJobs = true;
        try
        {
            foreach (var instance in store.ListInstances())
            {
                var directory = paths.Instance(instance.RelativePath); var file = NetworkJobFile(directory); if (!File.Exists(file)) continue;
                var job = ArchiveStore.ReadJson(file); var status = NetworkSchedules.StatusAt(job, DateTimeOffset.UtcNow);
                if (status == "Missed") { job["Status"] = status; ArchiveStore.WriteJson(file, job); continue; }
                if (status != "Due") continue;
                var secrets = store.ReadSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json")); string source;
                try { source = NetworkTuning.SourceFingerprint(instance.Plan, secrets); } finally { secrets.Clear(); }
                if (source != job.Text("SourceFingerprint")) { job["Status"] = "SourceChanged"; ArchiveStore.WriteJson(file, job); continue; }
                var request = new OperationRequest(OperationKind.MeasureNetwork, instance.RelativePath, job["Options"]!.DeepClone().AsObject());
                request.Options["Scheduled"] = true; var review = coordinator.Review(request);
                job["Status"] = "Running"; ArchiveStore.WriteJson(file, job); activeOperation = request;
                try
                {
                    await RunBackground("晚高峰后台采集", async token =>
                    {
                        var progress = new Progress<TaskProgress>(p => taskText.Text = StageLabel(p.Stage) + " · " + p.Message);
                        var record = await Task.Run(() => coordinator.ExecuteAsync(review, request, progress, token));
                        job["Status"] = record.Outcome.ToString(); job["FinishedAt"] = DateTimeOffset.UtcNow.ToString("O"); job["TaskId"] = record.Id;
                        ArchiveStore.WriteJson(file, job); taskText.Text = "晚高峰补测 · " + OutcomeLabel(record.Outcome);
                    });
                }
                finally { activeOperation = null; RefreshTaskResultPage(); }
                break;
            }
        }
        catch (Exception error) { taskText.Text = "晚高峰计划未能执行：" + SafeFailures.Describe(error).Message; }
        finally { checkingNetworkJobs = false; }
    }
}
