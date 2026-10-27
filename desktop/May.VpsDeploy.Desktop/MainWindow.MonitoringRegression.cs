using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> MonitoringRegression(string outputDirectory)
    {
        if (testSession == null || !backgroundTest || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only"))
            throw new OperationException("监测回归只能在合成隔离工作区运行。");
        static void Require(bool value, string reason) { if (!value) throw new OperationException(reason); }
        static void Invoke(Button button) => ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke();
        async Task Wait(Func<bool> condition)
        {
            for (var i = 0; i < 100; i++) { if (condition()) return; await Task.Delay(30); }
            throw new OperationException("合成监测界面未完成预期状态。");
        }
        async Task<ContentDialog> Dialog()
        {
            await Wait(() => activeTestDialog != null); var dialog = activeTestDialog!; dialog.UpdateLayout(); await Task.Delay(100); return dialog;
        }
        var file = paths.Resolve("private/monitor-read.private.json");
        var previous = File.Exists(file) ? File.ReadAllBytes(file) : null;
        var history = new TaskHistory(store).Read().Count;
        var added = new List<string>(); Task? pending = null;
        var ids = Enumerable.Range(0, 3).Select(_ => Guid.NewGuid().ToString("D")).ToArray();
        var serverInstanceId = Guid.NewGuid().ToString("D");
        var requests = 0; var failing = false; var hold = false; TaskCompletionSource? deferred = null;
        monitorTestHandler = () => new SyntheticMonitorHandler(async (_, ct) =>
        {
            Interlocked.Increment(ref requests);
            if (deferred != null) await deferred.Task;
            if (hold) await Task.Delay(Timeout.Infinite, ct);
            if (failing) return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            var nodes = new JsonArray();
            foreach (var id in ids) nodes.Add(new JsonObject { ["uuid"] = id, ["online"] = true, ["report_at"] = DateTimeOffset.UtcNow.ToString("O"), ["alerts"] = new JsonObject { ["active"] = 2, ["silenced"] = 1, ["delivery_failed"] = 1 }, ["metrics"] = new JsonObject { ["cpu_percent"] = 12.5, ["memory_used"] = 128L * 1024 * 1024, ["memory_total"] = 1024L * 1024 * 1024, ["upload_per_sec"] = 1024L, ["download_per_sec"] = 2048L, ["upload_total"] = 4096L, ["download_total"] = 8192L } });
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new JsonObject { ["schema_version"] = 1, ["server_version"] = "0.1.0-rc.7", ["server_instance_id"] = serverInstanceId, ["captured_at"] = DateTimeOffset.UtcNow.ToString("O"), ["nodes"] = nodes }.ToJsonString(), Encoding.UTF8, "application/json") };
        });
        try
        {
            // Independent synthetic inventory only; never source credentials or
            // addresses from the user's existing instance/private directories.
            foreach (var name in new[] { "Monitor-West", "Monitor-Europe", "Monitor-HK" })
            {
                var relative = "Example/" + name + "/May-VPS-Deploy";
                if (Directory.Exists(paths.Instance(relative))) throw new OperationException("合成监测实例名称已存在。");
                ArchiveStore.WriteJson(SafePath.Resolve(paths.Instance(relative), "deployment-plan.json"), new JsonObject { ["Provider"] = "Example", ["Instance"] = name, ["NodeName"] = name, ["Role"] = "RealityEntry", ["Server"] = new JsonObject { ["IPv4"] = "192.0.2.10" }, ["Import"] = new JsonObject { ["Status"] = "Completed" } });
                added.Add(relative);
            }
            MonitorArchive.Remove(); SelectPage("monitoring");
            Require(requests == 0 && Find<Button>(shell).Any(b => b.Content as string == "配置只读连接"), "未配置监测却自动联网或缺少入口。");
            pending = EditMonitorConnection(); var form = await Dialog();
            await RegressionPress(form, "CloseButton"); await pending; Require(!File.Exists(file), "取消配置仍写入连接。");
            pending = EditMonitorConnection(); form = await Dialog();
            await RegressionPress(form, "PrimaryButton");
            Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "Monitor.Validation").Text != "", "无效连接关闭对话框或没有反馈。");
            await RegressionFill(Find<TextBox>(form).Single(t => t.Header as string == "May Monitor HTTPS 地址"), "https://monitor.example/");
            await RegressionFill(Find<TextBox>(form).Single(t => t.Header as string == "已核验的服务安装 UUID"), serverInstanceId);
            Invoke(Find<Button>(form).Single(b => b.Content as string == "生成新只读令牌"));
            var secret = Find<PasswordBox>(form).Single(p => p.Tag as string == "Monitor.Token"); var token = secret.Password;
            for (var i = 0; i < added.Count; i++) await RegressionFill(Find<TextBox>(form).Single(t => t.Tag as string == "Monitor.Binding." + added[i]), ids[i]);
            Invoke(Find<Button>(form).Single(b => b.Content as string == "预览服务端授权配置"));
            await Wait(() => Find<TextBox>(form).Single(t => t.Tag as string == "Monitor.Provisioning").Text.Contains("MAY_MONITOR_READ_TOKEN_SHA256="));
            Require(!Find<TextBlock>(form).Any(t => t.Text.Contains(token)) && !Find<TextBox>(form).Any(t => t.Text.Contains(token)), "配置预览泄露只读令牌。");
            Find<TextBox>(form).Single(t => t.Tag as string == "Monitor.Provisioning").StartBringIntoView(); await Task.Delay(100);
            await Capture(SafePath.Resolve(outputDirectory, "monitor-read-connection.png"), form);
            await RegressionPress(form, "PrimaryButton"); await pending;
            Require(requests == 0 && monitorRows?.Children.Count == 3 && !File.ReadAllText(file).Contains(token), "保存连接自动联网、丢失实例或明文保存令牌。");
            Invoke(Find<Button>(shell).Single(b => b.Content as string == "刷新监测"));
            await Wait(() => monitorSnapshot != null && monitorCancellation == null);
            Require(monitorRows?.Children.Count == 3 && Find<TextBlock>(monitorRows).Count(t => t.Text == "在线") == 3, "授权实例没有逐项显示在线状态。");
            Require(Find<TextBlock>(monitorRows!).Count(t=>t.Text.Contains("告警 2")&&t.Text.Contains("静默 1")&&t.Text.Contains("通知失败 1"))==3 && Find<Button>(shell).Any(b=>b.Content as string=="打开 May Web"),"告警计数或独立 Web 入口没有显示。");
            notice.IsOpen = false; monitorRows!.StartBringIntoView(); await Task.Delay(100);
            await Capture(SafePath.Resolve(outputDirectory, "monitor-read-page.png"));
            var beforeAging = requests;
            monitorSnapshot = monitorSnapshot! with { ReceivedAt = DateTimeOffset.UtcNow.AddMilliseconds(-89900) };
            RenderMonitorRows(MonitorArchive.Load()!);
            await Wait(() => Find<TextBlock>(monitorRows!).Count(t => t.Text == "读取失败或快照过期") == 3);
            Require(requests == beforeAging && !monitorExpiryTimer.IsEnabled, "快照没有按时间过期，或过期刷新触发了网络／持续定时器。");
            var aged = monitorSnapshot;
            monitorSnapshot = monitorSnapshot! with { ReceivedAt = DateTimeOffset.UtcNow, CredentialExpiresAt = DateTimeOffset.UtcNow.AddMilliseconds(100) };
            RenderMonitorRows(MonitorArchive.Load()!);
            await Wait(() => Find<TextBlock>(monitorRows!).Any(t=>t.Text.Contains("只读凭据已到期")) && Find<TextBlock>(monitorRows!).All(t=>t.Text!="在线"));
            Require(requests==beforeAging,"凭据到期刷新触发了新的网络请求。");
            monitorSnapshot=aged;RenderMonitorRows(MonitorArchive.Load()!);
            failing = true; Invoke(Find<Button>(shell).Single(b => b.Content as string == "刷新监测"));
            await Wait(() => monitorReadFailed && monitorCancellation == null);
            Require(monitorMessage.Contains("令牌"),"鉴权失败没有给出凭据提示。");
            Require(Find<TextBlock>(monitorRows!).Count(t => t.Text == "读取失败或快照过期") == 3, "连接失败被显示为节点在线或全部离线。");
            failing = false; hold = true; Invoke(Find<Button>(shell).Single(b => b.Content as string == "刷新监测"));
            await Wait(() => monitorCancellation != null);
            var inFlight = requests; await RefreshMonitoring(); Require(requests == inFlight, "读取未结束时创建了重复请求。");
            Invoke(Find<Button>(shell).Single(b => b.Tag as string == "Monitor.Cancel")); await Wait(() => monitorCancellation == null);
            Require(monitorMessage.Contains("已取消"), "取消读取没有收敛。");
            Invoke(Find<Button>(shell).Single(b => b.Content as string == "刷新监测")); await Wait(() => monitorCancellation != null);
            SelectPage("overview"); await Wait(() => monitorCancellation == null); Require(!monitorTimer.IsEnabled && monitorRows == null, "离开监测页仍保留活动读取。");
            hold = false; SelectPage("monitoring");
            Require(!Find<ToggleSwitch>(shell).Single(t => t.Tag as string == "Monitor.Polling").IsOn, "重开页面默认启动自动刷新。");
            deferred = new(TaskCreationOptions.RunContinuationsAsynchronously);
            Invoke(Find<Button>(shell).Single(b => b.Content as string == "刷新监测")); await Wait(() => monitorCancellation != null);
            var original = MonitorArchive.Load()!;
            MonitorArchive.Save(new("https://changed.example/", original.Token, original.Bindings, original.ServerInstanceId));
            deferred.SetResult(); await Wait(() => monitorCancellation == null);
            Require(monitorSnapshot == null && monitorRows?.Children.Count == 0 && monitorMessage.Contains("连接已变化"), "旧来源响应进入了新连接。");
            deferred = null; SelectPage("monitoring");
            var removedFile = SafePath.Resolve(paths.Instance(added[0]), "deployment-plan.json"); var removedPlan = ArchiveStore.ReadJson(removedFile);
            File.Delete(removedFile); var beforeRemoval = requests; await RefreshMonitoring();
            Require(requests == beforeRemoval && monitorSnapshot == null && monitorMessage.Contains("绑定实例已移除"), "已移除实例仍触发监测请求。");
            ArchiveStore.WriteJson(removedFile, removedPlan);
            var prior = File.ReadAllText(file); pending = RemoveMonitorConnection(); form = await Dialog(); await RegressionPress(form, "CloseButton"); await pending;
            Require(File.ReadAllText(file) == prior, "取消移除仍修改连接。");
            pending = RemoveMonitorConnection(); form = await Dialog(); await RegressionPress(form, "PrimaryButton"); await pending;
            Require(!File.Exists(file) && monitorSnapshot == null && new TaskHistory(store).Read().Count == history && taskCancellation == null, "本机移除触发远端任务或保留快照。");
            return new() { ["configure_cancel"] = true, ["invalid_stays_open"] = true, ["encrypted_save"] = true, ["explicit_read"] = true, ["three_instance_rows"] = true, ["age_updates_without_network"] = true, ["failed_is_unknown"] = true, ["cancel_read"] = true, ["no_overlapping_read"] = true, ["leave_cancels"] = true, ["reopen_no_polling"] = true, ["old_response_rejected"] = true, ["removed_binding_blocked"] = true, ["disconnect_cancel"] = true, ["disconnect_local_only"] = true, ["network"] = "inert synthetic handler only" };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(80); }
            deferred?.TrySetResult();
            if (pending != null) { try { await pending.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationException) { } }
            StopMonitoring(); monitorTestHandler = null; monitorSnapshot = null; monitorIdentity = null;
            if (previous == null) MonitorArchive.Remove(); else ArchiveStore.AtomicWrite(file, previous);
            foreach (var relative in added)
            {
                var directory = paths.Instance(relative); testSession.RequireLocalPath(directory); SafePath.CheckTree(directory); Directory.Delete(directory, true);
            }
            Navigate("overview");
        }
    }
    private sealed class SyntheticMonitorHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => action(request, token); }
}
