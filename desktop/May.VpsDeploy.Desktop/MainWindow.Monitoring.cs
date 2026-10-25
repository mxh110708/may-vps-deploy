using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private readonly DispatcherTimer monitorTimer = new() { Interval = TimeSpan.FromSeconds(30) };
    private readonly DispatcherTimer monitorExpiryTimer = new();
    private DateTimeOffset monitorRenderedAt;
    private MonitorReadClient? monitorClient;
    private CancellationTokenSource? monitorCancellation;
    private MonitorReadSnapshot? monitorSnapshot;
    private string? monitorIdentity;
    private bool monitorPolling;
    private bool monitorReadFailed;
    private string monitorMessage = "尚未读取。";
    private StackPanel? monitorRows;
    private TextBlock? monitorStatus;
    private MonitorReadArchive MonitorArchive => new(store);
    private bool MonitorVisible => currentPage == "monitoring" && (AppWindow.IsVisible || backgroundTest && monitorTestHandler != null) && !minimizedToTray && !closing && (AppWindow.Presenter is not OverlappedPresenter presenter || presenter.State != OverlappedPresenterState.Minimized);

    private void InitializeMonitoring()
    {
        monitorTimer.Tick += async (_, _) => { if (MonitorVisible && monitorPolling && taskCancellation == null) await RefreshMonitoring(); };
        monitorExpiryTimer.Tick += (_, _) =>
        {
            monitorExpiryTimer.Stop();
            if (!MonitorVisible || monitorSnapshot == null) return;
            try
            {
                var connection = MonitorArchive.Load();
                if (connection?.Identity == monitorIdentity) RenderMonitorRows(connection!);
                else { monitorSnapshot = null; monitorRows?.Children.Clear(); if (monitorStatus != null) monitorStatus.Text = "只读连接已变化，请重新读取。"; }
            }
            catch (OperationException safe) { monitorSnapshot = null; monitorRows?.Children.Clear(); if (monitorStatus != null) monitorStatus.Text = safe.Message; }
        };
        AppWindow.Changed += (_, _) => UpdateMonitorVisibility();
        Activated += (_, _) => UpdateMonitorVisibility();
    }

    private void PauseMonitoring()
    {
        monitorTimer.Stop(); monitorExpiryTimer.Stop(); monitorCancellation?.Cancel(); monitorClient?.Dispose(); monitorClient = null;
    }
    private void StopMonitoring()
    {
        monitorPolling = false; PauseMonitoring(); monitorRows = null; monitorStatus = null;
    }
    private void UpdateMonitorVisibility()
    {
        if (!MonitorVisible) { PauseMonitoring(); return; }
        if (monitorPolling && !backgroundTest) monitorTimer.Start(); else monitorTimer.Stop();
        ScheduleMonitorExpiry();
    }

    private void ScheduleMonitorExpiry()
    {
        monitorExpiryTimer.Stop();
        if (!MonitorVisible || monitorSnapshot == null || monitorReadFailed) return;
        if (monitorRenderedAt - monitorSnapshot.ReceivedAt >= TimeSpan.FromSeconds(90)) return;
        var deadlines = new List<DateTimeOffset> { monitorSnapshot.ReceivedAt.AddSeconds(90) };
        foreach (var node in monitorSnapshot.Nodes.Values)
            if (node.ReportAt is { } report && report > DateTimeOffset.UnixEpoch && report < monitorSnapshot.ReceivedAt.AddMinutes(2))
            { deadlines.Add(report.AddSeconds(90)); deadlines.Add(report.AddSeconds(-5)); }
        var next = deadlines.Where(at => at > monitorRenderedAt).Order().FirstOrDefault();
        if (next == default) return;
        // One wakeup at the next state boundary, coalescing subsecond samples.
        // A paused view whose deadline passed updates immediately on restore.
        var delay = next - DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds(50);
        monitorExpiryTimer.Interval = delay > TimeSpan.FromMilliseconds(50) ? delay : TimeSpan.FromMilliseconds(50);
        monitorExpiryTimer.Start();
    }

    private void MonitoringPage()
    {
        MonitorReadConnection? connection = null;
        string? error = null;
        try { connection = MonitorArchive.Load(); }
        catch (OperationException safe) { error = safe.Message; }
        if (connection?.Identity != monitorIdentity) { monitorSnapshot = null; monitorIdentity = connection?.Identity; monitorReadFailed = false; monitorMessage = "尚未读取。"; }
        if (connection == null) page.Children.Add(Card(Column(Text("May Monitor 只读监测", 18), Text("连接已部署的 May Monitor，查看明确绑定实例的最近状态。", 13, true), Action("配置只读连接", EditMonitorConnection, true))));
        page.Children.Add(Card(Trailing(Column(Text("May Monitor 部署与维护", 17), Text("逐个实例迁移；保留现有 Komari，独立备份与恢复。", 12, true)), Action("部署与维护", ManageMayMonitorDialog))));
        page.Children.Add(Card(Trailing(Column(Text("May HTTPS 接入与试迁移", 17), Text("规划独立网址，核对服务身份及单节点连续上报。", 12, true)), Action("接入与验收", MayMonitorAccessDialog))));
        if (error != null) page.Children.Add(Card(Column(Text("监测连接需要核对", 17), Text(error, 13, true))));
        if (connection == null) return;
        var polling = new ToggleSwitch { Tag = "Monitor.Polling", IsOn = monitorPolling, OnContent = "", OffContent = "", MinWidth = 48 };
        AutomationProperties.SetName(polling, "此页可见时每 30 秒刷新");
        polling.Toggled += async (_, _) => { monitorPolling = polling.IsOn; UpdateMonitorVisibility(); if (monitorPolling && MonitorVisible) await RefreshMonitoring(); };
        var cancelRead = Action("取消读取", () => { monitorCancellation?.Cancel(); return Task.CompletedTask; }, allowDuringTask: true); cancelRead.Tag = "Monitor.Cancel";
        monitorStatus = Text(monitorMessage, 13, true); monitorStatus.Tag = "Monitor.Status";
        page.Children.Add(Card(Column(Trailing(Text(connection.Endpoint.AbsoluteUri, 13, true), Row(Action("修改只读连接", EditMonitorConnection), Action("移除本机连接", RemoveMonitorConnection))),
            Fields(Row(polling, Text("此页可见时每 30 秒刷新", 13)), Row(Action("刷新监测", RefreshMonitoring, true), cancelRead)),
            monitorStatus, Text("切换页面、最小化或关闭到托盘会暂停读取。离开后重新打开本页，自动刷新默认关闭。", 12, true))));
        monitorRows = new StackPanel { Spacing = 16 }; monitorRows.Tag = "Monitor.Rows"; page.Children.Add(monitorRows);
        RenderMonitorRows(connection);
        UpdateMonitorVisibility();
    }

    private void RenderMonitorRows(MonitorReadConnection connection)
    {
        if (monitorRows == null) return;
        monitorRows.Children.Clear();
        var instances = store.ListInstances().ToDictionary(i => i.RelativePath, i => i.Plan, StringComparer.Ordinal);
        var now = DateTimeOffset.UtcNow;
        foreach (var (relative, uuid) in connection.Bindings)
        {
            var label = instances.TryGetValue(relative, out var plan) ? plan.Text("Provider") + " / " + plan.Text("Instance") : "已移除的实例 · 请重新绑定";
            var node = monitorSnapshot?.Nodes.GetValueOrDefault(uuid);
            var state = monitorSnapshot == null ? "尚未读取" : node == null ? "未返回节点 · 核对授权与 UUID" : node.Status(now, monitorSnapshot.ReceivedAt, monitorReadFailed);
            var card = Column(Text(label, 18), Text(state, 14, state != "在线"), Text("监测节点 " + uuid, 12, true));
            if (node?.Metrics is { } metrics)
            {
                card.Children.Add(Text($"CPU {metrics.CpuPercent.ToString("0.0", CultureInfo.InvariantCulture)}%   ·   内存 {MonitorBytes(metrics.MemoryUsed)} / {MonitorBytes(metrics.MemoryTotal)}"));
                card.Children.Add(Text($"上传 {MonitorBytes(metrics.UploadPerSec)}/s   ·   下载 {MonitorBytes(metrics.DownloadPerSec)}/s"));
                card.Children.Add(Text($"累计上传 {MonitorBytes(metrics.UploadTotal)}   ·   累计下载 {MonitorBytes(metrics.DownloadTotal)}", 13, true));
            }
            if (node?.ReportAt is { } reported) card.Children.Add(Text("最近上报 " + reported.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz"), 12, true));
            monitorRows.Children.Add(Card(card));
        }
        monitorRenderedAt = now; ScheduleMonitorExpiry();
    }

    private static string MonitorBytes(long bytes)
    {
        var value = (double)bytes; string[] units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]; var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return value.ToString("0.##", CultureInfo.InvariantCulture) + " " + units[unit];
    }

    private async Task RefreshMonitoring()
    {
        if (monitorCancellation != null || !MonitorVisible) return;
        // Synthetic native UI sessions must never turn arbitrary text fields
        // into a new network permission. Their transport is an inert handler.
        if (testSession != null && monitorTestHandler == null) { monitorMessage = "隔离界面测试未配置合成监测传输。"; if (monitorStatus != null) monitorStatus.Text = monitorMessage; return; }
        MonitorReadConnection? connection;
        try { connection = MonitorArchive.Load(); }
        catch (OperationException safe) { monitorReadFailed = true; monitorMessage = safe.Message; if (monitorStatus != null) monitorStatus.Text = monitorMessage; monitorRows?.Children.Clear(); return; }
        if (connection == null) { monitorSnapshot = null; monitorRows?.Children.Clear(); monitorMessage = "只读连接已移除。"; if (monitorStatus != null) monitorStatus.Text = monitorMessage; return; }
        var existing = store.ListInstances().Select(i => i.RelativePath).ToHashSet(StringComparer.Ordinal);
        if (connection.Bindings.Keys.Any(relative => !existing.Contains(relative)))
        {
            monitorReadFailed = true; monitorSnapshot = null; monitorExpiryTimer.Stop(); monitorMessage = "绑定实例已移除，请先修改只读连接。";
            if (monitorStatus != null) monitorStatus.Text = monitorMessage; RenderMonitorRows(connection); return;
        }
        if (connection.Identity != monitorIdentity) { monitorSnapshot = null; monitorIdentity = connection.Identity; }
        var cancellation = new CancellationTokenSource(); monitorCancellation = cancellation;
        monitorMessage = "正在读取监测快照…"; if (monitorStatus != null) monitorStatus.Text = monitorMessage;
        try
        {
            monitorClient ??= monitorTestHandler == null ? new MonitorReadClient() : new MonitorReadClient(monitorTestHandler());
            var result = await monitorClient.FetchAsync(connection, cancellation.Token);
            if (cancellation.IsCancellationRequested || !MonitorVisible) return;
            var current = MonitorArchive.Load();
            if (current?.Identity != connection.Identity)
            {
                monitorSnapshot = null; monitorExpiryTimer.Stop(); monitorIdentity = current?.Identity; monitorReadFailed = true; monitorMessage = "只读连接已变化，请重新读取。";
                monitorRows?.Children.Clear(); if (monitorStatus != null) monitorStatus.Text = monitorMessage; return;
            }
            monitorSnapshot = result; monitorReadFailed = false;
            monitorMessage = "已读取 " + result.ReceivedAt.ToLocalTime().ToString("HH:mm:ss") + " · May Monitor " + result.ServerVersion;
        }
        catch (Exception) when (cancellation.IsCancellationRequested) { if (MonitorVisible) monitorMessage = "读取已取消，保留最近快照。"; }
        catch (Exception error)
        {
            monitorReadFailed = true;
            monitorMessage = error is OperationException safe ? safe.Message : "监测读取未完成，请核对只读连接。";
        }
        finally
        {
            if (ReferenceEquals(monitorCancellation, cancellation)) monitorCancellation = null;
            cancellation.Dispose();
            if (MonitorVisible && monitorIdentity == connection.Identity)
            {
                if (monitorStatus != null) monitorStatus.Text = monitorMessage;
                RenderMonitorRows(connection);
            }
        }
    }

    private async Task EditMonitorConnection()
    {
        MonitorReadConnection? previous = null;
        try { previous = MonitorArchive.Load(); } catch (OperationException) { /* Repair only after explicit save. */ }
        var model = new JsonObject { ["Endpoint"] = previous?.Endpoint.AbsoluteUri ?? "" };
        var password = SecretField("专用只读令牌", previous?.Token ?? ""); password.Tag = "Monitor.Token";
        var bindings = new List<(string Relative, JsonObject Value)>();
        var panel = Column(Field("May Monitor HTTPS 地址", model, "Endpoint"), password,
            Action("生成新只读令牌", () => { password.Password = MonitorReadConnection.NewToken(); return Task.CompletedTask; }),
            Text("逐项填写服务端已有节点的 UUID。留空的实例不接入监测；相同名称或 IP 不会自动绑定。", 13, true));
        foreach (var instance in store.ListInstances())
        {
            var value = new JsonObject { ["Uuid"] = previous?.Bindings.GetValueOrDefault(instance.RelativePath) ?? "" };
            bindings.Add((instance.RelativePath, value));
            var field = Field("监测节点 UUID", value, "Uuid"); field.Tag = "Monitor.Binding." + instance.RelativePath;
            panel.Children.Add(Column(Text(instance.Plan.Text("Provider") + " / " + instance.Plan.Text("Instance"), 14), field));
        }
        MonitorReadConnection Draft() => new(model.Text("Endpoint"), password.Password, bindings.Where(b => b.Value.Text("Uuid").Trim() != "").ToDictionary(b => b.Relative, b => b.Value.Text("Uuid").Trim(), StringComparer.Ordinal));
        var validation = Text("", 13, true); validation.Tag = "Monitor.Validation";
        var provisioning = new TextBox { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 100, Tag = "Monitor.Provisioning", PlaceholderText = "预览仅包含摘要、节点授权范围和 30 天有效期。" };
        panel.Children.Add(Action("预览服务端授权配置", () => { try { provisioning.Text = Draft().ProvisioningEnvironment(DateTimeOffset.UtcNow); validation.Text = ""; } catch (OperationException safe) { provisioning.Text = ""; validation.Text = safe.Message; } return Task.CompletedTask; }));
        panel.Children.Add(provisioning);
        panel.Children.Add(Text("由服务端管理员在独立的环境配置中应用授权并重启服务。轮换或撤销也在服务端完成。本机保存使用加密私人归档。v0.1.0-rc.1 尚不含此只读接口，需要后续配套发行。", 12, true));
        panel.Children.Add(validation);
        var dialog = OperationDialog("May Monitor 只读连接", panel, "保存连接");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try { MonitorArchive.Save(Draft()); }
            catch (Exception error) { args.Cancel = true; validation.Text = error is OperationException safe ? safe.Message : "只读连接未能保存，请核对私人归档目录。"; }
        };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) { password.Password = ""; return; }
        password.Password = "";
        StopMonitoring(); monitorIdentity = null; monitorSnapshot = null;
        Navigate("monitoring"); Show("只读连接已保存，可手动刷新验证。");
    }

    private async Task RemoveMonitorConnection()
    {
        var dialog = OperationDialog("移除本机只读连接", Column(Text("删除本机加密连接及内存快照。服务端的授权由管理员移除或轮换摘要后重启撤销。", 14)), "移除连接");
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        StopMonitoring(); MonitorArchive.Remove(); monitorSnapshot = null; monitorIdentity = null; Navigate("monitoring");
    }

    private Func<HttpMessageHandler>? monitorTestHandler;
}
