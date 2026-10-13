using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> MaintenanceRegression(string output)
    {
        if (!launchArguments.Contains("--app-root") || !File.Exists(paths.Resolve("qa-ui-review.fixture.json"))) throw new OperationException("维护界面回归需要隔离工作区。");
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        async Task Shot(string name) { shell.UpdateLayout(); await Task.Delay(120); await Capture(SafePath.Resolve(output, name + ".png")); }
        async Task DialogShot(string name, ContentDialog dialog, Func<Task>? inspect = null)
        {
            var pending = ShowDialog(dialog); await Task.Delay(160); shell.UpdateLayout();
            try
            {
                if (inspect != null) await inspect();
                var frame = Find<Border>(dialog).Where(b => b.ActualWidth >= 250 && b.ActualWidth < shell.ActualWidth - 40 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).First();
                await Capture(SafePath.Resolve(output, name + ".png"), frame);
            }
            finally { dialog.Hide(); await pending; }
        }
        var instance = store.ListInstances().First(); selectedInstance = instance.RelativePath; var plan = instance.Plan; var state = InstanceState(instance.RelativePath);
        SelectPage("instances"); await Task.Delay(120);
        Require(Find<ComboBox>(shell).Single(b => b.Header as string == "选择实例") is InstanceSelector, "实例选择器未阻止滚轮切换。");
        await Shot("instances-scoped-maintenance");
        var stateFile = SafePath.Resolve(paths.Instance(instance.RelativePath), "deployment-state.json"); var oldBytes = File.ReadAllBytes(stateFile);
        try
        {
            var diagnostic = state.DeepClone().AsObject(); diagnostic["HealthReport"] = new JsonObject { ["Status"] = "Warnings", ["Checks"] = new JsonArray(new JsonObject { ["Name"] = "SSH 配置", ["Status"] = "Warning", ["Message"] = "示例：SSH 配置检查失败。" }, new JsonObject { ["Name"] = "Reality 入口", ["Status"] = "Passed", ["Message"] = "核对通过" }) };
            ArchiveStore.WriteJson(stateFile, diagnostic); SelectPage("instances"); await Task.Delay(90);
            Require(Find<TextBlock>(page).Any(t => t.Text == "最近健康检查 · 有待处理项") && Find<TextBlock>(page).Any(t => t.Text.Contains("SSH 配置检查失败")), "健康诊断结果未显示在实例页。");
            shell.UpdateLayout();
            var warning = Find<TextBlock>(page).Single(t => t.Text == "最近健康检查 · 有待处理项");
            Require(warning.TransformToVisual(shell).TransformPoint(new(0, 0)).Y < shell.ActualHeight - 80, "健康异常在首屏之外。");
            await Shot("instances-health-warnings");
        }
        finally { ArchiveStore.AtomicWrite(stateFile, oldBytes); SelectPage("instances"); }
        var scroll = Find<ScrollViewer>(shell).Where(s => s.ActualHeight > 200 && s.ScrollableHeight > 0).OrderByDescending(s => s.ActualWidth).First();
        scroll.ChangeView(null, 400, null, true); await Shot("instances-monitoring-boundaries");
        var core = CoreUpgradeDialog(plan);
        await DialogShot("dialog-proxy-core", core.Dialog, () =>
        {
            Require(core.Options.Text("Scope") == "Protocol" && core.Options.Text("TargetVersion") != "", "核心升级范围或版本不明确。");
            Require(Find<ComboBox>(core.Dialog).All(b => b.Items.Cast<ComboBoxItem>().All(i => !((string)i.Tag).Contains("Komari"))), "代理核心出现监控组件。"); return Task.CompletedTask;
        });
        var monitorState = state.DeepClone().AsObject(); monitorState["KomariInstalled"] = true;
        monitorState.Put("KomariController.Installed", JsonValue.Create(true)); monitorState.Put("Cloudflared.Installed", JsonValue.Create(true));
        monitorState.Remove("MonitoringInventory");
        foreach (var scope in new[] { "KomariAgent", "KomariController", "Tunnel" })
        {
            var sheet = MonitoringDialog(plan, monitorState, scope);
            await DialogShot("dialog-monitor-" + scope, sheet.Dialog, () =>
            {
                Require(sheet.Options.Text("Scope") == scope && !sheet.Options.ContainsKey("Protocol"), "监控操作混入代理协议。");
                Require(Find<ComboBox>(sheet.Dialog).All(b => b.Header as string != "组件" && b.Header as string != "协议"), "监控对象仍允许混搭。"); return Task.CompletedTask;
            });
        }
        var restore = MonitoringDialog(plan, monitorState, "KomariController");
        await DialogShot("dialog-controller-restore-empty", restore.Dialog, async () =>
        {
            Find<ComboBox>(restore.Dialog).Single(b => b.Header as string == "操作").SelectedIndex = 2; await Task.Delay(80);
            Require(!restore.Dialog.IsPrimaryButtonEnabled && restore.Options.Text("Backup") == "", "无主控恢复点仍允许执行。");
        });
        var uninstalled = state.DeepClone().AsObject(); uninstalled["KomariInstalled"] = false;
        var unavailable = MonitoringControls(plan, uninstalled);
        page.Children.Clear(); page.Children.Add(unavailable); shell.UpdateLayout();
        Require(Find<Button>(unavailable).Single(b => b.Content as string == "安装 Agent").IsEnabled && !Find<Button>(unavailable).Any(b => b.Content as string == "管理 Agent"), "未安装 Agent 缺少安装入口或允许维护。");
        var offlinePlan = plan.DeepClone().AsObject(); offlinePlan.Put("Komari.Enabled", JsonValue.Create(false));
        var offlineState = new JsonObject { ["DesktopImport"] = new JsonObject { ["KomariAgentLastKnown"] = new JsonObject { ["Installed"] = true }, ["KomariControllerLastKnown"] = new JsonObject { ["Version"] = "1.5.0-fix1" }, ["CloudflaredLastKnown"] = new JsonObject { ["Installed"] = true } } };
        var pendingMonitoring = MonitoringControls(offlinePlan, offlineState); page.Children.Clear(); page.Children.Add(pendingMonitoring); shell.UpdateLayout();
        Require(Find<Button>(pendingMonitoring).Count(b => b.Content as string == "核对并纳管" && b.IsEnabled) == 3, "历史监控归档无法发起只读核对。");
        Require(Find<Button>(pendingMonitoring).All(b => !(b.Content as string ?? "").StartsWith("管理")), "历史监控信息直接开放远端维护。");
        var now = DateTimeOffset.UtcNow;
        store.AppendHistory(new("qa-history-1", OperationKind.HealthAudit, now, now, TaskOutcome.Completed, "health", InstanceRelativePath: instance.RelativePath));
        store.AppendHistory(new("qa-history-2", OperationKind.Komari, now, now, TaskOutcome.Cancelled, "maintenance-transaction-status", InstanceRelativePath: instance.RelativePath, TargetLabel: "Komari Agent · 升级"));
        store.AppendHistory(new("qa-history-3", OperationKind.Recover, now, now, TaskOutcome.Failed, "maintenance-transaction-status", "示例：连接超时。", "SshTimeout", "核对当前 SSH 端口后重试。", instance.RelativePath));
        SelectPage("records"); await Shot("records-delete-controls");
        Require(Find<Button>(shell).Count(b => b.Content as string == "删除记录") == 3 && Find<Button>(shell).Single(b => b.Content as string == "清空记录").IsEnabled, "缺少逐条删除或清空入口。");
        Require(!Find<TextBlock>(page).Any(t => t.Text.Contains("+00:00")), "记录仍显示原始 UTC 时间。");
        var history = new TaskHistory(store);
        await DialogShot("dialog-clear-history", HistoryDeletionDialog(history.ReviewDeletion()));
        var initialTheme = DesktopTheme.IsLight;
        try
        {
            SetAppearance("Light"); SelectPage("records"); await Shot("records-delete-controls-light");
            await DialogShot("dialog-proxy-core-light", CoreUpgradeDialog(plan).Dialog);
        }
        finally { SetAppearance(initialTheme ? "Light" : "Dark"); }
        history.Delete(history.ReviewDeletion("qa-history-1")); SelectPage("records");
        Require(Find<Button>(shell).Count(b => b.Content as string == "删除记录") == 2, "单条删除后列表未更新。");
        history.Delete(history.ReviewDeletion()); SelectPage("records"); await Shot("records-cleared");
        Require(!Find<Button>(shell).Single(b => b.Content as string == "清空记录").IsEnabled, "空列表仍允许清空。");
        var wheel = await SelectorWheelRegression();
        return new JsonObject { ["scoped_proxy_targets"] = true, ["monitor_components_separate"] = true, ["uninstalled_agent_installable"] = true,
            ["empty_restore_disabled"] = true, ["single_and_all_history_deletion"] = true, ["local_timestamps"] = true, ["dark_and_light"] = true, ["wheel"] = wheel, ["remote_connections"] = 0 };
    }
    private async Task<JsonObject> SelectorWheelRegression()
    {
        if (backgroundTest) return new JsonObject { ["message_delivery_available"] = false, ["skipped"] = "后台测试不发送鼠标消息；实体滚轮手势需人工检查。" };
        // Send wheel messages only to this QA window and its own input island;
        // never move the system pointer, focus another app or use global input.
        page.Children.Clear(); var model = new JsonObject { ["value"] = "5" }; var choices = Enumerable.Range(0, 12).Select(i => (i.ToString(), "实例 " + i)).ToArray();
        var baseline = Choice("隔离基准", model, "value", choices); var guarded = Choice("隔离实例选择", new JsonObject { ["value"] = "5" }, "value", choices, preventWheelSelection: true);
        page.Children.Add(baseline); page.Children.Add(guarded); page.Children.Add(new Border { Height = 1500 }); shell.UpdateLayout(); Activate(); await Task.Delay(250);
        var owner = WinRT.Interop.WindowNative.GetWindowHandle(this); var handles = new List<nint> { owner };
        void Children(nint parent, int depth)
        {
            if (depth > 12) return;
            for (var child = GetWindow(parent, 5); child != 0; child = GetWindow(child, 2))
            {
                var name = new StringBuilder(256); GetClassNameW(child, name, name.Capacity);
                if (IsWindowVisible(child) && (name.ToString().Contains("InputSite", StringComparison.Ordinal) || name.ToString().Contains("DesktopChildSiteBridge", StringComparison.Ordinal))) handles.Add(child);
                Children(child, depth + 1);
            }
        }
        Children(owner, 0);
        var received = 0; PointerEventHandler handler = (_, _) => received++;
        shell.AddHandler(UIElement.PointerWheelChangedEvent, handler, true);
        try
        {
            async Task Wheel(ComboBox box)
            {
                box.Focus(FocusState.Programmatic); await Task.Delay(80);
                var point = box.TransformToVisual(shell).TransformPoint(new global::Windows.Foundation.Point(box.ActualWidth / 2, box.ActualHeight - 16));
                var native = new WheelPoint { X = (int)(point.X * shell.XamlRoot.RasterizationScale), Y = (int)(point.Y * shell.XamlRoot.RasterizationScale) };
                if (!ClientToScreen(owner, ref native)) throw new OperationException("隔离滚轮坐标转换失败。");
                var data = unchecked((nint)((uint)(ushort)native.X | ((uint)(ushort)native.Y << 16)));
                foreach (var handle in handles)
                {
                    var client = native; ScreenToClient(handle, ref client);
                    PostMessageW(handle, 0x0200, 0, unchecked((nint)((uint)(ushort)client.X | ((uint)(ushort)client.Y << 16)))); await Task.Delay(80);
                    PostMessageW(handle, 0x020A, unchecked((nint)((uint)(ushort)(short)-120 << 16)), data); await Task.Delay(120);
                }
            }
            for (var attempt = 0; attempt < 3 && baseline.SelectedIndex == 5; attempt++) await Wheel(baseline);
            var baselineChanged = baseline.SelectedIndex != 5;
            // Some desktop/input-island states ignore posted mouse messages.
            // Record that harness limitation instead of claiming a wheel pass.
            if (!baselineChanged || received == 0) return new JsonObject { ["message_delivery_available"] = false, ["native_wheel_received"] = received, ["skipped"] = "WinUI did not route the QA window messages to the baseline selector." };
            var scroll = Find<ScrollViewer>(shell).Where(s => s.ActualHeight > 200 && s.ScrollableHeight > 0).OrderByDescending(s => s.ActualWidth).First();
            var offset = scroll.VerticalOffset; var before = guarded.SelectedIndex; var wheelCount = received;
            for (var attempt = 0; attempt < 3 && received == wheelCount; attempt++) await Wheel(guarded);
            RequireWheel(received > wheelCount, "隔离实例选择器未收到滚轮消息。");
            RequireWheel(guarded.SelectedIndex == before, "滚轮仍改变关闭的实例选择。");
            RequireWheel(scroll.VerticalOffset > offset, "阻止实例滚轮选择后页面不能滚动。");
            guarded.IsDropDownOpen = true; await Task.Delay(100); guarded.SelectedIndex = 7; guarded.IsDropDownOpen = false;
            RequireWheel(guarded.SelectedIndex == 7, "显式实例选择不可用。");
            return new JsonObject { ["message_delivery_available"] = true, ["native_wheel_received"] = received, ["baseline_changes"] = baselineChanged, ["closed_selector_unchanged"] = true, ["page_still_scrolls"] = true, ["explicit_selection_works"] = true };
        }
        finally { shell.RemoveHandler(UIElement.PointerWheelChangedEvent, handler); SelectPage("instances"); }
        static void RequireWheel(bool value, string message) { if (!value) throw new OperationException(message); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct WheelPoint { public int X; public int Y; }
    [DllImport("user32.dll", ExactSpelling = true)] private static extern nint GetWindow(nint window, uint command);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern int GetClassNameW(nint window, StringBuilder name, int count);
    [DllImport("user32.dll", ExactSpelling = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ClientToScreen(nint window, ref WheelPoint point);
    [DllImport("user32.dll", ExactSpelling = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ScreenToClient(nint window, ref WheelPoint point);
    [DllImport("user32.dll", ExactSpelling = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindowVisible(nint window);
}
