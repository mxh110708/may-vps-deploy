using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Automation;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> WindowPlacementRegression(string outputDirectory)
    {
        void Require(bool value, string reason) { if (!value) throw new OperationException(reason); }
        settings.Remove("WindowPlacement"); settings["RememberWindowPlacement"] = false; SelectPage("settings");
        var option = Find<ToggleSwitch>(shell).Single(item => AutomationProperties.GetName(item) == "记住关闭时的窗口位置和大小");
        Require(!option.IsOn, "窗口记忆没有默认关闭。");
        option.IsOn = true;
        Require(ArchiveStore.ReadJson(paths.Resolve("private/desktop-settings.json")).Flag("RememberWindowPlacement"), "窗口记忆选项未保存。");
        var autoUpdate = Find<ToggleSwitch>(shell).Single(item => item.Tag as string == "AutoCheckUpdates");
        autoUpdate.IsOn = true;
        var enabled = ArchiveStore.ReadJson(paths.Resolve("private/desktop-settings.json"));
        Require(enabled.Flag("AutoCheckUpdates") && enabled.Flag("RememberWindowPlacement") && option.IsOn, "更新开关与窗口记忆开关互相影响。");
        autoUpdate.IsOn = false;
        Require(ArchiveStore.ReadJson(paths.Resolve("private/desktop-settings.json")).Flag("RememberWindowPlacement"), "关闭更新开关清除了窗口记忆。");

        var probe = new Window { Content = new Grid(), Title = "May placement isolated regression" };
        var activations = 0; probe.Activated += (_, e) => { if (e.WindowActivationState != WindowActivationState.Deactivated) activations++; };
        var display = WindowsWindowPlacement.Displays().First(item => item.Primary);
        var work = display.WorkArea;
        var expected = new WindowBounds(work.X + 40, work.Y + 60, Math.Min(1000, work.Width - 80), Math.Min(700, work.Height - 120));
        probe.AppWindow.IsShownInSwitchers = false;
        probe.AppWindow.MoveAndResize(new(expected.X, expected.Y, expected.Width, expected.Height));
        var handle = WinRT.Interop.WindowNative.GetWindowHandle(probe);
        var captured = WindowsWindowPlacement.Capture(handle);
        Require(captured.Bounds == expected, "原生窗口正常位置捕获与屏幕坐标不一致。");
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        probe.AppWindow.Closing += (_, _) => SaveWindowPlacement(handle);
        probe.Closed += (_, _) => closed.TrySetResult();
        try
        {
            WindowsWindowLifecycle.RequestClose(handle);
            await closed.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var disk = ArchiveStore.ReadJson(paths.Resolve("private/desktop-settings.json"));
            Require(WindowPlacement.Read(disk["WindowPlacement"]) == captured, "关闭窗口未保存可恢复的位置和大小。");
            SaveWindowPlacementForClose();
            Require(WindowPlacement.Read(settings["WindowPlacement"]) == captured, "后台测试的屏幕外窗口污染了记忆位置。");
            option.IsOn = false;
            disk = ArchiveStore.ReadJson(paths.Resolve("private/desktop-settings.json"));
            Require(!disk.Flag("RememberWindowPlacement") && disk["WindowPlacement"] == null, "关闭记忆没有清除旧窗口位置。");
            Require(activations == 0, "未显示的窗口位置回归获得了焦点。");
            await Capture(Path.Combine(outputDirectory, "settings-window-startup.png"));
            return new() { ["default_off"] = true, ["setting_persisted"] = true, ["native_close_saved"] = true,
                ["normal_bounds_captured"] = true, ["settings_switches_independent"] = true, ["offscreen_test_not_saved"] = true, ["disabled_clears_old_bounds"] = true, ["window_activations"] = activations };
        }
        finally { if (!closed.Task.IsCompleted) probe.Close(); }
    }
}
