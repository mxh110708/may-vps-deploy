using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private JsonObject? startupPlacement;
    private void InitializeWindowPlacement()
    {
        var saved = settings.Flag("RememberWindowPlacement") ? WindowPlacement.Read(settings["WindowPlacement"]) : null;
        var displays = WindowsWindowPlacement.Displays();
        var display = displays.FirstOrDefault(item => item.Name == saved?.Display);
        if (display == null) { display = displays.FirstOrDefault(item => item.Primary) ?? displays[0]; saved = null; }
        // Move the still-hidden window onto its target monitor before reading per-window DPI.
        AppWindow.Move(new(display.WorkArea.X, display.WorkArea.Y));
        var scale = WindowsWindowPlacement.Scale(WinRT.Interop.WindowNative.GetWindowHandle(this));
        var bounds = WindowPlacement.Resolve(display.WorkArea, scale, saved);
        AppWindow.MoveAndResize(new(bounds.X, bounds.Y, bounds.Width, bounds.Height));
        startupPlacement = new()
        {
            ["restored"] = saved != null, ["display"] = display.Name, ["scale"] = scale, ["work_area"] = WindowPlacement.Json(display.WorkArea),
            ["bounds"] = WindowPlacement.Json(new(AppWindow.Position.X, AppWindow.Position.Y, AppWindow.Size.Width, AppWindow.Size.Height))
        };
    }
    private UIElement WindowPlacementSetting()
    {
        var remember = new ToggleSwitch { IsOn = settings.Flag("RememberWindowPlacement"), OnContent = "", OffContent = "", MinWidth = 0, Width = 48 };
        AutomationProperties.SetName(remember, "记住关闭时的窗口位置和大小");
        remember.Toggled += (_, _) =>
        {
            settings["RememberWindowPlacement"] = remember.IsOn;
            if (!remember.IsOn) settings.Remove("WindowPlacement");
            SaveSettings();
        };
        return SettingsGroup(SettingRow("记住关闭时的窗口位置和大小", "未开启时，以默认大小在主屏幕中央打开。开启后恢复上次正常窗口；显示器变化时自动调整到可见区域。", Symbol.View, remember));
    }
    private void SaveWindowPlacementForClose()
    {
        if (backgroundTest || !settings.Flag("RememberWindowPlacement")) return;
        SaveWindowPlacement(WinRT.Interop.WindowNative.GetWindowHandle(this));
    }
    private void SaveWindowPlacement(nint window)
    {
        try
        {
            var saved = WindowsWindowPlacement.Capture(window);
            var value = WindowPlacement.Write(saved);
            if (WindowPlacement.Read(value) == null) return;
            settings["WindowPlacement"] = value; SaveSettings();
        }
        catch { Show("窗口位置和大小未能保存，下次将使用原有设置打开。", InfoBarSeverity.Warning); }
    }
}
