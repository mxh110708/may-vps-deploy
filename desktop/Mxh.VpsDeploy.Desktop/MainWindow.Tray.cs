#nullable enable
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;
using Mxh.VpsDeploy.Windows;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private WindowsTrayIcon? trayIcon;
    private bool minimizedToTray;
    private UIElement CloseBehaviorSetting()
    {
        var options = Column(Text("关闭窗口时", 16));
        foreach (var (value, label) in new[] { ("Tray", "最小到托盘"), ("Exit", "关闭应用") })
        {
            var option = new RadioButton { Content = label, GroupName = "WindowCloseBehavior", IsChecked = settings.Text("CloseBehavior", "Exit") == value };
            option.Checked += (_, _) => { settings["CloseBehavior"] = value; SaveSettings(); };
            options.Children.Add(option);
        }
        options.Children.Add(Text("托盘中可打开应用或退出。关闭到托盘时任务继续；直接退出时先在安全边界结束任务。", 14, true));
        return Card(options);
    }
    private bool MinimizeToTray()
    {
        try
        {
            trayIcon ??= new WindowsTrayIcon(WinRT.Interop.WindowNative.GetWindowHandle(this), Path.Combine(AppContext.BaseDirectory, "assets", "gui", "app.ico"), testSession == null ? "MXH VPS Deploy" : "MXH VPS Deploy 后台测试", () => RestoreFromTray(), RequestTrayExit);
            CancelNodeReorder(); WindowsWindowLifecycle.ResetCaptionInteraction(WinRT.Interop.WindowNative.GetWindowHandle(this));
            AppWindow.Hide(); minimizedToTray = true; return true;
        }
        catch { Show("托盘图标未能创建，窗口保持打开。", InfoBarSeverity.Error); return false; }
    }
    private void RestoreFromTray(bool activate = true)
    {
        WindowsWindowLifecycle.ResetCaptionInteraction(WinRT.Interop.WindowNative.GetWindowHandle(this));
        AppWindow.Show(activate && !backgroundTest); minimizedToTray = false;
        if (activate && !backgroundTest) Activate();
        WindowsWindowLifecycle.ResetCaptionInteraction(WinRT.Interop.WindowNative.GetWindowHandle(this));
        trayIcon?.Dispose(); trayIcon = null;
    }
    private void RequestTrayExit()
    {
        // Reuse normal unsaved-scheme and safe-task-boundary handling.
        RestoreFromTray(); exitFromTray = true; WindowsWindowLifecycle.RequestClose(WinRT.Interop.WindowNative.GetWindowHandle(this));
    }
    private bool exitFromTray;
}
