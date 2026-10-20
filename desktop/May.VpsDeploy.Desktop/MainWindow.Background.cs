using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private bool backgroundTest;
    private int testActivations;
    private int testForegroundSamples;
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? foregroundMonitor;
    internal void ShowInBackground()
    {
        backgroundTest = true;
        var handle = WinRT.Interop.WindowNative.GetWindowHandle(this);
        WindowsTestWindow.PreventActivation(handle);
        AppWindow.IsShownInSwitchers = false;
        AppWindow.Move(new(-32000, -32000));
        Activated += (_, args) => { if (args.WindowActivationState != WindowActivationState.Deactivated) testActivations++; };
        foregroundMonitor = DispatcherQueue.CreateTimer(); foregroundMonitor.Interval = TimeSpan.FromMilliseconds(40);
        foregroundMonitor.Tick += (_, _) => { if (WindowsTestWindow.IsForeground(handle)) testForegroundSamples++; };
        foregroundMonitor.Start(); Closed += (_, _) => foregroundMonitor.Stop();
        AppWindow.Show(false);
    }
    private JsonObject BackgroundProof() => new()
    {
        ["background"] = backgroundTest, ["window_activations"] = testActivations, ["foreground_samples"] = testForegroundSamples,
        ["offscreen"] = AppWindow.Position.X < -10000 && AppWindow.Position.Y < -10000, ["shown_in_switchers"] = AppWindow.IsShownInSwitchers,
        ["minimized_to_tray"] = minimizedToTray, ["tray_registered"] = trayIcon != null,
        ["startup_placement"] = startupPlacement?.DeepClone()
    };
}
