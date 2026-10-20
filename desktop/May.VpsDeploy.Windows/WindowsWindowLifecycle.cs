using System.ComponentModel;
using System.Runtime.InteropServices;

namespace May.VpsDeploy.Windows;

public static class WindowsWindowLifecycle
{
    public static void ResetCaptionInteraction(nint ownWindow)
    {
        GetWindowThreadProcessId(ownWindow, out var process);
        if (process != Environment.ProcessId) throw new ArgumentException("Caption reset requires an owned window.", nameof(ownWindow));
        SendMessageW(ownWindow, 0x001F, 0, 0); // WM_CANCELMODE: cancel the close-button press before hiding.
        SendMessageW(ownWindow, 0x02A2, 0, 0); // WM_NCMOUSELEAVE: let the framework clear its own state too.
        // A cancelled close can hide the custom title bar before Windows sends its
        // leave message. DWM must receive that message to remove caption highlights.
        DwmDefWindowProc(ownWindow, 0x02A2, 0, 0, out _);
        RedrawWindow(ownWindow, 0, 0, 0x0001 | 0x0100 | 0x0400); // INVALIDATE | UPDATENOW | FRAME
    }
    // Window.Close destroys a WinUI window directly. WM_CLOSE follows the same
    // cancellable AppWindow.Closing path as its system close affordance.
    public static void RequestClose(nint ownWindow)
    {
        if (!PostMessageW(ownWindow, 0x0010, 0, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PostMessageW(nint window, uint message, nuint wParam, nint lParam);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(nint window, out uint process);
    [DllImport("user32.dll")] private static extern nint SendMessageW(nint window, uint message, nuint wParam, nint lParam);
    [DllImport("dwmapi.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DwmDefWindowProc(nint window, uint message, nuint wParam, nint lParam, out nint result);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool RedrawWindow(nint window, nint updateRect, nint updateRegion, uint flags);
}
