using System.Runtime.InteropServices;

namespace May.VpsDeploy.Windows;

/// <summary>Only changes the caller's test window. Never injects input or activates another window.</summary>
public static class WindowsTestWindow
{
    public static void PreventActivation(nint handle)
    {
        const int extendedStyle = -20;
        var style = GetWindowLongPtrW(handle, extendedStyle);
        SetWindowLongPtrW(handle, extendedStyle, style | 0x08000000 | 0x00000080); // NOACTIVATE, TOOLWINDOW
        EnableWindow(handle, false); // Block OS focus even when a XAML dialog requests it internally.
    }
    public static bool IsForeground(nint handle) => GetForegroundWindow() == handle;
    [DllImport("user32.dll", ExactSpelling = true)] private static extern nint GetWindowLongPtrW(nint window, int index);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern nint SetWindowLongPtrW(nint window, int index, nint value);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern nint GetForegroundWindow();
    [DllImport("user32.dll", ExactSpelling = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnableWindow(nint window, [MarshalAs(UnmanagedType.Bool)] bool enable);
}
