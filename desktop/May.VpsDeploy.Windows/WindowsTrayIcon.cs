using System.ComponentModel;
using System.Runtime.InteropServices;

namespace May.VpsDeploy.Windows;

/// <summary>Own-window notification icon; callbacks run on the window's UI thread.</summary>
public sealed class WindowsTrayIcon : IDisposable
{
    private const uint CallbackMessage = 0x8052;
    private readonly nint window;
    private readonly Action open;
    private readonly Action exit;
    private readonly SubclassProcedure procedure;
    private readonly uint taskbarCreated;
    private NotifyIconData data;
    private bool disposed;
    public WindowsTrayIcon(nint window, string iconPath, string title, Action open, Action exit)
    {
        this.window = window; this.open = open; this.exit = exit; procedure = WindowMessage;
        var icon = LoadImageW(0, iconPath, 1, 32, 32, 0x10);
        if (icon == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        data = new() { Size = (uint)Marshal.SizeOf<NotifyIconData>(), Window = window, Id = 1, Flags = 1 | 2 | 4, Callback = CallbackMessage, Icon = icon, Tip = title, Info = "", InfoTitle = "" };
        taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
        if (!SetWindowSubclass(window, procedure, 1, 0)) { DestroyIcon(icon); throw new Win32Exception(Marshal.GetLastWin32Error()); }
        if (!AddIcon()) { RemoveWindowSubclass(window, procedure, 1); DestroyIcon(icon); throw new Win32Exception(Marshal.GetLastWin32Error()); }
    }
    private bool AddIcon()
    {
        if (!Shell_NotifyIconW(0, ref data)) return false;
        data.Version = 4; Shell_NotifyIconW(4, ref data); return true;
    }
    private nint WindowMessage(nint handle, uint message, nuint wParam, nint lParam, nuint id, nuint reference)
    {
        if (message == taskbarCreated && !disposed) AddIcon();
        if (message == CallbackMessage && !disposed)
        {
            var notification = (uint)((long)lParam & 0xffff);
            if (notification is 0x0203 or 0x0400 or 0x0401) open();
            else if (notification is 0x0205 or 0x007b) ShowMenu();
            return 0;
        }
        return DefSubclassProc(handle, message, wParam, lParam);
    }
    private void ShowMenu()
    {
        var menu = CreatePopupMenu(); if (menu == 0) return;
        try
        {
            AppendMenuW(menu, 0, 1, "打开应用"); AppendMenuW(menu, 0, 2, "退出");
            GetCursorPos(out var point); SetForegroundWindow(window);
            var selected = TrackPopupMenu(menu, 0x0100 | 0x0080 | 0x0002, point.X, point.Y, 0, window, 0);
            if (selected == 1) open(); else if (selected == 2) exit();
            PostMessageW(window, 0, 0, 0);
        }
        finally { DestroyMenu(menu); }
    }
    public void Dispose()
    {
        if (disposed) return; disposed = true;
        Shell_NotifyIconW(2, ref data); RemoveWindowSubclass(window, procedure, 1); DestroyIcon(data.Icon);
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint Size; public nint Window; public uint Id; public uint Flags; public uint Callback; public nint Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Tip;
        public uint State; public uint StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Info;
        public uint Version;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string InfoTitle;
        public uint InfoFlags; public Guid Item; public nint BalloonIcon;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ScreenPoint { public int X; public int Y; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate nint SubclassProcedure(nint window, uint message, nuint wParam, nint lParam, nuint id, nuint reference);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool Shell_NotifyIconW(uint message, ref NotifyIconData data);
    [DllImport("comctl32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetWindowSubclass(nint window, SubclassProcedure procedure, nuint id, nuint reference);
    [DllImport("comctl32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool RemoveWindowSubclass(nint window, SubclassProcedure procedure, nuint id);
    [DllImport("comctl32.dll")] private static extern nint DefSubclassProc(nint window, uint message, nuint wParam, nint lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint LoadImageW(nint instance, string name, uint type, int width, int height, uint flags);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyIcon(nint icon);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint RegisterWindowMessageW(string message);
    [DllImport("user32.dll")] private static extern nint CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AppendMenuW(nint menu, uint flags, nuint id, string text);
    [DllImport("user32.dll")] private static extern uint TrackPopupMenu(nint menu, uint flags, int x, int y, int reserved, nint owner, nint rectangle);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyMenu(nint menu);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetCursorPos(out ScreenPoint point);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetForegroundWindow(nint window);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PostMessageW(nint window, uint message, nuint wParam, nint lParam);
}
