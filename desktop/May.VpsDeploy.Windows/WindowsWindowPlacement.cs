using System.ComponentModel;
using System.Runtime.InteropServices;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Windows;

public sealed record WindowDisplay(string Name, WindowBounds WorkArea, bool Primary);

public static class WindowsWindowPlacement
{
    public static WindowDisplay[] Displays()
    {
        var displays = new List<WindowDisplay>();
        MonitorCallback callback = (nint monitor, nint _, ref Rect rectangle, nint data) => { displays.Add(ReadMonitor(monitor)); return true; };
        if (!EnumDisplayMonitors(0, 0, callback, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (displays.Count == 0) throw new InvalidOperationException("No available display.");
        return displays.ToArray();
    }
    public static double Scale(nint window)
    {
        var dpi = GetDpiForWindow(window); return dpi == 0 ? 1 : dpi / 96d;
    }
    public static SavedWindowPlacement Capture(nint window)
    {
        var placement = new Placement { Length = (uint)Marshal.SizeOf<Placement>() };
        if (!GetWindowPlacement(window, ref placement)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var monitor = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>(), Device = "" };
        if (!GetMonitorInfoW(MonitorFromWindow(window, 2), ref monitor)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var normal = placement.Normal;
        // WINDOWPLACEMENT uses workspace coordinates for regular top-level windows.
        // Convert once before persisting screen coordinates; tool windows already use screen coordinates.
        var toolWindow = (GetWindowLongPtrW(window, -20).ToInt64() & 0x80) != 0;
        var dx = toolWindow ? 0 : monitor.Work.Left - monitor.Monitor.Left;
        var dy = toolWindow ? 0 : monitor.Work.Top - monitor.Monitor.Top;
        return new(monitor.Device, new(normal.Left + dx, normal.Top + dy, normal.Right - normal.Left, normal.Bottom - normal.Top), Bounds(monitor.Work), Scale(window));
    }
    private static WindowDisplay ReadMonitor(nint monitor)
    {
        var info = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>(), Device = "" };
        if (!GetMonitorInfoW(monitor, ref info)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new(info.Device, Bounds(info.Work), (info.Flags & 1) != 0);
    }
    private static WindowBounds Bounds(Rect rectangle) => new(rectangle.Left, rectangle.Top, rectangle.Right - rectangle.Left, rectangle.Bottom - rectangle.Top);
    [StructLayout(LayoutKind.Sequential)] private struct Point { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct Placement { public uint Length, Flags, Show; public Point Minimum, Maximum; public Rect Normal; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct MonitorInfo
    {
        public uint Size; public Rect Monitor, Work; public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string Device;
    }
    private delegate bool MonitorCallback(nint monitor, nint dc, ref Rect rectangle, nint data);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumDisplayMonitors(nint dc, nint rectangle, MonitorCallback callback, nint data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetMonitorInfoW(nint monitor, ref MonitorInfo info);
    [DllImport("user32.dll")] private static extern nint MonitorFromWindow(nint window, uint flags);
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(nint window);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetWindowPlacement(nint window, ref Placement placement);
    [DllImport("user32.dll")] private static extern nint GetWindowLongPtrW(nint window, int index);
}
