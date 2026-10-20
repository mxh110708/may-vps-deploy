using Microsoft.UI;
using Microsoft.UI.Xaml.Media;

namespace May.VpsDeploy.Desktop;

internal enum Paint
{
    Canvas, Title, Sidebar, SidebarBorder, SidebarText, SidebarMuted, SidebarIcon, SidebarSelected, SidebarSelectedText, SidebarSelectedIcon,
    Text, Muted, Surface, Border, Input, InputBorder, InputHover, Button, ButtonBorder, Accent, AccentText, Icon, Footer,
    Disabled, DisabledText, Info, Success, Warning, Error
}

internal static class DesktopTheme
{
    private static readonly Dictionary<Paint, SolidColorBrush> brushes = new();
    private static readonly string[] dark =
    [
        "#202227", "#202124", "#1E2025", "#30343C", "#EBEDF1", "#AFB6C0", "#BCC2CD", "#304456", "#D2E9F7", "#A4C7DD",
        "#EBEDF1", "#AFB6C0", "#292D35", "#373C45", "#22252C", "#525965", "#2C313A", "#373C45", "#474D58", "#A4C7DD", "#172631", "#C3CAD4", "#1E2025",
        "#30353D", "#79818D", "#303E4C", "#254438", "#463D27", "#4D2B2F"
    ];
    private static readonly string[] light =
    [
        "#FFFFFF", "#FFFFFF", "#284C86", "#23447A", "#F3F7FF", "#CBD9EE", "#D3E0F4", "#37619D", "#FFFFFF", "#FFFFFF",
        "#263449", "#78869B", "#F7F9FC", "#E3EAF3", "#FFFFFF", "#D5DFED", "#F0F5FD", "#FFFFFF", "#DCE5F1", "#3268E5", "#FFFFFF", "#687D9B", "#F7F9FC",
        "#EAF0F7", "#98A4B5", "#EAF3FF", "#EAF8F0", "#FFF6DF", "#FFF0F0"
    ];
    public static bool IsLight { get; private set; }
    public static global::Windows.UI.Color Color(Paint role)
    {
        var hex = (IsLight ? light : dark)[(int)role];
        return ColorHelper.FromArgb(255, Convert.ToByte(hex[1..3], 16), Convert.ToByte(hex[3..5], 16), Convert.ToByte(hex[5..7], 16));
    }
    public static SolidColorBrush Brush(Paint role)
    {
        if (!brushes.TryGetValue(role, out var value)) brushes[role] = value = new(Color(role));
        return value;
    }
    public static void Set(bool lightMode) { IsLight = lightMode; foreach (var pair in brushes) pair.Value.Color = Color(pair.Key); }
}
