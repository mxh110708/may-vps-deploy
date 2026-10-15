using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private static FontFamily InterfaceFont = new("ms-appx:///Fonts/SchibstedGrotesk-400.ttf#Schibsted Grotesk");
    private readonly LocalFonts fonts;
    private bool fontFallback;

    private void SetFont(string id, bool persist = false)
    {
        var source = id switch
        {
            "WenKai" => "ms-appx:///Fonts/LXGWWenKai-Regular.ttf#LXGW WenKai",
            "Route" => "ms-appx:///Fonts/SchibstedGrotesk-400.ttf#Schibsted Grotesk",
            _ => CustomFontSource(fonts.Resolve(id))
        };
        var selected = new FontFamily(source); var previous = settings.Text("FontId", "Route"); settings["FontId"] = id;
        if (persist)
        {
            try { SaveSettings(); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationException) { settings["FontId"] = previous; throw new OperationException("字体选择无法保存，请检查应用数据目录。"); }
        }
        InterfaceFont = selected;
        Application.Current.Resources["ContentControlThemeFontFamily"] = InterfaceFont;
        if (Content is DependencyObject root) ApplyFont(root);
    }
    private string CustomFontSource(LocalFont font)
    {
        // WinUI resolves ms-appx under the executable directory. No system font installation.
        var executableRoot = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
        if (!paths.Root.TrimEnd(Path.DirectorySeparatorChar).Equals(executableRoot, StringComparison.OrdinalIgnoreCase)) throw new OperationException("自定义字体需在应用自己的数据目录中预览。");
        // WinUI uses an app-relative rendering copy; the archive may be on a different disk.
        var name = Path.GetFileName(font.FilePath); var cached = paths.Resolve(".cache/font-rendering/" + name);
        var bytes = LocalFonts.Read(font.FilePath);
        if (!File.Exists(cached)) ArchiveStore.AtomicWrite(cached, bytes);
        else if (ClientSchemes.SourceFingerprint(cached) != ArchiveStore.Digest(bytes)) throw new OperationException("字体渲染副本发生变化，请核对本地文件。");
        return "ms-appx:///.cache/font-rendering/" + Uri.EscapeDataString(name) + "#" + font.Family;
    }
    private static void ApplyFont(DependencyObject root)
    {
        foreach (var control in Find<Control>(root)) control.FontFamily = InterfaceFont;
        foreach (var combo in Find<ComboBox>(root))
            foreach (var item in combo.Items.OfType<ComboBoxItem>()) item.FontFamily = InterfaceFont;
        foreach (var text in Find<TextBlock>(root))
        {
            var source = text.FontFamily?.Source ?? "";
            if (!source.Contains("Segoe Fluent Icons", StringComparison.Ordinal) && !source.Contains("Segoe MDL2", StringComparison.Ordinal) && !source.Contains("SourceSerif4", StringComparison.Ordinal)) text.FontFamily = InterfaceFont;
        }
        foreach (var text in Find<RichTextBlock>(root)) text.FontFamily = InterfaceFont;
        DesktopTypography.Apply(root);
    }
    private UIElement FontSetting()
    {
        var choice = new SelectionComboBox { MinWidth = 190, MaxWidth = 240, MinHeight = 38, FontSize = 13, CornerRadius = new CornerRadius(6), BorderThickness = new Thickness(1), BorderBrush = Brush(Paint.InputBorder), Background = Brush(Paint.Input), Foreground = Brush(Paint.Text), FontFamily = InterfaceFont, Tag = "FontId" };
        DesktopTypography.Mark(choice, TypeRole.Body, 14);
        AutomationProperties.SetName(choice, "界面字体"); var refreshing = false;
        void Refresh()
        {
            refreshing = true; choice.Items.Clear();
            foreach (var (id, title) in new[] { ("Route", "原版（Route 风格）"), ("WenKai", "霞鹜文楷") }.Concat(fonts.List().Select(f => (f.Id, f.DisplayName))))
            {
                var item = new ComboBoxItem { Content = title, Tag = id, FontFamily = InterfaceFont }; choice.Items.Add(item);
                if (id == settings.Text("FontId", "Route")) choice.SelectedItem = item;
            }
            refreshing = false;
        }
        Refresh();
        choice.SelectionChanged += (_, _) =>
        {
            if (refreshing || choice.SelectedItem is not ComboBoxItem item) return;
            var previous = settings.Text("FontId", "Route");
            try { SetFont((string)item.Tag, true); }
            catch (OperationException error) { settings["FontId"] = previous; Refresh(); Show(error.Message, InfoBarSeverity.Warning); }
        };
        var import = Action("导入字体", async () =>
        {
            if (backgroundTest) throw new OperationException("后台测试不打开系统文件选择器；字体导入由隔离回归验证。");
            var picker = new global::Windows.Storage.Pickers.FileOpenPicker(); picker.FileTypeFilter.Add(".ttf"); picker.FileTypeFilter.Add(".otf");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
            var file = await picker.PickSingleFileAsync(); if (file == null) return;
            var font = await Task.Run(() => fonts.Import(file.Path)); SetFont(font.Id, true); Refresh();
            Show("已应用字体：" + font.DisplayName, InfoBarSeverity.Success);
        });
        return SettingRow("界面字体", "字体预览：运维管理 · Aa 123", Symbol.Font, Row(choice, import));
    }
}
