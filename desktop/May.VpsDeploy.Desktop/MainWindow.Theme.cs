using Microsoft.UI.Xaml;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private void SetAppearance(string value, bool persist = false)
    {
        settings["Appearance"] = value == "Light" ? "Light" : "Dark";
        DesktopTheme.Set(value == "Light");
        AppWindow.TitleBar.ButtonForegroundColor = DesktopTheme.Color(Paint.Text);
        Application.Current.Resources["SystemAccentColor"] = DesktopTheme.Color(Paint.Accent);
        foreach (var (key, role) in new[]
        {
            ("AccentFillColorDefaultBrush", Paint.Accent), ("AccentTextFillColorPrimaryBrush", Paint.Accent),
            ("ContentDialogBackground", Paint.Surface), ("ContentDialogBorderBrush", Paint.ButtonBorder),
            ("TextControlBackgroundFocused", Paint.Input), ("TextControlBackgroundPointerOver", Paint.InputHover),
            ("TextControlForegroundFocused", Paint.Text), ("TextControlBorderBrushFocused", Paint.Accent),
            ("ButtonBackgroundDisabled", Paint.Disabled), ("ButtonForegroundDisabled", Paint.DisabledText)
        }) Application.Current.Resources[key] = Brush(role);
        // Template aliases may retain the previous SystemAccentColor. Bind their state
        // resources directly to the mutable palette used by the rest of the interface.
        foreach (var state in new[] { "", "PointerOver", "Pressed" })
        {
            foreach (var key in new[] { "ToggleSwitchFillOn", "ToggleSwitchStrokeOn", "CheckBoxCheckBackgroundFillChecked", "CheckBoxCheckBackgroundStrokeChecked", "CheckBoxCheckBackgroundFillIndeterminate", "CheckBoxCheckBackgroundStrokeIndeterminate", "RadioButtonOuterEllipseCheckedFill", "RadioButtonOuterEllipseCheckedStroke", "ToggleButtonBackgroundChecked" }) Application.Current.Resources[key + state] = Brush(Paint.Accent);
            foreach (var key in new[] { "CheckBoxCheckGlyphForegroundChecked", "CheckBoxCheckGlyphForegroundIndeterminate", "RadioButtonCheckGlyphFill", "ToggleButtonForegroundChecked" }) Application.Current.Resources[key + state] = Brush(Paint.AccentText);
            Application.Current.Resources["ToggleSwitchKnobFillOn" + state] = new Microsoft.UI.Xaml.Media.SolidColorBrush(Microsoft.UI.Colors.White);
        }
        Application.Current.Resources["AccentFillColorSecondaryBrush"] = Brush(Paint.Accent);
        Application.Current.Resources["AccentFillColorTertiaryBrush"] = Brush(Paint.Accent);
        foreach (var state in new[] { "Selected", "SelectedPointerOver", "SelectedPressed" })
        {
            Application.Current.Resources["ComboBoxItemBackground" + state] = Brush(Paint.InputHover);
            Application.Current.Resources["ComboBoxItemForeground" + state] = Brush(Paint.Text);
        }
        if (Content is FrameworkElement root) root.RequestedTheme = DesktopTheme.IsLight ? ElementTheme.Light : ElementTheme.Dark;
        if (persist) SaveSettings();
    }
}
