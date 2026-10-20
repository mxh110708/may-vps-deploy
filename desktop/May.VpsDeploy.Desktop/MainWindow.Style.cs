using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private static PasswordBox SecretField(string label, string value = "") => DesktopTypography.Mark(new PasswordBox
    {
        Header = label, Password = value, PasswordRevealMode = PasswordRevealMode.Hidden, FontFamily = InterfaceFont, FontSize = 13,
        MinHeight = 38, CornerRadius = new CornerRadius(6), Padding = new Thickness(12, 9, 12, 9), BorderThickness = new Thickness(1),
        BorderBrush = Brush(Paint.InputBorder), Background = Brush(Paint.Input), Foreground = Brush(Paint.Text)
    }, TypeRole.Body, 14);

    private static Style DialogButton(bool accent)
    {
        var style = new Style { TargetType = typeof(Button) };
        foreach (var setter in new[]
        {
            new Setter(Control.BackgroundProperty, Brush(accent ? Paint.Accent : Paint.Button)),
            new Setter(Control.ForegroundProperty, Brush(accent ? Paint.AccentText : Paint.Text)),
            new Setter(Control.BorderBrushProperty, Brush(accent ? Paint.Accent : Paint.ButtonBorder)),
            new Setter(Control.BorderThicknessProperty, new Thickness(1)), new Setter(Control.CornerRadiusProperty, new CornerRadius(6)),
            new Setter(Control.FontFamilyProperty, InterfaceFont), new Setter(Control.FontSizeProperty, DesktopTypography.Size(TypeRole.Body, 14)),
            new Setter(Control.PaddingProperty, new Thickness(16, 8, 16, 8))
        }) style.Setters.Add(setter);
        return style;
    }

    private async Task<ContentDialogResult> ShowDialog(ContentDialog dialog)
    {
        if (minimizedToTray) RestoreFromTray(false);
        dialog.RequestedTheme = DesktopTheme.IsLight ? ElementTheme.Light : ElementTheme.Dark;
        dialog.FontFamily = InterfaceFont; dialog.Background = Brush(Paint.Surface); dialog.Foreground = Brush(Paint.Text); dialog.CornerRadius = new CornerRadius(12);
        dialog.PrimaryButtonStyle = DialogButton(true); dialog.CloseButtonStyle = DialogButton(false);
        dialog.SecondaryButtonStyle = DialogButton(false);
        if (dialog.Title is string title) { Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(dialog, title); dialog.Title = Text(title, 22); }
        ApplyFont(dialog);
        // An explicit button click or keyboard focus is required to submit an operation.
        dialog.DefaultButton = ContentDialogButton.None;
        activeTestDialog = dialog;
        try { return await dialog.ShowAsync(); }
        finally { if (activeTestDialog == dialog) activeTestDialog = null; }
    }

    private static Grid SectionHeading(string title, Symbol icon, string? description = null)
    {
        var grid = new Grid { ColumnSpacing = 12 };
        grid.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new());
        grid.Children.Add(new SymbolIcon(icon) { Width = 20, Height = 20, Foreground = Brush(Paint.Accent), VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 2, 0, 0) });
        var label = new StackPanel { Spacing = 5 };
        var heading = Text(title, 16); heading.FontWeight = Microsoft.UI.Text.FontWeights.SemiBold; label.Children.Add(heading);
        if (description != null) label.Children.Add(Text(description, 12, true));
        Grid.SetColumn(label, 1); grid.Children.Add(label); return grid;
    }

    private static Border SettingsGroup(params UIElement[] rows)
    {
        var panel = new StackPanel();
        for (var i = 0; i < rows.Length; i++)
        {
            panel.Children.Add(rows[i]);
            if (i < rows.Length - 1) panel.Children.Add(new Border { Height = 1, Background = Brush(Paint.Border) });
        }
        return new Border { Background = Brush(Paint.Surface), BorderBrush = Brush(Paint.Border), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Child = panel };
    }

    private static Grid SettingRow(string title, string description, Symbol icon, FrameworkElement control)
        => SettingRow(title, description, new SymbolIcon(icon) { Width = 20, Height = 20, Foreground = Brush(Paint.Icon) }, control);

    private static Grid SettingRow(string title, string description, FrameworkElement icon, FrameworkElement control)
    {
        var grid = new Grid { Padding = new Thickness(22, 19, 22, 19), ColumnSpacing = 18 };
        grid.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        icon.VerticalAlignment = VerticalAlignment.Center; grid.Children.Add(icon);
        var text = new StackPanel { Spacing = 5, VerticalAlignment = VerticalAlignment.Center };
        text.Children.Add(Text(title, 14)); if (description.Length != 0) text.Children.Add(Text(description, 12, true));
        Grid.SetColumn(text, 1); grid.Children.Add(text);
        control.VerticalAlignment = VerticalAlignment.Center; control.HorizontalAlignment = HorizontalAlignment.Right;
        Grid.SetColumn(control, 2); grid.Children.Add(control); return grid;
    }

    private static TextBlock GroupLabel(string title) => DesktopTypography.Mark(new TextBlock { Text = title, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, Foreground = Brush(Paint.Muted), Margin = new Thickness(2, 2, 0, -8) }, TypeRole.Title, 14);

    private static Grid Trailing(FrameworkElement left, FrameworkElement right)
    {
        var grid = new Grid { ColumnSpacing = 20, RowSpacing = 14 };
        grid.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        grid.RowDefinitions.Add(new() { Height = GridLength.Auto }); grid.RowDefinitions.Add(new() { Height = GridLength.Auto });
        grid.Children.Add(left); Grid.SetColumn(right, 1); grid.Children.Add(right);
        grid.SizeChanged += (_, _) => { var stacked = grid.ActualWidth < 720; Grid.SetRow(right, stacked ? 1 : 0); Grid.SetColumn(right, stacked ? 0 : 1); Grid.SetColumnSpan(left, stacked ? 2 : 1); Grid.SetColumnSpan(right, stacked ? 2 : 1); };
        return grid;
    }
}
