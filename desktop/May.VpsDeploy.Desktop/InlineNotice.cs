using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace May.VpsDeploy.Desktop;

public sealed class InlineNotice : UserControl
{
    private readonly TextBlock text = new() { TextWrapping = TextWrapping.Wrap, FontSize = 14, Foreground = DesktopTheme.Brush(Paint.Text) };
    private readonly Border frame;
    public string Message { get => text.Text; set => text.Text = value; }
    private InfoBarSeverity severity;
    public InfoBarSeverity Severity { get => severity; set { severity = value; frame.Background = DesktopTheme.Brush(value switch { InfoBarSeverity.Error => Paint.Error, InfoBarSeverity.Warning => Paint.Warning, InfoBarSeverity.Success => Paint.Success, _ => Paint.Info }); } }
    public bool IsOpen { get => Visibility == Visibility.Visible; set => Visibility = value ? Visibility.Visible : Visibility.Collapsed; }
    public InlineNotice()
    {
        Visibility = Visibility.Collapsed;
        DesktopTypography.Mark(text, TypeRole.Note, 14);
        var grid = new Grid { ColumnSpacing = 16 }; grid.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) }); grid.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); grid.Children.Add(text);
        var close = new Button { Content = "关闭", VerticalAlignment = VerticalAlignment.Top }; close.Click += (_, _) => IsOpen = false; Grid.SetColumn(close, 1); grid.Children.Add(close); frame = new Border { Background = DesktopTheme.Brush(Paint.Info), CornerRadius = new CornerRadius(8), Padding = new Thickness(18), Child = grid }; Content = frame;
    }
}
