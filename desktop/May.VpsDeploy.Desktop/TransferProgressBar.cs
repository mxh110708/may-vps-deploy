using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace May.VpsDeploy.Desktop;

// A compact WinUI strip: byte-based fill for transfer/hash work, moving fill only
// while the total is unknown. Start animation after attachment to the window.
internal sealed class TransferProgressBar : Grid
{
    private readonly Border track = new() { CornerRadius = new CornerRadius(2) };
    private readonly Border fill = new() { CornerRadius = new CornerRadius(2), HorizontalAlignment = HorizontalAlignment.Left };
    private readonly TranslateTransform position = new();
    private DispatcherQueueTimer? timer;
    private bool indeterminate;
    private double value;
    public Brush Foreground { get => fill.Background; set => fill.Background = value; }
    public new Brush Background { get => track.Background; set => track.Background = value; }
    public double Value { get => value; set { this.value = Math.Clamp(value, 0, 100); ArrangeFill(); } }
    public bool IsIndeterminate { get => indeterminate; set { indeterminate = value; ArrangeFill(); UpdateAnimation(); } }
    public TransferProgressBar()
    {
        Children.Add(track); Children.Add(fill); fill.RenderTransform = position;
        AutomationProperties.SetName(this, "任务进度");
        SizeChanged += (_, _) => ArrangeFill();
        Loaded += (_, _) =>
        {
            timer ??= DispatcherQueue.CreateTimer(); timer.Interval = TimeSpan.FromMilliseconds(40);
            timer.Tick += Tick; ArrangeFill(); UpdateAnimation();
        };
        Unloaded += (_, _) => { if (timer != null) { timer.Stop(); timer.Tick -= Tick; } };
        RegisterPropertyChangedCallback(VisibilityProperty, (_, _) => UpdateAnimation());
    }
    private void ArrangeFill()
    {
        var width = Math.Max(0, ActualWidth);
        Clip = new RectangleGeometry { Rect = new global::Windows.Foundation.Rect(0, 0, width, Math.Max(0, ActualHeight)) };
        fill.Width = width * (indeterminate ? .25 : value / 100); position.X = indeterminate ? -fill.Width : 0;
    }
    private void UpdateAnimation()
    {
        if (timer == null) return;
        if (indeterminate && Visibility == Visibility.Visible && IsLoaded) timer.Start(); else timer.Stop();
    }
    private void Tick(DispatcherQueueTimer sender, object args)
    {
        position.X += Math.Max(4, ActualWidth / 100);
        if (position.X > ActualWidth) position.X = -fill.Width;
    }
}
