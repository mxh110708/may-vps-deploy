using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    // UI automation posts events; observe them before changing or submitting the next draft.
    private static async Task RegressionPress(ContentDialog dialog, string name)
    {
        var clicked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnClick(ContentDialog sender, ContentDialogButtonClickEventArgs args) => clicked.TrySetResult();
        if (name == "PrimaryButton") dialog.PrimaryButtonClick += OnClick; else dialog.CloseButtonClick += OnClick;
        try
        {
            var button = Find<Button>(dialog).Single(b => b.Name == name);
            ((IInvokeProvider)(FrameworkElementAutomationPeer.CreatePeerForElement(button) ?? new ButtonAutomationPeer(button)).GetPattern(PatternInterface.Invoke)).Invoke();
            await clicked.Task.WaitAsync(TimeSpan.FromSeconds(3));
        }
        finally { if (name == "PrimaryButton") dialog.PrimaryButtonClick -= OnClick; else dialog.CloseButtonClick -= OnClick; }
    }

    private static async Task RegressionInvoke(Button button)
    {
        var clicked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnClick(object sender, RoutedEventArgs args) => clicked.TrySetResult();
        button.Click += OnClick;
        try
        {
            ((IInvokeProvider)(FrameworkElementAutomationPeer.CreatePeerForElement(button) ?? new ButtonAutomationPeer(button)).GetPattern(PatternInterface.Invoke)).Invoke();
            await clicked.Task.WaitAsync(TimeSpan.FromSeconds(3));
        }
        finally { button.Click -= OnClick; }
    }

    private static async Task RegressionFill(TextBox input, string value)
    {
        if (input.Text == value) return;
        var changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnChange(object sender, TextChangedEventArgs args) => changed.TrySetResult();
        input.TextChanged += OnChange;
        try { input.Text = value; await changed.Task.WaitAsync(TimeSpan.FromSeconds(3)); }
        finally { input.TextChanged -= OnChange; }
    }

    private static async Task RegressionSelect(ComboBox input, int index)
    {
        if (input.SelectedIndex == index) return;
        var changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnChange(object sender, SelectionChangedEventArgs args) => changed.TrySetResult();
        input.SelectionChanged += OnChange;
        try { input.SelectedIndex = index; await changed.Task.WaitAsync(TimeSpan.FromSeconds(3)); }
        finally { input.SelectionChanged -= OnChange; }
    }
}
