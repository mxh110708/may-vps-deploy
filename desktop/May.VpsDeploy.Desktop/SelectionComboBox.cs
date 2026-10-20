using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace May.VpsDeploy.Desktop;

internal sealed class SelectionComboBox : ComboBox
{
    public SelectionComboBox() { DefaultStyleKey = typeof(ComboBox); }
    protected override void OnPointerWheelChanged(PointerRoutedEventArgs e)
    {
        // Scrolling a form must never change an option, even when it has focus.
        // Leave closed-selector input unhandled so the page can scroll; the open
        // list keeps native scrolling, click selection and keyboard navigation.
        if (IsDropDownOpen) base.OnPointerWheelChanged(e);
    }
}
