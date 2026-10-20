using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

internal enum TypeRole { Title, Body, Note, Metric }

internal static class DesktopTypography
{
    private static readonly Dictionary<TypeRole, string> choices = new();
    private static readonly DependencyProperty RoleProperty = DependencyProperty.RegisterAttached("TypographyRole", typeof(string), typeof(DesktopTypography), new PropertyMetadata(""));
    private static readonly DependencyProperty BaseProperty = DependencyProperty.RegisterAttached("TypographyBaseSize", typeof(double), typeof(DesktopTypography), new PropertyMetadata(0d));
    public static void Load(JsonObject settings)
    {
        foreach (var role in Enum.GetValues<TypeRole>()) { var value = settings.Text("FontSizes." + role, "Medium"); choices[role] = value is "Small" or "Medium" or "Large" ? value : "Medium"; }
    }
    public static double Size(TypeRole role, double basis)
    {
        var choice = choices.GetValueOrDefault(role, "Medium");
        return role switch
        {
            TypeRole.Note => choice switch { "Small" => 12, "Large" => 16, _ => 14 },
            TypeRole.Body => Math.Max(12, basis + (choice switch { "Small" => -1, "Large" => 2, _ => 0 })),
            TypeRole.Title => basis + (choice switch { "Small" => -2, "Large" => 3, _ => 0 }),
            _ => basis + (choice switch { "Small" => -4, "Large" => 4, _ => 0 })
        };
    }
    public static T Mark<T>(T element, TypeRole role, double basis) where T : DependencyObject
    {
        element.SetValue(RoleProperty, role.ToString()); element.SetValue(BaseProperty, basis); ApplyOne(element); return element;
    }
    private static void ApplyOne(DependencyObject element)
    {
        if (!Enum.TryParse<TypeRole>((string)element.GetValue(RoleProperty), out var role)) return;
        var size = Size(role, (double)element.GetValue(BaseProperty));
        if (element is Control control) control.FontSize = size;
        else if (element is TextBlock text) text.FontSize = size;
        else if (element is RichTextBlock rich) rich.FontSize = size;
    }
    public static void Apply(DependencyObject root)
    {
        ApplyOne(root);
        if (root is ComboBox combo) foreach (var item in combo.Items.OfType<ComboBoxItem>()) item.FontSize = combo.FontSize;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++) Apply(VisualTreeHelper.GetChild(root, i));
    }
}
