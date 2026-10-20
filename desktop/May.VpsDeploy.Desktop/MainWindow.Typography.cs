using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private void SetTextSize(TypeRole role, string value)
    {
        if (value is not ("Small" or "Medium" or "Large")) throw new OperationException("字号选项无效。");
        var previous = settings.Text("FontSizes." + role, "Medium"); settings.Put("FontSizes." + role, System.Text.Json.Nodes.JsonValue.Create(value));
        try { SaveSettings(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationException) { settings.Put("FontSizes." + role, System.Text.Json.Nodes.JsonValue.Create(previous)); throw new OperationException("字号选择无法保存。"); }
        DesktopTypography.Load(settings); if (Content is DependencyObject root) DesktopTypography.Apply(root);
    }
    private UIElement TypographySettings()
    {
        settings["FontSizes"] ??= new System.Text.Json.Nodes.JsonObject(); var preferences = settings["FontSizes"]!.AsObject();
        var rows = new List<UIElement>();
        foreach (var (role, title, description) in new[]
        {
            (TypeRole.Title, "标题", "页面名称、卡片与分区标题"), (TypeRole.Body, "功能文字", "导航、按钮、表单与选项"),
            (TypeRole.Note, "注释与说明", "提示、说明和辅助文字"), (TypeRole.Metric, "数值", "概述中的统计数字")
        })
        {
            preferences[role.ToString()] ??= "Medium";
            var selection = new System.Text.Json.Nodes.JsonObject { ["Value"] = preferences.Text(role.ToString()) }; var reverting = false;
            var choice = Choice("", selection, "Value", [("Small", "小"), ("Medium", "中"), ("Large", "大")]); choice.MinWidth = 150; choice.Tag = "FontSize." + role;
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(choice, title + "字号");
            choice.SelectionChanged += (_, _) =>
            {
                if (reverting) return;
                try { SetTextSize(role, selection.Text("Value")); }
                catch (OperationException error) { reverting = true; try { choice.SelectedItem = choice.Items.OfType<ComboBoxItem>().Single(i => i.Tag as string == preferences.Text(role.ToString())); } finally { reverting = false; } Show(error.Message, InfoBarSeverity.Warning); }
            };
            rows.Add(SettingRow(title, description, Symbol.Font, choice));
        }
        return SettingsGroup(rows.ToArray());
    }
}
