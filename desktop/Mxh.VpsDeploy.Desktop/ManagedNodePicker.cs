using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

internal sealed class ManagedNodePicker
{
    private readonly List<(CheckBox Check, ClientProfiles.NodePair Node)> entries = new();
    private readonly TextBlock count = DesktopTypography.Mark(new TextBlock(), TypeRole.Note, 14);
    internal StackPanel Content { get; }
    internal CheckBox ShowBackups { get; }
    internal Button SelectAll { get; }
    internal Button ClearAll { get; }
    internal HashSet<string> Selected => entries.Where(e => e.Check.Visibility == Visibility.Visible && e.Check.IsChecked == true).Select(e => e.Node.Name).ToHashSet(StringComparer.Ordinal);
    internal event Action? SelectionChanged;
    internal ManagedNodePicker(IEnumerable<ClientProfiles.NodePair> nodes, ISet<string>? existing = null)
    {
        var list = new StackPanel { Spacing = 6 };
        SelectAll = new Button { Content = "全选" }; ClearAll = new Button { Content = "取消全选" };
        foreach (var button in new[] { SelectAll, ClearAll }) DesktopTypography.Mark(button, TypeRole.Body, 14);
        SelectAll.Click += (_, _) => SelectVisible(true); ClearAll.Click += (_, _) => SelectVisible(false);
        ShowBackups = DesktopTypography.Mark(new CheckBox { Content = "显示备用入口", IsChecked = false }, TypeRole.Body, 14);
        foreach (var node in nodes)
        {
            var updating = existing?.Contains(node.Name) == true;
            var check = DesktopTypography.Mark(new CheckBox { Content = node.DisplayName + (updating ? " · 更新来源" : ""), IsChecked = !node.IsBackup && !updating, Visibility = node.IsBackup ? Visibility.Collapsed : Visibility.Visible }, TypeRole.Body, 14);
            check.Checked += (_, _) => RefreshCount(); check.Unchecked += (_, _) => RefreshCount();
            entries.Add((check, node)); list.Children.Add(check);
        }
        ShowBackups.Checked += (_, _) => DisplayBackups(true); ShowBackups.Unchecked += (_, _) => DisplayBackups(false);
        if (entries.Count == 0) list.Children.Add(DesktopTypography.Mark(new TextBlock { Text = "没有可读取的受管节点，请先完成实例部署或恢复。", TextWrapping = TextWrapping.Wrap }, TypeRole.Note, 14));
        ShowBackups.Visibility = entries.Any(e => e.Node.IsBackup) ? Visibility.Visible : Visibility.Collapsed;
        Content = new StackPanel { Spacing = 12, Children = {
            new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, Children = { SelectAll, ClearAll, count } },
            ShowBackups,
            DesktopTypography.Mark(new TextBlock { Text = "已在方案中的节点可勾选更新连接与凭据，保留所在顺序和连接组。", TextWrapping = TextWrapping.Wrap, Visibility = existing?.Count > 0 ? Visibility.Visible : Visibility.Collapsed }, TypeRole.Note, 14),
            DesktopTypography.Mark(new TextBlock { Text = "备用入口使用同一 VPS 的另一 Reality 连接端口，可按需加入；它不是备份归档。", TextWrapping = TextWrapping.Wrap, Visibility = entries.Any(e => e.Node.IsBackup) ? Visibility.Visible : Visibility.Collapsed }, TypeRole.Note, 14),
            new ScrollViewer { Content = list, MaxHeight = 390, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled }
        } };
        RefreshCount();
    }
    internal void SelectVisible(bool selected)
    {
        foreach (var entry in entries.Where(e => e.Check.Visibility == Visibility.Visible)) entry.Check.IsChecked = selected;
        RefreshCount();
    }
    internal void DisplayBackups(bool show)
    {
        foreach (var entry in entries.Where(e => e.Node.IsBackup)) { if (!show) entry.Check.IsChecked = false; entry.Check.Visibility = show ? Visibility.Visible : Visibility.Collapsed; }
        RefreshCount();
    }
    private void RefreshCount() { count.Text = $"已选择 {Selected.Count} 个节点"; SelectionChanged?.Invoke(); }
}
