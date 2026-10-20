using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> StorageRegression(string output)
    {
        if (!launchArguments.Contains("--app-root") || !File.Exists(paths.Resolve("qa-ui-review.fixture.json"))) throw new OperationException("归档界面验证需要隔离工作区。");
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        async Task DialogShot(string name, ContentDialog active)
        {
            shell.UpdateLayout();
            var frame = Find<Border>(active).Where(b => b.ActualWidth >= 250 && b.ActualWidth < shell.ActualWidth - 40 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).First();
            await Capture(SafePath.Resolve(output, name + ".png"), frame);
        }
        var plan = DeploymentPlans.Create(new JsonObject { ["Provider"] = "Example", ["Instance"] = "UI Storage", ["NodeName"] = "Example Node", ["IPv4"] = "192.0.2.10", ["Ipv6"] = "", ["RealityTarget"] = "example.com" }, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")), paths, false);
        var nodes = ClientProfiles.Nodes(plan, new JsonObject()).ToArray();
        var picker = new ManagedNodePicker(nodes); var dialog = OperationDialog("选择节点", picker.Content, "添加");
        var showing = ShowDialog(dialog); await Task.Delay(160);
        try
        {
            Require(picker.Selected.Count == nodes.Count(n => !n.IsBackup), "默认选择包含备用入口。");
            picker.SelectVisible(false); Require(picker.Selected.Count == 0, "取消全选未清空。");
            picker.SelectVisible(true); Require(picker.Selected.Count == nodes.Count(n => !n.IsBackup), "全选包含隐藏备用入口。");
            await DialogShot("node-picker-primary", dialog);
            picker.ShowBackups.IsChecked = true; picker.SelectVisible(true); Require(picker.Selected.Count == nodes.Length, "显示备用入口后的全选不完整。");
            await DialogShot("node-picker-backups", dialog);
            picker.ShowBackups.IsChecked = false; Require(picker.Selected.Count == nodes.Count(n => !n.IsBackup), "隐藏的备用入口仍被添加。");
        }
        finally { dialog.Hide(); await showing; }
        var originalFont = settings.Text("FontId", "Route"); var imported = fonts.Import(paths.Resolve("assets/gui/fonts/SourceSerif4-600.ttf")); SetFont(imported.Id, true);
        var width = FontWidth(InterfaceFont); Require(Math.Abs(width - FontWidth(Microsoft.UI.Xaml.Media.FontFamily.XamlAutoFontFamily)) > 1, "自定义字体没有实际加载。"); var source = paths.Private; var mover = new PrivateDirectory(store);
        var target = Path.Combine(Path.GetDirectoryName(paths.Root)!, "relocated-data-" + Guid.NewGuid().ToString("N"));
        var review = mover.Review(target); var sheet = PrivateDirectoryDialog(review); showing = ShowDialog(sheet); await Task.Delay(160);
        try { await DialogShot("private-directory-review", sheet); } finally { sheet.Hide(); await showing; }
        var moved = await Task.Run(() => mover.Move(review, prepareDestination: WindowsPrivateDirectoryAccess.Prepare));
        Require(moved.SourceRemoved && !Directory.Exists(source) && new AppPaths(paths.Root).Private == target, "迁移未切换或产生旧副本。");
        SetFont(imported.Id); Require(Math.Abs(FontWidth(InterfaceFont) - width) < 0.1 && !fontFallback, "自定义目录中的字体不能渲染。");
        SelectPage("settings"); await Task.Delay(120); Require(Find<TextBlock>(shell).Any(t => t.Text == target), "设置未显示当前归档目录。");
        var scroll = Find<ScrollViewer>(shell).Where(s => s.ActualHeight > 200 && s.ScrollableHeight > 0).OrderByDescending(s => s.ActualWidth).First(); scroll.ChangeView(null, scroll.ScrollableHeight, null, true); await Task.Delay(120);
        await Capture(SafePath.Resolve(output, "settings-custom-private-directory.png"));
        Require((await Task.Run(() => mover.Move(mover.Review(source), prepareDestination: WindowsPrivateDirectoryAccess.Prepare))).SourceRemoved, "回到默认目录未清理旧副本。");
        SetFont(originalFont, true);
        return new JsonObject { ["default_excludes_backup"] = true, ["select_and_clear_visible"] = true, ["backup_opt_in"] = true, ["migration_roundtrip"] = true, ["startup_locator"] = true, ["custom_font_rendered"] = true, ["source_removed"] = true, ["no_production_connections"] = true };
    }
}
