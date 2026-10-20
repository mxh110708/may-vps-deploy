using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private UIElement PrivateDirectorySetting() => SettingRow("私人归档", paths.Private, Symbol.Folder, Row(
        Action("打开目录", () => { if (backgroundTest) throw new OperationException("后台测试不打开资源管理器。"); SafePath.CheckLinks(paths.Private); Directory.CreateDirectory(paths.Private); System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(paths.Private) { UseShellExecute = true }); return Task.CompletedTask; }),
        Action("修改目录", ChangePrivateDirectory)));
    private async Task ChangePrivateDirectory()
    {
        if (backgroundTest) throw new OperationException("后台测试不打开系统目录选择器；归档迁移由隔离回归验证。");
        if (SchemeChanged && !await ExitScheme(false)) return;
        var picker = new global::Windows.Storage.Pickers.FolderPicker(); picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var folder = await picker.PickSingleFolderAsync(); if (folder == null) return;
        var mover = new PrivateDirectory(store); var review = await Task.Run(() => mover.Review(folder.Path));
        if (await ShowDialog(PrivateDirectoryDialog(review)) != ContentDialogResult.Primary) return;
        PrivateDirectoryResult? result = null;
        scheme = null;
        await RunBackground("迁移私人归档", async token => result = await Task.Run(() => mover.Move(review, token, WindowsPrivateDirectoryAccess.Prepare), token));
        scheme = null; SelectPage("settings");
        Show(result!.SourceRemoved ? "归档目录已修改，现有数据已迁移并校验，旧副本已移除。" : "新归档目录已启用。旧目录仍有被占用或变化的文件，已保留，请核对后清理。", result.SourceRemoved ? InfoBarSeverity.Success : InfoBarSeverity.Warning);
    }
    private ContentDialog PrivateDirectoryDialog(PrivateDirectoryReview review) => OperationDialog("修改归档目录", Column(
        Text("当前目录", 14), Text(review.Source, 14, true), Text("新目录", 14), Text(review.Destination, 14, true),
        Text($"迁移 {review.Files} 个文件，约 {review.Bytes / (1024d * 1024):0.##} MB。", 14),
        Text("实例、凭据、配置方案、字体和任务记录一起迁移；校验完成后移除旧副本。配置方案的候选结果需要重新生成和校验。", 14, true)), "迁移并使用");
}
