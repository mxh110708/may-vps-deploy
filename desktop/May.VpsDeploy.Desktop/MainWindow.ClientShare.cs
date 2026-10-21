using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task ShareClientLinks(JsonObject selected, Func<string, Task>? copy = null, Func<Task<string?>>? folder = null)
    {
        var preview = ClientShareLinks.Preview(selected); var exporter = new ClientShareExport(store); var chosen = new HashSet<string>(StringComparer.Ordinal);
        var options = new JsonObject { ["Format"] = "Plain", ["Name"] = "may-nodes.private.txt" }; var status = Text("", 13, true); status.Tag = "ClientShare.Status";
        var format = Choice("列表格式", options, "Format", [("Plain", "纯文本 · 每行一个链接"), ("Base64", "Base64 · 链接列表编码")]); format.Tag = "ClientShare.Format";
        var fileName = Field("保存文件名", options, "Name"); fileName.Tag = "ClientShare.FileName";
        var count = Text("", 14); count.Tag = "ClientShare.Count"; var rows = new StackPanel { Spacing = 10 }; var checks = new List<CheckBox>(); Button? copyButton = null, saveButton = null;
        void Refresh()
        {
            count.Text = "已选 " + chosen.Count + " / 可分享 " + preview.Rows.Count(r => r.Ready) + "；无法分享 " + preview.Rows.Count(r => !r.Ready) + "。";
            if (copyButton != null) copyButton.IsEnabled = preview.Ready && chosen.Count > 0; if (saveButton != null) saveButton.IsEnabled = preview.Ready && chosen.Count > 0;
        }
        foreach (var row in preview.Rows)
        {
            var check = new CheckBox { Content = row.Name + " · " + row.Protocol, IsEnabled = row.Ready && preview.Ready, IsChecked = row.Ready && preview.Ready, Tag = "ClientShare.Node." + row.Id, MaxWidth = 680 };
            if (check.IsChecked == true) chosen.Add(row.Id);
            check.Checked += (_, _) => { chosen.Add(row.Id); Refresh(); }; check.Unchecked += (_, _) => { chosen.Remove(row.Id); Refresh(); }; checks.Add(check);
            rows.Children.Add(Column(check, Text(row.Message, 13, true)));
        }
        copyButton = Action("复制已选链接", async () =>
        {
            try
            {
                var text = exporter.Generate(selected, preview, chosen.ToArray(), options.Text("Format"));
                if (copy != null) await copy(text);
                else { if (backgroundTest) throw new OperationException("后台测试使用隔离复制接收器。"); var data = new global::Windows.ApplicationModel.DataTransfer.DataPackage(); data.SetText(text); global::Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data); }
                status.Text = "已复制 " + chosen.Count + " 个节点链接。";
            }
            catch (Exception error) when (error is OperationException or IOException or UnauthorizedAccessException) { status.Text = SafeFailures.Describe(error).Message; }
        }); copyButton.Tag = "ClientShare.Copy";
        saveButton = Action("保存已选链接", async () =>
        {
            try
            {
                var name = fileName.Text.Trim();
                if (name.Length is < 1 or > 120 || name != Path.GetFileName(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || !name.EndsWith(".txt", StringComparison.Ordinal)) throw new OperationException("文件名需为不含路径的 .txt 名称。");
                var directory = folder != null ? await folder() : await ShareLinkFolder(); if (directory == null) return;
                var target = Path.Combine(directory, name); exporter.SaveNew(selected, preview, chosen.ToArray(), options.Text("Format"), target); status.Text = "已保存 " + chosen.Count + " 个节点到 " + target;
            }
            catch (Exception error) when (error is OperationException or IOException or UnauthorizedAccessException) { status.Text = SafeFailures.Describe(error).Message; }
        }); saveButton.Tag = "ClientShare.Save";
        var all = Action("全选可分享节点", () => { foreach (var check in checks.Where(c => c.IsEnabled)) check.IsChecked = true; return Task.CompletedTask; }); all.Tag = "ClientShare.All";
        var none = Action("取消全选", () => { foreach (var check in checks) check.IsChecked = false; return Task.CompletedTask; }); none.Tag = "ClientShare.None";
        Refresh();
        var content = Column(Text("分享链接只包含所选节点的连接参数，不包含分组、客户端路由、入口依赖或服务器配置。链接含鉴权信息；Base64 只是编码。", 14, true), format, count, Row(all, none), rows, fileName, Row(copyButton, saveButton), status);
        foreach (var issue in preview.Issues) content.Children.Insert(2, Text(issue.Message, 14));
        var dialog = OperationDialog("分享节点链接", DialogScroll(content), ""); dialog.PrimaryButtonText = ""; await ShowDialog(dialog);
    }
    private async Task<string?> ShareLinkFolder()
    {
        if (backgroundTest) throw new OperationException("后台测试不打开系统文件夹选择器。");
        var picker = new global::Windows.Storage.Pickers.FolderPicker(); picker.FileTypeFilter.Add("*"); WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this)); return (await picker.PickSingleFolderAsync())?.Path;
    }
}
