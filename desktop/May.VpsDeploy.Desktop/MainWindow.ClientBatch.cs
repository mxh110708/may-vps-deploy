using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task BatchClientNodes()
    {
        var selected = scheme!; var fingerprint = ArchiveStore.Fingerprint(selected); var chosen = new HashSet<string>(StringComparer.Ordinal);
        var nodes = selected["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        var options = new JsonObject { ["Action"] = "MoveStart", ["Region"] = selected["Layout"]!.Strings("region_groups")[0] };
        var search = new TextBox { Header = "筛选名称或协议", MaxLength = 120, Tag = "ClientBatch.Filter" };
        var action = Choice("批量操作", options, "Action", [("MoveStart", "移到开头"), ("MoveEnd", "移到末尾"), ("Sort", "所选位置内按名称排序"), ("Region", "调整入口地区"), ("Transit", "调整落地上游"), ("Remove", "从方案移除"), ("DetachSubscription", "订阅成员转为手动"), ("DetachGroup", "解除整组关联")]); action.Tag = "ClientBatch.Action";
        var region = Choice("目标地区／入口组", options, "Region", selected["Layout"]!.Strings("region_groups").Select(g => (g, g))); region.Tag = "ClientBatch.Region";
        var rows = new StackPanel { Spacing = 8 }; var count = Text("", 14); count.Tag = "ClientBatch.Count";
        JsonObject[] Visible() => nodes.Where(n => n.Text("name").Contains(search.Text.Trim(), StringComparison.OrdinalIgnoreCase) || n.Text("sing_box.type", n.Text("clash.type")).Contains(search.Text.Trim(), StringComparison.OrdinalIgnoreCase)).ToArray();
        ContentDialog? dialog = null;
        void Count() { count.Text = "已选 " + chosen.Count + " / " + nodes.Length + "；其中筛选外已选 " + chosen.Count(id => !Visible().Any(n => n.Text("Id") == id)) + "。筛选不会清空选择。"; if (dialog != null) dialog.IsPrimaryButtonEnabled = chosen.Count != 0; }
        void Render()
        {
            rows.Children.Clear();
            foreach (var node in Visible())
            {
                var id = node.Text("Id"); var check = new CheckBox { Content = node.Text("name") + " · " + (node.Text("kind") == "landing" ? "落地" : "入口") + " · " + node.Text(node.Text("kind") == "landing" ? "transit_group" : "region_group"), IsChecked = chosen.Contains(id), Tag = "ClientBatch.Node." + id };
                check.Checked += (_, _) => { chosen.Add(id); Count(); }; check.Unchecked += (_, _) => { chosen.Remove(id); Count(); }; rows.Children.Add(check);
            }
            Count();
        }
        search.TextChanged += (_, _) => Render(); action.SelectionChanged += (_, _) => region.Visibility = options.Text("Action") is "Region" or "Transit" ? Visibility.Visible : Visibility.Collapsed;
        var all = Action("选中筛选结果", () => { foreach (var node in Visible()) chosen.Add(node.Text("Id")); Render(); return Task.CompletedTask; }); all.Tag = "ClientBatch.All";
        var none = Action("清空全部选择", () => { chosen.Clear(); Render(); return Task.CompletedTask; }); none.Tag = "ClientBatch.None";
        region.Visibility = Visibility.Collapsed;
        dialog = OperationDialog("批量管理节点", DialogScroll(Column(Text("先选择节点和操作，再审阅影响。应用只修改当前方案草稿，保存与完整配置导出仍需分别执行。", 14, true), search, Row(all, none), count, rows, action, region)), "预览影响"); dialog.Tag = "ClientBatch.Select"; Render();
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        if (ArchiveStore.Fingerprint(selected) != fingerprint) throw new OperationException("方案已变化，请重新选择节点。");
        var preview = ClientNodeBatch.Preview(selected, options.Text("Action"), nodes.Where(n => chosen.Contains(n.Text("Id"))).Select(n => n.Text("Id")).ToArray(), options.Text("Action") is "Region" or "Transit" ? options.Text("Region") : "");
        var content = Column(Text("本次选中 " + chosen.Count + " 个节点；只应用下列变化。未选择的成员不自动解除来源关联。", 14, true));
        foreach (var change in preview.Changes) content.Children.Add(Text(change.Name + "\n" + change.Before + " → " + change.After, 14));
        foreach (var error in preview.Errors) content.Children.Add(Text("阻止应用：" + error, 14));
        if (preview.Changes.Count == 0) content.Children.Add(Text("没有需要应用的变化。", 14));
        var review = OperationDialog("审阅批量影响", DialogScroll(content), "应用到草稿"); review.Tag = "ClientBatch.Review"; review.IsPrimaryButtonEnabled = preview.Ready;
        if (await ShowDialog(review) != ContentDialogResult.Primary) return;
        ClientSourceBarrier.RequireAvailable(store, "Scheme", selected.Text("Id")); ClientNodeBatch.Apply(selected, preview); DirtyScheme();
    }

    private async Task ExportClientFragments(JsonObject selected, Func<string, Task>? copy = null, Func<Task<string?>>? folder = null)
    {
        var fingerprint = ArchiveStore.Fingerprint(selected); var effective = ClientOutputRules.RequireReady(selected); var chosen = new List<string>();
        var options = new JsonObject { ["Format"] = ClientSchemes.Formats(selected).First() };
        var format = Choice("原生节点格式", options, "Format", ClientSchemes.Formats(selected).Select(f => (f, f == "Clash" ? "Mihomo / Clash YAML" : "May Route / sing-box JSON"))); format.Tag = "ClientFragment.Format";
        var rows = new StackPanel { Spacing = 8 }; ContentDialog? dialog = null;
        foreach (var node in effective["Nodes"]!.AsArray().OfType<JsonObject>())
        {
            var id = node.Text("Id"); var check = new CheckBox { Content = node.Text("name"), Tag = "ClientFragment.Node." + id };
            check.Checked += (_, _) => { chosen.Add(id); if (dialog != null) dialog.IsPrimaryButtonEnabled = chosen.Count != 0; };
            check.Unchecked += (_, _) => { chosen.Remove(id); if (dialog != null) dialog.IsPrimaryButtonEnabled = chosen.Count != 0; }; rows.Children.Add(check);
        }
        dialog = OperationDialog("导出原生节点片段", DialogScroll(Column(Text("使用输出筛选与命名后的节点，保留原生连接字段。片段需合并到相应客户端配置；不包含完整 DNS、分流、监听和外部规则资源。", 14, true), format, rows)), "预览节点与依赖"); dialog.Tag = "ClientFragment.Select"; dialog.IsPrimaryButtonEnabled = false;
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        if (ArchiveStore.Fingerprint(selected) != fingerprint) throw new OperationException("方案已变化，请重新预览片段。");
        var preview = ClientNodeFragments.Preview(selected, options.Text("Format"), chosen);
        var content = Column(Text("所选 " + chosen.Count + " 个；片段共 " + preview.Rows.Count + " 个节点，另含 " + preview.Groups.Count + " 个入口组。依赖节点也包含连接与鉴权信息。", 14, true));
        foreach (var row in preview.Rows) content.Children.Add(Text((row.Dependency ? "依赖 · " : "所选 · ") + row.Name, 14));
        foreach (var group in preview.Groups) content.Children.Add(Text("入口组 · " + group, 14));
        foreach (var error in preview.Errors) content.Children.Add(Text("阻止导出：" + error, 14));
        var file = new TextBox { Header = "新文件名", Text = "may-nodes.private." + (preview.Format == "Clash" ? "yaml" : "json"), MaxLength = 120, Tag = "ClientFragment.FileName" };
        var status = Text("", 14, true); status.Tag = "ClientFragment.Status"; var busy = false;
        var copyButton = Action("复制已审阅片段", async () =>
        {
            if (busy) return; busy = true;
            try
            {
                var text = await workbench.GenerateFragmentAsync(selected, preview, CancellationToken.None);
                if (copy != null) await copy(text);
                else { if (backgroundTest) throw new OperationException("后台测试使用隔离复制接收器。"); var data = new global::Windows.ApplicationModel.DataTransfer.DataPackage(); data.SetText(text); global::Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data); }
                status.Text = "已复制已审阅的原生节点片段。";
            }
            catch (Exception error) { status.Text = SafeFailures.Describe(error).Message; }
            finally { busy = false; }
        }); copyButton.Tag = "ClientFragment.Copy"; copyButton.IsEnabled = preview.Ready;
        var save = Action("保存已审阅片段", async () =>
        {
            if (busy) return; busy = true;
            try
            {
                var name = file.Text.Trim();
                if (name.Length == 0 || name != Path.GetFileName(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) throw new OperationException("文件名不能包含路径或无效字符。");
                var directory = folder != null ? await folder() : await ShareLinkFolder(); if (directory == null) return;
                await workbench.SaveFragmentAsync(selected, preview, Path.Combine(directory, name), CancellationToken.None); status.Text = "已保存已审阅的节点与依赖。";
            }
            catch (Exception error) { status.Text = SafeFailures.Describe(error).Message; }
            finally { busy = false; }
        }); save.Tag = "ClientFragment.Save"; save.IsEnabled = preview.Ready;
        content.Children.Add(file); content.Children.Add(Row(copyButton, save)); content.Children.Add(status);
        var review = OperationDialog("审阅原生节点片段", DialogScroll(content), ""); review.Tag = "ClientFragment.Review"; review.PrimaryButtonText = ""; await ShowDialog(review);
    }

    private static string ClientPublishReviewText(ClientPublishReview review) => string.Join("\n\n", review.Targets.Select(t => (t.Format == "Clash" ? "Mihomo / Clash" : "May Route / sing-box") + "\n" + t.Path + "\n" + t.Summary)) + "\n\n只显示变化范围，鉴权信息不进入差异摘要。确认后写入所列文件；导出后请自行导入客户端。";
}
