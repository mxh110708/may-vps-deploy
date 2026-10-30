#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private void DesignerNodeGroups()
    {
        var save = Action("保存节点组", SaveClientNodeGroup); save.Tag = "ClientGroups.Save";
        var reuse = Action("复用节点组", ReuseClientNodeGroup); reuse.Tag = "ClientGroups.Reuse";
        page.Children.Add(Card(Column(Text("可复用节点组", 17), Text("节点和入口依赖一起保存，供多个方案使用；各方案手动同步更新。", 14, true), Row(save, reuse))));
        if (scheme!["GroupReferences"] is not JsonArray refs || refs.Count == 0) return;
        page.Children.Add(SettingsGroup(refs.OfType<JsonObject>().Select(reference => (UIElement)SettingRow(reference.Text("Name"), "已关联 · 导出前核对组版本与节点来源", Symbol.Library,
            Row(Action("同步预览", () => ReviewClientNodeGroup(reference.Text("Id"))), Action("解除关联", async () =>
            {
                if (!await ConfirmAsync(new("解除节点组关联", "保留当前节点和原始来源，之后独立编辑；不修改节点组或其他方案。"), CancellationToken.None)) return;
                ClientNodeGroups.Detach(scheme!, reference.Text("Id")); DirtyScheme();
            })))).ToArray()));
    }
    private async Task SaveClientNodeGroup()
    {
        var selected = scheme!; var library = new ClientNodeGroupStore(store); var existing = library.List();
        var model = new JsonObject { ["Name"] = selected.Text("Name") + " 节点组", ["Group"] = "new" }; var ids = new HashSet<string>(StringComparer.Ordinal);
        var target = Choice("保存到", model, "Group", new[] { ("new", "新建节点组") }.Concat(existing.Select(g => (g.Text("Id"), "更新 · " + g.Text("Name"))))); target.Tag = "ClientGroups.Target";
        var name = Field("节点组名称", model, "Name"); name.Tag = "ClientGroups.Name";
        var rows = Column(name, target, Text("勾选成员，落地所需的入口也须勾选。更新只保存本次快照，其他方案须同步预览后再导出。", 14, true));
        foreach (var node in selected["Nodes"]!.AsArray().OfType<JsonObject>())
        {
            var id = node.Text("Id"); ids.Add(id); var check = new CheckBox { Content = node.Text("name"), IsChecked = true, Tag = "ClientGroups.Member." + id };
            check.Checked += (_, _) => ids.Add(id); check.Unchecked += (_, _) => ids.Remove(id); rows.Children.Add(check);
        }
        var fingerprint = ArchiveStore.Fingerprint(selected); var dialog = OperationDialog("保存节点组", DialogScroll(rows), "保存节点组");
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        if (fingerprint != ArchiveStore.Fingerprint(selected)) throw new OperationException("方案已变化，请重新选择成员。");
        var old = existing.SingleOrDefault(g => g.Text("Id") == model.Text("Group"));
        var group = ClientNodeGroups.Capture(selected, model.Text("Name"), ids.ToArray(), old?.Text("Id"), old); library.Save(group, old == null ? null : ClientNodeGroups.Revision(old));
        Navigate("clients"); Show("节点组已保存。需要此组的方案可通过复用或同步预览加入最新快照。", InfoBarSeverity.Success);
    }
    private async Task ReuseClientNodeGroup()
    {
        var library = new ClientNodeGroupStore(store); var groups = library.List();
        if (groups.Count == 0) throw new OperationException("尚无可复用节点组，请先在含有节点的方案中保存节点组。");
        var model = new JsonObject { ["Id"] = groups[0].Text("Id") };
        var choice = Choice("节点组", model, "Id", groups.Select(g => (g.Text("Id"), g.Text("Name") + " · " + g["Nodes"]!.AsArray().Count + " 个节点"))); choice.Tag = "ClientGroups.Choice";
        var dialog = OperationDialog("选择节点组", Column(choice, Text("分组、鉴权、传输参数及来源原样保留；不会联网刷新订阅。", 14, true)), "预览复用"); dialog.SecondaryButtonText = "删除节点组";
        var result = await ShowDialog(dialog);
        if (result == ContentDialogResult.Primary) await ReviewClientNodeGroup(model.Text("Id"));
        else if (result == ContentDialogResult.Secondary)
        {
            if (!await ConfirmAsync(new("删除节点组", "删除本地加密节点组；仍有已保存方案引用时会阻止删除。"), CancellationToken.None)) return;
            library.Delete(model.Text("Id"), scheme); Navigate("clients");
        }
    }
    private async Task ReviewClientNodeGroup(string id)
    {
        var selected = scheme!; var library = new ClientNodeGroupStore(store); var preview = library.Preview(selected, id);
        var rows = Column(Text("仅修改当前方案；完成后保存方案，并重新生成、校验和导出配置。", 14, true));
        foreach (var change in preview.Changes) rows.Children.Add(Text((change.Kind switch { "Added" => "新增", "Removed" => "移除", "Changed" => "更新", _ => "保留" }) + " · " + change.Name + "\n" + change.Detail, 14));
        foreach (var error in preview.Errors) rows.Children.Add(Text(error, 14));
        var dialog = OperationDialog("节点组差异", DialogScroll(rows), "应用到当前方案"); dialog.IsPrimaryButtonEnabled = preview.Ready;
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        library.Apply(selected, id, preview); DirtyScheme(); Show("节点组已应用；其他方案保留原快照，须分别确认同步。", InfoBarSeverity.Success);
    }
}
