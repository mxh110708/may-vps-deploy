using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task AddForwardedClientNodes()
    {
        var selected = scheme ?? throw new OperationException("请先打开配置方案。");
        var regions = selected["Layout"]!.Strings("region_groups");
        var model = new JsonObject { ["Region"] = regions.First() };
        var choices = ForwardedNodeSources.Choices(store, model.Text("Region"));
        var panel = Column(Choice("归属入口地区组", model, "Region", regions.Select(r => (r, r))), Text("选择已经应用并通过代理验收的单机转发或跨实例线路。添加或更新只修改当前方案。", 14, true));
        var selection = new List<(CheckBox Box, JsonObject Node)>();
        foreach (var choice in choices)
        {
            var content = Column(Text(choice.Label, 16), Text(choice.Detail, 14, true));
            if (choice.Node != null) content.Children.Add(Text(choice.Node.Text("clash.server") + ":" + choice.Node.Number("clash.port"), 14, true));
            var box = new CheckBox { Content = content, IsEnabled = choice.Node != null, HorizontalAlignment = HorizontalAlignment.Stretch, Tag = "ClientForwarded.Choice." + choice.RuleId + "." + choice.Family };
            panel.Children.Add(box); if (choice.Node != null) selection.Add((box, choice.Node));
        }
        if (choices.Count == 0) panel.Children.Add(Text("还没有使用已保存代理节点验收的 TCP 转发。先在实例的“管理转发”中配置并完成验收，再返回此处添加。", 14, true));
        var error = Text("", 14); error.Tag = "ClientForwarded.Error"; panel.Children.Add(error);
        var dialog = OperationDialog("添加转发节点", panel, "添加 / 更新"); dialog.IsPrimaryButtonEnabled = false;
        foreach (var pair in selection)
        {
            pair.Box.Checked += (_, _) => dialog.IsPrimaryButtonEnabled = selection.Any(p => p.Box.IsChecked == true);
            pair.Box.Unchecked += (_, _) => dialog.IsPrimaryButtonEnabled = selection.Any(p => p.Box.IsChecked == true);
        }
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                var chosen = selection.Where(p => p.Box.IsChecked == true).Select(p => p.Node).ToArray();
                if (chosen.Length == 0) throw new OperationException("请至少选择一个有效转发节点。");
                ForwardedNodeSources.Apply(store, selected, chosen, model.Text("Region"));
            }
            catch (Exception exception) when (exception is OperationException or IOException or UnauthorizedAccessException)
            { args.Cancel = true; error.Text = exception is OperationException ? exception.Message : "来源无法安全读取，请核对转发和目标节点后重试。"; }
        };
        try { if (await ShowDialog(dialog) == ContentDialogResult.Primary) DirtyScheme(); }
        finally { foreach (var choice in choices) choice.Node?.Clear(); }
    }

    private async Task EditForwardedClientNode(JsonObject node)
    {
        var selected = scheme ?? throw new OperationException("请先打开配置方案。");
        var model = new JsonObject { ["Name"] = node.Text("name"), ["Kind"] = node.Text("kind"), ["Region"] = node.Text("region_group"), ["Transit"] = node.Text("transit_group") };
        var regions = selected["Layout"]!.Strings("region_groups");
        var panel = Column(Field("节点名称", model, "Name"), Choice("节点用途", model, "Kind", [("entry", "入口"), ("landing", "经入口连接的落地")]),
            Choice("入口地区组", model, "Region", regions.Select(r => (r, r)), preserveMissing: true), Choice("落地连接的入口组", model, "Transit", regions.Select(r => (r, r)), preserveMissing: true),
            Text(node["InboundOrigin"] != null ? "连接参数来自已验收的独立入站。修改入站后，使用“添加独立入站节点”重新选择，更新连接并保留名称和分组。" : VlessXhttp.IsNode(node) ? "保留完整 XHTTP 原生连接，只修改名称和分组。连接变化时从完整来源文件重新读取，不使用 Reality／Vision 表单转换。" : "连接参数来自已保存的转发和目标节点。修改转发后，使用“添加转发节点”重新选择，即可更新本节点并保留名称和分组。", 14, true));
        var error = Text("", 14); error.Tag = "ClientForwarded.EditError"; panel.Children.Add(error);
        var dialog = OperationDialog(node["InboundOrigin"] != null ? "编辑独立入站节点" : VlessXhttp.IsNode(node) ? "编辑 XHTTP 节点" : "编辑转发节点", panel, "保存");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                var name = model.Text("Name").Trim();
                if (name.Length is < 1 or > 120 || name.Any(char.IsControl) || selected["Nodes"]!.AsArray().OfType<JsonObject>().Any(n => n != node && n.Text("name") == name)) throw new OperationException("名称须为 1–120 个可打印字符，且不能与其他节点重复。");
                if (!regions.Contains(model.Text("Region")) || !regions.Contains(model.Text("Transit"))) throw new OperationException("请选择有效的地区组。");
                if (VlessXhttp.IsNode(node) && model.Text("Kind") != "entry") throw new OperationException("本轮 XHTTP 仅支持入口用途，不叠加客户端落地链路。");
                ClientSchemes.RenameNodeReferences(selected, node.Text("name"), name);
                node["name"] = name; if (node["clash"] is JsonObject clash) clash["name"] = name; if (node["sing_box"] is JsonObject sing) sing["tag"] = name;
                node["kind"] = model.Text("Kind"); node["region_group"] = model.Text("Region"); node["transit_group"] = model.Text("Transit");
            }
            catch (OperationException exception) { args.Cancel = true; error.Text = exception.Message; }
        };
        if (await ShowDialog(dialog) == ContentDialogResult.Primary) DirtyScheme();
    }
}
