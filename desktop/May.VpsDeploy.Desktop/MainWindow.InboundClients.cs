using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task AddInboundClientNodes()
    {
        var selected = scheme ?? throw new OperationException("请先打开配置方案。"); var choices = InboundSources.Choices(store).ToArray();
        var regions = selected["Layout"]!.Strings("region_groups"); var model = new JsonObject { ["Region"] = regions.First() };
        var panel = Column(Choice("入口地区组", model, "Region", regions.Select(r => (r,r))), Text("选择已启用并通过实际用户验收的独立入站。节点保留原鉴权、TLS 与出站身份；这里仅更新当前配置方案。", 14, true));
        var boxes = new List<(CheckBox Box, JsonObject Node)>();
        foreach (var choice in choices)
        {
            var box = new CheckBox { Content = Column(Text(choice.Label,16),Text(choice.Detail,14,true)), IsEnabled = choice.Node != null, HorizontalAlignment = HorizontalAlignment.Stretch, Tag = "ClientInbounds.Choice" };
            panel.Children.Add(box); if (choice.Node != null) boxes.Add((box,choice.Node));
        }
        var error = Text("",14,true); error.Tag = "ClientInbounds.Error"; panel.Children.Add(error);
        var dialog = OperationDialog("添加独立入站节点",DialogScroll(panel),"添加 / 更新"); dialog.IsPrimaryButtonEnabled = false;
        foreach (var pair in boxes) { pair.Box.Checked += (_,_) => dialog.IsPrimaryButtonEnabled=boxes.Any(p=>p.Box.IsChecked==true); pair.Box.Unchecked += (_,_) => dialog.IsPrimaryButtonEnabled=boxes.Any(p=>p.Box.IsChecked==true); }
        dialog.PrimaryButtonClick += (_,args) => { try { ForwardedNodeSources.Apply(store,selected,boxes.Where(p=>p.Box.IsChecked==true).Select(p=>p.Node).ToArray(),model.Text("Region")); } catch(OperationException exception) { error.Text=exception.Message;args.Cancel=true; } };
        try { if(await ShowDialog(dialog)==ContentDialogResult.Primary) DirtyScheme(); }
        finally { foreach(var choice in choices) choice.Node?.Clear(); }
    }
}
