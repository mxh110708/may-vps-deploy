using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task AddClientSubscription()
    {
        var source = ClientSubscriptions.New(scheme!["Layout"]!.Strings("region_groups").First());
        var address = SecretField("订阅 URL（保存在加密方案中）"); var proxy = Field("代理地址（HTTP / HTTPS / SOCKS5，无认证）", source, "Proxy");
        var mode = Choice("下载方式", source, "Network", [("System", "跟随系统代理"), ("Direct", "直连"), ("Proxy", "指定代理")]);
        proxy.Visibility = Visibility.Collapsed; mode.SelectionChanged += (_, _) => proxy.Visibility = source.Text("Network") == "Proxy" ? Visibility.Visible : Visibility.Collapsed;
        var dialog = OperationDialog("添加订阅来源", new ScrollViewer { MaxHeight = 480, Content = Column(Field("来源名称", source, "Name"), address, mode, proxy,
            Choice("入口归属 / 落地连接的入口组", source, "Region", scheme["Layout"]!.Strings("region_groups").Select(r => (r, r))),
            Choice("默认节点用途", source, "Role", [("Auto", "SS 作为落地，其余作为入口"), ("entry", "全部作为入口"), ("landing", "全部作为落地")]),
            Text("支持纯文本及 Base64 分享链接列表。只在点击获取或刷新时联网，先预览新增、变化和删除；失败或取消保留原节点。", 14, true)) }, "获取并预览");
        try { if (await ShowDialog(dialog) != ContentDialogResult.Primary) return; source["Url"] = address.Password.Trim(); }
        finally { address.Password = ""; }
        await FetchClientSubscription(source);
    }
    private async Task FetchClientSubscription(JsonObject source)
    {
        if (testSession != null) throw new OperationException("后台界面验证不获取公网来源；请使用本机订阅回归。");
        var selected = scheme!.DeepClone().AsObject(); var definition = source.DeepClone().AsObject(); ClientSourcePreview? preview = null;
        await RunBackground("获取并分析订阅来源", async token =>
        {
            var content = await new ClientSubscriptionDownload().FetchAsync(definition, token);
            preview = await Task.Run(() => ClientSubscriptions.Preview(selected, definition, content), token); token.ThrowIfCancellationRequested();
        });
        await ReviewClientSubscription(preview!);
    }
    private async Task ReviewClientSubscription(ClientSourcePreview preview)
    {
        var rows = Column(Text(ClientSubscriptions.Label(preview.Source), 16), Text("确认后更新当前方案；源链接及凭据只保存在加密私人归档中。移除默认出口后须重新指定，不会自动回退到直连。", 14, true));
        foreach (var error in preview.Errors) rows.Children.Add(Text("未更新：" + error, 14));
        string Label(string kind) => kind switch { "Added" => "新增", "Removed" => "删除", "Changed" => "参数变化", "Renamed" => "改名", "Conflict" => "冲突", "Existing" => "已有其他来源连接", "Impact" => "引用影响", _ => "保留" };
        foreach (var change in preview.Changes) rows.Children.Add(Text(Label(change.Kind) + " · " + change.Name + "\n" + change.Detail, 14, change.Kind is "Unchanged" or "Existing"));
        var dialog = OperationDialog("订阅来源差异", new ScrollViewer { Content = rows, MaxHeight = 480 }, "确认更新方案"); dialog.IsPrimaryButtonEnabled = preview.Ready;
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        ClientSubscriptions.Apply(scheme!, preview); Navigate("clients"); Show("来源已更新到方案；请保存方案，并重新生成已失效的候选配置。", InfoBarSeverity.Success);
    }
    private void DesignerClientSources()
    {
        if (scheme!["NodeSources"] is not JsonArray sources || sources.Count == 0) return;
        var rows = sources.OfType<JsonObject>().Select(source => (UIElement)SettingRow(ClientSubscriptions.Label(source), "仅手动刷新 · 上次获取 " + LocalTime(source.Text("LastFetchedAt")), Symbol.Sync,
            Row(Action("刷新并预览", () => FetchClientSubscription(source)), Action("停止管理来源", async () =>
            {
                if (!await ConfirmAsync(new("停止管理订阅来源", "保留此来源的所有节点并转为手动节点，移除本方案中的来源地址；不修改远端。"), CancellationToken.None)) return;
                foreach (var node in scheme["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => n.Text("Source.Id") == source.Text("Id"))) ClientSubscriptions.Detach(node);
                sources.Remove(source); DirtyScheme();
            })))).ToArray();
        page.Children.Add(Details("订阅来源（手动刷新）", SettingsGroup(rows)));
    }
    private Task DetachClientSourceNode(JsonObject node)
    { ClientSubscriptions.Detach(node); DirtyScheme(); return Task.CompletedTask; }
}
