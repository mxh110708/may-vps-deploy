using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private readonly JsonObject resourceFilter = new() { ["Instance"] = "", ["Kind"] = "", ["Query"] = "", ["Attention"] = false };
    private int resourcePage;

    private void ResourcesPage()
    {
        var overview = OperationsResources.Load(store, DateTimeOffset.UtcNow);
        var instances = store.ListInstances().ToArray();
        page.Children.Add(Card(Column(Text(overview.Items.Count(i => i.Kind == "Certificate") + " 张证书 · " + overview.Items.Count(OperationsResources.NeedsAttention) + " 项需留意 · " + overview.Items.Count + " 项资源", 17),
            Text("按归档查看关联资源；远端核验需手动运行，24 小时后需重新核对。", 13, true))));
        if (overview.Issues.Count > 0) page.Children.Add(Card(Column(Text("归档读取提示", 18), Text(string.Join("\n", overview.Issues), 13, true))));
        var selected = Choice("实例与关联资源", resourceFilter, "Instance", new[] { ("", "全部实例") }.Concat(instances.Select(i => (i.RelativePath, i.Plan.Text("Provider") + " / " + i.Plan.Text("Instance")))), true); selected.Tag = "Resources.Instance";
        var category = Choice("资源类别", resourceFilter, "Kind", new[] { ("", "全部资源") }.Concat(overview.Items.Select(i => i.Kind).Distinct().Order(StringComparer.Ordinal).Select(k => (k, OperationsResources.KindLabel(k)))), true); category.Tag = "Resources.Kind";
        var query = Field("搜索名称、实例或资源说明", resourceFilter, "Query"); query.Tag = "Resources.Query";
        var attention = Flag("只显示需留意的资源", resourceFilter, "Attention"); attention.Tag = "Resources.Attention";
        var rows = new StackPanel { Spacing = 12 }; var count = Text("", 13, true); count.Tag = "Resources.Count";
        var paging = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
        var check = Action("核对所选实例（只读健康检查）", async () =>
        {
            var relative = resourceFilter.Text("Instance"); var instance = instances.SingleOrDefault(i => i.RelativePath == relative);
            if (instance.Plan == null) throw new OperationException("请先选择一个实例，逐实例审阅核验范围。");
            var status = InstanceLifecycle.Read(store, relative, instance.Plan);
            if (!status.Managed || status.NeedsRecovery) throw new OperationException("先从实例页核对草稿或待恢复事务。");
            await Submit(new(OperationKind.HealthAudit, relative, new()));
        }); check.Tag = "Resources.Check";
        void Refresh()
        {
            rows.Children.Clear(); paging.Children.Clear();
            var text = resourceFilter.Text("Query"); var relative = resourceFilter.Text("Instance");
            var related = relative == "" ? null : overview.RelatedKeys(relative);
            var chosen = overview.Items.Where(i => (related == null || related.Contains(i.Key)) && (resourceFilter.Text("Kind") == "" || i.Kind == resourceFilter.Text("Kind")) && (!resourceFilter.Flag("Attention") || OperationsResources.NeedsAttention(i)) && (text == "" || (i.Name + " " + i.Instance + " " + i.Detail).Contains(text, StringComparison.OrdinalIgnoreCase))).ToArray();
            const int size = 30; resourcePage = Math.Clamp(resourcePage, 0, Math.Max(0, (chosen.Length - 1) / size));
            count.Text = "匹配 " + chosen.Length + " 项 · 第 " + (resourcePage + 1) + " / " + Math.Max(1, (chosen.Length + size - 1) / size) + " 页";
            foreach (var item in chosen.Skip(resourcePage * size).Take(size))
            {
                var details = Action("详情与变更影响", () => ResourceDetails(overview, item)); details.Tag = "Resources.Details." + item.Key;
                rows.Children.Add(Card(Column(Trailing(Text(item.Name, 17), Text(OperationsResources.StatusLabel(item.Status), 13)),
                    Text(OperationsResources.KindLabel(item.Kind) + (item.Instance == "" ? "" : " · " + item.Instance), 13, true),
                    Text(OperationsResources.EvidenceLabel(item.Evidence) + (item.ObservedAt == null ? "" : " · " + item.ObservedAt.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm")), 12, true),
                    Text(item.NotAfter == null ? item.Detail : "到期 " + item.NotAfter.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm zzz"), 13), details)));
            }
            if (chosen.Length == 0) rows.Children.Add(Card(Text("没有匹配资源。可调整筛选，或先接入已有实例。", 14, true)));
            var before = Action("上一页", () => { resourcePage--; Refresh(); return Task.CompletedTask; }); before.IsEnabled = resourcePage > 0;
            var after = Action("下一页", () => { resourcePage++; Refresh(); return Task.CompletedTask; }); after.IsEnabled = (resourcePage + 1) * size < chosen.Length;
            paging.Children.Add(before); paging.Children.Add(after);
            check.IsEnabled = relative != "" && instances.Any(i => i.RelativePath == relative && InstanceLifecycle.Read(store, relative, i.Plan) is { Managed: true, NeedsRecovery: false });
        }
        void Filter() { resourcePage = 0; Refresh(); }
        selected.SelectionChanged += (_, _) => Filter(); category.SelectionChanged += (_, _) => Filter(); query.TextChanged += (_, _) => Filter(); attention.Checked += (_, _) => Filter(); attention.Unchecked += (_, _) => Filter();
        var reload = Action("刷新本地归档", () => { SelectPage("resources"); return Task.CompletedTask; }); reload.Tag = "Resources.Reload";
        reload.HorizontalAlignment = HorizontalAlignment.Stretch; check.HorizontalAlignment = HorizontalAlignment.Stretch;
        attention.VerticalAlignment = VerticalAlignment.Bottom;
        page.Children.Add(Fields(reload, check));
        page.Children.Add(Fields(selected, category)); page.Children.Add(Fields(query, attention)); page.Children.Add(count); page.Children.Add(rows); page.Children.Add(paging); Refresh();
    }
    private ContentDialog ResourceDetailsDialog(OperationsResourceOverview overview, OperationsResource item)
    {
        var direct = overview.Consumers(item.Key, false); var all = overview.Consumers(item.Key);
        var content = Column(Text(OperationsResources.KindLabel(item.Kind) + " · " + OperationsResources.StatusLabel(item.Status), 16), Text(item.Detail, 13, true),
            Text(OperationsResources.EvidenceLabel(item.Evidence) + (item.ObservedAt == null ? "" : "\n采集时间 " + item.ObservedAt.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz")), 13, true),
            Text("直接使用者 " + direct.Count + " 项 · 全部受影响 " + all.Count + " 项", 17),
            Text("更换证书／用户／去向后，关联节点、复用组和线路需要重新核对来源及验收，再校验导出。这里列出归档依赖，不执行级联修改或删除。", 13, true));
        foreach (var consumer in all) content.Children.Add(Text((direct.Any(i => i.Key == consumer.Key) ? "直接 · " : "间接 · ") + OperationsResources.KindLabel(consumer.Kind) + " · " + consumer.Name + (consumer.Instance == "" ? "" : "\n" + consumer.Instance) + (consumer.Status == "Disabled" ? " · 已停用，仍保留引用" : ""), 13));
        if (all.Count == 0) content.Children.Add(Text("没有读到使用者。若存在归档读取提示，请先处理，不能据此认定可以安全删除。", 13, true));
        return OperationDialog(item.Name, DialogScroll(content), "打开维护入口");
    }
    private async Task ResourceDetails(OperationsResourceOverview overview, OperationsResource item)
    {
        if (await ShowDialog(ResourceDetailsDialog(overview, item)) != ContentDialogResult.Primary) return;
        // Re-read all identities after the detail dialog. Never dispatch a saved
        // mutation request from a potentially stale overview snapshot.
        var current = OperationsResources.Load(store, DateTimeOffset.UtcNow).Items.SingleOrDefault(i => i.Key == item.Key);
        if (current == null || current.Maintenance != item.Maintenance || current.Target != item.Target) throw new OperationException("该资源或维护范围已变化，请刷新总览。");
        if (item.Maintenance == "Clients") { await OpenResourceClient(current); return; }
        var instance = store.ListInstances().SingleOrDefault(i => i.RelativePath == item.Instance);
        if (instance.Plan == null) throw new OperationException("资源所属实例已移除，请刷新总览。");
        selectedInstance = instance.RelativePath;
        var status = InstanceLifecycle.Read(store, selectedInstance, instance.Plan);
        if (item.Maintenance == "WireGuard" && WireGuardTunnels.List(store).Any(r => r.Text("Configuration.Id") == item.Target && WireGuardTunnels.Pending(r))) { await WireGuardSheet(selectedInstance, instance.Plan, item.Target); return; }
        if (item.Maintenance == "Chain" && TcpChains.List(store).Any(r => r.Text("Configuration.Id") == item.Target && TcpChains.Pending(r))) { await TcpChainSheet(selectedInstance, instance.Plan, item.Target); return; }
        if (item.Maintenance == "Instance" || !status.Managed || status.NeedsRecovery) { SelectPage("instances"); return; }
        var plan = instance.Plan;
        switch (item.Maintenance)
        {
            case "Certificates": case "Users": case "Outbounds": case "Inbounds": await InboundsSheet(selectedInstance, plan, item.Maintenance, item.Target); break;
            case "InboundCore": await InboundsSheet(selectedInstance, plan, initialAction: item.Target); break;
            case "Protocol": await OperationSheet(OperationKind.ProtocolState, plan, item.Target); break;
            case "Upgrade": await UpgradeCore(plan, item.Target); break;
            case "ServerRoute": await ServerOutboundSheet(selectedInstance, plan, item.Target); break;
            case "TcpForward": await TcpForwardSheet(selectedInstance, plan); break;
            case "UdpForward": await UdpForwardSheet(selectedInstance, plan); break;
            case "WireGuard": await WireGuardSheet(selectedInstance, plan, item.Target); break;
            case "Chain": await TcpChainSheet(selectedInstance, plan, item.Target); break;
            case "MayMonitor": await ManageMayMonitorDialog(selectedInstance, item.Target); break;
            case "Monitoring": await ManageMonitoring(plan, item.Target); break;
            case "CertificateFixed": await FixedCertificateMaintenance(item, plan); break;
            default: SelectPage("instances"); break;
        }
    }
    private async Task OpenResourceClient(OperationsResource item)
    {
        var target = item.Target;
        if (item.Kind == "ClientGroup")
        {
            var overview = OperationsResources.Load(store, DateTimeOffset.UtcNow);
            var schemes = overview.Consumers(item.Key).Where(i => i.Kind == "ClientNode").DistinctBy(i => i.Target).ToArray();
            if (schemes.Length == 0) { Show("这个节点组成员还没有已保存的引用方案；在配置设计中选择方案后可显式复用节点组。"); return; }
            var model = new JsonObject(); var choice = Choice("选择引用此成员的方案", model, "Id", schemes.Select(i => (i.Target, i.Name)));
            if (await ShowDialog(OperationDialog("节点组使用者", Column(Text("选择要查看的方案；不会自动同步其他方案。", 14, true), choice), "打开方案")) != ContentDialogResult.Primary) return;
            target = model.Text("Id");
        }
        _ = InboundCatalog.Id(target);
        if (scheme?.Text("Id") == target) { SelectPage("clients"); return; }
        if (scheme != null && !await ExitScheme(false)) return;
        var saved = store.ReadSecret(paths.Resolve("private/client-schemes/" + target + ".dotnet.private.json"));
        if (saved.Text("Id") != target) { saved.Clear(); throw new OperationException("方案身份已变化，请刷新总览。"); }
        SelectPage("clients"); OpenScheme(saved);
    }
    private async Task FixedCertificateMaintenance(OperationsResource item, JsonObject plan)
    {
        var known = InstanceState(item.Instance)["ResourceObservation"];
        var panel = Column(Text(item.Name, 18), Text(item.Detail, 13, true),
            Text("此固定角色由 VPS 上现有 certbot 续期流程维护，与独立入站的手动导入证书分开。续期计时器状态不能证明下次签发或协议重载会成功。", 14, true),
            Text("归档续期计时器：" + (known.Flag("Timers.CertbotRenewEnabled") ? "启用" : "未确认启用") + " / " + (known.Flag("Timers.CertbotRenewActive") ? "运行" : "未确认运行"), 13),
            Text("若临近到期，请按证书维护文档核对 DNS 授权、续期日志、部署钩子和服务实际提供的证书；替换或重新申请须明确审阅对应服务范围。总览不会自动申请、续期或重启。", 14, true));
        var dialog = OperationDialog("固定角色证书维护", DialogScroll(panel), "重新核对（只读）");
        if (await ShowDialog(dialog) == ContentDialogResult.Primary) await Submit(new(OperationKind.HealthAudit, item.Instance, new()));
    }
}
