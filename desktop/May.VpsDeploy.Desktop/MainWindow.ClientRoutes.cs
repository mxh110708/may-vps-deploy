using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task ImportClientLinks()
    {
        var selected = scheme ?? throw new OperationException("请先打开方案。");
        var model = new JsonObject { ["Region"] = selected["Layout"]!.Strings("region_groups").First(), ["Role"] = "Auto" };
        var input = new TextBox { Header = "每行一个分享链接", AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, Height = 180, MaxLength = ClientNodeImport.MaximumCharacters, Tag = "ClientLinks.Input" };
        var panel = Column(Text("支持 VLESS Reality + Vision、AnyTLS、Shadowsocks。先逐条预览，不支持的参数会明确拒绝。链接含凭据，只保存到方案的加密私人归档。", 14, true), input,
            Choice("入口归属 / 落地连接的入口组", model, "Region", selected["Layout"]!.Strings("region_groups").Select(r => (r, r))),
            Choice("节点用途", model, "Role", [("Auto", "默认：SS 作为落地，其余作为入口"), ("entry", "全部作为入口"), ("landing", "全部作为落地")]));
        var dialog = OperationDialog("导入外部节点", panel, "预览");
        ClientImportPreview preview;
        try
        {
            if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
            preview = ClientNodeImport.Preview(input.Text, selected, model.Text("Region"), model.Text("Role"));
        }
        finally { input.Text = ""; }
        var rows = new StackPanel { Spacing = 14 };
        foreach (var row in preview.Rows)
        {
            var node = row.Node;
            var server = node?.Text("sing_box.server") ?? ""; var endpoint = (server.Contains(':') ? "[" + server + "]" : server) + ":" + node?.Number("sing_box.server_port");
            rows.Children.Add(Column(Text("第 " + row.Line + " 行 · " + (row.Status == "Ready" ? node!.Text("name") : row.Status == "Duplicate" ? "重复连接" : "无法导入"), 16),
                Text(node == null ? row.Message : node.Text("sing_box.type") + " · " + endpoint + " · " + (node.Text("kind") == "entry" ? "入口" : "落地") + "\n" + row.Message, 13, true)));
        }
        var review = OperationDialog("核对导入结果", Column(Text("可导入 " + preview.Accepted + " 个；重复 " + preview.Rows.Count(r => r.Status == "Duplicate") + " 个；拒绝 " + preview.Rows.Count(r => r.Status == "Rejected") + " 个。只有下方标为可导入的节点会加入方案。", 14),
            new ScrollViewer { Content = rows, MaxHeight = 400 }), "导入 " + preview.Accepted + " 个有效节点");
        review.IsPrimaryButtonEnabled = preview.Accepted > 0;
        if (await ShowDialog(review) != ContentDialogResult.Primary) return;
        var count = ClientNodeImport.Apply(selected, preview); DirtyScheme(); Show("已加入 " + count + " 个外部节点。请保存方案，并在导出前重新生成、校验。", InfoBarSeverity.Success);
    }

    private async Task RemoveClientNode(int index)
    {
        var node = scheme!["Nodes"]!.AsArray()[index]!.AsObject(); var impact = ClientTopology.RemovalImpact(scheme, node);
        if (impact.Length != 0 && !await ConfirmAsync(new("移除被引用的节点", "移除“" + node.Text("name") + "”会影响：\n" + string.Join("\n", impact) + "\n需要重新指定受影响业务组的默认出口，补全连接后才能生成配置。"), CancellationToken.None)) return;
        var name = node.Text("name"); var region = node.Text("region_group"); scheme["Nodes"]!.AsArray().RemoveAt(index);
        var emptyRegion = node.Text("kind") == "entry" && !scheme["Nodes"]!.AsArray().Any(n => n!.Text("kind") == "entry" && n.Text("region_group") == region);
        foreach (var group in scheme["Layout"]!["business_groups"]!.AsArray().OfType<JsonObject>())
            if (group.Text("default") == name || emptyRegion && group.Text("default") == region) group["default"] = "";
        DirtyScheme();
    }

    private static string NodeRouteLabel(JsonObject node) => node.Text("name") + "\n" + node.Text("sing_box.type", node.Text("clash.type")) + " · 连接：" + ClientTopology.ConnectionFamily(node) + " · " + ClientTopology.OriginLabel(node);
    private static string ExitLabel(JsonObject node) => (node.At("ServerRoute.DestinationRules") is JsonArray rules && rules.Count > 0 ? "默认落地：" : "") + (ClientTopology.EgressFamily(node) switch { "IPv4" => "IPv4 网站出口", "IPv6" => "IPv6 网站出口", _ => "网站出口地址族未标注，诊断时观测" });

    private void DesignerTopology()
    {
        var selected = scheme!; var regions = ClientTopology.Regions(selected);
        var extraUpstreams = selected["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => n.Text("kind") == "entry" && (n.Text("sing_box.detour") != "" || n.Text("clash.dialer-proxy") != "")).Select(n => n.Text("name")).ToArray();
        if (extraUpstreams.Length != 0) page.Children.Add(Card(Column(Text("存在图外上游依赖", 17), Text(string.Join("、", extraUpstreams) + " 保留了来源配置中的额外上游。下图只展示地区入口与落地关系；请核对高级配置，轻量诊断不支持此类路径。", 14, true))));
        foreach (var region in regions)
        {
            var stack = Column(Text(region.Name, 18), Text("入口候选（客户端从组内选择）", 14, true)); stack.Tag = "ClientTopology." + region.Name;
            foreach (var entry in region.Entries) stack.Children.Add(Column(Text(NodeRouteLabel(entry), 14), Text("↳ 直接使用入口时：" + ExitLabel(entry), 13, true)));
            if (region.Landings.Count > 0)
            {
                stack.Children.Add(Text("↓ 经此入口组连接的落地候选", 14, true));
                foreach (var landing in region.Landings) stack.Children.Add(Column(Text(NodeRouteLabel(landing), 14), Text("↳ " + ExitLabel(landing), 13, true)));
            }
            page.Children.Add(Card(stack));
        }
        var business = new StackPanel { Spacing = 10 };
        foreach (var definition in selected["Layout"]!["business_groups"]!.AsArray().OfType<JsonObject>()) business.Children.Add(Text(definition.Text("name") + " → " + (definition.Text("default") == "" ? "未设置 · 需重新指定" : definition.Text("default")), 14));
        business.Children.Add(Text(selected.Text("Layout.default_exit_group") + " 优先顺序：" + string.Join(" → ", selected["Layout"]!.Strings("default_exit_members")) + "\n此处为方案默认值；无节点的地区候选生成时会过滤。", 13, true));
        page.Children.Add(Details("业务 → 默认出口", business));
        var run = Action("轻量链路诊断", DiagnoseClientRoute); run.Tag = "ClientDiagnostics.Start"; run.IsEnabled = regions.Count != 0;
        page.Children.Add(Card(Column(SectionHeading("按需诊断", Symbol.Find, "选择具体入口和可选落地，检查短连接与真实出口。任务可取消，不持续监测，不进行吞吐测试。"), run)));
        if (selected["Diagnostics"] is JsonArray reports)
            foreach (var report in reports.OfType<JsonObject>().Reverse()) page.Children.Add(ClientDiagnosticCard(selected, report));
    }

    private async Task DiagnoseClientRoute()
    {
        var selected = scheme!; var entries = ClientTopology.Regions(selected).SelectMany(r => r.Entries).ToArray();
        if (entries.Length == 0) throw new OperationException("请先添加入口。");
        var model = new JsonObject { ["Entry"] = entries[0].Text("name"), ["Landing"] = "" };
        var entryChoice = Choice("具体入口（不会自动选择组内首个节点）", model, "Entry", entries.Select(n => (n.Text("name"), n.Text("region_group") + " / " + n.Text("name"))));
        var landingHost = new StackPanel();
        void Refresh()
        {
            var entry = entries.Single(n => n.Text("name") == model.Text("Entry")); model["Landing"] = ""; landingHost.Children.Clear();
            var landings = selected["Nodes"]!.AsArray().OfType<JsonObject>().Where(n => n.Text("kind") == "landing" && n.Text("transit_group") == entry.Text("region_group"));
            landingHost.Children.Add(Choice("出口路径", model, "Landing", new[] { ("", "直接使用所选入口出口") }.Concat(landings.Select(n => (n.Text("name"), "经入口 → " + n.Text("name"))))));
        }
        entryChoice.SelectionChanged += (_, _) => Refresh(); Refresh();
        var dialog = OperationDialog("轻量链路诊断", Column(entryChoice, landingHost, Text("经隔离核心请求 ipify HTTPS 出口检查，每阶段最长 12 秒，整项任务最长 75 秒。不会更改系统代理或 VPS 配置。远端两点间的纯 RTT 不在本次测量范围内。", 14, true)), "开始诊断");
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        if (testSession != null) throw new OperationException("后台界面验证不执行公网诊断，请使用独立的本机回环诊断测试。");
        var route = ClientTopology.DiagnosticRoute(selected, model.Text("Entry"), model.Text("Landing") == "" ? null : model.Text("Landing"));
        var origins = new[] { route.Entry, route.Landing }.Where(n => n?["ManagedOrigin"] != null).Select(n => (JsonNode?)n!["ManagedOrigin"]!.DeepClone()).ToArray();
        ManagedNodeSources.Verify(store, new JsonArray(origins));
        JsonObject? report = null;
        try
        {
            await RunBackground("轻量链路诊断", async token => report = await clientDiagnostics.RunAsync(route, paths.Resolve("private/client-diagnostics"), new Progress<string>(s => taskText.Text = s), token));
            report!["EntryId"] = route.Entry.Text("Id"); report["EntryName"] = route.Entry.Text("name"); report["LandingId"] = route.Landing?.Text("Id") ?? ""; report["LandingName"] = route.Landing?.Text("name") ?? "";
            if (selected["Diagnostics"] is not JsonArray) selected["Diagnostics"] = new JsonArray();
            var reports = selected["Diagnostics"]!.AsArray(); reports.Add(report); while (reports.Count > 8) reports.RemoveAt(0);
        }
        finally { route.Entry.Clear(); route.Landing?.Clear(); Navigate("clients"); }
    }

    private UIElement ClientDiagnosticCard(JsonObject selected, JsonObject report)
    {
        var nodes = selected["Nodes"]!.AsArray().OfType<JsonObject>().ToArray();
        JsonObject? Lookup(string prefix) => nodes.FirstOrDefault(n => report.Text(prefix + "Id") != "" ? n.Text("Id") == report.Text(prefix + "Id") : n.Text("name") == report.Text(prefix + "Name"));
        var entry = Lookup("Entry"); var landing = report.Text("LandingName") == "" ? null : Lookup("Landing"); var current = false;
        try { if (entry != null && (report.Text("LandingName") == "" || landing != null)) current = ClientTopology.DiagnosticRoute(selected, entry.Text("name"), landing?.Text("name")).Fingerprint == report.Text("Fingerprint"); } catch (OperationException) { }
        var stack = Column(Text((report.Text("Status") == "Reachable" ? "所选路径已连通" : report.Text("Status") == "TimedOut" ? "诊断超时" : "诊断未通过") + (current ? "" : " · 参数已变化，需重测"), 17), Text(report.Text("Path"), 14), Text(LocalTime(report.Text("At")) + " · " + report.Text("Scope"), 13, true));
        foreach (var stage in report["Stages"]!.AsArray().OfType<JsonObject>()) stack.Children.Add(Text(stage.Text("Label") + "：" + (stage.Text("Status") == "Passed" ? "通过 · " + stage.Long("Milliseconds") + " ms" : stage.Text("Status") == "NotMeasured" ? "未测量" : "失败") + (stage.Text("Detail") == "" ? "" : "\n" + stage.Text("Detail")), 14, stage.Text("Status") == "NotMeasured"));
        foreach (var key in new[] { "EntryEgress", "ChainEgress" }) if (report[key] is JsonObject egress) stack.Children.Add(Text((key == "EntryEgress" ? "入口出口：" : "链路出口：") + egress.Text("Family") + " · " + egress.Text("Address") + "\n" + egress.Text("Detail"), 13, true));
        return Card(stack);
    }
}
