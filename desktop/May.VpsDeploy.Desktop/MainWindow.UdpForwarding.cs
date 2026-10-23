using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task UdpForwardSheet(string relative, JsonObject plan)
    {
        var candidates = workbench.List().SelectMany(s => (s["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(ServerOutboundRouting.SupportedNode).Select(n => (Scheme: s, Node: n)) ?? []).ToArray();
        var config = (plan["UdpForwarding"] as JsonObject)?.DeepClone().AsObject() ?? UdpForwarding.Empty();
        var rules = config["Rules"]!.AsArray(); var model = new JsonObject { ["Action"] = "Apply" };
        var operation = Choice("操作", model, "Action", [("Apply", "保存 UDP 转发规则"), ("Check", "只读检查已保存转发"), ("Remove", "移除全部受管 UDP 转发")]); operation.Tag = "UdpForward.Action";
        var rows = new StackPanel { Spacing = 20 }; var error = Text("", 13, true); Button? add = null;
        void Refresh()
        {
            rows.Children.Clear();
            for (var i = 0; i < rules.Count; i++)
            {
                var index = i; var rule = rules[i]!.AsObject();
                var name = Field("转发名称", rule, "Name"); name.Tag = "UdpForward.Name." + i;
                var enabled = new CheckBox { Content = "启用此 UDP 转发", IsChecked = rule.Flag("Enabled"), Tag = "UdpForward.Enabled." + i };
                enabled.Checked += (_, _) => rule["Enabled"] = true; enabled.Unchecked += (_, _) => rule["Enabled"] = false;
                var family = Choice("监听地址族", rule, "ListenFamily", [("IPv4", "IPv4"), ("IPv6", "IPv6"), ("DualStack", "IPv4 + IPv6")]); family.Tag = "UdpForward.Family." + i;
                var port = Field("UDP 监听端口", rule, "ListenPort", numeric: true); port.Tag = "UdpForward.Port." + i;
                var target = Field("目标 IP 地址", rule, "TargetAddress"); target.Tag = "UdpForward.Target." + i;
                var targetPort = Field("目标 UDP 端口", rule, "TargetPort", numeric: true); targetPort.Tag = "UdpForward.TargetPort." + i;
                var timeout = Field("会话无流量超时（10–600 秒）", rule, "SessionTimeoutSeconds", numeric: true); timeout.Tag = "UdpForward.Timeout." + i;
                var maximum = Field("最大会话数（1–1024）", rule, "MaximumSessions", numeric: true); maximum.Tag = "UdpForward.Maximum." + i;
                var source = new JsonObject { ["Text"] = string.Join("\n", rule.Strings("AllowedSources")) };
                var sources = Field("允许来源（每行一个 IP 或 CIDR）", source, "Text"); sources.Tag = "UdpForward.Sources." + i; sources.AcceptsReturn = true; sources.TextWrapping = TextWrapping.Wrap; sources.MinHeight = 76;
                sources.TextChanged += (_, _) => rule["AllowedSources"] = new JsonArray(sources.Text.Split(['\r', '\n', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
                var validation = new JsonObject { ["Type"] = rule.Text("Validation.Type") };
                var kind = Choice("实际 UDP 往返验收", validation, "Type", [("Dns", "DNS 查询（目标提供 DNS）"), ("Echo", "随机回显（目标提供原样回显）"), ("Shadowsocks", "Shadowsocks／SS2022 代理 UDP")]); kind.Tag = "UdpForward.Validation." + i;
                var fields = new StackPanel { Spacing = 10 };
                void RefreshValidation()
                {
                    fields.Children.Clear(); var check = rule["Validation"]!.AsObject();
                    if (check.Text("Type") is "Dns" or "Shadowsocks")
                    {
                        if (check.Text("Type") == "Shadowsocks")
                        {
                            var selection = new JsonObject { ["Source"] = check.Text("SchemeId") + ":" + check.Text("NodeId") };
                            var choice = Choice("已保存的 Shadowsocks 来源", selection, "Source", candidates.Select(c => (c.Scheme.Text("Id") + ":" + c.Node.Text("Id"), c.Scheme.Text("Name") + " / " + c.Node.Text("name"))), true); choice.Tag = "UdpForward.Proxy." + index;
                            choice.PlaceholderText = "请选择已保存的 Shadowsocks 节点";
                            void UseSource()
                            {
                                var selected = workbench.List().SelectMany(s => (s["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(ServerOutboundRouting.SupportedNode).Select(n => (Scheme: s, Node: n)) ?? []).FirstOrDefault(c => c.Scheme.Text("Id") + ":" + c.Node.Text("Id") == selection.Text("Source"));
                                if (selected.Node == null) { error.Text = "所选代理来源已不可用，请保存受支持的 Shadowsocks 节点并重新打开。"; return; }
                                check["SchemeId"] = selected.Scheme.Text("Id"); check["NodeId"] = selected.Node.Text("Id"); check["NodeFingerprint"] = ArchiveStore.Fingerprint(selected.Node);
                                target.Text = selected.Node.Text("sing_box.server"); targetPort.Text = selected.Node.Text("sing_box.server_port"); error.Text = "";
                            }
                            choice.SelectionChanged += (_, _) => UseSource();
                            fields.Children.Add(choice); fields.Children.Add(Action("重新读取所选代理参数", () => { UseSource(); return Task.CompletedTask; }));
                            var resolver = Field("代理出口查询的 DNS 地址", check, "ResolverAddress"); resolver.Tag = "UdpForward.Resolver." + index;
                            var resolverPort = Field("DNS UDP 端口", check, "ResolverPort", numeric: true); resolverPort.Tag = "UdpForward.ResolverPort." + index;
                            fields.Children.Add(Fields(resolver, resolverPort));
                            fields.Children.Add(Text("只使用所选节点的原生 SS／SS2022 UDP 参数，凭据不发送到转发服务器。不支持额外链式、插件或 UDP-over-TCP；不以 TCP 成功代替 UDP，不代表 QUIC 等其他业务已验收。", 13, true));
                        }
                        var query = Field("查询域名（应返回有效记录）", check, "QueryName"); query.Tag = "UdpForward.Query." + index;
                        fields.Children.Add(query); fields.Children.Add(Choice("查询类型", check, "QueryType", [("A", "A / IPv4 记录"), ("AAAA", "AAAA / IPv6 记录")]));
                    }
                    else fields.Children.Add(Text("目标须将收到的数据报原样返回；每次验收使用新的随机内容。普通 UDP 服务可能不提供此能力。", 13, true));
                }
                kind.SelectionChanged += (_, _) =>
                {
                    var type = validation.Text("Type");
                    rule["Validation"] = type == "Echo" ? new JsonObject { ["Type"] = "Echo" } : new JsonObject { ["Type"] = type, ["QueryName"] = type == "Shadowsocks" ? "example.com" : "", ["QueryType"] = "A" };
                    if (type == "Shadowsocks") { var check = rule["Validation"]!.AsObject(); check["ResolverAddress"] = "1.1.1.1"; check["ResolverPort"] = 53; check["SchemeId"] = ""; check["NodeId"] = ""; check["NodeFingerprint"] = ""; }
                    RefreshValidation();
                };
                RefreshValidation();
                var remove = Action("移除此规则", () => { rules.RemoveAt(index); Refresh(); return Task.CompletedTask; }); remove.Tag = "UdpForward.Remove." + i;
                rows.Children.Add(Card(Column(Text("UDP 转发 " + (i + 1), 17), name, enabled, Fields(family, port), Fields(target, targetPort), Fields(timeout, maximum), sources, kind, fields, remove)));
            }
            if (add != null) add.IsEnabled = rules.Count < TcpForwarding.MaximumRules;
        }
        add = Action("添加 UDP 转发", () => { rules.Add(UdpForwarding.NewRule()); Refresh(); return Task.CompletedTask; }); add.Tag = "UdpForward.Add"; Refresh();
        var editor = Column(rows, add); operation.SelectionChanged += (_, _) => editor.Visibility = model.Text("Action") == "Apply" ? Visibility.Visible : Visibility.Collapsed;
        var dialog = OperationDialog("独立 UDP 端口转发", DialogScroll(Column(Text("验收支持目标的 DNS、原样回显或 Shadowsocks／SS2022 代理 UDP。允许来源须包含此电脑的公网地址／网段，双栈需同时放行两种来源。0.0.0.0/0、::/0 表示对应地址族的所有来源。保存会清空本组件旧会话。", 14, true), operation, editor, error)), "审阅");
        JsonObject? options = null;
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                var action = model.Text("Action"); options = UdpForwarding.Options(InstanceState(relative), action, action == "Apply" ? UdpForwarding.Normalize(config) : action == "Check" ? plan["UdpForwarding"] as JsonObject ?? UdpForwarding.Empty() : UdpForwarding.Empty());
                UdpForwarding.Prepare(store, new(OperationKind.UdpForward, relative, options)); error.Text = "";
            }
            catch (OperationException failure) { error.Text = failure.Message; args.Cancel = true; }
        };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        await Submit(new(OperationKind.UdpForward, relative, options ?? throw new OperationException("请重新审阅 UDP 转发。")));
    }
}
