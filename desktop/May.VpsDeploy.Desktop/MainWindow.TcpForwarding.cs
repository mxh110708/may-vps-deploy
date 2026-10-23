using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task TcpForwardSheet(string relative, JsonObject plan)
    {
        var configuration = (plan["TcpForwarding"] as JsonObject)?.DeepClone().AsObject() ?? TcpForwarding.Empty();
        var rules = configuration["Rules"]!.AsArray(); var model = new JsonObject { ["Action"] = "Apply" };
        var operation = Choice("操作", model, "Action", [("Apply", "保存转发规则"), ("Check", "只读检查已保存转发"), ("Remove", "移除全部受管 TCP 转发")]); operation.Tag = "TcpForward.Action";
        var candidates = workbench.List().SelectMany(s => (s["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(n => n["sing_box"] is JsonObject native && native.Text("type") is "vless" or "anytls" or "shadowsocks" && native.Text("detour") == "").Select(n => (Scheme: s, Node: n)) ?? []).ToArray();
        var rows = new StackPanel { Spacing = 20 }; var error = Text("", 13, true); Button? add = null;
        void Refresh()
        {
            rows.Children.Clear();
            for (var i = 0; i < rules.Count; i++)
            {
                var index = i; var rule = rules[i]!.AsObject();
                var enabled = new CheckBox { Content = "启用此转发", IsChecked = rule.Flag("Enabled"), Tag = "TcpForward.Enabled." + i };
                enabled.Checked += (_, _) => rule["Enabled"] = true; enabled.Unchecked += (_, _) => rule["Enabled"] = false;
                var name = Field("转发名称", rule, "Name"); name.Tag = "TcpForward.Name." + i;
                var family = Choice("监听地址族", rule, "ListenFamily", [("IPv4", "IPv4"), ("IPv6", "IPv6"), ("DualStack", "IPv4 + IPv6")]); family.Tag = "TcpForward.Family." + i;
                var port = Field("监听端口", rule, "ListenPort", numeric: true); port.Tag = "TcpForward.Port." + i;
                var target = Field("目标 IP 地址", rule, "TargetAddress"); target.Tag = "TcpForward.Target." + i;
                var targetPort = Field("目标端口", rule, "TargetPort", numeric: true); targetPort.Tag = "TcpForward.TargetPort." + i;
                var sourceModel = new JsonObject { ["Text"] = string.Join("\n", rule.Strings("AllowedSources")) };
                var sources = Field("允许来源（每行一个 IP 或 CIDR）", sourceModel, "Text"); sources.Tag = "TcpForward.Sources." + i; sources.AcceptsReturn = true; sources.TextWrapping = TextWrapping.Wrap; sources.MinHeight = 76;
                sources.TextChanged += (_, _) => rule["AllowedSources"] = new JsonArray(sources.Text.Split(['\r', '\n', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
                var checkModel = new JsonObject { ["Type"] = rule.Text("Validation.Type") };
                var checkType = Choice("实际转发验收", checkModel, "Type", [("Tls", "TLS 握手及证书"), ("Ssh", "SSH 协议响应"), ("Proxy", "已保存代理的 HTTPS 出口")]); checkType.Tag = "TcpForward.Validation." + i;
                var checks = new StackPanel { Spacing = 10 };
                void RefreshCheck()
                {
                    checks.Children.Clear(); var validation = rule["Validation"]!.AsObject();
                    if (validation.Text("Type") == "Tls") { var sni = Field("目标 TLS 域名（保留证书校验）", validation, "ServerName"); sni.Tag = "TcpForward.Sni." + index; checks.Children.Add(sni); }
                    else if (validation.Text("Type") == "Ssh") checks.Children.Add(Text("读取经转发的 SSH 2.0 响应，不登录或修改目标服务器。", 13, true));
                    else
                    {
                        var selection = new JsonObject { ["Source"] = validation.Text("SchemeId") + ":" + validation.Text("NodeId") };
                        var choice = Choice("代理验收来源", selection, "Source", candidates.Select(c => (c.Scheme.Text("Id") + ":" + c.Node.Text("Id"), c.Scheme.Text("Name") + " / " + c.Node.Text("name"))), true); choice.Tag = "TcpForward.Proxy." + index;
                        void UseSource()
                        {
                            var selected = candidates.FirstOrDefault(c => c.Scheme.Text("Id") + ":" + c.Node.Text("Id") == selection.Text("Source"));
                            if (selected.Node == null) return;
                            validation["SchemeId"] = selected.Scheme.Text("Id"); validation["NodeId"] = selected.Node.Text("Id"); validation["NodeFingerprint"] = ArchiveStore.Fingerprint(selected.Node);
                            target.Text = selected.Node.Text("sing_box.server"); targetPort.Text = selected.Node.Text("sing_box.server_port");
                        }
                        choice.SelectionChanged += (_, _) => UseSource();
                        checks.Children.Add(choice); checks.Children.Add(Action("重新读取所选代理参数", () => { UseSource(); return Task.CompletedTask; }));
                    }
                }
                checkType.SelectionChanged += (_, _) => { var kind = checkModel.Text("Type"); rule["Validation"] = kind == "Tls" ? new JsonObject { ["Type"] = kind, ["ServerName"] = "" } : new JsonObject { ["Type"] = kind }; RefreshCheck(); };
                RefreshCheck();
                var remove = Action("移除此规则", () => { rules.RemoveAt(index); Refresh(); return Task.CompletedTask; }); remove.Tag = "TcpForward.Remove." + i;
                rows.Children.Add(Card(Column(Text("转发 " + (i + 1), 17), name, enabled, Fields(family, port), Fields(target, targetPort), sources, checkType, checks, remove)));
            }
            if (add != null) add.IsEnabled = rules.Count < TcpForwarding.MaximumRules;
        }
        add = Action("添加 TCP 转发", () => { rules.Add(TcpForwarding.NewRule()); Refresh(); return Task.CompletedTask; }); add.Tag = "TcpForward.Add";
        Refresh();
        var editor = Column(rows, add); operation.SelectionChanged += (_, _) => editor.Visibility = model.Text("Action") == "Apply" ? Visibility.Visible : Visibility.Collapsed;
        var dialog = OperationDialog("独立 TCP 端口转发", DialogScroll(Column(Text("独立监听并转发到一个 IP 目标；仅 TCP。允许来源应包含此电脑的公网 IP 或网段，双栈验收需同时放行两种地址。0.0.0.0/0、::/0 表示相应地址族的所有来源。确认前不连接或修改 VPS。", 14, true), operation, editor, error)), "审阅");
        JsonObject? options = null;
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                var action = model.Text("Action");
                options = TcpForwarding.Options(InstanceState(relative), action, action == "Apply" ? TcpForwarding.Normalize(configuration) : action == "Check" ? plan["TcpForwarding"] as JsonObject ?? TcpForwarding.Empty() : TcpForwarding.Empty());
                TcpForwarding.Prepare(store, new(OperationKind.TcpForward, relative, options)); error.Text = "";
            }
            catch (OperationException failure) { error.Text = failure.Message; args.Cancel = true; }
        };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        await Submit(new(OperationKind.TcpForward, relative, options ?? throw new OperationException("请重新审阅转发表单。")));
    }
}
