using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task ServerOutboundSheet(string relative, JsonObject plan, string initialRole)
    {
        var roles = ServerOutboundRouting.Roles.Where(role => plan.Flag("ProtocolInventory." + role + ".Enabled", DeploymentPlans.InitiallyEnabled(plan, role))).ToArray();
        if (!roles.Contains(initialRole)) throw new OperationException("请先启用所选入站组件，再配置并验收服务器出站。");
        var allCandidates = workbench.List().SelectMany(s => (s["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(ServerOutboundRouting.SupportedNode).Select(n => (Scheme: s, Node: n)) ?? []).ToArray();
        var candidates = allCandidates.Where(c => ServerOutboundRouting.SupportedNode(c.Node, initialRole)).ToArray();
        var model = new JsonObject { ["Protocol"] = initialRole, ["Action"] = "Apply", ["Selection"] = "", ["ExpectedAddress"] = "" };
        var roleChoice = Choice("目标入站组件", model, "Protocol", roles.Select(role => (role, ServerOutboundRouting.Label(role))));
        var modeHost = new StackPanel { Spacing = 14 }; var currentText = Text("", 14, true); var scopeText = Text("", 14, true); var statusText = Text("", 13, true);
        JsonObject? current = null;
        var fields = new StackPanel { Spacing = 14 };
        var ruleInputs = new List<(JsonObject Rule, TextBox Input)>(); var hopInputs = new List<(JsonObject Model, TextBox Input)>(); var drafts = new Dictionary<string, JsonObject>(); string? shownRole = null;
        TextBox? expectedInput = null; JsonObject? reviewedOptions = null;
        var errorText = Text("", 13, true);
        var panel = Column(Text("入站 → 服务器连接所选下一跳 → 网站", 17), roleChoice, scopeText, currentText, statusText, modeHost, fields,
            Text("从已保存方案选择完整原生节点：sing-box 支持 Shadowsocks、Hysteria2、TUIC v5；固定 Xray 支持 Shadowsocks、Hysteria2。当前支持 IP 端点，不接受插件或客户端 detour。下一跳失败不会回退直连。", 13, true),
            Text("落地需允许当前 VPS 的来源地址；本操作不修改落地白名单。执行只重启所选组件，现有连接短暂断开。预期出口用于实际验收，不应填入口机地址。", 13, true), errorText);
        var dialog = OperationDialog("服务器固定下一跳", DialogScroll(panel), "审阅");
        void Refresh()
        {
            CaptureDestinationRules(ruleInputs); CaptureHopAddresses(hopInputs); if (expectedInput != null) model["ExpectedAddress"] = expectedInput.Text;
            ruleInputs.Clear(); hopInputs.Clear(); expectedInput = null; fields.Children.Clear();
            if (model.Text("Action") == "Remove") { dialog.IsPrimaryButtonEnabled = current != null; return; }
            dialog.IsPrimaryButtonEnabled = candidates.Length > 0;
            if (candidates.Length == 0) { fields.Children.Add(Text("请先在配置设计中导入并保存适用于所选核心的完整原生下一跳节点。")); return; }
            var selection = Choice("已保存的默认下一跳", model, "Selection", candidates.Select(c => (c.Scheme.Text("Id") + ":" + c.Node.Text("Id"), c.Scheme.Text("Name") + " / " + c.Node.Text("name"))), model.Text("Selection") != "");
            selection.PlaceholderText = "来源已缺失，请重新选择";
            var address = expectedInput = Field("预期网站出口 IP", model, "ExpectedAddress");
            void Selected(bool replace)
            {
                var chosen = candidates.FirstOrDefault(c => c.Scheme.Text("Id") + ":" + c.Node.Text("Id") == model.Text("Selection")); if (chosen.Node == null) return;
                var fallback = current?.Text("SchemeId") == chosen.Scheme.Text("Id") && current?.Text("NodeId") == chosen.Node.Text("Id") ? current!.Text("ExpectedAddress") : "";
                if (replace || model.Text("ExpectedAddress") == "") model["ExpectedAddress"] = chosen.Node.Text("Egress.ExpectedAddress", fallback); address.Text = model.Text("ExpectedAddress");
            }
            selection.SelectionChanged += (_, _) => Selected(true); Selected(false);
            fields.Children.Add(selection); fields.Children.Add(address);
            var rules = model["DestinationRules"]!.AsArray(); var hops = model["AdditionalHops"]!.AsArray(); var ruleHost = new StackPanel();
            void RefreshRules() { CaptureDestinationRules(ruleInputs); ruleInputs.Clear(); ruleHost.Children.Clear(); ruleHost.Children.Add(ServerDestinationEditor(rules, ruleInputs, ServerHopNames(hops, candidates))); }
            fields.Children.Add(ServerHopEditor(hops, rules, candidates, hopInputs, RefreshRules, model.Text("Selection"))); fields.Children.Add(ruleHost); RefreshRules();
        }
        void RefreshRole()
        {
            if (shownRole != null)
            {
                CaptureDestinationRules(ruleInputs); CaptureHopAddresses(hopInputs); if (expectedInput != null) model["ExpectedAddress"] = expectedInput.Text;
                drafts[shownRole] = new JsonObject { ["Selection"] = model["Selection"]?.DeepClone(), ["ExpectedAddress"] = model["ExpectedAddress"]?.DeepClone(), ["Action"] = model["Action"]?.DeepClone(), ["DestinationRules"] = model["DestinationRules"]?.DeepClone(), ["AdditionalHops"] = model["AdditionalHops"]?.DeepClone() };
            }
            ruleInputs.Clear(); hopInputs.Clear(); expectedInput = null;
            var role = model.Text("Protocol"); current = plan.At("ServerOutbound." + role) as JsonObject;
            candidates = allCandidates.Where(c => ServerOutboundRouting.SupportedNode(c.Node, role)).ToArray();
            shownRole = role;
            scopeText.Text = role == "RealityEntry" ? "Reality 主／备用端口、IPv4／IPv6 监听共同使用本次出口；保留 UUID、Reality 密钥和目标站点。" : "只处理 anytls-in 的出口；保留 AnyTLS 用户、TLS / ECH 和 padding。";
            currentText.Text = current == null ? "当前未设置固定下一跳。" : "当前下一跳：" + current.Text("Name") + " · 出口 " + current.Text("ExpectedAddress");
            statusText.Text = current == null ? "" : ServerOutboundRouting.SourcesSummary(store, current);
            model["Selection"] = current == null ? "" : current.Text("SchemeId") + ":" + current.Text("NodeId");
            model["ExpectedAddress"] = ""; model["Action"] = candidates.Length == 0 && current != null ? "Remove" : "Apply";
            model["DestinationRules"] = current?["DestinationRules"]?.DeepClone() ?? new JsonArray();
            model["AdditionalHops"] = new JsonArray((current?["AdditionalHops"] as JsonArray)?.OfType<JsonObject>().Select(h => (JsonNode?)new JsonObject { ["Id"] = h.Text("Id"), ["Selection"] = h.Text("SchemeId") + ":" + h.Text("NodeId"), ["ExpectedAddress"] = h.Text("ExpectedAddress") }).ToArray() ?? []);
            if (drafts.TryGetValue(role, out var draft)) foreach (var pair in draft) model[pair.Key] = pair.Value?.DeepClone();
            modeHost.Children.Clear(); var mode = Choice("本次操作", model, "Action", current == null ? [("Apply", "设置固定下一跳")] : [("Apply", "设置 / 更换固定下一跳"), ("Remove", "移除固定下一跳，恢复原出口策略")]);
            mode.SelectionChanged += (_, _) => Refresh(); modeHost.Children.Add(mode); errorText.Text = ""; Refresh();
        }
        roleChoice.SelectionChanged += (_, _) => RefreshRole(); RefreshRole();
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                if (model.Text("Action") == "Remove") reviewedOptions = ServerOutboundRouting.Options(InstanceState(relative), model.Text("Protocol"), "Remove");
                else
                {
                    var selected = candidates.FirstOrDefault(c => c.Scheme.Text("Id") + ":" + c.Node.Text("Id") == model.Text("Selection")); if (selected.Node == null) throw new OperationException("默认落地来源已缺失，请重新选择。");
                    // Snapshot the visible value before closing; WinUI TextChanged can be deferred.
                    CaptureDestinationRules(ruleInputs); CaptureHopAddresses(hopInputs); var references = new JsonArray();
                    foreach (var hop in model["AdditionalHops"]!.AsArray().OfType<JsonObject>())
                    {
                        var chosen = candidates.FirstOrDefault(c => c.Scheme.Text("Id") + ":" + c.Node.Text("Id") == hop.Text("Selection")); if (chosen.Node == null) throw new OperationException("附加落地来源已缺失，请重新选择。");
                        if (chosen.Scheme.Text("Id") + ":" + chosen.Node.Text("Id") == model.Text("Selection")) throw new OperationException("附加落地与默认落地重复，请在规则中直接选择默认落地。");
                        references.Add(ServerOutboundRouting.HopReference(hop.Text("Id"), chosen.Scheme, chosen.Node, hop.Text("ExpectedAddress").Trim()));
                    }
                    reviewedOptions = ServerOutboundRouting.Options(InstanceState(relative), model.Text("Protocol"), "Apply", selected.Scheme, selected.Node, expectedInput?.Text.Trim() ?? "", model["DestinationRules"]!.AsArray(), references);
                    ServerDestinationRules.ValidatePath(ServerDestinationRules.Normalize(reviewedOptions["DestinationRules"]), reviewedOptions.Text("ExpectedAddress").Contains(':') ? "IPv6" : "IPv4", plan.Flag((model.Text("Protocol") == "RealityEntry" ? "Reality" : "AnyTls") + ".ForceIpv4Egress", true), ServerOutboundRouting.HopFamilies(references));
                }
                errorText.Text = "";
            }
            catch (OperationException error) { errorText.Text = error.Message; args.Cancel = true; }
        };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        await Submit(new(OperationKind.ServerOutbound, relative, reviewedOptions ?? throw new OperationException("请重新审阅服务器出站表单。")));
    }
}
