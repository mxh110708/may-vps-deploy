using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private static void CaptureDestinationRules(List<(JsonObject Rule, TextBox Input)> inputs)
    {
        foreach (var (rule, input) in inputs) rule["Value"] = input.Text;
    }
    private UIElement ServerDestinationEditor(JsonArray rules, List<(JsonObject Rule, TextBox Input)> inputs, IReadOnlyDictionary<string, string>? hopNames = null)
    {
        var rows = new StackPanel { Spacing = 12 }; var message = Text("", 13, true);
        var destination = new TextBox { Header = "TCP 试算目标（不联网）", PlaceholderText = "域名或 IP", MaxLength = 300, Tag = "ServerRules.TestDestination" };
        var expander = new Expander { HorizontalAlignment = HorizontalAlignment.Stretch, IsExpanded = rules.Count > 0 };
        Button? add = null;
        void RefreshRules()
        {
            CaptureDestinationRules(inputs); inputs.Clear(); rows.Children.Clear(); expander.Header = "TCP 分流例外 · " + rules.Count + " 条";
            for (var i = 0; i < rules.Count; i++)
            {
                var index = i; var rule = rules[i]!.AsObject();
                var kind = Choice("匹配类型", rule, "Kind", [("Domain", "完整域名"), ("Suffix", "域名及其子域名"), ("Cidr", "目标 IP 网段")]); kind.Tag = "ServerRules.Kind." + i;
                var input = Field("匹配值", rule, "Value"); input.MaxLength = 300; input.Tag = "ServerRules.Value." + i; inputs.Add((rule, input));
                var choices = new List<(string, string)> { ("NextHop", "默认落地"), ("Direct", "入口机直连"), ("Reject", "阻断") };
                if (hopNames != null) choices.AddRange(hopNames.Select(pair => ("Hop:" + pair.Key, "附加落地 · " + pair.Value)));
                var selected = new JsonObject { ["Action"] = rule.Text("Target") == "" ? rule.Text("Action") : "Hop:" + rule.Text("Target") };
                var action = Choice("去向", selected, "Action", choices, true); action.PlaceholderText = "落地已缺失，请重新选择"; action.Tag = "ServerRules.Action." + i;
                action.SelectionChanged += (_, _) =>
                {
                    var value = selected.Text("Action"); rule["Action"] = value.StartsWith("Hop:", StringComparison.Ordinal) ? "NextHop" : value;
                    if (value.StartsWith("Hop:", StringComparison.Ordinal)) rule["Target"] = value[4..]; else rule.Remove("Target");
                };
                Task Move(int offset) { CaptureDestinationRules(inputs); var value = rules[index]!.DeepClone(); rules.RemoveAt(index); rules.Insert(index + offset, value); inputs.Clear(); RefreshRules(); message.Text = ""; return Task.CompletedTask; }
                var up = Action("上移", () => Move(-1)); up.IsEnabled = i > 0; up.Tag = "ServerRules.Up." + i;
                var down = Action("下移", () => Move(1)); down.IsEnabled = i + 1 < rules.Count; down.Tag = "ServerRules.Down." + i;
                var remove = Action("移除", () => { CaptureDestinationRules(inputs); rules.RemoveAt(index); inputs.Clear(); RefreshRules(); message.Text = ""; return Task.CompletedTask; }); remove.Tag = "ServerRules.Remove." + i;
                rows.Children.Add(Column(Text("规则 " + (i + 1), 15), Fields(kind, input, action), Row(up, down, remove)));
            }
            if (add != null) add.IsEnabled = rules.Count < ServerDestinationRules.MaximumRules;
        }
        add = Action("添加分流规则", () => { CaptureDestinationRules(inputs); rules.Add(new JsonObject { ["Kind"] = "Domain", ["Value"] = "", ["Action"] = "NextHop" }); inputs.Clear(); RefreshRules(); message.Text = ""; return Task.CompletedTask; }); add.Tag = "ServerRules.Add";
        var test = Action("试算匹配", () =>
        {
            try { CaptureDestinationRules(inputs); var normalized = ServerDestinationRules.Normalize(rules); message.Text = "试算去向：" + ServerDestinationRules.DecisionLabel(ServerDestinationRules.Match(normalized, destination.Text.Trim()), hopNames) + "。仅检查规则匹配，不代表连接成功。"; }
            catch (OperationException error) { message.Text = error.Message; }
            return Task.CompletedTask;
        }); test.Tag = "ServerRules.Test";
        expander.Content = Column(Text("只对 TCP 按顺序首条命中，未命中使用默认落地。UDP 保持默认落地。网段只匹配 IP 目标，不新增域名解析或嗅探。各落地独立验收，故障不回退到默认落地或直连。", 13, true), rows, add, destination, test, message);
        RefreshRules(); return expander;
    }
}
