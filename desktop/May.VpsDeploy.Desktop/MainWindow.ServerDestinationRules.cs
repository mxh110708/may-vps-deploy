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
    private UIElement ServerDestinationEditor(JsonArray rules, List<(JsonObject Rule, TextBox Input)> inputs, IReadOnlyDictionary<string, string>? hopNames = null, bool independent = false)
    {
        var available=AvailableServerRuleSets();
        var rows = new StackPanel { Spacing = 12 }; var message = Text("", 13, true);
        var trial = new JsonObject { ["Network"] = "tcp" };
        var trialNetwork = Choice("试算应用协议", trial, "Network", [("tcp", "TCP"), ("udp", "UDP")]); trialNetwork.Tag = "ServerRules.TestNetwork";
        var destination = new TextBox { Header = "试算目标（不联网）", PlaceholderText = "收到的域名或 IP", MaxLength = 300, Tag = "ServerRules.TestDestination" };
        var expander = new Expander { HorizontalAlignment = HorizontalAlignment.Stretch, IsExpanded = rules.Count > 0 };
        Button? add = null;
        void RefreshRules()
        {
            CaptureDestinationRules(inputs); inputs.Clear(); rows.Children.Clear(); expander.Header = "应用协议分流例外 · " + rules.Count + " 条";
            for (var i = 0; i < rules.Count; i++)
            {
                var index = i; var rule = rules[i]!.AsObject();
                var networkModel = new JsonObject { ["Network"] = ServerDestinationRules.Network(rule) };
                var network = Choice("应用协议", networkModel, "Network", [("TCP", "TCP（旧规则默认）"), ("UDP", "UDP"), ("Both", "TCP + UDP")]); network.Tag = "ServerRules.Network." + i;
                network.SelectionChanged += (_, _) => { if (networkModel.Text("Network") == "TCP") rule.Remove("Network"); else rule["Network"] = networkModel["Network"]!.DeepClone(); };
                var previousKind=rule.Text("Kind");var kind = Choice("匹配类型", rule, "Kind", [("Domain", "完整域名"), ("Suffix", "域名及其子域名"), ("Cidr", "目标 IP 网段"),("RuleSet","分类规则集（固定版本）")]); kind.Tag = "ServerRules.Kind." + i;
                kind.SelectionChanged+=(_,_)=>{CaptureDestinationRules(inputs);inputs.Clear();if(rule.Text("Kind")=="RuleSet"){var set=available.First();rule["Value"]=set.Text("Id");rule["RuleSet"]=set.DeepClone();}else{rule.Remove("RuleSet");if(previousKind=="RuleSet")rule["Value"]="";}RefreshRules();};
                FrameworkElement input;
                UIElement? snapshotDetails=null;
                if(rule.Text("Kind")=="RuleSet")
                {
                    var pinned=ServerRuleSets.Normalize(rule["RuleSet"]);var sets=new[]{pinned}.Concat(available).GroupBy(ServerRuleSets.Digest).Select(g=>g.First()).ToArray();var categorySelection=new JsonObject{["Digest"]=ServerRuleSets.Digest(pinned)};
                    var choice=Choice("分类与版本",categorySelection,"Digest",sets.Select(s=>(ServerRuleSets.Digest(s),s.Text("Name")+" v"+s.Text("Revision")+" · "+ServerRuleSets.Digest(s)[..8])));choice.Tag="ServerRules.RuleSet."+i;
                    choice.SelectionChanged+=(_,_)=>{var set=sets.Single(s=>ServerRuleSets.Digest(s)==categorySelection.Text("Digest"));rule["Value"]=set.Text("Id");rule["RuleSet"]=set.DeepClone();CaptureDestinationRules(inputs);inputs.Clear();RefreshRules();};input=choice;
                    snapshotDetails=Details("已固定版本的匹配项 · "+pinned["Rules"]!.AsArray().Count+" 项",new TextBox{Text=string.Join("\n",pinned["Rules"]!.AsArray().Select(r=>ServerDestinationRules.KindLabel(r!.Text("Kind"))+" · "+r.Text("Value"))),IsReadOnly=true,AcceptsReturn=true,MaxHeight=180});
                }
                else{var field=Field("匹配值",rule,"Value");field.MaxLength=300;field.Tag="ServerRules.Value."+i;inputs.Add((rule,field));input=field;}
                var choices = new List<(string, string)> { ("NextHop", independent ? "默认去向" : "默认落地"), ("Direct", independent ? "服务器直连" : "入口机直连"), ("Reject", "阻断") };
                if (hopNames != null) choices.AddRange(hopNames.Select(pair => ("Hop:" + pair.Key, (independent ? "出站 · " : "附加落地 · ") + pair.Value)));
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
                var row=Column(Text("规则 " + (i + 1), 15), Fields(network, kind, input, action), Row(up, down, remove));if(snapshotDetails!=null)row.Children.Add(snapshotDetails);rows.Children.Add(row);
            }
            if (add != null) add.IsEnabled = rules.Count < ServerDestinationRules.MaximumRules;
        }
        add = Action("添加分流规则", () => { CaptureDestinationRules(inputs); rules.Add(new JsonObject { ["Kind"] = "Domain", ["Value"] = "", ["Action"] = "NextHop" }); inputs.Clear(); RefreshRules(); message.Text = ""; return Task.CompletedTask; }); add.Tag = "ServerRules.Add";
        var test = Action("试算匹配", () =>
        {
            try { CaptureDestinationRules(inputs); var normalized = ServerDestinationRules.Normalize(rules, independent ? InboundCatalog.Id : null); var decision = ServerDestinationRules.Match(normalized, destination.Text.Trim(), trial.Text("Network")); message.Text = trial.Text("Network").ToUpperInvariant() + " 试算去向：" + (independent && decision.Target == "" ? decision.Action switch { "NextHop" => "默认去向", "Direct" => "服务器直连", _ => "阻断" } : ServerDestinationRules.DecisionLabel(decision, hopNames)) + "。仅检查规则匹配，不代表连接成功。"; }
            catch (OperationException error) { message.Text = error.Message; }
            return Task.CompletedTask;
        }); test.Tag = "ServerRules.Test";
        expander.Content = Column(Text("按应用协议与显示顺序首条命中，未命中使用默认去向；旧规则仅匹配 TCP。UDP 按核心目标会话选路，不以 QUIC 传输代替应用 UDP。只收到 IP 时按 IP 规则或默认去向，不反查或嗅探。分类固定版本；服务器直连使用 VPS 网络；选中去向失败不改走其他去向。", 13, true), rows, add, trialNetwork, destination, test, message);
        RefreshRules(); return expander;
    }
}
