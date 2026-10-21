using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private static void CaptureHopAddresses(List<(JsonObject Model, TextBox Input)> inputs)
    {
        foreach (var (model, input) in inputs) model["ExpectedAddress"] = input.Text;
    }
    private static IReadOnlyDictionary<string, string> ServerHopNames(JsonArray hops, (JsonObject Scheme, JsonObject Node)[] candidates) => hops.OfType<JsonObject>().ToDictionary(h => h.Text("Id"), h => candidates.FirstOrDefault(c => c.Scheme.Text("Id") + ":" + c.Node.Text("Id") == h.Text("Selection")).Node?.Text("name") ?? "来源已缺失", StringComparer.Ordinal);
    private UIElement ServerHopEditor(JsonArray hops, JsonArray rules, (JsonObject Scheme, JsonObject Node)[] candidates, List<(JsonObject Model, TextBox Input)> inputs, Action changed, string defaultSelection)
    {
        var rows = new StackPanel { Spacing = 14 }; var message = Text("", 13, true); Button? add = null;
        void Refresh()
        {
            CaptureHopAddresses(inputs); inputs.Clear(); rows.Children.Clear();
            for (var i = 0; i < hops.Count; i++)
            {
                var index = i; var hop = hops[i]!.AsObject();
                var choice = Choice("附加 TCP 落地 " + (i + 1), hop, "Selection", candidates.Select(c => (c.Scheme.Text("Id") + ":" + c.Node.Text("Id"), c.Scheme.Text("Name") + " / " + c.Node.Text("name"))), true);
                choice.PlaceholderText = "请选择有效的落地来源"; choice.Tag = "ServerHops.Selection." + i;
                var address = Field("此落地的预期网站出口 IP", hop, "ExpectedAddress"); address.Tag = "ServerHops.Address." + i; inputs.Add((hop, address));
                choice.SelectionChanged += (_, _) =>
                {
                    var node = candidates.Single(c => c.Scheme.Text("Id") + ":" + c.Node.Text("Id") == hop.Text("Selection")).Node;
                    hop["ExpectedAddress"] = node.Text("Egress.ExpectedAddress"); address.Text = hop.Text("ExpectedAddress"); changed();
                };
                var remove = Action("移除此落地", () =>
                {
                    if (rules.OfType<JsonObject>().Any(r => r.Text("Target") == hop.Text("Id"))) { message.Text = "此落地仍被规则引用，请先修改或移除对应规则。"; return Task.CompletedTask; }
                    CaptureHopAddresses(inputs); hops.RemoveAt(index); inputs.Clear(); Refresh(); changed(); message.Text = ""; return Task.CompletedTask;
                }); remove.Tag = "ServerHops.Remove." + i;
                rows.Children.Add(Column(choice, address, remove));
            }
            if (add != null) add.IsEnabled = hops.Count < ServerOutboundRouting.MaximumAdditionalHops;
        }
        add = Action("添加 TCP 落地", () =>
        {
            CaptureHopAddresses(inputs); var used = hops.OfType<JsonObject>().Select(h => h.Text("Selection")).Append(defaultSelection).ToHashSet(StringComparer.Ordinal);
            var candidate = candidates.FirstOrDefault(c => !used.Contains(c.Scheme.Text("Id") + ":" + c.Node.Text("Id")));
            hops.Add(new JsonObject { ["Id"] = Guid.NewGuid().ToString("N")[..16], ["Selection"] = candidate.Node == null ? "" : candidate.Scheme.Text("Id") + ":" + candidate.Node.Text("Id"), ["ExpectedAddress"] = candidate.Node?.Text("Egress.ExpectedAddress") ?? "" });
            inputs.Clear(); Refresh(); changed(); message.Text = ""; return Task.CompletedTask;
        }); add.Tag = "ServerHops.Add";
        Refresh(); return Column(Text("附加 TCP 落地", 16), Text("最多 7 个，每个落地需被分流规则使用。未命中规则和 UDP 仍走默认落地。", 13, true), rows, add, message);
    }
}
