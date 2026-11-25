using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private FrameworkElement ForwardProxyReceiveEditor(JsonObject rule, int index, Dictionary<string, JsonObject> drafts, JsonObject plan)
    {
        var id = rule.Text("Id");
        if (rule["ProxyReceive"] is JsonObject current) drafts[id] = current;
        if (!drafts.TryGetValue(id, out var policy)) { policy = ForwardProxyReceive.New(); policy["ProbeDestination"] = plan.Text("Server.IPv4"); drafts[id] = policy; }
        var enabled = new CheckBox { Content = "仅接收可信中转发送的 PROXY 头", IsChecked = rule["ProxyReceive"] != null, Tag = "TcpForward.Receive.Enabled." + index };
        var protocol = Choice("接收格式", policy, "Protocol", [("Auto", "识别 v1／v2"), ("v1", "仅 v1"), ("v2", "仅 v2")]); protocol.Tag = "TcpForward.Receive.Protocol." + index;
        TextBox Networks(string label, string key)
        {
            var text = new JsonObject { ["Value"] = string.Join("\n", policy.Strings(key)) };
            var field = Field(label, text, "Value"); field.Tag = "TcpForward.Receive." + key + "." + index;
            field.AcceptsReturn = true; field.TextWrapping = TextWrapping.Wrap; field.MinHeight = 68;
            field.TextChanged += (_, _) => policy[key] = new JsonArray(field.Text.Split(['\r', '\n', ',', ';'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
            return field;
        }
        var trusted = Networks("可信中转 IP／CIDR（须被连接白名单覆盖；不能填写全网）", "TrustedSources");
        var clients = Networks("允许中转声明的客户端 IP／CIDR（可明确填写全网）", "ClientSources");
        var probe = Field("验收时声明的测试客户端 IP（须位于客户端网段内）", policy, "ProbeSource"); probe.Tag = "TcpForward.Receive.ProbeSource." + index;
        var destination = Field("验收时声明的原目的 IP（与测试客户端同一地址族）", policy, "ProbeDestination"); destination.Tag = "TcpForward.Receive.ProbeDestination." + index;
        var timeout = Field("头部总接收时限（1–10 秒）", policy, "TimeoutSeconds", numeric: true); timeout.Tag = "TcpForward.Receive.TimeoutSeconds." + index;
        var fields = Column(protocol, trusted, clients, probe, destination, timeout,
            Text("此电脑须在可信中转范围内才能直接验收。启用后拒绝无头直连、非可信对端及超出客户端网段的声明；完整头部通过前不连接下游。需同时选择 PROXY 输出与 TLS 证书验收，下游只应信任本转发端。验收 IP 是明确声明的测试值，不推断公网来源。", 13, true));
        fields.Visibility = enabled.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
        enabled.Checked += (_, _) => { rule["ProxyReceive"] = policy; fields.Visibility = Visibility.Visible; };
        enabled.Unchecked += (_, _) => { rule.Remove("ProxyReceive"); fields.Visibility = Visibility.Collapsed; };
        return Column(enabled, fields);
    }
}
