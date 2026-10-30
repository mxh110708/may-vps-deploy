using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task ServerQuicUiChoices(string relative, JsonObject plan, string output)
    {
        var scheme = ClientSchemes.New(paths); scheme["Name"] = "第十七轮合成 QUIC 来源";
        foreach (var protocol in new[] { "hysteria2", "tuic" })
        {
            var password = ServerConfigurations.RandomKey(32); var native = new JsonObject { ["tag"] = "UI-" + protocol, ["type"] = protocol, ["server"] = "192.0.2.23", ["server_port"] = 24000, ["password"] = password, ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "next.example.test", ["min_version"] = "1.3", ["alpn"] = new JsonArray("h3") } }; var clash = new JsonObject { ["name"] = "UI-" + protocol, ["type"] = protocol, ["server"] = "192.0.2.23", ["port"] = 24000, ["password"] = password, ["sni"] = "next.example.test", ["skip-cert-verify"] = false, ["udp"] = true };
            if (protocol == "tuic") { var uuid = Guid.NewGuid().ToString(); native["uuid"] = uuid; native["zero_rtt_handshake"] = false; native["udp_relay_mode"] = "native"; clash["uuid"] = uuid; clash["reduce-rtt"] = false; clash["udp-relay-mode"] = "native"; }
            scheme["Nodes"]!.AsArray().Add(new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "UI-" + protocol, ["kind"] = "landing", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["sing_box"] = native, ["clash"] = clash, ["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = "198.51.100.22" } });
        }
        workbench.Save(scheme); Task? pending = null;
        static ComboBox Pick(ContentDialog form) => Find<ComboBox>(form).Single(c => c.Header as string == "已保存的默认下一跳");
        static void Require(bool ok, string message) { if (!ok) throw new OperationException(message); }
        async Task<ContentDialog> Dialog(ContentDialog? previous = null)
        {
            for (var n = 0; n < 160; n++) { await Task.Delay(30); if (pending?.IsFaulted == true) await pending; if (activeTestDialog != null && activeTestDialog != previous && Find<Button>(activeTestDialog).Any(b => b.Name == "CloseButton")) { await Task.Delay(100); return activeTestDialog; } }
            throw new OperationException("第十七轮服务器出站对话框未打开。");
        }
        try
        {
            var tuic = scheme["Nodes"]!.AsArray().OfType<JsonObject>().Single(n => n.Text("sing_box.type") == "tuic"); var selected = scheme.Text("Id") + ":" + tuic.Text("Id");
            pending = ServerOutboundSheet(relative, plan, "AnyTlsEntry"); var form = await Dialog(); var choice = Pick(form);
            Require(choice.Items.Cast<ComboBoxItem>().Any(i => i.Tag as string == selected), "sing-box 表单没有 TUIC 来源。");
            await RegressionSelect(choice, choice.Items.Cast<ComboBoxItem>().ToList().FindIndex(i => i.Tag as string == selected));
            var roles = Find<ComboBox>(form).Single(c => c.Header as string == "目标入站组件"); await RegressionSelect(roles, 0);
            Require(!Pick(form).Items.Cast<ComboBoxItem>().Any(i => i.Tag as string == selected) && Pick(form).Items.Cast<ComboBoxItem>().Any(i => i.Content?.ToString()?.Contains("UI-hysteria2") == true), "固定 Xray 的下一跳能力筛选错误。");
            await RegressionSelect(roles, 1); Require(((ComboBoxItem)Pick(form).SelectedItem).Tag as string == selected, "核心切换丢失 QUIC 选择草稿。");
            await Capture(SafePath.Resolve(output, "server-quic-form.png"), form);
            await RegressionPress(form, "PrimaryButton"); var review = await Dialog(form); var text = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text));
            Require(text.Contains("UI-tuic") && !text.Contains(tuic.Text("sing_box.password")) && !text.Contains(tuic.Text("sing_box.uuid")), "QUIC 审阅遗漏选择或泄露认证信息。");
            await Capture(SafePath.Resolve(output, "server-quic-review.png"), review); await RegressionPress(review, "CloseButton"); await pending;
        }
        finally { if (activeTestDialog != null) activeTestDialog.Hide(); if (pending != null) await pending; workbench.Delete(scheme); }
    }
}
