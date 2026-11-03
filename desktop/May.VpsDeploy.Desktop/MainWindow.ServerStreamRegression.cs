using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task ServerStreamUiChoices(string relative, JsonObject plan, string output)
    {
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        var scheme = ClientSchemes.New(paths); scheme["Name"] = "第二十九轮合成来源"; var region = scheme["Layout"]!.Strings("region_groups")[0];
        var uuid = Guid.NewGuid().ToString(); var password = "synthetic-round29-private-password";
        ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("vless://" + uuid + "@192.0.2.29:24029?security=tls&sni=next.example.test#UI29-VLESS", scheme, region, "landing"));
        ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("trojan://" + password + "@192.0.2.29:24030?security=tls&sni=next.example.test#UI29-Trojan", scheme, region, "landing"));
        ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("vless://" + uuid + "@192.0.2.29:24031?security=tls&sni=next.example.test&type=ws&host=front.example.test&path=%2Fnext29%2F#UI29-WS", scheme, region, "landing"));
        var anytls = new JsonObject { ["Id"] = Guid.NewGuid().ToString("N"), ["name"] = "UI29-AnyTLS", ["kind"] = "landing", ["region_group"] = region, ["transit_group"] = region,
            ["sing_box"] = new JsonObject { ["type"] = "anytls", ["tag"] = "UI29-AnyTLS", ["server"] = "192.0.2.29", ["server_port"] = 24032, ["password"] = password, ["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = "next.example.test", ["min_version"] = "1.3" } },
            ["clash"] = new JsonObject { ["name"] = "UI29-AnyTLS", ["type"] = "anytls", ["server"] = "192.0.2.29", ["port"] = 24032, ["password"] = password, ["sni"] = "next.example.test", ["skip-cert-verify"] = false, ["udp"] = true } };
        scheme["Nodes"]!.AsArray().Add(anytls);
        foreach (var node in scheme["Nodes"]!.AsArray().OfType<JsonObject>()) node["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = "198.51.100.29" };
        workbench.Save(scheme); Task? pending = null;
        async Task<ContentDialog> Dialog(ContentDialog? previous = null)
        { for (var n = 0; n < 180; n++) { await Task.Delay(30); if (pending?.IsFaulted == true) await pending; if (activeTestDialog != null && activeTestDialog != previous && Find<Button>(activeTestDialog).Any(b => b.Name == "CloseButton")) { await Task.Delay(80); return activeTestDialog; } } throw new OperationException("第二十九轮后台表单未打开。"); }
        async Task Select(ComboBox box, string value)
        { var index = box.Items.Cast<ComboBoxItem>().ToList().FindIndex(i => i.Tag as string == value); Require(index >= 0, "第二十九轮选项缺失。"); await RegressionSelect(box, index); }
        static ComboBox Pick(ContentDialog form) => Find<ComboBox>(form).Single(c => c.Header as string == "已保存的默认下一跳");
        string Id(string name) => scheme.Text("Id") + ":" + scheme["Nodes"]!.AsArray().Single(n => n!.Text("name") == name)!.Text("Id");
        try
        {
            pending = ServerOutboundSheet(relative, plan, "AnyTlsEntry"); var form = await Dialog();
            Require(new[] { "UI29-VLESS", "UI29-Trojan", "UI29-WS", "UI29-AnyTLS" }.All(name => Pick(form).Items.Cast<ComboBoxItem>().Any(i => i.Tag as string == Id(name))), "sing-box 未提供所有受支持的下一跳来源。");
            await Select(Pick(form), Id("UI29-AnyTLS")); await Select(Find<ComboBox>(form).Single(c => c.Header as string == "目标入站组件"), "RealityEntry");
            Require(Pick(form).Items.Cast<ComboBoxItem>().Any(i => i.Tag as string == Id("UI29-Trojan")) && !Pick(form).Items.Cast<ComboBoxItem>().Any(i => i.Tag as string == Id("UI29-AnyTLS") || i.Tag as string == Id("UI29-WS")), "Xray 未按可完整转换的范围筛选来源。");
            await Select(Find<ComboBox>(form).Single(c => c.Header as string == "目标入站组件"), "AnyTlsEntry"); Require(((ComboBoxItem)Pick(form).SelectedItem).Tag as string == Id("UI29-AnyTLS"), "切换核心丢失下一跳选择草稿。");
            await Select(Pick(form), Id("UI29-Trojan")); await RegressionPress(form, "PrimaryButton"); var review = await Dialog(form); var text = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text));
            Require(text.Contains("Trojan / TLS") && text.Contains("UI29-Trojan") && !text.Contains(password) && !text.Contains(uuid), "下一跳审阅未显示协议边界或泄露认证信息。");
            await Capture(SafePath.Resolve(output, "server-stream-review.png"), review); await RegressionPress(review, "CloseButton"); await pending;
            pending = InboundsSheet(relative, plan); form = await Dialog(); await RegressionInvoke(Find<Button>(form).Single(b => b.Tag as string == "Inbounds.Add"));
            await Select(Find<ComboBox>(form).Single(c => c.Tag as string == "Inbounds.Group"), "Outbounds"); await Select(Find<ComboBox>(form).Single(c => c.Tag as string == "Inbounds.OutboundKind"), "Proxy");
            var sources = Find<ComboBox>(form).Single(c => c.Tag as string == "Inbounds.ProxySource"); Require(sources.Items.Cast<ComboBoxItem>().Any(i => i.Tag as string == Id("UI29-Trojan")), "独立入站缺少 Trojan 下一跳来源。"); await Select(sources, Id("UI29-Trojan"));
            await Capture(SafePath.Resolve(output, "inbound-stream-source.png"), form); await RegressionPress(form, "CloseButton"); await pending;
        }
        finally { if (activeTestDialog != null) activeTestDialog.Hide(); if (pending != null) await pending; workbench.Delete(scheme); }
    }
}
