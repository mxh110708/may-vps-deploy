#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ClientStreamRegression(string output)
    {
        var previous = scheme; var step = designerStep; var result = new JsonObject();
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        async Task<ContentDialog> Wait(ContentDialog? old = null)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(5);
            while ((activeTestDialog == null || activeTestDialog == old || !Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
            Require(activeTestDialog != null && activeTestDialog != old, "WS／gRPC 对话框未出现。"); shell.UpdateLayout(); return activeTestDialog!;
        }
        void Press(ContentDialog dialog, string name) => ((IInvokeProvider)new ButtonAutomationPeer(Find<Button>(dialog).Single(b => b.Name == name)).GetPattern(PatternInterface.Invoke)).Invoke();
        async Task Shot(ContentDialog dialog, string file)
        {
            shell.UpdateLayout(); var visual = Find<Border>(dialog).Where(b => b.ActualWidth >= 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)dialog;
            await Capture(SafePath.Resolve(output, file), visual);
        }
        try
        {
            scheme = ClientSchemes.New(paths); designerStep = 1; SelectPage("clients");
            var ws = "vless://" + Guid.NewGuid() + "@192.0.2.18:443?security=tls&type=ws&encryption=none&sni=tls.example.test&path=%2Fws-route&host=front.example.test#External-WS";
            var grpc = "trojan://synthetic-private-password@192.0.2.19:443?type=grpc&sni=tls.example.test&serviceName=MayTest&mode=gun#External-gRPC";
            var import = ImportClientLinks(); var form = await Wait(); var input = Find<TextBox>(form).Single(t => t.Tag as string == "ClientLinks.Input"); input.Text = ws + "\n" + grpc;
            Press(form, "PrimaryButton"); var preview = await Wait(form); var text = string.Join('\n', Find<TextBlock>(preview).Select(t => t.Text));
            Require(text.Contains("vless / WebSocket") && text.Contains("trojan / gRPC") && !text.Contains("synthetic-private-password") && input.Text == "", "WS／gRPC 预览混淆协议传输或泄露凭据。"); await Shot(preview, "client-stream-import.png"); Press(preview, "PrimaryButton"); await import;
            result["import_separates_protocol_transport_and_redacts"] = true;
            var before = ArchiveStore.Fingerprint(scheme); var node = scheme["Nodes"]![0]!.AsObject(); var identity = node.Text("Id"); var connection = ClientNodeImport.ConnectionFingerprint(node);
            var edit = EditNode(0); var dialog = await Wait(preview); Require(Microsoft.UI.Xaml.Automation.AutomationProperties.GetName(dialog) == "编辑外部 WS／gRPC 节点" && !Find<TextBox>(dialog).Any(t => t.Header as string == "Reality 公钥"), "WS 节点仍使用 Reality 表单。");
            Find<TextBox>(dialog).Single(t => t.Header as string == "节点名称").Text = "cancelled"; Press(dialog, "CloseButton"); await edit; Require(ArchiveStore.Fingerprint(scheme) == before, "取消 WS 编辑仍修改方案。"); result["cancel_preserves_all_native_settings"] = true;
            edit = EditNode(0); dialog = await Wait(dialog); Find<TextBox>(dialog).Single(t => t.Header as string == "节点名称").Text = "Renamed-WS"; await Shot(dialog, "client-stream-edit.png"); Press(dialog, "PrimaryButton"); await edit;
            node = scheme["Nodes"]![0]!.AsObject(); Require(node.Text("Id") == identity && node.Text("name") == "Renamed-WS" && ClientNodeImport.ConnectionFingerprint(node) == connection && !node.Flag("Source.Modified"), "改名改变了 WS 连接参数或来源身份。"); result["rename_preserves_native_connection_and_identity"] = true;
            scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" }; edit = EditNode(0); dialog = await Wait(dialog); var replacement = Find<PasswordBox>(dialog).Single(p => p.Tag as string == "ClientStream.Replacement"); replacement.Password = ws.Replace("%2Fws-route", "%2Freplaced-route"); Press(dialog, "PrimaryButton"); await edit;
            node = scheme["Nodes"]![0]!.AsObject(); Require(node.Text("Id") == identity && node.Text("name") == "Renamed-WS" && node.Text("sing_box.transport.path") == "/replaced-route" && node.Flag("Source.Modified") && scheme["Candidate"] == null && replacement.Password == "", "替换连接丢失名称／身份、未标记修改或保留旧候选／输入。"); result["replace_link_preserves_identity_invalidates_candidate"] = true;
            return result;
        }
        finally { scheme = previous; designerStep = step; SelectPage("clients"); }
    }
}
