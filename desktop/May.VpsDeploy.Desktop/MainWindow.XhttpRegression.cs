using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> XhttpRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("XHTTP 界面回归只允许合成工作区。");
        static void Require(bool ok, string message) { if (!ok) throw new OperationException(message); }
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            for (var i = 0; i < 120; i++) { await Task.Delay(25); if (activeTestDialog != null && activeTestDialog != old) { activeTestDialog.UpdateLayout(); if (Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) { await Task.Delay(150); return activeTestDialog; } } }
            throw new OperationException("未收到 XHTTP 表单。");
        }
        static TextBox Input(ContentDialog form, string tag) => Find<TextBox>(form).Single(t => t.Tag as string == "Inbounds." + tag);
        static ComboBox ChoiceIn(ContentDialog form, string tag) => Find<ComboBox>(form).Single(c => c.Tag as string == "Inbounds." + tag);
        var previous = selectedInstance; var previousScheme = scheme; var plan = store.ListInstances().First().Plan.DeepClone().AsObject(); plan["Provider"] = "Example"; plan["Instance"] = "Round19-" + Guid.NewGuid().ToString("N")[..8]; plan.Remove("TcpChain"); plan.Put("Import.Status", JsonValue.Create("Completed")); var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative); plan.Put("Paths.Archive", JsonValue.Create(directory));
        var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var inbound = InboundCatalog.AddInbound(model, credentials, "VLESS"); using var key = RSA.Create(2048); var csr = new CertificateRequest("CN=xhttp.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("xhttp.example.test"); csr.CertificateExtensions.Add(san.Build()); using var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2)); var resource = InboundCatalog.ImportCertificate(model, credentials, "TLS identity", cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()); inbound["CertificateId"] = resource.Text("Id"); inbound["Options"]!["ServerName"] = "xhttp.example.test"; inbound["Options"]!["Transport"]!["Host"] = "front.example.test"; plan["InboundModel"] = model.DeepClone();
        var payload = InboundRendering.Payload(store, plan, model, credentials); var state = new JsonObject { ["Engine"] = "dotnet-v1", ["Inbounds"] = new JsonObject { ["RemoteHash"] = new string('a', 64), ["ModelFingerprint"] = ArchiveStore.Fingerprint(model), ["Core"] = payload["Core"]!.DeepClone(), ["Bindings"] = payload["Bindings"]!.DeepClone(), ["Runtime"] = new JsonObject { [inbound.Text("Id")] = new JsonObject { ["Enabled"] = true, ["Active"] = true } } } };
        var file = SafePath.Resolve(directory, "deployment-plan.json"); ArchiveStore.WriteJson(file, plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), new JsonObject { ["Inbounds"] = credentials.DeepClone() }); var history = new TaskHistory(store).Read().Count; Task? pending = null;
        try
        {
            selectedInstance = relative; pending = InboundsSheet(relative, plan); var form = await Dialog(); var originalPath = Input(form, "XhttpPath").Text;
            Require(ChoiceIn(form, "XhttpSecurity").SelectedIndex == 0 && ChoiceIn(form, "Certificate").SelectedIndex >= 0 && ChoiceIn(form,"XhttpMode").Items.Count==4 && ChoiceIn(form,"XhttpVersion").Items.Count==3 && Find<TextBlock>(form).Any(t => t.Text.Contains("May Core")), "XHTTP TLS 默认身份或完整范围说明缺失。");
            await RegressionFill(Input(form, "XhttpPath"), "/"+new string('a',8192)); await RegressionPress(form, "PrimaryButton"); await Task.Delay(100); Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "Inbounds.Error").Text.Contains("路径"), "XHTTP 超长路径进入执行审阅。"); await RegressionFill(Input(form, "XhttpPath"), originalPath);
            await Capture(SafePath.Resolve(output, "xhttp-tls-form.png"), form); await RegressionPress(form, "PrimaryButton"); var review = await Dialog(form); var text = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text));
            Require(text.Contains("TLS") && text.Contains("XHTTP") && text.Contains("stream-one") && !text.Contains(credentials.Text("Users." + inbound.Strings("UserIds")[0] + ".Value")), "XHTTP TLS 审阅遗漏参数或暴露 UUID。"); await Capture(SafePath.Resolve(output, "xhttp-tls-review.png"), review); await RegressionPress(review, "CloseButton"); await pending;
            pending = InboundsSheet(relative, plan); form = await Dialog();
            await RegressionSelect(ChoiceIn(form,"XhttpVersion"),2);await RegressionSelect(ChoiceIn(form,"XhttpMode"),3);
            await RegressionFill(Input(form,"XhttpExtra"),"{\"sessionPlacement\":\"header\",\"seqPlacement\":\"query\",\"scMaxEachPostBytes\":4096,\"xmux\":{\"maxConnections\":2,\"hMaxRequestTimes\":\"10-20\"}}");
            await RegressionPress(form,"PrimaryButton");review=await Dialog(form);text=string.Join('\n',Find<TextBlock>(review).Select(t=>t.Text));
            Require(text.Contains("HTTP/3")&&text.Contains("packet-up")&&text.Contains("高级参数"),"XHTTP 高级参数或 HTTP/3 未进入真实审阅。");await Capture(SafePath.Resolve(output,"xhttp-h3-review.png"),review);await RegressionPress(review,"CloseButton");await pending;
            pending = InboundsSheet(relative, plan); form = await Dialog();await RegressionSelect(ChoiceIn(form,"XhttpVersion"),2); await RegressionSelect(ChoiceIn(form, "XhttpSecurity"), 1);
            Require(ChoiceIn(form,"XhttpVersion").Items.Count==1&&ChoiceIn(form,"XhttpVersion").SelectedIndex==0,"Reality 切换后仍保留不适用的 HTTP/3。");
            Require(!Find<ComboBox>(form).Any(c => c.Tag as string == "Inbounds.Certificate") && Find<PasswordBox>(form).Any(p => p.Tag as string == "Inbounds.XhttpRealityPrivate"), "XHTTP 切换 Reality 后仍引用 TLS 证书或私钥未受保护。");
            await RegressionFill(Input(form, "XhttpTarget"), "target.example.test"); var generate = Find<Button>(form).Single(b => b.Tag as string == "Inbounds.XhttpGenerateReality"); await RegressionInvoke(generate);
            for (var i = 0; i < 120 && Input(form, "XhttpPublicKey").Text.Length != 43; i++) await Task.Delay(50);
            Require(Input(form, "XhttpPublicKey").Text.Length == 43 && Find<PasswordBox>(form).Single(p => p.Tag as string == "Inbounds.XhttpRealityPrivate").Password.Length == 43, "XHTTP Reality 密钥未同时接通。");
            await RegressionPress(form, "PrimaryButton"); review = await Dialog(form); text = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text)); Require(text.Contains("Reality") && text.Contains("stream-one") && text.Contains("target.example.test"), "XHTTP Reality 审阅遗漏目标或传输。"); await Capture(SafePath.Resolve(output, "xhttp-reality-review.png"), review); await RegressionPress(review, "CloseButton"); await pending;
            pending = InboundsSheet(relative, plan); form = await Dialog(); await RegressionSelect(ChoiceIn(form, "Action"), 3); Require(Find<TextBlock>(form).Any(t => t.Text.Contains("另一核心保持原版本")), "Xray 核心升级说明仍误称修改 sing-box。"); await RegressionPress(form, "CloseButton"); await pending;
            Require(new TaskHistory(store).Read().Count == history && ArchiveStore.Fingerprint(ArchiveStore.ReadJson(file)) == ArchiveStore.Fingerprint(plan), "XHTTP 取消后仍保存或执行。");
            scheme = ClientSchemes.New(paths); scheme["OutputClients"] = "Clash"; var node = InboundRendering.Nodes(store, relative, plan, model, credentials).First(); node.Remove("InboundOrigin"); node["region_group"] = scheme["Layout"]!.Strings("region_groups").First(); node["transit_group"] = node.Text("region_group"); scheme["Nodes"] = new JsonArray(node); var fingerprint = ClientNodeImport.ConnectionFingerprint(node);
            pending = EditNode(0); form = await Dialog(); Require(Microsoft.UI.Xaml.Automation.AutomationProperties.GetName(form) == "编辑 XHTTP 节点" && !Find<PasswordBox>(form).Any(), "原生 XHTTP 被错误送入 Reality／Vision 编辑器。"); await RegressionFill(Find<TextBox>(form).Single(t => t.Header as string == "节点名称"), "Renamed-XHTTP"); await RegressionPress(form, "PrimaryButton"); await pending; Require(node.Text("name") == "Renamed-XHTTP" && node.Text("sing_box.transport.type") == "xhttp" && ClientNodeImport.ConnectionFingerprint(node) == fingerprint, "XHTTP 改名改变了原生连接。");
            return new JsonObject { ["tls_defaults"] = true, ["bounded_path"] = true, ["tls_review"] = true,["advanced_h3_packet_review"]=true,["reality_resets_http_version"]=true, ["reality_switch"] = true, ["key_generation"] = true, ["reality_review"] = true, ["upgrade_scope"] = true, ["cancel_no_change"] = true, ["native_editor"] = true, ["rename_preserves_native_connection"] = true };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(100); } if (pending != null) try { await pending.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationException) { }
            plan.Remove("InboundModel"); ArchiveStore.WriteJson(file, plan); var deletion = new InstanceDeletion(store); deletion.Delete(deletion.Review(relative)); credentials.Clear(); payload["Configurations"]!.AsObject().Clear(); selectedInstance = previous; scheme = previousScheme; SelectPage("instances");
        }
    }
}
