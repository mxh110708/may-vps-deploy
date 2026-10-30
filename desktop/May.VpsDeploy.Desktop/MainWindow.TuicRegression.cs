using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> TuicRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("TUIC 界面回归只允许合成工作区。");
        static void Require(bool ok, string message) { if (!ok) throw new OperationException(message); }
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            for (var i = 0; i < 120; i++) { await Task.Delay(25); if (activeTestDialog != null && activeTestDialog != old) { activeTestDialog.UpdateLayout(); if (Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) { await Task.Delay(150); return activeTestDialog; } } }
            throw new OperationException("未收到 TUIC 表单。");
        }
        static TextBox Input(ContentDialog form, string tag) => Find<TextBox>(form).Single(t => t.Tag as string == "Inbounds." + tag);
        var previous = selectedInstance; var plan = store.ListInstances().First().Plan.DeepClone().AsObject(); plan["Provider"] = "Example"; plan["Instance"] = "Round16-" + Guid.NewGuid().ToString("N")[..8]; plan.Remove("TcpChain"); plan.Put("Import.Status", JsonValue.Create("Completed")); var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative); plan.Put("Paths.Archive", JsonValue.Create(directory));
        var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials(); var tuic = InboundCatalog.AddInbound(model, credentials, "TuicV5"); using var key = RSA.Create(2048); var csr = new CertificateRequest("CN=tuic.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("tuic.example.test"); csr.CertificateExtensions.Add(san.Build()); using var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2)); var resource = InboundCatalog.ImportCertificate(model, credentials, "TLS identity", cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()); tuic["CertificateId"] = resource.Text("Id"); tuic["Options"]!["ServerName"] = "tuic.example.test"; plan["InboundModel"] = model.DeepClone();
        var payload = InboundRendering.Payload(store, plan, model, credentials); var state = new JsonObject { ["Engine"] = "dotnet-v1", ["Inbounds"] = new JsonObject { ["RemoteHash"] = new string('a', 64), ["ModelFingerprint"] = ArchiveStore.Fingerprint(model), ["Core"] = payload["Core"]!.DeepClone(), ["Bindings"] = payload["Bindings"]!.DeepClone(), ["Runtime"] = new JsonObject { [tuic.Text("Id")] = new JsonObject { ["Enabled"] = true, ["Active"] = true } } } };
        var file = SafePath.Resolve(directory, "deployment-plan.json"); ArchiveStore.WriteJson(file, plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), new JsonObject { ["Inbounds"] = credentials.DeepClone() }); var history = new TaskHistory(store).Read().Count; Task? pending = null;
        try
        {
            selectedInstance = relative; pending = InboundsSheet(relative, plan); var form = await Dialog();
            Require(Input(form, "TuicHeartbeat").Text == "10" && Input(form, "TuicAuthTimeout").Text == "3" && Find<TextBlock>(form).Any(t => t.Text.Contains("0-RTT 固定关闭")), "TUIC 默认心跳、鉴权等待或 0-RTT 说明缺失。");
            await RegressionFill(Input(form, "TuicHeartbeat"), "4"); await RegressionPress(form, "PrimaryButton"); await Task.Delay(100); Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "Inbounds.Error").Text.Contains("心跳"), "无效 TUIC 心跳仍可进入执行。"); await RegressionFill(Input(form, "TuicHeartbeat"), "10");
            await RegressionFill(Input(form, "TuicAuthTimeout"), "31"); await RegressionPress(form, "PrimaryButton"); await Task.Delay(100); Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "Inbounds.Error").Text.Contains("鉴权"), "无效 TUIC 鉴权等待仍可进入执行。"); await RegressionFill(Input(form, "TuicAuthTimeout"), "3");
            await RegressionSelect(Find<ComboBox>(form).Single(c => c.Tag as string == "Inbounds.TuicRelay"), 1);
            await Capture(SafePath.Resolve(output, "tuic-form.png"), form);
            await RegressionPress(form, "PrimaryButton"); var review = await Dialog(form); var text = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text)); var password = credentials.Text("Users." + tuic.Strings("UserIds")[0] + ".Value");
            Require(text.Contains("TUIC v5") && text.Contains("UDP quic") && text.Contains("UUID + 密码") && text.Contains("0-RTT 关闭") && !text.Contains(password), "TUIC 审阅遗漏协议参数或暴露密码。"); await Capture(SafePath.Resolve(output, "tuic-review.png"), review); await RegressionPress(review, "CloseButton"); await pending;
            Require(new TaskHistory(store).Read().Count == history && ArchiveStore.Fingerprint(ArchiveStore.ReadJson(file)) == ArchiveStore.Fingerprint(plan), "TUIC 取消后仍保存或执行。");
            pending = InboundsSheet(relative, plan); form = await Dialog(); var category = Find<ComboBox>(form).Single(c => c.Tag as string == "Inbounds.Group"); await RegressionSelect(category, 1);
            Require(Guid.TryParseExact(Input(form, "TuicUuid").Text, "D", out _) && Find<PasswordBox>(form).Any(p => p.Tag as string == "Inbounds.UserCredential"), "TUIC UUID 和受保护密码字段未分别接通。");
            await RegressionFill(Input(form, "TuicUuid"), "invalid"); await RegressionPress(form, "PrimaryButton"); await Task.Delay(100); Require(activeTestDialog == form && Find<TextBlock>(form).Single(t => t.Tag as string == "Inbounds.Error").Text.Contains("UUID"), "无效 TUIC 用户身份仍可保存。"); await RegressionPress(form, "CloseButton"); await pending;
            return new JsonObject { ["defaults"] = true, ["bounded_fields"] = true, ["relay_projection"] = true, ["uuid_password_fields"] = true, ["invalid_uuid"] = true, ["review_masks_secrets"] = true, ["cancel_no_change"] = true };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(100); } if (pending != null) try { await pending.WaitAsync(TimeSpan.FromSeconds(3)); } catch (OperationException) { }
            plan.Remove("InboundModel"); ArchiveStore.WriteJson(file, plan); var deletion = new InstanceDeletion(store); deletion.Delete(deletion.Review(relative)); credentials.Clear(); payload["Configurations"]!.AsObject().Clear(); selectedInstance = previous; SelectPage("instances");
        }
    }
}
