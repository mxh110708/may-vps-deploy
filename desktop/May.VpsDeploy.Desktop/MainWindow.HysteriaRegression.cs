using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> HysteriaRegression(string output)
    {
        if(!File.Exists(paths.Resolve("qa-ui-review.fixture.json"))||!ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only"))throw new OperationException("Hysteria 界面回归只允许合成工作区。");
        static void Require(bool ok,string message){if(!ok)throw new OperationException(message);}
        async Task<ContentDialog> Dialog(ContentDialog? old=null){for(var i=0;i<120;i++){await Task.Delay(25);if(activeTestDialog!=null&&activeTestDialog!=old){activeTestDialog.UpdateLayout();if(Find<Button>(activeTestDialog).Any(b=>b.Name=="PrimaryButton")){await Task.Delay(150);return activeTestDialog;}}}throw new OperationException("未收到 Hysteria 表单。");}
        static TextBox Input(ContentDialog form,string tag)=>Find<TextBox>(form).Single(t=>t.Tag as string=="Inbounds."+tag);
        var previous=selectedInstance;var template=store.ListInstances().First();var plan=template.Plan.DeepClone().AsObject();plan["Provider"]="Example";plan["Instance"]="Round14-"+Guid.NewGuid().ToString("N")[..8];plan.Remove("TcpChain");plan.Put("Import.Status",JsonValue.Create("Completed"));var relative=plan.Text("Provider")+"/"+plan.Text("Instance")+"/May-VPS-Deploy";var directory=paths.Instance(relative);plan.Put("Paths.Archive",JsonValue.Create(directory));
        var model=InboundCatalog.Empty();var credentials=InboundCatalog.EmptyCredentials();var hy=InboundCatalog.AddInbound(model,credentials,"Hysteria2");using var key=RSA.Create(2048);var csr=new CertificateRequest("CN=hysteria.example.test",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var san=new SubjectAlternativeNameBuilder();san.AddDnsName("hysteria.example.test");csr.CertificateExtensions.Add(san.Build());using var cert=csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(2));var resource=InboundCatalog.ImportCertificate(model,credentials,"TLS identity",cert.ExportCertificatePem(),key.ExportPkcs8PrivateKeyPem());hy["CertificateId"]=resource.Text("Id");hy["Options"]!["ServerName"]="hysteria.example.test";plan["InboundModel"]=model.DeepClone();
        var payload=InboundRendering.Payload(store,plan,model,credentials);var state=new JsonObject{["Engine"]="dotnet-v1",["Inbounds"]=new JsonObject{["RemoteHash"]=new string('a',64),["ModelFingerprint"]=ArchiveStore.Fingerprint(model),["Core"]=payload["Core"]!.DeepClone(),["Bindings"]=payload["Bindings"]!.DeepClone(),["Runtime"]=new JsonObject{[hy.Text("Id")]=new JsonObject{["Enabled"]=true,["Active"]=true}}}};
        var file=SafePath.Resolve(directory,"deployment-plan.json");ArchiveStore.WriteJson(file,plan);ArchiveStore.WriteJson(SafePath.Resolve(directory,"deployment-state.json"),state);store.WriteSecret(SafePath.Resolve(directory,"secrets.dotnet.private.json"),new JsonObject{["Inbounds"]=credentials.DeepClone()});var history=new TaskHistory(store).Read().Count;Task? pending=null;
        try
        {
            selectedInstance=relative;pending=InboundsSheet(relative,plan);var form=await Dialog();Require(Input(form,"HysteriaUp").Text=="0"&&Input(form,"HysteriaDown").Text=="0"&&Find<TextBlock>(form).Any(t=>t.Text.Contains("仅监听 UDP")),"缺少 QUIC 说明或默认自适应速率。");Require(Find<ComboBox>(form).Any(c=>c.Tag as string=="Inbounds.Certificate")&&Input(form,"Sni").Text=="hysteria.example.test","证书与 SNI 未接入表单。");
            await RegressionFill(Input(form,"HysteriaUp"),"20");await RegressionPress(form,"PrimaryButton");await Task.Delay(100);Require(activeTestDialog==form&&Find<TextBlock>(form).Single(t=>t.Tag as string=="Inbounds.Error").Text.Contains("同时"),"半填写速率未保留表单报错。");await RegressionFill(Input(form,"HysteriaDown"),"60");Find<CheckBox>(form).Single(t=>t.Tag as string=="Inbounds.HysteriaObfs").IsChecked=true;var secret=Find<PasswordBox>(form).Single(t=>t.Tag as string=="Inbounds.HysteriaObfsPassword").Password;Require(secret.Length>=16,"混淆凭据不是受保护输入。");await Capture(SafePath.Resolve(output,"hysteria-form.png"),form);
            Find<CheckBox>(form).Single(t=>t.Tag as string=="Inbounds.HysteriaHopping").IsChecked=true;
            Require(Input(form,"HysteriaHopInterval").Text=="30"&&Input(form,"HysteriaHopPorts").Text.Contains("22000"),"跳跃默认值未保留主端口或默认间隔。");
            await RegressionFill(Input(form,"HysteriaHopInterval"),"4");await RegressionPress(form,"PrimaryButton");await Task.Delay(100);Require(activeTestDialog==form&&Find<TextBlock>(form).Single(t=>t.Tag as string=="Inbounds.Error").Text.Contains("间隔"),"无效跳跃间隔未保留表单报错。");
            await RegressionFill(Input(form,"HysteriaHopInterval"),"7");await RegressionFill(Input(form,"HysteriaHopPorts"),"24000-24001");await RegressionPress(form,"PrimaryButton");await Task.Delay(100);Require(activeTestDialog==form&&Find<TextBlock>(form).Single(t=>t.Tag as string=="Inbounds.Error").Text.Contains("监听端口"),"跳跃集合遗漏主端口仍可审阅。");
            await RegressionFill(Input(form,"HysteriaHopPorts"),"22000-22002");await Capture(SafePath.Resolve(output,"hysteria-hopping-form.png"),form);
            await RegressionPress(form,"PrimaryButton");var review=await Dialog(form);var text=string.Join("\n",Find<TextBlock>(review).Select(t=>t.Text));Require(text.Contains("UDP/QUIC")&&text.Contains("20 Mbps")&&text.Contains("60 Mbps")&&text.Contains("Salamander 已启用")&&text.Contains("22000-22002")&&text.Contains("7 秒")&&!text.Contains(secret),"审阅遗漏 UDP、速率、跳跃或混淆范围，或泄露秘密。");await Capture(SafePath.Resolve(output,"hysteria-review.png"),review);await RegressionPress(review,"CloseButton");await pending;
            Require(new TaskHistory(store).Read().Count==history&&ArchiveStore.Fingerprint(ArchiveStore.ReadJson(file))==ArchiveStore.Fingerprint(plan),"取消后仍执行或保存 Hysteria 配置。");
            pending=InboundsSheet(relative,plan);form=await Dialog();var action=Find<ComboBox>(form).Single(c=>c.Tag as string=="Inbounds.Action");await RegressionSelect(action,action.Items.Cast<ComboBoxItem>().ToList().FindIndex(c=>c.Tag as string=="UpgradeSingBox"));await RegressionPress(form,"PrimaryButton");await Task.Delay(100);Require(activeTestDialog==form&&Find<TextBlock>(form).Single(t=>t.Tag as string=="Inbounds.Error").Text.Contains("已经使用"),"当前固定核心仍可误启动更新任务。");await RegressionPress(form,"CloseButton");await pending;
            return new JsonObject{["udp_explanation"]=true,["adaptive_defaults"]=true,["certificate_and_sni"]=true,["bandwidth_validation"]=true,["masked_obfs"]=true,["hopping_defaults"]=true,["hopping_validation"]=true,["complete_review"]=true,["no_secret_in_review"]=true,["cancel_no_change"]=true,["pinned_core_update"]=true};
        }
        finally
        {
            if(activeTestDialog!=null){activeTestDialog.Hide();await Task.Delay(100);}if(pending!=null)try{await pending.WaitAsync(TimeSpan.FromSeconds(3));}catch(OperationException){}plan.Remove("InboundModel");ArchiveStore.WriteJson(file,plan);var deletion=new InstanceDeletion(store);deletion.Delete(deletion.Review(relative));credentials.Clear();payload["Configurations"]!.AsObject().Clear();selectedInstance=previous;SelectPage("instances");
        }
    }
}
