using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> CertificateRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("证书界面回归仅允许合成归档。");
        var assertions = 0;
        void Require(bool ok, string message) { if (!ok) throw new OperationException(message); assertions++; }
        async Task<ContentDialog> Dialog(ContentDialog? previous = null)
        {
            for (var i=0;i<100;i++) { await Task.Delay(30); if(activeTestDialog!=null&&activeTestDialog!=previous) { activeTestDialog.UpdateLayout(); if(Find<Button>(activeTestDialog).Any(b=>b.Name=="PrimaryButton")) {await Task.Delay(100);return activeTestDialog;} } }
            throw new OperationException("未收到证书对话框。");
        }
        TextBox Input(ContentDialog dialog,string name)=>Find<TextBox>(dialog).Single(t=>t.Tag as string=="Certificates."+name);
        async Task Select(ContentDialog dialog,string value)
        {
            var choice=Find<ComboBox>(dialog).Single(c=>c.Tag as string=="Certificates.Action");await RegressionSelect(choice,choice.Items.Cast<ComboBoxItem>().ToList().FindIndex(i=>i.Tag as string==value));await Task.Delay(50);
        }
        var plan=store.ListInstances().First().Plan.DeepClone().AsObject();plan["Instance"]="Certificate33-"+Guid.NewGuid().ToString("N")[..8];plan.Put("Import.Status",JsonValue.Create("Completed"));plan.Remove("InboundModel");
        var relative=plan.Text("Provider")+"/"+plan.Text("Instance")+"/May-VPS-Deploy";var directory=paths.Instance(relative); Directory.CreateDirectory(directory);
        var state=new JsonObject{["SchemaVersion"]=1,["Engine"]="dotnet-v1"};var planFile=SafePath.Resolve(directory,"deployment-plan.json");var stateFile=SafePath.Resolve(directory,"deployment-state.json");var secretsFile=SafePath.Resolve(directory,"secrets.dotnet.private.json");
        ArchiveStore.WriteJson(planFile,plan);ArchiveStore.WriteJson(stateFile,state);store.WriteSecret(secretsFile,new JsonObject());
        var token=SafePath.Resolve(directory,"cf.private.txt");File.WriteAllText(token,new string('x',40)); var previous=selectedInstance;Task? pending=null;
        try
        {
            selectedInstance=relative;var original=File.ReadAllBytes(planFile);var history=new TaskHistory(store).Read().Count;
            pending=CertificatesSheet(relative,plan);var form=await Dialog();Require(Find<TextBlock>(form).Any(t=>t.Text.Contains("关闭 Deploy")),"缺少独立续期和影响说明。");
            await RegressionFill(Input(form,"Name"),"测试托管证书");await RegressionFill(Input(form,"Zone"),"outside.test");await RegressionFill(Input(form,"Email"),"operator@example.test");await RegressionFill(Input(form,"Domains"),"tls.example.test");await RegressionFill(Input(form,"TokenFile"),token);
            await RegressionPress(form,"PrimaryButton");Require(activeTestDialog==form&&Find<TextBlock>(form).Single(t=>t.Tag as string=="Certificates.Error").Text.Contains("区域"),"跨区域域名未阻止审阅。");
            await RegressionFill(Input(form,"Zone"),"example.test");await Capture(SafePath.Resolve(output,"round33-issue.png"),form);await RegressionPress(form,"PrimaryButton");var review=await Dialog(form);
            Require(Find<TextBlock>(review).Any(t=>t.Text.Contains("Cloudflare")&&t.Text.Contains("DNS-01")),"证书审阅缺少申请和恢复范围。");Require(!Find<TextBlock>(review).Any(t=>t.Text.Contains(new string('x',40))),"证书审阅泄露Token。");
            await RegressionPress(review,"CloseButton");await pending;Require(File.ReadAllBytes(planFile).SequenceEqual(original)&&new TaskHistory(store).Read().Count==history,"取消审阅写入了归档或任务。");
            var model=InboundCatalog.Empty();var credentials=InboundCatalog.EmptyCredentials();using var key=RSA.Create(2048);var csr=new CertificateRequest("CN=tls.example.test",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var san=new SubjectAlternativeNameBuilder();san.AddDnsName("tls.example.test");csr.CertificateExtensions.Add(san.Build());using var cert=csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(60));
            var certificate=InboundCatalog.ImportCertificate(model,credentials,"共享证书",cert.ExportCertificatePem(),key.ExportPkcs8PrivateKeyPem());certificate["Managed"]=ManagedCertificates.Policy("example.test","operator@example.test",["tls.example.test"]);
            foreach(var enabled in new[]{true,false}){var inbound=InboundCatalog.AddInbound(model,credentials,"AnyTLS");inbound["CertificateId"]=certificate.Text("Id");inbound["Enabled"]=enabled;inbound["Options"]!["ServerName"]="tls.example.test";inbound["Name"]=enabled?"共享启用入站":"共享停用入站";}
            plan["InboundModel"]=model;ArchiveStore.WriteJson(planFile,plan);store.WriteSecret(secretsFile,new JsonObject{["Inbounds"]=credentials});var after=File.ReadAllBytes(planFile);
            pending=CertificatesSheet(relative,plan,certificate.Text("Id"));form=await Dialog();Require(!Find<TextBox>(form).Any(t=>t.Tag as string=="Certificates.TokenFile"),"检查表单错误要求重新输入授权。");Require(Find<TextBlock>(form).Any(t=>t.Text.Contains("共享启用入站")&&t.Text.Contains("共享停用入站")),"共享依赖没有同时展示停用入站。");
            await Select(form,"Remove");await RegressionPress(form,"PrimaryButton");Require(activeTestDialog==form&&Find<TextBlock>(form).Any(t=>t.Tag as string=="Certificates.Error"&&t.Text.Contains("引用")),"界面允许删除被引用证书。");
            await Select(form,"RotateToken");Require(Find<TextBox>(form).Any(t=>t.Tag as string=="Certificates.TokenFile"),"缺少授权替换入口。");await Capture(SafePath.Resolve(output,"round33-shared.png"),form);await RegressionPress(form,"CloseButton");await pending;
            Require(File.ReadAllBytes(planFile).SequenceEqual(after)&&taskCancellation==null,"取消维护改变了资源或留下任务。");
            return new(){["assertions"]=assertions,["issue_review_cancel"]=true,["no_secret_preview"]=true,["disabled_consumer_protected"]=true,["token_rotation_available"]=true,["no_remote_operations"]=true};
        }
        finally{activeTestDialog?.Hide();selectedInstance=previous;SelectPage("instances");}
    }
}
