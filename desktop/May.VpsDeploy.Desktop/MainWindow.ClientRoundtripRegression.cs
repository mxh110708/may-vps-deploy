#nullable enable
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;
public sealed partial class MainWindow
{
    private async Task<JsonObject> ClientRoundtripRegression(string output)
    {
        if(testSession==null||!ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only"))throw new OperationException("往返界面回归只允许在合成后台会话运行。");
        static void Require(bool b,string m){if(!b)throw new OperationException(m);}Task? pending=null;
        async Task<ContentDialog> Dialog(ContentDialog? old=null){var end=DateTimeOffset.UtcNow.AddSeconds(6);while((activeTestDialog==null||activeTestDialog==old||!Find<Button>(activeTestDialog).Any(b=>b.Name=="CloseButton"))&&DateTimeOffset.UtcNow<end){if(pending?.IsFaulted==true)await pending;shell.UpdateLayout();await Task.Delay(30);}if(pending?.IsFaulted==true)await pending;Require(activeTestDialog!=null&&activeTestDialog!=old,"往返回归对话框未建立。");return activeTestDialog!;}
        var previous=scheme;var baseline=schemeBaseline;var step=designerStep;string? copied=null;
        try
        {
            scheme=ClientSchemes.New(paths);designerStep=1;SelectPage("clients");var uuid=Guid.NewGuid().ToString();var links="tuic://"+uuid+":synthetic-tuic-ui@entry.example.test:443?sni=entry.example.test&congestion_control=bbr&udp_relay_mode=quic&alpn=h3#Tuic\nvless://"+uuid+"@entry.example.test:444?security=tls&type=tcp&sni=entry.example.test#TlsVless\ntrojan://synthetic-tls-ui@entry.example.test:445?sni=entry.example.test#TlsTrojan\n";var encoded=Convert.ToBase64String(Encoding.UTF8.GetBytes(links));var before=ArchiveStore.Fingerprint(scheme);
            pending=ImportClientLinks();var form=await Dialog();var input=Find<TextBox>(form).Single(t=>t.Tag as string=="ClientLinks.Input");Require(input.MaxLength==ClientNodeImport.MaximumInputCharacters,"界面仍截断合法 Base64 列表。");await RegressionFill(input,encoded);await RegressionPress(form,"PrimaryButton");var review=await Dialog(form);var text=string.Join('\n',Find<TextBlock>(review).Select(t=>t.Text));Require(text.Contains("可导入 3")&&!text.Contains("synthetic-tuic-ui")&&!text.Contains(uuid)&&input.Text=="","Base64 预览失败、凭据回显或输入未清理。");await Capture(SafePath.Resolve(output,"round27-import-review.png"),review);await RegressionPress(review,"CloseButton");await pending;Require(ArchiveStore.Fingerprint(scheme)==before,"取消导入改写方案。");
            pending=ImportClientLinks();form=await Dialog();await RegressionFill(Find<TextBox>(form).Single(t=>t.Tag as string=="ClientLinks.Input"),encoded);await RegressionPress(form,"PrimaryButton");review=await Dialog(form);await RegressionPress(review,"PrimaryButton");await pending;Require(scheme["Nodes"]!.AsArray().Count==3,"三种连接没有加入方案。");
            var node=scheme["Nodes"]![0]!.AsObject();var connection=ClientNodeImport.ConnectionFingerprint(node);var id=node.Text("Id");pending=EditNode(0);form=await Dialog();Require(Microsoft.UI.Xaml.Automation.AutomationProperties.GetName(form)=="编辑外部 TLS／TUIC 节点","TUIC 仍进入错误的 Reality 编辑表单。");await RegressionFill(Find<TextBox>(form).Single(t=>t.Header as string=="节点名称"),"Renamed-Tuic");await RegressionPress(form,"PrimaryButton");await pending;node=scheme["Nodes"]![0]!.AsObject();Require(node.Text("Id")==id&&node.Text("name")=="Renamed-Tuic"&&ClientNodeImport.ConnectionFingerprint(node)==connection,"编辑改名改变了身份或连接。");
            var unchanged=ArchiveStore.Fingerprint(scheme);pending=ShareClientLinks(scheme,t=>{copied=t;return Task.CompletedTask;},()=>Task.FromResult<string?>(null));form=await Dialog();Require(Find<CheckBox>(form).Count(c=>(c.Tag as string)?.StartsWith("ClientShare.Node.")==true&&c.IsEnabled)==3,"新连接在分享界面仍被禁用。");await RegressionSelect(Find<ComboBox>(form).Single(c=>c.Tag as string=="ClientShare.Format"),1);await RegressionInvoke(Find<Button>(form).Single(b=>b.Tag as string=="ClientShare.Copy"));Require(copied!=null&&ClientNodeImport.Preview(copied,ClientSchemes.New(paths),scheme["Layout"]!.Strings("region_groups")[0],"entry").Accepted==3,"界面生成的 Base64 不能直接往返。");await Capture(SafePath.Resolve(output,"round27-share-review.png"),form);await RegressionPress(form,"CloseButton");await pending;Require(ArchiveStore.Fingerprint(scheme)==unchanged&&taskCancellation==null,"分享改写了方案或启动远端任务。");
            return new(){["encoded_input_limit"]=true,["base64_preview"]=true,["redacted_preview"]=true,["secret_input_cleared"]=true,["cancel_preserved"]=true,["three_protocols_imported"]=true,["correct_editor"]=true,["rename_identity_preserved"]=true,["all_shareable"]=true,["base64_roundtrip"]=true,["copy_receiver_only"]=true,["source_unchanged"]=true};
        }
        finally{activeTestDialog?.Hide();scheme=previous;schemeBaseline=baseline;designerStep=step;SelectPage("clients");}
    }
}
