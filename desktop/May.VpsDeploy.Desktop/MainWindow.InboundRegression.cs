using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> InboundRegression(string output)
    {
        if(!File.Exists(paths.Resolve("qa-ui-review.fixture.json"))||!ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only"))throw new OperationException("入站界面回归只允许合成归档。");
        static void Require(bool ok,string message){if(!ok)throw new OperationException(message);}
        async Task<ContentDialog> Dialog(ContentDialog? old=null){for(var i=0;i<120;i++){await Task.Delay(25);if(activeTestDialog!=null&&activeTestDialog!=old){activeTestDialog.UpdateLayout();if(Find<Button>(activeTestDialog).Any(b=>b.Name=="PrimaryButton")){await Task.Delay(150);return activeTestDialog;}}}throw new OperationException("未收到独立入站界面。");}
        static ComboBox Pick(ContentDialog form,string tag)=>Find<ComboBox>(form).Single(b=>b.Tag as string=="Inbounds."+tag);
        static TextBox Input(ContentDialog form,string tag)=>Find<TextBox>(form).Single(t=>t.Tag as string=="Inbounds."+tag);
        async Task Select(ContentDialog form,string tag,string value){var box=Pick(form,tag);var index=box.Items.Cast<ComboBoxItem>().ToList().FindIndex(i=>i.Tag as string==value);Require(index>=0,"资源选项丢失："+tag);await RegressionSelect(box,index);await Task.Delay(50);}
        Task Invoke(ContentDialog form,string tag)=>RegressionInvoke(Find<Button>(form).Single(b=>b.Tag as string=="Inbounds."+tag));
        var previous=selectedInstance;var oldScheme=scheme;var oldSize=AppWindow.Size;var template=store.ListInstances().First();var plan=template.Plan.DeepClone().AsObject();plan["Provider"]="Example";plan["Instance"]="Round13-"+Guid.NewGuid().ToString("N")[..8];plan.Remove("TcpChain");plan.Remove("InboundModel");plan.Put("Import.Status",JsonValue.Create("Completed"));
        var relative=plan.Text("Provider")+"/"+plan.Text("Instance")+"/May-VPS-Deploy";var directory=paths.Instance(relative);plan.Put("Paths.Archive",JsonValue.Create(directory));var model=InboundCatalog.Empty();var credentials=InboundCatalog.EmptyCredentials();var a=InboundCatalog.AddInbound(model,credentials,"Shadowsocks2022");var b=InboundCatalog.AddInbound(model,credentials,"Shadowsocks2022");a["Name"]="入站 A";b["Name"]="入站 B";b["UserIds"]=a["UserIds"]!.DeepClone();plan["InboundModel"]=model.DeepClone();
        var payload=InboundRendering.Payload(store,plan,model,credentials);var evidence=new JsonObject();foreach(var n in InboundRendering.Nodes(store,relative,plan,model,credentials)){var id=n.Text("InboundOrigin.InboundId");evidence[id]=new JsonObject{["Status"]="Passed",["Items"]=new JsonArray(new JsonObject{["UserId"]=n.Text("InboundOrigin.UserId"),["Family"]=n.Text("InboundOrigin.Family"),["ConnectionFingerprint"]=ClientNodeImport.ConnectionFingerprint(n),["Status"]="Passed"})};}
        var runtime=new JsonObject();foreach(var i in InboundCatalog.Items(model,"Inbounds"))runtime[i.Text("Id")]=new JsonObject{["Enabled"]=true,["Active"]=true};
        var state=new JsonObject{["Engine"]="dotnet-v1",["Inbounds"]=new JsonObject{["RemoteHash"]=new string('a',64),["ModelFingerprint"]=ArchiveStore.Fingerprint(model),["Core"]=payload["Core"]!.DeepClone(),["Bindings"]=payload["Bindings"]!.DeepClone(),["Runtime"]=runtime,["ValidationById"]=evidence}};
        var planFile=SafePath.Resolve(directory,"deployment-plan.json");ArchiveStore.WriteJson(planFile,plan);ArchiveStore.WriteJson(SafePath.Resolve(directory,"deployment-state.json"),state);store.WriteSecret(SafePath.Resolve(directory,"secrets.dotnet.private.json"),new JsonObject{["Inbounds"]=credentials.DeepClone()});var history=new TaskHistory(store).Read().Count;Task? pending=null;
        try
        {
            var scale=shell.XamlRoot?.RasterizationScale??1;AppWindow.Resize(new((int)(1000*scale),(int)(720*scale)));selectedInstance=relative;SelectPage("instances");Require(Find<Button>(shell).Any(x=>x.Content as string=="管理入站"),"实例页没有管理入站入口。");
            pending=InboundsSheet(relative,plan);var form=await Dialog();Require(Input(form,"Port").Text==a.Number("Listener.Port").ToString()&&Pick(form,"Resource").Items.Count==2,"多入站身份未分别展示。");
            await RegressionFill(Input(form,"Name"),"草稿入站 A");await Select(form,"Resource",b.Text("Id"));await RegressionFill(Input(form,"Port"),a.Number("Listener.Port").ToString());await RegressionPress(form,"PrimaryButton");await Task.Delay(100);Require(activeTestDialog==form&&Find<TextBlock>(form).Single(t=>t.Tag as string=="Inbounds.Error").Text.Contains("端口"),"重复监听端口未保留表单报错。");await RegressionFill(Input(form,"Port"),b.Number("Listener.Port").ToString());
            await Select(form,"Group","Users");await Select(form,"Resource",a.Strings("UserIds")[0]);Require(Find<TextBlock>(form).Any(t=>t.Text.Contains("草稿入站 A")&&t.Text.Contains("入站 B")),"共享用户未显示所有引用入站。");await Invoke(form,"Remove");Require(Find<TextBlock>(form).Single(t=>t.Tag as string=="Inbounds.Error").Text.Contains("引用"),"仍被引用的用户可直接删除。");await Invoke(form,"RotateUser");var secret=Find<PasswordBox>(form).Single(p=>p.Tag as string=="Inbounds.UserCredential").Password;Require(secret.Length>10,"轮换凭据没有更新受保护输入框。");
            await Select(form,"Group","Outbounds");await Invoke(form,"Remove");Require(Find<TextBlock>(form).Single(t=>t.Tag as string=="Inbounds.Error").Text.Contains("引用"),"仍被引用的出站可直接删除。");
            await Select(form,"Group","Certificates");Require(Input(form,"ImportCertificate").AcceptsReturn&&Find<PasswordBox>(form).Any(p=>p.Tag as string=="Inbounds.ImportKey"),"证书链或受保护私钥输入缺失。");await Invoke(form,"AddCertificate");Require(Find<TextBlock>(form).Single(t=>t.Tag as string=="Inbounds.Error").Text.Length>0,"无效证书未在表单中拦截。");
            await Select(form,"Group","Inbounds");await Select(form,"Resource",a.Text("Id"));Require(Input(form,"Name").Text=="草稿入站 A","跨类别查看丢失入站草稿。");await Capture(SafePath.Resolve(output,"inbounds-form.png"),form);
            await RegressionPress(form,"PrimaryButton");var review=await Dialog(form);var text=string.Join("\n",Find<TextBlock>(review).Select(t=>t.Text));Require(text.Contains("草稿入站 A")&&text.Contains("入站 B")&&text.Contains("本次影响")&&!text.Contains(secret),"审阅遗漏共享影响或泄露凭据。");await Capture(SafePath.Resolve(output,"inbounds-review.png"),review);await RegressionPress(review,"CloseButton");await pending;
            Require(new TaskHistory(store).Read().Count==history&&ArchiveStore.Fingerprint(ArchiveStore.ReadJson(planFile))==ArchiveStore.Fingerprint(plan),"取消审阅仍保存模型或创建远端任务。");
            pending=InboundsSheet(relative,plan);form=await Dialog();await Select(form,"Action","Check");Require(!Find<Button>(form).Any(x=>x.Tag as string=="Inbounds.Add"),"只读检查仍显示可编辑草稿。");await RegressionPress(form,"PrimaryButton");review=await Dialog(form);Require(Find<TextBlock>(review).Any(t=>t.Text.Contains("只读检查")),"只读审阅类型不正确。");await RegressionPress(review,"CloseButton");await pending;
            scheme=ClientSchemes.New(paths);pending=AddInboundClientNodes();form=await Dialog();var boxes=Find<CheckBox>(form).Where(b=>b.Tag as string=="ClientInbounds.Choice"&&b.IsEnabled).ToArray();Require(boxes.Length==2,"已验收的独立入站未进入客户端选择器。");boxes[0].IsChecked=true;await RegressionPress(form,"PrimaryButton");await pending;Require(scheme["Nodes"]!.AsArray().Count==1&&scheme["Nodes"]![0]!["InboundOrigin"]!=null,"客户端添加丢失稳定来源。");
            var operation=new OperationRequest(OperationKind.Inbounds,relative,InboundCatalog.Options(state,"Apply",model,credentials));ShowExecution(operation);Require(executionRows.Count==5&&heading.Text.Contains("入站"),"入站执行阶段未完整展示。");await Capture(SafePath.Resolve(output,"inbounds-progress.png"),page);
            Require(new TaskHistory(store).Read().Count==history&&taskCancellation==null,"界面回归触发了远端操作。");
            return new JsonObject{["entry"]=true,["stable_selection"]=true,["listener_collision"]=true,["shared_user_references"]=true,["referenced_delete_blocked"]=true,["masked_credentials"]=true,["outbound_delete_blocked"]=true,["certificate_input"]=true,["invalid_certificate"]=true,["draft_preserved"]=true,["affected_scope_review"]=true,["no_secret_in_review"]=true,["cancel_no_task"]=true,["read_only_check"]=true,["client_source_chooser"]=true,["client_origin_preserved"]=true,["five_stages"]=true};
        }
        finally
        {
            if(activeTestDialog!=null){activeTestDialog.Hide();await Task.Delay(100);}if(pending!=null)try{await pending.WaitAsync(TimeSpan.FromSeconds(3));}catch(OperationException){}
            plan.Remove("InboundModel");ArchiveStore.WriteJson(planFile,plan);var deletion=new InstanceDeletion(store);deletion.Delete(deletion.Review(relative));credentials.Clear();payload["Configurations"]!.AsObject().Clear();ClearExecution();scheme=oldScheme;selectedInstance=previous;AppWindow.Resize(oldSize);SelectPage("instances");
        }
    }
}
