using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private IReadOnlyList<JsonObject> AvailableServerRuleSets()
    {
        var saved=new ServerRuleSetStore(store).List().OrderBy(r=>ServerRuleSetStore.Current(r).Text("Name"),StringComparer.Ordinal).SelectMany(r=>new[]{ServerRuleSetStore.Current(r)}.Concat(r["Versions"]!.AsArray().Where(v=>v!.Text("Digest")!=r.Text("Current")).Select(v=>v!["Snapshot"]!.DeepClone().AsObject()))).ToArray();
        return saved.Concat(ServerRuleSets.Builtins(paths).Where(s=>!saved.Any(v=>ServerRuleSets.Digest(v)==ServerRuleSets.Digest(s)))).ToArray();
    }
    private async Task ServerRuleSetLibrary()
    {
        var library=new ServerRuleSetStore(store,new ClientSubscriptionDownload());library.EnsureBuiltins();
        while(true)
        {
            var sets=library.List();var model=new JsonObject{["Id"]=sets.First().Text("Id"),["Action"]="Import"};
            var selected=Choice("分类规则集",model,"Id",sets.Select(r=>(r.Text("Id"),ServerRuleSetStore.Current(r).Text("Name"))));selected.Tag="ServerRuleSets.LibrarySelection";
            var action=Choice("规则库操作",model,"Action",[("Import","导入／更新 JSON"),("Fetch","从配置的来源获取并预览"),("Source","配置 HTTPS 来源"),("Version","选择历史版本作为当前版本")]);action.Tag="ServerRuleSets.LibraryAction";
            var status=Text("",14,true);
            void Refresh(){var set=ServerRuleSetStore.Current(sets.Single(r=>r.Text("Id")==model.Text("Id")));status.Text=set.Text("Name")+" v"+set.Text("Revision")+" · "+set["Rules"]!.AsArray().Count+" 项 · "+ServerRuleSets.Digest(set)[..12];}
            selected.SelectionChanged+=(_,_)=>Refresh();Refresh();
            var dialog=OperationDialog("服务器分类规则库",DialogScroll(Column(selected,action,status,Text("规则库只保存固定版本，不自动改写服务器。导入新版或选择旧版后，仍须在配置出站中选择该快照，审阅并完成实际路径验收。入口机直连不是本机校园网；学校 IP 授权访问应在客户端选择校园网直连。",14,true))),"继续");
            if(await ShowDialog(dialog)!=ContentDialogResult.Primary)return;
            var id=model.Text("Id");var record=library.Read(id);ServerRuleSetPreview? preview=null;
            if(model.Text("Action")=="Import")
            {
                var text=new TextBox{Header="规则集 JSON（公开域名／CIDR 匹配项）",AcceptsReturn=true,MinHeight=220,MaxHeight=340,MaxLength=524288,Text=ServerRuleSetStore.Current(record).ToJsonString(new System.Text.Json.JsonSerializerOptions{WriteIndented=true}),Tag="ServerRuleSets.Json"};
                var error=Text("",14);var form=OperationDialog("导入规则集版本",DialogScroll(Column(text,error)),"预览差异");
                form.PrimaryButtonClick+=(_,e)=>{try{preview=library.Preview(ServerRuleSetStore.Parse(text.Text));}catch(OperationException failure){error.Text=failure.Message;e.Cancel=true;}};
                if(await ShowDialog(form)!=ContentDialogResult.Primary)continue;
            }
            else if(model.Text("Action")=="Fetch")
            {
                if(testSession!=null)throw new OperationException("后台界面测试不获取公网规则集；获取流程由隔离测试验证。");
                await RunBackground("获取规则集快照",async token=>preview=await library.FetchAsync(id,token));
            }
            else if(model.Text("Action")=="Source")
            {
                var definition=(record["Source"] as JsonObject)?.DeepClone().AsObject()??ClientSubscriptions.New("");definition["Name"]=ServerRuleSetStore.Current(record).Text("Name");
                var address=SecretField("HTTPS JSON 地址（加密保存，可含令牌查询串）");address.Password=definition.Text("Url");
                var form=OperationDialog("规则集来源",Column(address,Choice("下载方式",definition,"Network",[("System","跟随系统代理"),("Direct","直连"),("Proxy","指定代理")]),Field("代理（指定代理时使用，无认证）",definition,"Proxy"),Text("只在手动获取时联网，30 秒／512 KiB 上限；获取后仍需差异确认。",14,true)),"保存来源");
                try{if(await ShowDialog(form)==ContentDialogResult.Primary){definition["Url"]=address.Password.Trim();library.ConfigureSource(id,definition,ArchiveStore.Fingerprint(record));}}finally{address.Password="";}continue;
            }
            else
            {
                var version=new JsonObject{["Digest"]=record.Text("Current")};var choice=Choice("保留版本",version,"Digest",record["Versions"]!.AsArray().Select(v=>(v!.Text("Digest"),"v"+v.Text("Snapshot.Revision")+" · "+v.Text("Digest")[..12])));choice.Tag="ServerRuleSets.Version";
                var form=OperationDialog("选择规则库历史版本",Column(choice,Text("只切换私人规则库的当前版本，不自动修改任何已部署快照。要退回服务器策略，在配置出站中选择旧版本并审阅应用。",14,true)),"切换当前版本");
                if(await ShowDialog(form)==ContentDialogResult.Primary)library.SelectVersion(id,version.Text("Digest"),ArchiveStore.Fingerprint(record));continue;
            }
            var snapshot=preview!.Snapshot;var changes=string.Join("\n",preview.Changes.Select(c=>(c.Kind=="Added"?"新增：":"删除：")+c.Name));
            var display=new TextBox{Text=changes==""?"匹配项未变化；核对名称、版本及摘要。":changes,IsReadOnly=true,AcceptsReturn=true,MaxHeight=280};
            var review=OperationDialog("规则集版本差异",DialogScroll(Column(Text(snapshot.Text("Name")+" v"+snapshot.Text("Revision"),18),Text("摘要 "+ServerRuleSets.Digest(snapshot)+"\n"+snapshot["Rules"]!.AsArray().Count+" 个匹配项",14,true),display,Text("确认只更新私人规则库；服务器继续使用原来的固定快照。",14,true))),"确认保存规则集");
            if(await ShowDialog(review)==ContentDialogResult.Primary)library.Apply(preview);
        }
    }
}
