#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private sealed class SyntheticCachedSource(string content):IClientSourceFetch
    {
        public Task<string> FetchAsync(JsonObject definition,CancellationToken token){token.ThrowIfCancellationRequested();return Task.FromResult(content);}
    }
    private async Task<JsonObject> SourceSyncRegression(string output)
    {
        if(testSession==null||!ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only"))throw new OperationException("来源同步界面回归仅用于合成后台会话。");
        static void Require(bool value,string message){if(!value)throw new OperationException(message);}
        Task? pending=null;
        async Task<ContentDialog> Dialog(ContentDialog? old=null)
        {
            var until=DateTimeOffset.UtcNow.AddSeconds(6);
            while((activeTestDialog==null||activeTestDialog==old||!Find<Button>(activeTestDialog).Any(b=>b.Name=="CloseButton"))&&DateTimeOffset.UtcNow<until){if(pending?.IsFaulted==true)await pending;shell.UpdateLayout();await Task.Delay(30);}
            if(pending?.IsFaulted==true)await pending;
            Require(activeTestDialog!=null&&activeTestDialog!=old,"来源同步对话框未建立。");shell.UpdateLayout();return activeTestDialog!;
        }
        async Task Select(ContentDialog dialog,string tag,string value)
        {
            var box=Find<ComboBox>(dialog).Single(c=>c.Tag as string==tag);var index=box.Items.Cast<ComboBoxItem>().ToList().FindIndex(i=>i.Tag as string==value);Require(index>=0,"来源同步选项缺失。");await RegressionSelect(box,index);
        }
        var previous=scheme;var baseline=schemeBaseline;var step=designerStep;var items=new List<JsonObject>();JsonObject? group=null;var groups=new ClientNodeGroupStore(store);
        try
        {
            var definition=ClientSubscriptions.New("US-West-LA Entry");definition["Url"]="https://source.example.test/ui?token=synthetic-private-source";definition["Network"]="Direct";
            const string a="anytls://synthetic-ui-source@a.example.test:443?sni=a.example.test#SourceA";
            const string b="anytls://synthetic-ui-other@b.example.test:443?sni=b.example.test#SourceB";
            foreach(var name in new[]{"来源同步方案 A","来源同步方案 B"}){var s=ClientSchemes.New(paths);s["Name"]=name;ClientSubscriptions.Apply(s,ClientSubscriptions.Preview(s,definition,a));workbench.Save(s);items.Add(s);}
            group=ClientNodeGroups.Capture(items[0],"来源同步节点组",items[0]["Nodes"]!.AsArray().Select(n=>n!.Text("Id")).ToArray());groups.Save(group);
            var consumer=ClientSchemes.New(paths);consumer["Name"]="来源同步组引用";ClientNodeGroups.Apply(consumer,group,ClientNodeGroups.Preview(consumer,group));workbench.Save(consumer);items.Add(consumer);
            var service=new ClientSourceSync(store,new SyntheticCachedSource(a.Replace("#SourceA","#SourceRenamed")+"\n"+b));var other=definition.DeepClone().AsObject();other["Url"]="https://other.example.test/ui";service.Register(other);service.Discover();var id=ClientSourceSync.SourceId(definition);await service.FetchAsync(id,default);
            scheme=items[0].DeepClone().AsObject();RememberScheme();designerStep=1;SelectPage("clients");Require(Find<Button>(shell).Any(c=>c.Tag as string=="SourceSync.Center"),"配置设计缺少来源中心入口。");
            var originals=items.ToDictionary(s=>s.Text("Id"),ArchiveStore.Fingerprint);var groupBefore=ClientNodeGroups.Revision(group);
            pending=ClientSourceCenter();var center=await Dialog();await Select(center,"SourceSync.Source",id);await Select(center,"SourceSync.Action","Schedule");await RegressionPress(center,"PrimaryButton");var schedule=await Dialog(center);
            Find<CheckBox>(schedule).Single(c=>c.Tag as string=="SourceSync.Enabled").IsChecked=true;await RegressionFill(Find<TextBox>(schedule).Single(c=>c.Tag as string=="SourceSync.Interval"),"15");await RegressionPress(schedule,"PrimaryButton");center=await Dialog(schedule);Require(service.Read(id).Flag("Schedule.Enabled")&&service.Read(id).Number("Schedule.IntervalMinutes")==15&&!sourceSyncTimer.IsEnabled,"定时策略未保存或测试会话开启了网络计时器。");Require((Find<ComboBox>(center).Single(c=>c.Tag as string=="SourceSync.Source").SelectedItem as ComboBoxItem)?.Tag as string==id,"返回来源中心后丢失所选来源。");await RegressionPress(center,"CloseButton");await pending;
            pending=ClientSourceCenter();center=await Dialog();await Select(center,"SourceSync.Source",id);Require(Find<CheckBox>(center).Count(c=>(c.Tag as string)?.StartsWith("SourceSync.Consumer.",StringComparison.Ordinal)==true)==4,"未列出三方案与节点组联合同步。");await RegressionPress(center,"PrimaryButton");var review=await Dialog(center);var text=string.Join('\n',Find<TextBlock>(review).Select(t=>t.Text));Require(text.Contains("改名")&&text.Contains("新增")&&!text.Contains("synthetic-ui-source")&&!text.Contains("token="),"同步差异未展示增改或泄漏凭据。");await Capture(SafePath.Resolve(output,"source-sync-review.png"),review);await RegressionPress(review,"CloseButton");center=await Dialog(review);await RegressionPress(center,"CloseButton");await pending;
            Require(items.All(s=>ArchiveStore.Fingerprint(workbench.List().Single(x=>x.Text("Id")==s.Text("Id")))==originals[s.Text("Id")])&&ClientNodeGroups.Revision(groups.Read(group.Text("Id")))==groupBefore,"取消联合预览改写了保存对象。");
            var edited=items[1].DeepClone().AsObject();edited["Nodes"]![0]!["sing_box"]!["password"]="synthetic-local-ui-edit";workbench.Save(edited);await new ClientSourceSync(store,new SyntheticCachedSource(a.Replace("synthetic-ui-source","synthetic-upstream-ui-source").Replace("#SourceA","#SourceRenamed")+"\n"+b)).FetchAsync(id,default);
            pending=ClientSourceCenter();center=await Dialog();await Select(center,"SourceSync.Source",id);await RegressionPress(center,"PrimaryButton");review=await Dialog(center);Require(!review.IsPrimaryButtonEnabled&&Find<TextBlock>(review).Any(t=>t.Text.Contains("冲突")),"一个方案的本地冲突没有阻止整批确认。");await RegressionPress(review,"CloseButton");center=await Dialog(review);await RegressionPress(center,"CloseButton");await pending;workbench.Save(items[1]);await service.FetchAsync(id,default);
            pending=ClientSourceCenter();center=await Dialog();await Select(center,"SourceSync.Source",id);await RegressionPress(center,"PrimaryButton");review=await Dialog(center);await RegressionPress(review,"PrimaryButton");await pending;
            var saved=workbench.List().Where(s=>originals.ContainsKey(s.Text("Id"))).ToArray();Require(saved.Length==3&&saved.All(s=>s["Nodes"]!.AsArray().Count==2)&&scheme!["Nodes"]!.AsArray().Count==2&&!SchemeChanged,"批量应用未更新所有方案或当前草稿未刷新。");groups.Verify(saved.Single(s=>s.Text("Id")==consumer.Text("Id")));service.Configure(id,false,60);
            Require(service.Pending().Count==0&&!service.Read(id).Flag("Schedule.Enabled")&&taskCancellation==null,"同步结束留下事务或任务。");
            return new(){["designer_entry"]=true,["schedule_opt_in_saved"]=true,["source_selection_preserved"]=true,["test_timer_disabled"]=true,["three_schemes_plus_group"]=true,["redacted_diff"]=true,["cancel_preserved"]=true,["conflict_blocks_batch"]=true,["batch_applied"]=true,["active_scheme_reloaded"]=true,["no_pending_task"]=true};
        }
        finally
        {
            activeTestDialog?.Hide();foreach(var item in items)workbench.Delete(item);if(group!=null)groups.Delete(group.Text("Id"));scheme=previous;schemeBaseline=baseline;designerStep=step;SelectPage("clients");
        }
    }
    private async Task<JsonObject> ServerRuleSetRegression(string output)
    {
        if(testSession==null||!ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only"))throw new OperationException("规则库界面回归仅用于合成后台会话。");
        static void Require(bool value,string message){if(!value)throw new OperationException(message);}
        Task? pending=null;
        async Task<ContentDialog> Dialog(ContentDialog? old=null)
        {
            var until=DateTimeOffset.UtcNow.AddSeconds(6);
            while((activeTestDialog==null||activeTestDialog==old||!Find<Button>(activeTestDialog).Any(b=>b.Name=="CloseButton"))&&DateTimeOffset.UtcNow<until){if(pending?.IsFaulted==true)await pending;shell.UpdateLayout();await Task.Delay(30);}
            if(pending?.IsFaulted==true)await pending;Require(activeTestDialog!=null&&activeTestDialog!=old,"规则库对话框未建立。");shell.UpdateLayout();return activeTestDialog!;
        }
        async Task Select(ContentDialog dialog,string tag,string value)
        {
            var box=Find<ComboBox>(dialog).Single(c=>c.Tag as string==tag);var index=box.Items.Cast<ComboBoxItem>().ToList().FindIndex(i=>i.Tag as string==value);Require(index>=0,"规则库选项缺失。");await RegressionSelect(box,index);
        }
        var library=new ServerRuleSetStore(store);library.EnsureBuiltins();var set=new JsonObject{["Schema"]=1,["Id"]="ui-rule-fixture",["Name"]="合成学术规则",["Revision"]="1.0.0",["Rules"]=new JsonArray(new JsonObject{["Kind"]="Suffix",["Value"]="papers.example.test"})};library.Apply(library.Preview(set));var id=set.Text("Id");var digest=ServerRuleSets.Digest(set);var v2=set.DeepClone().AsObject();v2["Revision"]="2.0.0";v2["Rules"]!.AsArray().Add(new JsonObject{["Kind"]="Domain",["Value"]="dataset.example.test"});
        try
        {
            pending=ServerRuleSetLibrary();var center=await Dialog();await Select(center,"ServerRuleSets.LibrarySelection",id);await RegressionPress(center,"PrimaryButton");var form=await Dialog(center);var input=Find<TextBox>(form).Single(t=>t.Tag as string=="ServerRuleSets.Json");await RegressionFill(input,"{}");await RegressionPress(form,"PrimaryButton");Require(activeTestDialog==form&&Find<TextBlock>(form).Any(t=>t.Text.Contains("不受支持")),"无效规则集没有保留表单报错。");await RegressionFill(input,v2.ToJsonString());await RegressionPress(form,"PrimaryButton");var review=await Dialog(form);Require(Find<TextBox>(review).Any(t=>t.Text.Contains("dataset.example.test"))&&Find<TextBlock>(review).Any(t=>t.Text.Contains("2.0.0")),"新版规则差异缺失。");await Capture(SafePath.Resolve(output,"server-rule-set-review.png"),review);await RegressionPress(review,"CloseButton");center=await Dialog(review);await RegressionPress(center,"CloseButton");await pending;Require(ServerRuleSetStore.Current(library.Read(id)).Text("Revision")=="1.0.0","取消规则导入写入了规则库。");
            pending=ServerRuleSetLibrary();center=await Dialog();await Select(center,"ServerRuleSets.LibrarySelection",id);await RegressionPress(center,"PrimaryButton");form=await Dialog(center);await RegressionFill(Find<TextBox>(form).Single(t=>t.Tag as string=="ServerRuleSets.Json"),v2.ToJsonString());await RegressionPress(form,"PrimaryButton");review=await Dialog(form);await RegressionPress(review,"PrimaryButton");center=await Dialog(review);await Select(center,"ServerRuleSets.LibrarySelection",id);Require(ServerRuleSetStore.Current(library.Read(id)).Text("Revision")=="2.0.0","确认规则导入没有保存新版本。");await Select(center,"ServerRuleSets.LibraryAction","Version");await RegressionPress(center,"PrimaryButton");form=await Dialog(center);await Select(form,"ServerRuleSets.Version",digest);await RegressionPress(form,"PrimaryButton");center=await Dialog(form);await RegressionPress(center,"CloseButton");await pending;Require(ServerRuleSetStore.Current(library.Read(id)).Text("Revision")=="1.0.0"&&library.Read(id)["Versions"]!.AsArray().Count==2,"历史版本切换没有保留两份快照。");
            var rules=new JsonArray(ServerRuleSets.Rule(set,"Reject"));var inputs=new List<(JsonObject Rule,TextBox Input)>();var editor=OperationDialog("合成分类规则编辑",ServerDestinationEditor(rules,inputs),"检查");pending=ShowDialog(editor);form=await Dialog();await Select(form,"ServerRules.RuleSet.0",ServerRuleSets.Digest(v2));Require(rules[0]!.Text("RuleSet.Revision")=="2.0.0","编辑器选新版仍保留旧快照。");await Select(form,"ServerRules.RuleSet.0",digest);Require(rules[0]!.Text("RuleSet.Revision")=="1.0.0","编辑器不能切回旧快照。");await RegressionFill(Find<TextBox>(form).Single(t=>t.Tag as string=="ServerRules.TestDestination"),"x.papers.example.test");var test=Find<Button>(form).Single(b=>b.Tag as string=="ServerRules.Test");await RegressionInvoke(test);Require(Find<TextBlock>(form).Any(t=>t.Text.Contains("阻断")),"版本分类试算未应用规则动作。");await RegressionPress(form,"CloseButton");await pending;
            return new(){["invalid_json_keeps_form"]=true,["version_diff"]=true,["cancel_import_preserved"]=true,["confirmed_import"]=true,["history_preserved"]=true,["old_version_selected"]=true,["editor_pins_version"]=true,["classification_match_preview"]=true,["no_remote_task"]=taskCancellation==null};
        }
        finally{activeTestDialog?.Hide();}
    }
}
