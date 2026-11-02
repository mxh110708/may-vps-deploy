using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private readonly DispatcherTimer sourceSyncTimer=new(){Interval=TimeSpan.FromMinutes(1)};
    private readonly CancellationTokenSource sourceSyncStop=new();
    private bool sourceSyncBusy;
    private void InitializeSourceSync()
    {
        sourceSyncTimer.Tick+=async(_,_)=>await RefreshDueSources();
        if(testSession!=null||launchArguments.Any(a=>a is "--ui-smoke" or "--verify-runtime" or "--verify-installed-update"))return;
        try{if(new ClientSourceSync(store).HasSchedules())sourceSyncTimer.Start();}catch(Exception){Show("来源定时策略需要核对，请打开来源中心。",InfoBarSeverity.Warning);}
    }
    private async Task RefreshDueSources()
    {
        if(sourceSyncBusy||closing||taskCancellation!=null||testSession!=null)return;
        sourceSyncBusy=true;
        try
        {
            var service=new ClientSourceSync(store,new ClientSubscriptionDownload());
            if(!service.HasSchedules()){sourceSyncTimer.Stop();return;}
            var count=await Task.Run(()=>service.FetchDueAsync(DateTimeOffset.UtcNow,sourceSyncStop.Token));
            if(count>0&&!closing)Show(count+" 个订阅来源有新缓存，请在来源中心查看差异；方案尚未修改。",InfoBarSeverity.Informational);
        }
        catch(OperationCanceledException){}
        catch(Exception){if(!closing)Show("来源定时检查未完成，旧方案保留；详情请在来源中心查看。",InfoBarSeverity.Warning);}
        finally{sourceSyncBusy=false;}
    }
    private void StopSourceSync(){sourceSyncTimer.Stop();sourceSyncStop.Cancel();}

    private async Task ClientSourceCenter()
    {
        if(SchemeChanged)throw new OperationException("请先保存当前方案草稿，再进行跨方案来源同步。");
        var service=new ClientSourceSync(store,new ClientSubscriptionDownload());service.Discover();var currentSource="";
        while(true)
        {
            var sources=service.Sources();var pending=service.Pending();
            if(sources.Count==0&&pending.Count==0)throw new OperationException("尚无已保存的订阅来源；先保存含有订阅的方案或节点组。");
            var model=new JsonObject{["Source"]=sources.Any(s=>s.Text("Id")==currentSource)?currentSource:sources.FirstOrDefault()?.Text("Id")??"",["Action"]=pending.Count>0?"Recover":"Preview"};
            var sourceChoice=Choice("订阅来源",model,"Source",sources.Select(s=>(s.Text("Id"),ClientSubscriptions.Label(s["Definition"]!.AsObject()))));sourceChoice.Tag="SourceSync.Source";
            var actions=new List<(string,string)>{("Preview","批量差异预览与同步"),("Fetch","立即获取（仅更新缓存）"),("Schedule","配置定时拉取")};if(pending.Count>0)actions.Add(("Recover","恢复未完成的批量同步"));
            var operation=Choice("操作",model,"Action",actions);operation.Tag="SourceSync.Action";
            var details=new StackPanel{Spacing=10};var chosenSchemes=new HashSet<string>();var chosenGroups=new HashSet<string>();
            void Refresh()
            {
                details.Children.Clear();chosenSchemes.Clear();chosenGroups.Clear();
                if(model.Text("Action")=="Recover"){details.Children.Add(Text("将核对并恢复最早的未完成本地批量事务；发现其他修改时保留材料，不覆盖新数据。",14));return;}
                var source=sources.SingleOrDefault(s=>s.Text("Id")==model.Text("Source"));if(source==null)return;
                details.Children.Add(Text("缓存状态："+source.Text("LastStatus","未获取")+" · 上次成功 "+LocalTime(source.Text("LastFetchedAt"))+"\n"+(source.Flag("Schedule.Enabled")?"定时 "+source.Number("Schedule.IntervalMinutes")+" 分钟":"定时未开启")+"\n"+source.Text("LastError"),14,true));
                var consumers=service.Consumers(source.Text("Id"));var groups=consumers.Where(c=>c.Kind=="Group").Select(c=>c.Id).ToHashSet(StringComparer.Ordinal);
                var saved=workbench.List().ToArray();var schemes=consumers.Where(c=>c.Kind=="Scheme").Select(c=>c.Id).Concat(saved.Where(s=>(s["GroupReferences"] as JsonArray??[]).Any(r=>groups.Contains(r!.Text("Id")))).Select(s=>s.Text("Id"))).Distinct().ToArray();
                foreach(var consumer in consumers.Where(c=>c.Kind=="Group").Concat(schemes.Select(id=>(Kind:"Scheme",Id:id,Name:saved.Single(s=>s.Text("Id")==id).Text("Name")))))
                {
                    var selected=consumer.Kind=="Group"?chosenGroups:chosenSchemes;selected.Add(consumer.Id);
                    var check=new CheckBox{Content=(consumer.Kind=="Group"?"节点组 · ":"方案 · ")+consumer.Name,IsChecked=true,Tag="SourceSync.Consumer."+consumer.Kind+"."+consumer.Id};
                    check.Checked+=(_,_)=>selected.Add(consumer.Id);check.Unchecked+=(_,_)=>selected.Remove(consumer.Id);details.Children.Add(check);
                }
                details.Children.Add(Text("定时仅在 Deploy 运行时获取缓存，不自动修改方案或服务器。批量同步先逐方案显示新增、删除、改名、参数与本地冲突；任一冲突阻止整批应用。",14,true));
            }
            sourceChoice.SelectionChanged+=(_,_)=>Refresh();operation.SelectionChanged+=(_,_)=>Refresh();Refresh();
            var dialog=OperationDialog("来源中心",DialogScroll(Column(sourceChoice,operation,details)),"继续");
            if(await ShowDialog(dialog)!=ContentDialogResult.Primary)return;
            var id=model.Text("Source");currentSource=id;
            if(model.Text("Action")=="Recover")
            {
                if(pending.Count==0)throw new OperationException("没有待恢复同步。");
                await RunBackground("恢复本地来源同步",token=>Task.Run(()=>{token.ThrowIfCancellationRequested();service.Recover(pending[0]);},token));ReloadSyncedScheme();continue;
            }
            if(model.Text("Action")=="Fetch")
            {
                if(testSession!=null)throw new OperationException("后台界面测试不获取公网来源；下载通过本机隔离回归验证。");
                await RunBackground("获取来源缓存",async token=>{await service.FetchAsync(id,token);});continue;
            }
            if(model.Text("Action")=="Schedule")
            {
                var source=service.Read(id);var schedule=source["Schedule"]!.DeepClone().AsObject();var interval=Field("刷新间隔（分钟，15–1440）",schedule,"IntervalMinutes",numeric:true);interval.Tag="SourceSync.Interval";
                var enabled=Flag("启用定时拉取",schedule,"Enabled");enabled.Tag="SourceSync.Enabled";
                var form=OperationDialog("来源定时策略",Column(enabled,interval,Text("仅在 Deploy 运行时拉取；关闭应用会取消下载。定时任务不会替你确认差异、改写方案或修改远端。",14,true)),"保存策略");
                if(await ShowDialog(form)==ContentDialogResult.Primary){if(!int.TryParse(interval.Text,out var minutes))throw new OperationException("刷新间隔须为 15–1440 的整数分钟。");service.Configure(id,schedule.Flag("Enabled"),minutes);if(testSession==null&&service.HasSchedules())sourceSyncTimer.Start();}
                continue;
            }
            var preview=service.Preview(id,chosenSchemes.ToArray(),chosenGroups.ToArray());
            var rows=Column(Text("整批只更新选中的加密方案／节点组；现有输出会失效，须重新生成和校验。源 URL 和鉴权不展示。",14,true));
            foreach(var item in preview.Items)
            {
                rows.Children.Add(Text((item.Kind=="Group"?"节点组：":"方案：")+item.Name,17));
                foreach(var change in item.Changes)rows.Children.Add(Text((change.Kind switch{"Added"=>"新增","Removed"=>"删除","Changed"=>"参数变化","Renamed"=>"改名","Conflict"=>"冲突","Existing"=>"已有其他来源连接","Impact"=>"引用影响",_=>"保留"})+" · "+change.Name+"\n"+change.Detail,13,change.Kind=="Unchanged"));
                foreach(var error in item.Errors)rows.Children.Add(Text("冲突："+error,14));
            }
            if(preview.OtherGroupConsumers>0)rows.Children.Add(Text("还有 "+preview.OtherGroupConsumers+" 个未选方案引用这些节点组；组更新后它们须另行同步才能导出。",14));
            var review=OperationDialog("跨方案来源差异",DialogScroll(rows),"确认批量同步");review.IsPrimaryButtonEnabled=preview.Ready;
            if(await ShowDialog(review)!=ContentDialogResult.Primary)continue;
            await RunBackground("应用本地来源同步",token=>Task.Run(()=>service.Apply(preview,token),token));ReloadSyncedScheme();Show("来源批量同步完成；请重新生成并校验客户端输出。",InfoBarSeverity.Success);return;
        }
    }
    private void ReloadSyncedScheme()
    {
        if(scheme!=null){var id=scheme.Text("Id");scheme=workbench.List().SingleOrDefault(s=>s.Text("Id")==id);RememberScheme();}
        Navigate("clients");
    }
}
