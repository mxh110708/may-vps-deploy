using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> MonitorAccessRegression(string outputDirectory)
    {
        if(testSession==null || !backgroundTest || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("接入界面回归只允许合成工作区。");
        static void Require(bool value,string message) { if(!value) throw new OperationException(message); }
        static void Invoke(Button button)=>((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke();
        var added=new List<string>(); Task? pending=null; var history=new TaskHistory(store).Read().Count;
        var readFile=paths.Resolve("private/monitor-read.private.json"); var previous=File.Exists(readFile)?File.ReadAllBytes(readFile):null;
        try
        {
            foreach(var name in new[]{"Access-Server","Access-Agent"})
            {
                var relative="Example/"+name+"/May-VPS-Deploy"; var directory=paths.Instance(relative);
                if(Directory.Exists(directory)) throw new OperationException("合成接入实例已经存在。"); added.Add(relative);
                var plan=new JsonObject{["Provider"]="Example",["Instance"]=name,["NodeName"]=name,["Role"]="RealityEntry",["Import"]=new JsonObject{["Status"]="Completed"}};
                var state=new JsonObject{["Engine"]="dotnet-v1"};
                if(name=="Access-Server") { plan["Cloudflared"]=new JsonObject{["PublicUrl"]="https://old.example/"}; state["MayMonitorServer"]=new JsonObject{["Installed"]=true,["Active"]=true,["Hash"]=new string('a',64),["Configuration"]=new JsonObject{["Port"]=25775,["InstanceId"]=Guid.NewGuid().ToString("D")}}; }
                else state["MayMonitorAgent"]=new JsonObject{["Installed"]=true,["Active"]=true,["Hash"]=new string('b',64)};
                ArchiveStore.WriteJson(SafePath.Resolve(directory,"deployment-plan.json"),plan); ArchiveStore.WriteJson(SafePath.Resolve(directory,"deployment-state.json"),state);
            }
            MonitorArchive.Remove(); SelectPage("monitoring"); Require(Find<Button>(shell).Any(b=>b.Content as string=="接入与验收"),"缺少接入入口。");
            pending=MayMonitorAccessDialog();
            for(var i=0;i<100 && activeTestDialog==null;i++) await Task.Delay(30);
            var dialog=activeTestDialog??throw new OperationException("接入表单未打开。");
            dialog.UpdateLayout(); await Task.Delay(150);
            var url=Find<TextBox>(dialog).Single(t=>t.Tag as string=="MayAccess.Url");
            await RegressionPress(dialog,"PrimaryButton"); Require(activeTestDialog==dialog,"缺少计划时进入了执行。");
            await RegressionFill(url,"http://may.example/"); Invoke(Find<Button>(dialog).Single(b=>b.Content as string=="保存计划与生成指引")); await Task.Delay(100);
            var planFile=MayMonitorAccess.PlanFile(store,added[0]); Require(!File.Exists(planFile) && Find<TextBlock>(dialog).Single(t=>t.Tag as string=="MayAccess.Validation").Text.Contains("HTTPS"),"非 HTTPS 接入计划没有被拒绝。");
            var deploymentFile=SafePath.Resolve(paths.Instance(added[0]),"deployment-plan.json");var deploymentBefore=File.ReadAllBytes(deploymentFile);
            await RegressionFill(url,"https://old.example/");Invoke(Find<Button>(dialog).Single(b=>b.Content as string=="保存计划与生成指引"));await Task.Delay(100);
            Require(File.Exists(planFile) && ArchiveStore.ReadJson(planFile).Text("PublicUrl")=="https://old.example/" && File.ReadAllBytes(deploymentFile).SequenceEqual(deploymentBefore) && new TaskHistory(store).Read().Count==history,"保存复用入口计划修改了原部署或启动了远端任务。");
            await RegressionFill(url,"https://may.example/"); Invoke(Find<Button>(dialog).Single(b=>b.Content as string=="保存计划与生成指引")); await Task.Delay(100);
            Require(File.Exists(planFile) && Find<TextBlock>(dialog).Single(t=>t.Tag as string=="MayAccess.Guidance").Text.Contains("http://127.0.0.1:25775"),"未保存本地接入计划或缺少正确服务地址。");
            var saved=File.ReadAllBytes(planFile); await RegressionFill(url,"https://draft.example/");
            var action=Find<ComboBox>(dialog).Single(b=>b.Tag as string=="MayAccess.Action"); action.SelectedItem=action.Items.Cast<ComboBoxItem>().Single(i=>i.Tag as string=="PilotCheck"); await Task.Delay(100);
            Require(url.Text=="https://draft.example/" && Find<ComboBox>(dialog).Single(b=>b.Tag as string=="MayAccess.Node").Items.Count==1,"切换检查范围丢失网址或混入未安装节点。");
            Require((Find<Expander>(dialog).Single(e=>e.Tag as string=="MayAccess.GuidePanel").Content as TextBlock)?.Text.Contains("http://127.0.0.1:25775")==true,"切换检查范围丢失已保存指引。");
            await RegressionFill(url,"https://may.example/"); await RegressionPress(dialog,"PrimaryButton");
            Require(activeTestDialog==dialog && Find<TextBlock>(dialog).Single(t=>t.Tag as string=="MayAccess.Validation").Text.Contains("只读连接"),"缺少专用连接仍开始验收。");
            Require(File.ReadAllBytes(planFile).SequenceEqual(saved),"编辑未保存网址仍改写计划。");
            dialog.UpdateLayout(); await Task.Delay(100); await Capture(SafePath.Resolve(outputDirectory,"may-monitor-access.png"),dialog);
            await RegressionPress(dialog,"CloseButton"); await pending;
            Require(taskCancellation==null && new TaskHistory(store).Read().Count==history,"关闭表单提交了远端任务。");
            return new(){["entry_without_connection"]=true,["missing_plan_blocked"]=true,["non_https_blocked"]=true,["reuse_plan_keeps_existing_deployment"]=true,["local_plan_and_guide"]=true,["scope_change_keeps_edit"]=true,["saved_guide_persists"]=true,["installed_agents_only"]=true,["missing_connection_blocked"]=true,["unsaved_edit_no_write"]=true,["close_no_remote_task"]=true,["production_connections"]=0};
        }
        finally
        {
            if(activeTestDialog!=null){activeTestDialog.Hide();await Task.Delay(100);} if(pending!=null) await pending.WaitAsync(TimeSpan.FromSeconds(3));
            if(previous==null) MonitorArchive.Remove(); else ArchiveStore.AtomicWrite(readFile,previous);
            foreach(var relative in added){var directory=paths.Instance(relative);testSession.RequireLocalPath(directory);SafePath.CheckTree(directory);Directory.Delete(directory,true);} Navigate("overview");
        }
    }
}
