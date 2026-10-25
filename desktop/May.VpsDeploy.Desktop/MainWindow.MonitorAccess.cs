using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task MayMonitorAccessDialog()
    {
        var instances = store.ListInstances().Where(i => { var life = InstanceLifecycle.Read(store, i.RelativePath, i.Plan); return life.Managed && !life.NeedsRecovery; }).ToArray();
        var servers = instances.Where(i => MayMonitorAccess.State(store, i.RelativePath).Flag("MayMonitorServer.Installed")).ToArray();
        if (servers.Length == 0) throw new OperationException("先部署并核对一台 May 服务端，再规划独立 HTTPS 网址。旧 Komari 可继续运行。");
        var model = new JsonObject { ["Server"] = servers[0].RelativePath, ["PublicUrl"] = "", ["Action"] = "VerifyHttps" };
        var panel = new StackPanel { Spacing = 14 }; var error = Text("", 13, true); error.Tag = "MayAccess.Validation";
        var server = Choice("May 服务端实例", model, "Server", servers.Select(i => (i.RelativePath, i.Plan.Text("Provider") + " / " + i.Plan.Text("Instance")))); server.Tag = "MayAccess.Server";
        var endpoint = Field("独立的 May HTTPS 网址", model, "PublicUrl"); endpoint.Tag = "MayAccess.Url";
        var action = Choice("检查范围", model, "Action", [("VerifyHttps", "核验 HTTPS 与服务身份"), ("PilotCheck", "单节点试迁移验收")]); action.Tag = "MayAccess.Action";
        var details = new StackPanel { Spacing = 12 }; var nodes = new StackPanel { Spacing = 12 };
        void Render(bool reloadEndpoint = true)
        {
            error.Text = ""; details.Children.Clear(); nodes.Children.Clear();
            var file = MayMonitorAccess.PlanFile(store, model.Text("Server"));
            if (reloadEndpoint)
            {
                if (File.Exists(file)) model["PublicUrl"] = MayMonitorAccess.ReadPlan(store, model.Text("Server")).Text("PublicUrl"); else model["PublicUrl"] = "";
                endpoint.Text = model.Text("PublicUrl");
            }
            details.Children.Add(Text(MayMonitorAccess.EvidenceLabel(store, model.Text("Server")), 13, true));
            var guide = Text("", 13, true); guide.Tag = "MayAccess.Guidance";
            if (File.Exists(file)) guide.Text = MayMonitorAccess.Guidance(MayMonitorAccess.ReadPlan(store, model.Text("Server")));
            var guidePanel = new Expander { Header = "查看本机接入指引", Content = guide, HorizontalAlignment = HorizontalAlignment.Stretch, Tag = "MayAccess.GuidePanel" };
            details.Children.Add(Action("保存计划与生成指引", () =>
            {
                try { var plan = MayMonitorAccess.SavePlan(store, model.Text("Server"), model.Text("PublicUrl")); guide.Text = MayMonitorAccess.Guidance(plan); guidePanel.IsExpanded = true; error.Text = "接入计划已保存到本机；云端路由尚未变更。"; }
                catch (OperationException safe) { error.Text = safe.Message; }
                return Task.CompletedTask;
            }));
            details.Children.Add(guidePanel);
            if (model.Text("Action") == "PilotCheck")
            {
                var candidates = instances.Where(i => MayMonitorAccess.State(store, i.RelativePath).Flag("MayMonitorAgent.Installed")).ToArray();
                var picker = Choice("试用的 May Agent 实例", model, "NodeInstance", candidates.Select(i => (i.RelativePath, i.Plan.Text("Provider") + " / " + i.Plan.Text("Instance")))); picker.Tag = "MayAccess.Node"; nodes.Children.Add(picker);
                if (candidates.Length == 0) nodes.Children.Add(Text("先选择一个节点部署 May Agent，并在只读连接中绑定它的 UUID。", 13, true));
            }
            else model.Remove("NodeInstance");
        }
        server.SelectionChanged += (_, _) => Render(); action.SelectionChanged += (_, _) => Render(false); Render();
        panel.Children.Add(server); panel.Children.Add(endpoint); panel.Children.Add(details); panel.Children.Add(action); panel.Children.Add(nodes);
        panel.Children.Add(Text("检查只读取服务身份与授权指标。试用检查约 6 秒；不会自动停止旧监控、迁移旧数据库或更改 Cloudflare 路由。", 13, true)); panel.Children.Add(error);
        OperationRequest? request = null; var dialog = OperationDialog("May HTTPS 接入与试迁移", panel, "审阅检查");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                var plan = MayMonitorAccess.ReadPlan(store, model.Text("Server"));
                if (MayMonitorAccess.NormalizeUrl(model.Text("PublicUrl")) != plan.Text("PublicUrl")) throw new OperationException("网址已修改，请先保存接入计划。");
                var connection = MonitorArchive.Load() ?? throw new OperationException("先保存专用只读连接和节点绑定。");
                var options = new JsonObject { ["Action"] = model.Text("Action"), ["ConnectionIdentity"] = connection.Identity };
                if (model.Text("Action") == "PilotCheck") options["NodeInstance"] = model.Text("NodeInstance");
                request = new(OperationKind.MayMonitorAccess, model.Text("Server"), options); MayMonitorAccess.Validate(request);
            }
            catch (OperationException safe) { args.Cancel = true; error.Text = safe.Message; }
        };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary || request == null) return;
        await Submit(request);
    }
}
