#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> AdditionsRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json"))) throw new OperationException("功能界面验证必须在合成工作区运行。");
        void Require(bool value, string reason) { if (!value) throw new OperationException(reason); }
        async Task WaitForState(Func<bool> condition, string reason)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(3);
            while (!condition() && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(25); }
            Require(condition(), reason);
        }
        var instances = store.ListInstances().ToArray(); string? createdDirectory = null;
        if (instances.Length == 0)
        {
            var fixture = DeploymentPlans.Create(new JsonObject { ["Provider"] = "Example", ["Instance"] = "UI Additions", ["IPv4"] = "192.0.2.10", ["RealityTarget"] = "example.com" }, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")), paths, false);
            fixture.Put("Import.Status", JsonValue.Create("Completed"));
            createdDirectory = paths.Instance("Example/UI Additions/MXH-VPS-Deploy");
            ArchiveStore.WriteJson(SafePath.Resolve(createdDirectory, "deployment-plan.json"), fixture);
            ArchiveStore.WriteJson(SafePath.Resolve(createdDirectory, "deployment-state.json"), new JsonObject { ["Engine"] = "dotnet-v1", ["CurrentManagementPort"] = fixture.Number("Ports.SshPrimary") });
        }
        var instance = store.ListInstances().First(); selectedInstance = instance.RelativePath;
        var originalScheme = scheme; var originalStep = designerStep; var originalTheme = settings.Text("Appearance", "Dark");
        try
        {
            var jobFile = NetworkJobFile(paths.Instance(instance.RelativePath));
            var previousJob = File.Exists(jobFile) ? File.ReadAllBytes(jobFile) : null;
            try
            {
                var job = NetworkSchedules.Create(instance.RelativePath, NetworkTuning.Defaults(instance.Plan), "synthetic-unreachable-source", DateTimeOffset.UtcNow);
                job["DueAt"] = DateTimeOffset.UtcNow.AddSeconds(-1).ToString("O"); ArchiveStore.WriteJson(jobFile, job);
                var modal = OperationDialog("审阅期间不启动补测", Text("合成界面回归"), "返回");
                var pending = ShowDialog(modal); await Task.Delay(90);
                await PollNetworkSchedules();
                Require(ArchiveStore.ReadJson(jobFile).Text("Status") == "Waiting" && taskCancellation == null && activeTestDialog == modal, "审阅弹窗期间后台计划启动或篡改了任务状态。");
                modal.Hide(); await pending;
            }
            finally
            {
                activeTestDialog?.Hide();
                if (previousJob == null) File.Delete(jobFile); else ArchiveStore.AtomicWrite(jobFile, previousJob);
            }
            foreach (var theme in new[] { "Dark", "Light" })
            {
                SetAppearance(theme); SelectPage("instances"); await Task.Delay(90);
                Require(Find<Button>(page).Any(b => b.Content as string == "添加协议"), "已有实例缺少追加协议入口。");
                Require(Find<Button>(page).Count(b => (b.Content as string ?? "").StartsWith("安装")) == 3, "监控和访问缺少三个独立安装入口。");
                await Capture(SafePath.Resolve(output, "additions-" + theme.ToLowerInvariant() + ".png"));
                foreach (var component in new[] { "AnyTlsEntry", "KomariController", "Tunnel" })
                {
                    var form = BuildInstallationDialog(instance.Plan, instance.RelativePath, component);
                    var pending = ShowDialog(form.Dialog);
                    try
                    {
                        await Task.Delay(180); shell.UpdateLayout();
                        Require(ComponentInstallations.Selected(form.Options).Single() == component && Find<TextBlock>(form.Dialog).Any(t => t.Text.StartsWith("沿用管理连接")), "安装表单缺少固定实例连接信息。");
                        if (component == "AnyTlsEntry") Require(form.Options.Number("Settings.AnyTlsEntry.AnyTlsPort") == 8443 && !Find<PasswordBox>(form.Dialog).Any(), "追加 AnyTLS 默认端口冲突或把凭据混入表单。");
                        if (component == "Tunnel") Require(Find<TextBlock>(form.Dialog).Any(t => t.Text.Contains("连接成功后") && t.Text.Contains("公开网址现在可以留空")), "Tunnel 安装要求先配置尚不能创建的公开路由。");
                        var frame = Find<Border>(form.Dialog).Where(b => b.ActualWidth >= 250 && b.ActualWidth < shell.ActualWidth - 40 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).First();
                        await Capture(SafePath.Resolve(output, "installation-" + component + "-" + theme.ToLowerInvariant() + ".png"), frame);
                    }
                    finally { form.Dialog.Hide(); await pending; }
                }
                var batchForm = BuildInstallationDialog(instance.Plan, instance.RelativePath, new[] { "ShadowsocksLanding", "KomariController" });
                var batchPending = ShowDialog(batchForm.Dialog);
                try
                {
                    await Task.Delay(160);
                    Require(Find<TextBox>(batchForm.Dialog).Any(box => box.Header as string == "可信入口 IP（逗号分隔）") && Find<TextBox>(batchForm.Dialog).Any(box => box.Header as string == "主控本机 HTTP 端口"), "组合安装表单未包含各组件参数。");
                    await Capture(SafePath.Resolve(output, "batch-installation-" + theme.ToLowerInvariant() + ".png"));
                }
                finally { batchForm.Dialog.Hide(); await batchPending; }
                var request = new OperationRequest(OperationKind.Deploy, instance.RelativePath, new JsonObject { ["Plan"] = instance.Plan.DeepClone() });
                SelectPage("deploy"); ShowExecution(request);
                Require(currentPage == "deploy" && !navigation.Keys.Any(key => key.Contains("progress")), "部署进度变成独立导航页面。");
                await RunBackground("合成部署执行", async token =>
                {
                    var planned = OperationSteps.Create(request, instance.Plan);
                    foreach (var step in planned.Take(3)) ExecutionProgress(new("fixture", step.Id, 0, planned.Count, "示例步骤完成", step.Id, TaskStepState.Completed));
                    ExecutionProgress(new("fixture", planned[3].Id, 3, planned.Count, "正在建立管理连接，等待远端返回。", planned[3].Id, TaskStepState.Running));
                    Require(pageHost.IsEnabled && navigation.Values.All(b => !b.IsEnabled) && executionRows.Values.Count(row => row.State == TaskStepState.Completed) == 3 && executionRows.Values.Count(row => row.State == TaskStepState.Running) == 1 && executionRows.Values.Any(row => row.State == TaskStepState.Waiting), "步骤状态或运行期间滚动不可用。");
                    await Task.Delay(140); shell.UpdateLayout(); await Capture(SafePath.Resolve(output, "execution-" + theme.ToLowerInvariant() + ".png"));
                    var closeBehavior = settings.Text("CloseBehavior", "Exit");
                    try
                    {
                        settings["CloseBehavior"] = "Tray";
                        Mxh.VpsDeploy.Windows.WindowsWindowLifecycle.RequestClose(WinRT.Interop.WindowNative.GetWindowHandle(this));
                        await Task.Delay(130);
                        Require(minimizedToTray && trayIcon != null && !token.IsCancellationRequested, "关闭到托盘取消了执行任务。");
                        RestoreFromTray(false);
                    }
                    finally { settings["CloseBehavior"] = closeBehavior; }
                    ExecutionProgress(new("fixture", planned[3].Id, 3, planned.Count, "示例：连接被拒绝，检查 SSH 端口。", planned[3].Id, TaskStepState.Failed));
                    FinishExecution(new("fixture", OperationKind.Deploy, executionStarted, DateTimeOffset.UtcNow, TaskOutcome.Failed, planned[3].Id, "示例：连接被拒绝，检查 SSH 端口。", InstanceRelativePath: instance.RelativePath));
                    Require(executionRows.Values.Count(row => row.State == TaskStepState.Completed) == 3 && executionRows.Values.Count(row => row.State == TaskStepState.Failed) == 1, "失败把待完成步骤改成完成。");
                });
                RefreshTaskResultPage(); Require(ShowingExecution && Find<Button>(page).Any(b => b.Content as string == "返回实例"), "执行结果未保留。");
                SelectPage("instances");
                var tunnelPlan = instance.Plan.DeepClone().AsObject(); tunnelPlan["Cloudflared"] = new JsonObject { ["PublicUrl"] = "", ["TokenFile"] = "/etc/cloudflared/mxh-token", ["MetricsPort"] = 20241 };
                var tunnelState = new JsonObject(); var guide = TunnelAccessPanel(tunnelPlan, tunnelState); page.Children.Add(guide);
                Require(!Find<Button>(guide).Single(b => b.Content as string == "验证公开访问").IsEnabled && Find<TextBlock>(guide).Any(t => t.Text.Contains("先安装本机")), "没有主控时错误开放公开访问验证。");
                tunnelPlan["KomariController"] = new JsonObject { ["Port"] = 25774, ["Version"] = "1.5.1" }; tunnelState["KomariController"] = new JsonObject { ["Installed"] = true }; page.Children.Remove(guide); guide = TunnelAccessPanel(tunnelPlan, tunnelState); page.Children.Add(guide);
                var publicField = Find<TextBox>(guide).Single(); var publicCheck = Find<Button>(guide).Single(b => b.Content as string == "验证公开访问");
                publicField.Text = "https://monitor.example.com";
                await WaitForState(() => publicCheck.IsEnabled && Find<TextBlock>(guide).Any(t => t.Text == "主机名：monitor.example.com"), "公开网址输入后按钮或主机名没有刷新。");
                Require(Find<TextBlock>(guide).Any(t => t.Text == "服务 URL：http://127.0.0.1:25774"), "公开路由未显示本机服务地址。");
                mainScroll!.ChangeView(null, mainScroll.ScrollableHeight, null, true); await Task.Delay(100);
                await Capture(SafePath.Resolve(output, "tunnel-route-guidance-" + theme.ToLowerInvariant() + ".png"), guide);
                publicField.Text = "http://monitor.example.com"; await WaitForState(() => !publicCheck.IsEnabled, "公开验证接受无 TLS 网址。");
                publicField.Text = "https://another.example.com"; await WaitForState(() => publicCheck.IsEnabled && Find<TextBlock>(guide).Any(t => t.Text == "主机名：another.example.com"), "修正公开网址后仍显示旧输入状态。");
                page.Children.Remove(guide);
                SelectPage("clients"); scheme = ClientSchemes.New(paths); designerStep = 1;
                foreach (var name in new[] { "入口 A", "入口 B", "入口 C" }) scheme["Nodes"]!.AsArray().Add(new JsonObject { ["name"] = name, ["kind"] = "entry", ["region_group"] = "US-West Entry" });
                await NodeReorderRegression(output, theme, Require);
                scheme["Candidate"] = null;
                designerStep = 3; Navigate("clients");
                Require(!((Button)pageAction.Content).IsEnabled && Find<TextBlock>(page).Any(t => t.Tag as string == "ExportPrerequisiteHint" && t.Text.Contains("生成配置")), "未生成时缺少导出指引。");
                scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Failed", ["ValidationError"] = "示例：所选核心未通过配置检查。" }; Navigate("clients");
                Require(Find<TextBlock>(page).Single(t => t.Tag as string == "ExportPrerequisiteHint").Text.Contains("校验未通过"), "未显示校验失败原因。");
                scheme["Candidate"]!["ValidationStatus"] = "Passed"; Navigate("clients");
                var fields = Find<TextBox>(page).Where(box => (box.Header as string ?? "").EndsWith("文件")).ToArray();
                Require(fields.Length == 2 && !((Button)pageAction.Content).IsEnabled, "空导出路径没有被提示。");
                await WaitForState(() => fields.All(box => box.IsLoaded && box.ActualHeight > 0), "导出位置字段未加载。");
                var exportOffset = Math.Clamp(mainScroll!.VerticalOffset + fields[0].TransformToVisual(mainScroll).TransformPoint(new(0, 0)).Y - 24, 0, mainScroll.ScrollableHeight);
                mainScroll.ChangeView(null, exportOffset, null, true);
                await WaitForState(() => Math.Abs(mainScroll.VerticalOffset - exportOffset) < 1 && fields[0].TransformToVisual(mainScroll).TransformPoint(new(0, 0)).Y >= 0 && fields[1].TransformToVisual(mainScroll).TransformPoint(new(0, fields[1].ActualHeight)).Y <= mainScroll.ActualHeight, "两个导出位置字段未进入可视区域。");
                fields[0].Text = "C:\\fixture\\example.yaml"; fields[1].Text = "C:\\fixture\\example.json";
                // TextChanged follows native text rendering asynchronously; a
                // fixed delay does not prove that both field events completed.
                await WaitForState(() => scheme.Text("Targets.Clash") == fields[0].Text && scheme.Text("Targets.SingBox") == fields[1].Text && ((Button)pageAction.Content).IsEnabled, "填写导出位置后字段或按钮未刷新。");
                ArchiveStore.WriteJson(SafePath.Resolve(output, "export-field-state-" + theme.ToLowerInvariant() + ".json"), new JsonObject
                {
                    ["button_enabled"] = ((Button)pageAction.Content).IsEnabled,
                    ["candidate_status"] = scheme.Text("Candidate.ValidationStatus"),
                    ["model_clash"] = scheme.Text("Targets.Clash"), ["model_sing_box"] = scheme.Text("Targets.SingBox"),
                    ["fields"] = new JsonArray(fields.Select(box => (JsonNode?)new JsonObject { ["header"] = box.Header as string, ["text"] = box.Text, ["loaded"] = box.IsLoaded, ["height"] = box.ActualHeight }).ToArray()),
                    ["window_width"] = shell.ActualWidth, ["window_height"] = shell.ActualHeight
                });
                Require(((Button)pageAction.Content).IsEnabled, "填写导出位置后按钮未刷新。");
                await Task.Delay(140); await Capture(SafePath.Resolve(output, "export-guidance-" + theme.ToLowerInvariant() + ".png"));
                scheme = null;
            }
        }
        finally
        {
            scheme = originalScheme; designerStep = originalStep; SetAppearance(originalTheme);
            if (createdDirectory != null) { SafePath.CheckTree(createdDirectory); Directory.Delete(createdDirectory, true); }
            SelectPage("instances");
        }
        return new JsonObject { ["scheduler_waits_for_review"] = true, ["inline_execution"] = true, ["explicit_completion_and_failure"] = true, ["drag_handles_and_scheme_order"] = true, ["drag_preview_cancel_scroll_and_keys"] = true, ["generation_validation_export_guidance"] = true, ["separate_component_installation"] = true, ["themes"] = new JsonArray("Dark", "Light"), ["remote_connections"] = 0 };
    }
}
