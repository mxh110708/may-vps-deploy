using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> DeploymentRegression(string output)
    {
        if (!launchArguments.Contains("--app-root") || !File.Exists(paths.Resolve("qa-ui-review.fixture.json"))) throw new OperationException("部署界面回归需要隔离工作区。");
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        TextBox Input(string label) => Find<TextBox>(shell).Single(box => box.Header as string == label);
        async Task Shot(string name) { shell.UpdateLayout(); await Task.Delay(120); await Capture(SafePath.Resolve(output, name + ".png")); }
        async Task DialogShot(string name, ContentDialog dialog, Func<ContentDialog, Task>? inspect = null)
        {
            var pending = ShowDialog(dialog); await Task.Delay(120); shell.UpdateLayout(); if (inspect != null) await inspect(dialog);
            try
            {
                var frame = Find<Border>(dialog).Where(b => b.ActualWidth >= 250 && b.ActualWidth < shell.ActualWidth - 40 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).First();
                await Capture(SafePath.Resolve(output, name + ".png"), frame);
                if (name == "dialog-deployment-review")
                {
                    var scroll = (ScrollViewer)dialog.Content; scroll.ChangeView(null, scroll.ScrollableHeight, null, true); await Task.Delay(120);
                    await Capture(SafePath.Resolve(output, name + "-details.png"), frame);
                }
            }
            finally { dialog.Hide(); await pending; }
        }
        deploymentForm.Clear(); SelectPage("deploy"); await Task.Delay(80); Input("服务商").Text = "示例服务商"; await Task.Delay(80); Input("实例名称").Text = "Test Node"; await Task.Delay(80);
        Require(Input("节点名称").Text == "示例服务商-Test-Node", "默认节点名未随输入生成。");
        Input("节点名称").Text = "我的自定义节点"; await Task.Delay(80); Input("服务商").Text = "另一个服务商"; await Task.Delay(80);
        Require(Input("节点名称").Text == "我的自定义节点", "自定义节点名被覆盖。");
        Require(!Find<TextBox>(shell).Any(b => b.Header as string == "Komari 主控地址"), "未选择监控仍显示主控字段。");
        Find<CheckBox>(shell).Single(b => b.Content as string == "Komari 监控 Agent").IsChecked = true;
        await Task.Delay(80);
        Require(Find<TextBox>(shell).Any(b => b.Header as string == "Komari 主控地址"), "选择监控缺少主控字段。");
        Find<CheckBox>(shell).Single(b => b.Content as string == "Komari 监控 Agent").IsChecked = false;
        await Task.Delay(80);
        Require(!Find<TextBox>(shell).Any(b => b.Header as string == "Komari 主控地址"), "关闭监控未隐藏字段。");
        await Shot("deploy-naming-and-monitor");
        deploymentForm["Provider"] = "示例服务商"; deploymentForm["Instance"] = "隔离部署草稿"; deploymentForm["NodeName"] = "示例服务商-隔离部署草稿";
        deploymentForm["IPv4"] = "192.0.2.11"; deploymentForm["SshPort"] = 22022; deploymentForm["RealityTarget"] = "example.com";
        var plan = DeploymentPlans.Create(deploymentForm, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")), paths, false);
        await DialogShot("dialog-deployment-review", OperationDialog("审阅部署计划", ReviewContent(plan, OperationKind.Deploy), "开始部署"), dialog =>
        {
            var texts = Find<TextBlock>(dialog).Select(t => t.Text).ToArray();
            Require(texts.Contains("SSH 连接与管理") && texts.Contains("执行与失败处理") && texts.Contains("本地归档与验收"), "审阅对话框遗漏关键分组。");
            Require(Find<ScrollViewer>(dialog).Any(s => s.ScrollableHeight > 0), "完整审阅没有滚动入口。");
            Require(dialog.DefaultButton == ContentDialogButton.None, "审阅允许隐式回车提交。");
            return Task.CompletedTask;
        });
        activeOperation = new(OperationKind.Deploy, plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy", new());
        var identity = new HostIdentity("192.0.2.11", 22022, "ssh-ed25519", "SHA256:" + new string('A', 43), false);
        await DialogShot("dialog-ssh-first-trust", HostIdentityDialog(identity), async dialog =>
        {
            var reference = Find<TextBox>(dialog).Single(); reference.Text = "SHA256:" + new string('B', 43); await Task.Delay(80);
            Require(!dialog.IsPrimaryButtonEnabled, "指纹不一致仍允许连接。"); reference.Text = "256 " + identity.Sha256Fingerprint + " console (ED25519)"; await Task.Delay(80);
            Require(dialog.IsPrimaryButtonEnabled && dialog.PrimaryButtonText == "核对一致并连接", "指纹自动比较未应用。"); reference.Text = ""; await Task.Delay(80);
        }); activeOperation = null;
        var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative);
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), new JsonObject { ["Engine"] = "dotnet-v1", ["LastTask"] = new JsonObject { ["Outcome"] = "Failed", ["SafeError"] = "SSH 连接超时。", ["NextAction"] = "核对当前端口后继续部署。" } });
        try
        {
            selectedInstance = relative; SelectPage("instances"); await Task.Delay(80);
            Require(Find<Button>(shell).Any(b => b.Content as string == "继续部署") && Find<Button>(shell).Any(b => b.Content as string == "删除实例"), "草稿缺少继续或删除操作。");
            Require(!Find<Button>(shell).Any(b => b.Content as string == "升级核心") && Find<TextBlock>(shell).Any(t => t.Text == "SSH 连接超时。"), "草稿误显示维护或失败原因丢失。");
            await Shot("instance-failed-draft");
            await DialogShot("dialog-delete-instance", InstanceDeletionDialog(new InstanceDeletion(store).Review(relative)));
            var stateFile = SafePath.Resolve(directory, "deployment-state.json"); var draft = ArchiveStore.ReadJson(stateFile);
            try
            {
                var pending = draft.DeepClone().AsObject();
                pending["DeploymentTransaction"] = new JsonObject { ["Status"] = "Armed" };
                pending["LastDeploymentTask"] = new JsonObject { ["Outcome"] = "NeedsRecovery", ["SafeError"] = "管理密钥权限准备失败。", ["NextAction"] = "先核对恢复状态。" };
                ArchiveStore.WriteJson(stateFile, pending); Show("管理密钥权限准备失败。", InfoBarSeverity.Error);
                RefreshTaskResultPage(); await Task.Delay(100);
                Require(!Find<Button>(shell).Any(b => b.Content as string == "继续部署") && Find<Button>(shell).Any(b => b.Content as string == "核对恢复状态"), "新失败后仍显示旧草稿入口。");
                Require(!Find<Button>(shell).Single(b => b.Content as string == "删除实例").IsEnabled, "待恢复实例仍可删除。");
                Require(Find<TextBlock>(shell).Any(t => t.Text == "管理密钥权限准备失败。") && !Find<TextBlock>(shell).Any(t => t.Text == "SSH 连接超时。") && notice.IsOpen && notice.Severity == InfoBarSeverity.Error, "新任务原因未刷新或通知丢失。");
                await Shot("instance-pending-refreshed");
            }
            finally { ArchiveStore.WriteJson(stateFile, draft); notice.IsOpen = false; RefreshTaskResultPage(); }
            Require(Find<Button>(shell).Any(b => b.Content as string == "继续部署") && Find<Button>(shell).Single(b => b.Content as string == "删除实例").IsEnabled, "解除事务后界面未刷新。");
        }
        finally { new InstanceDeletion(store).Delete(new InstanceDeletion(store).Review(relative)); selectedInstance = null; }
        var light = DesktopTheme.IsLight;
        try
        {
            SetAppearance("Light");
            await DialogShot("dialog-deployment-review-light", OperationDialog("审阅部署计划", ReviewContent(plan, OperationKind.Deploy), "开始部署"));
            await DialogShot("dialog-ssh-first-trust-light", HostIdentityDialog(identity));
        }
        finally { SetAppearance(light ? "Light" : "Dark"); }
        return new JsonObject { ["generated_and_custom_names"] = true, ["monitor_fields_conditional"] = true, ["detailed_review_scrolls"] = true, ["first_trust_comparison"] = true, ["draft_status_and_actions"] = true, ["task_result_refresh"] = true, ["pending_disables_continue_and_delete"] = true, ["local_delete_review"] = true, ["remote_connections"] = 0 };
    }
}
