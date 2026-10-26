using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> MayMonitorRegression(string outputDirectory)
    {
        if (testSession == null || !backgroundTest || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("维护界面回归仅允许合成工作区。");
        static void Require(bool value, string reason) { if (!value) throw new OperationException(reason); }
        var history = new TaskHistory(store).Read().Count; Task? pending = null;
        try
        {
            SelectPage("monitoring");
            Require(Find<Button>(shell).Any(b => b.Content as string == "部署与维护"), "缺少 May 部署入口。");
            pending = ManageMayMonitorDialog();
            for (var i = 0; i < 100 && activeTestDialog == null; i++) await Task.Delay(30);
            var dialog = activeTestDialog ?? throw new OperationException("May 维护表单未打开。");
            ComboBox Choice(string tag) => Find<ComboBox>(dialog).Single(b => b.Tag as string == "MayMonitor." + tag);
            async Task Pick(string tag, string value)
            { var box = Choice(tag); box.SelectedItem = box.Items.Cast<ComboBoxItem>().Single(i => i.Tag as string == value); await Task.Delay(80); }
            Require(Choice("Role").SelectedItem is ComboBoxItem initial && initial.Tag as string == "Server", "默认组件不明确。");
            await Pick("Action", "Install");
            Require(Find<TextBox>(dialog).Any(t => t.Header as string == "回环监听端口"), "服务端安装缺少监听参数。");
            await Pick("Role", "Agent");
            Require(Find<TextBox>(dialog).Any(t => t.Header as string == "May 服务端 HTTPS 地址") && !Find<TextBox>(dialog).Any(t => t.Header as string == "回环监听端口"), "组件切换残留另一组件参数。");
            await RegressionPress(dialog, "PrimaryButton");
            Require(activeTestDialog == dialog && Find<TextBlock>(dialog).Single(t => t.Tag as string == "MayMonitor.Validation").Text != "", "无效 Agent 地址进入审阅。");
            await Pick("Role", "Server"); await Pick("Action", "Restore");
            Require(Find<TextBlock>(dialog).Any(t => t.Text.Contains("没有可用于恢复的 May 一致性备份")), "无恢复点却提供其他组件备份。");
            await Pick("Role", "Agent"); await Pick("Action", "ConfigureRead");
            await RegressionPress(dialog, "PrimaryButton");
            Require(activeTestDialog == dialog, "Agent 接受了服务端只读授权操作。");
            await Pick("Action", "ConfigureAgent");
            Require(Find<TextBox>(dialog).Single(t => t.Header as string == "原 May 节点 UUID").IsReadOnly && Find<CheckBox>(dialog).Any(t => t.Tag as string == "MayMonitor.ReplaceToken"), "Agent 维护缺少固定节点或显式凭据选项。");
            Require(!Find<PasswordBox>(dialog).Any(), "维护表单提前读取了 Token。");
            await RegressionPress(dialog, "PrimaryButton");
            Require(activeTestDialog == dialog, "缺少节点身份的 Agent 配置进入审阅。");
            await Pick("Action", "RepairAgent");
            Require(!Find<CheckBox>(dialog).Single(t => t.Tag as string == "MayMonitor.ReplaceToken").IsEnabled, "凭据恢复允许沿用被撤销 Token。");
            await RegressionPress(dialog, "PrimaryButton");
            Require(activeTestDialog == dialog, "无待恢复事务仍执行了 Agent 修复。");
            await Pick("Action", "RevokeRead");
            await RegressionPress(dialog, "PrimaryButton");
            Require(activeTestDialog == dialog, "Agent 接受了撤销 Server 只读授权。");
            await Pick("Role", "Server"); await Pick("Action", "Install");
            dialog.UpdateLayout(); await Task.Delay(100); await Capture(SafePath.Resolve(outputDirectory, "may-monitor-maintenance.png"), dialog);
            await RegressionPress(dialog, "CloseButton"); await pending;
            Require(taskCancellation == null && new TaskHistory(store).Read().Count == history, "取消维护仍提交了任务。");
            return new() { ["entry_without_connection"] = true, ["explicit_role_action"] = true, ["role_fields_reset"] = true, ["invalid_stays_open"] = true, ["scoped_restore_only"] = true, ["agent_read_authorization_refused"] = true, ["fixed_agent_identity"] = true, ["token_prompt_deferred"] = true, ["invalid_agent_config_refused"] = true, ["explicit_pending_repair"] = true, ["agent_cannot_revoke_server_read"] = true, ["cancel_no_task"] = true, ["production_connections"] = 0 };
        }
        finally
        {
            if (activeTestDialog != null) { activeTestDialog.Hide(); await Task.Delay(100); }
            if (pending != null) await pending.WaitAsync(TimeSpan.FromSeconds(3));
            Navigate("overview");
        }
    }
}
