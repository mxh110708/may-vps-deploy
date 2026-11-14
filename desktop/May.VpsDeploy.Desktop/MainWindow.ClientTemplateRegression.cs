#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ClientTemplateRegression(string output)
    {
        if (testSession == null || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("模板界面回归仅允许后台合成会话。");
        var previous = scheme; var baseline = schemeBaseline; var step = designerStep; var proof = new JsonObject();
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        void Stage(string name) => ArchiveStore.WriteJson(SafePath.Resolve(output, "template-stage.json"), new JsonObject { ["Stage"] = name, ["At"] = DateTimeOffset.UtcNow });
        async Task<ContentDialog> Dialog(ContentDialog? previous = null)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(8);
            while ((activeTestDialog == null || activeTestDialog == previous || !Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
            Require(activeTestDialog != null && activeTestDialog != previous, "模板对话框未打开。"); shell.UpdateLayout(); return activeTestDialog!;
        }
        async Task Finished(Task task)
        {
            try { await task.WaitAsync(TimeSpan.FromSeconds(30)); }
            catch (TimeoutException)
            {
                var messages = activeTestDialog == null ? "无对话框" : string.Join("\n", Find<TextBlock>(activeTestDialog).Select(t => t.Text).Where(t => t.Length < 800).TakeLast(8));
                ArchiveStore.WriteJson(SafePath.Resolve(output, "template-wait-failure.json"), new JsonObject { ["Messages"] = messages, ["Busy"] = taskCancellation != null });
                throw new OperationException("模板合成操作未在30秒内完成，请查看阶段与表单错误。");
            }
        }
        try
        {
            Stage("prepare");
            scheme = ClientSchemes.New(paths); scheme["Name"] = "第38轮合成模板方案";
            ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic38-ui@192.0.2.10:443#SyntheticEntry", scheme, "US-West-LA Entry", "entry"));
            SaveScheme(); designerStep = 0; SelectPage("clients"); var original = ArchiveStore.Fingerprint(scheme); var nodes = scheme["Nodes"]!.DeepClone();
            Require(Find<Button>(page).Any(b => b.Tag as string == "ClientTemplates.Open"), "缺少模板库入口。"); proof["library_entry_visible"] = true;
            var builtin = TemplateLibrary.BuiltIn(); var draft = TemplateLibrary.Draft(builtin, true);
            Stage("invalid-parameter"); var edit = EditClientTemplate(draft); var dialog = await Dialog();
            var layoutText = Find<TextBox>(dialog).Single(t => t.Tag as string == "ClientTemplates.Layout").Text;
            ArchiveStore.WriteJson(SafePath.Resolve(output, "template-editor-initial.json"), new JsonObject { ["LayoutText"] = layoutText, ["Expected"] = draft["Layout"]!.DeepClone() });
            Require(JsonNode.DeepEquals(JsonNode.Parse(layoutText), draft["Layout"]), "初始多行布局内容与原配置不同。"); proof["multiline_initial_layout_preserved"] = true;
            await RegressionFill(Find<TextBox>(dialog).Single(t => t.Header as string == "Mihomo混合端口"), "0");
            await RegressionPress(dialog, "PrimaryButton"); await Task.Delay(60);
            Require(activeTestDialog == dialog && Find<TextBlock>(dialog).Any(t => t.Text.Contains("监听端口")) && !TemplateLibrary.List().Any(d => d.Text("Id") == draft.Text("Id")), "非法端口未显示准确错误、关闭表单或写入修订。"); proof["invalid_parameter_keeps_form"] = true;
            await RegressionPress(dialog, "CloseButton"); await edit; Require(ArchiveStore.Fingerprint(scheme) == original, "取消模板编辑改变方案。"); proof["edit_cancel_preserves_scheme_and_versions"] = true;
            draft = TemplateLibrary.Draft(builtin, true); draft["Name"] = "合成模板 · 可读修订";
            Stage("save-version"); edit = EditClientTemplate(draft); dialog = await Dialog(); await RegressionFill(Find<TextBox>(dialog).Single(t => t.Header as string == "Mihomo混合端口"), "28480");
            await RegressionFill(Find<TextBox>(dialog).Single(t => t.Header as string == "May Route混合端口"), "28481"); await RegressionPress(dialog, "PrimaryButton"); await Finished(edit);
            Require(TemplateLibrary.Read(draft.Text("Id"), 1).Number("Parameters.RouteMixedPort") == 28481 && ArchiveStore.Fingerprint(scheme) == original, "保存模板未固定参数或自动应用到了方案。"); proof["save_new_snapshot_without_auto_apply"] = true;
            Stage("preview-cancel"); var apply = ReviewClientTemplate(draft); dialog = await Dialog();
            Require(Find<TextBlock>(dialog).Any(t => t.Text.Contains("DNS") && t.Text.Contains("监听") && t.Text.Contains("保留 1 个节点")), "差异审阅缺少实际配置范围与保留内容。");
            await Capture(SafePath.Resolve(output, "client-template-diff.png"), dialog); await RegressionPress(dialog, "CloseButton"); await apply;
            Require(ArchiveStore.Fingerprint(scheme) == original && !ClientTemplates.Journals(store).Any(), "取消应用产生了方案变更或事务。"); proof["review_diff_cancel_no_scheme_write"] = true;
            Stage("apply-version"); apply = ReviewClientTemplate(draft); dialog = await Dialog(); await RegressionPress(dialog, "PrimaryButton"); await apply;
            Require(scheme!.Number("TemplateReference.Revision") == 1 && JsonNode.DeepEquals(scheme["Nodes"], nodes) && scheme["Candidate"] == null && !SchemeChanged, "应用修订没有更新已保存绑定或损坏节点。"); proof["apply_preserves_nodes_requires_regeneration"] = true;
            var version2 = TemplateLibrary.Draft(draft, false); version2["Parameters"]!["ClashMixedPort"] = 28482; await TemplateLibrary.SaveVersionAsync(version2, default);
            Require(scheme.Number("TemplateReference.Revision") == 1, "新增版本自动切换已使用的方案。"); proof["new_revision_does_not_upgrade_scheme"] = true;
            Stage("list-versions"); var libraryDialog = ClientTemplateLibrary(); dialog = await Dialog();
            Require(Find<ComboBox>(dialog).Single(c => c.Tag as string == "ClientTemplates.Version").Items.Count >= 3, "模板库没有同时展示历史修订。");
            await Capture(SafePath.Resolve(output, "client-template-library.png"), dialog); await RegressionPress(dialog, "CloseButton"); await libraryDialog; proof["version_library_readable"] = true;
            Stage("restore-cancel"); var restore = RestoreClientTemplate(); dialog = await Dialog(); await RegressionPress(dialog, "PrimaryButton"); dialog = await Dialog(dialog);
            Require(Find<TextBlock>(dialog).Any(t => t.Text.Contains("保留当前节点")), "恢复未披露组件范围。"); await RegressionPress(dialog, "CloseButton"); await restore;
            Require(scheme["TemplateReference"] != null, "取消恢复丢失模板绑定。"); proof["restore_cancel_preserves_applied_version"] = true;
            Stage("restore-confirm"); restore = RestoreClientTemplate(); dialog = await Dialog(); await RegressionPress(dialog, "PrimaryButton"); dialog = await Dialog(dialog); await RegressionPress(dialog, "PrimaryButton"); await restore;
            Require(scheme["TemplateReference"] == null && JsonNode.DeepEquals(scheme["Nodes"], nodes) && scheme.Text("Clash") == ClientSchemes.New(paths).Text("Clash"), "恢复没有准确恢复基础模板或改动节点。"); proof["scoped_restore_preserves_nodes"] = true;
            Require(!monitorTimer.IsEnabled && taskCancellation == null, "模板操作留下轮询或未完成任务。"); proof["no_polling_or_unfinished_task"] = true;
            Stage("complete"); return proof;
        }
        finally { activeTestDialog?.Hide(); scheme = previous; schemeBaseline = baseline; designerStep = step; SelectPage("overview"); }
    }
}
