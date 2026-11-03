using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ClientBatchRegression(string output)
    {
        if (testSession == null || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("批量与输出界面回归仅允许合成后台会话。");
        var assertions = 0; Task? pending = null;
        void Require(bool value, string message) { if (!value) throw new OperationException(message); assertions++; }
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(15);
            while ((activeTestDialog == null || activeTestDialog == old || !Find<Button>(activeTestDialog).Any(b => b.Name == "CloseButton")) && DateTimeOffset.UtcNow < until)
            { if (pending?.IsFaulted == true) await pending; shell.UpdateLayout(); await Task.Delay(40); }
            if (pending?.IsFaulted == true) await pending;
            Require(activeTestDialog != null && activeTestDialog != old, "未收到批量或导出审阅对话框。"); await Task.Delay(100); return activeTestDialog!;
        }
        async Task Until(Func<bool> test)
        {
            var end = DateTimeOffset.UtcNow.AddSeconds(15);
            while (!test() && DateTimeOffset.UtcNow < end) { shell.UpdateLayout(); await Task.Delay(40); }
            Require(test(), "后台节点片段操作未完成。");
        }
        var previous = scheme; var baseline = schemeBaseline; var step = designerStep; string? copied = null;
        try
        {
            scheme = ClientSchemes.New(paths); var region = scheme["Layout"]!.Strings("region_groups")[0];
            ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("anytls://synthetic-ui32-a@entry.example.test:443?sni=entry.example.test#EntryA\nanytls://synthetic-ui32-b@entry.example.test:444?sni=entry.example.test#EntryB\nss://aes-128-gcm:synthetic-ui32-c@landing.example.test:8443#Landing", scheme, region, "entry"));
            scheme["Nodes"]![2]!["kind"] = "landing"; scheme["Nodes"]![2]!["transit_group"] = region;
            designerStep = 1; SelectPage("clients"); Require(Find<Button>(page).Any(b => b.Tag as string == "ClientBatch.Open"), "节点页缺少批量入口。");
            var id = scheme["Nodes"]![1]!.Text("Id"); var fp = ArchiveStore.Fingerprint(scheme);
            pending = BatchClientNodes(); var form = await Dialog();
            await RegressionToggle(Find<CheckBox>(form).Single(c => c.Tag as string == "ClientBatch.Node." + id), true);
            await RegressionFill(Find<TextBox>(form).Single(t => t.Tag as string == "ClientBatch.Filter"), "Landing");
            Require(Find<TextBlock>(form).Any(t => t.Tag as string == "ClientBatch.Count" && t.Text.Contains("筛选外已选 1")), "筛选清掉了隐藏选择或未披露。");
            await RegressionPress(form, "PrimaryButton"); var review = await Dialog(form);
            Require(!string.Join('\n', Find<TextBlock>(review).Select(t => t.Text)).Contains("synthetic-ui32"), "批量预览显示鉴权内容。");
            await Capture(SafePath.Resolve(output, "round32-batch-review.png"), review); await RegressionPress(review, "CloseButton"); await pending;
            Require(ArchiveStore.Fingerprint(scheme) == fp, "取消批量操作改变了草稿。");
            pending = BatchClientNodes(); form = await Dialog(); await RegressionToggle(Find<CheckBox>(form).Single(c => c.Tag as string == "ClientBatch.Node." + id), true);
            await RegressionPress(form, "PrimaryButton"); review = await Dialog(form); await RegressionPress(review, "PrimaryButton"); await pending;
            Require(scheme["Nodes"]![0]!.Text("Id") == id, "批量顺序未应用到草稿。");
            var landingId = scheme["Nodes"]!.AsArray().Single(n => n!.Text("kind") == "landing")!.Text("Id"); fp = ArchiveStore.Fingerprint(scheme);
            var directory = paths.Resolve("exports/round32"); Directory.CreateDirectory(directory);
            pending = ExportClientFragments(scheme, text => { copied = text; return Task.CompletedTask; }, () => Task.FromResult<string?>(directory)); form = await Dialog();
            await RegressionSelect(Find<ComboBox>(form).Single(c => c.Tag as string == "ClientFragment.Format"), 1);
            await RegressionToggle(Find<CheckBox>(form).Single(c => c.Tag as string == "ClientFragment.Node." + landingId), true);
            await RegressionPress(form, "PrimaryButton"); review = await Dialog(form); var text = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text));
            Require(text.Contains("依赖 · EntryA") && text.Contains("依赖 · EntryB") && text.Contains("入口组 · ") && !text.Contains("synthetic-ui32"), "节点片段遗漏依赖或在审阅中泄露鉴权。");
            await RegressionInvoke(Find<Button>(review).Single(b => b.Tag as string == "ClientFragment.Copy")); await Until(() => copied != null);
            Require(JsonNode.Parse(copied!)!["outbounds"]!.AsArray().Count == 4, "复制接收器未获得完整节点依赖片段。");
            await RegressionInvoke(Find<Button>(review).Single(b => b.Tag as string == "ClientFragment.Save")); var file = Path.Combine(directory, "may-nodes.private.json"); await Until(() => File.Exists(file));
            Require(File.ReadAllText(file) == copied, "保存片段与复制接收器的内容不同。");
            await Capture(SafePath.Resolve(output, "round32-fragment-review.png"), review); await RegressionPress(review, "CloseButton"); await pending;
            Require(ArchiveStore.Fingerprint(scheme) == fp, "片段复制／保存改变了源方案。");
            await workbench.BuildAsync(scheme, default); await workbench.ValidateAsync(scheme, default);
            scheme["Targets"]!["Clash"] = Path.Combine(directory, "full.yaml"); scheme["Targets"]!["SingBox"] = Path.Combine(directory, "full.json"); designerStep = 3; SelectPage("clients"); fp = ArchiveStore.Fingerprint(scheme);
            Require(Find<Button>(page).Any(b => b.Tag as string == "ClientFragment.Open"), "导出页缺少原生片段入口。");
            pending = PublishClients(); form = await Dialog(); text = string.Join('\n', Find<TextBlock>(form).Select(t => t.Text));
            Require(text.Contains("DNS：") && text.Contains("代理组：") && text.Contains("分流规则：") && !text.Contains("synthetic-ui32"), "完整导出未展示安全差异摘要。");
            await Capture(SafePath.Resolve(output, "round32-full-difference.png"), form); await RegressionPress(form, "CloseButton"); await pending;
            Require(ArchiveStore.Fingerprint(scheme) == fp && !File.Exists(scheme.Text("Targets.Clash")) && !File.Exists(scheme.Text("Targets.SingBox")), "取消差异审阅修改了方案或文件。");
            pending = PublishClients(); form = await Dialog(); await RegressionPress(form, "PrimaryButton"); await pending;
            Require(File.Exists(scheme.Text("Targets.Clash")) && File.Exists(scheme.Text("Targets.SingBox")), "确认差异后未导出两个文件。");
            var saved = store.ReadSecret(paths.Resolve("private/client-schemes/" + scheme.Text("Id") + ".dotnet.private.json"));
            Require(saved.Text("Targets.SingBox") == scheme.Text("Targets.SingBox") && !SchemeChanged, "成功导出后未保存方案和导出位置。");
            Require(taskCancellation == null, "回归结束后仍保留运行任务。");
            return new() { ["assertions"] = assertions, ["hidden_selection_preserved"] = true, ["batch_cancel_preserved"] = true, ["batch_applied"] = true, ["dependency_review"] = true, ["copy_receiver_only"] = true, ["native_file_saved"] = true, ["native_cores_validated"] = true, ["publish_cancel_read_only"] = true, ["no_secret_preview"] = true };
        }
        finally { activeTestDialog?.Hide(); scheme = previous; schemeBaseline = baseline; designerStep = step; SelectPage("clients"); }
    }
}
