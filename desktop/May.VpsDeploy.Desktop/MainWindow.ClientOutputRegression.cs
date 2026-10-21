#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ClientOutputRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("输出及来源验证只允许在合成工作区运行。");
        var previous = scheme; var previousStep = designerStep; var proof = new JsonObject(); var stage = "输出设置";
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        static void Press(ContentDialog dialog, string name) => ((IInvokeProvider)new ButtonAutomationPeer(Find<Button>(dialog).Single(b => b.Name == name)).GetPattern(PatternInterface.Invoke)).Invoke();
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(5);
            while ((activeTestDialog == null || activeTestDialog == old || !Find<Button>(activeTestDialog).Any(b => b.Name == "CloseButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
            Require(activeTestDialog != null && activeTestDialog != old, "输出或来源对话框未打开。"); shell.UpdateLayout(); return activeTestDialog!;
        }
        async Task Shot(ContentDialog dialog, string file)
        {
            var visual = Find<Border>(dialog).Where(b => b.ActualWidth >= 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)dialog;
            await Capture(SafePath.Resolve(output, file), visual);
        }
        try
        {
            scheme = ClientSchemes.New(paths); scheme["Name"] = "第二轮合成设计";
            ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("anytls://synthetic-output-a@192.0.2.10:443?sni=example.com#EntryA\nanytls://synthetic-output-b@192.0.2.11:443?sni=example.com#EntryB", scheme, "US-West-LA Entry"));
            scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" }; designerStep = 3; SelectPage("clients");
            Require(Find<Button>(shell).Any(b => b.Tag as string == "ClientOutput.Rules") && Find<Button>(shell).Any(b => b.Tag as string == "ClientOutput.Preview"), "导出页缺少输出规则或报告入口。");
            var original = ArchiveStore.Fingerprint(scheme); var pending = EditClientOutputRules(); var settingsDialog = await Dialog();
            Find<CheckBox>(settingsDialog).Single(c => c.Content as string == "启用输出规则").IsChecked = true;
            Find<TextBox>(settingsDialog).Single(t => t.Header as string == "输出名前缀").Text = "May-";
            Find<TextBox>(settingsDialog).Single(t => t.Header as string == "排除名称").Text = "EntryB";
            Press(settingsDialog, "PrimaryButton"); var preview = await Dialog(settingsDialog);
            Require(Find<TextBlock>(preview).Any(t => t.Text.Contains("EntryA → May-EntryA")) && Find<TextBlock>(preview).Any(t => t.Text.Contains("EntryB → 筛除")), "输出预览未展示名称变化和筛除结果。");
            Require(Find<TextBlock>(preview).Any(t => t.Text.Contains("Clash")) && Find<TextBlock>(preview).Any(t => t.Text.Contains("sing-box")), "能力报告未按客户端展示。");
            await Shot(preview, "client-output-preview.png"); Press(preview, "CloseButton"); await pending;
            Require(ArchiveStore.Fingerprint(scheme) == original, "取消输出预览仍修改方案。");
            pending = EditClientOutputRules(); settingsDialog = await Dialog(); Find<CheckBox>(settingsDialog).Single(c => c.Content as string == "启用输出规则").IsChecked = true;
            Find<TextBox>(settingsDialog).Single(t => t.Header as string == "输出名前缀").Text = "May-"; Press(settingsDialog, "PrimaryButton"); preview = await Dialog(settingsDialog); Press(preview, "PrimaryButton"); await pending;
            Require(scheme.Flag("OutputRules.Enabled") && scheme["Candidate"] == null && scheme["Nodes"]![0]!.Text("name") == "EntryA", "规则未保存、旧候选未失效或源名称被改写。"); proof["output_preview_cancel_apply"] = true;
            pending = EditClientOutputRules(); settingsDialog = await Dialog(); Find<TextBox>(settingsDialog).Single(t => t.Header as string == "包含名称（留空为全部）").Text = "no-match";
            Press(settingsDialog, "PrimaryButton"); preview = await Dialog(settingsDialog); Require(!Find<Button>(preview).Single(b => b.Name == "PrimaryButton").IsEnabled, "筛空节点仍允许保存输出规则。"); Press(preview, "CloseButton"); await pending; proof["empty_output_blocked"] = true;
            stage = "来源定义与差异"; designerStep = 1; SelectPage("clients"); original = ArchiveStore.Fingerprint(scheme);
            pending = AddClientSubscription(); var sourceDialog = await Dialog(); Find<PasswordBox>(sourceDialog).Single().Password = "https://example.invalid/private?key=synthetic-ui-url"; Press(sourceDialog, "CloseButton"); await pending;
            Require(ArchiveStore.Fingerprint(scheme) == original && taskCancellation == null, "取消来源定义后仍获取来源或修改方案。"); proof["source_definition_cancel"] = true;
            scheme = ClientSchemes.New(paths); var source = ClientSubscriptions.New("US-West-LA Entry"); source["Url"] = "https://example.invalid/private?key=synthetic-ui-url";
            var a = "anytls://synthetic-source-a@192.0.2.20:443?sni=example.com#SourceEntry"; var landing = "ss://aes-128-gcm:synthetic-source-b@192.0.2.21:8443#SourceLanding";
            var fresh = ClientSubscriptions.Preview(scheme, source, a + "\n" + landing); original = ArchiveStore.Fingerprint(scheme);
            pending = ReviewClientSubscription(fresh); preview = await Dialog();
            Require(!Find<TextBlock>(preview).Any(t => t.Text.Contains("synthetic-ui-url") || t.Text.Contains("synthetic-source-a")), "来源差异显示了 URL 令牌或节点凭据。"); await Shot(preview, "client-source-preview.png"); Press(preview, "CloseButton"); await pending;
            Require(ArchiveStore.Fingerprint(scheme) == original, "取消来源差异仍更新了方案。");
            pending = ReviewClientSubscription(fresh); preview = await Dialog(); Press(preview, "PrimaryButton"); await pending;
            var id = scheme["Nodes"]![0]!.Text("Id"); scheme["Layout"]!["business_groups"]![0]!["default"] = "SourceLanding";
            var update = ClientSubscriptions.Preview(scheme, source, a.Replace("synthetic-source-a@", "synthetic-updated@")); pending = ReviewClientSubscription(update); preview = await Dialog();
            Require(Find<TextBlock>(preview).Any(t => t.Text.Contains("引用影响")), "来源删除预览未展示引用影响。"); Press(preview, "PrimaryButton"); await pending;
            Require(scheme["Nodes"]!.AsArray().Count == 1 && scheme["Nodes"]![0]!.Text("Id") == id && scheme["Layout"]!["business_groups"]![0]!.Text("default") == "", "确认刷新后身份丢失或默认出口被静默替代。"); proof["source_diff_cancel_apply_and_dependencies"] = true;
            scheme["Nodes"]![0]!["sing_box"]!["password"] = "synthetic-local-ui";
            var conflict = ClientSubscriptions.Preview(scheme, source, a.Replace("synthetic-source-a@", "synthetic-next@")); pending = ReviewClientSubscription(conflict); preview = await Dialog();
            Require(!Find<Button>(preview).Single(b => b.Name == "PrimaryButton").IsEnabled && Find<TextBlock>(preview).Any(t => t.Text.Contains("冲突")), "本地与来源冲突仍允许更新。"); Press(preview, "CloseButton"); await pending; proof["source_conflict_blocked"] = true;
            workbench.Save(scheme); var file = paths.Resolve("private/client-schemes/" + scheme.Text("Id") + ".dotnet.private.json"); Require(!File.ReadAllText(file).Contains("synthetic-ui-url"), "来源 URL 未随方案加密保存。"); proof["source_url_protected"] = true;
            return proof;
        }
        catch (Exception error) when (error is not OperationException)
        { File.WriteAllText(SafePath.Resolve(output, "client-output-failure.txt"), error.ToString()); throw new OperationException("第二轮合成界面验证失败：" + stage + "（" + error.GetType().Name + "）。"); }
        finally { scheme = previous; designerStep = previousStep; SelectPage("clients"); }
    }
}
