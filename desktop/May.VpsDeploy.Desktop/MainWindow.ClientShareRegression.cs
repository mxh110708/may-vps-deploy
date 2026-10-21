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
    private async Task<JsonObject> ClientShareRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("分享回归只允许在合成工作区运行。");
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        var previous = scheme; var previousStep = designerStep; string? copied = null; var copies = 0; Task? pending = null;
        var directory = paths.Resolve("share-test-exports"); Directory.CreateDirectory(directory);
        try
        {
            scheme = ClientSchemes.New(paths); var region = scheme["Layout"]!.Strings("region_groups")[0];
            ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("anytls://synthetic-share-a@192.0.2.10:443?sni=example.test#ShareEntry\nss://aes-128-gcm:synthetic-share-b@192.0.2.20:20001#ChainedLanding\nanytls://synthetic-share-c@192.0.2.11:443?sni=example.test#EchEntry", scheme, region, "entry"));
            scheme["Nodes"]![1]!["kind"] = "landing"; scheme["Nodes"]![2]!["sing_box"]!["tls"]!["ech"] = new JsonObject { ["enabled"] = true };
            var rules = ClientOutputRules.New(); rules["Enabled"] = true; rules["Prefix"] = "Share-"; scheme["OutputRules"] = rules;
            designerStep = 3; SelectPage("clients"); Require(Find<Button>(shell).Any(b => b.Tag as string == "ClientShare.Open"), "导出页缺少分享入口。"); var before = ArchiveStore.Fingerprint(scheme);
            async Task<ContentDialog> Dialog()
            {
                var until = DateTimeOffset.UtcNow.AddSeconds(6);
                while ((activeTestDialog == null || Find<CheckBox>(activeTestDialog).Count(c => (c.Tag as string)?.StartsWith("ClientShare.Node.") == true) != 3 || !Find<Button>(activeTestDialog).Any(b => b.Name == "CloseButton")) && DateTimeOffset.UtcNow < until) { if (pending?.IsFaulted == true) await pending; shell.UpdateLayout(); await Task.Delay(30); }
                Require(activeTestDialog != null, "分享对话框未显示。"); shell.UpdateLayout(); return activeTestDialog!;
            }
            pending = ShareClientLinks(scheme, text => { copied = text; copies++; return Task.CompletedTask; }, () => Task.FromResult<string?>(directory)); var dialog = await Dialog();
            void Click(string tag)
            {
                var button = Find<Button>(dialog).Single(b => b.Tag as string == tag); Require(button.IsEnabled, "分享操作不可用：" + tag); ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke(); shell.UpdateLayout();
            }
            async Task Until(Func<bool> predicate)
            {
                var until = DateTimeOffset.UtcNow.AddSeconds(5); while (!predicate() && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); } Require(predicate(), "分享操作未完成。");
            }
            var checks = Find<CheckBox>(dialog).Where(c => (c.Tag as string)?.StartsWith("ClientShare.Node.") == true).ToArray();
            Require(checks.Length == 3 && checks.Count(c => c.IsEnabled && c.IsChecked == true) == 1 && Find<TextBlock>(dialog).Any(t => t.Text.Contains("不能完整保留 ECH")) && Find<TextBlock>(dialog).Any(t => t.Text.Contains("依赖客户端入口")), "不支持节点未逐项禁用或解释。");
            Require(!string.Join('\n', Find<TextBlock>(dialog).Select(t => t.Text)).Contains("synthetic-share-"), "分享预览包含鉴权内容。");
            Click("ClientShare.None"); Require(!Find<Button>(dialog).Single(b => b.Tag as string == "ClientShare.Copy").IsEnabled && !Find<Button>(dialog).Single(b => b.Tag as string == "ClientShare.Save").IsEnabled, "空选择仍允许复制或保存。");
            Click("ClientShare.All"); Click("ClientShare.Copy"); await Until(() => copies == 1); Require(copied!.Contains("#Share-ShareEntry") && !copied.Contains("synthetic-share-b") && !copied.Contains("synthetic-share-c"), "复制未遵循筛选命名或包含被阻止节点。");
            Find<ComboBox>(dialog).Single(c => c.Tag as string == "ClientShare.Format").SelectedIndex = 1; Click("ClientShare.Copy"); await Until(() => copies == 2); Require(ClientSubscriptions.Decode(copied!).StartsWith("anytls://"), "Base64 分享无法还原。");
            Find<TextBox>(dialog).Single(t => t.Tag as string == "ClientShare.FileName").Text = "../foreign.txt"; Click("ClientShare.Save"); await Until(() => Find<TextBlock>(dialog).Any(t => t.Tag as string == "ClientShare.Status" && t.Text.Contains("不含路径"))); Require(!File.Exists(paths.Resolve("foreign.txt")), "分享文件名逃逸目录。");
            Find<TextBox>(dialog).Single(t => t.Tag as string == "ClientShare.FileName").Text = "nodes.txt"; Click("ClientShare.Save"); var target = Path.Combine(directory, "nodes.txt"); await Until(() => File.Exists(target)); Require(File.ReadAllText(target) == copied, "分享保存内容与选择格式不符。");
            File.WriteAllText(target, "external-content"); Click("ClientShare.Save"); await Until(() => Find<TextBlock>(dialog).Any(t => t.Tag as string == "ClientShare.Status" && t.Text.Contains("不覆盖已有文件"))); Require(File.ReadAllText(target) == "external-content", "分享覆盖了外部文件。");
            scheme["Name"] = "changed during sharing"; Click("ClientShare.Copy"); await Until(() => Find<TextBlock>(dialog).Any(t => t.Tag as string == "ClientShare.Status" && t.Text.Contains("预览后已变化"))); Require(copies == 2, "方案变化后仍复制旧链接。"); scheme["Name"] = "新方案";
            var scroll = Find<ScrollViewer>(dialog).OrderByDescending(s => s.ScrollableHeight).First(); scroll.ChangeView(null, 0, null, true); shell.UpdateLayout(); await Task.Delay(350);
            var visual = Find<Border>(dialog).Where(b => b.ActualWidth >= 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)dialog; await Capture(SafePath.Resolve(output, "client-share-preview.png"), visual);
            ((IInvokeProvider)new ButtonAutomationPeer(Find<Button>(dialog).Single(b => b.Name == "CloseButton")).GetPattern(PatternInterface.Invoke)).Invoke(); await pending;
            Require(ArchiveStore.Fingerprint(scheme) == before && taskCancellation == null, "分享或取消修改了方案、候选或发起服务器任务。");
            return new() { ["designer_entry"] = true, ["blocked_rows_explained"] = true, ["redacted_preview"] = true, ["selection_and_copy"] = true, ["base64_copy"] = true, ["file_name_guard"] = true, ["save_exact_content"] = true, ["existing_file_preserved"] = true, ["stale_preview_blocked"] = true, ["cancel_preserves_source"] = true, ["system_clipboard_untouched"] = true };
        }
        catch (Exception error) { File.WriteAllText(SafePath.Resolve(output, "client-share-ui-failure.txt"), error.ToString()); throw; }
        finally { scheme = previous; designerStep = previousStep; SelectPage("clients"); }
    }
}
