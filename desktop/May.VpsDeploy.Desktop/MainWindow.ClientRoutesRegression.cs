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
    private async Task<JsonObject> ClientRoutesRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("节点设计验证只允许在合成工作区运行。");
        var previousScheme = scheme; var previousStep = designerStep;
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        static void Invoke(Button button) => ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke();
        async Task<ContentDialog> WaitDialog(ContentDialog? previous = null)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(5);
            while ((activeTestDialog == null || activeTestDialog == previous || !Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
            Require(activeTestDialog != null && activeTestDialog != previous, "节点导入对话框未按预期打开。"); shell.UpdateLayout(); return activeTestDialog!;
        }
        void Press(ContentDialog dialog, string name) => Invoke(Find<Button>(dialog).Single(b => b.Name == name));
        var proof = new JsonObject(); var stage = "打开节点页面";
        try
        {
            scheme = ClientSchemes.New(paths); scheme["Name"] = "第一轮合成配置设计"; designerStep = 1; SelectPage("clients");
            Require(Find<Button>(shell).Any(b => b.Tag as string == "ClientLinks.Import"), "节点页缺少分享链接导入入口。");
            var initial = ArchiveStore.Fingerprint(scheme);
            var add = EditNode(null); var nodeForm = await WaitDialog();
            var protocolChoice = Find<ComboBox>(nodeForm).Single(c => c.Header as string == "协议"); var purpose = Find<ComboBox>(nodeForm).Single(c => c.Header as string == "节点用途");
            protocolChoice.SelectedIndex = protocolChoice.Items.Cast<ComboBoxItem>().ToList().FindIndex(c => c.Tag as string == "ShadowsocksLanding");
            Require(((ComboBoxItem)purpose.SelectedItem).Tag as string == "landing", "新建 Shadowsocks 节点未默认选择落地用途。"); proof["new_ss_defaults_to_landing"] = true;
            purpose.SelectedIndex = 0; protocolChoice.SelectedIndex = 0; protocolChoice.SelectedIndex = protocolChoice.Items.Cast<ComboBoxItem>().ToList().FindIndex(c => c.Tag as string == "ShadowsocksLanding");
            Require(((ComboBoxItem)purpose.SelectedItem).Tag as string == "entry", "协议变更覆盖了用户明确选择的用途。"); proof["explicit_purpose_preserved"] = true;
            Press(nodeForm, "CloseButton"); await add; Require(ArchiveStore.Fingerprint(scheme) == initial, "取消新建节点仍修改方案。"); proof["new_node_cancel_preserves_source"] = true;
            var links = string.Join('\n', new[]
            {
                "anytls://synthetic-one@192.0.2.10:443?sni=example.com#EntryA",
                "anytls://synthetic-two@192.0.2.10:443?sni=example.com#EntryB",
                "anytls://synthetic-three@[2001:db8::10]:443?sni=example.com#EntryC",
                "ss://aes-128-gcm:synthetic-four@192.0.2.20:8443#LandingA",
                "ss://aes-128-gcm:synthetic-five@[2001:db8::20]:8444#LandingB",
                "tuic://unsupported@192.0.2.30:443"
            });
            async Task Import(bool accept)
            {
                stage = "粘贴合成链接"; var pending = ImportClientLinks(); var first = await WaitDialog(); var input = Find<TextBox>(first).Single(t => t.Tag as string == "ClientLinks.Input"); input.Text = links;
                stage = "打开导入预览"; Press(first, "PrimaryButton"); var preview = await WaitDialog(first);
                Require(input.Text == "" && Find<TextBlock>(preview).Any(t => t.Text.Contains("可导入 5 个") && t.Text.Contains("拒绝 1 个")), "导入预览缺少逐项结果或未清空链接输入。");
                Require(!Find<TextBlock>(preview).Any(t => t.Text.Contains("synthetic-one")), "预览泄露认证信息。");
                stage = "截图导入预览";
                var visual = Find<Border>(preview).Where(b => b.ActualWidth >= 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)preview;
                await Capture(SafePath.Resolve(output, "client-import-preview.png"), visual);
                Press(preview, accept ? "PrimaryButton" : "CloseButton"); await pending;
            }
            await Import(false); Require(ArchiveStore.Fingerprint(scheme) == initial, "取消预览后方案已变化。");
            scheme["Candidate"] = new JsonObject { ["ValidationStatus"] = "Passed" };
            await Import(true); Require(scheme["Nodes"]!.AsArray().Count == 5 && scheme["Candidate"] == null, "导入未生效或旧候选仍有效。");
            proof["import_preview_cancel_apply"] = true; proof["preview_redacts_credentials"] = true;
            stage = "编辑外部节点"; var id = scheme["Nodes"]![0]!.Text("Id");
            var editing = EditNode(0); var edit = await WaitDialog(); Find<TextBox>(edit).Single(t => t.Header as string == "节点名称").Text = "Renamed Entry";
            Press(edit, "PrimaryButton"); await editing;
            Require(scheme["Nodes"]![0]!.Text("Id") == id && scheme["Nodes"]![0]!.At("sing_box.tls.ech") == null && !scheme["Nodes"]![0]!.Flag("Source.Modified"), "编辑改名丢失身份或为普通 AnyTLS 加入了空 ECH。");
            proof["rename_preserves_identity_and_tls"] = true;
            workbench.Save(scheme); Require(workbench.List().Single(s => s.Text("Id") == scheme.Text("Id"))["Nodes"]![0]!.Text("Id") == id, "保存后导入身份丢失。");
            stage = "展示连接关系"; designerStep = 2; SelectPage("clients"); shell.UpdateLayout();
            Require(Find<FrameworkElement>(shell).Any(e => e.Tag as string == "ClientTopology.US-West-LA Entry") && Find<TextBlock>(shell).Count(t => t.Text.StartsWith("↳ ")) >= 5, "连接图未逐项展示入口、落地和出口。");
            Require(Find<TextBlock>(shell).Any(t => t.Text.Contains("连接：IPv6")) && Find<TextBlock>(shell).Any(t => t.Text.Contains("网站出口地址族未标注")), "连接 IPv6 被误当成出口 IPv6。");
            await Capture(SafePath.Resolve(output, "client-topology.png")); proof["vertical_topology_and_address_families"] = true;
            stage = "诊断路径选择"; var diagnose = DiagnoseClientRoute(); var picker = await WaitDialog();
            Require(Find<ComboBox>(picker).Single(c => c.Header as string == "出口路径").Items.Count == 3, "诊断未提供具体入口和同组落地选择。");
            Press(picker, "CloseButton"); await diagnose; Require(taskCancellation == null, "取消诊断选择仍启动了网络任务。"); proof["diagnostic_selection_cancel"] = true;
            stage = "失效诊断提示"; var route = ClientTopology.DiagnosticRoute(scheme, "Renamed Entry", "LandingA");
            scheme["Diagnostics"] = new JsonArray(new JsonObject { ["Fingerprint"] = route.Fingerprint, ["EntryId"] = id, ["EntryName"] = "Renamed Entry", ["LandingId"] = scheme["Nodes"]![3]!.Text("Id"), ["LandingName"] = "LandingA", ["Path"] = route.Label,
                ["Status"] = "Reachable", ["At"] = DateTimeOffset.UtcNow.ToString("O"), ["Scope"] = "合成历史结果，不发起网络请求。", ["Stages"] = new JsonArray(new JsonObject { ["Label"] = "合成阶段", ["Status"] = "Passed", ["Milliseconds"] = 12 }) });
            SelectPage("clients"); Require(Find<TextBlock>(shell).Any(t => t.Text == "所选路径已连通"), "当前诊断记录未展示。");
            scheme["Nodes"]![3]!["sing_box"]!["password"] = "synthetic-changed"; SelectPage("clients");
            Require(Find<TextBlock>(shell).Any(t => t.Text.Contains("参数已变化，需重测")), "节点参数变化后仍显示旧健康结果为当前结果。"); proof["stale_diagnostic_visible"] = true;
            return proof;
        }
        catch (Exception error) when (error is not OperationException)
        {
            System.IO.File.WriteAllText(SafePath.Resolve(output, "client-routes-failure.txt"), error.ToString());
            throw new OperationException("合成节点界面验证失败：" + stage + "（" + error.GetType().Name + "）。");
        }
        finally { scheme = previousScheme; designerStep = previousStep; SelectPage("clients"); }
    }
}
