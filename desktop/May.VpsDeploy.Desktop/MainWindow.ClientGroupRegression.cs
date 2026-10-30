#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ClientGroupRegression(string output)
    {
        if (!ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("节点组界面回归仅用于合成归档。");
        var previous = scheme; var previousStep = designerStep; Task? pending = null;
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        static void Press(ContentDialog dialog, string name) => ((IInvokeProvider)new ButtonAutomationPeer(Find<Button>(dialog).Single(b => b.Name == name)).GetPattern(PatternInterface.Invoke)).Invoke();
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(6);
            while ((activeTestDialog == null || activeTestDialog == old || !Find<Button>(activeTestDialog).Any(b => b.Name == "CloseButton")) && DateTimeOffset.UtcNow < until) { if (pending?.IsFaulted == true) await pending; shell.UpdateLayout(); await Task.Delay(30); }
            Require(activeTestDialog != null && activeTestDialog != old, "节点组对话框未建立。"); shell.UpdateLayout(); return activeTestDialog!;
        }
        try
        {
            scheme = ClientSchemes.New(paths); ClientNodeImport.Apply(scheme, ClientNodeImport.Preview("anytls://synthetic-group-ui@192.0.2.10:443?sni=example.test#ReusableEntry", scheme, "US-West-LA Entry")); designerStep = 1; SelectPage("clients");
            Require(Find<Button>(shell).Any(b => b.Tag as string == "ClientGroups.Save") && Find<Button>(shell).Any(b => b.Tag as string == "ClientGroups.Reuse"), "配置设计缺少节点组入口。");
            var original = ArchiveStore.Fingerprint(scheme); pending = SaveClientNodeGroup(); var save = await Dialog(); Press(save, "CloseButton"); await pending;
            Require(ArchiveStore.Fingerprint(scheme) == original && new ClientNodeGroupStore(store).List().Count == 0, "取消保存写入了节点组。");
            pending = SaveClientNodeGroup(); save = await Dialog(); Find<TextBox>(save).Single(t => t.Tag as string == "ClientGroups.Name").Text = "后台合成节点组"; Press(save, "PrimaryButton"); await pending;
            var library = new ClientNodeGroupStore(store); var group = library.List().Single(); Require(ArchiveStore.Fingerprint(scheme) == original, "保存节点组改写了原方案。");
            scheme = ClientSchemes.New(paths); designerStep = 1; SelectPage("clients"); pending = ReuseClientNodeGroup(); var choose = await Dialog(); Press(choose, "PrimaryButton"); var review = await Dialog(choose);
            Require(!string.Join('\n', Find<TextBlock>(review).Select(t => t.Text)).Contains("synthetic-group-ui"), "复用预览泄漏了凭据。"); Press(review, "CloseButton"); await pending; Require(scheme["Nodes"]!.AsArray().Count == 0, "取消复用修改了方案。");
            pending = ReuseClientNodeGroup(); choose = await Dialog(); Press(choose, "PrimaryButton"); review = await Dialog(choose); Press(review, "PrimaryButton"); await pending;
            Require(scheme["Nodes"]!.AsArray().Count == 1 && scheme["GroupReferences"]!.AsArray().Count == 1, "复用没有接入真实方案与来源。");
            pending = ReviewClientNodeGroup(group.Text("Id")); review = await Dialog(); Press(review, "PrimaryButton"); await pending; Require(scheme["Nodes"]!.AsArray().Count == 1, "再次同步重复添加成员。");
            await Capture(SafePath.Resolve(output, "client-node-groups.png"), shell);
            return new() { ["designer_entry"] = true, ["cancel_save_preserved"] = true, ["encrypted_group_created"] = true, ["source_scheme_preserved"] = true, ["cancel_reuse_preserved"] = true, ["redacted_preview"] = true, ["reuse_applied"] = true, ["refresh_idempotent"] = true };
        }
        finally { scheme = previous; designerStep = previousStep; SelectPage("clients"); }
    }
}
