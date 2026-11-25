using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> InstanceAddressRegression(string output)
    {
        if (testSession == null || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("换址界面检查仅限后台合成会话。");
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        async Task<ContentDialog> Dialog(ContentDialog? previous = null)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(10);
            while ((activeTestDialog == null || activeTestDialog == previous || !Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) && DateTimeOffset.UtcNow < until) { shell.UpdateLayout(); await Task.Delay(30); }
            Require(activeTestDialog != null && activeTestDialog != previous, "换址对话框未打开。"); return activeTestDialog!;
        }
        var plan = DeploymentPlans.Create(new JsonObject { ["Provider"] = "Synthetic", ["Instance"] = "Round39Address", ["NodeName"] = "换址界面合成实例", ["Role"] = "RealityEntry", ["RealityTarget"] = "example.com", ["IPv4"] = "192.0.2.60", ["SshPort"] = 22, ["BandwidthMbps"] = 100 }, ArchiveStore.ReadJson(paths.Resolve("config/versions.json")), paths, false);
        plan.Put("Import.Status", JsonValue.Create("Completed"));
        var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative);
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan);
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), new JsonObject { ["Engine"] = "dotnet-v1", ["CurrentManagementPort"] = plan.Number("Ports.SshPrimary") });
        store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), new JsonObject());
        var trustFile = paths.Resolve("private/ssh-hosts.dotnet.json"); var trust = File.Exists(trustFile) ? ArchiveStore.ReadJson(trustFile) : new JsonObject();
        trust[ArchiveStore.Digest(Encoding.UTF8.GetBytes("192.0.2.60"))] = "SHA256:" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes("synthetic-address39-ui"))).TrimEnd('='); ArchiveStore.WriteJson(trustFile, trust);
        var original = File.ReadAllBytes(SafePath.Resolve(directory, "deployment-plan.json")); var proof = new JsonObject();
        selectedInstance = relative; SelectPage("instances");
        Require(Find<Button>(page).Any(b => b.Content?.ToString() == "修改地址"), "实例页缺少换址入口。"); proof["instance_entry_visible"] = true;
        var edit = InstanceAddressSheet(relative, plan); var dialog = await Dialog();
        var box = Find<TextBox>(dialog).Single(t => t.Tag as string == "InstanceAddress.IPv4");
        await RegressionPress(dialog, "PrimaryButton");
        Require(activeTestDialog == dialog && Find<TextBlock>(dialog).Any(t => t.Text == "地址没有变化。"), "未变化地址没有留在原表单。"); proof["unchanged_address_retains_form"] = true;
        await RegressionFill(box, "127.0.0.1"); await RegressionPress(dialog, "PrimaryButton");
        Require(activeTestDialog == dialog && box.Text == "127.0.0.1", "非法地址没有保留编辑内容。"); proof["invalid_address_retains_form"] = true;
        await RegressionFill(box, "192.0.2.61");
        await Capture(SafePath.Resolve(output, "instance-address-form.png"), dialog);
        await RegressionPress(dialog, "PrimaryButton"); var review = await Dialog(dialog);
        Require(Find<TextBlock>(review).Any(t => t.Text.Contains("192.0.2.60 → 192.0.2.61", StringComparison.Ordinal)), "审阅未显示真实地址差异。"); proof["review_contains_address_diff"] = true;
        Require(Find<TextBlock>(review).Any(t => t.Text.Contains("不接受重装后的新 SSH 身份", StringComparison.Ordinal)), "审阅缺少主机身份边界。"); proof["identity_scope_visible"] = true;
        await Capture(SafePath.Resolve(output, "instance-address-review.png"), review);
        await RegressionPress(review, "CloseButton"); await edit.WaitAsync(TimeSpan.FromSeconds(20));
        Require(original.SequenceEqual(File.ReadAllBytes(SafePath.Resolve(directory, "deployment-plan.json"))), "取消审阅修改了实例归档。"); proof["cancel_preserves_archive"] = true;
        Require(!InstanceLifecycle.Read(store, relative, plan).NeedsRecovery, "仅预览创建了待恢复事务。"); proof["preview_has_no_pending_transaction"] = true;
        Require(testActivations == 0 && testForegroundSamples == 0, "后台换址检查激活了前台。"); proof["zero_foreground_activity"] = true;
        return proof;
    }
}
