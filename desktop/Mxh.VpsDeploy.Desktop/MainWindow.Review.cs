using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    // Screenshots only: edit transient form models and cancel dialogs. No operation is submitted.
    private async Task ReviewScreenshots(string outputDirectory)
    {
        async Task Shot(string filename, string id, bool expand = false, bool bottom = false)
        {
            SelectPage(id); await Task.Delay(100);
            if (expand)
            {
                foreach (var button in disclosures.Keys.ToArray())
                    ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke();
                await Task.Delay(100);
            }
            var scroll = Find<ScrollViewer>(shell).First(v => v.Content is StackPanel panel && panel.Children.Contains(pageHost));
            shell.UpdateLayout(); scroll.ChangeView(null, bottom ? scroll.ScrollableHeight : 0, null, true); await Task.Delay(100);
            await Capture(SafePath.Resolve(outputDirectory, filename + ".png"));
        }
        async Task DialogShot(string filename, Func<Task> open)
        {
            var pending = open(); await Task.Delay(180);
            var dialog = VisualTreeHelper.GetOpenPopupsForXamlRoot(shell.XamlRoot).SelectMany(p => Find<ContentDialog>(p.Child)).First();
            try
            {
                var frame = Find<Border>(dialog).Where(b => b.ActualWidth >= 250 && b.ActualWidth < shell.ActualWidth - 40 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).First();
                await Capture(SafePath.Resolve(outputDirectory, filename + ".png"), frame);
            }
            finally { dialog.Hide(); await pending; }
        }

        await DialogShot("dialog-create-scheme", CreateScheme);
        deploymentForm["Provider"] = "示例服务商"; deploymentForm["Instance"] = "演示实例"; deploymentForm["NodeName"] = "示例入口";
        deploymentForm["IPv4"] = "192.0.2.10"; deploymentForm["RealityTarget"] = "example.com";
        deploymentForm["Role"] = "RealityEntry"; deploymentForm["Existing"] = false;
        await Shot("deploy-reality-advanced", "deploy", true, true);
        deploymentForm["Role"] = "AnyTlsEntry"; deploymentForm["AnyTlsName"] = "entry.example.com"; deploymentForm["EchPublicName"] = "ech.example.com";
        await Shot("deploy-anytls", "deploy", bottom: true);
        deploymentForm["Role"] = "ShadowsocksLanding"; deploymentForm["NodeName"] = "示例落地"; deploymentForm["TrustedEntries"] = "192.0.2.20";
        await Shot("deploy-landing", "deploy", true, true);
        deploymentForm["Roles"] = new JsonArray("RealityEntry", "AnyTlsEntry", "ShadowsocksLanding"); deploymentForm["ActiveEntry"] = "RealityEntry";
        await Shot("deploy-multiple", "deploy"); deploymentForm.Remove("Roles");
        deploymentForm["Existing"] = true; await Shot("deploy-existing", "deploy");
        await Shot("instances-recovery", "instances", true, true);
        await Shot("network-page", "network");
        var instance = store.ListInstances().First().Plan;
        await DialogShot("dialog-protocol-management", () => OperationSheet(OperationKind.ProtocolState, instance));
        await DialogShot("dialog-network", () => OperationSheet(OperationKind.TuneNetwork, instance));
        await DialogShot("dialog-monitor", () => OperationSheet(OperationKind.Komari, instance));

        scheme = ClientSchemes.New(paths); scheme["Name"] = "示例连接方案";
        scheme["Nodes"] = new JsonArray(
            new JsonObject { ["name"] = "示例入口", ["kind"] = "entry", ["region_group"] = "US-West-LA Entry", ["transit_group"] = "US-West-LA Entry", ["clash"] = new JsonObject { ["type"] = "vless", ["server"] = "192.0.2.10", ["port"] = 443, ["servername"] = "example.com" }, ["sing_box"] = new JsonObject() },
            new JsonObject { ["name"] = "示例落地", ["kind"] = "landing", ["transit_group"] = "US-West-LA Entry", ["clash"] = new JsonObject { ["type"] = "ss", ["server"] = "192.0.2.20", ["port"] = 45001, ["cipher"] = "2022-blake3-aes-128-gcm" }, ["sing_box"] = new JsonObject() });
        designerStep = 0; await Shot("clients-targets", "clients");
        designerStep = 1; await Shot("clients-nodes", "clients");
        designerStep = 2; await Shot("clients-connections", "clients", true);
        designerStep = 3;
        await Shot("clients-publish", "clients", true, true);
        await DialogShot("dialog-node-entry", () => EditNode(0));
        await DialogShot("dialog-node-landing", () => EditNode(1));
        await DialogShot("dialog-business-groups", EditBusinessGroups);
        await DialogShot("dialog-exit-order", EditExitOrder);
        await Shot("settings-expanded", "settings", true);
        await DialogShot("dialog-review", async () => { await ConfirmAsync(new("审阅并执行", "示例任务：调整指定实例的网络参数。\n\n仅展示确认界面；本次截图不执行操作。"), CancellationToken.None); });
        await DialogShot("dialog-credential", async () => { await SecretAsync("示例实例的 SSH 登录密码", CancellationToken.None); });
        scheme = null;
    }

    private static IEnumerable<T> Find<T>(DependencyObject root) where T : DependencyObject
    {
        if (root is T match) yield return match;
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
            foreach (var item in Find<T>(VisualTreeHelper.GetChild(root, i))) yield return item;
    }
}
