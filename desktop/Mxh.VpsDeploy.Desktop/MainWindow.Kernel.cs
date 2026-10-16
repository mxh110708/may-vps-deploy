using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private readonly Dictionary<string, JsonObject> bbrChoices = new();
    private string BbrChoice(string relative) => bbrChoices[relative].Text("Version", "Current");
    private void KernelPanel(StackPanel panel, string relative, JsonObject state)
    {
        var file = SafePath.Resolve(paths.Instance(relative), "network-bbr-choice.json");
        if (!bbrChoices.TryGetValue(relative, out var model)) bbrChoices[relative] = model = File.Exists(file) ? ArchiveStore.ReadJson(file) : new() { ["Version"] = "Current" };
        var choice = Choice("BBR 版本", model, "Version", [("Current", "VPS 原有内核自带版本（默认）"), ("v3", "BBR v3 · Google 官方源码 / MXH 固定预编译")]);
        var details = new StackPanel { Spacing = 12 };
        var content = Column(SectionHeading("拥塞控制版本", Symbol.Setting, "原有版本沿用 VPS 内核。v3 固定版使用随应用提供的预编译包，安装与重启分别审阅。"), choice, details);
        Task Run(string action) => Submit(new(OperationKind.BbrKernel, relative, new JsonObject { ["Action"] = action }));
        void Refresh()
        {
            details.Children.Clear(); var kernel = state["KernelUpgrade"] as JsonObject;
            if (kernel != null)
            {
                if (kernel.Text("Owner") != BbrKernels.Owner) { details.Children.Add(Text("此归档含不受支持来源的内核事务，未迁移或处理其记录。", 14, true)); return; }
                details.Children.Add(Text(BbrKernels.PhaseLabel(kernel.Text("Phase")), 16));
                if (kernel.Text("Phase") == "InstallFailed" && SafeFailures.Kernel(kernel.Text("FailureCode")) is { } failure) details.Children.Add(Text(failure.Message, 14, true));
                details.Children.Add(Text("VPS 原有内核：" + kernel.Text("OriginalKernel", kernel.Text("OldKernel", "待核对")) + " · 上一内核：" + kernel.Text("OldKernel") + " · 目标内核：" + kernel.Text("Catalog.Kernel") + " · 运行 BBR：" + kernel.Text("Runtime.BbrVersion", "待重启验收"), 13, true));
                var buttons = Row(Action("核对内核事务", () => Run("Reconcile")));
                if ((kernel.Text("Phase") is "Prepared" or "RolledBack" or "Aborted") && kernel.Text("NewImageSha256") != "" && new[] { kernel.Text("OldKernel"), kernel.Text("OriginalKernel", kernel.Text("OldKernel")) }.Contains(kernel.Text("Runtime.Kernel", kernel.Text("OldKernel")))) buttons.Children.Add(Action("审阅重启到 BBR v3", () => Run("Activate"), true));
                if (kernel.Text("Phase") is not ("Installing" or "RolledBack" or "Aborted")) buttons.Children.Add(Action("审阅回退上一内核", () => Run("Rollback")));
                if (kernel.Text("Phase") != "Installing" && kernel.Text("OriginalKernel", kernel.Text("OldKernel")) != kernel.Text("OldKernel") && kernel.Text("Runtime.Kernel") != kernel.Text("OriginalKernel")) buttons.Children.Add(Action("审阅回到 VPS 原有内核", () => Run("RollbackOriginal")));
                details.Children.Add(buttons);
                if (BbrKernels.Pending(state)) details.Children.Add(Text("请先结束本轮内核事务，再测速或应用网络配置。关闭应用不会重复安装；重新打开后可核对恢复。", 14, true));
            }
            if (model.Text("Version") != "v3") return;
            details.Children.Add(Text(BbrKernels.SourceNotice, 14, true));
            details.Children.Add(Text(BbrKernels.PackageLabel, 14));
            var check = state["LastKernelCheck"] as JsonObject;
            details.Children.Add(Action("检查 BBR v3 与升级兼容性", () => Run("Check")));
            if (check != null)
            {
                details.Children.Add(Text("最近检查：" + check.Text("Kernel") + " · BBR：" + check.Text("BbrVersion") + " · " + NetworkTime(check.Text("At")), 14));
                foreach (var reason in check.Strings("Reasons")) details.Children.Add(Text(reason, 13, true));
            }
            if (check?.Flag("Compatible") == true && !BbrKernels.Pending(state))
            {
                JsonObject catalog;
                try { catalog = BbrKernels.Catalog(paths); }
                catch (OperationException error) { details.Children.Add(Text(error.Message, 13, true)); return; }
                details.Children.Add(Text("官方源码提交：" + catalog.Text("Commit") + " · " + catalog.Text("SourceDate") + "\n基础内核：" + catalog.Text("BaseKernel") + " · 本应用构建目标：" + catalog.Text("Kernel") + "；上一内核及 VPS 原有内核保留。", 13, true));
                details.Children.Add(Text(BbrKernels.InstallDescription(catalog), 13, true));
                if (check.Text("Kernel") == catalog.Text("Kernel")) details.Children.Add(Text("已经运行此目标版本，无需重复安装或重启。", 14, true));
                else if (kernel?.Text("NewImageSha256") is { Length: > 0 } && kernel.Text("Catalog.Sha256") == catalog.Text("Sha256")) details.Children.Add(Text("该版本已安装并保留，可直接审阅重启。", 13, true));
                else if (BbrKernels.CanUpgrade(kernel, check, catalog)) details.Children.Add(Action(kernel?.Text("Phase") == "Committed" ? "审阅升级 BBR v3 内核" : "审阅安装 BBR v3 内核", () => Submit(new(OperationKind.BbrKernel, relative, new JsonObject { ["Action"] = "Install", ["CatalogId"] = catalog.Text("Id"), ["CatalogSha256"] = catalog.Text("Sha256"), ["SourceCommit"] = catalog.Text("Commit") })), true));
                else details.Children.Add(Text("此源码目标不适用于当前状态，可能基础内核较旧或运行版本没有受管来源；不会隐式降级覆盖。", 13, true));
            }
            details.Children.Add(Text("v3 仅使用随应用提供的固定预编译包，VPS 无需完整源码或编译工具。内核包由我们在开发机验证后随应用版本更新。", 13, true));
            if (kernel?.Text("Phase") == "Committed") details.Children.Add(Text("已验收的受管 v3 可直接升级到更新的受信任版本。每轮独立审阅安装和重启；失败时可回退上一版，也可回到 VPS 原有内核。", 13, true));
            details.Children.Add(Text("只有已验收的 Google 源码受管内核且运行版本为 v3，才能应用本项配置。沿用现有内核请选择原有内核版本。", 13, true));
        }
        choice.SelectionChanged += (_, _) => { ArchiveStore.WriteJson(file, model); Refresh(); }; Refresh(); panel.Children.Add(Card(content));
    }
}
