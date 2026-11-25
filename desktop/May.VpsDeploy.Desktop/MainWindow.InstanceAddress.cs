using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using Microsoft.UI.Xaml.Controls;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task InstanceAddressSheet(string relative, JsonObject plan)
    {
        var options = InstanceAddressChanges.Options(plan);
        var ipv4 = Field("新 IPv4 地址", options, "IPv4"); ipv4.Tag = "InstanceAddress.IPv4";
        var ipv6 = Field("IPv6 地址（未变更时保留）", options, "IPv6"); ipv6.Tag = "InstanceAddress.IPv6";
        var error = Text("", 13); error.Tag = "InstanceAddress.Error";
        var content = Column(Text(plan.Text("NodeName"), 18), Text("当前管理地址：" + plan.Text("Server.IPv4"), 14, true), ipv4, ipv6,
            Text("用于服务商已经完成的地址替换。先核对原 SSH 主机身份，再审阅关联实例、白名单、转发、隧道和客户端来源；运行规则与持久规则一并核对。", 14, true),
            Text("客户端导出文件仍需单独审阅后导出并手动加载。重装后的新主机身份须单独接入；此处不接受新 SSH 身份。", 13, true), error);
        var dialog = OperationDialog("实例换址与依赖", DialogScroll(content), "检查并审阅");
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try { InstanceAddressChanges.Validate(new(OperationKind.InstanceAddress, relative, options)); if (options.Text("IPv4") == plan.Text("Server.IPv4") && options.Text("IPv6") == plan.Text("Server.IPv6")) throw new OperationException("地址没有变化。"); }
            catch (OperationException e) { args.Cancel = true; error.Text = e.Message; }
        };
        if (await ShowDialog(dialog) != ContentDialogResult.Primary) return;
        await Submit(new(OperationKind.InstanceAddress, relative, options));
    }
}
