#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private UIElement TunnelAccessPanel(JsonObject plan, JsonObject state)
    {
        var options = new JsonObject { ["PublicUrl"] = state.Text("TunnelAccess.PublicUrl", plan.Text("Cloudflared.PublicUrl")) };
        var controller = MaintenanceTargets.Monitoring(plan, state).Single(t => t.Scope == "KomariController");
        var status = Text("", 14, true); var hostname = Text("", 14);
        var url = Field("公开主控 HTTPS 网址", options, "PublicUrl");
        var check = Action("验证公开访问", () => Submit(new(OperationKind.TunnelAccess, selectedInstance!, options)));
        var panel = Column(SectionHeading("完成 Tunnel 公开访问", Symbol.Link),
            Text("1 · 连接器已安装。连接成功后再在 Cloudflare 配置路由；仅安装连接器不代表公开访问已完成。", 14, true),
            Text("2 · 在这个 Tunnel 添加路由 → 已发布的应用程序。填写主机名和下方服务 URL，路径留空；其他选项通常保持默认。", 14, true),
            url, hostname, Text("服务 URL：" + TunnelAccess.ServiceUrl(plan), 14),
            Text(controller.Installed ? "使用 HTTP 回环地址作为服务 URL；公开访问网址使用 HTTPS。" : "请先安装本机 Komari 主控，再填写服务 URL。连接器可保留，无需重装。", 14, true),
            Text("3 · 保存 Cloudflare 路由后点击验证公开访问。通过后打开主控，以 admin 和安装时设置的密码登录并创建节点，再安装 Agent。", 14, true),
            status, check);
        void Refresh()
        {
            // A TextChanged notification can arrive before the generic field
            // binding is updated. Use the current control value for both.
            options["PublicUrl"] = url.Text.Trim();
            string? normalized = null;
            try { normalized = TunnelAccess.NormalizeUrl(options.Text("PublicUrl")); } catch (OperationException) { }
            hostname.Text = "主机名：" + (normalized == null ? "填写公开网址后显示" : new Uri(normalized).Host);
            check.IsEnabled = normalized != null && controller.Installed && plan.Number("KomariController.Port") > 0;
            var same = normalized != null && normalized == state.Text("TunnelAccess.PublicUrl");
            status.Text = same && state.Text("TunnelAccess.Status") == "Passed" ? "上次已验证：" + LocalTime(state.Text("TunnelAccess.At")) + " · 接口与本机主控版本一致" : same && state.Text("TunnelAccess.Status") == "Failed" ? "公开访问未通过：" + TunnelAccess.Failure(state.Text("TunnelAccess.Code"), state.Number("TunnelAccess.Evidence.HttpStatus")) : "公开访问待配置 / 待验证";
        }
        url.TextChanged += (_, _) => Refresh(); url.Loaded += (_, _) => Refresh(); Refresh();
        return Card(panel);
    }
}
