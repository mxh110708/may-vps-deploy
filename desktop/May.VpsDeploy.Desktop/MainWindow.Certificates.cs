using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task CertificatesSheet(string relative, JsonObject plan, string initialId = "")
    {
        var certificates = InboundCatalog.Items(plan["InboundModel"] as JsonObject ?? InboundCatalog.Empty(), "Certificates").Where(ManagedCertificates.Managed).ToArray();
        var selection = new JsonObject { ["Action"] = certificates.Length == 0 ? "Issue" : "Check", ["Id"] = initialId != "" ? initialId : certificates.FirstOrDefault()?.Text("Id") ?? "" };
        var freshId = Guid.NewGuid().ToString("N");
        var draft = new JsonObject { ["Name"] = "", ["Zone"] = "", ["Email"] = "", ["Domains"] = "", ["Propagation"] = 30, ["TokenFile"] = "" };
        var action = Choice("证书操作", selection, "Action", [("Issue", "申请新证书并启用自动续期"), ("Check", "检查远端证书与共享入站"), ("Renew", "检查到期并续期部署"), ("Disable", "停用自动续期，保留证书"), ("Enable", "启用自动续期"), ("RotateToken", "替换 Cloudflare 授权"), ("Remove", "移除无引用的托管证书")]); action.Tag = "Certificates.Action";
        var rows = Column(); var error = Text("", 13, true); error.Tag = "Certificates.Error";
        void Refresh()
        {
            rows.Children.Clear(); error.Text = "";
            if (selection.Text("Action") == "Issue")
            {
                foreach (var (field, title) in new[] { ("Name", "证书名称"), ("Zone", "Cloudflare 区域域名"), ("Email", "ACME 联系邮箱"), ("Domains", "证书域名（逗号或换行分隔，最多8个）") }) { var input = Field(title, draft, field); input.Tag = "Certificates." + field; rows.Children.Add(input); }
                var propagation = Field("DNS 等待时间（10–300秒）", draft, "Propagation", numeric: true); propagation.Tag = "Certificates.Propagation"; rows.Children.Add(propagation);
            }
            else
            {
                var choice = Choice("托管证书", selection, "Id", certificates.Select(c => (c.Text("Id"), c.Text("Name"))), true); choice.Tag = "Certificates.Resource";
                choice.SelectionChanged += (_, _) => Refresh(); rows.Children.Add(choice);
                var selected = certificates.SingleOrDefault(c => c.Text("Id") == selection.Text("Id"));
                if (selected != null)
                {
                    var state = InstanceState(relative); var observed = state.At("Certificates." + selected.Text("Id") + ".Observation");
                    rows.Children.Add(Text("域名：" + string.Join("，", selected["Managed"]!.Strings("Domains")) + "\n最近核对有效期：" + (observed?.Text("NotAfter") ?? selected.Text("NotAfter")) + "\n自动续期：" + (observed?.Flag("Enabled") == true ? "已启用" : "已停用或尚未核对") + "\n上次续期错误：" + observed?.Text("ErrorCode", "无") + "\n引用入站（含停用）：" + string.Join("，", InboundCatalog.Items(plan["InboundModel"]!.AsObject(), "Inbounds").Where(i => i.Text("CertificateId") == selected.Text("Id")).Select(i => i.Text("Name"))), 14, true));
                }
            }
            if (selection.Text("Action") is "Issue" or "RotateToken") { var token = Field("Cloudflare Token 私密文件路径", draft, "TokenFile"); token.Tag = "Certificates.TokenFile"; rows.Children.Add(token); }
        }
        action.SelectionChanged += (_, _) => Refresh(); Refresh();
        var panel = Column(Text("Cloudflare DNS-01 通过现有 Certbot 插件申请；同一区域最多8个域名，可使用单层通配符。首次申请后在「管理入站」选择该证书。VPS 独立定时检查续期，关闭 Deploy 后仍可运行；续期重启当前启用的引用入站，已有连接可能短暂重连。停用续期保留现有证书。", 14, true), action, rows, error);
        var dialog = OperationDialog("托管证书与自动续期", DialogScroll(panel), "审阅"); JsonObject? options = null;
        dialog.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                var issuing = selection.Text("Action") == "Issue"; var certificate = certificates.SingleOrDefault(c => c.Text("Id") == selection.Text("Id"));
                if (!issuing && certificate == null) throw new OperationException("请选择已保存的托管证书。");
                var policy = issuing ? ManagedCertificates.Policy(draft.Text("Zone"), draft.Text("Email"), draft.Text("Domains").Split([',', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), draft.Number("Propagation")) : certificate!["Managed"]!.AsObject();
                options = ManagedCertificates.Options(InstanceState(relative), selection.Text("Action"), issuing ? freshId : certificate!.Text("Id"), issuing ? draft.Text("Name") : certificate!.Text("Name"), policy, selection.Text("Action") is "Issue" or "RotateToken" ? draft.Text("TokenFile") : "");
                ManagedCertificates.Prepare(store, new(OperationKind.ManagedCertificate, relative, options));
            }
            catch (OperationException e) { error.Text = e.Message; args.Cancel = true; }
        };
        if (await ShowDialog(dialog) == ContentDialogResult.Primary) await Submit(new(OperationKind.ManagedCertificate, relative, options!));
    }
}
