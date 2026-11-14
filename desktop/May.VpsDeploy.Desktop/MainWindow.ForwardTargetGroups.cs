using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private static void UpdateForwardGroupHealth(JsonObject rule)
    {
        if (rule["TargetGroup"] is JsonObject group)
            group["Health"] = rule.Text("Validation.Type") == "Proxy" ? new JsonObject { ["Type"] = "Connect" } : rule["Validation"]!.DeepClone();
    }
    private StackPanel ForwardGroupEditor(JsonObject rule, string prefix, int index, JsonObject? savedState = null)
    {
        var draft = rule["TargetGroup"] as JsonObject ?? ForwardTargetGroups.New(rule);
        var toggle = new CheckBox { Content = "使用显式主备目标组（上方目标为主）", IsChecked = rule["TargetGroup"] != null, Tag = prefix + ".Group." + index };
        var content = new StackPanel { Spacing = 10, Visibility = toggle.IsChecked == true ? Visibility.Visible : Visibility.Collapsed };
        var address = Field("备用 IP 地址", draft, "BackupAddress"); address.Tag = prefix + ".BackupAddress." + index;
        var port = Field("备用端口", draft, "BackupPort", numeric: true); port.Tag = prefix + ".BackupPort." + index;
        var interval = Field("探测间隔（5–300 秒）", draft, "IntervalSeconds", numeric: true); interval.Tag = prefix + ".GroupInterval." + index;
        var timeout = Field("单目标超时（1–10 秒）", draft, "TimeoutSeconds", numeric: true); timeout.Tag = prefix + ".GroupTimeout." + index;
        var failures = Field("连续失败确认（2–10 次）", draft, "FailureThreshold", numeric: true); failures.Tag = prefix + ".GroupFailures." + index;
        var recoveries = Field("连续恢复确认（2–10 次）", draft, "RecoveryThreshold", numeric: true); recoveries.Tag = prefix + ".GroupRecoveries." + index;
        var hold = Field("首选恢复持续时间（10–600 秒）", draft, "RecoveryHoldSeconds", numeric: true); hold.Tag = prefix + ".GroupHold." + index;
        var auto = new CheckBox { Content = "首选稳定恢复后自动返回", IsChecked = draft.Flag("AutoReturn"), Tag = prefix + ".GroupReturn." + index };
        auto.Checked += (_, _) => draft["AutoReturn"] = true; auto.Unchecked += (_, _) => draft["AutoReturn"] = false;
        content.Children.Add(Fields(address, port)); content.Children.Add(Fields(interval, timeout)); content.Children.Add(Fields(failures, recoveries)); content.Children.Add(hold); content.Children.Add(auto);
        content.Children.Add(Text("先完成主备两端健康与实际入口验收。TCP 的 TLS 校验证书，SSH 只读协议响应；代理健康仅为连接可达性，主备须保留相同鉴权／TLS。UDP 主备仅用于 DNS／原样回显，不以 TCP 探测判断加密 UDP。", 13, true));
        content.Children.Add(Text("切换按 VPS 实际探测确认，Deploy 关闭后仍可工作；已有 TCP 不迁移或重放。两端均失效不回退直连。无连接／会话后工作进程退出，下次激活重新按明确顺序选择。", 13, true));
        if (savedState != null)
        {
            var observation = (savedState["TargetGroups"] as JsonArray)?.OfType<JsonObject>().SingleOrDefault(g => g.Text("Id") == rule.Text("Id"));
            if (observation != null) content.Children.Add(Text("上次检查的目标组状态：" + observation.Text("State", "Unknown") + "。此处为检查快照，当前状态请执行“只读检查已保存转发”。", 13, true));
        }
        toggle.Checked += (_, _) => { rule["TargetGroup"] = draft; UpdateForwardGroupHealth(rule); content.Visibility = Visibility.Visible; };
        toggle.Unchecked += (_, _) => { rule.Remove("TargetGroup"); content.Visibility = Visibility.Collapsed; };
        return Column(toggle, content);
    }
}
