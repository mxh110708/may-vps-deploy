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
        {
            if (rule.Text("Validation.Type") is "Proxy" or "Shadowsocks" && group.Text("Health.Type") == "Proxy") return;
            group["Health"] = rule.Text("Validation.Type") == "Proxy" ? new JsonObject { ["Type"] = "Connect" } : rule["Validation"]!.DeepClone();
        }
    }
    private StackPanel ForwardGroupEditor(JsonObject rule, string prefix, int index, JsonObject? savedState = null)
    {
        var draft = rule["TargetGroup"] as JsonObject ?? ForwardTargetGroups.New(rule);
        var mode = new ComboBox { Header = "目标分配方式", HorizontalAlignment = HorizontalAlignment.Stretch, Tag = prefix + ".GroupStrategy." + index };
        foreach (var (key, label) in new[] { ("Failover", "主备"), ("RoundRobin", "轮询"), ("SourceIpHash", "来源 IP 哈希") }) mode.Items.Add(new ComboBoxItem { Content = label, Tag = key });
        var current = ForwardTargetGroups.Balanced(rule) ? rule.Text("TargetGroup.Strategy") : "Failover";
        mode.SelectedItem = mode.Items.Cast<ComboBoxItem>().Single(i => (string)i.Tag == current);
        var body = new StackPanel(); var note = Text("同一入口分配新连接／会话。哈希按真实来源 IP；同一 NAT 用户可能集中。切换为主备前须先移除多余目标。", 13, true);
        void Render() { body.Children.Clear(); body.Children.Add(draft.Number("Version") == 2 ? ForwardMultiGroupEditor(rule, draft, prefix, index, savedState) : LegacyForwardGroupEditor(rule, prefix, index, savedState, draft)); }
        Render();
        mode.SelectionChanged += (_, _) =>
        {
            var selected = (string)((ComboBoxItem)mode.SelectedItem).Tag;
            if (selected == current) return;
            if (selected == "Failover" && draft["AdditionalTargets"] is JsonArray { Count: > 1 })
            {
                note.Text = "主备只支持两个目标；请先移除多余目标，再切换分配方式。";
                mode.SelectedItem = mode.Items.Cast<ComboBoxItem>().Single(i => (string)i.Tag == current); return;
            }
            var old = rule["TargetGroup"] as JsonObject ?? draft;
            if (selected == "Failover")
            {
                var next = ForwardTargetGroups.New(rule);
                if (old?.At("AdditionalTargets") is JsonArray { Count: 1 } targets) { next["BackupAddress"] = targets[0]!.Text("Address"); next["BackupPort"] = targets[0]!.Number("Port"); }
                rule["TargetGroup"] = next;
            }
            else if (old.Number("Version") == 2) { rule["TargetGroup"] = old; rule["TargetGroup"]!["Strategy"] = selected; }
            else
            {
                var next = ForwardTargetGroups.NewBalanced(rule, selected);
                if (old != null)
                {
                    next["AdditionalTargets"]![0]!["Address"] = old.Text("BackupAddress"); next["AdditionalTargets"]![0]!["Port"] = old.Number("BackupPort");
                    foreach (var key in new[] { "IntervalSeconds", "TimeoutSeconds", "FailureThreshold", "RecoveryThreshold", "RecoveryHoldSeconds" }) next[key] = old[key]!.DeepClone();
                }
                rule["TargetGroup"] = next;
            }
            // A different policy requires fresh, explicit protocol-health consent.
            current = selected; draft = rule["TargetGroup"]!.AsObject(); Render();
        };
        return Column(mode, note, body);
    }
    private StackPanel ForwardMultiGroupEditor(JsonObject rule, JsonObject draft, string prefix, int index, JsonObject? savedState)
    {
        var toggle = new CheckBox { Content = "启用多目标组（上方目标为目标 1）", IsChecked = true, Tag = prefix + ".Group." + index };
        var content = new StackPanel { Spacing = 10 };
        var targetRows = new StackPanel { Spacing = 10 };
        var healthArea = new StackPanel { Spacing = 10 };
        void RenderHealth()
        {
            healthArea.Children.Clear();
            if (rule.Text("Validation.Type") is not ("Proxy" or "Shadowsocks")) return;
            var health = draft.Text("Health.Type") == "Proxy" ? draft["Health"]!.AsObject() : ForwardProxyHealth.NewBalanced(rule);
            var consent = new CheckBox { Content = "启用协议健康，并授权在此 VPS 私有保存所选来源的探测凭据", IsChecked = health.Flag("Consent"), Tag = prefix + ".ProxyHealth." + index };
            var settings = Column(Choice("HTTPS 出口地址族", health, "EgressFamily", [("IPv4", "IPv4"), ("IPv6", "IPv6")]));
            foreach (var (identity, targetIndex) in ForwardTargetGroups.TargetIds(rule).Select((id, i) => (id, i))) settings.Children.Add(Field($"目标 {targetIndex + 1} 预期出口 IP（留空仅检查地址族）", health["ExpectedExits"]!.AsObject(), identity));
            settings.Visibility = consent.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            consent.Checked += (_, _) => { health["Consent"] = true; draft["Health"] = health; settings.Visibility = Visibility.Visible; };
            consent.Unchecked += (_, _) => { health["Consent"] = false; draft["Health"] = rule.Text("Validation.Type") == "Proxy" ? new JsonObject { ["Type"] = "Connect" } : rule["Validation"]!.DeepClone(); settings.Visibility = Visibility.Collapsed; };
            healthArea.Children.Add(consent); healthArea.Children.Add(settings);
        }
        void RenderTargets()
        {
            targetRows.Children.Clear(); var targets = draft["AdditionalTargets"]!.AsArray();
            foreach (var (target, targetIndex) in targets.OfType<JsonObject>().Select((t, i) => (t, i + 2)).ToArray())
            {
                var address = Field($"目标 {targetIndex} IP", target, "Address"); address.Tag = prefix + ".GroupTargetAddress." + index + "." + targetIndex;
                var port = Field("端口", target, "Port", numeric: true); port.Tag = prefix + ".GroupTargetPort." + index + "." + targetIndex;
                var remove = Action("移除此目标", () =>
                {
                    if (targets.Count <= 1) return Task.CompletedTask;
                    var id = target.Text("Id"); targets.Remove(target);
                    if (draft.At("Health.ExpectedExits") is JsonObject exits) exits.Remove(id);
                    RenderTargets(); RenderHealth(); return Task.CompletedTask;
                });
                remove.IsEnabled = targets.Count > 1; targetRows.Children.Add(Column(Fields(address, port), remove));
            }
        }
        var add = Action("添加目标（总计最多 8 个）", () =>
        {
            var targets = draft["AdditionalTargets"]!.AsArray(); if (targets.Count >= ForwardTargetGroups.MaximumTargets - 1) return Task.CompletedTask;
            var id = Guid.NewGuid().ToString("N"); targets.Add(new JsonObject { ["Id"] = id, ["Address"] = "", ["Port"] = rule.Number("TargetPort") });
            if (draft.At("Health.ExpectedExits") is JsonObject exits) exits[id] = "";
            RenderTargets(); RenderHealth(); return Task.CompletedTask;
        });
        content.Children.Add(targetRows); content.Children.Add(add);
        content.Children.Add(Fields(Field("探测间隔（须容纳全部目标超时，5–300 秒）", draft, "IntervalSeconds", numeric: true), Field("单目标超时（1–10 秒）", draft, "TimeoutSeconds", numeric: true)));
        content.Children.Add(Fields(Field("连续失败摘除（2–10 次）", draft, "FailureThreshold", numeric: true), Field("连续恢复确认（2–10 次）", draft, "RecoveryThreshold", numeric: true)));
        content.Children.Add(Field("恢复持续时间（10–600 秒）", draft, "RecoveryHoldSeconds", numeric: true)); content.Children.Add(healthArea);
        content.Children.Add(Text("所有目标须提供相同协议、鉴权与 TLS 身份；保存前逐目标验收。TLS 校验证书，SSH 只检查协议响应。代理 TCP 可选完整协议健康，SS／SS2022 UDP 必须明确授权协议健康。每组最多一个受限核心，每组件最多 4 个协议健康组。", 13, true));
        content.Children.Add(Text((rule["ProxyReceive"] != null ? "轮询按新连接分配；TCP 哈希使用通过可信中转与客户端网段核对的声明 IP。" : "轮询按新连接／UDP 会话分配；哈希仅使用 socket 来源 IP，不读取 PROXY 声明。") + "故障摘除、稳定恢复只影响新分配；已有 TCP 不迁移，UDP 失效会话关闭，后续新数据报重新分配，不重发旧报文。全部失效时停止转发。重启后重新探测，连接、会话和轮询游标不持久化。", 13, true));
        if (savedState?.At("TargetGroups") is JsonArray observations && observations.OfType<JsonObject>().SingleOrDefault(g => g.Text("Id") == rule.Text("Id")) is JsonObject observation) content.Children.Add(Text("上次检查状态：" + observation.Text("State", "Unknown") + "；当前状态请执行只读检查。", 13, true));
        toggle.Checked += (_, _) => { rule["TargetGroup"] = draft; UpdateForwardGroupHealth(rule); content.Visibility = Visibility.Visible; };
        toggle.Unchecked += (_, _) => { rule.Remove("TargetGroup"); content.Visibility = Visibility.Collapsed; };
        RenderTargets(); RenderHealth(); return Column(toggle, content);
    }
    private StackPanel LegacyForwardGroupEditor(JsonObject rule, string prefix, int index, JsonObject? savedState = null, JsonObject? retainedDraft = null)
    {
        var draft = rule["TargetGroup"] as JsonObject ?? retainedDraft ?? ForwardTargetGroups.New(rule);
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
        if (rule.Text("Validation.Type") is "Proxy" or "Shadowsocks")
        {
            var health = draft.Text("Health.Type") == "Proxy" ? draft["Health"]!.AsObject() : ForwardProxyHealth.New();
            var consent = new CheckBox { Content = "启用协议健康，并授权在此 VPS 私有保存所选来源的探测凭据", IsChecked = health.Flag("Consent"), Tag = prefix + ".ProxyHealth." + index };
            var settings = Column(Choice("探测 HTTPS 出口地址族", health, "EgressFamily", [("IPv4", "IPv4"), ("IPv6", "IPv6")]), Field("主目标预期出口 IP（留空仅检查地址族）", health, "PrimaryExit"), Field("备用预期出口 IP（留空仅检查地址族）", health, "BackupExit"));
            settings.Visibility = consent.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            consent.Checked += (_, _) => { health["Consent"] = true; draft["Health"] = health; settings.Visibility = Visibility.Visible; };
            consent.Unchecked += (_, _) => { health["Consent"] = false; if (rule.Text("Validation.Type") == "Proxy") draft["Health"] = new JsonObject { ["Type"] = "Connect" }; settings.Visibility = Visibility.Collapsed; };
            content.Children.Add(consent); content.Children.Add(settings);
            content.Children.Add(Text("固定核心验证代理鉴权、可信 HTTPS 与实际出口；SS／SS2022 UDP 还验证加密 DNS 回程。每组一个核心子进程，含转发的内存上限 160 MiB，每组件最多 4 组。主备必须使用同一套鉴权和 TLS 身份。UDP 加密主备必须明确授权，不能用端口可达代替。", 13, true));
        }
        content.Children.Add(Text("先完成主备两端健康与实际入口验收。TLS 校验证书，SSH 只读协议响应；未启用协议健康的旧代理 TCP 组仍只检查连接。普通 UDP 使用 DNS／原样回显；凭据与健康方式变化后须重新审阅。", 13, true));
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
