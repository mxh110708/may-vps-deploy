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
    private async Task<JsonObject> ServerOutboundRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("服务器出站界面验证只允许合成工作区。");
        static void Require(bool value, string message) { if (!value) throw new OperationException(message); }
        void Press(ContentDialog dialog, string name)
        {
            var button = Find<Button>(dialog).Single(b => b.Name == name);
            Require(button.IsEnabled, "出站对话框按钮不可用。");
            var peer = FrameworkElementAutomationPeer.CreatePeerForElement(button) ?? new ButtonAutomationPeer(button);
            ((IInvokeProvider)peer.GetPattern(PatternInterface.Invoke)).Invoke();
        }
        Task? operation = null;
        async Task<ContentDialog> Dialog(ContentDialog? old = null)
        {
            var until = DateTimeOffset.UtcNow.AddSeconds(6);
            while ((activeTestDialog == null || activeTestDialog == old || !Find<Button>(activeTestDialog).Any(b => b.Name == "CloseButton")) && DateTimeOffset.UtcNow < until) { if (operation?.IsFaulted == true) await operation; shell.UpdateLayout(); await Task.Delay(30); }
            if (operation?.IsFaulted == true) await operation;
            Require(activeTestDialog != null && activeTestDialog != old, "服务器出站对话框未打开。"); shell.UpdateLayout(); return activeTestDialog!;
        }
        async Task Shot(ContentDialog dialog, string file)
        {
            var visual = Find<Border>(dialog).Where(b => b.ActualWidth >= 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)dialog;
            await Capture(SafePath.Resolve(output, file), visual);
        }
        var previous = selectedInstance; var template = store.ListInstances().First(); var plan = template.Plan.DeepClone().AsObject();
        plan["Provider"] = "Example"; plan["Instance"] = "Round3-" + Guid.NewGuid().ToString("N")[..8]; plan["Role"] = "AnyTlsEntry"; plan["Roles"] = new JsonArray("AnyTlsEntry"); plan["ActiveEntry"] = "AnyTlsEntry";
        plan["ProtocolInventory"] = new JsonObject { ["AnyTlsEntry"] = new JsonObject { ["Installed"] = true, ["Enabled"] = true } }; plan.Put("AnyTls.ServerName", JsonValue.Create("entry.example.com"));
        var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative); plan.Put("Paths.Archive", JsonValue.Create(directory));
        var secrets = new JsonObject { ["AnyTls"] = new JsonObject { ["Password"] = "synthetic-round3-entry", ["EchClientConfigPem"] = "synthetic-ech" } };
        var config = ServerConfigurations.AnyTls(plan, secrets); var file = SafePath.Resolve(directory, ServerOutboundRouting.ConfigRelative("AnyTlsEntry")); ArchiveStore.WriteJson(file, config);
        var state = InstanceState(template.RelativePath).DeepClone().AsObject(); state.Put("ServerConfigHashes.AnyTlsEntry", JsonValue.Create(ClientSchemes.SourceFingerprint(file)));
        ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), secrets);
        var source = ClientSchemes.New(paths); source["Name"] = "第三轮合成来源";
        ClientNodeImport.Apply(source, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-round3-private@192.0.2.20:20001#Round3Landing", source, "US-West-LA Entry", "landing"));
        var node = source["Nodes"]![0]!.AsObject(); node["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = "198.51.100.20" }; workbench.Save(source);
        var historyCount = new TaskHistory(store).Read().Count;
        try
        {
            selectedInstance = relative; SelectPage("instances");
            Require(Find<Button>(shell).Any(b => b.Content as string == "配置出站"), "实例页未提供服务器出站入口。");
            var before = ClientSchemes.SourceFingerprint(file); var pending = operation = ServerOutboundSheet(relative, plan, "AnyTlsEntry"); var form = await Dialog();
            await Shot(form, "server-outbound-form.png"); Press(form, "CloseButton"); await pending;
            Require(ClientSchemes.SourceFingerprint(file) == before && taskCancellation == null, "取消出站表单仍执行变更。");
            pending = operation = ServerOutboundSheet(relative, plan, "AnyTlsEntry"); form = await Dialog();
            var choice = Find<ComboBox>(form).Single(c => c.Header as string == "已保存的默认下一跳");
            choice.SelectedIndex = choice.Items.Cast<ComboBoxItem>().ToList().FindIndex(c => c.Tag as string == source.Text("Id") + ":" + node.Text("Id"));
            Require(Find<TextBox>(form).Single(t => t.Header as string == "预期网站出口 IP").Text == "198.51.100.20", "选择节点未带入出口核验地址。");
            var address = Find<TextBox>(form).Single(t => t.Header as string == "预期网站出口 IP"); address.Text = "127.0.0.1"; Press(form, "PrimaryButton"); await Task.Delay(80);
            Require(activeTestDialog == form && Find<TextBlock>(form).Any(t => t.Text.Contains("非回环")), "无效出口地址没有保留表单并提示修正。");
            address.Text = "198.51.100.20";
            Press(form, "PrimaryButton"); var review = await Dialog(form);
            var reviewText = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text));
            Require(reviewText.Contains("Round3Landing") && reviewText.Contains("预期网站出口") && reviewText.Contains("TCP 与 UDP") && !reviewText.Contains("synthetic-round3-private") && !reviewText.Contains("synthetic-round3-entry"), "出站审阅缺少范围或显示凭据。");
            await Shot(review, "server-outbound-review.png"); Press(review, "CloseButton"); await pending;
            Require(ClientSchemes.SourceFingerprint(file) == before && new TaskHistory(store).Read().Count == historyCount && taskCancellation == null, "取消最终审阅仍启动远端任务。");
            var origin = new JsonObject { ["SchemeId"] = source.Text("Id"), ["NodeId"] = node.Text("Id") };
            var applied = ServerOutboundRouting.Build("AnyTlsEntry", config, null, node, "198.51.100.20", plan, origin);
            plan.Put("ServerOutbound.AnyTlsEntry", applied.Metadata!.DeepClone()); ArchiveStore.WriteJson(file, applied.Configuration); state.Put("ServerConfigHashes.AnyTlsEntry", JsonValue.Create(ClientSchemes.SourceFingerprint(file)));
            ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state);
            pending = operation = ServerOutboundSheet(relative, plan, "AnyTlsEntry"); form = await Dialog();
            var action = Find<ComboBox>(form).Single(c => c.Header as string == "本次操作"); action.SelectedIndex = 1;
            Press(form, "PrimaryButton"); review = await Dialog(form);
            Require(Find<TextBlock>(review).Any(t => t.Text.Contains("恢复原 AnyTLS 出口策略")), "移除审阅没有说明原策略恢复。");
            Press(review, "CloseButton"); await pending;
            plan["Roles"] = new JsonArray("RealityEntry", "AnyTlsEntry"); plan.Put("ProtocolInventory.RealityEntry", new JsonObject { ["Installed"] = true, ["Enabled"] = true }); plan.Put("Reality.Target", JsonValue.Create("example.com"));
            secrets["Xray"] = new JsonObject { ["Uuid"] = Guid.NewGuid().ToString(), ["RealityPrivateKey"] = ServerConfigurations.RandomKey(32), ["RealityClientKey"] = ServerConfigurations.RandomKey(32), ["ShortId"] = "abcd1234" };
            var realityFile = SafePath.Resolve(directory, ServerOutboundRouting.ConfigRelative("RealityEntry"));
            var realityRoute = ServerOutboundRouting.Build("RealityEntry", ServerConfigurations.Xray(plan, secrets), null, node, "198.51.100.20", plan, origin);
            plan.Put("ServerOutbound.RealityEntry", realityRoute.Metadata!.DeepClone()); ArchiveStore.WriteJson(realityFile, realityRoute.Configuration); state.Put("ServerConfigHashes.RealityEntry", JsonValue.Create(ClientSchemes.SourceFingerprint(realityFile)));
            ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); store.WriteSecret(SafePath.Resolve(directory, "secrets.dotnet.private.json"), secrets);
            var realityBefore = ClientSchemes.SourceFingerprint(realityFile); var anyTlsBefore = ClientSchemes.SourceFingerprint(file); var sourceBefore = ArchiveStore.Fingerprint(source);
            pending = operation = ServerOutboundSheet(relative, plan, "RealityEntry"); form = await Dialog();
            Require(Find<TextBlock>(form).Any(t => t.Text.Contains("来源与已审阅快照一致")) && Find<ComboBox>(form).Single(c => c.Header as string == "已保存的默认下一跳").SelectedItem is ComboBoxItem selected && selected.Tag as string == source.Text("Id") + ":" + node.Text("Id"), "当前 Reality 下一跳未预选或来源状态错误。");
            var roles = Find<ComboBox>(form).Single(c => c.Header as string == "目标入站组件");
            roles.SelectedIndex = 1; Require(Find<TextBlock>(form).Any(t => t.Text.StartsWith("只处理 anytls-in")), "切到 AnyTLS 没有更新作用范围。");
            roles.SelectedIndex = 0; Require(Find<TextBlock>(form).Any(t => t.Text.StartsWith("Reality 主／备用端口")), "切回 Reality 没有恢复主备双栈作用范围。");
            void RuleButton(string tag)
            {
                var button = Find<Button>(form).Single(b => b.Tag as string == tag); Require(button.IsEnabled, "分流规则操作不可用。");
                ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke(); shell.UpdateLayout();
            }
            void FillRule(int index, int kindIndex, string value, int actionIndex)
            {
                Find<ComboBox>(form).Single(c => c.Tag as string == "ServerRules.Kind." + index).SelectedIndex = kindIndex;
                Find<TextBox>(form).Single(t => t.Tag as string == "ServerRules.Value." + index).Text = value;
                Find<ComboBox>(form).Single(c => c.Tag as string == "ServerRules.Action." + index).SelectedIndex = actionIndex;
            }
            Find<Expander>(form).Single().IsExpanded = true; shell.UpdateLayout(); RuleButton("ServerRules.Add");
            Press(form, "PrimaryButton"); await Task.Delay(60);
            Require(activeTestDialog == form && Find<TextBlock>(form).Any(t => t.Text.Contains("请填写")), "空分流规则没有保留表单。");
            FillRule(0, 0, "AI.EXAMPLE.TEST.", 0); RuleButton("ServerRules.Add"); FillRule(1, 1, "example.test", 1);
            RuleButton("ServerRules.Add"); FillRule(2, 2, "192.0.2.15/24", 2);
            Find<TextBox>(form).Single(t => t.Tag as string == "ServerRules.TestDestination").Text = "ai.example.test";
            RuleButton("ServerRules.Test"); Require(Find<TextBlock>(form).Any(t => t.Text.Contains("试算去向：所选落地")), "首条规则试算错误。");
            RuleButton("ServerRules.Up.1"); RuleButton("ServerRules.Test"); Require(Find<TextBlock>(form).Any(t => t.Text.Contains("试算去向：入口机直连")), "上移规则没有改变试算顺序。");
            RuleButton("ServerRules.Down.0"); RuleButton("ServerRules.Remove.2"); RuleButton("ServerRules.Add"); FillRule(2, 2, "192.0.2.15/24", 2);
            roles.SelectedIndex = 1; Require(!Find<TextBox>(form).Any(t => (t.Tag as string)?.StartsWith("ServerRules.Value.") == true), "Reality 规则草稿泄漏到 AnyTLS。");
            roles.SelectedIndex = 0; shell.UpdateLayout();
            Require(Find<TextBox>(form).Count(t => (t.Tag as string)?.StartsWith("ServerRules.Value.") == true) == 3 && Find<TextBox>(form).Single(t => t.Tag as string == "ServerRules.Value.0").Text == "AI.EXAMPLE.TEST.", "切回组件丢失了分流草稿或未提交文本。");
            RuleButton("ServerRules.Add"); FillRule(3, 1, "ipify.org", 1); Press(form, "PrimaryButton"); await Task.Delay(60);
            Require(activeTestDialog == form && Find<TextBlock>(form).Any(t => t.Text.Contains("验收绕过落地")), "不完整的落地验收路径被接受。");
            RuleButton("ServerRules.Remove.3");
            await Shot(form, "reality-outbound-form.png");
            var scroll = Find<ScrollViewer>(form).OrderByDescending(s => s.ScrollableHeight).First();
            Require(scroll.ChangeView(null, Math.Min(scroll.ScrollableHeight, 650), null, true), "规则编辑区不能滚动。"); shell.UpdateLayout(); await Task.Delay(80);
            Require(Find<TextBox>(form).Where(t => (t.Tag as string)?.StartsWith("ServerRules.Value.") == true).All(t => t.ActualWidth >= 120), "规则输入列被挤压。");
            await Shot(form, "server-destination-editor.png");
            Press(form, "PrimaryButton"); review = await Dialog(form);
            reviewText = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text));
            Require(reviewText.Contains("reality-primary-ipv4") && reviewText.Contains("reality-backup-ipv6") && reviewText.Contains("全部用户，TCP 与 UDP") && !reviewText.Contains(secrets.Text("Xray.RealityPrivateKey")) && !reviewText.Contains(secrets.Text("Xray.Uuid")), "Reality 审阅缺少主备双栈范围或显示凭据。");
            Require(reviewText.Contains("完整域名 ai.example.test → 所选落地") && reviewText.Contains("域名及其子域名 example.test → 入口机直连") && reviewText.Contains("192.0.2.0/24 → 阻断"), "规则审阅未反映规范化结果或顺序。");
            await Shot(review, "reality-outbound-review.png"); Press(review, "CloseButton"); await pending;
            Require(ArchiveStore.Fingerprint(source) == sourceBefore, "切换入站组件修改了来源方案。");
            var savedPolicy = new JsonArray(new JsonObject { ["Kind"] = "Suffix", ["Value"] = "example.test", ["Action"] = "Direct" });
            var withRules = ServerOutboundRouting.Build("RealityEntry", realityRoute.Configuration, realityRoute.Metadata, node, "198.51.100.20", plan, origin, savedPolicy);
            ArchiveStore.WriteJson(realityFile, withRules.Configuration); plan.Put("ServerOutbound.RealityEntry", withRules.Metadata!.DeepClone()); state.Put("ServerConfigHashes.RealityEntry", JsonValue.Create(ClientSchemes.SourceFingerprint(realityFile)));
            ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); realityBefore = ClientSchemes.SourceFingerprint(realityFile);
            pending = operation = ServerOutboundSheet(relative, plan, "RealityEntry"); form = await Dialog();
            Require(Find<TextBox>(form).Single(t => t.Tag as string == "ServerRules.Value.0").Text == "example.test", "现有分流规则未载入表单。");
            Find<ComboBox>(form).Single(c => c.Header as string == "本次操作").SelectedIndex = 1; Press(form, "PrimaryButton"); review = await Dialog(form);
            Require(Find<TextBlock>(review).Any(t => t.Text.Contains("原分流例外") && t.Text.Contains("example.test")), "移除审阅遗漏现有分流规则。");
            Press(review, "CloseButton"); await pending;
            ClientNodeImport.Apply(source, ClientNodeImport.Preview("ss://aes-128-gcm:synthetic-round6-private@192.0.2.21:20002#Round6Extra", source, "US-West-LA Entry", "landing"));
            var extraNode = source["Nodes"]!.AsArray().OfType<JsonObject>().Single(n => n.Text("name") == "Round6Extra"); extraNode["Egress"] = new JsonObject { ["Family"] = "IPv4", ["ExpectedAddress"] = "198.51.100.21" }; workbench.Save(source);
            pending = operation = ServerOutboundSheet(relative, plan, "RealityEntry"); form = await Dialog(); RuleButton("ServerHops.Add");
            var extraChoice = Find<ComboBox>(form).Single(c => c.Tag as string == "ServerHops.Selection.0"); extraChoice.SelectedIndex = extraChoice.Items.Cast<ComboBoxItem>().ToList().FindIndex(c => c.Tag as string == source.Text("Id") + ":" + extraNode.Text("Id"));
            Require(Find<TextBox>(form).Single(t => t.Tag as string == "ServerHops.Address.0").Text == "198.51.100.21", "附加落地未带入独立出口。");
            Press(form, "PrimaryButton"); await Task.Delay(60); Require(activeTestDialog == form && Find<TextBlock>(form).Any(t => t.Text.Contains("没有规则引用")), "未使用的附加落地被接受。");
            Find<Expander>(form).Single().IsExpanded = true; FillRule(0, 0, "AI.EXAMPLE.TEST.", 3); RuleButton("ServerHops.Remove.0");
            Require(Find<ComboBox>(form).Any(c => c.Tag as string == "ServerHops.Selection.0") && Find<TextBlock>(form).Any(t => t.Text.Contains("仍被规则引用")), "被引用落地被直接删除。");
            Find<TextBox>(form).Single(t => t.Tag as string == "ServerRules.TestDestination").Text = "ai.example.test"; RuleButton("ServerRules.Test");
            Require(Find<TextBlock>(form).Any(t => t.Text.Contains("指定落地 · Round6Extra")), "附加落地规则试算未显示实际名称。");
            Find<TextBox>(form).Single(t => t.Tag as string == "ServerHops.Address.0").Text = "198.51.100.25";
            roles = Find<ComboBox>(form).Single(c => c.Header as string == "目标入站组件"); roles.SelectedIndex = 1; Require(!Find<TextBox>(form).Any(t => t.Tag as string == "ServerHops.Address.0"), "附加落地草稿泄漏到另一组件。"); roles.SelectedIndex = 0; shell.UpdateLayout(); await Task.Delay(40);
            Require(Find<TextBox>(form).Single(t => t.Tag as string == "ServerHops.Address.0").Text == "198.51.100.25" && ((ComboBoxItem)Find<ComboBox>(form).Single(c => c.Tag as string == "ServerRules.Action.0").SelectedItem).Tag is string actionTag && actionTag.StartsWith("Hop:"), "附加落地或规则去向草稿丢失。");
            var namedId = ((string)((ComboBoxItem)Find<ComboBox>(form).Single(c => c.Tag as string == "ServerRules.Action.0").SelectedItem).Tag)[4..];
            var hopScroll = Find<ScrollViewer>(form).OrderByDescending(s => s.ScrollableHeight).First(); hopScroll.ChangeView(null, Math.Min(hopScroll.ScrollableHeight, 420), null, true); shell.UpdateLayout(); await Task.Delay(80); await Shot(form, "server-hops-editor.png");
            Press(form, "PrimaryButton"); review = await Dialog(form); reviewText = string.Join('\n', Find<TextBlock>(review).Select(t => t.Text));
            Require(reviewText.Contains("Round6Extra") && reviewText.Contains("198.51.100.25") && reviewText.Contains("ai.example.test → 指定落地 · Round6Extra") && !reviewText.Contains("synthetic-round6-private"), "多落地审阅遗漏独立出口、去向或泄露凭据。");
            await Shot(review, "server-hops-review.png"); Press(review, "CloseButton"); await pending;
            var namedRules = new JsonArray(new JsonObject { ["Kind"] = "Domain", ["Value"] = "ai.example.test", ["Action"] = "NextHop", ["Target"] = namedId });
            var extraOrigin = new JsonObject { ["SchemeId"] = source.Text("Id"), ["NodeId"] = extraNode.Text("Id") };
            var namedRoute = ServerOutboundRouting.Build("RealityEntry", withRules.Configuration, withRules.Metadata, node, "198.51.100.20", plan, origin, namedRules, [new(namedId, extraNode, "198.51.100.21", extraOrigin)]);
            ArchiveStore.WriteJson(realityFile, namedRoute.Configuration); plan.Put("ServerOutbound.RealityEntry", namedRoute.Metadata!.DeepClone()); state.Put("ServerConfigHashes.RealityEntry", JsonValue.Create(ClientSchemes.SourceFingerprint(realityFile))); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-plan.json"), plan); ArchiveStore.WriteJson(SafePath.Resolve(directory, "deployment-state.json"), state); realityBefore = ClientSchemes.SourceFingerprint(realityFile);
            pending = operation = ServerOutboundSheet(relative, plan, "RealityEntry"); form = await Dialog();
            Require(Find<TextBox>(form).Single(t => t.Tag as string == "ServerHops.Address.0").Text == "198.51.100.21" && ((ComboBoxItem)Find<ComboBox>(form).Single(c => c.Tag as string == "ServerRules.Action.0").SelectedItem).Tag as string == "Hop:" + namedId, "已保存多落地未正确预选。");
            Find<ComboBox>(form).Single(c => c.Header as string == "本次操作").SelectedIndex = 1; Press(form, "PrimaryButton"); review = await Dialog(form); Require(Find<TextBlock>(review).Any(t => t.Text.Contains("原分流例外") && t.Text.Contains("Round6Extra")), "多落地移除审阅遗漏原落地。"); Press(review, "CloseButton"); await pending;
            source["Nodes"]!.AsArray().Remove(extraNode); workbench.Save(source);
            pending = operation = ServerOutboundSheet(relative, plan, "RealityEntry"); form = await Dialog();
            Require(Find<ComboBox>(form).Single(c => c.Tag as string == "ServerHops.Selection.0").SelectedIndex == -1, "已删除的附加来源被自动替换。"); Press(form, "PrimaryButton"); await Task.Delay(60); Require(activeTestDialog == form && Find<TextBlock>(form).Any(t => t.Text.Contains("附加落地来源已缺失")), "缺失的附加来源被默认落地替代。"); Press(form, "CloseButton"); await pending;
            node["name"] = "Round4 changed landing"; workbench.Save(source);
            pending = operation = ServerOutboundSheet(relative, plan, "RealityEntry"); form = await Dialog();
            Require(Find<TextBlock>(form).Any(t => t.Text.Contains("服务器未同步")), "来源变更没有显示需手动审阅提示。");
            await Shot(form, "reality-outbound-source-changed.png"); Press(form, "CloseButton"); await pending;
            source["Nodes"]!.AsArray().Clear(); workbench.Save(source);
            pending = operation = ServerOutboundSheet(relative, plan, "RealityEntry"); form = await Dialog();
            Require(Find<TextBlock>(form).Any(t => t.Text.Contains("来源节点已删除")), "来源删除没有提示服务器仍使用快照。");
            Press(form, "CloseButton"); await pending;
            Require(ClientSchemes.SourceFingerprint(realityFile) == realityBefore && ClientSchemes.SourceFingerprint(file) == anyTlsBefore && new TaskHistory(store).Read().Count == historyCount && taskCancellation == null, "组件切换或取消审阅仍执行变更。");
            return new() { ["instance_entry"] = true, ["form_cancel"] = true, ["egress_selection"] = true, ["invalid_egress_keeps_form"] = true, ["redacted_review_cancel"] = true, ["remove_review_cancel"] = true, ["current_reality_preselected"] = true, ["role_switch_scope"] = true, ["reality_dual_stack_review"] = true, ["source_changed_notice"] = true, ["source_missing_notice"] = true, ["cancel_isolation"] = true, ["destination_add_remove"] = true, ["invalid_rules_keep_form"] = true, ["ordered_match_preview"] = true, ["component_drafts_isolated"] = true, ["acceptance_path_guard"] = true, ["normalized_rule_review"] = true, ["existing_rules_remove_review"] = true, ["hop_independent_egress"] = true, ["hop_unused_guard"] = true, ["hop_referenced_remove_guard"] = true, ["hop_named_match"] = true, ["hop_component_drafts"] = true, ["hop_redacted_review"] = true, ["hop_saved_selection_remove_review"] = true, ["hop_missing_source_guard"] = true };
        }
        catch (Exception error) { File.WriteAllText(SafePath.Resolve(output, "server-outbound-ui-failure.txt"), error.ToString()); throw; }
        finally { workbench.Delete(source); new InstanceDeletion(store).Delete(new InstanceDeletion(store).Review(relative)); selectedInstance = previous; SelectPage("instances"); }
    }
}
