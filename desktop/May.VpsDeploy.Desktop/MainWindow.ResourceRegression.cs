using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task<JsonObject> ResourceRegression(string output)
    {
        if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("资源界面回归仅允许合成归档。");
        var assertions = 0;
        void Require(bool ok, string message) { if (!ok) throw new OperationException(message); assertions++; }
        async Task<ContentDialog> Dialog(ContentDialog? previous = null)
        {
            for (var i = 0; i < 100; i++) { await Task.Delay(30); if (activeTestDialog != null && activeTestDialog != previous) { activeTestDialog.UpdateLayout(); if (Find<Button>(activeTestDialog).Any(b => b.Name == "PrimaryButton")) { await Task.Delay(120); return activeTestDialog; } } }
            throw new OperationException("未收到资源维护对话框。");
        }
        async Task Choose(string tag, string value)
        {
            var choice = Find<ComboBox>(page).Single(b => b.Tag as string == "Resources." + tag);
            var index = choice.Items.Cast<ComboBoxItem>().ToList().FindIndex(i => i.Tag as string == value);
            Require(index >= 0, "资源筛选选项缺失。"); await RegressionSelect(choice, index); await Task.Delay(70);
        }
        var previousSelection = selectedInstance; var oldFilter = resourceFilter.DeepClone().AsObject(); var oldSize = AppWindow.Size;
        var template = store.ListInstances().First(); var plan = template.Plan.DeepClone().AsObject(); plan["Instance"] = "Resource31-" + Guid.NewGuid().ToString("N")[..8]; plan.Put("Import.Status", JsonValue.Create("Completed"));
        foreach (var field in new[] { "InboundModel", "TcpForwarding", "UdpForwarding", "TcpChain", "WireGuardTunnel", "WireGuardTunnel2" }) plan.Remove(field);
        var relative = plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy"; var directory = paths.Instance(relative);
        var model = InboundCatalog.Empty(); var credentials = InboundCatalog.EmptyCredentials();
        var a = InboundCatalog.AddInbound(model, credentials, "AnyTLS"); var b = InboundCatalog.AddInbound(model, credentials, "AnyTLS");
        a["Name"] = "共享证书入站 A"; b["Name"] = "共享证书入站 B（已停用仍保留依赖）"; b["UserIds"] = a["UserIds"]!.DeepClone(); b["Enabled"] = false;
        using var key = RSA.Create(2048); var csr = new CertificateRequest("CN=tls.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("tls.example.test"); csr.CertificateExtensions.Add(san.Build());
        using var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));
        var certificate = InboundCatalog.ImportCertificate(model, credentials, "000 共享 TLS 证书", cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
        a["CertificateId"] = certificate.Text("Id"); b["CertificateId"] = certificate.Text("Id"); a["Options"]!["ServerName"] = "tls.example.test"; b["Options"]!["ServerName"] = "tls.example.test";
        // Enough distinct archive identities to exercise pagination without
        // increasing the number of actual listeners or starting any service.
        for (var i = 0; i < 34; i++) InboundCatalog.ImportCertificate(model, credentials, "未使用证书 " + i.ToString("D2"), cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
        plan["InboundModel"] = model.DeepClone();
        var state = new JsonObject { ["Engine"] = "dotnet-v1", ["Inbounds"] = new JsonObject { ["RemoteHash"] = new string('a', 64) } };
        var observed = new JsonArray(new JsonObject { ["Key"] = "inbound:" + a.Text("Id"), ["Status"] = "Observed", ["NotBefore"] = new DateTimeOffset(cert.NotBefore.ToUniversalTime()).ToString("O"), ["NotAfter"] = certificate.Text("NotAfter"), ["Sha256"] = certificate.Text("Sha256"), ["HostnameMatches"] = true },
            new JsonObject { ["Key"] = "inbound:" + b.Text("Id"), ["Status"] = "Observed", ["NotBefore"] = new DateTimeOffset(cert.NotBefore.ToUniversalTime()).ToString("O"), ["NotAfter"] = certificate.Text("NotAfter"), ["Sha256"] = certificate.Text("Sha256"), ["HostnameMatches"] = true });
        state["ResourceObservation"] = OperationsResources.Observation(plan, state, new JsonObject { ["Inbounds"] = new JsonObject { ["MatchesArchive"] = true } }, new JsonObject { ["Items"] = observed }, DateTimeOffset.UtcNow);
        var planFile = SafePath.Resolve(directory, "deployment-plan.json"); var stateFile = SafePath.Resolve(directory, "deployment-state.json"); var secretsFile = SafePath.Resolve(directory, "secrets.dotnet.private.json");
        ArchiveStore.WriteJson(planFile, plan); ArchiveStore.WriteJson(stateFile, state); store.WriteSecret(secretsFile, new JsonObject { ["Inbounds"] = credentials.DeepClone() });
        var before = new[] { planFile, stateFile, secretsFile }.ToDictionary(f => f, f => File.ReadAllBytes(f)); var history = new TaskHistory(store).Read().Count;
        var scopedFiles = new List<string>();
        Task? pending = null;
        try
        {
            var scale = shell.XamlRoot?.RasterizationScale ?? 1; AppWindow.Resize(new((int)(1040 * scale), (int)(760 * scale)));
            resourceFilter["Instance"] = relative; resourceFilter["Kind"] = "Certificate"; resourceFilter["Query"] = ""; resourceFilter["Attention"] = false; resourcePage = 0;
            SelectPage("resources"); await Task.Delay(120); shell.UpdateLayout();
            Require(heading.Text == "运维资源" && navigation.ContainsKey("resources"), "资源总览没有独立导航入口。");
            Require(Find<TextBlock>(page).Any(t => t.Tag as string == "Resources.Count" && t.Text.Contains("35 项")), "证书清单数量不完整。");
            Require(Find<Button>(page).Count(b => (b.Tag as string)?.StartsWith("Resources.Details.") == true) == 30, "总览分页未限制可见资源数量。");
            Require(Find<Button>(page).Single(b => b.Tag as string == "Resources.Check").IsEnabled, "选中受管实例没有只读核验入口。");
            Require(!Find<TextBlock>(page).Any(t => t.Text.Contains("PRIVATE KEY") || t.Text.Contains("BEGIN CERTIFICATE")), "总览展示了证书材料。");
            await Capture(SafePath.Resolve(output, "resources-overview.png"));
            Require(Find<TextBlock>(page).Single(t => t.Text == certificate.Text("Name")).TransformToVisual(shell).TransformPoint(new(0, 0)).Y < shell.ActualHeight - 100, "小窗口首屏没有可见的资源条目。");
            await RegressionInvoke(Find<Button>(page).Single(b => b.Content as string == "下一页")); await Task.Delay(80);
            Require(Find<Button>(page).Count(b => (b.Tag as string)?.StartsWith("Resources.Details.") == true) == 5, "第二页漏项或重复资源。");
            await RegressionInvoke(Find<Button>(page).Single(b => b.Content as string == "上一页"));
            var filter = Find<TextBox>(page).Single(t => t.Tag as string == "Resources.Query"); await RegressionFill(filter, "000 共享");
            Require(Find<TextBlock>(page).Single(t => t.Tag as string == "Resources.Count").Text.Contains("1 项"), "资源搜索不匹配显示名。");
            var overview = OperationsResources.Load(store, DateTimeOffset.UtcNow); var target = overview.Items.Single(i => i.Key == OperationsResources.Key(relative, "Certificate", certificate.Text("Id")));
            pending = ResourceDetails(overview, target); var details = await Dialog();
            Require(Find<TextBlock>(details).Any(t => t.Text.Contains("直接使用者 2 项")), "共享证书没有列出所有使用者。");
            Require(Find<TextBlock>(details).Any(t => t.Text.Contains("已停用，仍保留引用")), "停用入站从影响清单消失。");
            Require(Find<ScrollViewer>(details).Any(s => s.MaxHeight > 200 && s.HorizontalScrollBarVisibility == ScrollBarVisibility.Disabled), "资源影响对话框没有竖向自适应滚动。");
            await Capture(SafePath.Resolve(output, "resources-certificate-impact.png"), details);
            await RegressionPress(details, "PrimaryButton"); var form = await Dialog(details);
            Require(Find<ComboBox>(form).Single(c => c.Tag as string == "Inbounds.Group").SelectedItem is ComboBoxItem group && group.Tag as string == "Certificates", "证书维护入口没有打开证书类别。");
            Require(Find<ComboBox>(form).Single(c => c.Tag as string == "Inbounds.Resource").SelectedItem is ComboBoxItem selected && selected.Tag as string == certificate.Text("Id"), "证书维护入口选择了其他证书。");
            await RegressionPress(form, "CloseButton"); await pending; pending = null;
            Require(before.All(p => File.ReadAllBytes(p.Key).SequenceEqual(p.Value)) && new TaskHistory(store).Read().Count == history, "查看影响或取消维护改变了归档、凭据或提交任务。");
            var pendingFile = SafePath.Resolve(directory, "operation-pending.dotnet.json"); scopedFiles.Add(pendingFile);
            foreach (var tunnel in new[] { true, false })
            {
                var configuration = tunnel ? WireGuardTunnels.New(relative) : TcpChains.New(relative);
                if (tunnel) configuration["SecondInstance"] = template.RelativePath;
                else { configuration["RelayInstance"] = template.RelativePath; configuration["LandingInstance"] = plan.Text("Provider") + "/Synthetic-Landing/May-VPS-Deploy"; }
                var recordFile = tunnel ? WireGuardTunnels.FileName(paths, configuration.Text("Id")) : TcpChains.FileName(paths, configuration.Text("Id")); scopedFiles.Add(recordFile);
                ArchiveStore.WriteJson(recordFile, new JsonObject { ["Version"] = 1, ["Configuration"] = configuration.DeepClone(), ["Phase"] = "NeedsRecovery" });
                ArchiveStore.WriteJson(pendingFile, new JsonObject { ["Kind"] = tunnel ? "WireGuardTunnel" : "TcpChain", ["Phase"] = "Armed", ["TaskId"] = Guid.NewGuid().ToString("N") });
                var pendingView = OperationsResources.Load(store, DateTimeOffset.UtcNow); var identity = tunnel ? OperationsResources.TunnelKey(configuration.Text("Id")) : OperationsResources.ChainKey(configuration.Text("Id")); var pendingResource = pendingView.Items.Single(i => i.Key == identity);
                Require(pendingResource.Status == "Pending", "待恢复线路／通道未在资源总览提示。");
                pending = ResourceDetails(pendingView, pendingResource); var pendingDetails = await Dialog(); await RegressionPress(pendingDetails, "PrimaryButton"); var recovery = await Dialog(pendingDetails);
                var prefix = tunnel ? "WireGuard" : "TcpChain";
                Require(Find<ComboBox>(recovery).Single(c => c.Tag as string == prefix + ".Selection").SelectedItem is ComboBoxItem chosen && chosen.Tag as string == configuration.Text("Id"), "恢复入口选择了另一条线路／通道。");
                Require(Find<ComboBox>(recovery).Single(c => c.Tag as string == prefix + ".Action").SelectedItem is ComboBoxItem operation && operation.Tag as string == "Recover", "专用恢复入口被错误地替换为新建操作。");
                await RegressionPress(recovery, "CloseButton"); await pending; pending = null; File.Delete(recordFile); File.Delete(pendingFile);
            }
            Require(new TaskHistory(store).Read().Count == history, "查看待恢复范围或返回提交了恢复任务。");
            SelectPage("resources"); await Choose("Instance", ""); Require(!Find<Button>(page).Single(b => b.Tag as string == "Resources.Check").IsEnabled, "未选择实例时允许批量远端核验。");
            await Choose("Instance", relative); await RegressionFill(Find<TextBox>(page).Single(t => t.Tag as string == "Resources.Query"), "");
            var attention = Find<CheckBox>(page).Single(b => b.Tag as string == "Resources.Attention"); attention.IsChecked = true; await Task.Delay(70);
            Require(Find<TextBlock>(page).Single(t => t.Tag as string == "Resources.Count").Text.Contains("0 项"), "有效期正常的证书被标为即将到期。");
            var changed = plan.DeepClone().AsObject(); changed["InboundModel"]!["Certificates"]![0]!["NotAfter"] = DateTimeOffset.UtcNow.AddDays(-1).ToString("O"); ArchiveStore.WriteJson(planFile, changed); SelectPage("resources"); await Task.Delay(70);
            Require(Find<TextBlock>(page).Any(t => t.Text == "已到期") && Find<TextBlock>(page).Any(t => t.Text.Contains("归档已变化")), "过期证书或旧证据失效没有独立展示。");
            await Capture(SafePath.Resolve(output, "resources-expired-and-stale.png"));
            ArchiveStore.AtomicWrite(planFile, before[planFile]);
            var stale = state.DeepClone().AsObject(); stale["ResourceObservation"]!["At"] = DateTimeOffset.UtcNow.AddHours(-25).ToString("O"); ArchiveStore.WriteJson(stateFile, stale); resourceFilter["Attention"] = false; resourceFilter["Query"] = "000 共享"; SelectPage("resources");
            Require(Find<TextBlock>(page).Any(t => t.Text.Contains("超过 24 小时")), "陈旧快照仍作为新鲜远端核验。");
            ArchiveStore.AtomicWrite(stateFile, before[stateFile]);
            AppWindow.Resize(new((int)(1280 * scale), (int)(900 * scale))); resourceFilter["Query"] = ""; SelectPage("resources"); await Task.Delay(100); await Capture(SafePath.Resolve(output, "resources-wide.png"));
            Require(Find<Button>(page).Any(b => b.Tag as string == "Resources.Reload"), "缺少本地刷新入口。");
            Require(testActivations == 0 && testForegroundSamples == 0, "资源回归曾激活窗口。");
            return new() { ["checks"] = assertions, ["scope"] = "resources_expiry_impact_search_paging_scoped_maintenance_cancel", ["production_ssh"] = false };
        }
        finally
        {
            activeTestDialog?.Hide(); if (pending != null) try { await pending; } catch { }
            foreach (var file in scopedFiles) { SafePath.CheckLinks(file); if (File.Exists(file)) File.Delete(file); }
            credentials.Clear(); foreach (var item in before) ArchiveStore.AtomicWrite(item.Key, item.Value);
            SafePath.CheckTree(directory); Directory.Delete(directory, true); selectedInstance = previousSelection;
            resourceFilter.Clear(); foreach (var pair in oldFilter) resourceFilter[pair.Key] = pair.Value?.DeepClone(); resourcePage = 0; AppWindow.Resize(oldSize); SelectPage("overview");
        }
    }
}
