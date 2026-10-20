using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private UpdateFixtureTransport? updateFixture;
    private string? updateProof;
    private bool updateStarted;
    private bool updateConfirmationClicked;
    private JsonArray? updateNegativeChecks;
    private readonly JsonObject updateProgressChecks = new();
    private readonly List<Task> updateProgressCaptures = [];
    private WindowsUpdates CreateUpdates() => updateFixture == null
        ? new(paths, settings.Text("UpdateProxy"))
        : new(paths, new HttpClient(updateFixture, false) { Timeout = TimeSpan.FromMinutes(8) });

    private async Task InstalledUpdateSmoke()
    {
        var proof = paths.Resolve(".tmp/ui-update-proof.json"); var checks = new JsonArray();
        var timer = DispatcherQueue.CreateTimer(); timer.Interval = TimeSpan.FromMilliseconds(100);
        try
        {
            // Only an installer fixture can substitute transport or approve this synthetic update.
            if (!ArchiveStore.ReadJson(paths.Resolve("desktop-runtime.json")).Flag("test_build") || !paths.Root.Equals(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)) throw new OperationException("应用内更新验证只能使用隔离 QA 安装包。");
            var directory = paths.Resolve(".tmp/qa-update-fixture"); var baseline = ArchiveStore.ReadJson(SafePath.Resolve(directory, "release.json"));
            async Task Refuses(string name, Action<UpdateFixtureTransport> change, bool prepare)
            {
                using var transport = new UpdateFixtureTransport(directory, baseline.DeepClone().AsObject()); change(transport);
                using var updates = new WindowsUpdates(paths, new HttpClient(transport, false));
                try { var update = await updates.CheckAsync(default); if (prepare) await updates.PrepareAsync(update!, default); }
                catch (OperationException) { checks.Add(name); return; }
                throw new OperationException("更新边界未拒绝：" + name);
            }
            await Refuses("foreign_asset_url", t => t.Release["assets"]!.AsArray()[0]!["browser_download_url"] = "https://example.invalid/installer.exe", false);
            await Refuses("missing_github_digest", t => t.Release["assets"]!.AsArray()[0]!["digest"] = "", false);
            await Refuses("oversized_asset", t => t.Release["assets"]!.AsArray()[0]!["size"] = 300L * 1024 * 1024 + 1, false);
            await Refuses("checksum_tamper", t => t.Corrupt = "SHA256SUMS.txt", true);
            await Refuses("installer_tamper", t => t.Corrupt = Path.GetFileName(t.Release["assets"]!.AsArray()[0]!.Text("browser_download_url")), true);
            await Refuses("download_size_overrun", t => t.Release["assets"]!.AsArray()[0]!["size"] = 1, true);
            if (Directory.EnumerateDirectories(paths.Resolve(".tmp"), "app-update-*").Any()) throw new OperationException("失败的下载暂存未清理。");
            checks.Add("failed_stages_removed");
            using (var transport = new UpdateFixtureTransport(directory, baseline.DeepClone().AsObject()))
            {
                transport.Release["tag_name"] = "v" + ArchiveStore.ReadJson(paths.Resolve("config/application.json")).Text("version");
                using var updates = new WindowsUpdates(paths, new HttpClient(transport, false));
                if (await updates.CheckAsync(default) != null) throw new OperationException("重复版本被视为更新。"); checks.Add("equal_version_ignored");
            }
            var statusCases = new JsonArray();
            using (var transport = new UpdateFixtureTransport(directory, baseline.DeepClone().AsObject()))
            {
                transport.Release["tag_name"] = "v" + ArchiveStore.ReadJson(paths.Resolve("config/application.json")).Text("version"); updateFixture = transport;
                foreach (var automatic in new[] { true, false })
                {
                    await CheckUpdates(automatic);
                    if (taskText.Text != "已是最新版本" || taskProgress.Visibility != Visibility.Collapsed || taskCancellation != null) throw new OperationException("更新检查完成后仍显示忙碌状态。");
                    statusCases.Add(automatic ? "automatic_check_completed" : "manual_check_completed");
                }
                transport.Release["tag_name"] = "invalid"; await CheckUpdates(false);
                if (taskText.Text != "应用更新未完成" || taskProgress.Visibility != Visibility.Collapsed) throw new OperationException("更新检查失败后状态未结束。");
                statusCases.Add("failed_check_completed");
            }
            async Task DecisionCase(bool accept, bool cancelDownload)
            {
                using var transport = new UpdateFixtureTransport(directory, baseline.DeepClone().AsObject()) { SlowReads = cancelDownload }; updateFixture = transport;
                var decisionTimer = DispatcherQueue.CreateTimer(); decisionTimer.Interval = TimeSpan.FromMilliseconds(60); var decided = false; var cancelled = false;
                decisionTimer.Tick += (_, _) =>
                {
                    if (!decided)
                    {
                        var dialog = VisualTreeHelper.GetOpenPopupsForXamlRoot(shell.XamlRoot).SelectMany(p => Find<ContentDialog>(p.Child)).FirstOrDefault(d => d.Tag as string == "ApplicationUpdate");
                        var button = dialog == null ? null : Find<Button>(dialog).FirstOrDefault(b => b.Name == (accept ? "PrimaryButton" : "CloseButton") && b.IsEnabled);
                        if (button == null) return; decided = true; ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke();
                    }
                    else if (cancelDownload && !cancelled && updateDialogProgress is { IsIndeterminate: false, Value: > 0 } && updateDialog != null)
                    { var button = Find<Button>(updateDialog).Single(b => b.Name == "CloseButton"); cancelled = true; ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke(); }
                };
                try { decisionTimer.Start(); await CheckUpdates(false); }
                finally { decisionTimer.Stop(); }
                if (!decided || cancelDownload && !cancelled || taskText.Text != "已取消更新" || taskProgress.Visibility != Visibility.Collapsed || Directory.EnumerateDirectories(paths.Resolve(".tmp"), "app-update-*").Any()) throw new OperationException("取消更新后状态或暂存未正确结束。");
                statusCases.Add(cancelDownload ? "download_cancelled_and_cleaned" : "confirmation_declined");
            }
            await DecisionCase(false, false); await DecisionCase(true, true);
            using (var transport = new UpdateFixtureTransport(directory, baseline.DeepClone().AsObject()))
            { transport.Release["tag_name"] = "v" + ArchiveStore.ReadJson(paths.Resolve("config/application.json")).Text("version"); updateFixture = transport; await CheckUpdates(true); }
            updateFixture = null; SelectPage("settings"); shell.UpdateLayout(); await Task.Delay(150);
            var aboutIcon = Find<Image>(shell).Single(i => i.Name == "AboutApplicationIcon");
            aboutIcon.StartBringIntoView(); await Task.Delay(150); shell.UpdateLayout();
            await Capture(SafePath.Resolve(directory, "about-application-icon.png"), (UIElement)((FrameworkElement)((FrameworkElement)aboutIcon.Parent).Parent).Parent);
            await Capture(SafePath.Resolve(directory, "completed-update-status.png"), (UIElement)((FrameworkElement)taskText.Parent).Parent);
            ArchiveStore.WriteJson(paths.Resolve(".tmp/update-status-proof.json"), new JsonObject { ["cases"] = statusCases });
            updateFixture = new(directory, baseline) { SlowReads = true }; updateProof = proof; updateNegativeChecks = checks;
            var confirmed = false;
            timer.Tick += async (_, _) =>
            {
                if (confirmed) return;
                var dialog = VisualTreeHelper.GetOpenPopupsForXamlRoot(shell.XamlRoot).SelectMany(p => Find<ContentDialog>(p.Child)).FirstOrDefault(d => d.Tag as string == "ApplicationUpdate");
                if (dialog == null) return;
                var button = Find<Button>(dialog).FirstOrDefault(b => b.Name == "PrimaryButton" && b.IsEnabled); if (button == null) return;
                confirmed = true; await Capture(SafePath.Resolve(directory, "ui-update-notes.png"), dialog);
                updateConfirmationClicked = true; ((IInvokeProvider)new ButtonAutomationPeer(button).GetPattern(PatternInterface.Invoke)).Invoke();
            };
            timer.Start(); SelectPage("settings");
            var check = Find<Button>(shell).Single(b => b.Content as string == "检查更新");
            ((IInvokeProvider)new ButtonAutomationPeer(check).GetPattern(PatternInterface.Invoke)).Invoke();
            for (var attempt = 0; attempt < 600 && !updateStarted; attempt++) await Task.Delay(100);
            if (!updateStarted || !confirmed) throw new OperationException("应用内检查更新未完成交接。");
            var result = ArchiveStore.ReadJson(proof); result["negative_checks"] = checks; result["confirmation_clicked"] = confirmed; ArchiveStore.WriteJson(proof, result);
        }
        catch (Exception error)
        {
            ArchiveStore.WriteJson(proof, new JsonObject { ["ui_update_started"] = false, ["error"] = error is OperationException safe ? safe.Message : error.GetType().Name }); Environment.ExitCode = 1; Close();
        }
        finally { timer.Stop(); }
    }
    private void RecordUpdateStart(string stage)
    {
        if (updateProof == null) return;
        var job = ArchiveStore.ReadJson(SafePath.Resolve(stage, "update-job.private.json"));
        ArchiveStore.WriteJson(updateProof, new JsonObject { ["ui_update_started"] = true, ["version"] = job.Text("Version"), ["stage"] = stage, ["launcher_pid_recorded"] = job.Number("LauncherPid") > 0, ["confirmation_clicked"] = updateConfirmationClicked, ["release_notes_displayed"] = displayedReleaseNotes == updateFixture!.Release.Text("body") && displayedReleaseNotes.Length > 0, ["negative_checks"] = updateNegativeChecks?.DeepClone(), ["progress"] = updateProgressChecks.DeepClone(), ["requests"] = new JsonArray(updateFixture.Requests.Select(u => (JsonNode?)JsonValue.Create(u)).ToArray()) }); updateStarted = true;
    }
    private void ObserveUpdateProgress(ApplicationUpdateProgress progress)
    {
        if (updateProof == null) return;
        var key = progress.Phase.ToString(); var previous = updateProgressChecks[key]?.AsObject();
        var bar = updateDialogProgress ?? taskProgress;
        if (progress.Percent < (previous?["percent"]?.GetValue<double>() ?? 0) || bar.Visibility != Visibility.Visible || bar.IsIndeterminate != (progress.TotalBytes == 0) || updateDialog == null) throw new OperationException("更新弹窗进度显示无效。");
        updateProgressChecks[key] = new JsonObject { ["percent"] = progress.Percent, ["visible"] = true, ["in_dialog"] = true, ["captured"] = previous?.Flag("captured") ?? false, ["total_bytes"] = progress.TotalBytes };
        if (!updateProgressChecks[key]!.Flag("captured") && progress.Percent >= 25 && progress.Phase is UpdatePhase.Downloading or UpdatePhase.Verifying)
        {
            updateProgressChecks[key]!["captured"] = true;
            updateDialog.UpdateLayout(); updateProgressCaptures.Add(Capture(paths.Resolve(".tmp/qa-update-fixture/ui-update-" + key.ToLowerInvariant() + ".png"), updateDialog));
        }
    }
    private Task CompleteUpdateProgressReview() => updateProof == null ? Task.CompletedTask : Task.WhenAll(updateProgressCaptures);
}

internal sealed class UpdateFixtureTransport(string directory, JsonObject release) : HttpMessageHandler
{
    public JsonObject Release { get; } = release;
    public string? Corrupt { get; set; }
    public bool SlowReads { get; set; }
    public List<string> Requests { get; } = [];
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); var uri = request.RequestUri!; Requests.Add(uri.AbsoluteUri);
        if (uri.AbsoluteUri == "https://api.github.com/repos/mxh110708/may-vps-deploy/releases/latest") return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Release.ToJsonString(), Encoding.UTF8, "application/json") });
        var name = Uri.UnescapeDataString(uri.Segments.Last());
        if (uri.Host != "github.com" || !uri.AbsolutePath.StartsWith("/mxh110708/may-vps-deploy/releases/download/", StringComparison.Ordinal)) throw new OperationException("QA 请求超出更新范围。");
        HttpContent content = name == Corrupt ? new ByteArrayContent([1, 2, 3]) : new StreamContent(new UpdateFixtureStream(File.OpenRead(SafePath.Resolve(directory, name)), SlowReads));
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
    }
}

internal sealed class UpdateFixtureStream(Stream input, bool slow) : Stream
{
    private long delayedBytes;
    public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
    public override long Length => input.Length; public override long Position { get => input.Position; set => throw new NotSupportedException(); }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
    {
        var count = await input.ReadAsync(buffer, token); delayedBytes += count;
        if (slow && delayedBytes >= 1024 * 1024) { delayedBytes = 0; await Task.Delay(15, token); }
        return count;
    }
    public override int Read(byte[] buffer, int offset, int count) => input.Read(buffer, offset, count);
    protected override void Dispose(bool disposing) { if (disposing) input.Dispose(); base.Dispose(disposing); }
    public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
