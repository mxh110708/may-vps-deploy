using System.Text.RegularExpressions;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private ContentDialog? updateDialog;
    private TransferProgressBar? updateDialogProgress;
    private TextBlock? updateDialogStatus;
    private string displayedReleaseNotes = "";

    private async Task<string?> PrepareUpdateInDialog(WindowsUpdates updates, ApplicationUpdate update, CancellationToken token)
    {
        var current = ArchiveStore.ReadJson(paths.Resolve("config/application.json")).Text("version");
        displayedReleaseNotes = update.ReleaseNotes;
        var notes = Text(ReadableUpdateNotes(update.ReleaseNotes), 14); notes.Name = "UpdateReleaseNotes"; notes.IsTextSelectionEnabled = true;
        var details = Column(Text("当前 v" + current + "   →   新版 v" + update.Version, 14, true), GroupLabel("GitHub 更新内容"), new ScrollViewer { Content = notes, MaxHeight = 300, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled });
        updateDialogProgress = new TransferProgressBar { Name = "UpdateDialogProgress", Height = 5, Foreground = Brush(Paint.Accent), Background = Brush(Paint.Button), Visibility = Visibility.Collapsed };
        updateDialogStatus = Text("下载并校验后原位安装，私人归档与本地配置保留。", 13, true);
        var progressArea = Column(updateDialogStatus, updateDialogProgress);
        var dialog = new ContentDialog { XamlRoot = shell.XamlRoot, Title = "应用更新", Tag = "ApplicationUpdate", Content = Column(details, new Border { Height = 1, Background = Brush(Paint.Border) }, progressArea), PrimaryButtonText = "下载并安装", CloseButtonText = "暂不更新", DefaultButton = ContentDialogButton.None };
        updateDialog = dialog; taskProgress.Visibility = Visibility.Collapsed;
        var downloading = false; var receiving = false; string? stage = null; Exception? failure = null;
        using var registration = token.Register(() => DispatcherQueue.TryEnqueue(() => { if (!downloading) dialog.Hide(); }));
        dialog.PrimaryButtonClick += async (_, args) =>
        {
            // Keep the dialog open without a button deferral: WinUI deferrals also
            // disable its Cancel button for the duration of the download.
            args.Cancel = true;
            if (downloading) return;
            downloading = true; receiving = true; failure = null;
            dialog.IsPrimaryButtonEnabled = false; dialog.PrimaryButtonText = "正在更新…"; dialog.CloseButtonText = "取消更新";
            updateDialogProgress.Visibility = Visibility.Visible;
            var progress = new Progress<ApplicationUpdateProgress>(value => { if (receiving && taskCancellation != null) DisplayUpdateProgress(value); });
            try
            {
                stage = await Task.Run(() => updates.PrepareAsync(update, progress, token), token); receiving = false;
                var total = update.Installer.Bytes + update.Manifest.Bytes; DisplayUpdateProgress(new(UpdatePhase.Ready, total, total));
                await CompleteUpdateProgressReview(); token.ThrowIfCancellationRequested(); dialog.Hide();
            }
            catch (OperationCanceledException) { dialog.Hide(); }
            catch (Exception error)
            {
                if (stage != null) { updates.Discard(stage); stage = null; }
                failure = error; taskText.Text = "应用更新未完成"; updateDialogProgress.Visibility = Visibility.Collapsed;
                updateDialogStatus.Text = error is OperationException safe ? safe.Message : "下载或校验未完成，请检查网络后重试。";
                dialog.PrimaryButtonText = "重试"; dialog.IsPrimaryButtonEnabled = true; dialog.CloseButtonText = "关闭";
            }
            finally { receiving = false; downloading = false; }
        };
        dialog.CloseButtonClick += (_, args) =>
        {
            if (!downloading) return;
            args.Cancel = true; taskCancellation?.Cancel(); dialog.CloseButtonText = "正在取消…"; updateDialogStatus.Text = "正在取消应用更新…";
        };
        try
        {
            await ShowDialog(dialog);
            if (token.IsCancellationRequested) { if (stage != null) { updates.Discard(stage); stage = null; } token.ThrowIfCancellationRequested(); }
            if (failure != null) throw failure;
            return stage;
        }
        finally { updateDialog = null; updateDialogProgress = null; updateDialogStatus = null; }
    }
    private static string ReadableUpdateNotes(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown)) return "此版本未填写更新说明。";
        // Display release text only: no HTML execution, automatic links or instructions.
        var text = Regex.Replace(markdown.Replace("\r\n", "\n"), @"(?m)^#{1,6}\s+", "");
        text = Regex.Replace(text, @"\[([^\]]+)\]\([^\r\n)]*\)", "$1");
        text = Regex.Replace(text, @"(?m)^[-*]\s+", "• "); return text.Replace("**", "").Replace("`", "").Trim();
    }
}
