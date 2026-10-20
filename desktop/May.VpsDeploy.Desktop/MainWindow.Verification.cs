using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task CheckUpdates(bool automatic)
    {
        if (testSession != null) { Show("后台测试会话不执行应用安装或系统弹窗。", InfoBarSeverity.Warning); return; }
        if (taskCancellation != null) { if (!automatic) Show("请等待当前任务结束后再更新。"); return; }
        updateTask = true;
        try { await RunBackground("正在检查应用更新", async token =>
        {
            using var updates = CreateUpdates(); var update = await updates.CheckAsync(token);
            if (update == null) { taskText.Text = "已是最新版本"; if (!automatic) Show("当前没有更高版本的正式桌面更新。", InfoBarSeverity.Success); return; }
            taskText.Text = "发现新版本 v" + update.Version;
            string? stage = null;
            try
            {
                stage = await PrepareUpdateInDialog(updates, update, token);
                if (stage == null) { taskText.Text = "已取消更新"; return; }
                token.ThrowIfCancellationRequested(); SaveDraft(); SaveSettings();
                taskText.Text = "正在打开安装进度窗口…"; var prepared = stage; updates.Start(prepared); stage = null; closing = true; RecordUpdateStart(prepared);
            }
            finally { if (stage != null) updates.Discard(stage); }
        }); }
        catch (OperationCanceledException) { taskText.Text = "已取消更新"; Show("应用更新已取消。"); }
        catch (Exception error) { taskText.Text = "应用更新未完成"; Show(error is OperationException safe ? safe.Message : "更新检查或下载未完成，请核对网络与更新代理。", InfoBarSeverity.Warning); }
        finally { updateTask = false; }
    }
    private void DisplayUpdateProgress(ApplicationUpdateProgress value)
    {
        var bar = updateDialogProgress ?? taskProgress; bar.IsIndeterminate = value.TotalBytes == 0; bar.Value = value.Percent;
        taskText.Text = value.Phase switch
        {
            UpdatePhase.Preparing => "正在读取更新清单…",
            UpdatePhase.Downloading => $"正在下载应用更新 · {value.Percent:F0}% · {value.CompletedBytes / 1048576d:F1} / {value.TotalBytes / 1048576d:F1} MB",
            UpdatePhase.Verifying => $"正在校验应用更新 · {value.Percent:F0}%",
            _ => "下载与校验完成"
        };
        if (updateDialogStatus != null) updateDialogStatus.Text = taskText.Text;
        ObserveUpdateProgress(value);
    }
    private async Task UiSmoke()
    {
        var flag = launchArguments.Contains("--ui-smoke") ? "--ui-smoke" : "--verify-runtime"; var index = Array.IndexOf(launchArguments, flag); var proofPath = Path.GetFullPath(launchArguments[index + 1]);
        try
        {
            var pages = new JsonArray(); var outputDirectory = Path.GetDirectoryName(proofPath)!; Directory.CreateDirectory(outputDirectory);
            var review = flag == "--ui-smoke" && launchArguments.Contains("--review-screenshots");
            if (review && (!launchArguments.Contains("--app-root") || !File.Exists(paths.Resolve("qa-ui-review.fixture.json")))) throw new OperationException("全面截图需要隔离的示例工作区。");
            var initialTheme = settings.Text("Appearance"); var initialFont = settings.Text("FontId", "Route"); var originalForm = deploymentForm.DeepClone().AsObject();
            var fontPreferenceVerified = false;
            if (initialFont == "WenKai" && Math.Abs(FontWidth(InterfaceFont) - FontWidth(FontFamily.XamlAutoFontFamily)) < 1) throw new OperationException("内置字体未实际加载。");
            async Task RenderPages(string directory, bool record)
            {
                Directory.CreateDirectory(directory);
                foreach (var id in new[] { "overview", "instances", "deploy", "clients", "network", "records", "settings" })
                {
                    if (id == "clients" && flag == "--ui-smoke" && launchArguments.Contains("--exercise-forms")) scheme = ClientSchemes.New(paths);
                    Program.Trace(launchArguments, "Render " + id); SelectPage(id); shell.UpdateLayout(); await Task.Delay(120); if (shell.ActualWidth < 800 || shell.ActualHeight < 500 || page.Children.Count == 0 || notice.Severity == InfoBarSeverity.Error && notice.IsOpen) throw new OperationException("WinUI 页面加载或布局失败。");
                    if (flag == "--ui-smoke") await Capture(SafePath.Resolve(directory, id + ".png")); if (record) pages.Add(id);
                }
            }
            async Task Compact(string directory)
            {
                var size = AppWindow.Size; var scale = shell.XamlRoot.RasterizationScale;
                AppWindow.Resize(new((int)(840 * scale), (int)(760 * scale))); SelectPage("deploy"); await Task.Delay(180); shell.UpdateLayout();
                if (shell.ActualWidth < 800 || pageAction.Content is not Button) throw new OperationException("窄窗口操作入口不可用。");
                await Capture(SafePath.Resolve(directory, "deploy-compact.png")); AppWindow.Resize(size); SelectPage("settings"); await Task.Delay(120);
            }
            if (review) { SetAppearance("Dark"); SetFont("Route"); }
            await RenderPages(outputDirectory, true);
            if (flag == "--ui-smoke" && launchArguments.Contains("--exercise-desktop")) ArchiveStore.WriteJson(SafePath.Resolve(outputDirectory, "desktop-regression-proof.json"), await DesktopRegression(outputDirectory));
            if (flag == "--ui-smoke" && launchArguments.Contains("--exercise-deployment")) ArchiveStore.WriteJson(SafePath.Resolve(outputDirectory, "deployment-regression-proof.json"), await DeploymentRegression(outputDirectory));
            if (flag == "--ui-smoke" && launchArguments.Contains("--exercise-maintenance")) ArchiveStore.WriteJson(SafePath.Resolve(outputDirectory, "maintenance-regression-proof.json"), await MaintenanceRegression(outputDirectory));
            if (flag == "--ui-smoke" && launchArguments.Contains("--exercise-storage")) ArchiveStore.WriteJson(SafePath.Resolve(outputDirectory, "storage-regression-proof.json"), await StorageRegression(outputDirectory));
            if (flag == "--ui-smoke" && launchArguments.Contains("--exercise-additions")) ArchiveStore.WriteJson(SafePath.Resolve(outputDirectory, "additions-regression-proof.json"), await AdditionsRegression(outputDirectory));
            var preferenceVerified = false;
            if (flag == "--ui-smoke") await Compact(outputDirectory);
            if (review)
            {
                await ReviewScreenshots(outputDirectory);
                fontPreferenceVerified = await ReviewFonts(outputDirectory);
                SetFont("Route", true);
                SelectPage("settings"); var choice = Find<ComboBox>(shell).Single(c => c.Tag as string == "Appearance"); choice.SelectedIndex = 1; await Task.Delay(100);
                preferenceVerified = DesktopTheme.IsLight && ArchiveStore.ReadJson(paths.Resolve("private/desktop-settings.json")).Text("Appearance") == "Light";
                if (!preferenceVerified) throw new OperationException("颜色模式未保存。");
                deploymentForm.Clear(); foreach (var pair in originalForm) deploymentForm[pair.Key] = pair.Value?.DeepClone(); scheme = null;
                var lightDirectory = SafePath.Resolve(outputDirectory, "light"); await RenderPages(lightDirectory, false); await Compact(lightDirectory); await ReviewScreenshots(lightDirectory);
                fontPreferenceVerified &= await ReviewFonts(lightDirectory);
            }
            var dialog = new ContentDialog { XamlRoot = shell.XamlRoot, Title = "隔离界面验证", Content = Column(new TextBox { Header = "文本输入" }, new PasswordBox { Header = "凭据输入" }, new CheckBox { Content = "确认选项" }, new ListView { Items = { "项目一", "项目二" } }), PrimaryButtonText = "确认", CloseButtonText = "取消" };
            var timer = DispatcherQueue.CreateTimer(); timer.Interval = TimeSpan.FromMilliseconds(400); timer.Tick += (_, _) => { timer.Stop(); dialog.Hide(); }; timer.Start(); await ShowDialog(dialog);
            if (backgroundTest && (testActivations != 0 || testForegroundSamples != 0)) throw new OperationException("后台验证窗口发生激活，验证失败。");
            ArchiveStore.WriteJson(proofPath, new JsonObject { ["background_window"] = BackgroundProof(), ["winui_loaded"] = true, ["pages"] = pages, ["engine"] = "dotnet", ["runtime"] = RuntimeInformation.FrameworkDescription, ["runtime_paths_local"] = Path.GetDirectoryName(typeof(object).Assembly.Location)!.Equals(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase), ["powershell_loaded"] = AppDomain.CurrentDomain.GetAssemblies().Any(a => a.GetName().Name == "System.Management.Automation"), ["wpf_loaded"] = AppDomain.CurrentDomain.GetAssemblies().Any(a => a.GetName().Name == "PresentationFramework"), ["initial_theme"] = initialTheme, ["themes_reviewed"] = review ? new JsonArray("Dark", "Light") : null, ["appearance_preference_verified"] = preferenceVerified, ["initial_font"] = initialFont, ["font_fallback"] = fontFallback, ["font_preference_verified"] = fontPreferenceVerified, ["fonts_reviewed"] = review ? new JsonArray("Route", "WenKai", "Custom") : null });
        }
        catch (Exception error) { Program.Trace(launchArguments, "UI fixture stack: " + error.StackTrace); ArchiveStore.WriteJson(proofPath, new JsonObject { ["background_window"] = BackgroundProof(), ["winui_loaded"] = false, ["error"] = error.GetType().Name, ["safe_message"] = error is OperationException safe ? safe.Message : null }); Environment.ExitCode = 1; }
        finally { scheme = null; Close(); }
    }
    private static double FontWidth(FontFamily family)
    {
        var text = new TextBlock { Text = "AaBb 12345 · 归档", FontSize = 30, FontFamily = family };
        text.Measure(new global::Windows.Foundation.Size(double.PositiveInfinity, double.PositiveInfinity)); return text.DesiredSize.Width;
    }
    private async Task<bool> ReviewFonts(string directory)
    {
        void Choose(string id)
        {
            var choice = Find<ComboBox>(shell).Single(c => c.Tag as string == "FontId");
            choice.SelectedItem = choice.Items.OfType<ComboBoxItem>().Single(item => item.Tag as string == id);
            if (settings.Text("FontId") != id || ArchiveStore.ReadJson(paths.Resolve("private/desktop-settings.json")).Text("FontId") != id) throw new OperationException("字体偏好未保存。");
        }
        SelectPage("settings"); Choose("WenKai"); Choose("Route"); Choose("WenKai");
        if (Math.Abs(FontWidth(InterfaceFont) - FontWidth(FontFamily.XamlAutoFontFamily)) < 1) throw new OperationException("霞鹜文楷未实际渲染。");
        foreach (var id in new[] { "settings", "overview", "deploy" }) { SelectPage(id); await Task.Delay(180); shell.UpdateLayout(); await Capture(SafePath.Resolve(directory, id + "-wenkai.png")); }
        var original = paths.Resolve("Fonts/SourceSerif4-600.ttf"); var font = fonts.Import(original);
        if (fonts.Import(original).Id != font.Id) throw new OperationException("重复字体未复用。");
        SelectPage("settings"); Choose(font.Id); await Task.Delay(180); shell.UpdateLayout();
        var expected = new FontFamily("ms-appx:///Fonts/SourceSerif4-600.ttf#" + font.Family);
        if (Math.Abs(FontWidth(InterfaceFont) - FontWidth(expected)) > .1 || Math.Abs(FontWidth(InterfaceFont) - FontWidth(FontFamily.XamlAutoFontFamily)) < 1) throw new OperationException("导入字体未实际渲染。");
        await Capture(SafePath.Resolve(directory, "settings-custom-font.png")); return true;
    }
    private async Task Capture(string filename, UIElement? element = null)
    {
        var bitmap = new RenderTargetBitmap(); await bitmap.RenderAsync(element ?? shell); var buffer = await bitmap.GetPixelsAsync(); var bytes = new byte[buffer.Length]; using (var reader = global::Windows.Storage.Streams.DataReader.FromBuffer(buffer)) reader.ReadBytes(bytes);
        File.WriteAllBytes(filename, []); var file = await global::Windows.Storage.StorageFile.GetFileFromPathAsync(filename); using var output = await file.OpenAsync(global::Windows.Storage.FileAccessMode.ReadWrite);
        var encoder = await global::Windows.Graphics.Imaging.BitmapEncoder.CreateAsync(global::Windows.Graphics.Imaging.BitmapEncoder.PngEncoderId, output); encoder.SetPixelData(global::Windows.Graphics.Imaging.BitmapPixelFormat.Bgra8, global::Windows.Graphics.Imaging.BitmapAlphaMode.Premultiplied, (uint)bitmap.PixelWidth, (uint)bitmap.PixelHeight, 96, 96, bytes); await encoder.FlushAsync();
    }
}
