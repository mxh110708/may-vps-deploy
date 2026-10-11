#nullable enable
using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Media;
using Mxh.VpsDeploy.Core;
using Mxh.VpsDeploy.Infrastructure;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private readonly BackgroundTestSession? testSession;
    private BackgroundTestPipe? testPipe;
    private ContentDialog? activeTestDialog;
    private readonly Dictionary<FrameworkElement, string> testIds = new();
    private int nextTestId;
    private string testSuiteState = "idle";
    private JsonObject? testSuiteResult;

    private void StartTestSession()
    {
        if (testSession == null || !backgroundTest) throw new OperationException("后台测试未启用。");
        testPipe = new(testSession, DispatchTestCommand); testPipe.Start();
        Closed += async (_, _) =>
        {
            ArchiveStore.WriteJson(testSession.Artifact("session-proof.json"), new JsonObject
            {
                ["schema_version"] = 1, ["session_id"] = testSession.Id, ["window"] = BackgroundProof(),
                ["unfinished_task"] = taskCancellation != null, ["suite_state"] = testSuiteState,
                ["suite_result"] = testSuiteResult?.DeepClone(), ["global_input_injected"] = false
            });
            if (testPipe != null) await testPipe.DisposeAsync();
        };
        ArchiveStore.WriteJson(testSession.Artifact("ready.json"), new JsonObject { ["schema_version"] = 1, ["session_id"] = testSession.Id, ["process_id"] = Environment.ProcessId });
    }
    private Task<JsonObject> DispatchTestCommand(string command, JsonObject arguments)
    {
        var completion = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!DispatcherQueue.TryEnqueue(async () =>
        {
            try { completion.TrySetResult(await TestCommand(command, arguments)); }
            catch (Exception error) { completion.TrySetException(error); }
        })) completion.TrySetException(new OperationException("测试窗口已关闭。"));
        return completion.Task;
    }
    private async Task<JsonObject> TestCommand(string command, JsonObject args)
    {
        if (testSession == null) throw new OperationException("测试接口未启用。");
        if (testActivations != 0 || testForegroundSamples != 0) throw new OperationException("测试窗口曾获得前台焦点，本轮测试应停止。", code: "TestWindowActivated");
        if (testSuiteState == "running" && command is not ("ui.read" or "suite.status" or "session.stop")) throw new OperationException("隔离界面回归运行中，请等待结果。");
        switch (command)
        {
            case "ui.read": return ReadTestUi();
            case "network.schedule.check":
                if (taskCancellation != null || activeTestDialog != null) throw new OperationException("当前状态不能检查后台计划。");
                DispatcherQueue.TryEnqueue(async () => await PollNetworkSchedules());
                return new() { ["accepted"] = true }; // The same application scheduler, without advancing its clock.
            case "ui.set":
            {
                if (TestElement(args) is not TextBox field) throw new OperationException("目标不是文本输入框。");
                var value = args.Text("value"); if (value.Length > 4096) throw new OperationException("测试输入过长。");
                var name = TestName(field);
                if (name.Contains("文件") || name.Contains("目录") || name.Contains("SSH 私钥")) testSession.RequireLocalPath(value);
                field.Text = value; break;
            }
            case "ui.secret":
            {
                if (TestElement(args) is not PasswordBox field) throw new OperationException("目标不是凭据输入框。");
                field.Password = testSession.Secret(args.Text("reference")); break;
            }
            case "ui.choose":
            {
                if (TestElement(args) is not ComboBox choice) throw new OperationException("目标不是选择框。");
                var value = args.Text("value"); var items = choice.Items.OfType<ComboBoxItem>().Where(item => item.Tag as string == value || item.Content as string == value).ToArray();
                if (items.Length != 1) throw new OperationException("未找到唯一的可选项。"); choice.SelectedItem = items[0]; break;
            }
            case "ui.toggle":
            {
                var element = TestElement(args);
                if (element is CheckBox check) check.IsChecked = args.Flag("value");
                else if (element is ToggleButton target) target.IsChecked = args.Flag("value");
                else if (element is ToggleSwitch toggle) toggle.IsOn = args.Flag("value");
                else throw new OperationException("目标不是勾选或开关控件。"); break;
            }
            case "ui.invoke":
            {
                if (TestElement(args) is not Button button) throw new OperationException("目标不是按钮。");
                var peer = FrameworkElementAutomationPeer.CreatePeerForElement(button) ?? new ButtonAutomationPeer(button);
                if (peer.GetPattern(PatternInterface.Invoke) is not IInvokeProvider provider) throw new OperationException("按钮未提供原生调用接口。");
                provider.Invoke(); break; // Normal Click handler, including validation/review/credentials and coordinator.
            }
            case "ui.scroll":
            {
                if (TestElement(args) is not ScrollViewer scroll) throw new OperationException("目标不是滚动容器。");
                scroll.ChangeView(null, Math.Clamp(args.Number("offset"), 0, scroll.ScrollableHeight), null, true); break;
            }
            case "ui.drag":
            {
                if (activeTestDialog != null || taskCancellation != null || scheme == null || currentPage != "clients" || designerStep != 1) throw new OperationException("当前页面不能拖动节点。");
                var phase = args.Text("phase", "complete");
                if (phase is not ("begin" or "move" or "end" or "cancel" or "complete")) throw new OperationException("拖动阶段无效。");
                NodeReorderHandle handle;
                if (phase is "begin" or "complete")
                {
                    if (TestElement(args) is not NodeReorderHandle selectedHandle) throw new OperationException("请选择当前节点的拖动手柄。");
                    handle = selectedHandle;
                    var origin = handle.TransformToVisual(mainScroll).TransformPoint(new(handle.ActualWidth / 2, handle.ActualHeight / 2));
                    if (origin.Y < 0 || origin.Y > mainScroll!.ActualHeight || !handle.IsLoaded || !handle.IsHitTestVisible) throw new OperationException("请先滚动到可见的拖动手柄。");
                    // Invoke the handlers wired to the native routed events, without
                    // synthesizing OS input or pretending to test OS pointer capture.
                    if (handle.Press?.Invoke(origin, 1, () => true) != true) throw new OperationException("拖动未开始。");
                    if (phase == "begin") return new() { ["started"] = true, ["input"] = "application_pointer_handlers" };
                }
                else handle = nodePointerDrag is { } active ? nodeDropRows[active.Source].Handle : throw new OperationException("没有正在进行的拖动。");
                if (phase == "cancel") { handle.Cancel?.Invoke(1); return new() { ["cancelled"] = true }; }
                var insertion = args.Number("insertion", -1); if (insertion < 0 || insertion > nodeDropRows.Count) { handle.Cancel?.Invoke(1); throw new OperationException("拖动目标位置无效。"); }
                var targetRow = nodeDropRows[Math.Min(insertion, nodeDropRows.Count - 1)].Row;
                var originX = handle.TransformToVisual(mainScroll).TransformPoint(new(handle.ActualWidth / 2, 0)).X;
                var target = targetRow.TransformToVisual(mainScroll).TransformPoint(new(0, insertion == nodeDropRows.Count ? targetRow.ActualHeight - 2 : 2)); target.X = originX;
                handle.Move?.Invoke(target, 1);
                var indicator = nodeDropRows.Any(row => row.Line.Visibility == Visibility.Visible);
                var preview = nodeDragPreview != null;
                if (phase == "move") return new() { ["indicator"] = indicator, ["preview"] = preview, ["input"] = "application_pointer_handlers" };
                if (args.Flag("cancel")) { handle.Cancel?.Invoke(1); return new() { ["cancelled"] = true, ["indicator"] = indicator, ["preview"] = preview, ["input"] = "application_pointer_handlers" }; }
                return new() { ["moved"] = handle.Release?.Invoke(target, 1) == true, ["indicator"] = indicator, ["preview"] = preview, ["input"] = "application_pointer_handlers" };
            }
            case "window.close": Mxh.VpsDeploy.Windows.WindowsWindowLifecycle.RequestClose(WinRT.Interop.WindowNative.GetWindowHandle(this)); return new() { ["accepted"] = true };
            case "window.restore":
                if (!minimizedToTray) throw new OperationException("测试窗口未在托盘中。"); RestoreFromTray(); break;
            case "ui.capture":
            {
                var name = args.Text("name", "page.png"); if (!name.EndsWith(".png", StringComparison.Ordinal)) throw new OperationException("截图输出必须为 PNG。");
                shell.UpdateLayout();
                // Popup visuals are outside the root tree. Render the active dialog itself when present.
                UIElement target = activeTestDialog == null ? shell : Find<Border>(activeTestDialog).Where(b => b.ActualWidth >= 250 && b.ActualHeight > 100).OrderByDescending(b => b.ActualWidth * b.ActualHeight).FirstOrDefault() ?? (UIElement)activeTestDialog;
                await Capture(testSession.Artifact(name), target); return new() { ["artifact"] = name, ["dialog"] = activeTestDialog != null };
            }
            case "suite.run":
            {
                if (taskCancellation != null || activeTestDialog != null || testSuiteState == "running") throw new OperationException("当前状态不能开始界面回归。");
                if (!File.Exists(paths.Resolve("qa-ui-review.fixture.json")) || !ArchiveStore.ReadJson(paths.Resolve("qa-ui-review.fixture.json")).Flag("synthetic_only")) throw new OperationException("界面回归只允许在合成归档中运行。");
                testSuiteState = "running"; testSuiteResult = null;
                DispatcherQueue.TryEnqueue(async () =>
                {
                    try
                    {
                        var directory = Path.GetDirectoryName(testSession.Artifact("suite.json"))!;
                        var result = new JsonObject { ["deployment"] = await DeploymentRegression(directory), ["maintenance"] = await MaintenanceRegression(directory), ["additions"] = await AdditionsRegression(directory), ["window_placement"] = await WindowPlacementRegression(directory) };
                        if (testActivations != 0 || testForegroundSamples != 0) throw new OperationException("界面回归获得前台焦点。");
                        testSuiteResult = result; testSuiteState = "passed";
                    }
                    catch (Exception error) { testSuiteState = "failed"; testSuiteResult = new() { ["error"] = error.GetType().Name, ["safe_message"] = error is OperationException safe ? safe.Message : "原生界面回归失败。" }; }
                    ArchiveStore.WriteJson(testSession.Artifact("suite.json"), new JsonObject { ["state"] = testSuiteState, ["result"] = testSuiteResult?.DeepClone(), ["window"] = BackgroundProof() });
                    SelectPage("overview");
                }); return new() { ["state"] = testSuiteState };
            }
            case "suite.status": return new() { ["state"] = testSuiteState, ["result"] = testSuiteResult?.DeepClone() };
            case "session.stop":
            {
                if (testSuiteState == "running") throw new OperationException("请等待原生界面回归结束后停止会话。");
                // Let the response finish before closing the server and window. A remote mutation finishes at its safe boundary.
                var timer = DispatcherQueue.CreateTimer(); timer.Interval = TimeSpan.FromMilliseconds(200);
                timer.Tick += (_, _) => { timer.Stop(); scheme = null; closing = true; if (taskCancellation != null) { taskCancellation.Cancel(); activeTestDialog?.Hide(); } else { activeTestDialog?.Hide(); Close(); } }; timer.Start();
                return new() { ["stopping"] = true, ["safe_boundary"] = taskCancellation != null };
            }
            default: throw new OperationException("不支持该测试指令。", code: "TestUnknownCommand");
        }
        return new() { ["accepted"] = true }; // Use a subsequent read to observe async UI events; acceptance is not success.
    }
    private string TestName(FrameworkElement element)
    {
        var name = AutomationProperties.GetName(element); if (name != "") return name;
        var nav = navigation.FirstOrDefault(pair => pair.Value == element); if (nav.Key != null) return nav.Key;
        return element switch { TextBox t => t.Header?.ToString() ?? "", PasswordBox p => p.Header?.ToString() ?? "", ComboBox c => c.Header?.ToString() ?? "", Button b => b.Content as string ?? b.Name, CheckBox c => c.Content as string ?? c.Name, ToggleButton t => t.Content as string ?? t.Name, ToggleSwitch t => t.Header?.ToString() ?? "", TextBlock t => t.Text, _ => element.Name };
    }
    private IEnumerable<FrameworkElement> TestElements()
    {
        IEnumerable<FrameworkElement> Walk(DependencyObject root, bool visible)
        {
            if (root is UIElement ui && ui.Visibility != Visibility.Visible) visible = false;
            if (!visible) yield break;
            if (root is FrameworkElement element) yield return element;
            // Do not inspect input templates, especially the password reveal/text visual.
            if (root is TextBox or PasswordBox or ComboBox or ButtonBase or ToggleSwitch) yield break;
            for (var index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
                foreach (var child in Walk(VisualTreeHelper.GetChild(root, index), visible)) yield return child;
        }
        shell.UpdateLayout();
        return Walk(activeTestDialog ?? (DependencyObject)shell, true).Where(e => e is Button or ToggleButton or TextBox or PasswordBox or ComboBox or CheckBox or ToggleSwitch or TextBlock or ScrollViewer or NodeReorderHandle);
    }
    private FrameworkElement TestElement(JsonObject args)
    {
        var candidates = TestElements().Where(e => args.Text("id") != "" ? TestId(e) == args.Text("id") : TestName(e) == args.Text("name") && (args.Text("kind") == "" || e.GetType().Name == args.Text("kind"))).ToArray();
        if (candidates.Length != 1) throw new OperationException("测试目标不存在或不唯一；请重新读取界面并使用控件 ID。");
        if (candidates[0] is Control control && !control.IsEnabled) throw new OperationException("目标控件当前不可用。");
        return candidates[0];
    }
    private string TestId(FrameworkElement element)
    {
        if (testIds.TryGetValue(element, out var id)) return id;
        id = "e" + ++nextTestId; testIds[element] = id; return id;
    }
    private JsonObject ReadTestUi()
    {
        var elements = new JsonArray();
        var live = TestElements().ToArray(); foreach (var old in testIds.Keys.Except(live).ToArray()) testIds.Remove(old);
        foreach (var element in live.Take(1200))
        {
            var item = new JsonObject { ["id"] = TestId(element), ["kind"] = element.GetType().Name, ["name"] = TestName(element), ["enabled"] = element is not Control control || control.IsEnabled };
            switch (element)
            {
                case TextBox text: item["value"] = text.Text; break;
                case PasswordBox password: item["filled"] = password.Password.Length > 0; break;
                case CheckBox check: item["checked"] = check.IsChecked; break;
                case ToggleButton toggle: item["checked"] = toggle.IsChecked; break;
                case ToggleSwitch toggle: item["checked"] = toggle.IsOn; break;
                case ComboBox choice:
                    item["value"] = (choice.SelectedItem as ComboBoxItem)?.Tag as string;
                    item["choices"] = new JsonArray(choice.Items.OfType<ComboBoxItem>().Select(i => (JsonNode?)new JsonObject { ["value"] = i.Tag as string, ["label"] = i.Content as string }).ToArray()); break;
                case ScrollViewer scroll: item["offset"] = scroll.VerticalOffset; item["extent"] = scroll.ScrollableHeight; break;
            }
            elements.Add(item);
        }
        return new JsonObject { ["page"] = currentPage, ["busy"] = taskCancellation != null, ["dialog"] = activeTestDialog == null ? null : AutomationProperties.GetName(activeTestDialog),
            ["task"] = taskText.Text, ["notice"] = notice.IsOpen ? notice.Message : "", ["window"] = BackgroundProof(), ["elements"] = elements };
    }
}
