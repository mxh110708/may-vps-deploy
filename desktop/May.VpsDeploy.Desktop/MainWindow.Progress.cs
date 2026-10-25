#nullable enable
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private sealed record ExecutionRow(TextBlock Status, TextBlock Detail, TextBlock Time, Border Badge)
    {
        public TaskStepState State { get; set; } = TaskStepState.Waiting;
        public DateTimeOffset? Started { get; set; }
        public DateTimeOffset? Finished { get; set; }
    }
    private readonly Dictionary<string, ExecutionRow> executionRows = new();
    private readonly DispatcherTimer executionTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private TextBlock? executionSummary;
    private DateTimeOffset executionStarted;
    private TaskRecord? executionResult;
    private ScrollViewer? mainScroll;
    private bool ShowingExecution => executionSummary != null;
    private void ShowExecution(OperationRequest request)
    {
        var plan = request.Options["Plan"] as JsonObject ?? ArchiveStore.ReadJson(SafePath.Resolve(paths.Instance(request.InstanceRelativePath), "deployment-plan.json"));
        executionRows.Clear(); executionResult = null; executionStarted = DateTimeOffset.UtcNow;
        page.Children.Clear(); pageAction.Content = null; notice.IsOpen = false;
        heading.Text = request.Kind switch { OperationKind.Inbounds => "通用多入站任务", OperationKind.TcpChain => "跨实例 TCP 线路任务", OperationKind.InstallComponent => "正在追加安装", OperationKind.MeasureNetwork => "正在测量入口线路", OperationKind.TuneNetwork => "正在配置网络", OperationKind.BbrKernel => "BBR 内核任务", _ => "正在部署" };
        caption.Text = plan.Text("Provider") + " / " + plan.Text("Instance") + " · " + plan.Text("NodeName");
        executionSummary = Text("正在准备执行计划。", 16); executionSummary.Tag = "ExecutionSummary";
        page.Children.Add(Card(Column(executionSummary, Text("每一步完成后会更新状态。取消会在安全边界处理，未执行的步骤保留为待完成。", 14, true))));
        if (request.Kind == OperationKind.TcpChain && request.Options["Configuration"] is JsonObject chain)
            page.Children.Add(Card(Column(Text(chain.Text("Name"), 17), Text("前置：" + chain.Text("FrontInstance") + ":" + chain.Number("FrontPort") + "\n↓ TCP\n中转：" + chain.Text("RelayInstance") + ":" + chain.Number("RelayPort") + "\n↓ TCP\n落地：" + chain.Text("LandingInstance"), 14, true))));
        var table = new StackPanel { Spacing = 0 };
        var header = ExecutionGrid(Text(request.Kind == OperationKind.TcpChain ? "跨实例执行计划" : request.Kind is OperationKind.MeasureNetwork or OperationKind.TuneNetwork or OperationKind.BbrKernel ? "网络任务计划" : "部署计划", 14, true), Text("状态", 14, true), Text("耗时", 14, true));
        header.Padding = new Thickness(20, 14, 20, 14); table.Children.Add(header);
        foreach (var (step, index) in OperationSteps.Create(request, plan).Select((step, index) => (step, index)))
        {
            var detail = Text(step.Description, 13, true); var status = Text("待完成", 13); var time = Text("—", 13, true);
            var badge = new Border { Background = Brush(Paint.Button), CornerRadius = new CornerRadius(5), Padding = new Thickness(10, 5, 10, 5), Child = status, HorizontalAlignment = HorizontalAlignment.Left, VerticalAlignment = VerticalAlignment.Top };
            var row = ExecutionGrid(Column(Text((index + 1) + ". " + step.Title, 16), detail), badge, time);
            row.Padding = new Thickness(20, 16, 20, 16); row.Tag = "ExecutionStep." + step.Id;
            table.Children.Add(new Border { BorderBrush = Brush(Paint.Border), BorderThickness = new Thickness(0, 1, 0, 0), Child = row });
            executionRows[step.Id] = new(status, detail, time, badge);
        }
        page.Children.Add(new Border { Background = Brush(Paint.Surface), BorderBrush = Brush(Paint.Border), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Child = table });
        executionTimer.Tick -= ExecutionClock; executionTimer.Tick += ExecutionClock; executionTimer.Start();
        mainScroll?.ChangeView(null, 0, null); UpdateExecutionSummary();
    }
    private static Grid ExecutionGrid(FrameworkElement description, FrameworkElement status, FrameworkElement time)
    {
        var grid = new Grid { ColumnSpacing = 20 };
        grid.ColumnDefinitions.Add(new() { Width = new GridLength(1, GridUnitType.Star) }); grid.ColumnDefinitions.Add(new() { Width = new GridLength(100) }); grid.ColumnDefinitions.Add(new() { Width = new GridLength(70) });
        grid.Children.Add(description); Grid.SetColumn(status, 1); grid.Children.Add(status); Grid.SetColumn(time, 2); grid.Children.Add(time); return grid;
    }
    private void ExecutionClock(object? sender, object e) => UpdateExecutionSummary();
    private static string Duration(DateTimeOffset start, DateTimeOffset finish)
    {
        var elapsed = finish - start; return elapsed.TotalHours >= 1 ? elapsed.ToString(@"h\:mm\:ss") : elapsed.ToString(@"mm\:ss");
    }
    private void UpdateExecutionSummary()
    {
        if (executionSummary == null) return;
        var now = executionResult?.FinishedAt ?? DateTimeOffset.UtcNow;
        var completed = executionRows.Values.Count(row => row.State == TaskStepState.Completed);
        executionSummary.Text = (executionResult == null ? "执行中" : OutcomeLabel(executionResult.Outcome)) + " · 已完成 " + completed + " / " + executionRows.Count + " 步 · 用时 " + Duration(executionStarted, now);
        foreach (var row in executionRows.Values.Where(row => row.Started != null)) row.Time.Text = Duration(row.Started!.Value, row.Finished ?? now);
    }
    private void ExecutionProgress(TaskProgress progress)
    {
        taskText.Text = StageLabel(progress.Stage) + " · " + progress.Message;
        if (executionSummary == null || progress.StepId == null || !executionRows.TryGetValue(progress.StepId, out var row)) return;
        if (progress.StepState is { } state)
        {
            row.State = state;
            if (state == TaskStepState.Running) row.Started ??= DateTimeOffset.UtcNow;
            else if (state != TaskStepState.Waiting) row.Finished = DateTimeOffset.UtcNow;
            PaintExecutionRow(row);
        }
        row.Detail.Text = progress.Message; UpdateExecutionSummary();
        taskProgress.IsIndeterminate = false; taskProgress.Value = executionRows.Count == 0 ? 0 : 100d * executionRows.Values.Count(r => r.State == TaskStepState.Completed) / executionRows.Count;
    }
    private static void PaintExecutionRow(ExecutionRow row)
    {
        row.Status.Text = row.State switch { TaskStepState.Completed => "已完成", TaskStepState.Running => "正在进行", TaskStepState.Failed => "失败", TaskStepState.Cancelled => "已取消", TaskStepState.Skipped => "已跳过", _ => "待完成" };
        row.Badge.Background = Brush(row.State switch { TaskStepState.Completed => Paint.Success, TaskStepState.Running => Paint.Info, TaskStepState.Failed => Paint.Error, TaskStepState.Cancelled => Paint.Warning, _ => Paint.Button });
        row.Status.Foreground = Brush(Paint.Text);
    }
    private void FinishExecution(TaskRecord record)
    {
        executionResult = record; executionTimer.Stop();
        heading.Text = record.Kind switch { OperationKind.Inbounds => "通用多入站结果", OperationKind.TcpChain => "跨实例 TCP 线路结果", OperationKind.CheckComponentUpdate => "组件版本查询结果", OperationKind.InstallComponent => "追加安装结果", OperationKind.MeasureNetwork => "线路测量结果", OperationKind.TuneNetwork => "网络配置结果", OperationKind.BbrKernel => "BBR 内核任务结果", _ => "部署结果" };
        foreach (var row in executionRows.Values.Where(row => row.State == TaskStepState.Running))
        {
            row.State = record.Outcome == TaskOutcome.Cancelled ? TaskStepState.Cancelled : TaskStepState.Failed; row.Detail.Text = TaskMessage(record); row.Finished = record.FinishedAt; PaintExecutionRow(row);
        }
        UpdateExecutionSummary();
        var networkTask = record.Kind is OperationKind.MeasureNetwork or OperationKind.TuneNetwork or OperationKind.BbrKernel;
        var result = Card(Column(Text(OutcomeLabel(record.Outcome), 18), Text(TaskMessage(record)), Action(record.Kind == OperationKind.BbrKernel ? "查看内核与网络配置" : networkTask ? "查看测量与建议" : "返回实例", () => { selectedInstance = record.InstanceRelativePath; SelectPage(networkTask ? "network" : "instances"); return Task.CompletedTask; }, true)));
        result.Tag = "ExecutionResult"; page.Children.Add(result);
        result.StartBringIntoView();
    }
    private void ClearExecution()
    {
        executionTimer.Stop(); executionSummary = null; executionResult = null; executionRows.Clear();
    }
}
