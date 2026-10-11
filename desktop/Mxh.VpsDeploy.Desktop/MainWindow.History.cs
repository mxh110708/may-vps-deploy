using System.Text.Json.Nodes;
using Microsoft.UI.Xaml.Controls;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private static string LocalTime(string value) => DateTimeOffset.TryParse(value, out var time) ? time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "时间未记录";
    private static string KindLabel(OperationKind kind) => kind switch
    {
        OperationKind.ConnectExisting or OperationKind.ResumeImport => "接入实例", OperationKind.Deploy or OperationKind.Resume => "部署实例",
        OperationKind.HealthAudit => "健康检查", OperationKind.TunnelAccess => "公开访问验证", OperationKind.TuneNetwork => "网络调优", OperationKind.MeasureNetwork => "入口线路测量", OperationKind.ProtocolState => "协议管理",
        OperationKind.RotateCredentials => "凭据轮换", OperationKind.Upgrade => "代理核心升级", OperationKind.Restore => "协议恢复",
        OperationKind.BbrKernel => "BBR 内核管理", OperationKind.Recover => "事务状态核对", OperationKind.Komari => "监控与访问管理", OperationKind.Decommission => "实例退役", _ => "任务"
    };
    private void Records()
    {
        var publisher = new CandidatePublisher(paths);
        foreach (var pending in publisher.Pending()) page.Children.Add(Card(Column(Text("配置导出待恢复", 18), Text("上次导出未确认结束。恢复前会核对该事务涉及的目标与备份摘要。", 13, true), Action("核对并恢复", async () => { if (await ConfirmAsync(new("恢复配置导出", "仅恢复此导出事务涉及的配置文件；发现外部改动时停止。"), CancellationToken.None)) await RunBackground("恢复配置导出", token => { token.ThrowIfCancellationRequested(); publisher.Recover(pending); Show("配置导出已恢复。", InfoBarSeverity.Success); return Task.CompletedTask; }); }))));
        var records = new TaskHistory(store).Read();
        var clear = Action("清空记录", () => DeleteHistory()); clear.IsEnabled = records.Count > 0;
        page.Children.Add(Trailing(Column(Text(records.Count + " 条任务记录", 16), Text("删除记录只清理此列表；实例归档、备份与恢复材料保留。时间按本机时区显示。", 13, true)), clear));
        if (records.Count == 0) { page.Children.Add(Card(Text("还没有任务记录。", 16, true))); return; }
        foreach (var record in records.Reverse())
        {
            var outcome = (TaskOutcome)record.Number("Outcome"); var kind = KindLabel((OperationKind)record.Number("Kind"));
            var texts = new StackPanel { Spacing = 8 };
            texts.Children.Add(Text(kind + " · " + OutcomeLabel(outcome), 18));
            var instance = record.Text("InstanceRelativePath").Replace("/MXH-VPS-Deploy", ""); if (instance != "") texts.Children.Add(Text(instance, 14));
            if (record.Text("TargetLabel") != "") texts.Children.Add(Text(record.Text("TargetLabel"), 14));
            texts.Children.Add(Text(LocalTime(record.Text("StartedAt")) + (record.Text("Stage") == "" ? "" : " · " + StageLabel(record.Text("Stage"))), 13, true));
            if (record.Text("SafeError") != "") texts.Children.Add(Text(record.Text("SafeError"), 14));
            if (record.Text("NextAction") != "") texts.Children.Add(Text("下一步：" + record.Text("NextAction"), 14, true));
            if (record.Text("ErrorCode") != "") texts.Children.Add(Text("错误代码：" + record.Text("ErrorCode"), 12, true));
            var id = record.Text("Id"); page.Children.Add(Card(Trailing(texts, Action("删除记录", () => DeleteHistory(id)))));
        }
    }
    private ContentDialog HistoryDeletionDialog(HistoryDeletionReview review)
    {
        var content = Column(Text(review.RecordId == null ? "将清空 " + review.Count + " 条任务记录。" : "将删除这条任务记录。", 17));
        if (review.RecordId != null)
        {
            var record = new TaskHistory(store).Read().SingleOrDefault(r => r.Text("Id") == review.RecordId) ?? throw new OperationException("该记录已不存在，请重新选择。");
            content.Children.Add(Card(Column(Text(KindLabel((OperationKind)record.Number("Kind")) + " · " + OutcomeLabel((TaskOutcome)record.Number("Outcome")), 16),
                Text(record.Text("InstanceRelativePath").Replace("/MXH-VPS-Deploy", ""), 14), Text(LocalTime(record.Text("StartedAt")), 14, true))));
        }
        content.Children.Add(Text("仅清理记录列表。实例归档、配置方案、备份和未完成事务的恢复材料会保留；服务器状态不受影响。", 14, true));
        return OperationDialog(review.RecordId == null ? "清空任务记录" : "删除任务记录", content, review.RecordId == null ? "清空记录" : "删除记录");
    }
    private async Task DeleteHistory(string? id = null)
    {
        var history = new TaskHistory(store); var review = history.ReviewDeletion(id);
        if (await ShowDialog(HistoryDeletionDialog(review)) != ContentDialogResult.Primary) return;
        await RunBackground("清理任务记录", token => Task.Run(() => { token.ThrowIfCancellationRequested(); history.Delete(review); }, token));
        SelectPage("records"); taskText.Text = id == null ? "任务记录已清空" : "任务记录已删除";
        Show("记录列表已更新，归档与恢复材料保留。", InfoBarSeverity.Success);
    }
}
