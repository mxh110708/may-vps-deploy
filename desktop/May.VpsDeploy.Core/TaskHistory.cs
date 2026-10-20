using System.Text.Json;
using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record HistoryDeletionReview(string? RecordId, int Count, string Fingerprint);

// This file is only the task list. Instance transactions and recovery evidence
// have separate ownership and must survive clearing this list.
public sealed class TaskHistory(ArchiveStore store)
{
    private string FilePath => store.Paths.Resolve("private/task-history.dotnet.json");
    private FileStream Lock()
    {
        var path = store.Paths.Resolve("private/task-history.lock");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { throw new OperationException("任务记录正在更新，请稍后重试。", code: "HistoryBusy"); }
    }
    private JsonArray Load()
    {
        if (!File.Exists(FilePath)) return new();
        try
        {
            var records = JsonNode.Parse(File.ReadAllBytes(FilePath)) as JsonArray;
            if (records == null || records.Any(r => r is not JsonObject || r.Text("Id") == "") || records.Select(r => r.Text("Id")).Distinct(StringComparer.Ordinal).Count() != records.Count)
                throw new OperationException("任务记录格式不完整，已保留原文件。", code: "InvalidHistory");
            return records;
        }
        catch (JsonException) { throw new OperationException("任务记录文件无法解析，已保留原文件。", code: "InvalidHistory"); }
    }
    public IReadOnlyList<JsonObject> Read()
    {
        if (!File.Exists(FilePath)) return [];
        using var guard = Lock(); return Load().OfType<JsonObject>().ToArray();
    }
    public void Append(TaskRecord record)
    {
        using var guard = Lock(); var records = Load();
        var previous = records.OfType<JsonObject>().FirstOrDefault(r => r.Text("Id") == record.Id);
        var node = JsonSerializer.SerializeToNode(record);
        if (previous != null) records[records.IndexOf(previous)] = node; else records.Add(node);
        while (records.Count > 120) records.RemoveAt(0);
        ArchiveStore.WriteJson(FilePath, records);
    }
    public HistoryDeletionReview ReviewDeletion(string? recordId = null)
    {
        using var guard = Lock(); var records = Load(); var selected = Selected(records, recordId);
        EnsureInactive(selected);
        return new(recordId, selected.Length, ArchiveStore.Fingerprint(records));
    }
    public void Delete(HistoryDeletionReview review)
    {
        using var guard = Lock(); var records = Load();
        if (ArchiveStore.Fingerprint(records) != review.Fingerprint) throw new OperationException("任务记录在审阅后发生变化，请重新选择。", code: "HistoryChanged");
        var selected = Selected(records, review.RecordId);
        if (selected.Length != review.Count) throw new OperationException("所选记录数量发生变化，请重新选择。");
        EnsureInactive(selected);
        foreach (var record in selected) records.Remove(record);
        ArchiveStore.WriteJson(FilePath, records);
    }
    private static JsonObject[] Selected(JsonArray records, string? recordId)
    {
        var selected = records.OfType<JsonObject>().Where(r => recordId == null || r.Text("Id") == recordId).ToArray();
        if (recordId != null && selected.Length != 1) throw new OperationException("该任务记录已不存在，请刷新记录页。");
        return selected;
    }
    private void EnsureInactive(IEnumerable<JsonObject> records)
    {
        foreach (var record in records.Where(r => r.Text("Outcome") is "0" or "Running" && r.Text("InstanceRelativePath") != ""))
        {
            using var guard = store.LockInstanceGuard(record.Text("InstanceRelativePath"));
        }
    }
}
