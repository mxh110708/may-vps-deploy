using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public sealed record InstanceDeletionReview(string RelativePath, string Name, string Directory, int FileCount, long Bytes, string Fingerprint);

public sealed class InstanceDeletion(ArchiveStore store)
{
    public InstanceDeletionReview Review(string relative)
    {
        OperationPolicy.Validate(new(OperationKind.HealthAudit, relative, new()));
        return Read(store.Paths.Instance(relative), relative);
    }
    private InstanceDeletionReview Read(string directory, string relative)
    {
        SafePath.CheckTree(directory);
        var plan = ArchiveStore.ReadJson(SafePath.Resolve(directory, "deployment-plan.json"));
        if (InboundCatalog.Items(plan["InboundModel"] as JsonObject ?? InboundCatalog.Empty(), "Inbounds").Any()) throw new OperationException("请先在通用多入站中移除全部独立入站，再删除其归档；停用仍保留恢复材料。");
        if (plan["TcpChain"] != null || TcpChains.List(store).Any(r => TcpChains.Pending(r) && TcpChains.Instances(r["Configuration"]!.AsObject()).Contains(relative, StringComparer.OrdinalIgnoreCase))) throw new OperationException("此实例仍被跨实例线路依赖，请先移除或恢复整条线路，再删除归档。");
        if (relative != plan.Text("Provider") + "/" + plan.Text("Instance") + "/May-VPS-Deploy") throw new OperationException("实例归档身份不一致，未删除。", code: "InstanceIdentityMismatch");
        var stateFile = SafePath.Resolve(directory, "deployment-state.json");
        var state = File.Exists(stateFile) ? ArchiveStore.ReadJson(stateFile) : new JsonObject();
        var pendingFile = SafePath.Resolve(directory, "operation-pending.dotnet.json");
        if (InstanceLifecycle.HasPending(state, File.Exists(pendingFile) ? ArchiveStore.ReadJson(pendingFile) : null))
            throw new OperationException("该实例有结果未确认的事务，请先核对恢复状态。", true, "InstanceDeletionBlocked", "先处理该实例的未完成事务，再删除本地归档。");
        var manifest = new JsonObject(); long bytes = 0;
        foreach (var file in System.IO.Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var name = Path.GetRelativePath(directory, file).Replace('\\', '/');
            if (name == ".operation.lock") continue;
            SafePath.CheckLinks(file); manifest[name] = ClientSchemes.SourceFingerprint(file); bytes += new FileInfo(file).Length;
        }
        return new(relative, plan.Text("Provider") + " / " + plan.Text("Instance"), directory, manifest.Count, bytes, ArchiveStore.Fingerprint(manifest));
    }
    public void Delete(InstanceDeletionReview reviewed)
    {
        var directory = store.Paths.Instance(reviewed.RelativePath);
        if (!System.IO.Directory.Exists(directory)) throw new OperationException("实例归档已不存在。", code: "InstanceMissing");
        SafePath.CheckTree(directory);
        // An outside guard stays held while Windows renames/deletes the archive.
        // Check the old in-directory lock too, without holding its child handle during rename.
        using var held = store.LockInstanceGuard(reviewed.RelativePath);
        try { using var legacy = new FileStream(SafePath.Resolve(directory, ".operation.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { throw new OperationException("该实例的原运行锁仍被占用，请等待任务结束。", code: "InstanceBusy"); }
        var current = Read(directory, reviewed.RelativePath);
        if (current.Fingerprint != reviewed.Fingerprint || current.FileCount != reviewed.FileCount || current.Bytes != reviewed.Bytes)
            throw new OperationException("实例材料在审阅后发生变化，请重新审阅删除范围。", code: "InstanceDeletionStale");
        var staging = store.Paths.Resolve("private/instance-deletions/" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(staging)!);
        SafePath.CheckTree(directory); SafePath.CheckLinks(staging);
        System.IO.Directory.Move(directory, staging);
        try
        {
            var detached = Read(staging, reviewed.RelativePath);
            if (detached.Fingerprint != reviewed.Fingerprint) throw new OperationException("删除前检测到实例材料变化，已停止。", code: "InstanceDeletionStale");
            var deletionRoot = store.Paths.Resolve("private/instance-deletions") + Path.DirectorySeparatorChar;
            if (!Path.GetFullPath(staging).StartsWith(deletionRoot, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) throw new OperationException("删除路径越过应用范围。");
            SafePath.CheckTree(staging);
            if (System.IO.Directory.EnumerateFiles(staging, "*", SearchOption.AllDirectories).Any(file => (File.GetAttributes(file) & FileAttributes.ReadOnly) != 0)) throw new OperationException("实例材料中存在只读文件，请核对访问权限后重试。", code: "LocalAccessDenied");
            System.IO.Directory.Delete(staging, true);
        }
        catch
        {
            // Retain remaining materials under the original instance identity if cleanup fails.
            if (System.IO.Directory.Exists(staging) && !System.IO.Directory.Exists(directory)) { SafePath.CheckTree(staging); System.IO.Directory.Move(staging, directory); }
            throw;
        }
        var parent = Path.GetDirectoryName(directory)!;
        var provider = Path.GetDirectoryName(parent)!;
        foreach (var empty in new[] { parent, provider, Path.GetDirectoryName(staging)! })
        {
            SafePath.CheckLinks(empty);
            if (System.IO.Directory.Exists(empty) && !System.IO.Directory.EnumerateFileSystemEntries(empty).Any()) System.IO.Directory.Delete(empty);
        }
    }
}
