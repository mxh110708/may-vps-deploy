using System.Text.Json.Nodes;
using System.Security.Cryptography;

namespace May.VpsDeploy.Core;

public sealed record PrivateDirectoryReview(string Source, string Destination, int Files, long Bytes, string Fingerprint, string LocationFingerprint);
public sealed record PrivateDirectoryResult(bool SourceRemoved);

// The installation owns a locator; all portable storage consumers resolve through AppPaths.
public sealed class PrivateDirectory(ArchiveStore store)
{
    public const string LocationFile = "archive-location.private.json";
    public const string OwnershipFile = ".may-private-directory.json";
    private static StringComparison Comparison => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    private static string Normal(string path) => Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    private static bool Inside(string path, string parent) => path.StartsWith(parent + Path.DirectorySeparatorChar, Comparison);
    public static string Validate(string appRoot, string directory)
    {
        if (!Path.IsPathFullyQualified(directory) || directory.StartsWith("\\\\", StringComparison.Ordinal)) throw new OperationException("请选择独立的本地归档文件夹。");
        var full = Normal(directory); var app = Normal(appRoot); var standard = SafePath.Resolve(app, "private");
        if (full.Length < 4 || full == Normal(Path.GetPathRoot(full)!) || full.Equals(app, Comparison) || Inside(app, full) || Inside(full, app) && !full.Equals(standard, Comparison)) throw new OperationException("归档目录不能是磁盘根目录、安装目录或其父目录。");
        SafePath.CheckLinks(full); return full;
    }
    public static string Load(string appRoot)
    {
        var file = SafePath.Resolve(appRoot, LocationFile); var standard = SafePath.Resolve(appRoot, "private");
        if (!File.Exists(file)) return standard;
        var locator = ArchiveStore.ReadJson(file);
        if (locator.Number("SchemaVersion") != 1 || !Guid.TryParseExact(locator.Text("OwnerId"), "N", out _)) throw new OperationException("归档目录设置无效，请核对本地设置。");
        var directory = Validate(appRoot, locator.Text("Directory"));
        var markerFile = SafePath.Resolve(directory, OwnershipFile);
        if (!File.Exists(markerFile)) throw new OperationException("自定义归档目录不可用，请接回对应磁盘或核对目录；未创建空归档。");
        var marker = ArchiveStore.ReadJson(markerFile);
        if (marker.Number("SchemaVersion") != 1 || marker.Text("OwnerId") != locator.Text("OwnerId") || !Normal(marker.Text("AppRoot")).Equals(Normal(appRoot), Comparison)) throw new OperationException("归档目录所属应用不一致，已停止读取。");
        return directory;
    }
    private Dictionary<string, string> Snapshot(string source)
    {
        var files = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!Directory.Exists(source)) return files;
        SafePath.CheckTree(source);
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            files.Add(Path.GetRelativePath(source, file).Replace('\\', '/'), ClientSchemes.SourceFingerprint(file));
        return files;
    }
    private static string Fingerprint(Dictionary<string, string> files) => ArchiveStore.Fingerprint(new JsonObject(files.Select(p => new KeyValuePair<string, JsonNode?>(p.Key, JsonValue.Create(p.Value)))));
    private void Ready(string target)
    {
        var source = Normal(store.Paths.Private);
        if (Directory.Exists(source)) SafePath.CheckTree(source);
        if (source.Equals(target, Comparison) || Inside(source, target) || Inside(target, source)) throw new OperationException("请选择与当前目录相互独立的新文件夹。");
        if (File.Exists(target) || Directory.Exists(target) && Directory.EnumerateFileSystemEntries(target).Any()) throw new OperationException("目标目录已有文件，请选择空文件夹；不会合并或覆盖现有数据。");
        if (new CandidatePublisher(store.Paths).Pending().Any() || store.ListInstances().Any(i => InstanceLifecycle.Read(store, i.RelativePath, i.Plan).NeedsRecovery)) throw new OperationException("存在待恢复事务，请处理完成后再迁移归档目录。");
        if (Directory.Exists(source) && Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories).Any(p => (File.GetAttributes(p) & FileAttributes.ReadOnly) != 0)) throw new OperationException("归档中有只读文件，请先核对访问权限。");
    }
    public PrivateDirectoryReview Review(string destination)
    {
        var target = Validate(store.Paths.Root, destination); Ready(target);
        var files = Snapshot(store.Paths.Private);
        return new(store.Paths.Private, target, files.Count, files.Keys.Sum(p => new FileInfo(SafePath.Resolve(store.Paths.Private, p)).Length), Fingerprint(files), ClientSchemes.SourceFingerprint(store.Paths.Resolve(LocationFile)));
    }
    public PrivateDirectoryResult Move(PrivateDirectoryReview review, CancellationToken cancellationToken = default, Action<string>? prepareDestination = null)
    {
        var target = Validate(store.Paths.Root, review.Destination);
        using var guard = new FileStream(store.Paths.Resolve("archive-location.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        Ready(target);
        var source = store.Paths.Private; var originals = Snapshot(source);
        if (source != review.Source || Fingerprint(originals) != review.Fingerprint || ClientSchemes.SourceFingerprint(store.Paths.Resolve(LocationFile)) != review.LocationFingerprint) throw new OperationException("归档或目录设置在审阅后发生变化，请重新审阅。");
        var handles = new List<FileStream>(); var written = new Dictionary<string, string>(); var committed = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var relative in originals.Keys) handles.Add(new FileStream(SafePath.Resolve(source, relative), FileMode.Open, FileAccess.Read, FileShare.Read));
            Directory.CreateDirectory(target);
            prepareDestination?.Invoke(target);
            foreach (var relative in originals.Keys.Where(p => p != OwnershipFile))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var input = SafePath.Resolve(source, relative); var output = SafePath.Resolve(target, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(output)!);
                using (var copy = new FileStream(output, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                {
                    try
                    {
                        using var read = File.OpenRead(input); var buffer = new byte[65536]; int length;
                        while ((length = read.Read(buffer)) != 0) { cancellationToken.ThrowIfCancellationRequested(); copy.Write(buffer, 0, length); }
                        copy.Flush(true);
                    }
                    finally { copy.Position = 0; written[relative] = Convert.ToHexStringLower(SHA256.HashData(copy)); }
                }
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(output, File.GetUnixFileMode(input));
                if (written[relative] != originals[relative]) throw new OperationException("归档复制校验失败，原目录保持有效。");
            }
            Rewrite(target, source, written);
            var id = Guid.NewGuid().ToString("N");
            ArchiveStore.WriteJson(SafePath.Resolve(target, OwnershipFile), new JsonObject { ["SchemaVersion"] = 1, ["OwnerId"] = id, ["AppRoot"] = store.Paths.Root });
            written[OwnershipFile] = ClientSchemes.SourceFingerprint(SafePath.Resolve(target, OwnershipFile));
            cancellationToken.ThrowIfCancellationRequested();
            if (Fingerprint(Snapshot(source)) != review.Fingerprint || Directory.EnumerateFiles(target, "*", SearchOption.AllDirectories).Count() != written.Count || written.Any(p => ClientSchemes.SourceFingerprint(SafePath.Resolve(target, p.Key)) != p.Value)) throw new OperationException("迁移期间目录发生变化，原目录保持有效。");
            ArchiveStore.WriteJson(store.Paths.Resolve(LocationFile), new JsonObject { ["SchemaVersion"] = 1, ["Directory"] = target, ["OwnerId"] = id });
            committed = true; store.Paths.SetPrivate(target);
        }
        catch
        {
            if (!committed) RemoveUnchanged(target, written);
            throw;
        }
        finally { foreach (var handle in handles) handle.Dispose(); }
        // Commit first, then remove only the source files we verified. Never remove a changed file.
        try { return new(RemoveUnchanged(source, originals)); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or OperationException) { return new(false); }
    }
    private void Rewrite(string target, string source, Dictionary<string, string> written)
    {
        foreach (var relative in written.Keys.ToArray())
        {
            if (!relative.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || relative.StartsWith("client-publish/", StringComparison.Ordinal)) continue;
            var file = SafePath.Resolve(target, relative);
            JsonNode? json;
            try { json = JsonNode.Parse(File.ReadAllBytes(file)); }
            catch (System.Text.Json.JsonException) { continue; } // Preserve unrelated user files byte for byte.
            if (json == null || json is JsonObject envelope && envelope.ContainsKey("protection")) continue;
            var changed = Rebase(json, source, target);
            if (ArchiveStore.Fingerprint(changed) == ArchiveStore.Fingerprint(json)) continue;
            ArchiveStore.WriteJson(file, changed); written[relative] = ClientSchemes.SourceFingerprint(file);
        }
        // Sources are hashed after plan paths have changed. Validated candidates must be regenerated.
        foreach (var relative in written.Keys.Where(p => p.EndsWith(".dotnet.private.json", StringComparison.Ordinal)).ToArray())
        {
            var file = SafePath.Resolve(target, relative); var original = store.ReadSecret(file);
            var changed = Rebase(original, source, target).AsObject();
            if (relative.StartsWith("client-schemes/", StringComparison.Ordinal))
            {
                changed.Remove("Candidate");
            }
            if (ArchiveStore.Fingerprint(original) != ArchiveStore.Fingerprint(changed)) { store.WriteSecret(file, changed); written[relative] = ClientSchemes.SourceFingerprint(file); }
            original.Clear(); changed.Clear();
        }
        foreach (var relative in written.Keys.Where(p => p.StartsWith("client-schemes/", StringComparison.Ordinal) && p.EndsWith(".dotnet.private.json", StringComparison.Ordinal)).ToArray())
        {
            var file = SafePath.Resolve(target, relative); var scheme = store.ReadSecret(file); var before = ArchiveStore.Fingerprint(scheme);
            if (scheme["Sources"] is JsonObject sources) foreach (var name in sources.Select(p => p.Key).ToArray())
                if (Inside(name, target)) sources[name] = ClientSchemes.SourceFingerprint(name);
            if (before != ArchiveStore.Fingerprint(scheme)) { store.WriteSecret(file, scheme); written[relative] = ClientSchemes.SourceFingerprint(file); }
            scheme.Clear();
        }
        foreach (var relative in written.Keys.Where(p => Path.GetFileName(p) == "SHA256SUMS.txt").OrderByDescending(p => p.Split('/').Length).ToArray())
        {
            var file = SafePath.Resolve(target, relative); var directory = Path.GetDirectoryName(file)!;
            var lines = File.ReadAllLines(file).Where(line => !string.IsNullOrWhiteSpace(line)).Select(line =>
            {
                if (line.Length < 67 || !System.Text.RegularExpressions.Regex.IsMatch(line[..64], "^[a-fA-F0-9]{64}$")) throw new OperationException("归档校验清单无效，未迁移。");
                var name = line[64..].TrimStart(' ', '*'); var entry = SafePath.Resolve(directory, name.Replace('\\', '/'));
                if (!File.Exists(entry)) throw new OperationException("归档校验清单引用缺失文件，未迁移。");
                return ClientSchemes.SourceFingerprint(entry) + "  " + name;
            });
            ArchiveStore.AtomicWrite(file, System.Text.Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n")); written[relative] = ClientSchemes.SourceFingerprint(file);
        }
    }
    private static JsonNode Rebase(JsonNode node, string source, string target)
    {
        string Map(string value)
        {
            if (!Path.IsPathFullyQualified(value)) return value;
            var path = Normal(value);
            return path.Equals(source, Comparison) || Inside(path, source) ? target + path[source.Length..] : value;
        }
        return node switch
        {
            JsonObject o => new JsonObject(o.Select(p => new KeyValuePair<string, JsonNode?>(Map(p.Key), p.Value == null ? null : Rebase(p.Value, source, target)))),
            JsonArray a => new JsonArray(a.Select(v => v == null ? null : Rebase(v, source, target)).ToArray()),
            JsonValue v when v.TryGetValue<string>(out var text) => JsonValue.Create(Map(text))!,
            _ => node.DeepClone()
        };
    }
    private static bool RemoveUnchanged(string directory, Dictionary<string, string> expected)
    {
        if (!Directory.Exists(directory)) return true;
        SafePath.CheckTree(directory);
        foreach (var item in expected)
        {
            var file = SafePath.Resolve(directory, item.Key);
            if (File.Exists(file) && ClientSchemes.SourceFingerprint(file) == item.Value) File.Delete(file);
        }
        foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.AllDirectories).OrderByDescending(p => p.Length))
            if (!Directory.EnumerateFileSystemEntries(child).Any()) Directory.Delete(child);
        if (Directory.EnumerateFileSystemEntries(directory).Any()) return false;
        Directory.Delete(directory); return true;
    }
}
