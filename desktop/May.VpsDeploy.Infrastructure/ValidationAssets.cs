using System.IO.Compression;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public interface IValidationAssets { string ResolveCore(string name); string DataDirectory { get; } string ExpectedVersion(string name) => ""; }
public sealed class ValidationAssets(AppPaths paths, string platform) : IValidationAssets
{
    public string DataDirectory => paths.Resolve("vendor/test-cores/" + platform + "/mihomo-geodata");
    public string ExpectedVersion(string name) => ArchiveStore.ReadJson(paths.Resolve("vendor/test-cores/" + platform + "/checksums.json"))["artifacts"]!.AsArray().Single(n => n!.Text("core") == name)!.Text("version");
    public string ResolveCore(string name)
    {
        var root = paths.Resolve("vendor/test-cores/" + platform);
        var manifest = ArchiveStore.ReadJson(SafePath.Resolve(root, "checksums.json"));
        var artifact = manifest["artifacts"]!.AsArray().FirstOrDefault(n => n!.Text("core") == name) ?? throw new OperationException("该平台缺少固定验证核心。");
        var archive = SafePath.Resolve(root, artifact.Text("file"));
        if (ArchiveStore.Digest(File.ReadAllBytes(archive)) != artifact.Text("sha256")) throw new OperationException("验证核心归档摘要不匹配，未替换现有缓存。");
        using var zip = ZipFile.OpenRead(archive);
        var executableName = platform.StartsWith("windows-") ? name + ".exe" : name;
        var entries = zip.Entries.Where(e => Path.GetFileName(e.FullName).Equals(executableName, StringComparison.OrdinalIgnoreCase) || name == "mihomo" && e.Name.StartsWith("mihomo", StringComparison.OrdinalIgnoreCase) && e.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (entries.Length != 1) throw new OperationException("验证归档中的核心不唯一。");
        using var source = entries[0].Open(); using var content = new MemoryStream(); source.CopyTo(content); var bytes = content.ToArray();
        var destination = paths.Resolve(".cache/dotnet-client-cores/" + artifact.Text("sha256") + "/" + executableName);
        if (File.Exists(destination)) { if (ArchiveStore.Digest(File.ReadAllBytes(destination)) != ArchiveStore.Digest(bytes)) throw new OperationException("验证核心缓存已改动，请先由维护者核对。"); }
        else ArchiveStore.AtomicWrite(destination, bytes);
        foreach (var data in manifest["data_files"]!.AsArray().Where(n => n!.Text("consumer") == name)) if (ArchiveStore.Digest(File.ReadAllBytes(SafePath.Resolve(root, data!.Text("file")))) != data.Text("sha256")) throw new OperationException("验证规则或 GeoData 摘要不匹配。");
        return destination;
    }
}
