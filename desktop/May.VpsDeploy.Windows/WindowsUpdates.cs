using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Windows;

public sealed record UpdateAsset(string Name, string Url, string Sha256, long Bytes);
public sealed record ApplicationUpdate(string Version, UpdateAsset Installer, UpdateAsset Manifest, UpdateAsset Checksums, string ReleaseNotes = "");
public enum UpdatePhase { Preparing, Downloading, Verifying, Ready }
public sealed record ApplicationUpdateProgress(UpdatePhase Phase, long CompletedBytes, long TotalBytes)
{
    public double Percent => TotalBytes > 0 ? Math.Clamp(100d * CompletedBytes / TotalBytes, 0, 100) : 0;
}

public sealed class WindowsUpdates : IDisposable
{
    private readonly AppPaths paths;
    private readonly HttpClient client;
    public WindowsUpdates(AppPaths paths, string proxy) : this(paths, CreateClient(proxy)) { }
    // The caller can provide a transport for isolated update integration tests.
    public WindowsUpdates(AppPaths paths, HttpClient client) { this.paths = paths; this.client = client; }
    private static HttpClient CreateClient(string proxy)
    {
        var handler = new HttpClientHandler { UseProxy = proxy != "", Proxy = proxy == "" ? null : new WebProxy(proxy) };
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(8) }; client.DefaultRequestHeaders.UserAgent.ParseAdd("May-VPS-Deploy-Desktop"); return client;
    }
    public async Task<ApplicationUpdate?> CheckAsync(CancellationToken cancellationToken)
    {
        var current = ArchiveStore.ReadJson(paths.Resolve("config/application.json")).Text("version");
        var release = JsonNode.Parse(await ReadLimitedAsync("https://api.github.com/repos/mxh110708/may-vps-deploy/releases/latest", 2 * 1024 * 1024, cancellationToken))!.AsObject();
        var tag = release.Text("tag_name");
        if (!Regex.IsMatch(tag, "^v[0-9]+\\.[0-9]+\\.[0-9]+$")) throw new OperationException("正式发行版本无效。");
        var version = tag[1..];
        if (release.Flag("draft") || release.Flag("prerelease") || !Version.TryParse(version, out var latest) || latest <= Version.Parse(current)) return null;
        var name = "may-vps-deploy-v" + version + "-windows-amd64"; var entries = release["assets"]!.AsArray();
        UpdateAsset Asset(string filename, long maximum)
        {
            var entry = entries.SingleOrDefault(a => a!.Text("name") == filename) ?? throw new OperationException("正式发行缺少桌面更新资产。");
            var digest = entry.Text("digest"); var bytes = entry.Long("size");
            if (!Regex.IsMatch(digest, "^sha256:[a-f0-9]{64}$") || bytes <= 0 || bytes > maximum || entry.Text("state") != "uploaded") throw new OperationException("发行资产摘要或大小无效。");
            var url = entry.Text("browser_download_url");
            if (url != "https://github.com/mxh110708/may-vps-deploy/releases/download/" + tag + "/" + filename) throw new OperationException("发行资产来源异常。");
            return new(filename, url, digest[7..], bytes);
        }
        return new(version, Asset(name + "-setup.exe", 300L * 1024 * 1024), Asset(name + ".files.json", 2 * 1024 * 1024), Asset("SHA256SUMS.txt", 1024 * 1024), release.Text("body"));
    }
    public Task<string> PrepareAsync(ApplicationUpdate update, CancellationToken cancellationToken) => PrepareAsync(update, null, cancellationToken);
    public async Task<string> PrepareAsync(ApplicationUpdate update, IProgress<ApplicationUpdateProgress>? progress, CancellationToken cancellationToken)
    {
        UpdatePhase? lastPhase = null; var lastPercent = -1;
        void Report(UpdatePhase phase, long completed = 0, long total = 0)
        {
            var value = new ApplicationUpdateProgress(phase, completed, total); var percent = (int)value.Percent;
            if (phase == lastPhase && percent == lastPercent) return;
            lastPhase = phase; lastPercent = percent; progress?.Report(value);
        }
        Report(UpdatePhase.Preparing);
        var marker = paths.Resolve("installation.json");
        if (!File.Exists(marker)) throw new OperationException("此目录尚未使用安装包安装，请先选择正式安装包。");
        var installed = ArchiveStore.ReadJson(marker);
        if (installed.Number("schema_version") != 1 || installed.Text("type") != "installed" || installed.Text("app_id") != "may-vps-deploy-desktop") throw new OperationException("应用安装记录无效。");
        var checksumText = await ReadLimitedAsync(update.Checksums.Url, 1024 * 1024, cancellationToken);
        if (ArchiveStore.Digest(checksumText) != update.Checksums.Sha256 || checksumText.LongLength != update.Checksums.Bytes) throw new OperationException("发行校验清单摘要不匹配。");
        var sums = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in Encoding.UTF8.GetString(checksumText).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2 || !Regex.IsMatch(parts[0], "^[a-f0-9]{64}$") || !sums.TryAdd(parts[1], parts[0])) throw new OperationException("发行校验清单格式无效。");
        }
        var stage = paths.Resolve(".tmp/app-update-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(stage);
        try
        {
            var assets = new[] { update.Installer, update.Manifest }; var totalBytes = assets.Sum(a => a.Bytes); long downloaded = 0;
            Report(UpdatePhase.Downloading, 0, totalBytes);
            foreach (var asset in assets)
            {
                if (!sums.TryGetValue(asset.Name, out var hash) || hash != asset.Sha256) throw new OperationException("发行资产与校验清单不一致。");
                var destination = SafePath.Resolve(stage, asset.Name);
                using var response = await client.GetAsync(asset.Url, HttpCompletionOption.ResponseHeadersRead, cancellationToken); response.EnsureSuccessStatusCode();
                await using (var input = await response.Content.ReadAsStreamAsync(cancellationToken))
                await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, true))
                    await CopyLimitedAsync(input, output, asset.Bytes, cancellationToken, bytes => Report(UpdatePhase.Downloading, downloaded + bytes, totalBytes));
                downloaded += asset.Bytes;
                if (new FileInfo(destination).Length != asset.Bytes) throw new OperationException("更新资产大小不匹配，未安装。");
            }
            long verified = 0; Report(UpdatePhase.Verifying, 0, totalBytes);
            foreach (var asset in assets)
            {
                var destination = SafePath.Resolve(stage, asset.Name);
                await using var read = File.OpenRead(destination);
                if (read.Length != asset.Bytes || await HashAsync(read, bytes => Report(UpdatePhase.Verifying, verified + bytes, totalBytes), cancellationToken) != asset.Sha256) throw new OperationException("更新资产摘要或大小不匹配，未安装。");
                verified += asset.Bytes;
            }
            if (ArchiveStore.ReadJson(SafePath.Resolve(stage, update.Manifest.Name)).Text("version") != update.Version) throw new OperationException("更新版本与清单不一致。");
            var originalHelper = paths.Resolve("app-helpers/InstalledUpdate.exe");
            var currentManifest = ArchiveStore.ReadJson(paths.Resolve("application-files.json"));
            if (currentManifest.Text("version") != ArchiveStore.ReadJson(paths.Resolve("config/application.json")).Text("version")) throw new OperationException("当前应用版本与清单不一致。");
            var helperEntry = currentManifest["files"]!.AsArray().Single(n => n!.Text("path") == "app-helpers/InstalledUpdate.exe");
            if (ArchiveStore.Digest(File.ReadAllBytes(originalHelper)) != helperEntry!.Text("sha256")) throw new OperationException("更新辅助程序已变化，未执行。");
            var helper = SafePath.Resolve(stage, "InstalledUpdate.exe"); File.Copy(originalHelper, helper, false);
            using var process = Process.GetCurrentProcess();
            var job = new JsonObject { ["ProjectRoot"] = paths.Root, ["Stage"] = stage, ["Version"] = update.Version, ["ParentPid"] = 0, ["ParentStarted"] = "", ["LauncherPid"] = process.Id, ["LauncherStarted"] = process.StartTime.ToUniversalTime().ToString("o"), ["InstallerSha256"] = update.Installer.Sha256, ["ManifestSha256"] = update.Manifest.Sha256, ["CurrentManifestSha256"] = ArchiveStore.Digest(File.ReadAllBytes(paths.Resolve("application-files.json"))) };
            cancellationToken.ThrowIfCancellationRequested();
            ArchiveStore.WriteJson(SafePath.Resolve(stage, "update-job.private.json"), job); Report(UpdatePhase.Ready, totalBytes, totalBytes); return stage;
        }
        catch { SafePath.CheckTree(stage); Directory.Delete(stage, true); throw; }
    }
    public void Start(string stage)
    {
        SafePath.CheckTree(stage);
        var start = new ProcessStartInfo(SafePath.Resolve(stage, "InstalledUpdate.exe")) { UseShellExecute = false, CreateNoWindow = true }; start.ArgumentList.Add(SafePath.Resolve(stage, "update-job.private.json")); using var helper = Process.Start(start);
    }
    public void Discard(string stage)
    {
        var root = paths.Resolve(".tmp") + Path.DirectorySeparatorChar;
        if (!Path.GetFullPath(stage).StartsWith(root, StringComparison.OrdinalIgnoreCase) || !Regex.IsMatch(Path.GetFileName(stage), "^app-update-[a-f0-9]{32}$")) throw new OperationException("更新暂存不属于当前应用，未清理。");
        var job = ArchiveStore.ReadJson(SafePath.Resolve(stage, "update-job.private.json"));
        if (job.Text("ProjectRoot") != paths.Root || job.Text("Stage") != stage || job.Number("LauncherPid") != Environment.ProcessId) throw new OperationException("更新暂存身份发生变化，未清理。");
        SafePath.CheckTree(stage); Directory.Delete(stage, true);
    }
    private async Task<byte[]> ReadLimitedAsync(string url, int maximum, CancellationToken token)
    {
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token); response.EnsureSuccessStatusCode();
        await using var input = await response.Content.ReadAsStreamAsync(token); using var output = new MemoryStream();
        await CopyLimitedAsync(input, output, maximum, token); return output.ToArray();
    }
    private static async Task CopyLimitedAsync(Stream input, Stream output, long maximum, CancellationToken token, Action<long>? progress = null)
    {
        var buffer = new byte[65536]; long total = 0; int length;
        while ((length = await input.ReadAsync(buffer, token)) != 0)
        {
            total += length; if (total > maximum) throw new OperationException("更新下载超过发行声明的大小，已停止。");
            await output.WriteAsync(buffer.AsMemory(0, length), token);
            progress?.Invoke(total);
        }
    }
    private static async Task<string> HashAsync(Stream input, Action<long> progress, CancellationToken token)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); var buffer = new byte[65536]; long total = 0; int length;
        while ((length = await input.ReadAsync(buffer, token)) != 0)
        {
            token.ThrowIfCancellationRequested(); hash.AppendData(buffer, 0, length); total += length; progress(total);
        }
        token.ThrowIfCancellationRequested(); return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
    public void Dispose() => client.Dispose();
}
