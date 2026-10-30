using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

internal static class UpdateMetadataTests
{
    public static async Task Run(string root, Action<bool, string> check)
    {
        Directory.CreateDirectory(Path.Combine(root, "config"));
        ArchiveStore.WriteJson(Path.Combine(root, "config/application.json"), new JsonObject { ["version"] = "0.9.38" });
        JsonObject Release(long bytes) => new() { ["tag_name"] = "v0.9.39", ["assets"] = new JsonArray(new[] { ("may-vps-deploy-v0.9.39-windows-amd64-setup.exe", bytes), ("may-vps-deploy-v0.9.39-windows-amd64.files.json", 100L), ("SHA256SUMS.txt", 100L) }.Select(p => (JsonNode?)new JsonObject { ["name"] = p.Item1, ["size"] = p.Item2, ["digest"] = "sha256:" + new string('a', 64), ["state"] = "uploaded", ["browser_download_url"] = "https://github.com/mxh110708/may-vps-deploy/releases/download/v0.9.39/" + p.Item1 }).ToArray()) };
        async Task<ApplicationUpdate?> Read(JsonObject data)
        {
            using var updater = new WindowsUpdates(new AppPaths(root), new HttpClient(new MetadataTransport(data)));
            return await updater.CheckAsync(default);
        }
        async Task Reject(JsonObject data, string message)
        {
            try { await Read(data); } catch (OperationException) { check(true, message); return; }
            check(false, message);
        }
        check((await Read(Release(335718775)))?.Installer.Bytes == 335718775, "paired-core package rejected at the old size limit");
        check((await Read(Release(512L * 1024 * 1024))) != null, "maximum bounded installer rejected");
        await Reject(Release(512L * 1024 * 1024 + 1), "oversize installer accepted");
        var changed = Release(100); changed["assets"]![1]!["size"] = 3 * 1024 * 1024;
        await Reject(changed, "manifest limit grew with installer limit");
        changed = Release(100); changed["assets"]![0]!["browser_download_url"] = "https://example.invalid/setup.exe";
        await Reject(changed, "foreign download bypassed source identity");
        changed = Release(100); changed["assets"]![0]!["state"] = "uploading";
        await Reject(changed, "unfinished release attachment accepted");
        changed = Release(100); changed["assets"]![0]!["digest"] = "sha256:invalid";
        await Reject(changed, "size change weakened digest validation");
    }
    private sealed class MetadataTransport(JsonObject data) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.AbsoluteUri != "https://api.github.com/repos/mxh110708/may-vps-deploy/releases/latest") throw new InvalidOperationException("Unexpected update request.");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(data.ToJsonString(), Encoding.UTF8, "application/json") });
        }
    }
}
