using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class MonitorReadArchive(ArchiveStore store)
{
    // Resolve on every call so private-directory migration moves this archive
    // with the rest of the user's data, with no old-path compatibility copy.
    private string FilePath => store.Paths.Resolve("private/monitor-read.private.json");
    public MonitorReadConnection? Load()
    {
        if (!File.Exists(FilePath)) return null;
        var value = store.ReadSecret(FilePath);
        try { return MonitorReadConnection.FromJson(value); }
        finally { value.Clear(); }
    }
    public void Save(MonitorReadConnection connection)
    {
        var instances = store.ListInstances().Select(i => i.RelativePath).ToHashSet(StringComparer.Ordinal);
        foreach (var relative in connection.Bindings.Keys)
            if (!instances.Contains(relative)) throw new OperationException("绑定实例已移除，请重新选择。");
        var data = connection.ToJson();
        try { store.WriteSecret(FilePath, data); }
        finally { data.Clear(); }
    }
    public void Remove() { SafePath.CheckLinks(FilePath); if (File.Exists(FilePath)) File.Delete(FilePath); }
}

public sealed class MonitorReadClient : IDisposable, IMonitorReadProbe
{
    private const int MaxResponseBytes = 256 * 1024;
    private readonly HttpClient http;
    public MonitorReadClient() : this(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false, AutomaticDecompression = DecompressionMethods.None }) { }
    // Explicit handler injection is for isolated tests; the production handler
    // never follows redirects, sends cookies or relaxes TLS validation.
    public MonitorReadClient(HttpMessageHandler handler) { http = new(handler) { Timeout = TimeSpan.FromSeconds(10) }; }

    public async Task<MonitorReadSnapshot> FetchAsync(MonitorReadConnection connection, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var token = deadline.Token;
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(connection.Endpoint, MonitorReadConnection.SnapshotPath));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", connection.Token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) throw new OperationException("监测只读令牌无效、已过期或未被服务端启用；没有尝试管理员权限。");
            if ((int)response.StatusCode is >= 300 and < 400) throw new OperationException("监测地址返回重定向，已停止，未向新地址发送令牌。");
            if (response.StatusCode != HttpStatusCode.OK) throw new OperationException("监测服务未返回快照，请核对服务状态与只读接口版本。");
            if (response.Content.Headers.ContentType?.MediaType != "application/json" || response.Content.Headers.ContentEncoding.Count != 0 || response.Content.Headers.ContentLength > MaxResponseBytes) throw new OperationException("监测响应类型或大小不符合只读接口约定。");
            await using var source = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            while (true)
            {
                var count = await source.ReadAsync(chunk, token).ConfigureAwait(false);
                if (count == 0) break;
                if (buffer.Length + count > MaxResponseBytes) throw new OperationException("监测响应超过大小限制，已停止读取。");
                buffer.Write(chunk, 0, count);
            }
            return MonitorReadSnapshot.Parse(buffer.ToArray(), DateTimeOffset.UtcNow);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is HttpRequestException or IOException or OperationCanceledException)
        { throw new OperationException("监测连接失败或超时，请核对网络、TLS 与服务地址；最近快照不代表当前在线状态。"); }
    }
    public void Dispose() => http.Dispose();
}
