using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class ClientSubscriptionDownload
{
    public const int MaximumBytes = 524288;
    public async Task<string> FetchAsync(JsonObject source, CancellationToken cancellationToken)
    {
        var uri = ClientSubscriptions.Validate(source);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(30)); var token = deadline.Token;
        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, Credentials = null, ConnectTimeout = TimeSpan.FromSeconds(8), MaxResponseHeadersLength = 8,
            MaxResponseDrainSize = 0, AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            UseProxy = source.Text("Network", "System") != "Direct", Proxy = source.Text("Network") == "Proxy" ? new WebProxy(source.Text("Proxy")) : null };
        using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan }; http.DefaultRequestHeaders.UserAgent.ParseAdd("May-VPS-Deploy");
        try
        {
            for (var redirects = 0; ; redirects++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri); request.Headers.CacheControl = new() { NoCache = true, NoStore = true };
                using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
                if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
                {
                    if (redirects >= 3 || response.Headers.Location == null) throw new OperationException("订阅重定向过多或缺少目标地址。");
                    var next = new Uri(uri, response.Headers.Location); var nextDefinition = source.DeepClone().AsObject(); nextDefinition["Url"] = next.AbsoluteUri; ClientSubscriptions.Validate(nextDefinition);
                    if (uri.Scheme == "https" && next.Scheme != "https") throw new OperationException("订阅重定向降低了传输安全性，未继续下载。"); uri = next; continue;
                }
                if (!response.IsSuccessStatusCode) throw new OperationException("订阅服务器返回 HTTP " + (int)response.StatusCode + "；旧节点未修改。");
                if (response.Content.Headers.ContentLength is > MaximumBytes) throw new OperationException("订阅响应超过 512 KiB；旧节点未修改。");
                using var stream = await response.Content.ReadAsStreamAsync(token); using var output = new MemoryStream(); var buffer = new byte[8192];
                while (true)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, MaximumBytes + 1 - output.Length)), token); if (read == 0) break; output.Write(buffer, 0, read);
                    if (output.Length > MaximumBytes) throw new OperationException("订阅响应超过 512 KiB；旧节点未修改。");
                }
                try { return new UTF8Encoding(false, true).GetString(output.GetBuffer(), 0, (int)output.Length); }
                catch (DecoderFallbackException) { throw new OperationException("订阅响应不是有效 UTF-8 文本；旧节点未修改。"); }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new OperationException("订阅获取超时；旧节点未修改。"); }
        catch (Exception error) when (error is HttpRequestException or IOException) { throw new OperationException("无法获取订阅，请检查连接方式、代理和来源状态；旧节点未修改。"); }
    }
}
