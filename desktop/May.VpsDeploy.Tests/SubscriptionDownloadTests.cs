using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private sealed class SubscriptionServer : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new();
        private readonly List<Task> clients = new();
        private readonly Task loop;
        public ConcurrentQueue<string> Requests { get; } = new();
        public TaskCompletionSource SlowStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string Address { get; }
        public string Body { get; set; } = "anytls://synthetic-download@entry.example:443?sni=example.com#Download";
        public SubscriptionServer()
        {
            listener.Start(); Address = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
            loop = Task.Run(async () =>
            {
                try { while (!stop.IsCancellationRequested) { var client = await listener.AcceptTcpClientAsync(stop.Token); clients.Add(Respond(client)); } }
                catch (OperationCanceledException) { }
            });
        }
        private async Task Respond(TcpClient client)
        {
            using (client)
            try
            {
                using var stream = client.GetStream(); using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
                var request = await reader.ReadLineAsync(stop.Token) ?? ""; Requests.Enqueue(request); string? line;
                do { line = await reader.ReadLineAsync(stop.Token); } while (!string.IsNullOrEmpty(line));
                var target = request.Split(' ')[1]; var path = target.StartsWith("http", StringComparison.Ordinal) ? new Uri(target).AbsolutePath : target.Split('?')[0];
                var body = Encoding.UTF8.GetBytes(Body); var status = "200 OK"; var headers = ""; var slow = false; var chunked = false;
                if (path == "/redirect") { status = "302 Found"; headers = "Location: /ok\r\n"; body = []; }
                if (path == "/loop") { status = "302 Found"; headers = "Location: /loop\r\n"; body = []; }
                if (path == "/failure") { status = "503 Service Unavailable"; body = []; }
                if (path == "/too-large") { headers = "Content-Length: " + (ClientSubscriptionDownload.MaximumBytes + 1) + "\r\n"; body = []; }
                if (path == "/stream-large") { chunked = true; body = Enumerable.Repeat((byte)'x', ClientSubscriptionDownload.MaximumBytes + 1).ToArray(); }
                if (path == "/invalid-utf8") body = [255];
                if (path == "/slow") { slow = true; headers = "Content-Length: 123\r\n"; body = []; }
                if (path == "/gzip") { using var compressed = new MemoryStream(); using (var zip = new System.IO.Compression.GZipStream(compressed, System.IO.Compression.CompressionMode.Compress, leaveOpen: true)) await zip.WriteAsync(body, stop.Token); body = compressed.ToArray(); headers = "Content-Encoding: gzip\r\n"; }
                if (chunked) headers += "Transfer-Encoding: chunked\r\n";
                else if (!headers.Contains("Content-Length:", StringComparison.Ordinal)) headers += "Content-Length: " + body.Length + "\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 " + status + "\r\nConnection: close\r\n" + headers + "\r\n"), stop.Token);
                if (slow) { SlowStarted.TrySetResult(); await Task.Delay(Timeout.Infinite, stop.Token); }
                if (chunked) { await stream.WriteAsync(Encoding.ASCII.GetBytes(body.Length.ToString("X") + "\r\n"), stop.Token); await stream.WriteAsync(body, stop.Token); await stream.WriteAsync(Encoding.ASCII.GetBytes("\r\n0\r\n\r\n"), stop.Token); }
                else await stream.WriteAsync(body, stop.Token);
            }
            catch (Exception error) when (error is OperationCanceledException or IOException or SocketException) { }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await loop; await Task.WhenAll(clients); stop.Dispose(); }
    }
    private async Task SubscriptionDownloadExperience()
    {
        await using var server = new SubscriptionServer(); var download = new ClientSubscriptionDownload(); var source = ClientSubscriptions.New("US-West-LA Entry"); source["Network"] = "Direct";
        source["Url"] = server.Address + "/redirect";
        Check(await download.FetchAsync(source, CancellationToken.None) == server.Body && server.Requests.Count == 2, "bounded subscription redirect failed");
        source["Url"] = server.Address + "/gzip"; Check(await download.FetchAsync(source, CancellationToken.None) == server.Body, "compressed subscription was not decoded");
        source["Url"] = server.Address + "/loop"; var before = server.Requests.Count; await RefusesAsync(() => download.FetchAsync(source, CancellationToken.None), "unbounded redirect accepted"); Check(server.Requests.Count - before == 4, "redirect limit retried or was not enforced");
        foreach (var path in new[] { "/failure", "/too-large", "/stream-large", "/invalid-utf8" })
        {
            source["Url"] = server.Address + path; await RefusesAsync(() => download.FetchAsync(source, CancellationToken.None), "invalid subscription response accepted: " + path);
        }
        source["Network"] = "Proxy"; source["Proxy"] = server.Address; source["Url"] = "http://127.0.0.1:9/proxy-proof";
        Check(await download.FetchAsync(source, CancellationToken.None) == server.Body && server.Requests.Last().StartsWith("GET http://127.0.0.1:9/proxy-proof ", StringComparison.Ordinal), "selected proxy was ignored or bypassed");
        source["Network"] = "Direct"; source["Url"] = server.Address + "/slow"; using var cancellation = new CancellationTokenSource();
        var pending = download.FetchAsync(source, cancellation.Token); await server.SlowStarted.Task.WaitAsync(TimeSpan.FromSeconds(5)); var watch = Stopwatch.StartNew(); cancellation.Cancel(); var cancelled = false;
        try { await pending; } catch (OperationCanceledException) { cancelled = true; }
        Check(cancelled && watch.Elapsed < TimeSpan.FromSeconds(3), "subscription cancellation waited for network timeout");
        source["Url"] = server.Address + "/failure?key=synthetic-secret";
        try { await download.FetchAsync(source, CancellationToken.None); throw new Exception("request unexpectedly succeeded"); }
        catch (OperationException error) { Check(!error.Message.Contains("synthetic-secret") && !error.Message.Contains(server.Address), "network error exposed private subscription URL"); }
    }
}
