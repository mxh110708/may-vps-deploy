using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    public async Task RunMonitorReadTests()
    {
        using var f = new Fixture(repository); await MonitorReadExperience(f);
        Console.WriteLine($"PASS: {assertions} read-only monitoring, encrypted archive, response boundary, cancellation and loopback assertions; no production connections.");
    }

    private static JsonObject MonitorSample(string id, DateTimeOffset? now = null) => new()
    {
        ["schema_version"] = 1, ["server_version"] = "0.1.0-rc.1+read-api", ["captured_at"] = (now ?? DateTimeOffset.UtcNow).ToString("O"),
        ["nodes"] = new JsonArray(new JsonObject
        {
            ["uuid"] = id, ["online"] = true, ["report_at"] = (now ?? DateTimeOffset.UtcNow).ToString("O"),
            ["metrics"] = new JsonObject { ["cpu_percent"] = 12.5, ["memory_used"] = 512L, ["memory_total"] = 1024L, ["upload_per_sec"] = 10L, ["download_per_sec"] = 20L, ["upload_total"] = 100L, ["download_total"] = 200L }
        })
    };

    private async Task MonitorReadExperience(Fixture f)
    {
        var plan = f.Plan("Monitor-read"); f.SaveInstance(plan); var relative = f.Relative(plan);
        var id = Guid.NewGuid().ToString("D");
        var token = MonitorReadConnection.NewToken();
        var bindings = new Dictionary<string, string> { [relative] = id };
        var connection = new MonitorReadConnection("https://monitor.example/prefix", token, bindings);
        Check(connection.Endpoint.AbsoluteUri == "https://monitor.example/prefix/", "base prefix was lost");
        Check(!connection.ToString().Contains(token), "connection display leaked credential");
        Refuses(() => new MonitorReadConnection("https://monitor.example/", "synthetic-admin-key", bindings), "admin key accepted for monitoring");
        foreach (var endpoint in new[] { "http://monitor.example/", "https://user:pass@monitor.example/", "https://monitor.example/?token=secret", "https://monitor.example/#secret", "file:///tmp", "https://monitor.example/%2fprivate" })
            Refuses(() => new MonitorReadConnection(endpoint, token, bindings), "unsafe endpoint accepted");
        foreach (var endpoint in new[] { "http://127.0.0.1:12345/", "http://[::1]:12345/" }) Check(new MonitorReadConnection(endpoint, token, bindings).Endpoint.IsLoopback, "loopback test endpoint rejected");
        Refuses(() => new MonitorReadConnection(connection.Endpoint.AbsoluteUri, token, new Dictionary<string, string>()), "unscoped connection accepted");
        Refuses(() => new MonitorReadConnection(connection.Endpoint.AbsoluteUri, token, new Dictionary<string, string> { [relative] = id, ["Example/Other/May-VPS-Deploy"] = id }), "ambiguous duplicate binding accepted");
        Refuses(() => new MonitorReadConnection(connection.Endpoint.AbsoluteUri, token, new Dictionary<string, string> { ["../escape"] = id }), "binding path escaped");
        var archive = new MonitorReadArchive(f.Store);
        Check(archive.Load() == null, "missing connection became configured"); archive.Save(connection);
        var file = f.Paths.Resolve("private/monitor-read.private.json");
        Check(!File.ReadAllText(file).Contains(token), "credential saved in plaintext");
        Check(archive.Load()?.Identity == connection.Identity, "encrypted connection did not round trip");
        var ciphertext = File.ReadAllText(file); archive.Save(connection);
        Check(File.ReadAllText(file) == ciphertext, "unchanged connection rewrote encrypted data");
        var env = connection.ProvisioningEnvironment(DateTimeOffset.UtcNow);
        Check(!env.Contains(token) && env.Contains("MAY_MONITOR_READ_TOKEN_SHA256=") && env.Contains(id), "provisioning exposed raw token or omitted explicit scope");
        var now = DateTimeOffset.UtcNow;
        var sample = MonitorSample(id, now);
        MonitorReadSnapshot Parse(JsonObject value) => MonitorReadSnapshot.Parse(Encoding.UTF8.GetBytes(value.ToJsonString()), now);
        var snapshot = Parse(sample); var node = snapshot.Nodes[id];
        Check(node.Status(now, now, false) == "在线" && node.Metrics?.CpuPercent == 12.5, "valid snapshot lost values");
        Check(node.Status(now, now, true) != "在线", "failed refresh left a healthy online state");
        Check(node.Status(now.AddMinutes(2), now, false).Contains("过期"), "stale snapshot remained current");
        Check((node with { Online = false }).Status(now, now, false).StartsWith("离线"), "offline node remained online");
        Check((node with { ReportAt = null, Metrics = null }).Status(now, now, false) == "尚无上报", "missing sample displayed zero load");
        Check((node with { ReportAt = now.AddSeconds(10) }).Status(now, now, false) == "节点时间异常", "future clock interpreted as fresh data");
        Check((node with { ReportAt = now.AddMinutes(-2) }).Status(now, now, false).Contains("上报已过期"), "old agent sample remained current");
        foreach (var field in new[] { "memory_used", "upload_per_sec", "download_total" })
        {
            var bad = sample.DeepClone().AsObject(); bad["nodes"]![0]!["metrics"]![field] = -1;
            Refuses(() => Parse(bad), "negative metric accepted");
        }
        var invalid = sample.DeepClone().AsObject(); invalid["schema_version"] = 99; Refuses(() => Parse(invalid), "unknown snapshot schema accepted");
        invalid = sample.DeepClone().AsObject(); invalid["nodes"]!.AsArray().Add(invalid["nodes"]![0]!.DeepClone()); Refuses(() => Parse(invalid), "duplicate node accepted");
        invalid = sample.DeepClone().AsObject(); invalid["captured_at"] = now.AddMinutes(-3).ToString("O"); Refuses(() => Parse(invalid), "cached response accepted");
        invalid = sample.DeepClone().AsObject(); invalid["nodes"]![0]!["metrics"]!["cpu_percent"] = 101; Refuses(() => Parse(invalid), "invalid CPU accepted");

        using (var client = new MonitorReadClient(new MonitorHandler((request, ct) =>
        {
            var target = request.RequestUri ?? throw new Exception("Missing HTTP target");
            Check(request.Method == HttpMethod.Get && target.AbsolutePath == "/prefix/api/integration/v1/snapshot", "monitoring used a write path");
            Check(request.Headers.Authorization?.Parameter == token && target.Query == "", "credential not confined to header");
            return Task.FromResult(MonitorResponse(sample));
        })))
        {
            Check((await client.FetchAsync(connection, default)).Nodes[id].Online, "snapshot was not read");
        }
        foreach (var status in new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.Found, HttpStatusCode.ServiceUnavailable })
        {
            using var client = new MonitorReadClient(new MonitorHandler((_, _) => Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent("synthetic-server-secret-" + token), Headers = { Location = new Uri("https://untrusted.example/") } })));
            try { await client.FetchAsync(connection, default); throw new Exception("invalid response accepted"); }
            catch (OperationException safe) { Check(!safe.Message.Contains(token) && !safe.Message.Contains("synthetic-server-secret"), "server error leaked secret"); }
        }
        using (var client = new MonitorReadClient(new MonitorHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("<html>login</html>", Encoding.UTF8, "text/html") }))))
            await RefusesAsync(() => client.FetchAsync(connection, default), "login HTML was treated as a snapshot");
        using (var client = new MonitorReadClient(new MonitorHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new OversizedMonitorContent() }))))
            await RefusesAsync(() => client.FetchAsync(connection, default), "unknown-length oversized response accepted");
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using (var client = new MonitorReadClient(new MonitorHandler(async (_, ct) => { started.SetResult(); await Task.Delay(Timeout.Infinite, ct); return MonitorResponse(sample); })))
        using (var cancelRead = new CancellationTokenSource())
        {
            var reading = client.FetchAsync(connection, cancelRead.Token); await started.Task; cancelRead.Cancel();
            try { await reading; throw new Exception("cancel ignored"); } catch (OperationCanceledException) { Check(true, "request cancellation propagated"); }
        }
        var bodyStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using (var client = new MonitorReadClient(new MonitorHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new WaitingMonitorContent(bodyStarted) }))))
        using (var cancelBody = new CancellationTokenSource())
        {
            var reading = client.FetchAsync(connection, cancelBody.Token); await bodyStarted.Task.WaitAsync(TimeSpan.FromSeconds(3)); cancelBody.Cancel();
            try { await reading.WaitAsync(TimeSpan.FromSeconds(3)); throw new Exception("body cancellation ignored"); } catch (OperationCanceledException) { Check(true, "body cancellation propagated after headers"); }
        }
        await MonitorReadLoopback(connection, bindings, sample);
        var beforePlan = File.ReadAllBytes(SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json"));
        archive.Remove(); Check(archive.Load() == null && File.ReadAllBytes(SafePath.Resolve(f.Paths.Instance(relative), "deployment-plan.json")).SequenceEqual(beforePlan), "disconnect altered instance archive");
    }

    private async Task MonitorReadLoopback(MonitorReadConnection connection, Dictionary<string, string> bindings, JsonObject sample)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var redirected = new TcpListener(IPAddress.Loopback, 0); redirected.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = Task.Run(async () =>
        {
            for (var requestNumber = 0; requestNumber < 2; requestNumber++)
            {
            using var socket = await listener.AcceptTcpClientAsync(timeout.Token);
            await using var stream = socket.GetStream(); using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true);
            var first = await reader.ReadLineAsync(timeout.Token); var authorization = ""; var cookie = false;
            for (var i = 0; i < 40; i++) { var line = await reader.ReadLineAsync(timeout.Token); if (string.IsNullOrEmpty(line)) break; if (line.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)) authorization = line; if (line.StartsWith("Cookie:", StringComparison.OrdinalIgnoreCase)) cookie = true; }
            Check(first == "GET /api/integration/v1/snapshot HTTP/1.1" && authorization.EndsWith(connection.Token, StringComparison.Ordinal), "actual HTTP request used wrong path or credential transport");
            Check(!cookie, "monitoring reused a web session cookie");
            if (requestNumber == 1)
            {
                var target = (IPEndPoint)redirected.LocalEndpoint;
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target.Port}/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), timeout.Token);
                continue;
            }
            var body = Encoding.UTF8.GetBytes(sample.ToJsonString());
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: session_token=synthetic-cookie; Path=/\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"), timeout.Token);
            await stream.WriteAsync(body, timeout.Token);
            }
        }, timeout.Token);
        using var client = new MonitorReadClient();
        var loopback = new MonitorReadConnection($"http://127.0.0.1:{endpoint.Port}/", connection.Token, bindings);
        Check((await client.FetchAsync(loopback, timeout.Token)).Nodes.Count == 1, "real loopback response failed");
        await RefusesAsync(() => client.FetchAsync(loopback, timeout.Token), "real HTTP redirect followed");
        await server; Check(!redirected.Pending(), "redirect destination received a connection");
    }

    private static HttpResponseMessage MonitorResponse(JsonObject value) => new(HttpStatusCode.OK) { Content = new StringContent(value.ToJsonString(), Encoding.UTF8, "application/json") };
    private sealed class MonitorHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => action(request, token); }
    private sealed class OversizedMonitorContent : HttpContent
    {
        public OversizedMonitorContent() { Headers.ContentType = new MediaTypeHeaderValue("application/json"); }
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(new byte[256 * 1024 + 1]).AsTask();
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new MemoryStream(new byte[256 * 1024 + 1], false));
    }
    private sealed class WaitingMonitorContent : HttpContent
    {
        private readonly TaskCompletionSource started;
        public WaitingMonitorContent(TaskCompletionSource started) { this.started = started; Headers.ContentType = new MediaTypeHeaderValue("application/json"); }
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new NotSupportedException();
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new WaitingMonitorStream(started));
        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken token) => CreateContentReadStreamAsync();
    }
    private sealed class WaitingMonitorStream(TaskCompletionSource started) : Stream
    {
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) { started.TrySetResult(); await Task.Delay(Timeout.Infinite, token); return 0; }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
