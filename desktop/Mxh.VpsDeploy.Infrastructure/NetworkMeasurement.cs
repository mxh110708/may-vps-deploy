using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Infrastructure;

public sealed class NetworkMeasurement(IValidationAssets assets, IExternalToolRunner tools) : INetworkMeasurement
{
    public async Task<JsonObject> MeasureAsync(NetworkMeasurementPath path, JsonObject options, string directory,
        Func<CancellationToken, Task<JsonObject>> observe, IProgress<string> progress, CancellationToken cancellationToken)
    {
        NetworkTuning.ValidateMeasurement(options);
        var node = path.Entry ?? path.Node;
        var executable = assets.ResolveCore("sing-box");
        await ProtocolValidation.VerifyVersion(assets, tools, "sing-box", executable, cancellationToken);
        var work = SafePath.Resolve(directory, "network-core-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        var configuration = SafePath.Resolve(work, "probe.private.json"); ArchiveStore.WriteJson(configuration, ClientProfiles.SingProbe(path.Node, port, path.Entry));
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "run", "-c", configuration }) start.ArgumentList.Add(arg);
        Process started;
        try
        {
            var check = await tools.RunAsync(executable, ["check", "-c", configuration], null, TimeSpan.FromSeconds(30), cancellationToken); check.RequireSuccess("测速核心拒绝配置，未启动代理。");
            started = Process.Start(start) ?? throw new OperationException("无法启动隔离测速核心。");
        }
        catch { SafePath.CheckTree(work); Directory.Delete(work, true); throw; }
        using var process = started;
        if (OperatingSystem.IsWindows()) try { process.PriorityClass = ProcessPriorityClass.BelowNormal; } catch (InvalidOperationException) { }
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(NetworkTuning.DurationSeconds(options)));
        var token = deadline.Token; var transfers = new JsonArray(); var idle = new List<double>(); var loaded = new List<double>(); var observations = new List<JsonObject>();
        var startup = new JsonArray();
        long reservedPayload = 0;
        var result = new JsonObject { ["Status"] = "Incomplete", ["EvidencePolicy"] = NetworkTuning.EvidencePolicy, ["Path"] = NetworkTuning.Topology(options), ["Family"] = node.Family, ["Startup"] = startup,
            ["Core"] = "sing-box", ["PayloadBudgetBytes"] = NetworkTuning.PayloadBudget(options), ["Transfers"] = transfers,
            ["EgressVerified"] = false, ["Udp"] = new JsonObject { ["Status"] = "NotMeasured" } };
        try
        {
            var ready = false;
            for (var i = 0; i < 50 && !process.HasExited; i++)
            {
                token.ThrowIfCancellationRequested();
                try { using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, port, token); ready = true; break; }
                catch (SocketException) { await Task.Delay(100, token); }
            }
            if (!ready) throw new OperationException("测速核心未就绪。");
            using var handler = Handler(port);
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
            http.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Encoding", "identity");
            http.DefaultRequestHeaders.CacheControl = new() { NoCache = true, NoStore = true };
            progress.Report("正在核对所选入口的真实代理出口。");
            using (var response = await http.GetAsync(path.ExpectedEgress.Contains(':') ? "https://api6.ipify.org" : "https://api.ipify.org", HttpCompletionOption.ResponseHeadersRead, token))
            {
                response.EnsureSuccessStatusCode(); if (response.Content.Headers.ContentLength is > 128) throw new OperationException("出口检查返回异常。");
                using var stream = await response.Content.ReadAsStreamAsync(token); var bytes = new byte[129]; var count = 0;
                while (count < bytes.Length) { var read = await stream.ReadAsync(bytes.AsMemory(count), token); if (read == 0) break; count += read; }
                var address = System.Text.Encoding.UTF8.GetString(bytes, 0, count).Trim();
                if (!IPAddress.TryParse(address, out var parsed) || !IPAddress.TryParse(path.ExpectedEgress, out var expected) || !parsed.Equals(expected)) throw new OperationException("所选路径的最终出口与归档不一致，测速未计为有效。");
                result["EgressVerified"] = true;
            }
            progress.Report("重复测量两个独立目标的短连接启动，保护网页与视频起步。");
            foreach (var endpoint in new[] { "Cloudflare", "Hetzner" })
            for (var round = 1; round <= 3; round++) startup.Add(await Startup(port, endpoint, round, token));
            progress.Report("采集空闲响应时间；无需填写 RTT。");
            // Warm the HTTPS connection before measuring idle response latency.
            await Latency(http, new List<double>(), token);
            for (var i = 0; i < 8; i++) { await Latency(http, idle, token); await Task.Delay(150, token); }
            observations.Add(await observe(token));
            // Eighteen bounded rounds: two independent download peers, one public upload peer.
            // Payload reservations are global, including all parallel streams; diagnostics do not try to saturate indefinitely.
            var budget = NetworkTuning.PayloadBudget(options) - Math.Min(NetworkTuning.PayloadBudget(options) / 8, 8388608);
            var roundBytes = budget / 18;
            for (var round = 0; round < 3; round++)
            foreach (var direction in new[] { "Download", "Upload" })
            foreach (var endpoint in direction == "Download" ? new[] { "Cloudflare", "Hetzner" } : new[] { "Cloudflare" })
            foreach (var streams in new[] { 1, 4 })
            {
                token.ThrowIfCancellationRequested(); progress.Report($"{endpoint} · {direction switch { "Download" => "下载", _ => "上传" }} · {streams} 个连接 · 第 {round + 1}/3 轮。");
                var phasePoints = new List<JsonObject> { await observe(token) };
                var amount = roundBytes / streams; var watch = Stopwatch.StartNew();
                reservedPayload += amount * streams;
                using var phase = CancellationTokenSource.CreateLinkedTokenSource(token);
                var latency = SampleLoaded(http, loaded, phase.Token);
                var socketSamples = SampleSockets(observe, phasePoints, phase.Token, token);
                var operations = Enumerable.Range(0, streams).Select(_ => Transfer(http, direction, endpoint, amount, token)).ToArray();
                long completedBytes = 0; var complete = false;
                try { var payloads = await Task.WhenAll(operations); completedBytes = payloads.Sum(); complete = payloads.All(bytes => bytes == amount); }
                catch (Exception error) when (error is HttpRequestException or IOException or OperationException || error is OperationCanceledException && !token.IsCancellationRequested) { result["TransferFailure"] = "EndpointOrPathUnavailable"; }
                finally
                {
                    watch.Stop(); phase.Cancel(); try { await latency; } catch (OperationCanceledException) { }
                    try { await socketSamples; } catch (OperationCanceledException) { }
                    phasePoints.Add(await observe(token));
                    if (round == 0 && streams == 4) observations.AddRange(phasePoints);
                }
                var tcp = NetworkTuning.SocketEvidence(phasePoints, direction == "Download" ? "ToUser" : "ToNextHop");
                tcp["PayloadMatched"] = tcp.Flag("ByteCoverageKnown") && tcp.Long("BytesSent") >= amount * streams * .7 && tcp.Long("BytesSent") <= amount * streams * 1.5;
                transfers.Add(new JsonObject { ["Endpoint"] = endpoint, ["Direction"] = direction, ["Streams"] = streams, ["Round"] = round + 1, ["Bytes"] = completedBytes,
                    ["TcpEvidence"] = tcp,
                    ["RequestedBytes"] = amount * streams, ["Seconds"] = watch.Elapsed.TotalSeconds, ["Mbps"] = watch.Elapsed.TotalSeconds > 0 ? completedBytes * 8 / watch.Elapsed.TotalSeconds / 1000000 : 0, ["Complete"] = complete });
            }
            progress.Report("采集有限 UDP 样本和 VPS 端状态。");
            result["Udp"] = await UdpSample(port, token);
            observations.Add(await observe(token)); result["Status"] = transfers.OfType<JsonObject>().All(x => x.Flag("Complete")) ? "Measured" : "Incomplete";
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { result["LimitReached"] = "Duration"; }
        catch (Exception error) when (error is HttpRequestException or SocketException or IOException or OperationException) { result["SafeFailure"] = error is OperationException ? error.Message : "所选路径或测速服务不可用；未确认性能。"; }
        finally
        {
            if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); await Task.WhenAll(stdout, stderr);
            SafePath.CheckTree(work); Directory.Delete(work, true);
        }
        result["IdleLatencyMs"] = new JsonArray(idle.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
        result["LoadedLatencyMs"] = new JsonArray(loaded.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
        result["Observations"] = new JsonArray(observations.Select(x => (JsonNode?)new JsonObject { ["BootId"] = x["BootId"]?.DeepClone(), ["Cpu"] = x["Cpu"]?.DeepClone(), ["MemoryKiB"] = x["MemoryKiB"]?.DeepClone() }).ToArray());
        if (observations.Count > 0)
        {
            var server = observations[^1].DeepClone().AsObject();
            server.Put("Cpu.BusyPercent", JsonValue.Create(observations.Max(x => NetworkTuning.Value(x, "Cpu.BusyPercent"))));
            server.Put("Cpu.StealPercent", JsonValue.Create(observations.Max(x => NetworkTuning.Value(x, "Cpu.StealPercent"))));
            server.Put("Tcp.RttMs", new JsonArray(observations.SelectMany(x => (x.At("Tcp.RttMs") as JsonArray ?? []).Select(y => y?.DeepClone())).ToArray()));
            result["ServerAfter"] = server;
        }
        result["ReservedPayloadBytes"] = reservedPayload;
        cancellationToken.ThrowIfCancellationRequested(); return result;
    }
    private static SocketsHttpHandler Handler(int port) => new() { Proxy = new WebProxy("http://127.0.0.1:" + port), UseProxy = true,
        AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.None, MaxConnectionsPerServer = 8,
        ConnectTimeout = TimeSpan.FromSeconds(8), PooledConnectionLifetime = TimeSpan.FromSeconds(60), MaxResponseDrainSize = 0 };
    private static async Task SampleSockets(Func<CancellationToken, Task<JsonObject>> observe, List<JsonObject> points, CancellationToken stop, CancellationToken token)
    {
        while (!stop.IsCancellationRequested)
        {
            points.Add(await observe(token)); await Task.Delay(100, stop);
        }
    }
    private static async Task<JsonObject> Startup(int port, string endpoint, int round, CancellationToken token)
    {
        var result = new JsonObject { ["Endpoint"] = endpoint, ["Round"] = round, ["Complete"] = false };
        using var handler = Handler(port); using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint == "Cloudflare" ? "https://speed.cloudflare.com/__down?bytes=1024" : "https://fsn1-speed.hetzner.com/100MB.bin");
        request.Headers.Range = new(0, 1023); request.Headers.ConnectionClose = true;
        var watch = Stopwatch.StartNew();
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token); response.EnsureSuccessStatusCode();
            if (endpoint == "Hetzner" && response.StatusCode != HttpStatusCode.PartialContent) throw new HttpRequestException("The endpoint did not honor the payload range.");
            using var body = await response.Content.ReadAsStreamAsync(token); var bytes = new byte[1024]; await body.ReadExactlyAsync(bytes, token);
            watch.Stop(); result["Complete"] = true; result["Milliseconds"] = watch.Elapsed.TotalMilliseconds;
        }
        catch (Exception error) when (error is HttpRequestException or IOException || error is OperationCanceledException && !token.IsCancellationRequested) { result["Failure"] = "EndpointOrPathUnavailable"; }
        return result;
    }
    private static async Task<long> Transfer(HttpClient http, string direction, string endpoint, long amount, CancellationToken token)
    {
        using var request = new HttpRequestMessage(direction == "Download" ? HttpMethod.Get : HttpMethod.Post,
            direction == "Download" ? endpoint == "Hetzner" ? "https://fsn1-speed.hetzner.com/100MB.bin" : "https://speed.cloudflare.com/__down?bytes=" + amount : "https://speed.cloudflare.com/__up");
        if (endpoint == "Hetzner") request.Headers.Range = new(0, amount - 1);
        if (direction == "Upload") { var content = new byte[checked((int)amount)]; RandomNumberGenerator.Fill(content); request.Content = new ByteArrayContent(content); }
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token); response.EnsureSuccessStatusCode();
        if (endpoint == "Hetzner" && response.StatusCode != HttpStatusCode.PartialContent) throw new OperationException("独立测速目标未遵守流量范围，停止该项。");
        if (direction == "Download" && response.Content.Headers.ContentLength is { } length && (length < amount || endpoint == "Cloudflare" && length != amount) || direction == "Upload" && response.Content.Headers.ContentLength is > 65536) throw new OperationException("测速响应长度不符合预算。");
        using var stream = await response.Content.ReadAsStreamAsync(token); var buffer = new byte[32768]; long bytes = 0; var cap = direction == "Download" ? amount : 65536;
        while (bytes < cap)
        {
            var received = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, cap - bytes)), token);
            if (received == 0) break; bytes += received;
        }
        return direction == "Download" ? bytes : amount;
    }
    private static async Task Latency(HttpClient http, List<double> points, CancellationToken token)
    {
        var watch = Stopwatch.StartNew(); using var response = await http.GetAsync("https://speed.cloudflare.com/__down?bytes=0", HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode(); watch.Stop(); lock (points) points.Add(watch.Elapsed.TotalMilliseconds);
    }
    private static async Task SampleLoaded(HttpClient http, List<double> points, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try { await Latency(http, points, token); }
            catch (HttpRequestException) { }
            await Task.Delay(400, token);
        }
    }
    private static async Task<JsonObject> UdpSample(int port, CancellationToken token)
    {
        var result = new JsonObject { ["Sent"] = 0, ["Received"] = 0, ["Status"] = "Unavailable", ["Scope"] = "FiveUdpDnsSamplesViaSelectedProtocol" };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(12));
        try
        {
            using var control = new TcpClient(); await control.ConnectAsync(IPAddress.Loopback, port, deadline.Token); var stream = control.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, deadline.Token); var response = new byte[2]; await stream.ReadExactlyAsync(response, deadline.Token);
            if (response[0] != 5 || response[1] != 0) return result;
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var local = (IPEndPoint)udp.Client.LocalEndPoint!;
            await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 127, 0, 0, 1, (byte)(local.Port >> 8), (byte)local.Port }, deadline.Token);
            var header = new byte[4]; await stream.ReadExactlyAsync(header, deadline.Token); if (header[0] != 5 || header[1] != 0 || header[3] is not (1 or 4)) return result;
            var relayAddress = new byte[header[3] == 1 ? 4 : 16]; await stream.ReadExactlyAsync(relayAddress, deadline.Token); var relayPort = new byte[2]; await stream.ReadExactlyAsync(relayPort, deadline.Token);
            var address = new IPAddress(relayAddress); if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) address = IPAddress.Loopback;
            if (!IPAddress.IsLoopback(address)) return result;
            var relay = new IPEndPoint(address, relayPort[0] * 256 + relayPort[1]); var matched = 0;
            for (var i = 0; i < 5; i++)
            {
                byte[] dns = [(byte)0x6d, (byte)(i + 1), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1];
                byte[] datagram = [0, 0, 0, 1, 1, 1, 1, 1, 0, 53, .. dns];
                await udp.SendAsync(datagram.AsMemory(), relay, deadline.Token); result["Sent"] = i + 1;
                using var item = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token); item.CancelAfter(TimeSpan.FromSeconds(2));
                try
                {
                    while (true)
                    {
                        var received = (await udp.ReceiveAsync(item.Token)).Buffer; var offset = received.Length > 4 ? received[3] == 1 ? 10 : received[3] == 4 ? 22 : received[3] == 3 ? 7 + received[4] : 0 : 0;
                        if (offset > 0 && received.Length >= offset + 12 && received[offset] == 0x6d && received[offset + 1] == i + 1 && (received[offset + 2] & 0x80) != 0 && (received[offset + 3] & 15) == 0) { matched++; break; }
                    }
                }
                catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { }
                result["Received"] = matched;
            }
            result["Status"] = "Sampled";
        }
        catch (Exception error) when (error is SocketException or IOException or OperationCanceledException) { token.ThrowIfCancellationRequested(); }
        return result;
    }
}
