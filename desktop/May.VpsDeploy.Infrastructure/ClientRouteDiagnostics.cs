using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed record ClientDiagnosticEndpoints(Uri Ipv4, Uri Ipv6, Uri Any)
{
    public static ClientDiagnosticEndpoints Default { get; } = new(new("https://api.ipify.org"), new("https://api6.ipify.org"), new("https://api64.ipify.org"));
}

// One finite, user-requested check. This never changes the OS proxy, TUN or remote configuration.
public sealed class ClientRouteDiagnostics(IValidationAssets assets, IExternalToolRunner tools, ClientDiagnosticEndpoints? endpoints = null)
{
    public async Task<JsonObject> RunAsync(ClientDiagnosticRoute route, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
    {
        var targets = endpoints ?? ClientDiagnosticEndpoints.Default;
        foreach (var uri in new[] { targets.Ipv4, targets.Ipv6, targets.Any })
            if (uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback)) throw new OperationException("诊断目标必须使用 HTTPS。");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(75));
        var token = deadline.Token; var stages = new JsonArray();
        var report = new JsonObject { ["Fingerprint"] = route.Fingerprint, ["At"] = DateTimeOffset.UtcNow.ToString("O"), ["Path"] = route.Label, ["Status"] = "Incomplete", ["Stages"] = stages,
            ["Scope"] = "本机经所选入口及可选落地的短连接检查；不代表客户端当前选择，不测吞吐、UDP 或纯远端 RTT。" };
        string? work = null; Process? process = null; Task? stdout = null; Task? stderr = null;
        var clock = Stopwatch.StartNew();
        async Task<bool> Stage(string id, string label, Func<CancellationToken, Task> action)
        {
            progress.Report(label); var watch = Stopwatch.StartNew();
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token); limit.CancelAfter(TimeSpan.FromSeconds(12));
            try { await action(limit.Token); stages.Add(new JsonObject { ["Id"] = id, ["Label"] = label, ["Status"] = "Passed", ["Milliseconds"] = watch.ElapsedMilliseconds }); return true; }
            catch (Exception error) when (error is SocketException or HttpRequestException or IOException or OperationException || error is OperationCanceledException && !cancellationToken.IsCancellationRequested)
            {
                stages.Add(new JsonObject { ["Id"] = id, ["Label"] = label, ["Status"] = "Failed", ["Milliseconds"] = watch.ElapsedMilliseconds,
                    ["Detail"] = error is OperationCanceledException ? "此阶段超时。" : error is OperationException safe ? safe.Message : "目标或此路径不可用，不能仅凭此结果断定节点故障。" }); return false;
            }
        }
        try
        {
            var host = route.Entry.Text("sing_box.server");
            IPAddress[] addresses = [];
            if (!await Stage("Dns", "解析入口地址（本机）", async t => addresses = await Dns.GetHostAddressesAsync(host, t))) return report;
            if (!await Stage("Tcp", "本机 → 入口 TCP", async t =>
            {
                using var tcp = new TcpClient(); await tcp.ConnectAsync(addresses, route.Entry.Number("sing_box.server_port"), t);
                report["ConnectedFamily"] = tcp.Client.RemoteEndPoint is IPEndPoint remote && remote.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
            })) return report;
            progress.Report("准备隔离诊断核心");
            var executable = assets.ResolveCore("sing-box"); await ProtocolValidation.VerifyVersion(assets, tools, "sing-box", executable, token);
            work = SafePath.Resolve(privateDirectory, "client-diagnostic-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            using var entrySocket = new TcpListener(IPAddress.Loopback, 0); entrySocket.Start();
            using var chainSocket = new TcpListener(IPAddress.Loopback, 0); chainSocket.Start();
            var entryPort = ((IPEndPoint)entrySocket.LocalEndpoint).Port; var chainPort = ((IPEndPoint)chainSocket.LocalEndpoint).Port;
            var config = SafePath.Resolve(work, "diagnostic.private.json"); ArchiveStore.WriteJson(config, ClientTopology.DiagnosticConfiguration(route, entryPort, chainPort));
            var check = await tools.RunAsync(executable, ["check", "-c", config], null, TimeSpan.FromSeconds(20), token); check.RequireSuccess("诊断配置未通过固定核心校验。");
            var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "run", "-c", config }) start.ArgumentList.Add(arg);
            entrySocket.Stop(); chainSocket.Stop();
            process = Process.Start(start) ?? throw new OperationException("无法启动隔离诊断核心。");
            stdout = Drain(process.StandardOutput); stderr = Drain(process.StandardError);
            var ready = false;
            for (var i = 0; i < 40 && !process.HasExited; i++)
            {
                token.ThrowIfCancellationRequested();
                try { using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, entryPort, token); ready = true; break; }
                catch (SocketException) { await Task.Delay(100, token); }
            }
            if (!ready) throw new OperationException("隔离诊断核心未就绪。");
            if (!await Stage("EntryHttps", "入口协议握手与 HTTPS 出口", async t => report["EntryEgress"] = await Egress(entryPort, route.Entry, targets, t))) return report;
            if (route.Landing != null)
            {
                stages.Add(new JsonObject { ["Id"] = "RemoteLeg", ["Label"] = "入口 → 落地纯远端 RTT", ["Status"] = "NotMeasured", ["Detail"] = "未在远端执行探测；整条链路检查包含入口、落地握手及网站响应。" });
                if (!await Stage("ChainHttps", "本机 → 入口 → 落地 → HTTPS 出口", async t => report["ChainEgress"] = await Egress(chainPort, route.Landing, targets, t))) return report;
            }
            report["Status"] = "Reachable";
            return report;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { report["Status"] = "TimedOut"; return report; }
        finally
        {
            report["ElapsedMilliseconds"] = clock.ElapsedMilliseconds;
            if (report.Text("Status") == "Incomplete" && stages.Any(s => s!.Text("Status") == "Failed")) report["Status"] = "Failed";
            try
            {
                if (process != null)
                {
                    try { if (!process.HasExited) process.Kill(entireProcessTree: true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); if (stdout != null && stderr != null) await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(2)); }
                    finally { process.Dispose(); }
                }
            }
            finally { if (work != null) { SafePath.CheckTree(work); Directory.Delete(work, true); } }
        }
    }

    private static async Task Drain(StreamReader stream)
    {
        try { var buffer = new char[2048]; while (await stream.ReadAsync(buffer.AsMemory()) != 0) { } }
        catch (IOException) { }
    }
    private static async Task<JsonObject> Egress(int port, JsonObject node, ClientDiagnosticEndpoints targets, CancellationToken token)
    {
        var family = ClientTopology.EgressFamily(node); var expectedText = node.Text("Egress.ExpectedAddress");
        var expected = expectedText == "" ? null : IPAddress.Parse(expectedText);
        if (family == "Unknown" && expected != null) family = expected.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
        var target = family == "IPv4" ? targets.Ipv4 : family == "IPv6" ? targets.Ipv6 : targets.Any;
        using var handler = new SocketsHttpHandler { Proxy = new WebProxy("http://127.0.0.1:" + port), UseProxy = true, AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(8), AutomaticDecompression = DecompressionMethods.None, MaxResponseDrainSize = 0, MaxResponseHeadersLength = 8 };
        using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        using var request = new HttpRequestMessage(HttpMethod.Get, target); request.Headers.ConnectionClose = true; request.Headers.CacheControl = new() { NoCache = true, NoStore = true };
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token); response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > 128) throw new OperationException("出口检查返回内容过长。");
        using var stream = await response.Content.ReadAsStreamAsync(token); var bytes = new byte[129]; var count = 0;
        while (count < bytes.Length) { var read = await stream.ReadAsync(bytes.AsMemory(count), token); if (read == 0) break; count += read; }
        if (count > 128 || !IPAddress.TryParse(Encoding.UTF8.GetString(bytes, 0, count).Trim(), out var address)) throw new OperationException("出口检查未返回有效 IP 地址。");
        if (family == "IPv4" && address.AddressFamily != AddressFamily.InterNetwork || family == "IPv6" && address.AddressFamily != AddressFamily.InterNetworkV6) throw new OperationException("实测出口地址族与标注不符。");
        if (expected != null && !expected.Equals(address)) throw new OperationException("实测出口与预期地址不符，请核对路径。");
        return new JsonObject { ["Address"] = address.ToString(), ["Family"] = address.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4", ["Verified"] = expected != null,
            ["Detail"] = expected == null ? "已观测出口，未提供预期地址，未核验出口身份。" : "与预期出口一致。", ["Target"] = target.GetLeftPart(UriPartial.Authority) };
    }
}
