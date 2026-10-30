using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed record ClientDiagnosticEndpoints(Uri Ipv4, Uri Ipv6, Uri Any)
{
    public static ClientDiagnosticEndpoints Default { get; } = new(new("https://api.ipify.org"), new("https://api6.ipify.org"), new("https://api64.ipify.org"));
    public IPEndPoint Udp4 { get; init; } = new(IPAddress.Parse("1.1.1.1"), 53);
    public IPEndPoint Udp6 { get; init; } = new(IPAddress.Parse("2606:4700:4700::1111"), 53);
}

// One finite, user-requested check. This never changes the OS proxy, TUN or remote configuration.
public interface IClientRouteDiagnostics
{
    Task<JsonObject> RunAsync(ClientDiagnosticRoute route, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken);
}
public sealed partial class ClientRouteDiagnostics(IValidationAssets assets, IExternalToolRunner tools, ClientDiagnosticEndpoints? endpoints = null, X509Certificate2? certificateAuthority = null) : IClientRouteDiagnostics
{
    public async Task<JsonObject> RunAsync(ClientDiagnosticRoute route, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
    {
        var xhttp=VlessXhttp.IsNode(route.Entry);
        if (xhttp && route.Entry["sing_box"]==null) return await XhttpAsync(route, privateDirectory, progress, cancellationToken);
        if (xhttp) _=VlessXhttp.RequireNative(route.Entry);
        var targets = endpoints ?? ClientDiagnosticEndpoints.Default;
        foreach (var uri in new[] { targets.Ipv4, targets.Ipv6, targets.Any })
            if (uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback)) throw new OperationException("诊断目标必须使用 HTTPS。");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(75));
        var token = deadline.Token; var stages = new JsonArray();
        var protocol = route.Entry.Text("sing_box.type"); var quic = protocol is "hysteria2" or "tuic" || xhttp && VlessXhttp.Version(route.Entry["sing_box"]!.AsObject())=="3";
        var applicationUdp = protocol == "tuic" || xhttp || route.RequiresApplicationUdp;
        var report = new JsonObject { ["Fingerprint"] = route.Fingerprint, ["At"] = DateTimeOffset.UtcNow.ToString("O"), ["Path"] = route.Label, ["Status"] = "Incomplete", ["Stages"] = stages,
            ["Scope"] = applicationUdp ? "本机经所选入口检查 HTTPS 与有限 UDP DNS 回程，可选落地另查 HTTPS；不代表客户端当前选择，不测吞吐、任意 UDP 应用或纯远端 RTT。" : "本机经所选入口及可选落地的短连接检查；不代表客户端当前选择，不测吞吐、UDP 或纯远端 RTT。" };
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
            if (quic) stages.Add(new JsonObject { ["Id"] = "Udp", ["Label"] = "等待 QUIC 代理协议请求", ["Status"] = "NotMeasured", ["Detail"] = "UDP 端口本身不判为可达；后续由固定核心执行真实鉴权请求。" });
            else if (!await Stage("Tcp", "本机 → 入口 TCP", async t =>
            {
                using var tcp = new TcpClient(); await tcp.ConnectAsync(addresses, route.Entry.Number("sing_box.server_port"), t);
                report["ConnectedFamily"] = tcp.Client.RemoteEndPoint is IPEndPoint remote && remote.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
            })) return report;
            progress.Report("准备隔离诊断核心");
            var coreName=xhttp?"may-core":"sing-box";
            if(xhttp&&!assets.Supports(coreName,"vless-xhttp-round20"))throw new OperationException("缺少来源与摘要可核对的配套 May Core；上游 sing-box 不能验证 XHTTP。");
            var executable = assets.ResolveCore(coreName); await ProtocolValidation.VerifyVersion(assets, tools, coreName, executable, token);
            work = SafePath.Resolve(privateDirectory, "client-diagnostic-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            using var entrySocket = new TcpListener(IPAddress.Loopback, 0); entrySocket.Start();
            using var chainSocket = new TcpListener(IPAddress.Loopback, 0); chainSocket.Start();
            var entryPort = ((IPEndPoint)entrySocket.LocalEndpoint).Port; var chainPort = ((IPEndPoint)chainSocket.LocalEndpoint).Port;
            var configuration = ClientTopology.DiagnosticConfiguration(route, entryPort, chainPort);
            if(xhttp&&certificateAuthority!=null&&!route.Entry.Flag("sing_box.tls.reality.enabled")&&configuration["outbounds"]![0]!["tls"]!["certificate"]==null)configuration["outbounds"]![0]!["tls"]!["certificate"]=new JsonArray(certificateAuthority.ExportCertificatePem());
            // A QUIC proxy success must use the generated, authenticated protocol
            // outbound. No direct/fallback egress can stand in for the UDP path.
            if (quic && (configuration["outbounds"]![0]!.Text("type") != protocol || configuration["outbounds"]!.AsArray().Any(o => o!.Text("type") == "direct") || configuration["route"]!["rules"]![0]!.Text("outbound") != "diagnostic-entry")) throw new OperationException("QUIC 代理诊断路径含有非预期回退，未执行。");
            var config = SafePath.Resolve(work, "diagnostic.private.json"); ArchiveStore.WriteJson(config, configuration);
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
            report["ValidatedProtocol"] = route.Entry.Text("sing_box.type");
            if(xhttp){report["Transport"]="xhttp";report["TransportSecurity"]=VlessXhttp.Security(route.Entry);report["TransportAlpn"]=VlessXhttp.Alpn(VlessXhttp.Version(route.Entry["sing_box"]!.AsObject()));report["ClientCore"]="may-core";}
            if (applicationUdp && !await Stage("EntryUdp", "入口至出口的应用 UDP 与 DNS 回程", async t => report["UdpValidation"] = await ClientProxyUdp.ProbeAsync(entryPort, ClientTopology.EgressFamily(route.Entry) == "IPv6" ? targets.Udp6 : targets.Udp4, t))) return report;
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
    private async Task<JsonObject> Egress(int port, JsonObject node, ClientDiagnosticEndpoints targets, CancellationToken token)
    {
        var family = ClientTopology.EgressFamily(node); var expectedText = node.Text("Egress.ExpectedAddress");
        var expected = expectedText == "" ? null : IPAddress.Parse(expectedText);
        if (family == "Unknown" && expected != null) family = expected.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
        var target = family == "IPv4" ? targets.Ipv4 : family == "IPv6" ? targets.Ipv6 : targets.Any;
        using var handler = new SocketsHttpHandler { Proxy = new WebProxy("http://127.0.0.1:" + port), UseProxy = true, AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(8), AutomaticDecompression = DecompressionMethods.None, MaxResponseDrainSize = 0, MaxResponseHeadersLength = 8 };
        // Controlled integration endpoints can supply a process-local CA. The
        // product constructor uses OS trust; hostname checks always apply.
        if (certificateAuthority != null)
        {
            handler.SslOptions.CertificateChainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
            handler.SslOptions.CertificateChainPolicy.CustomTrustStore.Add(certificateAuthority);
        }
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
