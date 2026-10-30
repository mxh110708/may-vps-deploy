using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed partial class ClientRouteDiagnostics
{
    private async Task<JsonObject> XhttpAsync(ClientDiagnosticRoute route, string privateDirectory, IProgress<string> progress, CancellationToken cancellationToken)
    {
        if (route.Landing != null) throw new OperationException("有限 XHTTP 诊断不叠加客户端落地。");
        var version=VlessXhttp.NodeVersion(route.Entry);
        var proxy = VlessXhttp.RequireClash(route.Entry); proxy["name"] = "xhttp-checked-entry";
        var targets = endpoints ?? ClientDiagnosticEndpoints.Default;
        foreach (var uri in new[] { targets.Ipv4, targets.Ipv6, targets.Any }) if (uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback)) throw new OperationException("诊断目标必须使用 HTTPS。");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(75)); var ct = deadline.Token;
        var stages = new JsonArray(); var report = new JsonObject { ["Fingerprint"] = route.Fingerprint, ["At"] = DateTimeOffset.UtcNow.ToString("O"), ["Path"] = route.Label, ["Status"] = "Incomplete", ["Stages"] = stages, ["Scope"] = "固定 Mihomo 经所选 VLESS/XHTTP 入口检查 HTTPS 与有限 UDP DNS；不代表公网 CDN、任意高级模式、吞吐或当前客户端选择。" };
        var clock = Stopwatch.StartNew(); string? work = null; Process? process = null; Task? output = null, error = null;
        async Task<bool> Stage(string id, string label, Func<CancellationToken, Task> action)
        {
            progress.Report(label); var watch = Stopwatch.StartNew(); using var part = CancellationTokenSource.CreateLinkedTokenSource(ct); part.CancelAfter(TimeSpan.FromSeconds(12));
            try { await action(part.Token); stages.Add(new JsonObject { ["Id"] = id, ["Label"] = label, ["Status"] = "Passed", ["Milliseconds"] = watch.ElapsedMilliseconds }); return true; }
            catch (Exception e) when (e is SocketException or HttpRequestException or IOException or AuthenticationException or OperationException || e is OperationCanceledException && !cancellationToken.IsCancellationRequested)
            { stages.Add(new JsonObject { ["Id"] = id, ["Label"] = label, ["Status"] = "Failed", ["Milliseconds"] = watch.ElapsedMilliseconds, ["Detail"] = e is OperationCanceledException ? "此阶段超时。" : e is OperationException safe ? safe.Message : "所选协议、传输安全或目标不可用；未采用直连兜底。" }); return false; }
        }
        try
        {
            IPAddress[] addresses = [];
            if (!await Stage("Dns", "解析 XHTTP 入口地址", async t => addresses = await Dns.GetHostAddressesAsync(proxy.Text("server"), t))) return report;
            if (version!="3"&&!await Stage("Tcp", "本机至 XHTTP 入口 TCP", async t => { using var socket = new TcpClient(); await socket.ConnectAsync(addresses, proxy.Number("port"), t); })) return report;
            if (version!="3"&&VlessXhttp.Security(route.Entry) == "TLS" && !await Stage("TransportTls", "核对入口 TLS 证书与 HTTP 协商", async t =>
            {
                using var socket = new TcpClient(); await socket.ConnectAsync(addresses, proxy.Number("port"), t); using var tls = new SslStream(socket.GetStream());
                var expected=version=="1.1"?SslApplicationProtocol.Http11:SslApplicationProtocol.Http2;
                var options = new SslClientAuthenticationOptions { TargetHost = proxy.Text("servername"), EnabledSslProtocols = SslProtocols.Tls12|SslProtocols.Tls13, ApplicationProtocols = [expected] };
                if (certificateAuthority != null) { options.CertificateChainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck }; options.CertificateChainPolicy.CustomTrustStore.Add(certificateAuthority); }
                await tls.AuthenticateAsClientAsync(options, t); if (tls.NegotiatedApplicationProtocol != expected) throw new OperationException("入口未协商到所选 HTTP 版本。");
            })) return report;
            progress.Report("准备固定 Mihomo 隔离核心"); var binary = assets.ResolveCore("mihomo"); await ProtocolValidation.VerifyVersion(assets, tools, "mihomo", binary, ct);
            work = SafePath.Resolve(privateDirectory, "xhttp-diagnostic-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
            using var incoming = new TcpListener(IPAddress.Loopback, 0); using var controller = new TcpListener(IPAddress.Loopback, 0); incoming.Start(); controller.Start();
            var port = ((IPEndPoint)incoming.LocalEndpoint).Port; var controlPort = ((IPEndPoint)controller.LocalEndpoint).Port; var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var config = new JsonObject { ["mixed-port"] = port, ["bind-address"] = "127.0.0.1", ["allow-lan"] = false, ["mode"] = "rule", ["log-level"] = "silent", ["external-controller"] = "127.0.0.1:" + controlPort, ["secret"] = token, ["proxies"] = new JsonArray(proxy), ["rules"] = new JsonArray("MATCH,xhttp-checked-entry") };
            if (certificateAuthority != null) config["tls"] = new JsonObject { ["custom-certifactes"] = new JsonArray(certificateAuthority.ExportCertificatePem()) };
            var file = SafePath.Resolve(work, "config.private.json"); ArchiveStore.WriteJson(file, config);
            (await tools.RunAsync(binary, ["-t", "-d", work, "-f", file], null, TimeSpan.FromSeconds(15), ct)).RequireSuccess("有限 XHTTP 配置未通过固定 Mihomo 校验。");
            var start = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }; foreach (var a in new[] { "-d", work, "-f", file }) start.ArgumentList.Add(a);
            incoming.Stop(); controller.Stop(); process = Process.Start(start) ?? throw new OperationException("无法启动隔离 Mihomo。"); output = Drain(process.StandardOutput); error = Drain(process.StandardError);
            if (!await Stage("Core", "启动隔离 Mihomo 并加载受审阅配置", async t =>
            {
                using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { Timeout = Timeout.InfiniteTimeSpan }; http.DefaultRequestHeaders.Authorization = new("Bearer", token);
                while (true)
                {
                    t.ThrowIfCancellationRequested(); if (process.HasExited) throw new OperationException("隔离核心未就绪。");
                    try { using var content = new StringContent(new JsonObject { ["payload"] = config.ToJsonString() }.ToJsonString(), System.Text.Encoding.UTF8, "application/json"); using var response = await http.PutAsync("http://127.0.0.1:" + controlPort + "/configs?force=true", content, t); response.EnsureSuccessStatusCode(); break; }
                    catch (HttpRequestException) { await Task.Delay(100, t); }
                }
            })) return report;
            if (!await Stage("EntryHttps", "VLESS / " + VlessXhttp.Security(route.Entry) + " / XHTTP h2 实际 HTTPS 出口", async t => report["EntryEgress"] = await Egress(port, route.Entry, targets, t))) return report;
            if (!await Stage("EntryUdp", "经 XHTTP 的应用 UDP DNS 回程", async t => report["UdpValidation"] = await ClientProxyUdp.ProbeAsync(port, ClientTopology.EgressFamily(route.Entry) == "IPv6" ? targets.Udp6 : targets.Udp4, t))) return report;
            report["ValidatedProtocol"] = "vless"; report["Transport"] = "xhttp"; report["TransportSecurity"] = VlessXhttp.Security(route.Entry); report["TransportAlpn"] = VlessXhttp.Alpn(version); report["ClientCore"] = "mihomo"; report["Status"] = "Reachable"; return report;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { report["Status"] = "TimedOut"; return report; }
        finally
        {
            report["ElapsedMilliseconds"] = clock.ElapsedMilliseconds; if (report.Text("Status") == "Incomplete" && stages.Any(s => s!.Text("Status") == "Failed")) report["Status"] = "Failed";
            try { if (process != null) { try { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); if (output != null && error != null) await Task.WhenAll(output, error).WaitAsync(TimeSpan.FromSeconds(2)); } finally { process.Dispose(); } } }
            finally { if (work != null) { SafePath.CheckTree(work); Directory.Delete(work, true); } }
        }
    }
}
