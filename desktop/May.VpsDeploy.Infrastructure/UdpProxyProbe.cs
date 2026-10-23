using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

// A short-lived UDP-only core. No OS proxy, DNS capture, TCP or direct fallback.
public sealed class UdpProxyProbe(IValidationAssets assets, IExternalToolRunner tools)
{
    public async Task<JsonObject> RunAsync(JsonObject node, JsonObject validation, string address, int port, string privateDirectory, CancellationToken cancellationToken)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); limit.CancelAfter(TimeSpan.FromSeconds(30));
        var token = limit.Token;
        var executable = assets.ResolveCore("sing-box"); await ProtocolValidation.VerifyVersion(assets, tools, "sing-box", executable, token);
        var work = SafePath.Resolve(privateDirectory, "udp-proxy-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(work);
        var file = SafePath.Resolve(work, "probe.private.json"); Process? process = null; Task? stdout = null; Task? stderr = null;
        try
        {
            using var reservation = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var localPort = ((IPEndPoint)reservation.Client.LocalEndPoint!).Port;
            var config = UdpForwarding.ProxyConfiguration(node, validation, address, port, localPort);
            try { ArchiveStore.WriteJson(file, config); } finally { config.Clear(); }
            (await tools.RunAsync(executable, ["check", "-c", file], null, TimeSpan.FromSeconds(10), token)).RequireSuccess("UDP 代理验收配置未通过固定核心校验。");
            var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "run", "-c", file }) start.ArgumentList.Add(arg);
            reservation.Dispose();
            process = Process.Start(start) ?? throw new OperationException("无法启动隔离 UDP 验收核心。");
            stdout = Drain(process.StandardOutput); stderr = Drain(process.StandardError);
            using var client = new UdpClient(AddressFamily.InterNetwork); client.Connect(IPAddress.Loopback, localPort);
            for (var attempt = 0; attempt < 3; attempt++)
            {
                if (process.HasExited) throw new OperationException("隔离 UDP 验收核心提前退出，未取得响应。", code: "UdpProxyCoreExited");
                token.ThrowIfCancellationRequested();
                var query = UdpDnsProbe.Query(validation.Text("QueryName"), validation.Text("QueryType"));
                using var responseBudget = CancellationTokenSource.CreateLinkedTokenSource(token); responseBudget.CancelAfter(TimeSpan.FromSeconds(3));
                try
                {
                    await client.SendAsync(query, responseBudget.Token);
                    for (var count = 0; count < 16; count++)
                    {
                        var response = await client.ReceiveAsync(responseBudget.Token);
                        if (UdpDnsProbe.Matches(query, response.Buffer))
                            return new JsonObject { ["Transport"] = "UDP", ["ResponseMatched"] = true, ["ResolverAddress"] = validation.Text("ResolverAddress"), ["ResolverPort"] = validation.Number("ResolverPort"), ["QueryName"] = validation.Text("QueryName"), ["QueryType"] = validation.Text("QueryType") };
                    }
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
                // The first datagram can precede core readiness. Retry only this finite
                // probe with a new DNS identity, never the remote apply operation.
                catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionReset && !token.IsCancellationRequested) { await Task.Delay(100, token); }
            }
            throw new OperationException("未收到经转发及 Shadowsocks UDP 返回的匹配 DNS 回答；请核对凭据、UDP 放行及代理出口 DNS。", code: "UdpProxyProbeFailed");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new OperationException("UDP 代理验收超时，未提交变更。", code: "UdpProxyProbeTimeout"); }
        finally
        {
            try
            {
                if (process != null) { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)); }
                if (stdout != null && stderr != null) await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(2));
            }
            finally { process?.Dispose(); if (File.Exists(file)) File.Delete(file); Directory.Delete(work); }
        }
    }
    private static async Task Drain(StreamReader reader)
    {
        try { var buffer = new char[4096]; while (await reader.ReadAsync(buffer) != 0) { } }
        catch (IOException) { }
    }
}
