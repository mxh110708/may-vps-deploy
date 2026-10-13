using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Infrastructure;

public sealed class ProtocolValidation(IValidationAssets assets, IExternalToolRunner tools, ArchiveStore? store = null) : IProtocolValidation
{
    public void Export(JsonObject plan, JsonObject secrets, string directory) => ClientProfiles.Export(plan, secrets, directory);
    public async Task<JsonObject> ValidateAsync(JsonObject plan, JsonObject secrets, string privateDirectory, IUserInteraction user, IProgress<string> progress, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(privateDirectory); var items = new JsonArray(); var incomplete = false;
        foreach (var node in ClientProfiles.Nodes(plan, secrets, true))
        {
            var entry = node.Role == "ShadowsocksLanding" ? FindTrustedEntry(plan, secrets, node.Family) : null;
            if (node.Role == "ShadowsocksLanding" && entry == null)
            {
                if (!await user.ConfirmAsync(new("缺少可信入口验收路径", "Shadowsocks 仅允许可信入口连接。请先纳管并启用白名单中的入口；本机不会直接连接落地端口。是否保留此项未完成记录并继续？"), cancellationToken)) throw new OperationException("Shadowsocks 可信入口验收路径尚未配置。", code: "TrustedEntryMissing");
                items.Add(new JsonObject { ["Node"] = node.Name, ["Role"] = node.Role, ["Status"] = "SkippedByUser", ["FailedStage"] = "TrustedEntryMissing" }); incomplete = true; continue;
            }
            if ((entry?.Family ?? node.Family) == "IPv6" && !Socket.OSSupportsIPv6)
            {
                if (!await user.ConfirmAsync(new("IPv6 验收不可用", "本机 IPv6 不可用。是否明确跳过此入口的本机验证？跳过不计为通过。"), cancellationToken)) throw new OperationException("IPv6 入口验证尚未完成。");
                items.Add(new JsonObject { ["Node"] = node.Name, ["Status"] = "SkippedByUser" }); incomplete = true; continue;
            }
            foreach (var core in new[] { "sing-box", "mihomo" })
            {
                cancellationToken.ThrowIfCancellationRequested(); progress.Report("正在独立验证 " + core + " / " + node.Family + " 入口。");
                var id = Guid.NewGuid().ToString("N"); var work = SafePath.Resolve(privateDirectory, id); Directory.CreateDirectory(work);
                var executable = assets.ResolveCore(core);
                await VerifyVersion(assets, tools, core, executable, cancellationToken);
                var dataDirectory = SafePath.Resolve(work, "data"); Directory.CreateDirectory(dataDirectory);
                if (core == "mihomo") foreach (var file in Directory.EnumerateFiles(assets.DataDirectory)) { SafePath.CheckLinks(file); File.Copy(file, SafePath.Resolve(dataDirectory, Path.GetFileName(file))); }
                var port = FreePort(); var config = SafePath.Resolve(work, core == "mihomo" ? "profile.yaml" : "profile.json");
                ArchiveStore.WriteJson(config, core == "mihomo" ? ClientProfiles.ClashProbe(node, port, entry) : ClientProfiles.SingProbe(node, port, entry));
                var check = await tools.RunAsync(executable, core == "mihomo" ? ["-t", "-d", dataDirectory, "-f", config] : ["check", "-c", config], null, TimeSpan.FromSeconds(40), cancellationToken);
                check.RequireSuccess("固定核心拒绝验证配置，未启动测试代理。");
                var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                foreach (var arg in core == "mihomo" ? new[] { "-d", dataDirectory, "-f", config } : ["run", "-c", config]) start.ArgumentList.Add(arg);
                using var process = Process.Start(start) ?? throw new OperationException("验证核心无法启动。");
                // Drain private diagnostic streams without displaying or persisting credential-bearing output.
                var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
                var stage = "回环监听"; var httpsPassed = false; var egressPassed = false;
                try
                {
                    var ready = false;
                    for (var i = 0; i < 50 && !process.HasExited; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        try { using var socket = new TcpClient(); await socket.ConnectAsync(IPAddress.Loopback, port, cancellationToken); ready = true; break; }
                        catch (SocketException) { await Task.Delay(100, cancellationToken); }
                    }
                    if (!ready) throw new OperationException("验证核心回环监听未就绪。");
                    using var handler = new HttpClientHandler { Proxy = new WebProxy("http://127.0.0.1:" + port), UseProxy = true };
                    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
                    stage = "HTTPS";
                    var http = await client.GetAsync("https://cp.cloudflare.com/generate_204", cancellationToken);
                    if (http.StatusCode != HttpStatusCode.NoContent) throw new OperationException("协议 HTTPS 验收未返回预期结果。");
                    httpsPassed = true; stage = "出口地址";
                    var egress = (await client.GetStringAsync(node.EgressFamily == "IPv6" ? "https://api64.ipify.org" : "https://api.ipify.org", cancellationToken)).Trim();
                    var expected = node.EgressFamily == "IPv6" ? plan.Text("Shadowsocks.SecondaryIpv6Address") : plan.Text("Server.IPv4");
                    if (!IPAddress.TryParse(egress, out var address) || address.ToString() != IPAddress.Parse(expected).ToString()) throw new OperationException("协议出口与计划不一致，未计为通过。");
                    egressPassed = true; stage = "UDP DNS";
                    await SocksUdpProbe(port, node.EgressFamily == "IPv6", cancellationToken);
                    items.Add(new JsonObject { ["Core"] = core, ["Node"] = node.Name, ["Role"] = node.Role, ["Path"] = entry == null ? "DirectEntry" : "TrustedEntry", ["Entry"] = entry?.Name, ["Status"] = "Passed", ["Https"] = "Passed", ["Egress"] = egress, ["Udp"] = "Passed" });
                }
                catch (Exception error) when (error is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
                {
                    var failure = SafeFailures.Describe(error is OperationCanceledException ? new TimeoutException() : error);
                    if (!await user.ConfirmAsync(new("协议验收未完成", node.Name + " · " + core + " / " + node.Family + "\n失败阶段：" + stage + "\n" + failure.Message + "\n是否明确跳过并保留记录？跳过不会显示为通过。"), cancellationToken)) throw new OperationException("协议验收未完成（" + core + " / " + node.Family + "，阶段：" + stage + "），受管变更将恢复。", code: "ProtocolValidationIncomplete");
                    items.Add(new JsonObject { ["Core"] = core, ["Node"] = node.Name, ["Status"] = "SkippedByUser", ["FailedStage"] = stage, ["ErrorCode"] = failure.Code, ["Https"] = httpsPassed ? "Passed" : "Incomplete", ["Egress"] = egressPassed ? "Passed" : "Incomplete", ["Udp"] = "Incomplete" }); incomplete = true;
                }
                finally
                {
                    if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); await Task.WhenAll(stdout, stderr);
                    SafePath.CheckTree(dataDirectory); Directory.Delete(dataDirectory, true);
                }
            }
        }
        return new JsonObject { ["Status"] = items.Count == 0 ? "NoEnabledProtocols" : incomplete ? "Incomplete" : "Passed", ["Items"] = items, ["At"] = DateTimeOffset.UtcNow };
    }
    public ClientProfiles.NodePair? FindTrustedEntry(JsonObject plan, JsonObject secrets, string landingFamily)
    {
        var trusted = plan.Strings("Shadowsocks.TrustedEntry" + (landingFamily == "IPv6" ? "IPv6s" : "IPv4s")).Select(IPAddress.Parse).ToHashSet();
        ClientProfiles.NodePair? Match(JsonObject candidate, JsonObject credentials) => trusted.Contains(IPAddress.TryParse(candidate.Text("Server." + landingFamily), out var address) ? address : IPAddress.None)
            ? ClientProfiles.Nodes(candidate, credentials, true).FirstOrDefault(n => n.Role is "RealityEntry" or "AnyTlsEntry" && !n.IsBackup && n.Family == "IPv4") : null;
        var local = Match(plan, secrets); if (local != null) return local;
        if (store == null) return null;
        foreach (var instance in store.ListInstances().OrderBy(i => i.RelativePath, StringComparer.Ordinal))
        {
            var lifecycle = InstanceLifecycle.Read(store, instance.RelativePath, instance.Plan);
            if (!lifecycle.Managed || lifecycle.NeedsRecovery) continue;
            var file = SafePath.Resolve(store.Paths.Instance(instance.RelativePath), "secrets.dotnet.private.json");
            if (!File.Exists(file)) continue;
            var credentials = store.ReadSecret(file);
            try { var entry = Match(instance.Plan, credentials); if (entry != null) return entry; }
            finally { credentials.Clear(); }
        }
        return null;
    }
    private static int FreePort() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); try { return ((IPEndPoint)listener.LocalEndpoint).Port; } finally { listener.Stop(); } }
    public static async Task VerifyVersion(IValidationAssets assets, IExternalToolRunner tools, string name, string executable, CancellationToken cancellationToken)
    {
        var expected = assets.ExpectedVersion(name); if (expected == "") return;
        var result = await tools.RunAsync(executable, name == "mihomo" ? ["-v"] : ["version"], null, TimeSpan.FromSeconds(15), cancellationToken); result.RequireSuccess("验证核心版本无法读取。");
        if (!System.Text.RegularExpressions.Regex.IsMatch(result.Output, @"(?<![0-9])v?" + System.Text.RegularExpressions.Regex.Escape(expected) + @"(?![0-9.])")) throw new OperationException("验证核心实际版本与固定目录不符。");
    }
    private static async Task SocksUdpProbe(int port, bool ipv6, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(15)); var token = deadline.Token;
        using var control = new TcpClient(); await control.ConnectAsync(IPAddress.Loopback, port, token); var stream = control.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, token); var response = new byte[2]; await stream.ReadExactlyAsync(response, token);
        if (response[0] != 5 || response[1] != 0) throw new OperationException("SOCKS UDP 认证协商失败。");
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var local = (IPEndPoint)udp.Client.LocalEndPoint!;
        await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 127, 0, 0, 1, (byte)(local.Port >> 8), (byte)local.Port }, token);
        var header = new byte[4]; await stream.ReadExactlyAsync(header, token); if (header[0] != 5 || header[1] != 0) throw new OperationException("SOCKS UDP 通道建立失败。");
        byte[] relayAddress;
        if (header[3] == 1) relayAddress = new byte[4]; else if (header[3] == 4) relayAddress = new byte[16]; else throw new OperationException("UDP 回环中继格式不支持。");
        await stream.ReadExactlyAsync(relayAddress, token); var relayPort = new byte[2]; await stream.ReadExactlyAsync(relayPort, token);
        var relay = new IPEndPoint(new IPAddress(relayAddress), relayPort[0] * 256 + relayPort[1]); if (relay.Address.Equals(IPAddress.Any) || relay.Address.Equals(IPAddress.IPv6Any)) relay.Address = IPAddress.Loopback;
        if (!IPAddress.IsLoopback(relay.Address)) throw new OperationException("验证 UDP 中继不是回环地址。");
        byte[] dns = [0x6d, 0x78, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1];
        byte[] packet = ipv6 ? [0, 0, 0, 4, .. IPAddress.Parse("2606:4700:4700::1111").GetAddressBytes(), 0, 53, .. dns] : [0, 0, 0, 1, 1, 1, 1, 1, 0, 53, .. dns]; await udp.SendAsync(packet, relay, token); var received = await udp.ReceiveAsync(token);
        var bytes = received.Buffer; var offset = bytes.Length > 4 ? bytes[3] == 1 ? 10 : bytes[3] == 4 ? 22 : bytes[3] == 3 ? 7 + bytes[4] : 0 : 0;
        if (offset == 0 || bytes.Length < offset + 12 || bytes[2] != 0 || bytes[offset] != 0x6d || bytes[offset + 1] != 0x78 || (bytes[offset + 2] & 0x80) == 0 || (bytes[offset + 3] & 0x0f) != 0 || bytes[offset + 6] * 256 + bytes[offset + 7] == 0) throw new OperationException("UDP DNS 验收没有收到匹配的有效响应。");
    }
}
