using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

// Finite application-UDP check through the already isolated client's SOCKS
// listener. The controller never sends DNS directly to the external resolver.
public static class ClientProxyUdp
{
    public static async Task<JsonObject> ProbeAsync(int proxyPort, IPEndPoint target, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(11)); var token = deadline.Token;
        using var control = new TcpClient(); await control.ConnectAsync(IPAddress.Loopback, proxyPort, token); var stream = control.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, token); var greeting = new byte[2]; await stream.ReadExactlyAsync(greeting, token);
        if (!greeting.AsSpan().SequenceEqual(new byte[] { 5, 0 })) throw new OperationException("隔离 SOCKS UDP 协商失败。");
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var local = (IPEndPoint)udp.Client.LocalEndPoint!;
        await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 127, 0, 0, 1, (byte)(local.Port >> 8), (byte)local.Port }, token);
        var head = new byte[4]; await stream.ReadExactlyAsync(head, token);
        if (head[0] != 5 || head[1] != 0 || head[2] != 0 || head[3] is not (1 or 4)) throw new OperationException("隔离 SOCKS UDP 通道未建立。");
        var address = new byte[head[3] == 1 ? 4 : 16]; await stream.ReadExactlyAsync(address, token); var number = new byte[2]; await stream.ReadExactlyAsync(number, token);
        var relay = new IPEndPoint(new IPAddress(address), BinaryPrimitives.ReadUInt16BigEndian(number));
        if (relay.Address.Equals(IPAddress.Any)) relay.Address = IPAddress.Loopback; if (relay.Address.Equals(IPAddress.IPv6Any)) relay.Address = IPAddress.IPv6Loopback;
        if (!IPAddress.IsLoopback(relay.Address) || relay.Port == 0) throw new OperationException("隔离 UDP 中继必须是本机回环监听。");
        if (relay.AddressFamily != AddressFamily.InterNetwork) throw new OperationException("隔离 SOCKS 监听返回了非预期的本机地址族。");
        var ipv6 = target.AddressFamily == AddressFamily.InterNetworkV6; var targetBytes = target.Address.GetAddressBytes();
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var query = UdpDnsProbe.Query("example.com", ipv6 ? "AAAA" : "A");
            byte[] packet = [0, 0, 0, ipv6 ? (byte)4 : (byte)1, .. targetBytes, (byte)(target.Port >> 8), (byte)target.Port, .. query];
            using var responseBudget = CancellationTokenSource.CreateLinkedTokenSource(token); responseBudget.CancelAfter(TimeSpan.FromSeconds(3));
            try
            {
                await udp.SendAsync(packet, relay, responseBudget.Token);
                for (var count = 0; count < 16; count++)
                {
                    var received = await udp.ReceiveAsync(responseBudget.Token); var data = received.Buffer; var offset = 6 + targetBytes.Length;
                    if (!received.RemoteEndPoint.Equals(relay) || data.Length < offset + 12 || data[0] != 0 || data[1] != 0 || data[2] != 0 || data[3] != packet[3] || !data.AsSpan(4, targetBytes.Length).SequenceEqual(targetBytes) || BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset - 2, 2)) != target.Port) continue;
                    if (UdpDnsProbe.Matches(query, data[offset..])) return new JsonObject { ["Transport"] = "UDP", ["ResponseMatched"] = true, ["ResolverAddress"] = target.Address.ToString(), ["ResolverPort"] = target.Port, ["QueryName"] = "example.com", ["QueryType"] = ipv6 ? "AAAA" : "A" };
                }
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
        }
        throw new OperationException("未收到经代理返回的匹配 UDP DNS 回答；请核对 UDP 放行、中继方式及出口 DNS。");
    }
}
