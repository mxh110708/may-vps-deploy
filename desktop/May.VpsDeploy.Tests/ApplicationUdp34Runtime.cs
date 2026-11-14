using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    // A fresh destination association per exchange, matching native UDP-session
    // routing. The response records the source observed by the owned target.
    private static async Task<string?> Udp34Exchange(int proxyPort, IPEndPoint target, CancellationToken ct, string? domain = null, bool denied = false)
    {
        using var control = new TcpClient(); await control.ConnectAsync(IPAddress.Loopback, proxyPort, ct); var stream = control.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, ct); var greeting = new byte[2]; await stream.ReadExactlyAsync(greeting, ct);
        if (!greeting.SequenceEqual(new byte[] { 5, 0 })) throw new Exception("Round34 SOCKS negotiation failed");
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); var local = (IPEndPoint)socket.Client.LocalEndPoint!;
        await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 127, 0, 0, 1, (byte)(local.Port >> 8), (byte)local.Port }, ct);
        var head = new byte[4]; await stream.ReadExactlyAsync(head, ct); if (!head.SequenceEqual(new byte[] { 5, 0, 0, 1 })) throw new Exception("Round34 UDP relay failed");
        var endpoint = new byte[6]; await stream.ReadExactlyAsync(endpoint, ct); var address = new IPAddress(endpoint[..4]); if (address.Equals(IPAddress.Any)) address = IPAddress.Loopback;
        if (!IPAddress.IsLoopback(address)) throw new Exception("Round34 relay is outside the fixture");
        socket.Connect(new IPEndPoint(address, BinaryPrimitives.ReadUInt16BigEndian(endpoint.AsSpan(4))));
        var ipv6 = target.AddressFamily == AddressFamily.InterNetworkV6;
        byte[] destination = domain == null ? [ipv6 ? (byte)4 : (byte)1, .. target.Address.GetAddressBytes()] : [3, (byte)Encoding.ASCII.GetByteCount(domain), .. Encoding.ASCII.GetBytes(domain)];
        for (var attempt = 0; attempt < (denied ? 1 : 3); attempt++)
        {
            var query = UdpDnsProbe.Query("example.com", ipv6 ? "AAAA" : "A");
            byte[] request = [0, 0, 0, .. destination, (byte)(target.Port >> 8), (byte)target.Port, .. query];
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct); budget.CancelAfter(TimeSpan.FromMilliseconds(denied ? 450 : 1500));
            try
            {
                await socket.SendAsync(request, budget.Token);
                for (var count = 0; count < 16; count++)
                {
                    var response = (await socket.ReceiveAsync(budget.Token)).Buffer;
                    if (response.Length < 8 || response[0] != 0 || response[1] != 0 || response[2] != 0) continue;
                    var offset = response[3] == 1 ? 10 : response[3] == 4 ? 22 : response[3] == 3 ? 7 + response[4] : 0;
                    if (offset == 0 || response.Length < offset || !UdpDnsProbe.Matches(query, response[offset..])) continue;
                    return new IPAddress(response[^(ipv6 ? 16 : 4)..]).ToString();
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionReset && !ct.IsCancellationRequested) { }
        }
        return null;
    }
    private sealed class Policy34UdpTarget : IAsyncDisposable
    {
        private readonly UdpClient listener; private readonly CancellationTokenSource stop = new(); private readonly Task task;
        private int requests;
        public int Requests => Volatile.Read(ref requests);
        public IPEndPoint Endpoint => (IPEndPoint)listener.Client.LocalEndPoint!;
        public Policy34UdpTarget(string address)
        {
            listener = new(new IPEndPoint(IPAddress.Parse(address), 0));
            task = Task.Run(async () =>
            {
                try
                {
                    while (!stop.IsCancellationRequested)
                    {
                        var received = await listener.ReceiveAsync(stop.Token); var query = received.Buffer;
                        if (query.Length < 17) continue; Interlocked.Increment(ref requests);
                        var answer = query.ToArray(); answer[2] = 0x81; answer[3] = 0x80; answer[6] = 0; answer[7] = 1;
                        var source = received.RemoteEndPoint.Address.GetAddressBytes();
                        byte[] packet = [.. answer, 0xc0, 0x0c, .. query[^4..], 0, 0, 0, 1, 0, (byte)source.Length, .. source];
                        await listener.SendAsync(packet, received.RemoteEndPoint, stop.Token);
                    }
                }
                catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
            });
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Dispose(); await task; stop.Dispose(); }
    }
}
