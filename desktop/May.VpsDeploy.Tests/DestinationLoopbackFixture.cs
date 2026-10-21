using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

internal sealed partial class BoundaryTests
{
    private static JsonArray LoopbackDestinationRules() => new(DestinationRule("Domain", "localhost", "Direct"), DestinationRule("Suffix", "localhost", "Reject"), DestinationRule("Cidr", "127.0.0.2/32", "Reject"), DestinationRule("Cidr", "127.0.0.1/32", "NextHop"));
    private sealed class DestinationHttpTarget : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Parse("127.0.0.2"), 0);
        private readonly CancellationTokenSource stop;
        private readonly Task server;
        private int requests;
        public int Requests => Volatile.Read(ref requests);
        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
        public DestinationHttpTarget(CancellationToken token)
        {
            stop = CancellationTokenSource.CreateLinkedTokenSource(token); listener.Start();
            server = Task.Run(async () =>
            {
                try
                {
                    while (!stop.IsCancellationRequested)
                    {
                        using var socket = await listener.AcceptTcpClientAsync(stop.Token); using var stream = socket.GetStream(); using var reader = new StreamReader(stream, leaveOpen: true);
                        while (await reader.ReadLineAsync(stop.Token) is { Length: > 0 }) { }
                        Interlocked.Increment(ref requests); await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\ndenied-ok"), stop.Token);
                    }
                }
                catch (Exception error) when (error is OperationCanceledException or SocketException or IOException or ObjectDisposedException) { }
            });
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await server; stop.Dispose(); }
    }
    private async Task CheckDeniedTarget(int proxyPort, DestinationHttpTarget target, CancellationToken token)
    {
        using (var directHandler = new HttpClientHandler { UseProxy = false })
        using (var direct = new HttpClient(directHandler) { Timeout = TimeSpan.FromSeconds(3) }) Check(await direct.GetStringAsync("http://127.0.0.2:" + target.Port, token) == "denied-ok", "denial target itself is not available");
        var before = target.Requests;
        using var handler = new HttpClientHandler { UseProxy = true, Proxy = new WebProxy("http://127.0.0.1:" + proxyPort) }; using var proxy = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) }; var denied = false;
        try { await proxy.GetStringAsync("http://127.0.0.2:" + target.Port, token); } catch (Exception error) when (error is HttpRequestException or TaskCanceledException) { denied = true; }
        Check(denied && target.Requests == before, "CIDR rejection allowed a request to reach the available target");
    }
    private async Task CheckUdpKeepsFixedPath(int relayPort, bool landingOnline, CancellationToken token)
    {
        using var target = new UdpClient(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0)); var port = ((IPEndPoint)target.Client.LocalEndPoint!).Port;
        using var sender = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        await sender.SendAsync(new byte[] { 1, 2, 3 }, new IPEndPoint(IPAddress.Parse("127.0.0.2"), port), token);
        Check((await target.ReceiveAsync(token)).Buffer.SequenceEqual(new byte[] { 1, 2, 3 }), "UDP denial target is not available");
        await sender.SendAsync(new byte[] { 0, 0, 0, 1, 127, 0, 0, 2, (byte)(port >> 8), (byte)port, 8, 9, 10 }, new IPEndPoint(IPAddress.Loopback, relayPort), token);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromMilliseconds(600)); var arrived = false;
        try { var packet = await target.ReceiveAsync(deadline.Token); arrived = packet.Buffer.SequenceEqual(new byte[] { 8, 9, 10 }); } catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
        Check(arrived == landingOnline, landingOnline ? "TCP exception changed existing UDP forwarding" : "UDP fell back to direct after the fixed landing stopped");
    }
}
