using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

internal sealed partial class BoundaryTests
{
    // Mihomo's mixed listener binds both transports. A TCP-only ephemeral
    // selection can land inside a Windows UDP exclusion range. Check both
    // exclusively on loopback, without changing any host networking setting.
    private static int MixedPort(Func<int>? candidate = null)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var port = candidate?.Invoke() ?? RandomNumberGenerator.GetInt32(20000, 49000);
            using var tcp = new TcpListener(IPAddress.Loopback, port);
            using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            tcp.Server.ExclusiveAddressUse = true;
            udp.ExclusiveAddressUse = true;
            try
            {
                udp.Bind(new IPEndPoint(IPAddress.Loopback, port));
                tcp.Start();
                return port;
            }
            catch (SocketException) { }
        }
        throw new IOException("No exclusive loopback TCP/UDP test port was available.");
    }
    private void MixedPortBoundaries()
    {
        using var blockedUdp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        blockedUdp.ExclusiveAddressUse = true; blockedUdp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort = ((IPEndPoint)blockedUdp.LocalEndPoint!).Port; var attempts = 0;
        var first = MixedPort(() => attempts++ == 0 ? udpPort : RandomNumberGenerator.GetInt32(20000, 49000));
        Check(first != udpPort && attempts > 1, "mixed fixture accepted an unavailable UDP port");
        using var blockedTcp = new TcpListener(IPAddress.Loopback, 0); blockedTcp.Start();
        var tcpPort = ((IPEndPoint)blockedTcp.LocalEndpoint).Port; attempts = 0;
        var second = MixedPort(() => attempts++ == 0 ? tcpPort : RandomNumberGenerator.GetInt32(20000, 49000));
        Check(second != tcpPort && attempts > 1, "mixed fixture accepted an unavailable TCP port");
        using var tcp = new TcpListener(IPAddress.Loopback, first);
        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        tcp.Server.ExclusiveAddressUse = true; udp.ExclusiveAddressUse = true;
        udp.Bind(new IPEndPoint(IPAddress.Loopback, first)); tcp.Start();
        Check(tcp.Server.IsBound && udp.IsBound, "mixed fixture did not release a usable pair of transports");
    }
}
