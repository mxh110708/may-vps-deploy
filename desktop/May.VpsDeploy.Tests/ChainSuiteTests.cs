using System.Diagnostics;

internal sealed partial class BoundaryTests
{
    // The normal suite and CI phases share the same cases and order. Keep the
    // phase names aligned with scripts/ci/run.py; no case is CI-only.
    private static readonly string[] ChainPhases =
        ["forwarding-models", "adjacent-tunnels", "forwarding-paths", "underlays", "shared-chains", "wireguard-inbounds"];

    public async Task RunChainPhase(string phase)
    {
        var before = assertions;
        var watch = Stopwatch.StartNew();
        Console.WriteLine("START: chain phase " + phase);
        switch (phase)
        {
            case "forwarding-models":
                await ForwardProxy42Model(); await ForwardProxy42Workflows(); await ForwardProxy42Validation();
                await ForwardTarget36Model(); await ForwardTarget36Workflows();
                await ForwardProxy40Model(); await ForwardProxy40Workflows();
                await ForwardMulti41Model(); await ForwardMulti41Workflows();
                break;
            case "adjacent-tunnels":
                await Chain30Coverage();
                break;
            case "forwarding-paths":
                using (var nodes = new Fixture(repository)) await ForwardedNodeExperience(nodes);
                using (var forwarding = new Fixture(repository))
                {
                    await TcpForwardExperience(forwarding);
                    await TcpForwardValidationLoopback(forwarding);
                }
                await TcpChainExperience();
                await Chain21Coverage();
                break;
            case "underlays":
                await Chain24Coverage();
                break;
            case "shared-chains":
                await SharedChainCoverage();
                break;
            case "wireguard-inbounds":
                await WireGuardCoverage();
                await InboundExperience();
                await InboundPolicy28Model();
                await InboundPolicy28Runtime();
                await InboundPolicy28ProbeRuntime();
                break;
            default:
                throw new ArgumentException("Unknown chain phase: " + phase);
        }
        Console.WriteLine($"PASS: {assertions - before} chain assertions (phase {phase}); {watch.Elapsed.TotalSeconds:F2}s; no production connections.");
    }
}
