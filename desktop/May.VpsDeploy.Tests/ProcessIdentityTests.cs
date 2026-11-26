using System.Diagnostics;

internal sealed partial class BoundaryTests
{
    public void RunProcessIdentityTests()
    {
        ProcessIdentityBoundaries();
        Console.WriteLine($"PASS: {assertions} process ownership assertions.");
    }

    private void ProcessIdentityBoundaries()
    {
        using var process = Process.GetCurrentProcess();
        var current = new TestProcessIdentity(process);
        Check(!current.Exited, "the currently owned live process was reported exited");
        var previous = new TestProcessIdentity(current.ProcessId, current.StartedUtc.AddSeconds(-1));
        Check(previous.Exited, "a reused PID was attributed to the previous process instance");
        Check(!current.Exited && !process.HasExited, "rejecting a stale identity changed the live process");
    }
}
