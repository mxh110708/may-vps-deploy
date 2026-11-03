using System.Diagnostics;

// A disposed child handle no longer identifies the process currently using its
// PID. Retain creation time so parallel fixtures never claim another process.
internal readonly record struct TestProcessIdentity(int ProcessId, DateTime StartedUtc)
{
    public TestProcessIdentity(Process process) : this(process.Id, process.StartTime.ToUniversalTime()) { }
    public bool Exited
    {
        get
        {
            try { using var process = Process.GetProcessById(ProcessId); return process.HasExited || process.StartTime.ToUniversalTime() != StartedUtc; }
            catch (ArgumentException) { return true; }
            catch (InvalidOperationException) { return true; }
        }
    }
}
