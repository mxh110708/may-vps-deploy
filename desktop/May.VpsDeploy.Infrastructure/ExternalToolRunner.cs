using System.Diagnostics;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class ExternalToolRunner : IExternalToolRunner
{
    public async Task<CommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, string? input, TimeSpan timeout, CancellationToken cancellationToken)
    {
        SafePath.CheckLinks(executable);
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        start.Environment["PYTHONUTF8"] = "1";
        using var process = Process.Start(start) ?? throw new OperationException("辅助工具无法启动。");
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        if (input != null) await process.StandardInput.WriteAsync(input.AsMemory(), cancellationToken);
        process.StandardInput.Close();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(timeout);
        try { await process.WaitForExitAsync(deadline.Token); return new(process.ExitCode, await output, await error); }
        catch { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); throw; }
    }
}
