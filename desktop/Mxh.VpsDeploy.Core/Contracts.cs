using System.Text.Json.Nodes;

namespace Mxh.VpsDeploy.Core;

public enum OperationKind { ConnectExisting, Deploy, Resume, HealthAudit, TuneNetwork, ProtocolState, RotateCredentials, Upgrade, Restore, Recover, Komari, Decommission, ResumeImport, InstallComponent, TunnelAccess, MeasureNetwork, BbrKernel, CheckComponentUpdate }
public enum TaskOutcome { Running, Completed, CompletedWithWarnings, Cancelled, Failed, NeedsRecovery }
public enum ComponentScope { Protocol, Network, Firewall, Ssh, KomariAgent, KomariController, Tunnel, ManagedInstance }
public sealed record HostIdentity(string Host, int Port, string Algorithm, string Sha256Fingerprint, bool Changed);
public sealed record UserDecision(string Title, string Description, string? RequiredPhrase = null);
public interface IUserInteraction
{
    Task<bool> ConfirmHostAsync(HostIdentity identity, CancellationToken cancellationToken);
    Task<bool> ConfirmAsync(UserDecision decision, CancellationToken cancellationToken);
    Task<string?> SecretAsync(string title, CancellationToken cancellationToken);
}
public interface ISecretProtector
{
    string Format { get; }
    byte[] Protect(ReadOnlySpan<byte> data);
    byte[] Unprotect(ReadOnlySpan<byte> data);
}
public interface IPrivateKeyAccess { void PrepareManagedCopy(string path); }
public interface IManagedKeyStore { string Prepare(string directory, string source, string? passphrase = null); }
public interface IExternalToolRunner
{
    Task<CommandResult> RunAsync(string executable, IReadOnlyList<string> arguments, string? input, TimeSpan timeout, CancellationToken cancellationToken);
}
public sealed record CommandResult(int ExitCode, string Output, string Error)
{
    public void RequireSuccess(string safeDescription)
    {
        if (ExitCode != 0) throw SafeFailures.Remote(this, safeDescription);
    }
}
public sealed record SshEndpoint(string Host, int Port, string User, string? KeyPath, string? Password = null, string? KeyPassphrase = null);
public interface IRemoteSession : IAsyncDisposable
{
    Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken cancellationToken);
    Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken cancellationToken);
    Task<byte[]> ReadFileAsync(string absolutePath, CancellationToken cancellationToken);
    Task DownloadAsync(string absolutePath, string destination, CancellationToken cancellationToken);
}
public interface IRemoteSessionFactory
{
    Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction interaction, CancellationToken cancellationToken);
}
public sealed record OperationRequest(OperationKind Kind, string InstanceRelativePath, JsonObject Options)
{
    public OperationRequest Snapshot() => this with { Options = (JsonObject)Options.DeepClone() };
}
public sealed record ReviewedOperation(OperationRequest Request, string Fingerprint, string PlanFingerprint, string Summary);
public enum TaskStepState { Waiting, Running, Completed, Skipped, Failed, Cancelled }
public sealed record PlannedTaskStep(string Id, string Title, string Description);
public sealed record TaskProgress(string TaskId, string Stage, int Completed, int Total, string Message,
    string? StepId = null, TaskStepState? StepState = null, IReadOnlyList<PlannedTaskStep>? Steps = null);
public sealed record TaskRecord(string Id, OperationKind Kind, DateTimeOffset StartedAt, DateTimeOffset? FinishedAt, TaskOutcome Outcome, string Stage, string? SafeError = null, string? ErrorCode = null, string? NextAction = null, string? InstanceRelativePath = null, string? TargetLabel = null);
public sealed class OperationException(string safeMessage, bool needsRecovery = false, string? code = null, string? nextAction = null) : Exception(safeMessage)
{
    public bool NeedsRecovery { get; } = needsRecovery;
    public string? Code { get; } = code;
    public string? NextAction { get; } = nextAction;
}
public sealed class KeyPassphraseRequiredException : Exception { }

public static class JsonFields
{
    public static JsonNode? At(this JsonNode? node, string path)
    {
        JsonNode? current = node;
        foreach (var key in path.Split('.')) current = (current as JsonObject)?[key];
        return current;
    }
    public static string Text(this JsonNode? node, string path, string fallback = "") => node.At(path)?.ToString() ?? fallback;
    public static int Number(this JsonNode? node, string path, int fallback = 0) => int.TryParse(node.Text(path), out var value) ? value : fallback;
    public static long Long(this JsonNode? node, string path, long fallback = 0) => long.TryParse(node.Text(path), out var value) ? value : fallback;
    public static bool Flag(this JsonNode? node, string path, bool fallback = false) => bool.TryParse(node.Text(path), out var value) ? value : fallback;
    public static string[] Strings(this JsonNode? node, string path) => (node.At(path) as JsonArray)?.Select(x => x?.ToString() ?? "").ToArray() ?? [];
    public static void Put(this JsonObject node, string path, JsonNode? value)
    {
        var keys = path.Split('.'); var target = node;
        foreach (var key in keys[..^1]) { target[key] ??= new JsonObject(); target = target[key]!.AsObject(); }
        target[keys[^1]] = value;
    }
}
