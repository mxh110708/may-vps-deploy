using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Mxh.VpsDeploy.Core;

namespace Mxh.VpsDeploy.Infrastructure;

/// <summary>Explicit opt-in configuration for a disposable app instance; never loaded by normal startup.</summary>
public sealed class BackgroundTestSession
{
    public const string Marker = "background-test.fixture.json";
    public string Root { get; }
    public string PipeName { get; }
    public string Token { get; }
    public string Id { get; }
    private readonly bool allowManagementPortTransition;
    private readonly bool allowTransportFaults;
    private readonly object endpointLock = new();
    private readonly HashSet<string> endpoints = new(StringComparer.Ordinal);
    private readonly HashSet<string> initialEndpoints = new(StringComparer.Ordinal);
    private BackgroundTestSession(JsonObject config, string root)
    {
        Root = root; PipeName = config.Text("PipeName"); Token = config.Text("Token"); Id = config.Text("SessionId");
        allowManagementPortTransition = config.Flag("AllowManagementPortTransition");
        allowTransportFaults = config.Flag("AllowTransportFaults");
        if (allowTransportFaults && (config["AllowedEndpoints"] as JsonArray ?? []).Count == 0) throw new OperationException("中断测试需要明确的测试机白名单。");
        if (config.Number("SchemaVersion") != 1 || !Guid.TryParseExact(Id, "N", out _) ||
            !Regex.IsMatch(PipeName, @"^mxh-test-[a-f0-9]{32}$") || !Regex.IsMatch(Token, @"^[a-f0-9]{64}$"))
            throw new OperationException("后台测试会话参数无效。");
        foreach (var target in (config["AllowedEndpoints"] as JsonArray ?? []))
        {
            var host = target.Text("Host"); var port = target.Number("Port");
            if (!IPAddress.TryParse(host, out var ip) || IPAddress.IsLoopback(ip) || port is < 1 or > 65535)
                throw new OperationException("测试机白名单必须包含明确 IP 和 SSH 端口。");
            endpoints.Add(ip + ":" + port);
            initialEndpoints.Add(ip + ":" + port);
        }
    }
    public static BackgroundTestSession Load(string manifest, string applicationRoot)
    {
        SafePath.CheckLinks(manifest); var config = ArchiveStore.ReadJson(manifest);
        var root = Path.GetFullPath(config.Text("Root")).TrimEnd(Path.DirectorySeparatorChar);
        var application = Path.GetFullPath(applicationRoot).TrimEnd(Path.DirectorySeparatorChar);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!Path.IsPathFullyQualified(config.Text("Root")) || root.Equals(application, comparison) ||
            root.StartsWith(application + Path.DirectorySeparatorChar, comparison) || application.StartsWith(root + Path.DirectorySeparatorChar, comparison) ||
            !Path.GetFullPath(manifest).Equals(SafePath.Resolve(root, "test-session.private.json"), comparison))
            throw new OperationException("后台测试必须使用独立目录和会话清单。");
        var session = new BackgroundTestSession(config, root);
        var markerFile = SafePath.Resolve(root, Marker);
        if (!File.Exists(markerFile)) throw new OperationException("后台测试工作区缺少隔离标记。");
        var marker = ArchiveStore.ReadJson(markerFile);
        if (!marker.Flag("IsolatedTestRoot") || marker.Text("SessionId") != session.Id ||
            File.Exists(SafePath.Resolve(root, PrivateDirectory.LocationFile)))
            throw new OperationException("后台测试工作区缺少匹配标记，或重用了外部私人归档。");
        Directory.CreateDirectory(SafePath.Resolve(root, "test-artifacts"));
        return session;
    }
    public string Artifact(string name)
    {
        if (!Regex.IsMatch(name, @"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$")) throw new OperationException("测试输出名称无效。");
        return SafePath.Resolve(Root, "test-artifacts/" + name);
    }
    public string Secret(string reference)
    {
        var file = SafePath.Resolve(SafePath.Resolve(Root, "test-secrets"), reference);
        if (new FileInfo(file).Length > 65536) throw new OperationException("测试凭据文件过大。");
        return File.ReadAllText(file).TrimEnd('\r', '\n');
    }
    public void RequireLocalPath(string value)
    {
        if (value == "") return;
        var full = Path.GetFullPath(value); var prefix = Root + Path.DirectorySeparatorChar;
        if (!Path.IsPathFullyQualified(value) || !full.StartsWith(prefix, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new OperationException("后台测试的文件和输出路径必须位于本次工作区。");
        SafePath.CheckLinks(full);
    }
    public IRemoteSessionFactory Restrict(IRemoteSessionFactory factory) => new RestrictedFactory(this, factory);
    public void PrepareReviewedDeployment(JsonObject plan)
    {
        var bootstrap = plan.Number("Server.BootstrapSshPort");
        var ports = new[] { plan.Number("Ports.SshPrimary"), plan.Number("Ports.SshRescue") };
        if (!IPAddress.TryParse(plan.Text("Server.IPv4"), out var ip) || IPAddress.IsLoopback(ip) ||
            bootstrap is < 1 or > 65535 || ports.Any(port => port is < 1 or > 65535))
            throw new OperationException("审阅计划中的测试 SSH 目标无效。", code: "TestTargetDenied");
        lock (endpointLock)
        {
            // A reviewed plan can extend only its original, explicitly listed bootstrap
            // endpoint. Derived ports cannot authorize another host or bootstrap endpoint.
            if (!initialEndpoints.Contains(ip + ":" + bootstrap))
                throw new OperationException("此部署的初始 SSH 目标未列入本次测试白名单。", code: "TestTargetDenied");
            var additions = ports.Distinct().Select(port => ip + ":" + port).Where(target => !endpoints.Contains(target)).ToArray();
            if (additions.Length == 0) return;
            if (!allowManagementPortTransition)
                throw new OperationException("审阅计划包含尚未授权的管理端口。请为本轮测试显式启用管理端口切换；部署尚未开始。", code: "TestTargetDenied");
            ArchiveStore.WriteJson(Artifact("reviewed-management-" + Guid.NewGuid().ToString("N") + ".private.json"),
                new JsonObject { ["plan_fingerprint"] = ArchiveStore.Fingerprint(plan),
                    ["bootstrap"] = ip + ":" + bootstrap,
                    ["added_endpoints"] = new JsonArray(additions.Select(target => (JsonNode?)JsonValue.Create(target)).ToArray()) });
            foreach (var target in additions) endpoints.Add(target);
        }
    }
    private bool Allows(SshEndpoint endpoint)
    {
        lock (endpointLock) return IPAddress.TryParse(endpoint.Host, out var ip) && endpoints.Contains(ip + ":" + endpoint.Port);
    }
    private sealed class RestrictedFactory(BackgroundTestSession session, IRemoteSessionFactory factory) : IRemoteSessionFactory
    {
        public async Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction interaction, CancellationToken cancellationToken)
        {
            if (!session.Allows(endpoint))
                throw new OperationException("此 SSH 目标未列入本次后台测试白名单，连接已阻止。", code: "TestTargetDenied");
            if (endpoint.KeyPath != null) session.RequireLocalPath(endpoint.KeyPath);
            var connection = await factory.OpenAsync(endpoint, interaction, cancellationToken);
            return session.allowTransportFaults ? new BackgroundFaultSession(session, connection) : connection;
        }
    }
}
