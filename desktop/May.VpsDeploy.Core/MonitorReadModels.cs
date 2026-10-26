using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public sealed class MonitorReadConnection
{
    public const string SnapshotPath = "api/integration/v1/snapshot";
    public const int MaxNodes = 100;
    public Uri Endpoint { get; }
    public string Token { get; }
    public IReadOnlyDictionary<string, string> Bindings { get; }
    public string Identity { get; }
    public string? ServerInstanceId { get; }

    public MonitorReadConnection(string endpoint, string token, IReadOnlyDictionary<string, string> bindings, string? serverInstanceId = null)
    {
        Endpoint = ValidateEndpoint(endpoint);
        if (!string.IsNullOrEmpty(serverInstanceId) && (!Guid.TryParseExact(serverInstanceId, "D", out var origin) || origin == Guid.Empty || origin.ToString("D") != serverInstanceId))
            throw new OperationException("监控服务身份须为有效的安装 UUID。");
        ServerInstanceId = string.IsNullOrEmpty(serverInstanceId) ? null : serverInstanceId;
        if (!Regex.IsMatch(token, @"^may_read_[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant))
            throw new OperationException("请使用 May Monitor 专用只读令牌，不能使用管理员 API Key 或 Agent Token。");
        var encoded = token[9..];
        try { if (Convert.ToBase64String(Convert.FromBase64String(encoded.Replace('-', '+').Replace('_', '/') + "=")).TrimEnd('=').Replace('+', '-').Replace('/', '_') != encoded) throw new FormatException(); }
        catch (FormatException) { throw new OperationException("只读令牌格式无效。"); }
        if (bindings.Count is < 1 or > MaxNodes) throw new OperationException("请明确绑定 1 至 100 个实例与监测节点。");
        var selected = new Dictionary<string, string>(StringComparer.Ordinal);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (relative, id) in bindings)
        {
            OperationPolicy.Validate(new(OperationKind.HealthAudit, relative, new()));
            if (!Guid.TryParseExact(id, "D", out var uuid) || uuid == Guid.Empty || uuid.ToString("D") != id || !ids.Add(id))
                throw new OperationException("监测节点 UUID 无效或重复绑定；请逐项核对，不按名称或 IP 自动匹配。");
            selected.Add(relative, id);
        }
        Token = token;
        Bindings = new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(selected);
        Identity = ArchiveStore.Fingerprint(ToJson());
    }

    public static Uri ValidateEndpoint(string value)
    {
        if (value.Length > 2048 || !Uri.TryCreate(value.Trim(), UriKind.Absolute, out var endpoint) || endpoint.UserInfo != "" || endpoint.Query != "" || endpoint.Fragment != "" || endpoint.AbsolutePath.Contains('%') || endpoint.Host.Length == 0 || (endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.IsLoopback)))
            throw new OperationException("监测地址须为 HTTPS，不能包含账号、查询参数或片段；HTTP 仅允许本机回环地址。");
        return new Uri(endpoint.GetLeftPart(UriPartial.Path).TrimEnd('/') + "/");
    }

    public JsonObject ToJson() => new()
    {
        ["SchemaVersion"] = 1, ["Endpoint"] = Endpoint.AbsoluteUri, ["Token"] = Token, ["ServerInstanceId"] = ServerInstanceId,
        ["Bindings"] = new JsonObject(Bindings.Select(p => KeyValuePair.Create<string, JsonNode?>(p.Key, JsonValue.Create(p.Value))))
    };

    public static MonitorReadConnection FromJson(JsonObject value)
    {
        if (value.Number("SchemaVersion") != 1 || value["Bindings"] is not JsonObject bindings)
            throw new OperationException("监测连接格式不受支持，未修改原记录。");
        try { return new(value.Text("Endpoint"), value.Text("Token"), bindings.ToDictionary(p => p.Key, p => p.Value?.GetValue<string>() ?? throw new FormatException(), StringComparer.Ordinal), value.Text("ServerInstanceId")); }
        catch (Exception error) when (error is InvalidOperationException or FormatException or ArgumentException)
        { throw new OperationException("监测连接记录无效，未修改原记录。"); }
    }

    public static string NewToken() => "may_read_" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // Only the digest and explicitly selected UUIDs are exported. The private
    // token stays in the encrypted connection archive, never an env file.
    public string ProvisioningEnvironment(DateTimeOffset now) =>
        "MAY_MONITOR_READ_TOKEN_SHA256=" + ArchiveStore.Digest(Encoding.UTF8.GetBytes(Token)) + "\n" +
        "MAY_MONITOR_READ_CLIENT_UUIDS=" + string.Join(',', Bindings.Values.Order(StringComparer.Ordinal)) + "\n" +
        "MAY_MONITOR_READ_EXPIRES_AT=" + now.ToUniversalTime().AddDays(30).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) + "\n";

    public override string ToString() => "May Monitor read-only connection";
}

public sealed record MonitorReadMetrics(double CpuPercent, long MemoryUsed, long MemoryTotal, long UploadPerSec, long DownloadPerSec, long UploadTotal, long DownloadTotal);
public sealed record MonitorReadAlerts(int Active, int Silenced, int DeliveryFailed);
public sealed record MonitorReadNode(string Uuid, bool Online, DateTimeOffset? ReportAt, MonitorReadMetrics? Metrics, MonitorReadAlerts? Alerts = null)
{
    public string Status(DateTimeOffset now, DateTimeOffset receivedAt, bool failed)
    {
        if (failed || now - receivedAt > TimeSpan.FromSeconds(90)) return "读取失败或快照过期";
        if (ReportAt == null) return "尚无上报";
        if (ReportAt > now.AddSeconds(5)) return "节点时间异常";
        if (!Online) return "离线 · 保留最近上报";
        if (now - ReportAt > TimeSpan.FromSeconds(90)) return "在线 · 上报已过期";
        return Metrics == null ? "在线 · 指标无效" : "在线";
    }
}

public interface IMonitorReadProbe
{
    Task<MonitorReadSnapshot> FetchAsync(MonitorReadConnection connection, CancellationToken cancellationToken);
}

public sealed record MonitorReadSnapshot(DateTimeOffset CapturedAt, DateTimeOffset ReceivedAt, string ServerVersion, IReadOnlyDictionary<string, MonitorReadNode> Nodes, string? ServerInstanceId = null, DateTimeOffset? CredentialExpiresAt = null)
{
    public static MonitorReadSnapshot Parse(ReadOnlyMemory<byte> bytes, DateTimeOffset receivedAt)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 12 });
            var root = document.RootElement;
            if (root.GetProperty("schema_version").GetInt32() != 1) throw new FormatException();
            var captured = root.GetProperty("captured_at").GetDateTimeOffset();
            if ((receivedAt - captured).Duration() > TimeSpan.FromMinutes(2)) throw new FormatException();
            var version = root.GetProperty("server_version").GetString() ?? "";
            if (version.Length is < 1 or > 80 || version.Any(char.IsControl)) throw new FormatException();
            string? instance = null;
            if (root.TryGetProperty("server_instance_id", out var identity))
            {
                instance = identity.GetString();
                if (!Guid.TryParseExact(instance, "D", out var parsed) || parsed == Guid.Empty || parsed.ToString("D") != instance) throw new FormatException();
            }
            var items = root.GetProperty("nodes");
            if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() > MonitorReadConnection.MaxNodes) throw new FormatException();
            var nodes = new Dictionary<string, MonitorReadNode>(StringComparer.Ordinal);
            DateTimeOffset? credentialExpiresAt = null;
            if (root.TryGetProperty("credential_expires_at", out var expires) && expires.ValueKind != JsonValueKind.Null)
            {
                credentialExpiresAt = expires.GetDateTimeOffset();
                if (credentialExpiresAt <= captured || credentialExpiresAt > captured.AddDays(90)) throw new FormatException();
            }
            foreach (var item in items.EnumerateArray())
            {
                var id = item.GetProperty("uuid").GetString()!;
                if (!Guid.TryParseExact(id, "D", out var uuid) || uuid == Guid.Empty || uuid.ToString("D") != id) throw new FormatException();
                var report = item.GetProperty("report_at");
                DateTimeOffset? at = report.ValueKind == JsonValueKind.Null ? null : report.GetDateTimeOffset();
                var values = item.GetProperty("metrics");
                MonitorReadMetrics? metrics = null;
                if (values.ValueKind != JsonValueKind.Null)
                {
                    metrics = new(values.GetProperty("cpu_percent").GetDouble(), values.GetProperty("memory_used").GetInt64(), values.GetProperty("memory_total").GetInt64(), values.GetProperty("upload_per_sec").GetInt64(), values.GetProperty("download_per_sec").GetInt64(), values.GetProperty("upload_total").GetInt64(), values.GetProperty("download_total").GetInt64());
                    if (at == null || !double.IsFinite(metrics.CpuPercent) || metrics.CpuPercent is < 0 or > 100 || metrics.MemoryUsed < 0 || metrics.MemoryTotal <= 0 || metrics.MemoryUsed > metrics.MemoryTotal || metrics.UploadPerSec < 0 || metrics.DownloadPerSec < 0 || metrics.UploadTotal < 0 || metrics.DownloadTotal < 0) throw new FormatException();
                }
                MonitorReadAlerts? alerts = null;
                if (item.TryGetProperty("alerts", out var alert) && alert.ValueKind != JsonValueKind.Null)
                {
                    alerts = new(alert.GetProperty("active").GetInt32(), alert.GetProperty("silenced").GetInt32(), alert.GetProperty("delivery_failed").GetInt32());
                    if (alerts.Active is < 0 or > 32 || alerts.Silenced < 0 || alerts.Silenced > alerts.Active || alerts.DeliveryFailed is < 0 or > 32) throw new FormatException();
                }
                if (!nodes.TryAdd(id, new(id, item.GetProperty("online").GetBoolean(), at, metrics, alerts))) throw new FormatException();
            }
            return new(captured, receivedAt, version, new System.Collections.ObjectModel.ReadOnlyDictionary<string, MonitorReadNode>(nodes), instance, credentialExpiresAt);
        }
        catch (Exception error) when (error is JsonException or FormatException or InvalidOperationException or KeyNotFoundException or ArgumentException or OverflowException)
        { throw new OperationException("监测响应格式、指标或时间无效；需要支持只读接口的 May Monitor 版本。"); }
    }
}
