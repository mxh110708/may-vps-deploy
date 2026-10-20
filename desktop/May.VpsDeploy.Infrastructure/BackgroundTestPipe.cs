using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

/// <summary>One bounded JSON line per connection. Local, current-user-only, authenticated, serial commands.</summary>
public sealed class BackgroundTestPipe(BackgroundTestSession session, Func<string, JsonObject, Task<JsonObject>> dispatch) : IAsyncDisposable
{
    public const int MaximumBytes = 1024 * 1024;
    private readonly CancellationTokenSource stopping = new();
    private readonly HashSet<string> seen = new(StringComparer.Ordinal);
    private Task? listener;
    public void Start() { if (listener != null) throw new InvalidOperationException(); listener = Listen(); }
    private async Task Listen()
    {
        // Keep the listener alive across clients. On Unix, disposing the last server
        // instance also closes its listening socket and drops already queued clients.
        await using var pipe = new NamedPipeServerStream(session.PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        while (!stopping.IsCancellationRequested)
        {
            var connected = false;
            try
            {
                await pipe.WaitForConnectionAsync(stopping.Token);
                connected = true;
                using var limit = CancellationTokenSource.CreateLinkedTokenSource(stopping.Token); limit.CancelAfter(TimeSpan.FromSeconds(15));
                var request = await Read(pipe, limit.Token);
                var response = await Handle(request);
                await Write(pipe, response, limit.Token);
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested) { break; }
            catch (Exception error) when (error is IOException or JsonException or OperationException or OperationCanceledException) { /* Reject malformed/oversized/idle clients; keep the session available. */ }
            finally { if (connected) pipe.Disconnect(); }
        }
    }
    private async Task<JsonObject> Handle(JsonObject request)
    {
        var id = request.Text("id"); var command = request.Text("command");
        var response = new JsonObject { ["version"] = 1, ["id"] = id };
        try
        {
            var token = request.Text("token");
            if (request.Number("version") != 1 || !Guid.TryParseExact(id, "N", out _) || token.Length != session.Token.Length ||
                !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(token), Encoding.ASCII.GetBytes(session.Token)))
                throw new OperationException("测试协议或会话凭据不匹配。", code: "TestAuthenticationDenied");
            if (!seen.Add(id)) throw new OperationException("重复测试请求已拒绝，避免重复操作。", code: "TestDuplicateRequest");
            if (seen.Count > 100000) throw new OperationException("本次测试会话已达到请求上限，请开启新会话。");
            if (command.Length > 40) throw new OperationException("测试指令无效。");
            response["result"] = await dispatch(command, request["arguments"]?.AsObject() ?? new()); response["ok"] = true;
        }
        catch (Exception error)
        {
            response["ok"] = false; response["error_code"] = error is OperationException safe ? safe.Code ?? "TestCommandRefused" : "TestCommandFailed";
            response["message"] = error is OperationException operation ? operation.Message : "测试操作未完成；没有返回凭据或异常堆栈。";
        }
        // Deliberately omit selectors, values, tokens, replies and paths from the audit trail.
        File.AppendAllText(session.Artifact("commands.jsonl"), new JsonObject { ["at"] = DateTimeOffset.UtcNow.ToString("O"), ["id"] = Guid.TryParseExact(id, "N", out _) ? id : "invalid", ["command"] = System.Text.RegularExpressions.Regex.IsMatch(command, @"^[a-z.]{1,40}$") ? command : "invalid", ["ok"] = response["ok"]?.DeepClone(), ["error_code"] = response["error_code"]?.DeepClone() }.ToJsonString() + "\n");
        return response;
    }
    public static async Task<JsonObject> Read(Stream pipe, CancellationToken token)
    {
        using var data = new MemoryStream(); var chunk = new byte[4096];
        while (true)
        {
            var count = await pipe.ReadAsync(chunk, token); if (count == 0) throw new IOException("Closed test pipe.");
            var newline = Array.IndexOf(chunk, (byte)'\n', 0, count); var used = newline < 0 ? count : newline;
            if (data.Length + used > MaximumBytes) throw new OperationException("测试请求超过大小限制。");
            data.Write(chunk, 0, used);
            if (newline >= 0) return JsonNode.Parse(data.GetBuffer().AsSpan(0, (int)data.Length), documentOptions: new JsonDocumentOptions { MaxDepth = 32 }) as JsonObject ?? throw new JsonException();
        }
    }
    public static async Task Write(Stream pipe, JsonObject value, CancellationToken token)
    {
        var bytes = Encoding.UTF8.GetBytes(value.ToJsonString() + "\n");
        if (bytes.Length > MaximumBytes) throw new OperationException("测试结果超过大小限制。");
        await pipe.WriteAsync(bytes, token); await pipe.FlushAsync(token);
    }
    public static async Task<JsonObject> SendAsync(BackgroundTestSession session, string command, JsonObject arguments, CancellationToken token)
    {
        await using var pipe = new NamedPipeClientStream(".", session.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await pipe.ConnectAsync(5000, token);
        await Write(pipe, new JsonObject { ["version"] = 1, ["id"] = Guid.NewGuid().ToString("N"), ["token"] = session.Token, ["command"] = command, ["arguments"] = arguments.DeepClone() }, token);
        return await Read(pipe, token);
    }
    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync(); if (listener != null) await listener; stopping.Dispose();
    }
}
