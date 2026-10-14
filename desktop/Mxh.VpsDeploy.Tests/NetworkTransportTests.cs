using System.Net;
using System.Reflection;
using Mxh.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private sealed class CountingBody : Stream
    {
        public long Written; public int LargestWrite;
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => Written; public override long Position { get => Written; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] b, int o, int n) => throw new NotSupportedException();
        public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long n) => throw new NotSupportedException();
        public override void Write(byte[] b, int o, int n) { Written += n; LargestWrite = Math.Max(LargestWrite, n); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> b, CancellationToken token = default) { token.ThrowIfCancellationRequested(); Written += b.Length; LargestWrite = Math.Max(LargestWrite, b.Length); return ValueTask.CompletedTask; }
    }
    private sealed class UploadRecorder(bool reject = false) : HttpMessageHandler
    {
        public int Requests; public long Written; public long LargestBody; public int LargestWrite;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Requests++; LargestBody = Math.Max(LargestBody, request.Content!.Headers.ContentLength ?? 0);
            using var sink = new CountingBody(); await request.Content.CopyToAsync(sink, token); Written += sink.Written; LargestWrite = Math.Max(LargestWrite, sink.LargestWrite);
            return new HttpResponseMessage(reject ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK) { Content = new StringContent("{}") };
        }
    }
    private async Task NetworkTransportExperience()
    {
        var transfer = typeof(NetworkMeasurement).GetMethod("Transfer", BindingFlags.NonPublic | BindingFlags.Static)!;
        Task<long> Send(HttpClient client, long bytes, CancellationToken token = default) => (Task<long>)transfer.Invoke(null, [client, "Upload", "Cloudflare", bytes, token])!;
        using var recording = new UploadRecorder(); using var http = new HttpClient(recording); var amount = 17L * 1048576 + 13;
        Check(await Send(http, amount) == amount && recording.Written == amount && recording.Requests == 3, "large uploads escaped exact reserved payload or duplicated chunks");
        Check(recording.LargestBody <= 8L * 1048576 && recording.LargestWrite <= 65536, "larger budget allocated an entire large upload body");
        using var failed = new UploadRecorder(true); using var failedHttp = new HttpClient(failed); var rejected = false;
        try { await Send(failedHttp, amount); } catch (HttpRequestException) { rejected = true; }
        Check(rejected && failed.Requests == 1, "failed upload retried outside the approved payload reservation");
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel(); var cancelled = false;
        try { await Send(http, amount, cancellation.Token); } catch (OperationCanceledException) { cancelled = true; }
        Check(cancelled && recording.Requests == 3, "cancelled measurement started another upload");
    }
}
