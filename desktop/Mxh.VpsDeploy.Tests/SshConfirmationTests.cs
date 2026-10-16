using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Mxh.VpsDeploy.Core;
using Mxh.VpsDeploy.Infrastructure;

internal sealed partial class BoundaryTests
{
    private async Task LocalSshConfirmation(Fixture fixture, string python)
    {
        var root = fixture.Paths.Resolve("loopback"); Directory.CreateDirectory(root);
        var script = Path.Combine(repository, "desktop/Mxh.VpsDeploy.Tests/fixtures/ssh_confirmation_server.py");
        var statsFile = Path.Combine(root, "stats.json"); var readyFile = Path.Combine(root, "ready.json");
        async Task<Process> Start()
        {
            if (File.Exists(readyFile)) File.Delete(readyFile);
            var start = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
            foreach (var arg in new[] { script, "--ready", readyFile, "--stats", statsFile, "--operations" }) start.ArgumentList.Add(arg);
            var process = Process.Start(start)!;
            try
            {
                for (var i = 0; i < 200 && !File.Exists(readyFile); i++) { if (process.HasExited) throw new Exception("Loopback fixture failed to start."); await Task.Delay(50); }
                if (!File.Exists(readyFile)) throw new Exception("Loopback fixture startup timed out.");
                return process;
            }
            catch { Stop(process); throw; }
        }
        static void Stop(Process process) { if (!process.HasExited) { process.Kill(true); process.WaitForExit(5000); } process.Dispose(); }
        var process = await Start();
        try
        {
            var endpoint = new SshEndpoint("127.0.0.1", ArchiveStore.ReadJson(readyFile).Number("port"), "fixture", null, "fixture-only");
            var factory = new SshSessionFactory(fixture.Store, TimeSpan.FromSeconds(3));
            var user = new HostTestUser(async (_, token) =>
            {
                Check(ArchiveStore.ReadJson(statsFile).Number("auth") == 0, "identity probe sent credentials before approval");
                await Task.Delay(TimeSpan.FromSeconds(6), token); return true;
            });
            await using (await factory.OpenAsync(endpoint, user, default)) { }
            Check(user.Confirmations == 1 && ArchiveStore.ReadJson(statsFile).Number("exec") == 0, "delayed confirmation failed or sent command");
            var known = new HostTestUser((_, _) => throw new Exception("Trusted host unexpectedly asked again."));
            await using (await factory.OpenAsync(endpoint, known, default)) { }
            Check(known.Confirmations == 0, "known identity requested repeated trust");
            await using (var session = await factory.OpenAsync(endpoint, known, default))
            {
                var payload = "# MXH_TRANSPORT_FIXTURE\r\nset -euo pipefail\r\nprintf 'VPSDEPLOY_SCRIPT_OK\\n'\r\n" + string.Concat(Enumerable.Repeat("# 中文节点\r\n", 4096));
                var result = await session.RunScriptAsync(payload, TimeSpan.FromSeconds(10), false, default);
                RemoteAssets.RequireMarker(result, "SCRIPT_OK");
                var stats = ArchiveStore.ReadJson(statsFile);
                Check(stats.Number("uploads") == 1 && stats.Number("chmod") == 1 && stats.Number("script_exec") == 1, "script transfer skipped upload, permissions or actual Bash execution");
                Check(stats.Number("last_mode") == 384, "remote script permissions are not owner-only 0600");
                Check(stats.Number("upload_bytes") > 32768 && !stats.Flag("upload_has_cr"), "multi-buffer UTF-8 upload changed or retained CRLF");
                Check(stats.Number("temporary_files") == 0 && stats.Number("cleanup") == 1, "successful script left temporary materials");
                var downloaded = await session.ReadFileAsync("/fixture/read-only.txt", default);
                Check(Encoding.UTF8.GetString(downloaded) == "fixture-read-only\n", "real SFTP read changed content");
                result = await session.RunScriptAsync("# MXH_TRANSPORT_FIXTURE\nprintf 'fixture-error-details\\n' >&2\nexit 7\n", TimeSpan.FromSeconds(10), true, default);
                Check(result.ExitCode == 7 && result.Error.Trim() == "fixture-error-details", "remote failure lost exit status or error channel");
                stats = ArchiveStore.ReadJson(statsFile);
                Check(stats.Number("temporary_files") == 0 && stats.Number("cleanup") == 2, "failed script left temporary materials");
                try { await session.RunScriptAsync(payload + "# DENY_PERMISSIONS\r\n", TimeSpan.FromSeconds(10), false, default); throw new Exception("SFTP permission failure accepted."); }
                catch (OperationException error) { Check(error.Code == "SftpAccessDenied", "script permission failure lost its typed cause"); }
                stats = ArchiveStore.ReadJson(statsFile);
                Check(stats.Number("script_exec") == 2 && stats.Number("temporary_files") == 0 && stats.Number("cleanup") == 3, "permission failure executed script or leaked temporary materials");
                using var canceled = new CancellationTokenSource(); canceled.Cancel();
                try { await session.RunScriptAsync(payload, TimeSpan.FromSeconds(10), false, canceled.Token); throw new Exception("Canceled script executed."); }
                catch (OperationCanceledException) { Check(ArchiveStore.ReadJson(statsFile).Number("exec") == stats.Number("exec"), "pre-canceled transport sent remote commands"); }
                var artifact = Path.Combine(root, "kernel-upload.bin"); var binary = Enumerable.Range(0, 131072).Select(n => (byte)n).ToArray(); File.WriteAllBytes(artifact, binary);
                var uploaded = await session.UploadTemporaryFileAsync(artifact, default);
                Check(uploaded.EndsWith("/kernel.deb", StringComparison.Ordinal) && (await session.ReadFileAsync(uploaded, default)).SequenceEqual(binary), "binary SFTP upload corrupted bytes or used a command argument");
                stats = ArchiveStore.ReadJson(statsFile); Check(stats.Number("last_mode") == 384, "binary kernel upload is not private 0600");
                await session.RunAsync("rm -f -- '" + uploaded + "'; rmdir -- '" + uploaded[..uploaded.LastIndexOf('/')] + "'", TimeSpan.FromSeconds(10), default);
                try { await session.UploadTemporaryFileAsync(artifact, canceled.Token); throw new Exception("Canceled binary upload started."); }
                catch (OperationCanceledException) { Check(ArchiveStore.ReadJson(statsFile).Number("uploads") == stats.Number("uploads"), "pre-canceled binary upload sent data"); }
            }
            try { await using var invalid = await factory.OpenAsync(endpoint with { Password = "wrong-fixture-only" }, known, default); throw new Exception("Wrong password accepted."); }
            catch (OperationException error) { Check(error.Code == "SshAuthenticationFailed", "authentication failure lost typed cause"); }
            var isolatedStore = new ArchiveStore(new AppPaths(Path.Combine(root, "cancelled")), new TestProtector());
            var cancel = new HostTestUser((_, _) => Task.FromResult(false));
            try { await using var canceled = await new SshSessionFactory(isolatedStore, TimeSpan.FromSeconds(3)).OpenAsync(endpoint, cancel, default); throw new Exception("Canceled host trusted."); }
            catch (OperationCanceledException) { Check(cancel.Confirmations == 1 && !File.Exists(isolatedStore.Paths.Resolve("private/ssh-hosts.dotnet.json")), "canceled trust saved"); }
            var fingerprint = ClientSchemes.SourceFingerprint(fixture.Paths.Resolve("private/ssh-hosts.dotnet.json"));
            Stop(process); process = await Start();
            endpoint = endpoint with { Port = ArchiveStore.ReadJson(readyFile).Number("port") };
            try { await using var changed = await factory.OpenAsync(endpoint, known, default); throw new Exception("Changed key accepted."); }
            catch (OperationException error) { Check(error.Code == "HostIdentityChanged", "host key change lacks explicit reason"); }
            Check(fingerprint == ClientSchemes.SourceFingerprint(fixture.Paths.Resolve("private/ssh-hosts.dotnet.json")) && ArchiveStore.ReadJson(statsFile).Number("auth") == 0, "changed host updated trust or sent credentials");
        }
        finally { Stop(process); }
    }
}

internal sealed class HostTestUser(Func<HostIdentity, CancellationToken, Task<bool>> confirmation) : IUserInteraction
{
    public int Confirmations { get; private set; }
    public Task<bool> ConfirmHostAsync(HostIdentity identity, CancellationToken token) { Confirmations++; return confirmation(identity, token); }
    public Task<bool> ConfirmAsync(UserDecision decision, CancellationToken token) => Task.FromResult(false);
    public Task<string?> SecretAsync(string title, CancellationToken token) => Task.FromResult<string?>(null);
}
