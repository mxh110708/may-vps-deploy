using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Mxh.VpsDeploy.Core;
using Renci.SshNet;

namespace Mxh.VpsDeploy.Infrastructure;

public sealed class SshSessionFactory(ArchiveStore store, TimeSpan? connectionTimeout = null) : IRemoteSessionFactory
{
    private readonly HostTrust trust = new(store);
    public async Task<IRemoteSession> OpenAsync(SshEndpoint endpoint, IUserInteraction interaction, CancellationToken cancellationToken)
    {
        if (endpoint.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(endpoint.Host) || !Regex.IsMatch(endpoint.User, "^[a-z_][a-z0-9_-]{0,31}$")) throw new OperationException("SSH 连接参数无效。");
        return await Task.Run(async () =>
        {
            PrivateKeyFile? key = null;
            var methods = new List<AuthenticationMethod>();
            if (endpoint.KeyPath != null)
            {
                SafePath.CheckLinks(endpoint.KeyPath);
                try { key = string.IsNullOrEmpty(endpoint.KeyPassphrase) ? new PrivateKeyFile(endpoint.KeyPath) : new PrivateKeyFile(endpoint.KeyPath, endpoint.KeyPassphrase); }
                catch (Renci.SshNet.Common.SshPassPhraseNullOrEmptyException) { throw new KeyPassphraseRequiredException(); }
                methods.Add(new PrivateKeyAuthenticationMethod(endpoint.User, key));
            }
            if (endpoint.Password != null) methods.Add(new PasswordAuthenticationMethod(endpoint.User, endpoint.Password));
            if (methods.Count == 0) throw new OperationException("请提供 SSH 密钥或密码。");
            try
            {
                // At most one identity probe followed by one authenticated connection.
                // Reject unknown keys immediately; ask the human after that connection ends.
                for (var attempt = 0; attempt < 2; attempt++)
                {
                    var connection = new ConnectionInfo(endpoint.Host, endpoint.Port, endpoint.User, methods.ToArray()) { Timeout = connectionTimeout ?? TimeSpan.FromSeconds(20) };
                    var ssh = new SshClient(connection); var sftp = new SftpClient(connection);
                    HostIdentity? unknown = null; OperationException? identityFailure = null;
                    bool Accept(byte[] hostKey, string algorithm)
                    {
                        var identity = HostTrust.Identity(endpoint.Host, endpoint.Port, algorithm, hostKey);
                        try { if (trust.IsTrusted(identity)) return true; unknown = identity; }
                        catch (Exception error) { identityFailure = SafeFailures.Describe(error); }
                        return false;
                    }
                    ssh.HostKeyReceived += (_, e) => e.CanTrust = Accept(e.HostKey, e.HostKeyName);
                    sftp.HostKeyReceived += (_, e) => e.CanTrust = Accept(e.HostKey, e.HostKeyName);
                    try
                    {
                        await ssh.ConnectAsync(cancellationToken);
                        await sftp.ConnectAsync(cancellationToken);
                        return new SshRemoteSession(ssh, sftp, key);
                    }
                    catch (Exception error)
                    {
                        ssh.Dispose(); sftp.Dispose();
                        if (identityFailure != null) throw identityFailure;
                        if (error is OperationCanceledException) throw;
                        if (unknown == null || attempt != 0) throw TransportFailures.Describe(error);
                    }
                    if (!await trust.ConfirmAsync(unknown!, interaction, cancellationToken)) throw new OperationCanceledException(cancellationToken);
                }
                throw new OperationException("未能建立已信任的 SSH 连接。", code: "SshIdentityProbeFailed");
            }
            catch { key?.Dispose(); throw; }
        }, cancellationToken);
    }
}

internal sealed class SshRemoteSession(SshClient ssh, SftpClient sftp, PrivateKeyFile? key) : IRemoteSession
{
    public async Task<CommandResult> RunAsync(string command, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            using var remote = ssh.CreateCommand(command); remote.CommandTimeout = timeout;
            await remote.ExecuteAsync(cancellationToken);
            return new(remote.ExitStatus ?? -1, remote.Result, remote.Error);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) { throw TransportFailures.Describe(error, "SSH 命令"); }
    }
    public async Task<CommandResult> RunScriptAsync(string payload, TimeSpan timeout, bool mutating, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var created = await RunAsync("umask 077; mktemp -d /tmp/mxh-vps.XXXXXXXXXX", TimeSpan.FromSeconds(30), cancellationToken);
        created.RequireSuccess("无法建立远端任务临时目录。");
        var directory = created.Output.Trim();
        if (!Regex.IsMatch(directory, @"^/tmp/mxh-vps\.[A-Za-z0-9]{10}$")) throw new OperationException("远端临时目录返回异常。");
        var script = directory + "/operation.sh";
        try
        {
            var bytes = Encoding.UTF8.GetBytes(payload.Replace("\r\n", "\n").Replace('\r', '\n'));
            using var stream = new MemoryStream(bytes);
            // SSH.NET expects chmod-style digits (600), not the numeric permission bits (0x180).
            try { await Task.Run(() => sftp.UploadFile(stream, script, false), cancellationToken); sftp.ChangePermissions(script, 600); }
            catch (OperationCanceledException) { throw; }
            catch (Exception error) { throw TransportFailures.Describe(error, "SFTP 上传"); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            cancellationToken.ThrowIfCancellationRequested();
            // Once a mutation starts, finish the remote step before honoring UI cancellation.
            // Disconnecting a channel does not establish whether a remote write happened.
            return await RunAsync("bash " + ShellQuote(script), timeout, mutating ? CancellationToken.None : cancellationToken);
        }
        finally
        {
            try { await RunAsync("rm -f -- " + ShellQuote(script) + "; rmdir -- " + ShellQuote(directory), TimeSpan.FromSeconds(30), CancellationToken.None); }
            catch { /* A connection loss is reported by the caller as requiring recovery. */ }
        }
    }
    public async Task<byte[]> ReadFileAsync(string absolutePath, CancellationToken cancellationToken)
    {
        ValidateRemotePath(absolutePath);
        try { return await Task.Run(() => { using var data = new MemoryStream(); sftp.DownloadFile(absolutePath, data); return data.ToArray(); }, cancellationToken); }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) { throw TransportFailures.Describe(error, "SFTP 读取"); }
    }
    public async Task DownloadAsync(string absolutePath, string destination, CancellationToken cancellationToken)
    {
        ValidateRemotePath(absolutePath); SafePath.CheckLinks(destination);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var temporary = destination + ".download-" + Guid.NewGuid().ToString("N");
        try
        {
            await Task.Run(() => { using var file = new FileStream(temporary, FileMode.CreateNew); sftp.DownloadFile(absolutePath, file); file.Flush(true); }, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested(); SafePath.CheckLinks(destination); File.Move(temporary, destination, false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) { throw TransportFailures.Describe(error, "SFTP 下载"); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public async Task<string> UploadTemporaryFileAsync(string source, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); SafePath.CheckLinks(source);
        using var stream = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > 1073741824) throw new OperationException("内置内核包大小无效。");
        var created = await RunAsync("umask 077; mktemp -d /tmp/mxh-vps.XXXXXXXXXX", TimeSpan.FromSeconds(30), cancellationToken);
        created.RequireSuccess("无法建立内核上传临时目录。");
        var directory = created.Output.Trim();
        if (!Regex.IsMatch(directory, @"^/tmp/mxh-vps\.[A-Za-z0-9]{10}$")) throw new OperationException("内核上传目录返回异常。");
        var target = directory + "/kernel.deb";
        var priorTimeout = sftp.OperationTimeout; sftp.OperationTimeout = TimeSpan.FromSeconds(60);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); deadline.CancelAfter(TimeSpan.FromMinutes(15));
        try
        {
            await Task.Run(() => sftp.UploadFile(stream, target, false, _ => deadline.Token.ThrowIfCancellationRequested()), deadline.Token);
            sftp.ChangePermissions(target, 600); deadline.Token.ThrowIfCancellationRequested(); return target;
        }
        catch (Exception error)
        {
            try { await RunAsync("rm -f -- " + ShellQuote(target) + "; rmdir -- " + ShellQuote(directory), TimeSpan.FromSeconds(30), CancellationToken.None); } catch { }
            if (error is OperationCanceledException && !cancellationToken.IsCancellationRequested) throw new OperationException("内核包上传超过 15 分钟，尚未开始安装。", code: "KernelUploadTimeout");
            if (error is OperationCanceledException) throw;
            throw TransportFailures.Describe(error, "SFTP 内核包上传");
        }
        finally { sftp.OperationTimeout = priorTimeout; }
    }
    public static string ShellQuote(string value) => "'" + value.Replace("'", "'\"'\"'") + "'";
    private static void ValidateRemotePath(string path)
    {
        if (!path.StartsWith('/') || path.Contains('\0') || path.Contains('\r') || path.Contains('\n') || path.Split('/').Contains("..")) throw new OperationException("远端文件路径无效。");
    }
    public ValueTask DisposeAsync() { ssh.Dispose(); sftp.Dispose(); key?.Dispose(); return ValueTask.CompletedTask; }
}
