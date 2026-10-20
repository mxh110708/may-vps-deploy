using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class HostTrust(ArchiveStore store)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    public static HostIdentity Identity(string host, int port, string algorithm, byte[] key) => new(host, port, algorithm, "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('='), false);
    private string FilePath => store.Paths.Resolve("private/ssh-hosts.dotnet.json");
    public bool IsTrusted(HostIdentity identity)
    {
        var hosts = File.Exists(FilePath) ? ArchiveStore.ReadJson(FilePath) : new JsonObject();
        var id = ArchiveStore.Digest(Encoding.UTF8.GetBytes(identity.Host));
        if (!hosts.ContainsKey(id)) return false;
        if (hosts.Text(id) == identity.Sha256Fingerprint) return true;
        throw new OperationException("SSH 主机身份与已保存记录不同，连接已停止。", code: "HostIdentityChanged", nextAction: "若刚重装系统，请通过服务商控制台独立核对新身份；不要直接覆盖旧记录。");
    }
    public Task<bool> AcceptAsync(string host, int port, string algorithm, byte[] key, IUserInteraction user, CancellationToken token) => ConfirmAsync(Identity(host, port, algorithm, key), user, token);
    public async Task<bool> ConfirmAsync(HostIdentity identity, IUserInteraction user, CancellationToken token)
    {
        if (IsTrusted(identity)) return true;
        // Human confirmation runs outside SSH key exchange and outside this gate.
        if (!await user.ConfirmHostAsync(identity, token)) return false;
        await gate.WaitAsync(token);
        try
        {
            token.ThrowIfCancellationRequested();
            if (IsTrusted(identity)) return true;
            var hosts = File.Exists(FilePath) ? ArchiveStore.ReadJson(FilePath) : new JsonObject();
            hosts[ArchiveStore.Digest(Encoding.UTF8.GetBytes(identity.Host))] = identity.Sha256Fingerprint;
            ArchiveStore.WriteJson(FilePath, hosts); return true;
        }
        finally { gate.Release(); }
    }
}
