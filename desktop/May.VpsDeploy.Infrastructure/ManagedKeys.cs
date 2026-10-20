using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Infrastructure;

public sealed class ManagedKeys(IPrivateKeyAccess access) : IManagedKeyStore
{
    public string Prepare(string directory, string source, string? passphrase = null)
    {
        Directory.CreateDirectory(directory); var target = SafePath.Resolve(directory, "id_vps_management");
        if (File.Exists(target))
        {
            // A previous ACL failure can leave the private copy without its public file.
            // Validate and protect that same key before completing it; never generate a replacement.
            using (var check = Open(target, passphrase)) { }
            access.PrepareManagedCopy(target); ValidateAndWritePublic(target, passphrase); return target;
        }
        if (source != "")
        {
            SafePath.CheckLinks(source); if (!File.Exists(source)) throw new OperationException("SSH 私钥不存在。");
            // Read and validate the source before creating an app-owned copy.
            using (var check = Open(source, passphrase)) { }
            File.Copy(source, target, false); access.PrepareManagedCopy(target); ValidateAndWritePublic(target, passphrase); return target;
        }
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(false);
        using var encoded = new MemoryStream();
        WriteString(encoded, Encoding.ASCII.GetBytes("ecdsa-sha2-nistp256")); WriteString(encoded, Encoding.ASCII.GetBytes("nistp256"));
        WriteString(encoded, [4, .. parameters.Q.X!, .. parameters.Q.Y!]);
        ArchiveStore.AtomicWrite(target, Encoding.ASCII.GetBytes(key.ExportECPrivateKeyPem())); access.PrepareManagedCopy(target);
        ArchiveStore.AtomicWrite(target + ".pub", Encoding.ASCII.GetBytes("ecdsa-sha2-nistp256 " + Convert.ToBase64String(encoded.ToArray()) + " May-VPS-Deploy\n"));
        return target;
    }
    private static void ValidateAndWritePublic(string path, string? passphrase)
    {
        using var key = Open(path, passphrase);
        var data = key.HostKeyAlgorithms.First().Data;
        var nameLength = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(0, 4));
        var name = Encoding.ASCII.GetString(data, 4, nameLength);
        var publicText = name + " " + Convert.ToBase64String(data) + " May-VPS-Deploy\n";
        if (File.Exists(path + ".pub"))
        {
            var saved = File.ReadAllText(path + ".pub").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (saved.Length < 2 || saved[0] != name || saved[1] != Convert.ToBase64String(data)) throw new OperationException("管理私钥与公钥不匹配，未覆盖原文件。");
        }
        else ArchiveStore.AtomicWrite(path + ".pub", Encoding.ASCII.GetBytes(publicText));
    }
    private static void WriteString(Stream stream, byte[] value)
    {
        Span<byte> length = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(length, value.Length); stream.Write(length); stream.Write(value);
    }
    private static Renci.SshNet.PrivateKeyFile Open(string path, string? passphrase)
    {
        try { return string.IsNullOrEmpty(passphrase) ? new Renci.SshNet.PrivateKeyFile(path) : new Renci.SshNet.PrivateKeyFile(path, passphrase); }
        catch (Renci.SshNet.Common.SshPassPhraseNullOrEmptyException) { throw new KeyPassphraseRequiredException(); }
    }
}
