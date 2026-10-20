using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Windows;

public sealed class WindowsSecretProtector : ISecretProtector
{
    // Credentials use one May format, bound to the current Windows user.
    private static readonly byte[] Entropy = System.Text.Encoding.UTF8.GetBytes("May.VPSDeploy.Credentials.v1");
    public string Format => "WindowsCurrentUser.May.dotnet.v1";
    public byte[] Protect(ReadOnlySpan<byte> data) { var bytes = data.ToArray(); try { return ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser); } finally { CryptographicOperations.ZeroMemory(bytes); } }
    public byte[] Unprotect(ReadOnlySpan<byte> data) { var bytes = data.ToArray(); try { return ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.CurrentUser); } finally { CryptographicOperations.ZeroMemory(bytes); } }
}

public sealed class WindowsManagedKeyAccess : IPrivateKeyAccess
{
    public void PrepareManagedCopy(string path)
    {
        SafePath.CheckLinks(path);
        // Protect only the app-managed copy, including a previous interrupted preparation.
        // Updating the DACL does not require changing the file owner or elevated privileges.
        var user = WindowsIdentity.GetCurrent().User ?? throw new OperationException("无法识别当前 Windows 用户。");
        var access = new FileSecurity(); access.SetAccessRuleProtection(true, false);
        access.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(access);
    }
}

public static class WindowsPrivateDirectoryAccess
{
    public static void Prepare(string directory)
    {
        SafePath.CheckLinks(directory);
        if (Directory.EnumerateFileSystemEntries(directory).Any()) throw new OperationException("目标目录已有内容，未修改目录权限。");
        var user = WindowsIdentity.GetCurrent().User ?? throw new OperationException("无法识别当前 Windows 用户。");
        var access = new DirectorySecurity(); access.SetAccessRuleProtection(true, false);
        access.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(access);
    }
}
