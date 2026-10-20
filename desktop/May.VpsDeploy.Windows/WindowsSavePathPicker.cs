using System.Runtime.InteropServices;
using May.VpsDeploy.Core;

namespace May.VpsDeploy.Windows;

// Common Item Dialog returns a filesystem path. Creation/replacement belongs to
// the reviewed publisher, never to this Windows-only adapter.
public static class WindowsSavePathPicker
{
    public static string? Select(nint owner, string extension, string? initialPath = null)
    {
        if (extension is not (".json" or ".yaml")) throw new OperationException("配置文件类型无效。");
        var native = Activator.CreateInstance(Type.GetTypeFromCLSID(new("C0B4E2F3-BA21-4773-8DBA-335EC946EB8B"), true)!)!;
        IShellItem? item = null;
        try
        {
            var dialog = (IFileDialog)native;
            dialog.GetOptions(out var options);
            // FORCEFILESYSTEM | PATHMUSTEXIST | NOCHANGEDIR | NOTESTFILECREATE |
            // DONTADDTORECENT. The app's review supplies replacement approval.
            dialog.SetOptions((options | 0x40 | 0x800 | 0x8 | 0x10000 | 0x02000000) & ~0x2u);
            dialog.SetFileTypes(1, [new() { Name = extension == ".yaml" ? "Clash YAML 配置" : "sing-box JSON 配置", Pattern = extension == ".yaml" ? "*.yaml;*.yml" : "*.json" }]);
            dialog.SetDefaultExtension(extension[1..]); dialog.SetTitle("选择导出位置"); dialog.SetOkButtonLabel("选择");
            if (!string.IsNullOrEmpty(initialPath) && Path.IsPathFullyQualified(initialPath))
            {
                var directory = Path.GetDirectoryName(initialPath)!; SafePath.CheckLinks(directory);
                var iid = typeof(IShellItem).GUID; Marshal.ThrowExceptionForHR(SHCreateItemFromParsingName(directory, 0, ref iid, out var folder));
                try { dialog.SetFolder(folder); } finally { Marshal.FinalReleaseComObject(folder); }
                dialog.SetFileName(Path.GetFileName(initialPath));
            }
            else dialog.SetFileName(extension == ".yaml" ? "Clash-General.yaml" : "sing-box-general.json");
            var result = dialog.Show(owner); if (result == unchecked((int)0x800704C7)) return null; Marshal.ThrowExceptionForHR(result);
            dialog.GetResult(out item); item.GetDisplayName(0x80058000, out var path); return path;
        }
        finally { if (item != null) Marshal.FinalReleaseComObject(item); Marshal.FinalReleaseComObject(native); }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHCreateItemFromParsingName(string path, nint bindContext, ref Guid iid, [MarshalAs(UnmanagedType.Interface)] out IShellItem item);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FilterSpec
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        [MarshalAs(UnmanagedType.LPWStr)] public string Pattern;
    }
    [ComImport, Guid("42F85136-DB7E-439C-85F1-E4075D135FC8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileDialog
    {
        [PreserveSig] int Show(nint owner);
        void SetFileTypes(uint count, [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] FilterSpec[] filters);
        void SetFileTypeIndex(uint index);
        void GetFileTypeIndex(out uint index);
        void Advise(nint events, out uint cookie);
        void Unadvise(uint cookie);
        void SetOptions(uint options);
        void GetOptions(out uint options);
        void SetDefaultFolder(IShellItem item);
        void SetFolder(IShellItem item);
        void GetFolder(out IShellItem item);
        void GetCurrentSelection(out IShellItem item);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string name);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string name);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
        void GetResult(out IShellItem item);
        void AddPlace(IShellItem item, uint location);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string extension);
        void Close(int result);
        void SetClientGuid(ref Guid guid);
        void ClearClientData();
        void SetFilter(nint filter);
    }
    [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        void BindToHandler(nint bindContext, ref Guid handler, ref Guid iid, out nint result);
        void GetParent(out IShellItem parent);
        void GetDisplayName(uint displayName, [MarshalAs(UnmanagedType.LPWStr)] out string name);
        void GetAttributes(uint mask, out uint attributes);
        void Compare(IShellItem item, uint hints, out int order);
    }
}
