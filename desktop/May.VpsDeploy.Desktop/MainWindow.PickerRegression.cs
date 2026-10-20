using System.Runtime.InteropServices;
using System.Text;
using May.VpsDeploy.Core;
using May.VpsDeploy.Windows;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    // Only called by DesktopRegression in an explicit app-root with the QA marker.
    // Dialog messages are restricted to this window's own, identified popup.
    private async Task<bool> SavePathPickerRegression()
    {
        var owner = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var directory = paths.Resolve("private/picker-regression"); Directory.CreateDirectory(directory);
        async Task<string?> Pick(string path, bool cancel = false)
        {
            var respond = Task.Run(async () =>
            {
                for (var i = 0; i < 100; i++)
                {
                    await Task.Delay(80); var popup = GetLastActivePopup(owner); if (popup == owner) continue;
                    var title = new StringBuilder(256); GetWindowTextW(popup, title, title.Capacity);
                    if (title.ToString() != "选择导出位置") continue;
                    // Give the filesystem view time to initialize before selecting.
                    await Task.Delay(300); return PostMessageW(popup, cancel ? 0x0010u : 0x0111u, cancel ? 0 : 1, 0);
                }
                return false;
            });
            var selected = WindowsSavePathPicker.Select(owner, ".json", path);
            if (!await respond) throw new OperationException("隔离文件选择对话框未响应。"); return selected;
        }
        var fresh = SafePath.Resolve(directory, "new-config.json"); if (File.Exists(fresh)) throw new OperationException("隔离选择路径应为新文件。");
        if (await Pick(fresh) != fresh || File.Exists(fresh)) throw new OperationException("选择新配置位置提前创建了文件。");
        var existing = SafePath.Resolve(directory, "existing-config.json"); ArchiveStore.AtomicWrite(existing, Encoding.UTF8.GetBytes("existing fixture"));
        var before = ClientSchemes.SourceFingerprint(existing);
        if (await Pick(existing) != existing || ClientSchemes.SourceFingerprint(existing) != before) throw new OperationException("选择已有配置位置改写了文件。");
        if (await Pick(fresh, true) != null || File.Exists(fresh) || ClientSchemes.SourceFingerprint(existing) != before) throw new OperationException("取消选择位置产生了写入。");
        File.Delete(existing); Directory.Delete(directory); return true;
    }
    [DllImport("user32.dll", ExactSpelling = true)] private static extern nint GetLastActivePopup(nint owner);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] private static extern int GetWindowTextW(nint window, StringBuilder text, int count);
    [DllImport("user32.dll", ExactSpelling = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PostMessageW(nint window, uint message, nint value, nint data);
}
