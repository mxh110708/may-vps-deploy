using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Threading;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("May VPS Deploy")]
[assembly: AssemblyProduct("May VPS Deploy")]
[assembly: AssemblyCompany("May")]
[assembly: AssemblyDescription("Windows desktop for VPS deployment and maintenance")]

namespace May.VpsDeploy.Desktop
{
    internal static class DesktopApp
    {
        [STAThread]
        static int Main(string[] args)
        {
            bool diagnostic = args.Length == 2 && args[0] == "--verify-runtime";
            try
            {
                string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
                string runtime = Path.Combine(root, "runtime", "powershell", "pwsh.exe");
                var manifest = new JavaScriptSerializer().Deserialize<RuntimeManifest>(File.ReadAllText(Path.Combine(root, "desktop-runtime.json")));
                if (manifest == null || manifest.schema_version != 1 || manifest.files == null) throw new InvalidDataException();
                foreach (var file in manifest.files)
                {
                    string path = CheckedPath(root, file.path);
                    if (!File.Exists(path) || Hash(path) != file.sha256) throw new InvalidDataException();
                }
                if (diagnostic)
                {
                    string proof = Path.GetFullPath(args[1]);
                    string prefix = root + Path.DirectorySeparatorChar;
                    if (!proof.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
                    var probe = CreateStart(root, runtime);
                    probe.Arguments = "-NoLogo -NoProfile -STA -File " + Quote(Path.Combine(root, "scripts", "Test-DesktopRuntime.ps1")) + " -OutputPath " + Quote(proof);
                    using (var process = Process.Start(probe)) { process.WaitForExit(); return process.ExitCode; }
                }
                if (args.Length != 0) throw new ArgumentException();
                using (var mutex = new Mutex(false, "Local\\may-vps-deploy-desktop"))
                {
                    bool owned;
                    try { owned = mutex.WaitOne(0); } catch (AbandonedMutexException) { owned=true; }
                    if (!owned) { IntPtr window=FindWindow(null,"May VPS Deploy"); if(window!=IntPtr.Zero){ShowWindow(window,9);SetForegroundWindow(window);} return 0; }
                    try
                    {
                        var start = CreateStart(root, runtime);
                        start.EnvironmentVariables["MXH_VPS_DESKTOP_PARENT"] = Process.GetCurrentProcess().Id.ToString();
                        start.Arguments = "-NoLogo -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File " + Quote(Path.Combine(root, "Start-VPSDeploy.Gui.ps1"));
                        using (var process = Process.Start(start)) { process.WaitForExit(); return process.ExitCode; }
                    }
                    finally { mutex.ReleaseMutex(); }
                }
            }
            catch
            {
                if (!diagnostic) MessageBox.Show("应用文件不完整或运行环境无法启动。请重新运行正式安装包修复；私人数据会保留。", "May VPS Deploy", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 1;
            }
        }
        internal static ProcessStartInfo CreateStart(string root, string runtime)
        {
            var start = new ProcessStartInfo(runtime) { UseShellExecute=false, CreateNoWindow=true, WorkingDirectory=root };
            start.EnvironmentVariables["PATH"] = Path.Combine(root,"runtime","powershell") + ";" + Path.Combine(root,"runtime","python") + ";" + Path.Combine(root,"runtime","openssh") + ";" + Environment.GetEnvironmentVariable("PATH");
            start.EnvironmentVariables["PYTHONNOUSERSITE"] = "1";
            start.EnvironmentVariables["PYTHONDONTWRITEBYTECODE"] = "1";
            start.EnvironmentVariables["POWERSHELL_TELEMETRY_OPTOUT"] = "1";
            return start;
        }
        internal static string Quote(string value)
        {
            var result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') { result.Append('\\', slashes * 2 + 1); result.Append('"'); }
                else { result.Append('\\', slashes); result.Append(c); }
                slashes = 0;
            }
            result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
        }
        internal static string CheckedPath(string root, string relative)
        {
            if (String.IsNullOrWhiteSpace(relative) || relative.Contains("\\") || relative.Contains(":") || relative.StartsWith("/") || relative.Contains("..")) throw new InvalidDataException();
            string path = Path.GetFullPath(Path.Combine(root, relative.Replace('/',Path.DirectorySeparatorChar)));
            if (!path.StartsWith(root + Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            for (string parent = Path.GetDirectoryName(path); !String.IsNullOrEmpty(parent) && parent.StartsWith(root,StringComparison.OrdinalIgnoreCase); parent=Path.GetDirectoryName(parent))
                if (Directory.Exists(parent) && (File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
            if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException();
            return path;
        }
        internal static string Hash(string path)
        {
            using (var stream=File.OpenRead(path)) using (var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }
        internal sealed class RuntimeManifest { public int schema_version {get;set;} public List<FileDigest> files {get;set;} }
        internal sealed class FileDigest { public string path {get;set;} public string sha256 {get;set;} }
        [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr FindWindow(string className,string title);
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr window,int command);
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);
    }
}
