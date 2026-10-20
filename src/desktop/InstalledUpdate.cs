using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace May.VpsDeploy.Desktop
{
    internal sealed class UpdateJob
    {
        public string ProjectRoot {get;set;}
        public string Stage {get;set;}
        public string Version {get;set;}
        public int ParentPid {get;set;}
        public int LauncherPid {get;set;}
        public string ParentStarted {get;set;}
        public string LauncherStarted {get;set;}
        public string InstallerSha256 {get;set;}
        public string ManifestSha256 {get;set;}
        public string CurrentManifestSha256 {get;set;}
    }
    internal static class InstalledUpdate
    {
        [STAThread]
        static int Main(string[] args)
        {
            bool started=false;
            string stage=null;
            try
            {
                if(args.Length!=1) throw new InvalidDataException();
                string jobPath=Path.GetFullPath(args[0]);
                stage=DesktopFiles.Root(AppDomain.CurrentDomain.BaseDirectory);
                if(!Regex.IsMatch(Path.GetFileName(stage),"^app-update-[0-9a-f]{32}$") || jobPath!=Path.Combine(stage,"update-job.private.json")) throw new InvalidDataException();
                var job=new JavaScriptSerializer().Deserialize<UpdateJob>(File.ReadAllText(jobPath));
                string root=DesktopFiles.Root(job.ProjectRoot);
                if(job.Stage!=stage || !stage.StartsWith(Path.Combine(root,".tmp")+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) || !Regex.IsMatch(job.Version??"","^\\d+\\.\\d+\\.\\d+$")) throw new InvalidDataException();
                string setup=Path.Combine(stage,"may-vps-deploy-v"+job.Version+"-windows-amd64-setup.exe");
                string nextPath=Path.Combine(stage,"may-vps-deploy-v"+job.Version+"-windows-amd64.files.json");
                if(DesktopFiles.Hash(setup)!=job.InstallerSha256 || DesktopFiles.Hash(nextPath)!=job.ManifestSha256) throw new InvalidDataException();
                Wait(job.ParentPid,job.ParentStarted,Path.Combine(root,"runtime","powershell","pwsh.exe"));
                Wait(job.LauncherPid,job.LauncherStarted,Path.Combine(root,"May-VPS-Deploy.exe"));
                string oldPath=Path.Combine(root,"application-files.json");
                if(DesktopFiles.Hash(oldPath)!=job.CurrentManifestSha256) throw new InvalidDataException();
                var old=DesktopFiles.Read(oldPath);
                var next=DesktopFiles.CheckInstall(root,nextPath);
                if(next.version!=job.Version || new Version(next.version)<=new Version(old.version)) throw new InvalidDataException();
                var start=new ProcessStartInfo(setup) {UseShellExecute=false,CreateNoWindow=false,WindowStyle=ProcessWindowStyle.Normal,WorkingDirectory=stage};
                start.Arguments="/SP- /SILENT /NORESTART /NOCLOSEAPPLICATIONS /NORESTARTAPPLICATIONS /DIR="+Quote(root);
                started=true;
                using(var process=Process.Start(start))
                {
                    if(!process.WaitForExit(600000)) throw new InvalidOperationException();
                    if(process.ExitCode!=0) throw new InvalidOperationException();
                }
                if(DesktopFiles.Hash(oldPath)!=job.ManifestSha256) throw new InvalidDataException();
                DesktopFiles.VerifyInstalled(root,next);
                var names=next.files.Select(file=>file.path).ToArray();
                foreach(var file in old.files)
                {
                    if(names.Contains(file.path,StringComparer.OrdinalIgnoreCase)) continue;
                    string obsolete=DesktopFiles.PathFor(root,file.path);
                    if(File.Exists(obsolete)) {if(DesktopFiles.Hash(obsolete)!=file.sha256) throw new InvalidDataException();File.Delete(obsolete);}
                }
#if DESKTOP_TEST
                File.WriteAllText(Path.Combine(root,"private","update-test-completed.txt"),job.Version);
#endif
                var restart=new ProcessStartInfo(Path.Combine(root,"May-VPS-Deploy.exe")) {UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root};
#if DESKTOP_TEST
                restart.Arguments="--verify-runtime "+Quote(Path.Combine(root,".tmp","update-restart-proof.json"));
#endif
                Process.Start(restart);
                // This helper is locked until exit. A short native child removes only this stage afterwards.
                var cleanup=new ProcessStartInfo(Path.Combine(root,"app-helpers","CleanupUpdate.exe")) {UseShellExecute=false,CreateNoWindow=true};
                cleanup.Arguments=Quote(stage)+" "+Process.GetCurrentProcess().Id;
                Process.Start(cleanup);
                return 0;
            }
            catch
            {
#if !DESKTOP_TEST
                MessageBox.Show(started?"更新未完成。私人数据保留；本次材料留在应用 .tmp 中，请处理后重试。":"更新尚未开始，原应用和私人数据保留。请重新打开应用后重试。","May VPS Deploy 更新",MessageBoxButtons.OK,MessageBoxIcon.Error);
#endif
                return 1;
            }
        }
        static void Wait(int pid,string started,string executable)
        {
            if(pid<=0) return;
            Process process;
            try {process=Process.GetProcessById(pid);} catch(ArgumentException) {return;}
            using(process)
            {
                if(process.HasExited) return;
                if(process.StartTime.ToUniversalTime().ToString("o")!=started || !String.Equals(process.MainModule.FileName,executable,StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
                if(!process.WaitForExit(120000)) throw new InvalidOperationException();
            }
        }
        static string Quote(string value) {return "\""+value.Replace("\"","\\\"")+"\"";}
    }
}
