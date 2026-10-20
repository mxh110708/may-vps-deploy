using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
namespace May.VpsDeploy.Desktop
{
    internal static class CleanupUpdate
    {
        static int Main(string[] args)
        {
            try
            {
                if(args.Length!=2) return 1;
                string root=DesktopFiles.Root(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,".."));
                string stage=DesktopFiles.Root(args[0]);
                if(!stage.StartsWith(Path.Combine(root,".tmp")+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) || !Regex.IsMatch(Path.GetFileName(stage),"^app-update-[0-9a-f]{32}$")) return 1;
                int pid=int.Parse(args[1]);
                try{using(var parent=Process.GetProcessById(pid)){if(!parent.WaitForExit(120000)) return 1;}}catch(ArgumentException){}
                foreach(string directory in Directory.GetDirectories(stage,"*",SearchOption.AllDirectories)) if((File.GetAttributes(directory)&FileAttributes.ReparsePoint)!=0) return 1;
                Directory.Delete(stage,true);
                return 0;
            }catch{return 1;}
        }
    }
}
