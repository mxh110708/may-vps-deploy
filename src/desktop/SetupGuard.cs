using System;
namespace May.VpsDeploy.Desktop
{
    internal static class SetupGuard
    {
        static int Main(string[] args)
        {
            if(args.Length!=2) return 1;
            try { DesktopFiles.CheckInstall(args[0],args[1]); return 0; }
            catch { return 1; }
        }
    }
}
