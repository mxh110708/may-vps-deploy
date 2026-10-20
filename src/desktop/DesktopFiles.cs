using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web.Script.Serialization;

namespace May.VpsDeploy.Desktop
{
    internal sealed class AppFile { public string path {get;set;} public string sha256 {get;set;} }
    internal sealed class AppFiles { public int schema_version {get;set;} public string version {get;set;} public List<AppFile> files {get;set;} }
    internal static class DesktopFiles
    {
        internal static string Root(string path)
        {
            string root=Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
            if(root.Length<4 || String.Equals(root,Path.GetPathRoot(root).TrimEnd(Path.DirectorySeparatorChar),StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            for(string parent=root;!String.IsNullOrEmpty(parent);parent=Path.GetDirectoryName(parent))
                if(Directory.Exists(parent) && (File.GetAttributes(parent) & FileAttributes.ReparsePoint)!=0) throw new InvalidDataException();
            return root;
        }
        internal static string Hash(string path)
        {
            using(var stream=File.OpenRead(path)) using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
        }
        internal static string PathFor(string root,string relative)
        {
            if(String.IsNullOrWhiteSpace(relative) || relative.Contains("\\") || relative.Contains(":") || relative.StartsWith("/") || relative.Contains("..")) throw new InvalidDataException();
            string path=Path.GetFullPath(Path.Combine(root,relative.Replace('/',Path.DirectorySeparatorChar)));
            if(!path.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            for(string parent=Path.GetDirectoryName(path);parent!=null && parent.StartsWith(root,StringComparison.OrdinalIgnoreCase);parent=Path.GetDirectoryName(parent))
                if(Directory.Exists(parent) && (File.GetAttributes(parent) & FileAttributes.ReparsePoint)!=0) throw new InvalidDataException();
            if(File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint)!=0) throw new InvalidDataException();
            return path;
        }
        internal static AppFiles Read(string path)
        {
            if(new FileInfo(path).Length>2097152) throw new InvalidDataException();
            var manifest=new JavaScriptSerializer().Deserialize<AppFiles>(File.ReadAllText(path));
            Version parsed;
            if(manifest==null || manifest.schema_version!=1 || !Version.TryParse(manifest.version,out parsed) || manifest.files==null || manifest.files.Count<1 || manifest.files.Count>2500) throw new InvalidDataException();
            var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var file in manifest.files)
            {
                if(file==null || !seen.Add(file.path) || !System.Text.RegularExpressions.Regex.IsMatch(file.sha256??"","^[0-9a-f]{64}$")) throw new InvalidDataException();
                string normalized="/"+file.path.ToLowerInvariant()+"/";
                foreach(string forbidden in new[]{"/private/","/.git/","/.cache/","/.tmp/","/logs/","/state/","/data/","/exports/"}) if(normalized.Contains(forbidden)) throw new InvalidDataException();
                if(file.path.EndsWith(".local.json",StringComparison.OrdinalIgnoreCase) || file.path.EndsWith(".private.json",StringComparison.OrdinalIgnoreCase) || file.path.EndsWith(".private.txt",StringComparison.OrdinalIgnoreCase) || file.path.EndsWith(".pem",StringComparison.OrdinalIgnoreCase) || file.path.EndsWith(".key",StringComparison.OrdinalIgnoreCase) || file.path=="installation.json" || file.path=="application-files.json") throw new InvalidDataException();
                PathFor(Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar),file.path);
            }
            return manifest;
        }
        internal static AppFiles CheckInstall(string root,string newManifest)
        {
            root=Root(root);
            var next=Read(newManifest);
            var oldNames=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string oldPath=Path.Combine(root,"application-files.json");
            if(File.Exists(oldPath))
            {
                if(!File.Exists(Path.Combine(root,"installation.json"))) throw new InvalidDataException();
                var installation=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(root,"installation.json")));
                if(installation==null || !installation.ContainsKey("app_id") || !Object.Equals(installation["app_id"],"may-vps-deploy-desktop")) throw new InvalidDataException();
                var old=Read(oldPath);
                if(new Version(next.version)<new Version(old.version)) throw new InvalidDataException();
                foreach(var file in old.files)
                {
                    string path=PathFor(root,file.path);
                    if(!File.Exists(path) || Hash(path)!=file.sha256) throw new InvalidDataException();
                    oldNames.Add(file.path);
                }
            }
            else if(Directory.Exists(root))
            {
                foreach(string entry in Directory.GetFileSystemEntries(root))
                {
                    string name=Path.GetFileName(entry);
                    if(Directory.Exists(entry) && new[]{"private",".cache",".tmp",".test-output"}.Contains(name,StringComparer.OrdinalIgnoreCase)) continue;
                    if(File.Exists(entry) && new[]{"archive-location.private.json","archive-location.lock"}.Contains(name,StringComparer.OrdinalIgnoreCase)) continue;
                    if(Directory.Exists(entry) && name.Equals("config",StringComparison.OrdinalIgnoreCase))
                    {
                        foreach(string local in Directory.GetFileSystemEntries(entry)) if(!File.Exists(local) || !local.EndsWith(".local.json",StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
                        continue;
                    }
                    throw new InvalidDataException();
                }
            }
            foreach(var file in next.files)
            {
                string path=PathFor(root,file.path);
                if((File.Exists(path)||Directory.Exists(path)) && !oldNames.Contains(file.path)) throw new InvalidDataException();
            }
            return next;
        }
        internal static void VerifyInstalled(string root,AppFiles manifest)
        {
            foreach(var file in manifest.files) { string path=PathFor(root,file.path); if(!File.Exists(path) || Hash(path)!=file.sha256) throw new InvalidDataException(); }
        }
    }
}
