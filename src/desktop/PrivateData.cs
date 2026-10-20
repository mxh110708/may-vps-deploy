using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

namespace May.VpsDeploy.Desktop
{
    internal sealed class DataLocation { public int SchemaVersion {get;set;} public string Directory {get;set;} public string OwnerId {get;set;} public string AppRoot {get;set;} }
    // Native uninstall helper: keep is the default. External deletion requires matching ownership.
    internal static class PrivateData
    {
        internal const string LocationFile = "archive-location.private.json";
        internal const string OwnershipFile = ".may-private-directory.json";
        internal static string Location(string app)
        {
            app=DesktopFiles.Root(app);
            string file=DesktopFiles.PathFor(app,LocationFile);
            if(!File.Exists(file)) return Path.Combine(app,"private");
            var locator=Read(file); Guid id;
            if(locator.SchemaVersion!=1 || !Guid.TryParseExact(locator.OwnerId,"N",out id) || !Path.IsPathRooted(locator.Directory) || locator.Directory.StartsWith("\\\\",StringComparison.Ordinal)) throw new InvalidDataException();
            string data=DesktopFiles.Root(locator.Directory);
            if(data.Equals(app,StringComparison.OrdinalIgnoreCase) || app.StartsWith(data+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) || data.StartsWith(app+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) && !data.Equals(Path.Combine(app,"private"),StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            var owner=Read(DesktopFiles.PathFor(data,OwnershipFile));
            if(owner.SchemaVersion!=1 || owner.OwnerId!=locator.OwnerId || !DesktopFiles.Root(owner.AppRoot).Equals(app,StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
            return data;
        }
        static DataLocation Read(string path)
        {
            if(!File.Exists(path) || new FileInfo(path).Length>16384) throw new InvalidDataException();
            return new JavaScriptSerializer().Deserialize<DataLocation>(File.ReadAllText(path));
        }
        static Dictionary<string,string> Files(string data)
        {
            var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            if(!Directory.Exists(data)) return result;
            DesktopFiles.Root(data); Visit(data,result); return result;
        }
        static void Visit(string directory,Dictionary<string,string> files)
        {
            foreach(string entry in Directory.GetFileSystemEntries(directory))
            {
                if((File.GetAttributes(entry)&FileAttributes.ReparsePoint)!=0 || Path.GetFileName(entry).Equals(".git",StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException();
                if(Directory.Exists(entry)) Visit(entry,files);
                else {if((File.GetAttributes(entry)&FileAttributes.ReadOnly)!=0) throw new InvalidDataException();files.Add(entry,DesktopFiles.Hash(entry));}
            }
        }
        static int Main(string[] args)
        {
            try
            {
                if(args.Length!=2 || args[0]!="validate" && args[0]!="remove") return 1;
                string app=DesktopFiles.Root(args[1]); string data=Location(app); var files=Files(data);
                if(args[0]=="validate") return 0;
                var held=new List<FileStream>();
                try {foreach(string file in files.Keys) held.Add(new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read));}
                finally {foreach(var handle in held) handle.Dispose();}
                if(Location(app)!=data || Files(data).Count!=files.Count || files.Any(p=>DesktopFiles.Hash(p.Key)!=p.Value)) throw new InvalidDataException();
                // The whole selected directory belongs to this application; unrelated parent files stay.
                if(Directory.Exists(data)) Directory.Delete(data,true);
                return 0;
            }
            catch {return 1;}
        }
    }
}
