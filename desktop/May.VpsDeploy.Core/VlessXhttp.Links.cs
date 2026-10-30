using System.Text.Json.Nodes;

namespace May.VpsDeploy.Core;

public static partial class VlessXhttp
{
    public static JsonObject DownloadFromXray(JsonObject d)
    {
        Only(d,"address","port","network","security","tlsSettings","realitySettings","xhttpSettings");
        if(d.Text("network")!="xhttp"||d.Text("security") is not ("tls" or "reality")||d["xhttpSettings"] is not JsonObject x)throw new OperationException("下载设置需要明确的 XHTTP、地址和 TLS／Reality 身份。");
        Only(x,"host","path","mode","extra");var settings=d[d.Text("security")=="tls"?"tlsSettings":"realitySettings"] as JsonObject??throw new OperationException("下载设置缺少传输安全身份。");
        Only(settings,"serverName","alpn","fingerprint","allowInsecure","publicKey","password","shortId","minVersion","maxVersion");
        if(settings.Flag("allowInsecure"))throw new OperationException("下载设置不能跳过证书验证。");
        var tls=new JsonObject{["enabled"]=true,["server_name"]=settings.Text("serverName")};
        if(settings["alpn"]!=null)tls["alpn"]=settings["alpn"]!.DeepClone();
        if(settings.Text("fingerprint")!="")tls["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]=settings.Text("fingerprint")};
        if(settings["minVersion"]!=null)tls["min_version"]=settings["minVersion"]!.DeepClone();if(settings["maxVersion"]!=null)tls["max_version"]=settings["maxVersion"]!.DeepClone();
        if(d.Text("security")=="reality")tls["reality"]=new JsonObject{["enabled"]=true,["public_key"]=settings.Text("publicKey",settings.Text("password")),["short_id"]=settings.Text("shortId")};
        var t=new JsonObject{["type"]="xhttp",["path"]=x.Text("path","/"),["host"]=x.Text("host"),["mode"]=x.Text("mode","auto")};if(x["extra"]!=null)t["extra"]=x["extra"]!.DeepClone();
        // A temporary identity only reuses transport validation; download
        // settings carry no separate VLESS user and never retain this UUID.
        var n=CanonicalNative(new JsonObject{["type"]="vless",["tag"]="download",["server"]=d.Text("address"),["server_port"]=d.Number("port"),["uuid"]=Guid.NewGuid().ToString(),["tls"]=tls,["transport"]=t},"download");
        return new JsonObject{["server"]=n["server"]!.DeepClone(),["server_port"]=n["server_port"]!.DeepClone(),["tls"]=n["tls"]!.DeepClone(),["transport"]=n["transport"]!.DeepClone()};
    }
    private static JsonObject DownloadToXray(JsonObject down)
    {
        var tls=down["tls"]!.AsObject();Only(tls,"enabled","server_name","alpn","utls","reality","min_version","max_version");var reality=tls.Flag("reality.enabled");var settings=new JsonObject{["serverName"]=tls.Text("server_name"),["alpn"]=tls["alpn"]?.DeepClone()??new JsonArray(Alpn(Version(down)))};
        if(tls["utls"]!=null)settings["fingerprint"]=tls.Text("utls.fingerprint");
        if(reality){settings["publicKey"]=tls.Text("reality.public_key");settings["shortId"]=tls.Text("reality.short_id");}
        if(tls["min_version"]!=null)settings["minVersion"]=tls["min_version"]!.DeepClone();if(tls["max_version"]!=null)settings["maxVersion"]=tls["max_version"]!.DeepClone();
        var t=down["transport"]!.AsObject();var x=new JsonObject{["path"]=t.Text("path"),["host"]=t.Text("host"),["mode"]=t.Text("mode","auto")};if(t["extra"]!=null)x["extra"]=t["extra"]!.DeepClone();
        return new JsonObject{["address"]=down.Text("server"),["port"]=down.Number("server_port"),["network"]="xhttp",["security"]=reality?"reality":"tls",[reality?"realitySettings":"tlsSettings"]=settings,["xhttpSettings"]=x};
    }
    public static string ShareLink(JsonObject node)
    {
        var n=RequireNative(node);var name=node.Text("name");Only(n,"type","tag","server","server_port","uuid","packet_encoding","flow","tls","transport");var tls=n["tls"]!.AsObject();Only(tls,"enabled","server_name","alpn","utls","reality");
        if(n.Text("packet_encoding","xudp")!="xudp")throw new OperationException("标准 VLESS 链接不能保留此 UDP 编码，请导出完整原生配置。");
        var t=n["transport"]!.AsObject();var extra=(t["extra"] as JsonObject??new()).DeepClone().AsObject();if(t["download_settings"] is JsonObject d)extra["downloadSettings"]=DownloadToXray(d);
        static string E(string s)=>Uri.EscapeDataString(s);var host=n.Text("server");var address=(host.Contains(':')?"["+host+"]":host)+":"+n.Number("server_port");
        var q="encryption=none&type=xhttp&security="+(tls.Flag("reality.enabled")?"reality":"tls")+"&sni="+E(tls.Text("server_name"))+"&alpn="+E(Alpn(Version(n)))+"&path="+E(t.Text("path"))+"&host="+E(t.Text("host"))+"&mode="+E(t.Text("mode","auto"));
        if(tls["utls"]!=null)q+="&fp="+E(tls.Text("utls.fingerprint"));if(tls.Flag("reality.enabled"))q+="&pbk="+E(tls.Text("reality.public_key"))+"&sid="+E(tls.Text("reality.short_id"));if(extra.Count>0)q+="&extra="+E(extra.ToJsonString());
        var link="vless://"+E(n.Text("uuid"))+"@"+address+"?"+q+"#"+E(name);
        var region=name=="Share Entry"?"Share Validation":"Share Entry";
        var fixture=new JsonObject{["Nodes"]=new JsonArray(),["Layout"]=new JsonObject{["region_groups"]=new JsonArray(region),["business_groups"]=new JsonArray()}};var preview=ClientNodeImport.Preview(link,fixture,region);
        if(preview.Accepted!=1||ArchiveStore.Fingerprint(RequireNative(preview.Rows.Single().Node!))!=ArchiveStore.Fingerprint(n))throw new OperationException("XHTTP 链接无法完整还原连接；请导出完整原生配置。");
        return link;
    }
}
