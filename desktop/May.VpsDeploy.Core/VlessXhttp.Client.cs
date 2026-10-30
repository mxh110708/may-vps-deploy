using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace May.VpsDeploy.Core;

public static partial class VlessXhttp
{
    // Xray 26.3.27 names are canonical; Mihomo 1.19.32 uses a distinct schema.
    public static readonly IReadOnlyDictionary<string, string> ExtraNames = new Dictionary<string, string>
    {
        ["headers"]="headers",["xPaddingBytes"]="x-padding-bytes",["noGRPCHeader"]="no-grpc-header",
        ["xPaddingObfsMode"]="x-padding-obfs-mode",["xPaddingKey"]="x-padding-key",["xPaddingHeader"]="x-padding-header",["xPaddingPlacement"]="x-padding-placement",["xPaddingMethod"]="x-padding-method",
        ["uplinkHTTPMethod"]="uplink-http-method",["sessionPlacement"]="session-placement",["sessionKey"]="session-key",["seqPlacement"]="seq-placement",["seqKey"]="seq-key",["uplinkDataPlacement"]="uplink-data-placement",["uplinkDataKey"]="uplink-data-key",["uplinkChunkSize"]="uplink-chunk-size",
        ["scMaxEachPostBytes"]="sc-max-each-post-bytes",["scMinPostsIntervalMs"]="sc-min-posts-interval-ms",["xmux"]="reuse-settings"
    };
    private static readonly string[] ServerFields = ["noSSEHeader","scMaxBufferedPosts","scStreamUpServerSecs","serverMaxHeaderBytes"];
    private static readonly Dictionary<string,string> MuxNames = new() { ["maxConcurrency"]="max-concurrency",["maxConnections"]="max-connections",["cMaxReuseTimes"]="c-max-reuse-times",["hMaxRequestTimes"]="h-max-request-times",["hMaxReusableSecs"]="h-max-reusable-secs",["hKeepAlivePeriod"]="h-keep-alive-period" };
    private static readonly string[] RangeNames = ["xPaddingBytes","scMaxEachPostBytes","scMinPostsIntervalMs","scStreamUpServerSecs","uplinkChunkSize"];
    private static void Only(JsonObject value, params string[] keys) { if(value.Any(p=>!keys.Contains(p.Key,StringComparer.Ordinal))) throw new OperationException("XHTTP 含未识别字段，未删除或猜测转换；请核对固定版本参数。"); }
    public static string Alpn(string version) => version switch { "1.1"=>"http/1.1","3"=>"h3",_=>"h2" };
    public static string Version(JsonObject native) => native.Text("transport.http_version") is "1.1" or "2" or "3" ? native.Text("transport.http_version") : native.At("tls.alpn") is JsonArray {Count:1} a ? a[0]?.ToString() switch {"http/1.1"=>"1.1","h3"=>"3",_=>"2"}:"2";
    private static string Range(JsonNode? value)
    {
        if(value is JsonObject obj&&(obj.Count!=2||obj["from"] is not JsonValue from||!from.TryGetValue<int>(out _)||obj["to"] is not JsonValue to||!to.TryGetValue<int>(out _)))throw new OperationException("XHTTP 范围对象需要整数 from／to。");
        var text = value is JsonObject o && o.Count==2 && o.ContainsKey("from") && o.ContainsKey("to") ? o.Number("from")+"-"+o.Number("to") : value?.ToString() ?? "";
        if(!Regex.IsMatch(text,@"^\d+(?:-\d+)?$")) throw new OperationException("XHTTP 范围须为非负整数或 min-max。");
        var ends=text.Split('-').Select(s=>long.TryParse(s,NumberStyles.None,CultureInfo.InvariantCulture,out var n)?n:-1).ToArray();
        if(ends.Any(n=>n<0||n>int.MaxValue)||ends.Length==2&&ends[0]>ends[1]) throw new OperationException("XHTTP 范围次序或大小无效。");
        return text;
    }
    public static void ValidateExtra(JsonObject extra)
    {
        Only(extra,ExtraNames.Keys.Concat(ServerFields).ToArray());
        foreach(var pair in extra)
        {
            if(RangeNames.Contains(pair.Key)) { var range=Range(pair.Value);if(long.Parse(range.Split('-')[^1],CultureInfo.InvariantCulture)>16*1024*1024) throw new OperationException("XHTTP 单项范围超过 16 MiB 资源上限。"); }
            else if(pair.Key=="headers") { if(pair.Value is not JsonObject headers||headers.Count>64) throw new OperationException("XHTTP 请求头应为对象且不超过 64 项。");foreach(var h in headers){if(!Regex.IsMatch(h.Key,@"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")||h.Value is not JsonValue v||!v.TryGetValue<string>(out var text)||text.Any(c=>c=='\r'||c=='\n'||c=='\0')||new[]{"host","content-length","transfer-encoding","connection"}.Contains(h.Key.ToLowerInvariant())) throw new OperationException("XHTTP 请求头无效或覆盖了传输握手字段。");} }
            else if(pair.Key=="xmux") { if(pair.Value is not JsonObject mux) throw new OperationException("XMux 应为对象。");Only(mux,MuxNames.Keys.ToArray());foreach(var item in mux){if(item.Key=="hKeepAlivePeriod"){if(item.Value is not JsonValue v||!v.TryGetValue<int>(out _)) throw new OperationException("XMux 保活周期须为整数。");}else _=Range(item.Value);}if(mux.ContainsKey("maxConcurrency")&&mux.ContainsKey("maxConnections")&&Range(mux["maxConcurrency"]).Split('-').Any(s=>s!="0")&&Range(mux["maxConnections"]).Split('-').Any(s=>s!="0"))throw new OperationException("XMux 并发上限与连接数上限不能同时启用。"); }
            else if(pair.Key is "noGRPCHeader" or "noSSEHeader" or "xPaddingObfsMode") { if(pair.Value is not JsonValue v||!v.TryGetValue<bool>(out _))throw new OperationException("XHTTP 开关须为布尔值。"); }
            else if(pair.Key is "scMaxBufferedPosts" or "serverMaxHeaderBytes") { if(pair.Value is not JsonValue v||!v.TryGetValue<int>(out var n)||n<0)throw new OperationException("XHTTP 服务端限制须为非负整数。"); }
            else if(pair.Value is not JsonValue s||!s.TryGetValue<string>(out var text)||text.Any(char.IsControl)) throw new OperationException("XHTTP 元数据参数须为无控制字符的文本。");
        }
        foreach(var key in new[]{"sessionPlacement","seqPlacement"}) if(extra.ContainsKey(key)&&!new[]{"","path","query","header","cookie"}.Contains(extra.Text(key)))throw new OperationException("XHTTP 会话或序号位置无效。");
        if(extra["headers"] is JsonObject headerMap&&headerMap.Select(p=>p.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=headerMap.Count)throw new OperationException("XHTTP 请求头名称不能仅大小写不同而重复。");
        if(extra.ContainsKey("uplinkDataPlacement")&&!new[]{"","auto","body","header","cookie"}.Contains(extra.Text("uplinkDataPlacement")))throw new OperationException("XHTTP 上传数据位置无效。");
        if(extra.ContainsKey("xPaddingPlacement")&&!new[]{"","header","cookie","query","queryInHeader"}.Contains(extra.Text("xPaddingPlacement")))throw new OperationException("XHTTP 填充位置无效。");
        if(extra.ContainsKey("xPaddingMethod")&&!new[]{"","repeat-x","tokenish"}.Contains(extra.Text("xPaddingMethod")))throw new OperationException("XHTTP 填充方法无效。");
    }
    public static JsonObject Transport(JsonObject model) => new() { ["type"]="xhttp",["path"]=model.Text("Path"),["host"]=model.Text("Host"),["mode"]=model.Text("Mode","auto"),["http_version"]=model.Text("HTTPVersion","2"),["extra"]=model["Extra"]?.DeepClone() ?? new JsonObject(),["download_settings"]=model["DownloadSettings"]?.DeepClone() };
    public static void ValidateTransport(JsonObject t,bool reality,bool download=false)
    {
        Only(t,"type","path","host","mode","http_version","extra","download_settings");_ = Path(t.Text("path"));
        if(t.Text("type")!="xhttp"||!new[]{"","auto","stream-one","stream-up","packet-up"}.Contains(t.Text("mode"))||!new[]{"","auto","1.1","2","3"}.Contains(t.Text("http_version")))throw new OperationException("XHTTP 模式或 HTTP 版本无效。");
        var host=t.Text("host");if(host.Length>253||host.Any(c=>char.IsControl(c)||char.IsWhiteSpace(c)||"/?#@\\".Contains(c)))throw new OperationException("XHTTP Host 无效，可含端口，不能含路径或认证信息。");
        if(reality&&t.Text("http_version") is "1.1" or "3")throw new OperationException("固定 Reality XHTTP 仅适用于 HTTP/2。");
        if(t["extra"] is JsonObject extra)ValidateExtra(extra);else if(t["extra"]!=null)throw new OperationException("XHTTP extra 应为对象。");
        if(t["extra"] is JsonObject advanced&&t.Text("mode")!="packet-up"&&(advanced.Text("uplinkHTTPMethod").Equals("GET",StringComparison.OrdinalIgnoreCase)||advanced.Text("uplinkDataPlacement") is "header" or "cookie"))throw new OperationException("GET 上传或头部／Cookie 载荷需要明确选择 packet-up。");
        if(t["download_settings"] is JsonObject d)
        {
            if(download||t.Text("mode")=="stream-one")throw new OperationException("XHTTP stream-one 或嵌套下载不能分离上下行。");
            Only(d,"server","server_port","tls","transport");if(Uri.CheckHostName(d.Text("server"))==UriHostNameType.Unknown||d.Number("server_port") is <1 or >65535||d["tls"] is not JsonObject tls||!tls.Flag("enabled")||tls.Flag("insecure")||tls.Flag("disable_sni")||d["transport"] is not JsonObject dt)throw new OperationException("独立下载需要完整地址、端口、传输及验证 TLS／Reality。");
            ValidateTransport(dt,tls.Flag("reality.enabled"),true);
        }
        else if(t["download_settings"]!=null)throw new OperationException("XHTTP 下载设置应为对象。");
    }
    public static JsonObject Native(string name,string address,int port,string uuid,JsonNode options)
    {
        var tls=new JsonObject{["enabled"]=true,["server_name"]=options.Text("ServerName"),["alpn"]=new JsonArray(Alpn(options.Text("Transport.HTTPVersion","2")))};
        if(options.Text("Security")=="Reality"){tls["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]="chrome"};tls["reality"]=new JsonObject{["enabled"]=true,["public_key"]=options.Text("Reality.PublicKey"),["short_id"]=options.Text("Reality.ShortId")};}
        return CanonicalNative(new JsonObject{["type"]="vless",["tag"]=name,["server"]=address,["server_port"]=port,["uuid"]=uuid,["packet_encoding"]="xudp",["tls"]=tls,["transport"]=Transport(options["Transport"]!.AsObject())},name);
    }
    public static JsonObject CanonicalNative(JsonObject source,string name)
    {
        if(source.Text("type")!="vless"||source.Text("tag")!=name||source.Number("server_port") is <1 or >65535||Uri.CheckHostName(source.Text("server"))==UriHostNameType.Unknown||!Guid.TryParseExact(source.Text("uuid"),"D",out var id)||id==Guid.Empty||source.Text("flow")!=""||source.Flag("multiplex.enabled")||source["tls"] is not JsonObject tls||!tls.Flag("enabled")||tls.Flag("insecure")||tls.Flag("disable_sni")||tls.Flag("kernel_tx")||tls.Flag("kernel_rx")||source["transport"] is not JsonObject t)throw new OperationException("XHTTP 需要完整 VLESS 身份和验证 TLS／Reality，不能附加 Vision flow 或另一层多路复用。");
        DeploymentPlans.Domain(tls.Text("server_name"));ValidateTransport(t,tls.Flag("reality.enabled"));
        if(tls.Flag("reality.enabled")){Key(tls.Text("reality.public_key"));ShortId(tls.Text("reality.short_id"),client:true);}
        var result=source.DeepClone().AsObject();result["transport"]!["mode"]=t.Text("mode","auto");result["transport"]!["http_version"]=Version(source);result["tls"]!["alpn"]=new JsonArray(Alpn(Version(source)));
        if(tls.Flag("reality.enabled"))result["tls"]!["reality"]!["short_id"]=tls.Text("reality.short_id").ToLowerInvariant();
        var rt=result["transport"]!.AsObject();if(rt["extra"] is JsonObject {Count:0})rt.Remove("extra");if(rt["download_settings"]==null)rt.Remove("download_settings");
        if(tls["alpn"] is JsonArray a&&a.Count>0&&!a.Any(v=>v?.ToString()==Alpn(Version(source))))throw new OperationException("XHTTP HTTP 版本与 TLS ALPN 冲突。");
        if(tls.Flag("reality.enabled")&&Version(result)!="2")throw new OperationException("Reality XHTTP 需要 HTTP/2。");
        return result;
    }
    public static void CompletePair(JsonObject node)
    {
        if(!IsNode(node))return;
        if(node["sing_box"]==null&&(node.At("clash.xhttp-opts.session-table")!=null||node.At("clash.xhttp-opts.session-length")!=null)){_=RequireClash(node);return;}
        var native=RequireNative(node);node["sing_box"]=native;
        if(node["clash"]==null){try{node["clash"]=ToClash(native,node.Text("name"));}catch(OperationException){ /* Keep a native-only source; capability review explains the unavailable projection. */ }}
    }
    public static JsonObject RequireNative(JsonObject node)
    {
        var name=node.Text("name");var native=node["sing_box"] is JsonObject s?CanonicalNative(s,name):node["clash"] is JsonObject c?FromClash(c,name):throw new OperationException("缺少完整 XHTTP 客户端配置。");
        if(node["sing_box"]!=null&&node["clash"] is JsonObject paired&&ArchiveStore.Fingerprint(ToClash(native,name))!=ArchiveStore.Fingerprint(ToClash(FromClash(paired,name),name)))throw new OperationException("XHTTP 双客户端参数不一致，请重新读取完整来源。");
        return native;
    }
    private static JsonObject ClashExtra(JsonObject extra)
    {
        ValidateExtra(extra);var result=new JsonObject();
        foreach(var p in extra){if(ServerFields.Contains(p.Key))continue;if(p.Key=="xmux"){var mux=new JsonObject();foreach(var x in p.Value!.AsObject())mux[MuxNames[x.Key]]=x.Key=="hKeepAlivePeriod"?x.Value!.DeepClone():JsonValue.Create(Range(x.Value));result["reuse-settings"]=mux;}else result[ExtraNames[p.Key]]=RangeNames.Contains(p.Key)?JsonValue.Create(Range(p.Value)):p.Value!.DeepClone();}
        return result;
    }
    public static JsonObject ToClash(JsonObject source,string name)
    {
        var n=CanonicalNative(source,name);var tls=n["tls"]!.AsObject();Only(n,"type","tag","server","server_port","uuid","packet_encoding","tls","transport","flow");Only(tls,"enabled","server_name","insecure","min_version","max_version","alpn","utls","reality");
        if(n.Text("packet_encoding","xudp")!="xudp")throw new OperationException("Mihomo XHTTP 无法等价表达此 UDP 编码；请保留 May Core 原生配置。");
        if(tls.Text("min_version") is not ("" or "1.2" or "1.3")||tls.Text("max_version") is not ("" or "1.3"))throw new OperationException("Mihomo 不能等价表达此 TLS 版本限制，请保留 May Core 原生配置。");
        var t=n["transport"]!.AsObject();var x=ClashExtra(t["extra"] as JsonObject??new());x["path"]=t.Text("path");x["host"]=t.Text("host");x["mode"]=t.Text("mode","auto");
        var c=new JsonObject{["name"]=name,["type"]="vless",["server"]=n.Text("server"),["port"]=n.Number("server_port"),["uuid"]=n.Text("uuid"),["tls"]=true,["servername"]=tls.Text("server_name"),["skip-cert-verify"]=false,["alpn"]=new JsonArray(Alpn(Version(n))),["udp"]=true,["packet-encoding"]="xudp",["network"]="xhttp",["xhttp-opts"]=x};
        if(tls["utls"] is JsonObject u){Only(u,"enabled","fingerprint");if(!u.Flag("enabled"))throw new OperationException("不能转换禁用的显式 uTLS 设置。");c["client-fingerprint"]=u.Text("fingerprint");}
        if(tls["reality"] is JsonObject r){Only(r,"enabled","public_key","short_id");c["reality-opts"]=new JsonObject{["public-key"]=r.Text("public_key"),["short-id"]=r.Text("short_id")};}
        if(t["download_settings"] is JsonObject d)
        {
            var dt=d["transport"]!.AsObject();var de=dt["extra"] as JsonObject??new();var ue=t["extra"] as JsonObject??new();
            foreach(var k in ExtraNames.Keys.Where(k=>k is not ("headers" or "xmux")))if(!JsonNode.DeepEquals(de[k],ue[k]))throw new OperationException("Mihomo 下载仅能独立覆盖 Host／路径／请求头／XMux，其他独立元数据请保留 May Core 原生配置。");
            var dn=d.DeepClone().AsObject();dn["type"]="vless";dn["tag"]=name;dn["uuid"]=n["uuid"]!.DeepClone();var dc=ToClash(dn,name);var settings=new JsonObject();
            foreach(var k in new[]{"server","port","tls","alpn","servername","skip-cert-verify","client-fingerprint","reality-opts"})if(dc[k]!=null)settings[k]=dc[k]!.DeepClone();
            settings["path"]=dt.Text("path");settings["host"]=dt.Text("host");settings["headers"]=(de["headers"]??new JsonObject()).DeepClone();if(de["xmux"]!=null)settings["reuse-settings"]=ClashExtra(de)["reuse-settings"]!.DeepClone();x["download-settings"]=settings;
        }
        return c;
    }
    public static JsonObject FromClash(JsonObject c,string name)
    {
        if(c.At("xhttp-opts.session-table")!=null||c.At("xhttp-opts.session-length")!=null)throw new OperationException("Mihomo 自定义会话字符表／长度属于客户端扩展；保留完整 Mihomo 配置，不生成有损 May Core 配置。");
        Only(c,"name","type","server","port","uuid","tls","servername","skip-cert-verify","alpn","udp","packet-encoding","network","xhttp-opts","reality-opts","client-fingerprint");
        if(c.Text("name")!=name||c.Text("type")!="vless"||c.Text("network")!="xhttp"||!c.Flag("tls")||c.Flag("skip-cert-verify")||!c.Flag("udp",true)||c.Text("packet-encoding","xudp")!="xudp"||c["xhttp-opts"] is not JsonObject x)throw new OperationException("Mihomo XHTTP 参数不完整或无法等价转换。");
        Only(x,ExtraNames.Values.Concat(new[]{"path","host","mode","download-settings"}).ToArray());var extra=new JsonObject();
        foreach(var p in x.Where(p=>p.Key is not ("path" or "host" or "mode" or "download-settings"))){var key=ExtraNames.Single(k=>k.Value==p.Key).Key;if(key=="xmux"){var mux=new JsonObject();Only(p.Value!.AsObject(),MuxNames.Values.ToArray());foreach(var m in p.Value!.AsObject())mux[MuxNames.Single(k=>k.Value==m.Key).Key]=m.Value!.DeepClone();extra[key]=mux;}else extra[key]=p.Value!.DeepClone();}
        var tls=new JsonObject{["enabled"]=true,["server_name"]=c.Text("servername"),["alpn"]=c["alpn"]?.DeepClone()??new JsonArray("h2")};
        if(c["client-fingerprint"]!=null)tls["utls"]=new JsonObject{["enabled"]=true,["fingerprint"]=c.Text("client-fingerprint")};
        if(c["reality-opts"] is JsonObject r){Fields(r,"public-key","short-id");tls["reality"]=new JsonObject{["enabled"]=true,["public_key"]=r.Text("public-key"),["short_id"]=r.Text("short-id")};}
        var t=new JsonObject{["type"]="xhttp",["path"]=x.Text("path"),["host"]=x.Text("host"),["mode"]=x.Text("mode","auto")};if(extra.Count>0)t["extra"]=extra;
        var n=new JsonObject{["type"]="vless",["tag"]=name,["server"]=c.Text("server"),["server_port"]=c.Number("port"),["uuid"]=c.Text("uuid"),["packet_encoding"]="xudp",["tls"]=tls,["transport"]=t};
        if(x["download-settings"] is JsonObject ds)
        {
            Only(ds,"path","host","headers","reuse-settings","server","port","tls","alpn","servername","skip-cert-verify","client-fingerprint","reality-opts");
            var dc=c.DeepClone().AsObject();dc["xhttp-opts"]!.AsObject().Remove("download-settings");
            foreach(var p in ds){if(p.Key is "path" or "host" or "headers" or "reuse-settings")dc["xhttp-opts"]![p.Key]=p.Value!.DeepClone();else dc[p.Key]=p.Value!.DeepClone();}
            var dn=FromClash(dc,name);t["download_settings"]=new JsonObject{["server"]=dn["server"]!.DeepClone(),["server_port"]=dn["server_port"]!.DeepClone(),["tls"]=dn["tls"]!.DeepClone(),["transport"]=dn["transport"]!.DeepClone()};
        }
        return CanonicalNative(n,name);
    }
}
