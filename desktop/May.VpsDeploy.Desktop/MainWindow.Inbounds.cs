using System.Text.Json.Nodes;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using May.VpsDeploy.Core;
using May.VpsDeploy.Infrastructure;

namespace May.VpsDeploy.Desktop;

public sealed partial class MainWindow
{
    private async Task InboundsSheet(string relative, JsonObject plan)
    {
        var saved = (plan["InboundModel"] ?? InboundCatalog.Empty()).DeepClone().AsObject(); var model = saved.DeepClone().AsObject();
        var allSecrets = store.ReadSecret(SafePath.Resolve(paths.Instance(relative), "secrets.dotnet.private.json"));
        var savedCredentials = (allSecrets["Inbounds"] ?? InboundCatalog.EmptyCredentials()).DeepClone().AsObject(); allSecrets.Clear(); var credentials = savedCredentials.DeepClone().AsObject();
        var selection = new JsonObject { ["Action"] = "Apply", ["Group"] = "Inbounds", ["Protocol"] = "Shadowsocks2022", ["UserKind"] = "Password" };
        var selectedIds = new Dictionary<string,string>(); var rows = new StackPanel { Spacing=16 }; var error = Text("",14,true); error.Tag="Inbounds.Error";
        var assets = new ValidationAssets(paths,"windows-amd64"); var tools = new ExternalToolRunner();
        var sources = workbench.List().SelectMany(s => (s["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(n=>n["sing_box"] is JsonObject native && native.Text("type") is "vless" or "anytls" or "shadowsocks" or "hysteria2" or "tuic" && n.Text("ManagedOrigin.Instance") != relative && n.Text("InboundOrigin.Instance") != relative).Select(n=>(Scheme:s,Node:n)) ?? []).ToArray();
        var action = Choice("操作",selection,"Action",[("Apply","保存模型变更"),("Check","只读检查已保存模型"),("UpgradeSingBox","更新当前包内固定 sing-box 核心"),("UpgradeXray","更新当前包内固定 Xray 核心")]); action.Tag="Inbounds.Action";
        var group = Choice("资源类别",selection,"Group",[("Inbounds","入站与监听"),("Users","用户与凭据"),("Certificates","证书"),("Outbounds","出站")]); group.Tag="Inbounds.Group";
        void Edit(Action edit) { try { edit(); error.Text=""; } catch(OperationException exception) { error.Text=exception.Message; } }
        PasswordBox Secret(string title,JsonObject value,string key,string tag)
        {
            var box=SecretField(title); box.Password=value.Text(key);box.Tag=tag;box.PasswordChanged+=(_,_)=>value[key]=box.Password;return box;
        }
        CheckBox Toggle(string title,JsonObject value,string key,string tag)
        {
            var box=new CheckBox {Content=title,IsChecked=value.Flag(key),Tag=tag};box.Checked+=(_,_)=>value[key]=true;box.Unchecked+=(_,_)=>value[key]=false;return box;
        }
        void Refresh()
        {
            rows.Children.Clear();error.Text="";
            if(selection.Text("Action")!="Apply") { rows.Children.Add(Text("检查或核心更新使用已保存的模型与凭据；草稿保留。更新只替换所选核心，并重新验收引用它的受影响入站；另一核心保持原版本。",14,true));return; }
            var category=selection.Text("Group");var items=InboundCatalog.Items(model,category).ToArray();
            var selectedId=selectedIds.GetValueOrDefault(category,items.FirstOrDefault()?.Text("Id")??"");
            var pickModel=new JsonObject {["Id"]=selectedId};var pick=Choice("选择资源",pickModel,"Id",items.Select(i=>(i.Text("Id"),i.Text("Name"))),true);pick.Tag="Inbounds.Resource";
            pick.SelectionChanged+=(_,_)=>{selectedIds[category]=pickModel.Text("Id");Refresh();};rows.Children.Add(pick);
            var addModel=selection;
            if(category=="Inbounds")
            {
                var type=Choice("新建协议",addModel,"Protocol",InboundCatalog.Protocols.Select(p=>(p,InboundCatalog.Label(p))));type.Tag="Inbounds.NewProtocol";rows.Children.Add(type);
                var add=Action("新增独立入站",()=>{Edit(()=>{if(items.Length>=InboundCatalog.MaximumInbounds)throw new OperationException("最多配置 16 个独立入站。");var item=InboundCatalog.AddInbound(model,credentials,selection.Text("Protocol"));selectedIds[category]=item.Text("Id");Refresh();});return Task.CompletedTask;});add.Tag="Inbounds.Add";rows.Children.Add(add);
            }
            else if(category=="Users")
            {
                rows.Children.Add(Choice("新用户认证类型",selection,"UserKind",[("Uuid","VLESS UUID"),("Password","AnyTLS / Hysteria2 密码"),("TuicV5","TUIC v5 UUID + 密码"),("SS128","SS2022 AES-128 密钥"),("SS256","SS2022 AES-256 密钥")]));
                var add=Action("新增用户",()=>{Edit(()=>{var item=InboundCatalog.AddUser(model,credentials,"用户 "+(items.Length+1),selection.Text("UserKind"));selectedIds[category]=item.Text("Id");Refresh();});return Task.CompletedTask;});add.Tag="Inbounds.AddUser";rows.Children.Add(add);
            }
            else if(category=="Outbounds")
            {
                var add=Action("新增出站",()=>{Edit(()=>{var item=InboundCatalog.AddDirect(model,"出站 "+(items.Length+1));selectedIds[category]=item.Text("Id");Refresh();});return Task.CompletedTask;});add.Tag="Inbounds.AddOutbound";rows.Children.Add(add);
            }
            else
            {
                var draft=new JsonObject{["Name"]="新证书",["CertificatePem"]="",["PrivateKeyPem"]=""};
                var pem=Field("证书链 PEM",draft,"CertificatePem");pem.AcceptsReturn=true;pem.MinHeight=70;pem.Tag="Inbounds.ImportCertificate";var key=Secret("私钥 PEM",draft,"PrivateKeyPem","Inbounds.ImportKey");
                var add=Action("导入独立证书",()=>{Edit(()=>{var item=InboundCatalog.ImportCertificate(model,credentials,draft.Text("Name"),draft.Text("CertificatePem"),draft.Text("PrivateKeyPem"));selectedIds[category]=item.Text("Id");Refresh();});return Task.CompletedTask;});add.Tag="Inbounds.AddCertificate";rows.Children.Add(Column(Field("新证书名称",draft,"Name"),pem,key,add));
            }
            var current=items.SingleOrDefault(i=>i.Text("Id")==selectedId);if(current==null)return;
            var name=Field("资源名称",current,"Name");name.Tag="Inbounds.Name";rows.Children.Add(name);rows.Children.Add(Text("稳定身份："+current.Text("Id"),12,true));
            if(category=="Inbounds")
            {
                rows.Children.Add(Text(InboundCatalog.Label(current.Text("Protocol"))+" · 独立服务与配置；变更不重启其他无关入站。",14,true));rows.Children.Add(Toggle("启用入站",current,"Enabled","Inbounds.Enabled"));
                var address=Field("监听地址（0.0.0.0 / :: 或本机地址）",current["Listener"]!.AsObject(),"Address");address.Tag="Inbounds.Address";var port=Field("监听端口",current["Listener"]!.AsObject(),"Port",numeric:true);port.Tag="Inbounds.Port";rows.Children.Add(Fields(address,port));
                var protocol=current.Text("Protocol");var options=current["Options"]!.AsObject();var own=credentials["Inbounds"]![current.Text("Id")]!.AsObject();
                var kind=InboundCatalog.UserKind(current);
                rows.Children.Add(Text("引用用户（可共享；共享凭据变化会列出所有受影响入站）",14));
                foreach(var user in InboundCatalog.Items(model,"Users").Where(u=>u.Text("Kind")==kind))
                {
                    var userId=user.Text("Id");var box=new CheckBox{Content=user.Text("Name"),IsChecked=current.Strings("UserIds").Contains(userId),Tag="Inbounds.User."+userId};
                    box.Checked+=(_,_)=>{if(!current.Strings("UserIds").Contains(userId))current["UserIds"]!.AsArray().Add(userId);};box.Unchecked+=(_,_)=>{var value=current["UserIds"]!.AsArray().FirstOrDefault(n=>n!.ToString()==userId);if(value!=null)current["UserIds"]!.AsArray().Remove(value);};rows.Children.Add(box);
                }
                var outbound=Choice("出站引用",current,"OutboundId",InboundCatalog.Items(model,"Outbounds").Select(o=>(o.Text("Id"),o.Text("Name"))),true);outbound.Tag="Inbounds.Outbound";rows.Children.Add(outbound);
                if(protocol!="Shadowsocks2022") {var sni=Field("TLS / Reality SNI",options,"ServerName");sni.Tag="Inbounds.Sni";rows.Children.Add(sni);}
                if(protocol=="Reality")
                {
                    rows.Children.Add(Fields(Field("Reality 握手目标域名",options,"HandshakeServer"),Field("目标端口",options,"HandshakePort",numeric:true)));rows.Children.Add(Fields(Field("公钥",options,"PublicKey"),Field("Short ID",options,"ShortId")));rows.Children.Add(Secret("本入站 Reality 私钥",own,"RealityPrivateKey","Inbounds.RealityPrivate"));
                    var generate=Action("生成本入站 Reality 密钥",async()=>{try{var keys=await InboundKeyGeneration.RealityAsync(assets,tools,default);own["RealityPrivateKey"]=keys.Text("PrivateKey");options["PublicKey"]=keys.Text("PublicKey");keys.Clear();Refresh();}catch(OperationException ex){error.Text=ex.Message;}});generate.Tag="Inbounds.GenerateReality";rows.Children.Add(generate);
                }
                else if(protocol=="VLESS")
                {
                    rows.Children.Add(Text("VLESS XHTTP 使用配套 May Core 或可等价表达的 Mihomo 参数，不启用 Vision flow。HTTP/3 监听 UDP；Reality 仅适用 HTTP/2。切换身份后须重新验收。",14,true));
                    var security=Choice("传输安全",options,"Security",[("TLS","TLS 证书"),("Reality","Reality")]);security.Tag="Inbounds.XhttpSecurity";
                    security.SelectionChanged+=(_,_)=>{current["CertificateId"]="";own.Clear();options["Reality"]=options.Text("Security")=="Reality"?VlessXhttp.RealityOptions():new JsonObject();if(options.Text("Security")=="Reality"){own["RealityPrivateKey"]="";options["Transport"]!["HTTPVersion"]="2";}Refresh();};rows.Children.Add(security);
                    var transport=options["Transport"]!.AsObject();var path=Field("XHTTP 路径（保留查询串与转义）",transport,"Path");path.Tag="Inbounds.XhttpPath";rows.Children.Add(path);var host=Field("XHTTP Host",transport,"Host");host.Tag="Inbounds.XhttpHost";rows.Children.Add(host);
                    if(!transport.ContainsKey("HTTPVersion"))transport["HTTPVersion"]="2";
                    var httpVersion=Choice("HTTP 版本",transport,"HTTPVersion",options.Text("Security")=="Reality"?[("2","HTTP/2")]:[("1.1","HTTP/1.1"),("2","HTTP/2"),("3","HTTP/3（UDP）")]);httpVersion.Tag="Inbounds.XhttpVersion";rows.Children.Add(httpVersion);
                    var mode=Choice("XHTTP 模式",transport,"Mode",[("auto","auto（跟随 TLS／Reality 语义）"),("stream-one","stream-one"),("stream-up","stream-up"),("packet-up","packet-up")]);mode.Tag="Inbounds.XhttpMode";rows.Children.Add(mode);
                    var extraBox=new TextBox{Header="高级 extra（固定 Xray 字段 JSON）",AcceptsReturn=true,TextWrapping=TextWrapping.Wrap,MaxHeight=180,Text=transport["Extra"] is JsonObject extraObject?extraObject.ToJsonString():transport["Extra"] is JsonValue extraValue&&extraValue.TryGetValue<string>(out var rawExtra)?rawExtra:"{}",Tag="Inbounds.XhttpExtra"};
                    extraBox.TextChanged+=(_,_)=>{try{var extra=JsonNode.Parse(extraBox.Text) as JsonObject??throw new System.Text.Json.JsonException();VlessXhttp.ValidateExtra(extra);transport["Extra"]=extra;error.Text="";}catch(Exception ex) when(ex is OperationException or System.Text.Json.JsonException){transport["Extra"]=JsonValue.Create(extraBox.Text);error.Text="请填写有效的 XHTTP extra JSON；未丢弃原输入。";}};rows.Children.Add(extraBox);
                    if(options.Text("Security")=="TLS") {var cert=Choice("证书引用",current,"CertificateId",InboundCatalog.Items(model,"Certificates").Select(c=>(c.Text("Id"),c.Text("Name")+" · "+c.Text("NotAfter"))),true);cert.Tag="Inbounds.Certificate";rows.Children.Add(cert);}
                    else
                    {
                        var reality=options["Reality"]!.AsObject();var target=Field("Reality 握手目标域名",reality,"HandshakeServer");target.Tag="Inbounds.XhttpTarget";var targetPort=Field("目标端口",reality,"HandshakePort",numeric:true);targetPort.Tag="Inbounds.XhttpTargetPort";rows.Children.Add(Fields(target,targetPort));var publicKey=Field("公钥",reality,"PublicKey");publicKey.Tag="Inbounds.XhttpPublicKey";var shortId=Field("Short ID",reality,"ShortId");shortId.Tag="Inbounds.XhttpShortId";rows.Children.Add(Fields(publicKey,shortId));rows.Children.Add(Secret("本入站 Reality 私钥",own,"RealityPrivateKey","Inbounds.XhttpRealityPrivate"));
                        var generate=Action("生成 XHTTP Reality 密钥",async()=>{try{var keys=await InboundKeyGeneration.RealityAsync(assets,tools,default);own["RealityPrivateKey"]=keys.Text("PrivateKey");reality["PublicKey"]=keys.Text("PublicKey");keys.Clear();Refresh();}catch(OperationException ex){error.Text=ex.Message;}});generate.Tag="Inbounds.XhttpGenerateReality";rows.Children.Add(generate);
                    }
                }
                else if(protocol is "AnyTLS" or "Hysteria2" or "TuicV5")
                {
                    var cert=Choice("证书引用",current,"CertificateId",InboundCatalog.Items(model,"Certificates").Select(c=>(c.Text("Id"),c.Text("Name")+" · "+c.Text("NotAfter"))),true);cert.Tag="Inbounds.Certificate";rows.Children.Add(cert);
                    if(protocol=="AnyTLS") { rows.Children.Add(Toggle("启用 ECH",options,"EchEnabled","Inbounds.Ech"));rows.Children.Add(Action("按当前 SNI 生成 ECH 材料",async()=>{try{var keys=await InboundKeyGeneration.EchAsync(assets,tools,options.Text("ServerName"),default);own["EchKey"]=keys.Text("Key");own["EchConfig"]=keys.Text("Config");keys.Clear();options["EchEnabled"]=true;Refresh();}catch(OperationException ex){error.Text=ex.Message;}})); }
                    else if(protocol=="TuicV5")
                    {
                        rows.Children.Add(Text("TUIC v5 仅监听 UDP，使用 UUID + 密码和可验证的 TLS 1.3 / h3。需要放行相同 UDP 端口；保存时按用户与地址族验收 HTTPS 及代理 UDP DNS 回程。0-RTT 固定关闭。",14,true));
                        var congestion=Choice("拥塞控制",options,"CongestionControl",[("cubic","cubic（默认）"),("new_reno","new_reno"),("bbr","bbr")]);congestion.Tag="Inbounds.TuicCongestion";rows.Children.Add(congestion);
                        var relay=Choice("应用 UDP 中继",options,"UdpRelayMode",[("native","native 数据报（默认）"),("quic","quic 可靠流")]);relay.Tag="Inbounds.TuicRelay";rows.Children.Add(relay);
                        var heartbeat=Field("心跳间隔（秒，5–120）",options,"HeartbeatSeconds",numeric:true);heartbeat.Tag="Inbounds.TuicHeartbeat";
                        var timeout=Field("服务端鉴权等待（秒，1–30）",options,"AuthTimeoutSeconds",numeric:true);timeout.Tag="Inbounds.TuicAuthTimeout";rows.Children.Add(Fields(heartbeat,timeout));
                    }
                    else
                    {
                        rows.Children.Add(Text("Hysteria2 仅监听 UDP；请在服务商防火墙放行相同 UDP 端口。上、下行均从客户端视角填写，均为 0 时使用自适应 BBR；固定速率请按线路能力保守填写。",14,true));
                        var up=Field("客户端上行 Mbps",options,"UploadMbps",numeric:true);up.Tag="Inbounds.HysteriaUp";var down=Field("客户端下载 Mbps",options,"DownloadMbps",numeric:true);down.Tag="Inbounds.HysteriaDown";rows.Children.Add(Fields(up,down));
                        rows.Children.Add(Toggle("启用 Salamander",options,"ObfsEnabled","Inbounds.HysteriaObfs"));rows.Children.Add(Secret("Salamander 密码（与用户鉴权独立）",own,"ObfsPassword","Inbounds.HysteriaObfsPassword"));
                        rows.Children.Add(Action("生成新 Salamander 密码",()=>{own["ObfsPassword"]=ServerConfigurations.RandomKey(32);Refresh();return Task.CompletedTask;}));
                        var hopping = new CheckBox { Content="启用端口跳跃", IsChecked=options.Text("HopPorts")!="", Tag="Inbounds.HysteriaHopping" };
                        hopping.Checked+=(_,_)=>{options["HopPorts"]=current.Number("Listener.Port")+","+(current.Number("Listener.Port")==65535?65534:current.Number("Listener.Port")+1);options["HopIntervalSeconds"]=Hysteria2Ports.DefaultInterval;Refresh();};
                        hopping.Unchecked+=(_,_)=>{options.Remove("HopPorts");options.Remove("HopIntervalSeconds");Refresh();};rows.Children.Add(hopping);
                        if(options.Text("HopPorts")!="")
                        {
                            var hopPorts=Field("跳跃端口（含监听端口；逗号分隔，范围用 -）",options,"HopPorts");hopPorts.Tag="Inbounds.HysteriaHopPorts";
                            var interval=Field("跳跃间隔（秒，5–3600，默认 30）",options,"HopIntervalSeconds",numeric:true);interval.Tag="Inbounds.HysteriaHopInterval";rows.Children.Add(Fields(hopPorts,interval));
                            rows.Children.Add(Text("最多 256 个端口，停用时仍保留。需要本应用受管 nftables；服务商安全组须放行完整 UDP 端口集。重定向复用同一监听，不增加常驻进程。标准分享链接只保留默认 30 秒间隔，自定义间隔请导出完整配置。",14,true));
                        }
                    }
                }
                else
                {
                    var method=Choice("Shadowsocks 方法",options,"Method",[("2022-blake3-aes-128-gcm","2022 AES-128"),("2022-blake3-aes-256-gcm","2022 AES-256")]);method.Tag="Inbounds.Method";method.SelectionChanged+=(_,_)=>Refresh();rows.Children.Add(method);rows.Children.Add(Secret("本入站服务器密钥（独立于用户密钥）",own,"ServerKey","Inbounds.ServerKey"));rows.Children.Add(Action("重新生成本入站服务器密钥",()=>{own["ServerKey"]=ServerConfigurations.RandomKey(options.Text("Method")=="2022-blake3-aes-256-gcm"?32:16);Refresh();return Task.CompletedTask;}));
                }
            }
            else if(category=="Users")
            {
                var id=current.Text("Id");rows.Children.Add(Text("认证类型："+current.Text("Kind")+"；引用入站："+string.Join("，",InboundCatalog.Items(model,"Inbounds").Where(i=>i.Strings("UserIds").Contains(id)).Select(i=>i.Text("Name"))),14,true));
                rows.Children.Add(Secret(current.Text("Kind")=="TuicV5"?"TUIC v5 用户密码（保存时加密归档）":"认证凭据（保存时加密归档）",credentials["Users"]![id]!.AsObject(),"Value","Inbounds.UserCredential"));
                if(current.Text("Kind")=="TuicV5")
                {
                    var uuid=Field("TUIC v5 用户 UUID",credentials["Users"]![id]!.AsObject(),"Uuid");uuid.Tag="Inbounds.TuicUuid";rows.Children.Add(uuid);
                    rows.Children.Add(Action("生成此用户的新 UUID",()=>{credentials["Users"]![id]!["Uuid"]=Guid.NewGuid().ToString();Refresh();return Task.CompletedTask;}));
                }
                var rotate=Action(current.Text("Kind")=="TuicV5"?"生成此用户的新密码":"生成此用户的新凭据",()=>{credentials["Users"]![id]!["Value"]=current.Text("Kind")=="Uuid"?Guid.NewGuid().ToString():ServerConfigurations.RandomKey(current.Text("Kind")=="SS128"?16:32);Refresh();return Task.CompletedTask;});rotate.Tag="Inbounds.RotateUser";rows.Children.Add(rotate);
            }
            else if(category=="Certificates")
            {
                var material=credentials["Certificates"]![current.Text("Id")]!.AsObject();var draft=material.DeepClone().AsObject();var pem=Field("替换证书链 PEM",draft,"CertificatePem");pem.AcceptsReturn=true;pem.MinHeight=70;var key=Secret("替换私钥 PEM",draft,"PrivateKeyPem","Inbounds.ReplaceKey");rows.Children.Add(Text("SHA-256："+current.Text("Sha256")+"\n有效期至："+current.Text("NotAfter"),13,true));rows.Children.Add(pem);rows.Children.Add(key);rows.Children.Add(Action("核对并替换此证书材料",()=>{Edit(()=>{InboundCatalog.ReplaceCertificate(current,credentials,draft.Text("CertificatePem"),draft.Text("PrivateKeyPem"));Refresh();});return Task.CompletedTask;}));
            }
            else
            {
                var type=Choice("出站类型",current,"Kind",[("Direct","直连"),("Proxy","已保存代理节点")]);type.Tag="Inbounds.OutboundKind";type.SelectionChanged+=(_,_)=>{if(current.Text("Kind")=="Direct")current["Source"]=new JsonObject();Refresh();};rows.Children.Add(type);rows.Children.Add(Choice("出口地址族",current,"Family",[("IPv4","IPv4"),("IPv6","IPv6"),("Auto","自动")]));rows.Children.Add(Field("预期出口 IP（可留空，只观测地址族）",current,"ExpectedAddress"));
                if(current.Text("Kind")=="Proxy")
                {
                    rows.Children.Add(Text("sing-box 支持 Hysteria2 / TUIC v5 下一跳；Reality 使用固定 Xray，仅支持可转换的 Shadowsocks / Hysteria2。QUIC 出站必须同时通过 HTTPS 与应用 UDP 回程，来源变化需重新选择并审阅。",13,true));
                    var proxyModel=new JsonObject{["Source"]=current.Text("Source.SchemeId")+":"+current.Text("Source.NodeId")};var source=Choice("代理来源",proxyModel,"Source",sources.Select(s=>(s.Scheme.Text("Id")+":"+s.Node.Text("Id"),s.Scheme.Text("Name")+" / "+s.Node.Text("name"))),true);source.Tag="Inbounds.ProxySource";
                    source.SelectionChanged+=(_,_)=>{var chosen=sources.FirstOrDefault(s=>s.Scheme.Text("Id")+":"+s.Node.Text("Id")==proxyModel.Text("Source"));if(chosen.Node!=null)current["Source"]=new JsonObject{["SchemeId"]=chosen.Scheme.Text("Id"),["NodeId"]=chosen.Node.Text("Id"),["Fingerprint"]=ArchiveStore.Fingerprint(chosen.Node)};};rows.Children.Add(source);
                }
            }
            var remove=Action("移除此资源",()=>{Edit(()=>{InboundCatalog.RemoveEntity(model,credentials,category,current.Text("Id"));selectedIds.Remove(category);Refresh();});return Task.CompletedTask;});remove.Tag="Inbounds.Remove";rows.Children.Add(remove);
        }
        group.SelectionChanged+=(_,_)=>Refresh();action.SelectionChanged+=(_,_)=>Refresh();Refresh();
        var existing=InboundSources.ExistingRoles(plan);var panel=Column(Text("每个入站使用独立身份和运行配置；用户、证书与出站通过引用管理。证书需自行申请并导入，程序不静默重建现有协议或更改服务商设置。",14,true));
        if(existing.Count>0)panel.Children.Add(Text("现有组件（继续使用原维护入口）："+string.Join("，",existing.Select(i=>i!.Text("Name"))),14,true));
        panel.Children.Add(action);panel.Children.Add(group);panel.Children.Add(rows);panel.Children.Add(error);
        var dialog=OperationDialog("通用多入站资源",DialogScroll(panel),"审阅");JsonObject? options=null;
        dialog.PrimaryButtonClick+=(_,args)=>{try{var check=selection.Text("Action")!="Apply";options=InboundCatalog.Options(InstanceState(relative),selection.Text("Action"),check?saved:model,check?savedCredentials:credentials);var preview=InboundCatalog.Prepare(store,new(OperationKind.Inbounds,relative,options));preview.Credentials.Clear();preview.Payload["Configurations"]!.AsObject().Clear();error.Text="";}catch(OperationException exception){error.Text=exception.Message;args.Cancel=true;}};
        try{if(await ShowDialog(dialog)==ContentDialogResult.Primary)await Submit(new(OperationKind.Inbounds,relative,options!));}
        finally{credentials.Clear();savedCredentials.Clear();if(options?["Credentials"] is JsonObject supplied)supplied.Clear();foreach(var source in sources.Select(s=>s.Scheme).Distinct())source.Clear();}
    }
}
