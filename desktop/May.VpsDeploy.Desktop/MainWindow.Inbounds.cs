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
        var sources = workbench.List().SelectMany(s => (s["Nodes"] as JsonArray)?.OfType<JsonObject>().Where(n=>n["sing_box"] is JsonObject native && native.Text("type") is "vless" or "anytls" or "shadowsocks" && n.Text("ManagedOrigin.Instance") != relative && n.Text("InboundOrigin.Instance") != relative).Select(n=>(Scheme:s,Node:n)) ?? []).ToArray();
        var action = Choice("操作",selection,"Action",[("Apply","保存模型变更"),("Check","只读检查已保存模型"),("UpgradeSingBox","更新当前包内固定 sing-box 核心")]); action.Tag="Inbounds.Action";
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
            if(selection.Text("Action")!="Apply") { rows.Children.Add(Text("检查或核心更新使用已保存的模型与凭据；草稿保留。核心更新会审阅共享 sing-box 的影响入站并重新验收，Xray 固定版本保留。",14,true));return; }
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
                rows.Children.Add(Choice("新用户认证类型",selection,"UserKind",[("Uuid","VLESS UUID"),("Password","AnyTLS 密码"),("SS128","SS2022 AES-128 密钥"),("SS256","SS2022 AES-256 密钥")]));
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
                else if(protocol is "AnyTLS" or "Hysteria2")
                {
                    var cert=Choice("证书引用",current,"CertificateId",InboundCatalog.Items(model,"Certificates").Select(c=>(c.Text("Id"),c.Text("Name")+" · "+c.Text("NotAfter"))),true);cert.Tag="Inbounds.Certificate";rows.Children.Add(cert);
                    if(protocol=="AnyTLS") { rows.Children.Add(Toggle("启用 ECH",options,"EchEnabled","Inbounds.Ech"));rows.Children.Add(Action("按当前 SNI 生成 ECH 材料",async()=>{try{var keys=await InboundKeyGeneration.EchAsync(assets,tools,options.Text("ServerName"),default);own["EchKey"]=keys.Text("Key");own["EchConfig"]=keys.Text("Config");keys.Clear();options["EchEnabled"]=true;Refresh();}catch(OperationException ex){error.Text=ex.Message;}})); }
                    else
                    {
                        rows.Children.Add(Text("Hysteria2 仅监听 UDP；请在服务商防火墙放行相同 UDP 端口。上、下行均从客户端视角填写，均为 0 时使用自适应 BBR；固定速率请按线路能力保守填写。",14,true));
                        var up=Field("客户端上行 Mbps",options,"UploadMbps",numeric:true);up.Tag="Inbounds.HysteriaUp";var down=Field("客户端下载 Mbps",options,"DownloadMbps",numeric:true);down.Tag="Inbounds.HysteriaDown";rows.Children.Add(Fields(up,down));
                        rows.Children.Add(Toggle("启用 Salamander",options,"ObfsEnabled","Inbounds.HysteriaObfs"));rows.Children.Add(Secret("Salamander 密码（与用户鉴权独立）",own,"ObfsPassword","Inbounds.HysteriaObfsPassword"));
                        rows.Children.Add(Action("生成新 Salamander 密码",()=>{own["ObfsPassword"]=ServerConfigurations.RandomKey(32);Refresh();return Task.CompletedTask;}));
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
                rows.Children.Add(Secret("认证凭据（保存时加密归档）",credentials["Users"]![id]!.AsObject(),"Value","Inbounds.UserCredential"));
                var rotate=Action("生成此用户的新凭据",()=>{credentials["Users"]![id]!["Value"]=current.Text("Kind")=="Uuid"?Guid.NewGuid().ToString():ServerConfigurations.RandomKey(current.Text("Kind")=="SS128"?16:32);Refresh();return Task.CompletedTask;});rotate.Tag="Inbounds.RotateUser";rows.Children.Add(rotate);
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
