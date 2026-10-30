# 第十八轮：外部 WS／gRPC 节点兼容

本轮接通外部 VLESS／Trojan 节点的 TLS WebSocket 和 gRPC 导入、配置输出、分享及按需诊断。协议与传输分别保存；不把 `WS` 或 `gRPC` 当成一种代理协议，也不把它们加入新建 VPS 的默认部署选项。

当前发行基线仍是 v0.9.38，第十五至十八轮属于未发行源码。本文描述包含本轮改动的开发构建，不代表已安装应用、Route 或任何生产 VPS 已更新。

## 支持矩阵

| 外部连接 | 链接导入／订阅刷新 | sing-box 1.14.2 | Mihomo 1.19.32 | 本轮实际验证 |
| --- | --- | --- | --- | --- |
| VLESS + TLS + WS | 支持有限参数 | 原生 `vless` + `transport.type=ws` | `vless` + `network=ws` | HTTPS、应用 UDP、失败反例。 |
| Trojan + TLS + WS | 支持有限参数 | 原生 `trojan` + `transport.type=ws` | `trojan` + `network=ws` | HTTPS、应用 UDP、失败反例。 |
| VLESS + TLS + gRPC | 单流 `gun` | `transport.service_name` | `grpc-opts.grpc-service-name` | HTTPS、应用 UDP、错误 serviceName。 |
| Trojan + TLS + gRPC | 单流 `gun` | `transport.service_name` | `grpc-opts.grpc-service-name` | HTTPS、应用 UDP、错误 serviceName。 |

这些是**外部客户端节点**的能力。通用独立入站、固定角色、服务器下一跳、透明转发和跨实例编排没有因此自动获得任意传输转换能力。现有 Reality + Vision、AnyTLS、SS／SS2022、Hysteria2 的导入与输出入口继续保留。

不新增 VMess、裸 TLS 关闭的 VLESS、Trojan-Go 插件、HTTPUpgrade、gRPC multi、多路复用开关或 Reality + gRPC 链接转换。XHTTP 属于第十九轮；固定 sing-box 缺少实现时，不用删除字段的方式声称兼容。

## 导入与使用

1. 在「配置设计」新建或打开方案，选择生成 sing-box、Clash 或两者。
2. 使用「导入外部节点」，每行粘贴一条完整分享链接。选择用途及地区组，先查看逐行预览。
3. 预览分开显示协议与传输，例如 `vless / WebSocket`。名称相同但连接参数不同的节点保留不同身份；完全重复的连接会提示跳过。错误参数逐行拒绝，预览不会显示原链接或密码。
4. 确认导入并保存方案。它只修改加密私人草稿，不会更新远端或客户端当前运行副本。
5. 配置地区、入口／落地关系及业务默认出口，生成候选并用所选固定核心校验；检查差异后导出。
6. 在实际客户端加载文件，再验证所需网站及实际命中规则。配置解析成功不能代替连接或授权验证。

已有订阅来源继续使用「获取／刷新 → 差异预览 → 确认」流程。Host、路径、serviceName、TLS 或鉴权变化会改变连接摘要。来源和本地同时修改时停止更新，不用新参数覆盖本地修改；抓取失败、取消或空结果不清空旧节点。

读取现有 Clash YAML／sing-box JSON 时，支持从单份来源或两份配对来源提取上述节点。保存其完整原生配置，不凭一份来源猜测另一份的高级参数；所选客户端缺少配置时仍须补齐。原生来源中的复杂路径或高级设置保留，但不能据此声称具备跨客户端等价转换和实际连接验收。

## 参数对应

| 链接／含义 | sing-box | Mihomo |
| --- | --- | --- |
| VLESS UUID | `uuid` | `uuid`，保留 xudp 对应。 |
| Trojan 密码 | `password` | `password`；保留百分号编码后的原始字符。 |
| `type=ws`／`type=grpc` | 独立 `transport.type` | 独立 `network`。 |
| TLS 服务器身份 `sni` | `tls.server_name` | VLESS 的 `servername` 或 Trojan 的 `sni`。 |
| WS HTTP Host `host` | `transport.headers.Host` | `ws-opts.headers.Host`。 |
| WS `path` | `transport.path` | `ws-opts.path`。 |
| gRPC `serviceName` | `transport.service_name` | `grpc-opts.grpc-service-name`。 |
| 可选 TLS `fp` | `tls.utls` | `client-fingerprint`。 |
| 显式 `alpn` | `tls.alpn` | `alpn`；WS 为 `http/1.1`，gRPC 为 `h2`。 |
| WS `ed`／`eh` | `max_early_data`／`early_data_header_name` | 对应 `max-early-data`／`early-data-header-name`。 |

服务器连接地址、TLS SNI、WS Host 是三个不同字段。例如连接某个 IP、以一个域名校验证书、使用另一个 Host 进行 HTTP 路由时，不把它们自动合并。

VLESS 链接必须使用 `security=tls`、`encryption=none`、空 flow；不将 Vision flow 塞进 WS／gRPC。Trojan 允许省略 `security=tls`，但运行时仍验证 TLS。未知字段、重复参数、无效编码、跳过证书验证、字段类型错误及传输混用明确拒绝，不静默丢掉。

### WS 路径和早期数据

**实测发现固定核心存在路径语义差异。** sing-box 1.14.2 将带查询串的路径按路径正文处理，Mihomo 1.19.32 会拆分查询串；已转义的保留字符也可能再次规范化。因此本轮链接的双客户端转换仅接受由 `/`、ASCII 字母、数字、点、下划线、连字符和波浪号构成的绝对路径，最多 2048 字符。分享链接查询参数本身仍使用标准百分号编码，例如 `path=%2Fproxy-path` 导入后是 `/proxy-path`。

带查询串、二次转义路径或特殊路径的链接会拒绝，而不是删去查询串后继续。此时保留原生配置，按实际目标客户端分别校验；不要为了通过导入自行删除服务商要求的参数。

早期数据用独立的 `ed`／`eh` 表达，不混入路径的 `?ed=`。支持 1–2048 字节，固定使用 `Sec-WebSocket-Protocol` 请求头；省略 `eh` 时该头是明确默认值。只提供 `eh`、未知承载头、路径承载或超限大小均拒绝。VLESS／Trojan 两种 WS 的早期数据都完成了实际连接验证。

gRPC `serviceName` 保留大小写，可使用 1–128 个字母、数字、点、下划线或连字符；只支持单流 `gun`。包含斜线、多路模式、自定义 authority 或 keepalive 等高级设置不通过链接转换，保留原生配置。

## 编辑与分享

外部 WS／gRPC 使用独立编辑表单。改名、用途、地区和出口标注保留完整原生连接；不会再使用 Reality 表单为普通 VLESS 加入公钥、short-id 或 Vision 设置。

更换连接地址、鉴权、TLS 或传输参数时，在「替换连接链接」粘贴一条受支持的完整新链接。保存保留节点 ID、当前显示名及分组，新链接的片段名称不覆盖编辑名称；参数变化会标记来源修改并使旧候选失效。取消不修改草稿，结束时清空凭据输入。

分享同时核对两份客户端配置是否等价，并重新导入生成的链接核对完整连接。配对路径、Host、TLS 等不一致时拒绝分享。额外 WS 请求头、私有证书路径、自定义拨号依赖、TLS 高级参数或其他无法用链接表达的设置须使用完整配置；不会靠忽略字段生成“可用”链接。已有入口／落地依赖的节点仍不能靠普通分享链接保存整条客户端链路。

分享内容属于凭据材料，即使使用 Base64 也不是加密。只输出到明确选择的私人位置，不把原链接加入预览、来源说明或普通日志。

## 验收与边界

实际协议验收使用固定 Xray 26.3.27 合成服务端、sing-box 1.14.2 和 Mihomo 1.19.32 客户端，均限制为本机回环。TLS 测试使用专门生成的临时信任材料，不跳过代理证书验证，不写系统信任库。

每种 VLESS／Trojan × WS／gRPC 完成实际 HTTPS 和匹配问题、目标及回答的应用 UDP DNS 往返；另测两种 WS 的早期数据，共 12 个客户端组合。有限录制网关核对 WS 实际请求路径、Host、SNI 及早期数据头；gRPC 由固定 Xray 检查服务名。错误用户／密码、SNI、WS 路径／Host 或 gRPC serviceName 不能抵达受控 HTTPS 目标，没有 DIRECT 兜底。临时核心和网关随任务关闭，不增加常驻监测。

模型和真实生成器检查还覆盖订阅来源变化、本地冲突、单份／配对来源提取、原生字段逐项保留、分享往返、额外请求头拒绝分享、旧候选失效、来源模板只读及本地导出。完整 .NET 回归通过 **2681 项断言**，本轮新增 147 项模型／真实链路断言。原生 WinUI 的既有九项检查及本轮四项检查全部通过，覆盖协议与传输显示、凭据脱敏、取消、改名和替换连接；前台激活与前台采样均为零，测试实例随后关闭。

`ValidateProject` 通过 956 项主断言以及交互、工作台、审计、GUI、更新、Python 和 Bash 检查。独立固定客户端兼容回归及每核心 16 项实际学术分流检查通过；627 个公开文本文件的秘密扫描通过。两项 Windows 符号链接权限断言依原规则跳过，Unix CI 负责该分支；NuGet 漏洞源不可达产生 NU1900，编译成功但不代表补做了新的依赖漏洞扫描。早期 UI 测试读取了已转换为 TextBlock 的标题字符串，修正为无障碍标题后重跑通过，未修改产品标题或绕过保存断言。

早期隔离验收失败分别来自沙箱阻止回环 TCP、Windows Schannel 不接受临时密钥句柄及上述真实路径语义差异。前两项只修正本机测试执行／临时证书夹具，后一项落实为明确转换边界，未放宽证书校验或连接验收。公网 CDN／反向代理、Cloudflare 代理与 Tunnel、远端真实线路、任意高级参数、吞吐和长时间资源稳定性未在本轮验收。

## 固定来源与下一轮

- [sing-box 1.14.2 传输字段](https://github.com/SagerNet/sing-box/blob/v1.14.2/option/v2ray_transport.go)与[WS 请求实现](https://github.com/SagerNet/sing-box/blob/v1.14.2/transport/v2raywebsocket/client.go)。
- [Mihomo 1.19.32 VLESS 参数](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/adapter/outbound/vless.go)、[Trojan 参数](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/adapter/outbound/trojan.go)及[WS 请求实现](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/transport/vmess/websocket.go)。
- [固定 Xray 传输配置](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/transport_internet.go)。

第十九轮继续原计划的有限 XHTTP，先验证 Xray 服务端到 Mihomo 的 TLS／HTTP/2 路径及维护闭环，不能用本轮 WS／gRPC 的成功代替它的实际验收。
