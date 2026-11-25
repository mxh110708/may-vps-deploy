# Deploy 能力、FlyX 对照与后续建议

核对日期：2026-11-16。Deploy 最新正式版为 [v0.9.42](https://github.com/mxh110708/may-vps-deploy/releases/tag/v0.9.42)，本地与远端主分支均为 `80d2aaf20d4d7b5f95940b71c759e7fbb94cb3e3`，已包含主线第1至38轮及独立监控配套。FlyX 最新正式版为 [3.9.5](https://github.com/kure29/flyx/releases/tag/3.9.5)，主分支为 `0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03`。

本次核对 Deploy 当前源码、教程、各轮记录与发行元数据，以及 FlyX 固定提交的官方文档和相关源码，没有运行 FlyX 面板做部署互通。已实现、已发布、生产应用与长期观测分别记录；本表不把既有隔离验证扩大为生产验收，也不推断本机安装版本。

## 已实现并发布

| 范围 | 当前能力与必要边界 |
| --- | --- |
| 控制端与交付 | WinUI 3 桌面、安装版与便携版、内置运行时、应用内检查更新。正式控制端为 Windows amd64；远端运维验收面向 Debian 12／13 amd64。 |
| 实例生命周期 | 新机部署、已有实例接入、追加组件、健康审计、升级、凭据轮换、备份恢复与退役。 |
| SSH 与私人资料 | 主机身份核对、管理与救援入口、密钥接入及轮换、私人凭据加密归档。新机验证密钥后关闭密码认证；已有实例接入保留原策略。 |
| 多入站资源 | 入站、监听、用户、证书和出站独立管理，支持共享引用、依赖保护、按影响范围维护和单组件恢复。 |
| 代理入站 | VLESS Reality／Vision、AnyTLS／可选 ECH、SS2022、Hysteria2、TUIC v5、VLESS XHTTP。Hysteria2 包含 Salamander 与受管端口跳跃。 |
| XHTTP 配套 | 四种模式、固定实现中合法的 HTTP／TLS／Reality 组合、独立下载身份和高级参数；May Core → Route → Deploy 配套。Mihomo 仅输出其能等价表达的配置，公网／CDN 按已验收范围使用。 |
| 服务器下一跳 | SS／SS2022、Hysteria2、TUIC、VLESS TLS／Reality、Trojan TLS、AnyTLS、按核心限定的 WS／gRPC，以及第35轮固定 Xray 的 XHTTP。各核心和对端的支持矩阵独立核对。 |
| 服务器分类 | 固定入口和独立入站的应用 TCP／UDP 规则、域名／后缀／CIDR、分类规则集、多个去向、直连与阻断；固定版本、差异更新、旧快照恢复和逐去向验收。UDP 缺少域名时按实际 IP 或默认策略处理。 |
| 独立端口转发 | TCP／UDP、IPv4／IPv6、来源白名单、多个独立监听与目标、UDP 会话隔离及真实回程验收；限定 TLS 场景发送 PROXY v1／v2。 |
| 转发主备 | VPS 侧显式主备、连续失败确认、稳定恢复及回切，支持 TCP 和 UDP DNS／回显。代理 TCP 运行时健康仅判断可达性；加密 UDP 主备、权重负载未加入。 |
| 跨实例线路 | 前置→中转→落地，双地址族 TCP、固定端口 Hysteria2／TUIC UDP、依赖与白名单、整链业务验收和分阶段补偿。支持共享实例的多线路管理。 |
| WireGuard | 受管双实例内核通道、每台两个独立槽位、三机两个相邻段同时加密、双向挑战、重启恢复和依赖保护。它不是订阅式 WireGuard VPN 入口。 |
| 来源与节点库 | 受管提取、手填、分享链接、Base64、现有 Mihomo／sing-box 配置及订阅来源；加密节点组复用、批量处理、跨方案差异同步。定时获取仅在桌面运行时更新缓存，不自动应用变更。 |
| 客户端输出 | Mihomo／Clash 与 May Route／sing-box 完整配置、受支持分享链接、保留入口依赖与高级参数的原生片段、完整导出差异、备份和外部改动保护。 |
| 模板库 | 不可变修订、参数与基础 DNS／规则／布局编辑、固定核心、依赖声明、应用预览、来源失效和范围恢复；新修订不自动替换使用中的方案。远程规则 URL 当前只做声明检查。 |
| 证书与资源 | Cloudflare DNS-01／Certbot 申请、VPS 自动续期、共享入站部署、授权替换、停用与清理；证书到期、使用者、间接影响及维护入口总览。第33轮真实公网签发尚未执行。 |
| 线路诊断 | 集中显示本机与远端分段、协议、HTTPS 出口、有限 UDP 回程、失败阶段、May Monitor 旁证及加密历史；按相同条件计算中位数、P95 和峰值。连接耗时不当成纯 RTT。 |
| 网络调优 | 角色、方向、双栈、流量预算与前后复测；fq／BBR、证据充分时的发送缓冲试调、固定预构建 Google BBR v3 内核升级与恢复。没有默认全局 HTB 整形。 |
| 监控配套 | May Monitor Server／Agent 的安装维护、凭据与地址调整、HTTPS 身份核对、只读指标、主题和独立 watchdog。历史、探测和告警由 Monitor 提供，公开展示由 May Status 提供。 |
| 操作与恢复 | 审阅后执行、来源变化使旧候选失效、取消、组件快照和恢复；确认丢失先核对事务状态，避免重放远端变更。 |

第39轮实例换址已在当前工作区完成源码及隔离验收：固定原 SSH 身份、同步下一跳／转发／双槽位隧道／白名单／客户端来源，分阶段验收并统一恢复。它尚未进入 v0.9.42 安装包，具体证据和外部维护边界见[换址指南](INSTANCE-ADDRESS-ROUND-39-2026-11-16.zh-CN.md)。

实际使用见[桌面手册](USER-GUIDE.zh-CN.md)、[配置与线路](CLIENT-AND-LINES.zh-CN.md)、[网络调优](NETWORK-TUNING.zh-CN.md)和[v0.9.42 发行检查](TESTING-0.9.42.zh-CN.md)。Monitor 持续监测与 Route 的 Windows 流量接管、运行时切换分别维护。

## 上次对照后已补齐的项目

| 第33至38轮 | 本次状态 |
| --- | --- |
| 33 通用证书生命周期 | 已发布 Cloudflare 托管证书申请、续期、共享部署与恢复；提供商范围和公网验收限制仍保留。 |
| 34 服务器应用 UDP 分类 | 已发布，不再列为“只能分类 TCP”。 |
| 35 XHTTP 服务器下一跳 | 已发布，不再与只完成入站或客户端配套混淆。 |
| 36 转发目标组主备 | 已发布显式主备，但没有完成通用负载均衡或加密 UDP 主备。 |
| 37 线路诊断工作台 | 已发布分段、协议、出口与质量历史；仍有回程识别和持续监测扩展空间。 |
| 38 可管理模板库 | 已发布固定版本、参数、依赖、差异和恢复；网址模板与脚本体系仍有区别。 |

## FlyX 已提供的能力与剩余差距

各项来源均固定到本次读取的提交。引用说明的是 FlyX 自身实现范围，不等于本项目已经完成其生产互通验收。

| 能力 | FlyX 当前范围 | Deploy 的现状与差距 |
| --- | --- | --- |
| 更多客户端及输入 | Surge、Shadowrocket、Stash、Loon、Quantumult X 等输出与导入入口；另有 Surge／Loon 节点行输入，各客户端保留协议差异。[客户端](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/subscription.md)、[导入](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/import.md) | 完整配置重点覆盖 Mihomo 与 May Route；没有把这些额外客户端逐项适配和验收。 |
| 常驻在线订阅 | 持续订阅 URL、按 UA 返回格式、多个节点组组合、链接重置。[订阅](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/subscription.md) | 已有订阅读取、本地方案与导出；没有常驻在线分发服务。 |
| 分发凭据与配额 | 支持协议的独立凭据、到期停用、流量上限与重置、流量历史；SS／Snell／WireGuard 和外部节点的共用凭据存在撤销及计量限制。[凭据与流量](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/subscription-users.md) | 入站多用户已有；没有订阅接收者的整套授权、到期和用量控制。 |
| 更多入站类型 | 普通 VLESS／Trojan TLS、WS／gRPC、Snell、NaïveProxy、ShadowTLS、VLESS Encryption、SOCKS／HTTP 及节点式 WireGuard 等。[协议矩阵](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/kernels.md) | 部分已有导入或下一跳能力，但没有对应的服务器部署、维护与恢复闭环。受管 WireGuard 通道不能算相同入口能力。 |
| 更多 ACME 方式 | sing-box 的 HTTP、Cloudflare、阿里云 DNS 申请方式。[证书范围](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/kernels.md) | 已有 Cloudflare／Certbot，尚未统一加入 HTTP-01 和其他 DNS 提供商。 |
| 多目标负载与真实来源 | 多入口、多个目标、realm 的轮询／IP 哈希、PROXY 发送与接收、按规则上下行统计。[转发](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/forward.md) | 已有多个独立端口映射和显式主备；第41轮源码新增同一入口轮询／来源 IP 哈希、健康摘除及会话固定，隔离验收完成，未发行。第42轮源码补齐可信 TCP PROXY v1／v2 接收、原端点透传及限定 TLS 目标，隔离验收完成，未发行；加权分配和同等转发用量历史仍未提供。 |
| 远程模板与处理 | 网址模板每日获取、失败保留缓存；节点组另有受限 JS 筛选／命名／排序。[模板](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/subscription-templates.md)、[处理](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/subscription-nodes.md) | 已有本地固定模板和结构化节点处理；网址模板获取／更新审阅未接入，没有任意 JS 处理体系。 |
| 出站双栈优先与回退 | 按入站选择自动、仅 IPv4、仅 IPv6、优先 IPv4、优先 IPv6，并区分直连和下一跳。[出站策略](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/routing.md) | 已有出口地址族字段和双栈测量；尚无统一的双栈优先顺序、失败回退与各路径一致维护闭环。 |
| 定时回程识别 | 定时路由追踪、双栈骨干网分类、历史和线路变化通知。[延迟与回程](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/latency.md) | 已有诊断工作台、Monitor 探测历史和告警；尚未统一提供同等回程分类及变化告警。回程追踪方向与用户实际访问方向须区分。 |
| 更多转发引擎与运行平台 | agent／realm／nftables 转发，Linux amd64／arm64、Alpine、Docker／Compose。[转发](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/forward.md)、[Agent](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/agent.md) | 正式运维验收面向 Debian 12／13 amd64；没有同等平台矩阵或可切换的多转发引擎。 |
| 跨面板共享 | 服务器可与其他 FlyX 面板互相分享用于转发。[共享](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/forward.md) | 已有本地受管实例共享线路，没有跨控制端联邦共享。 |
| 深度整形 | 固定 tcpfit 代码、限速器拐点扫描、HTB 全局上限与 fq pacing，带预算、验证和恢复。[调优](https://github.com/kure29/flyx/blob/0a73aca4579cf8f53a3ab1dcb88c6aef6d52de03/doc/guide/agent.md) | 已有真实路径、双向、预算和复测，但没有该全局整形闭环；现有设计有意不从单个测速结果自动施加全局限速，是否新增需另评估。 |

三项口径纠正：

1. FlyX 当前是单管理员面板，不能继续写成它已经提供通用 Web 多租户管理。订阅接收者的凭据和配额是另一层能力。
2. 当前转发说明明确移除了旧规则限速、最大连接数和每 IP 限制的下发；不能因旧源码、历史计划或数据库字段仍在就算作可用功能。
3. Deploy 已配套 May Monitor 与 May Status 的历史、告警和公开展示；FlyX 的一体化状态页不等于我们完全没有监测或状态展示。FlyX 文档同时明确其 XHTTP 客户端输出限制，不能仅按协议或格式数量判断覆盖是否完整。

本次还抽查了 FlyX 的 `capabilities.go`、`sub_template.go`、`subscription_template.go`、`subscription_traffic.go`、`forward_services.go` 和 `tuning_auto.go`，核对能力表、模板格式／每日刷新、流量历史、PROXY 双向配置以及固定 tcpfit 与预算实现。旧功能残留不作为新功能证据。

## 后续建议与执行边界

建议主线按第39至44轮推进，固定编号及完成目标写在[主线路线图](DEPLOY-ROADMAP-2026-10-24.zh-CN.md)：

1. **39：实例换址与依赖一致性。** 已完成工作区源码与隔离验收，尚未发行，见[第39轮](INSTANCE-ADDRESS-ROUND-39-2026-11-16.zh-CN.md)。
2. **40：转发协议健康与加密 UDP 主备。** 已完成工作区源码与隔离验收，显式授权、真实 HTTPS／出口和加密 UDP、资源及恢复，尚未发行；见[第40轮](FORWARD-PROXY-HEALTH-ROUND-40-2026-11-16.zh-CN.md)。
3. **41：多目标转发策略。** 工作区源码与隔离验收完成，未发行；见[第41轮](FORWARD-MULTI-TARGET-ROUND-41-2026-11-24.zh-CN.md)。权重按实际需求后置。
4. **42：PROXY 接收与真实来源。** 工作区源码与隔离验收完成，未发行；显式可信中转与客户端网段、TLS 目标、来源哈希、直连限制及恢复，见[第42轮](FORWARD-PROXY-RECEIVE-ROUND-42-2026-11-25.zh-CN.md)。
5. **43：远程模板与规则来源。** 获取缓存、产生固定修订、查看差异并审阅应用，不自动覆盖方案。
6. **44：出站地址族策略。** 完善优先 IPv4／IPv6 与建连回退，统一直连、下一跳和最终出口的核验。

第43至44轮仍为建议，未实施。新增客户端优先选择实际在用者；普通 TLS／WS／gRPC 部署、Snell／NaïveProxy／ShadowTLS、VLESS Encryption、更多 ACME 方式和 Linux 平台按需要确定下一组范围。定时回程与变化告警归监控支线。在线托管、分发配额、跨面板共享、任意 JS 和全局整形没有因本表自动进入近期主线；旧协议也不为补齐数量而新增。

能力对照以首次核对的 FlyX 提交为基线；后续第39、40、41轮进展在本页单列。正式版本、安装与生产状态分别记录，不因工作区源码完成而改变。
