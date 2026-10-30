# May VPS Deploy

面向 Debian VPS 的 Windows 部署与维护工具。通过 WinUI 3 桌面界面管理实例、代理服务、跨实例线路、客户端配置及 May Monitor，把审阅、实际验收、私人归档和失败恢复放进同一操作流程。

[English](README.en.md) · [下载发行版](https://github.com/mxh110708/may-vps-deploy/releases/latest) · [使用手册](docs/USER-GUIDE.zh-CN.md) · [文档目录](docs/README.md)

## 适用范围

正式桌面控制端为 Windows 10 2004 及以上／Windows 11 amd64；远端运维验收面向 Debian 12／13 amd64。安装版自带 .NET、WinUI 及专用配置转换运行时，日常使用不需要另外安装 PowerShell、Python 或 .NET SDK。其他系统、架构与自定义服务器布局需要独立验证。

当前文档以 **v0.9.39** 为基准；下载页面是获取新版本的入口。源码主分支可能包含尚未发行的文档或功能，不能用分支内容推断本机已安装版本。

本版纳入[第十五轮 Hysteria2 分享与端口跳跃](docs/HYSTERIA2-ROUND-15-2026-10-28.zh-CN.md)、[第十六轮 TUIC v5](docs/TUIC-ROUND-16-2026-10-28.zh-CN.md)、[第十七轮服务器 QUIC 下一跳](docs/SERVER-QUIC-ROUND-17-2026-10-28.zh-CN.md)、[第十八轮外部 WS／gRPC](docs/CLIENT-STREAMS-ROUND-18-2026-10-29.zh-CN.md)、[第二十轮 XHTTP 客户端配套](docs/XHTTP-ROUND-20-2026-10-29.zh-CN.md)、[第二十一轮双地址族 TCP／限定 UDP 编排](docs/CHAIN-ROUND-21-2026-10-30.zh-CN.md)和[第二十二轮 WireGuard 双实例通道](docs/WIREGUARD-ROUND-22-2026-10-30.zh-CN.md)。XHTTP 已扩展四模式、合法 HTTP 版本、独立下载身份及高级字段，使用配套 May Core／可等价表达的 Mihomo；跨实例 UDP 限固定端口 Hysteria2／TUIC。原第十九轮有限范围作为历史保留，不能推断当前安装或公网 CDN 支持。

## 能做什么

| 工作 | v0.9.39 发行基线的能力与边界 |
| --- | --- |
| 实例生命周期 | 新机部署、受支持布局的已有实例接入、SSH 身份核对、健康审计、维护、恢复与退役。 |
| 代理入站 | Reality、AnyTLS、SS2022、Hysteria2、TUIC v5 及限定 XHTTP 组合；独立管理监听、用户、证书、出站和恢复范围。 |
| 服务端线路 | TCP／UDP 转发、经 Shadowsocks／SS2022 的 UDP 验收、双地址族 TCP／限定 UDP 前置→中转→落地编排及 WireGuard 双实例通道；不是任意协议的通用多跳控制器。 |
| 客户端配置 | 生成 Clash／Mihomo 和 sing-box 配置；方案、节点来源、地区组、路由分类、校验、导出及变更后的来源复核。 |
| 网络维护 | 测量与建议、fq／BBR 配置、固定预构建 Google BBR v3 内核的显式升级与恢复。 |
| May Monitor | 独立 Server／Agent 生命周期、HTTPS 来源核对、受限只读查看、固定静态主题维护；完整历史、探测和告警管理由监控 Web 提供。 |
| 操作保护 | 先审阅后写入，限定组件快照与恢复，凭据加密归档；连接中断后的确认不明先核对身份和状态，不自动重复执行。 |

Hysteria2 的部署与验收不代表 TCP 转发支持 QUIC。TUIC 与限定 UDP 整链编排适用上列边界；服务商 ATT IPv6 租约申请、任意 UDP 多跳、用户计费及在线订阅托管不属于当前能力。详细范围见[配置与线路](docs/CLIENT-AND-LINES.zh-CN.md)。

节点组可保存为加密快照，并在多个方案中复用、差异同步和解除关联；来源变化后必须重新生成、校验。使用步骤见[节点组与输出](docs/CLIENT-GROUPS-ROUND-23-2026-10-30.zh-CN.md)。

## 快速开始

1. 从本仓库 Release 下载 Windows amd64 安装包或便携 ZIP，并对照同次发行的 `SHA256SUMS.txt`。不要把源码 ZIP 当作应用包。
2. 安装并打开 **May VPS Deploy**。安装器默认目录为 `C:\Programs\May VPS Deploy`，可选择其他可写目录；更新已有安装时保留原位置。
3. 在「部署」选择新机、接入已有实例或追加安装。准备当前 SSH 密码／私钥、主机指纹及服务商恢复控制台。已有业务的机器先只读检查，不能当作干净新机。
4. 审阅实例、监听、协议、证书、白名单、影响范围、归档位置及验收步骤后执行。
5. 任务成功后核对实际服务与真实协议连接；到「配置设计」生成并校验候选，再审阅导出到自己的权威配置文件。

完整步骤、预期结果和失败处理见[桌面使用手册](docs/USER-GUIDE.zh-CN.md)。浏览表单和生成本地候选不等于已部署或已发布配置。

## 项目如何配合

- **Deploy** 操作服务器并保存私人运维档案；关闭桌面不应停止已部署服务。
- [**May Monitor**](https://github.com/mxh110708/may-monitor-server) 负责采集、历史、探测与告警；[May Status](https://github.com/mxh110708/may-monitor-theme-status) 是其公开展示主题。
- [**May Route**](https://github.com/mxh110708/may-route-desktop) 在 Windows 使用代理配置、接管流量并按实际使用入口进行故障切换。监控告警不会自动授予 Deploy 或 Route 改路由的权限。

账号、协议名和上游 Go 模块名是不同于产品名称的标识；`mxh110708` 仍是仓库所属账号。

## 文档阅读顺序

| 需要做什么 | 文档 |
| --- | --- |
| 第一次安装和接入实例 | [桌面使用手册](docs/USER-GUIDE.zh-CN.md) |
| 生成配置、搭建转发和多跳线路 | [配置与线路](docs/CLIENT-AND-LINES.zh-CN.md) |
| 升级、备份、恢复和排错 | [维护手册](docs/MAINTENANCE.zh-CN.md) |
| 安装或维护监控 | [May Monitor 运维](docs/MONITOR-OPERATIONS.zh-CN.md)、[独立检查](docs/MONITOR-WATCHDOG.zh-CN.md) |
| 构建和修改源码 | [开发与验证](docs/DEVELOPMENT.zh-CN.md) |
| 查具体轮次的验证证据 | [历史记录索引](docs/HISTORY.md)、[更新记录](CHANGELOG.md) |

## 数据与反馈

私人数据默认位于应用目录下的 `private/`，包含实例、加密凭据、方案、恢复材料和任务记录。不要把它当作可重建缓存，也不要将 DPAPI 加密文件当作可跨用户直接搬运的明文备份。外部 root 密码、私钥和 Cloudflare 令牌应在各自私密位置管理，不能放入仓库或公开问题截图。

反馈请附应用版本、Windows／Debian 版本、操作入口、阶段、错误代码及脱敏日志。服务启动、配置解析、隔离测试、真实连接与长测分别证明不同事情；本项目不承诺所有机器都有相同资源占用或线路质量。

第三方材料见[组件授权说明](vendor/test-cores/windows-amd64/THIRD-PARTY-NOTICES.md)及各随附许可；本仓库未单独提供项目根许可证文件，不把第三方许可当作整个项目的授权声明。贡献或运维前阅读[安全边界](docs/SECURITY.md)。
