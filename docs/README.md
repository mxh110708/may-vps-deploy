# May VPS Deploy 文档

当前教程基线：**v0.9.42**，Windows WinUI 3 → Debian 12／13 amd64。中文为主，[English overview](../README.en.md) 和 [English walkthrough](USER-GUIDE.en.md) 提供英文说明。

本版汇总主线第33至38轮；使用入口、参数、依赖和恢复范围见下方专项教程，汇总验证见[发行记录](TESTING-0.9.42.zh-CN.md)。历史各轮的真实回环、Debian 整机和公网证据分别保留，不因发行而扩大。

2026-11-16 的[能力盘点与 FlyX 对照](CAPABILITIES-AND-FLYX-2026-11-16.zh-CN.md)记录当前剩余差距；[第39轮实例换址](INSTANCE-ADDRESS-ROUND-39-2026-11-16.zh-CN.md)已完成工作区源码和隔离验收，纳入 v0.9.43。[主线路线图](DEPLOY-ROADMAP-2026-10-24.zh-CN.md)保留第39至44轮实现与验收范围；[第40轮](FORWARD-PROXY-HEALTH-ROUND-40-2026-11-16.zh-CN.md)同样为已完成并纳入 v0.9.43。

[第41轮多目标策略](FORWARD-MULTI-TARGET-ROUND-41-2026-11-24.zh-CN.md)已完成同一入口的轮询、来源 IP 哈希及健康摘除与隔离验收，纳入 v0.9.43。

[第42轮可信 PROXY 接收](FORWARD-PROXY-RECEIVE-ROUND-42-2026-11-25.zh-CN.md)已完成受信中转、原来源透传、TLS 目标及恢复的源码与隔离验收，纳入 v0.9.43。

## 推荐阅读顺序

1. [项目首页](../README.md)：职责、平台、能力和未完成边界。
2. [桌面使用手册](USER-GUIDE.zh-CN.md)：安装、新部署、接入、通用入站和结果验收。
3. [客户端配置与线路](CLIENT-AND-LINES.zh-CN.md)：方案、业务分流、转发、编排和导出。
4. [维护手册](MAINTENANCE.zh-CN.md)：备份、更新、取消、确认不明、恢复和退役。

## 专项教程

| 主题 | 文档 |
| --- | --- |
| 可信 PROXY 接收 | [第42轮：中转信任、客户端来源、实际路径与恢复](FORWARD-PROXY-RECEIVE-ROUND-42-2026-11-25.zh-CN.md)，当前源码，未发行。 |
| 多目标转发策略 | [第41轮：轮询、来源 IP 哈希、健康摘除与会话固定](FORWARD-MULTI-TARGET-ROUND-41-2026-11-24.zh-CN.md)，当前源码，未发行。 |
| 协议健康与加密 UDP 主备 | [第40轮：授权、真实业务健康、资源与恢复](FORWARD-PROXY-HEALTH-ROUND-40-2026-11-16.zh-CN.md)，当前源码，未发行。 |
| 实例换址 | [第39轮：原身份、依赖、分阶段同步与统一恢复](INSTANCE-ADDRESS-ROUND-39-2026-11-16.zh-CN.md)，当前源码，未发行。 |
| 模板版本与恢复 | [第38轮：参数、基础配置、依赖、应用差异与恢复](CLIENT-TEMPLATES-ROUND-38-2026-11-14.zh-CN.md) |
| 线路诊断 | [第37轮：分段、协议、出口、旁证与质量历史](ROUTE-DIAGNOSTICS-ROUND-37-2026-11-14.zh-CN.md) |
| 转发主备 | [第36轮：显式顺序、健康确认与稳定恢复](FORWARD-TARGET-GROUPS-ROUND-36-2026-11-13.zh-CN.md) |
| XHTTP 下一跳 | [第35轮：固定 Xray 投影、上下行身份与验收](SERVER-XHTTP-ROUND-35-2026-11-13.zh-CN.md) |
| 应用 UDP 分类 | [第34轮：协议范围、缺失域名、实际回程与恢复](APPLICATION-UDP-ROUND-34-2026-11-13.zh-CN.md) |
| 托管证书 | [第33轮：申请、续期、共享部署与恢复](CERTIFICATES-ROUND-33-2026-11-12.zh-CN.md) |
| 节点批量与输出 | [第三十二轮：批量操作、原生片段、完整配置差异](CLIENT-BATCH-OUTPUT-ROUND-32-2026-11-03.zh-CN.md) |
| 下一跳扩展 | [第二十九轮：常用协议、核心矩阵与参数审阅](SERVER-STREAM-NEXT-HOPS-ROUND-29-2026-11-02.zh-CN.md)。 |
| 独立入站分类 | [第二十八轮：独立入站分类与多出站策略](INBOUND-POLICY-ROUND-28-2026-11-02.zh-CN.md)，纳入 v0.9.41。 |
| 分享与往返 | [第二十七轮：TUIC、TLS TCP、Base64和原生输出](CLIENT-OUTPUT-ROUND-27-2026-11-02.zh-CN.md) |
| 节点组 | [保存、复用、同步与输出一致性](CLIENT-GROUPS-ROUND-23-2026-10-30.zh-CN.md) |
| v0.9.40 新功能 | [第二十四轮：WireGuard 接入三实例线路](CHAIN-WIREGUARD-ROUND-24-2026-11-01.zh-CN.md)、[第二十五轮：来源与跨方案同步](SOURCE-SYNC-ROUND-25-2026-11-01.zh-CN.md)、[第二十六轮：服务器分类规则与版本恢复](SERVER-RULESETS-ROUND-26-2026-11-01.zh-CN.md)，以及[追加的共享实例多线路管理](SHARED-CHAINS-ROUND-25-2026-11-01.zh-CN.md)，纳入 v0.9.40；v0.9.39 安装包不包含这些功能。 |
| 组件与版本 | [版本维护](COMPONENT-UPGRADES.zh-CN.md) |
| 网络 | [测量和调优](NETWORK-TUNING.zh-CN.md)、[固定 BBR 内核构建与维护](GOOGLE-BBR-PREBUILT.zh-CN.md) |
| TLS／DNS | [Cloudflare 与 Certbot](CLOUDFLARE-CERTBOT.zh-CN.md)，具体动作仍以当前受管范围审阅。 |
| 监控 | [Server／Agent／HTTPS／主题](MONITOR-OPERATIONS.zh-CN.md)、[独立 watchdog](MONITOR-WATCHDOG.zh-CN.md) |
| 开发 | [开发与验证](DEVELOPMENT.zh-CN.md)、[安全](SECURITY.md)、[架构参考](DOTNET-ARCHITECTURE.zh-CN.md) |
| v0.9.39 新功能 | [第十五轮 Hysteria2 分享与端口跳跃](HYSTERIA2-ROUND-15-2026-10-28.zh-CN.md)、[第十六轮 TUIC v5](TUIC-ROUND-16-2026-10-28.zh-CN.md)、[第十七轮服务器 QUIC 下一跳](SERVER-QUIC-ROUND-17-2026-10-28.zh-CN.md)、[第十八轮外部 WS／gRPC](CLIENT-STREAMS-ROUND-18-2026-10-29.zh-CN.md)、[第二十轮 XHTTP 完整客户端配套](XHTTP-ROUND-20-2026-10-29.zh-CN.md)、[第二十一轮双地址族 TCP／限定 UDP 编排](CHAIN-ROUND-21-2026-10-30.zh-CN.md)、[第二十二轮 WireGuard 双实例通道](WIREGUARD-ROUND-22-2026-10-30.zh-CN.md)、[主线后续计划](DEPLOY-ROADMAP-2026-10-24.zh-CN.md) |

## 历史、CLI 与证据

[历史索引](HISTORY.md)保留各轮协议、转发、监控、资源及迁移记录；[CHANGELOG](../CHANGELOG.md)保留版本沿革。[重构前首页](HISTORICAL-README-2026-10-27.zh-CN.md)只作历史参考。[旧命令行手册](CLI-REFERENCE.zh-CN.md)不描述当前桌面导航。

当前文档不包含真实实例、密码、Token 或私人目录材料。字段／格式合法、模拟判断、真实协议和长测分别证明不同事情；不能因为教程改成稳定版本就宣称补做过验证。

第43轮[远程模板与规则来源](REMOTE-LIBRARY-ROUND-43-2026-11-25.zh-CN.md)、第44轮[统一出站地址族](OUTBOUND-ADDRESS-ROUND-44-2026-11-25.zh-CN.md)及[本版发行验证](TESTING-0.9.43.zh-CN.md)。
