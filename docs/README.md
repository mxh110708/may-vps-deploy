# May VPS Deploy 文档

当前教程基线：v0.9.38，Windows WinUI 3 → Debian 12／13 amd64。中文为主，[English overview](../README.en.md) 和 [English walkthrough](USER-GUIDE.en.md) 提供英文说明。

## 推荐阅读顺序

1. [项目首页](../README.md)：职责、平台、能力和未完成边界。
2. [桌面使用手册](USER-GUIDE.zh-CN.md)：安装、新部署、接入、通用入站和结果验收。
3. [客户端配置与线路](CLIENT-AND-LINES.zh-CN.md)：方案、业务分流、转发、编排和导出。
4. [维护手册](MAINTENANCE.zh-CN.md)：备份、更新、取消、确认不明、恢复和退役。

## 专项教程

| 主题 | 文档 |
| --- | --- |
| 组件与版本 | [版本维护](COMPONENT-UPGRADES.zh-CN.md) |
| 网络 | [测量和调优](NETWORK-TUNING.zh-CN.md)、[固定 BBR 内核构建与维护](GOOGLE-BBR-PREBUILT.zh-CN.md) |
| TLS／DNS | [Cloudflare 与 Certbot](CLOUDFLARE-CERTBOT.zh-CN.md)，具体动作仍以当前受管范围审阅。 |
| 监控 | [Server／Agent／HTTPS／主题](MONITOR-OPERATIONS.zh-CN.md)、[独立 watchdog](MONITOR-WATCHDOG.zh-CN.md) |
| 开发 | [开发与验证](DEVELOPMENT.zh-CN.md)、[安全](SECURITY.md)、[架构参考](DOTNET-ARCHITECTURE.zh-CN.md) |

## 历史、CLI 与证据

[历史索引](HISTORY.md)保留各轮协议、转发、监控、资源及迁移记录；[CHANGELOG](../CHANGELOG.md)保留版本沿革。[重构前首页](HISTORICAL-README-2026-10-27.zh-CN.md)只作历史参考。[旧命令行手册](CLI-REFERENCE.zh-CN.md)不描述当前桌面导航。

当前文档不包含真实实例、密码、Token 或私人目录材料。字段／格式合法、模拟判断、真实协议和长测分别证明不同事情；不能因为教程改成稳定版本就宣称补做过验证。
