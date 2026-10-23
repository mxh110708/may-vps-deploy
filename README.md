# May VPS Deploy

面向个人 Debian VPS 的中文部署与运维工具，由 Windows 控制端统一管理部署计划、远端操作、私有归档和客户端配置。

v0.9.35 补齐校园、学术数据库及全文下载链路的业务分类与 DNS，Scholar 等研究平台和 ML 开发工具不再按厂商或 AI 主题粗略归组；国内校园入口明确直连，两种真实核心已完成隔离分流验证。见[分类审查](docs/ACADEMIC-ROUTING-AUDIT-2026-10-23.zh-CN.md)、[此前 Hugging Face 修复](docs/HUGGINGFACE-RESEARCH-ROUTING-2026-10-22.zh-CN.md)及[发行范围](docs/TESTING-0.9.35.zh-CN.md)。ExistingAuthority 仍保持显式修改边界。

v0.9.34 整合七轮配置与链路扩展：分享链接导入、来源刷新与差异预览、输出处理、连接图和按需诊断；Reality / AnyTLS 的服务器固定落地、TCP 目的地及多落地分流；新增按输出规则复制或保存分享列表。每个落地分别验收，无法完整表达的客户端链路和 ECH 参数不会被静默删除。详见[设计与实施索引](docs/FLYX-DESIGN-REVIEW-2026-10-20.zh-CN.md)、[第七轮分享导出](docs/CLIENT-SHARE-ROUND-7-2026-10-21.zh-CN.md)和[发行验证](docs/TESTING-0.9.34.zh-CN.md)。

v0.9.31 将项目与应用统一更名为 May VPS Deploy，采用独立安装身份、私人归档目录和凭据加密格式。旧版由用户自行卸载；迁移前先备份，再导入新目录。GitHub 账号保持不变。详见[全新安装迁移说明](docs/BRAND-MIGRATION-2026-10-20.zh-CN.md)。

v0.9.30 统一新方案的城市/湾区命名：LA 入口与 SF 湾区入口分别建组，SF 包含 San Jose。IPv4、IPv6 落地出口可分别保存节点名，避免重新提取时恢复旧名称；改名保留原连接与凭据。详见[命名约定与归档同步](docs/CITY-NAMING-2026-10-19.zh-CN.md)。

正式版为 [v0.9.35](https://github.com/mxh110708/may-vps-deploy/releases/tag/v0.9.35)，提供 Windows EXE 安装包。此前的 WPF 原生入口 v0.7.0 已撤销发行，源提交保留。

v0.9.28 将 BBR v3 改用 Google 官方 `google/bbr` v3 源码。固定版由 May 在开发机预编译，内核包、通用配置和校验清单随应用提供，小 VPS 只接收、验证和安装；不提供最新提交选择或 VPS 在线编译，固定包随应用版本更新。审阅展示真实基础版本、日期、提交及包 SHA256，不标作 Google 官方二进制或最新 LTS。旧版 XanMod 来源及其事务兼容处理已移除；默认仍沿用 VPS 原有内核。详见[网络调优流程](docs/NETWORK-TUNING.zh-CN.md)、[预编译维护](docs/GOOGLE-BBR-PREBUILT.zh-CN.md)及[安装启动验证](docs/GOOGLE-BBR-PREBUILT-2026-10-16.zh-CN.md)。下方 v0.9.16–v0.9.18 的内核发行、签名与 LTS 描述属于当时的第三方实现。

v0.9.21 继续全局审查并修复 16 项边界与功能问题：修正本机 Reality 证书及端口校验，接入时识别独立端口共存入口；首次部署和 SSH 恢复保留其他防火墙表，证书恢复限定受管域名，原生部署恢复不重放未修改的网络参数，补齐配置恢复兼容性、备份清理锁及初始公钥追加。导出保护应用及私人材料，调度等待审阅结束，健康检查覆盖本机证书与续期；同步修正 Agent 地址、分组生成及退役后证书复用。详见[全局审查与验证记录](docs/TESTING-0.9.21.zh-CN.md)。

v0.9.20 修复全项目审查发现的 17 项跨功能边界问题：防火墙只修改受管表，网络配置与恢复限定本轮对象，客户端来源按实际连接校验，删除及重命名同步导出引用，Shadowsocks 通过可信入口验收；补齐证书来源隔离、备用入口验收、主控恢复状态、历史内核复用、卸载归档清理及首屏健康提示。详见[修复与验证记录](docs/TESTING-0.9.20.zh-CN.md)。

v0.9.19 补齐新部署和追加安装的固定版/官方最新版选择，在审阅前锁定版本与 SHA256；补齐网络回退的原文件权限，后台测试沿用正常启动的计划核对。AnyTLS 完整调优、无收益回退、主动取消、定时计划分支及官方最新版主控追加安装已实测，详见[本轮记录与边界](docs/TESTING-0.9.19.zh-CN.md)。

v0.9.18 为 Xray、sing-box、Komari Agent/主控及 cloudflared 增加固定版与官方最新稳定版选择，查询后锁定版本、资产及 SHA256，再审阅升级。受管 BBR v3 可以直接升级到更新的兼容 LTS，并分别回退上一版或 VPS 原有内核；修正 Reality 备用端口为 0 时的安装与验收。详见[组件版本维护](docs/COMPONENT-UPGRADES.zh-CN.md)与[实测记录](docs/TESTING-0.9.18.zh-CN.md)。

v0.9.17 补齐 Debian 13 的 sqv 签名验证及含 `+` 的 GRUB 内核标识，保留兼容性与仓库错误的具体原因。详见[实测记录](docs/TESTING-0.9.17.zh-CN.md)。

v0.9.16 增加可选 BBR v3 内核管理，默认沿用 VPS 原有内核；当时的固定版和联网兼容 LTS 来自 XanMod 第三方发行。独立审阅安装与重启，通过运行版本、原服务和主/救援 SSH 验收后才提交，保留旧内核及回退入口。时区支持常用选项和自定义输入，高峰说明实时更新，支持结束时间 24 和跨午夜。历史实测见[记录](docs/TESTING-0.9.16.zh-CN.md)。

v0.9.15 重构网络调优：入口机自动采集 RTT、吞吐、延迟和资源，结合套餐与时段生成建议，应用后复测，未确认收益时恢复；落地机仅启用 fq 与可用 BBR。加入应用内一次性晚高峰补测，测量和配置进度直接显示在主页面。详见[使用说明](docs/NETWORK-TUNING.zh-CN.md)与[实测结果及边界](docs/TESTING-0.9.15.zh-CN.md)。

v0.9.14 修正托盘恢复后的标题栏交互状态，兼容证书 DNS Token 的单行与 Certbot 凭据格式；补做首次部署中断恢复、专用令牌吊销与轮换、隔离安装更新及 Komari 真实备份副本验证，详见[结果与边界](docs/TESTING-0.9.14.zh-CN.md)。此前的双栈证书出口与恢复修正见 [v0.9.13](docs/TESTING-0.9.13.zh-CN.md)。窗口居中、位置大小记忆及节点拖动修正见 [v0.9.11 实测记录](docs/TESTING-0.9.11.zh-CN.md)。

v0.9.10 调整 Tunnel 流程：先安装并连接，再按实例页指引配置公开路由、验证 HTTPS 访问；组合安装先启动主控与 Tunnel，再提示创建节点并提供 Agent Token。重做节点拖动排序，扩大手柄，整行跟随并显示序号与落点高亮，支持边缘滚动和取消；修正 Tunnel 更新后未同步本地加密 Token 的问题。专用 Tunnel 的公开访问、登录退出、WebSocket 持续指标、主控恢复与错误 Token 回滚已实测，详见[结果与边界](docs/TESTING-0.9.10.zh-CN.md)。

v0.9.8 支持一次勾选多个组件追加安装，统一审阅与恢复、逐项显示进度；修复节点手柄拖动排序，并可设置关闭窗口时最小到托盘或直接退出。已有受管实例可追加 Reality、AnyTLS / ECH、Shadowsocks、Komari Agent、Komari 主控和 Cloudflare Tunnel，保留既有服务与管理连接；端口冲突先停止，本轮失败或取消一并恢复新增组件。详见[追加安装与部署过程说明](docs/COMPONENT-INSTALLATION-2026-10-08.zh-CN.md)。

v0.9.7 加入 [B 方案后台实测接口](docs/BACKGROUND-TESTING.zh-CN.md)，以独立原生实例驱动实际表单、审阅与部署，不占鼠标或前台窗口。v0.9.8 完成组合追加 SS 与主控及取消恢复实测；v0.9.9 修复 AnyTLS 服务与 Xray 的冲突定义，并补做真实 DNS 证书、续期、ECH 与双核心联网验收。各轮结果分别见 [v0.9.8](docs/TESTING-0.9.8.zh-CN.md) 和 [v0.9.9](docs/TESTING-0.9.9.zh-CN.md)。

v0.9.6 修正 Windows 管理密钥权限准备失败，普通账号即可完成；密钥准备提前到远端变更之前。已有待恢复基线需在实例页核对恢复状态，明确恢复部署前基线后再继续草稿；恢复使用当时实际可用的登录方式。任务结束立即刷新实例状态，避免继续显示旧错误。

v0.9.4 支持修改并迁移私人归档目录，节点选择提供全选、取消全选及备用入口显式选择；健康检查补齐旧监控归档的纳管状态。使用方式见 [桌面版说明](docs/DESKTOP.zh-CN.md)。

v0.9.2 修正首次 SSH 身份确认占用连接超时的问题，保留具体失败原因并正确结束步骤状态；补齐节点默认命名、条件监控字段、详细部署审阅、草稿续作和本地删除实例。详见 [部署体验修正](docs/DEPLOYMENT-FIXES-2026-10-08.zh-CN.md)。

v0.9.1 增加独立更新弹窗，在同一窗口显示 GitHub 更新内容、下载与 SHA-256 校验进度，并显示安装进度窗口；同时修正检查结束后的状态，调整新安装的默认路径与“关于”图标。v0.9.0 引入的 sing-box / Clash 独立点亮目标、四类字号、多用途部署与独立网络调优见 [桌面调整说明](docs/DESKTOP-ADJUSTMENTS-2026-10-07.zh-CN.md)。安装版可通过应用内检查更新原位升级，保留私人数据；桌面发行不再同步旧命令行使用目录。

桌面采用 **WinUI 3 界面 + C#/.NET 共享运维核心 + Windows 适配层**，提供深浅两种配色、原版与霞鹜文楷两套内置字体及自定义字体导入。安装版通过“设置 → 检查更新”下载、校验、原位安装并自动重启，保留私人数据和本地配置，无需卸载重装。参见 [桌面版使用与数据目录](docs/DESKTOP.zh-CN.md) 和 [架构与边界](docs/DOTNET-ARCHITECTURE.zh-CN.md)。

支持新机部署、已有实例接入、协议管理、网络调优、维护恢复及实例退役。交互向导负责收集与确认，远端 Bash 模块负责执行，计划与状态文件用于继续任务和核对结果。

## 项目基准

- **兼容性**：明确支持范围，尊重已有实例的配置选择；遇到不兼容条件先提示，不隐式切换协议或接管防火墙。
- **稳定性**：关键变更使用快照、回滚保护和结果复验；区分已通过、用户跳过与尚未完成，不把服务启动当成完整验收。
- **易用性**：桌面按实例和任务组织表单、按钮和结果，支持返回、默认值与帮助；复杂参数和恢复限制放在具体操作提示及使用手册中。

这些是实现与审计基准，不代表所有环境和故障场景都已验证。离线测试、远端模拟和真实 VPS 验收各有边界。

## 快速开始

### 1. 准备环境

| 项目 | 支持范围或要求 |
|---|---|
| 新桌面控制端 | Windows 10 2004 / Windows 11，amd64；内置 .NET 与 WinUI 3 |
| 源码构建 | .NET SDK 10.0.400；打包与旧命令行测试需要 PowerShell 7.4+ |
| SSH 工具 | 新桌面使用 SSH.NET 直接连接；不依赖 PowerShell 或 OpenSSH 进程 |
| 目标 VPS | Debian 12/13，amd64，使用 systemd 和 apt |
| 初始登录 | 可用的 root SSH 登录方式：密码或已有 OpenSSH 私钥 |
| 客户端配置设计器 | 安装版内置 Python 3.13.16 与固定 YAML 依赖；源码开发需要 Python 3.9+ |

源码开发或未打包的命令行使用者安装客户端构建依赖：

```powershell
python -m pip install -r .\requirements-client-merge.txt
```

Debian 是远端目标环境，不是控制端运行平台。操作前请保留服务商控制台或其他恢复入口；服务商安全组需要自行放行。

### 2. 本地自检

源码开发者在项目目录打开 PowerShell，运行既有命令行回归和新增共享核心回归：

```powershell
pwsh -NoProfile -File .\Start-VPSDeploy.ps1 -Mode ValidateProject
dotnet run --project .\desktop\May.VpsDeploy.Tests -c Release -- $PWD
```

自检不连接 VPS，检查项目文件、脚本和离线测试；通过不等于真实服务器或代理连接已经验收。

### 3. 启动工具

在正式发行页下载 `may-vps-deploy-v0.9.28-windows-amd64-setup.exe`，按同页 `SHA256SUMS.txt` 核对后安装，通过桌面／开始菜单启动。便携 ZIP 解压后双击 `May-VPS-Deploy.exe`；需要应用内原位更新时使用安装版。源码可先构建预览：

```powershell
pwsh -NoProfile -File .\scripts\New-VpsReleasePackage.ps1 -Development -Destination '<预览输出目录>'
```

保留原命令行入口 `Start-VPSDeploy.Cli.cmd`，脚本自动化继续使用：

```powershell
pwsh -NoProfile -File .\Start-VPSDeploy.ps1
```

## 按任务选择入口

| 桌面页面 | 使用方式 |
|---|---|
| **概述** | 查看本地记录，进入部署、接入或配置设计 |
| **实例** | 先选择实例，再进入运维、协议管理、继续部署或恢复 |
| **部署** | 新机用途可组合，接入已有 VPS 保留现有配置；审阅后执行 |
| **配置设计** | 点亮 sing-box / Clash 目标，编辑节点与连接关系，生成、校验并导出 |
| **网络调优** | 入口机自动采集并生成建议；落地机仅启用 fq＋可用 BBR；部署不自动调优 |
| **记录** | 查看任务结果，核对并恢复未完成的配置导出 |
| **设置** | 深浅模式、字体与四类字号、检查更新及数据位置 |

“继续未完成部署”需要已有 `deployment-plan.json`。尚未纳管的实例先在部署页接入，已纳管的实例在实例页选择后管理。旧归档由维护者离线转换，应用不提供一次性导入入口。

### 命令行交互约定

命令行主菜单依次提供新部署、继续、接入、协议管理、运维、网络参数、客户端配置、本地自检和退出。以下约定仅适用于 `Start-VPSDeploy.Cli.cmd` 和命令行脚本：

- 主菜单用 `9` 退出；子菜单、向导和确认页用 `0` 返回。
- 如果字段允许数值 `0`，提示中会说明，改用 `/back` 返回。
- 直接回车采用显示的默认值；`clear` / `cls` 清屏，`help` / `h` / `?` 查看帮助。
- `b`、`back` 是普通输入，不是返回命令。
- 只有明确提示支持的字段才将 `!empty` 解释为清空默认值。
- 向导回退保留适用的非敏感输入；敏感值不回显，必要时需要重新填写。

## 功能与边界

下列详细协议与维护说明同时覆盖成熟命令行。新 WinUI 版本开放新机部署、只读接入、多组件追加安装、健康检查、独立网络调优、已安装协议启停/切换/卸载、固定版本升级、凭据轮换、按协议范围恢复、Agent 升级/卸载、主控备份/升级/恢复、Tunnel Token 轮换和受管实例退役。主控整套卸载及旧归档转换仍由维护者按明确任务处理。

### 部署与接入

新部署支持密码引导或复用服务商私钥。复用时默认建立实例规范副本，不修改源私钥或轮换服务器公钥；只有密码引导或明确选择时才生成新的管理密钥。

新部署创建 `admin` 并配置公钥登录。初始为低位 SSH 端口时迁移到随机高位主、救援端口；已有非特权高位端口时复用为主端口，再新增救援端口。

已有实例接入默认保留当前 SSH 认证策略、端口和防火墙，只识别标准路径中的受支持协议，不是任意第三方面板配置的迁移工具。

### 代理协议

| 协议 | 用途与特点 | 共存限制 |
|---|---|---|
| Xray VLESS + REALITY + Vision | 入口；外部目标或本机静态 HTTPS 目标 | 与 AnyTLS 可同时安装，只能启用一个 |
| sing-box AnyTLS + TLS + ECH | 入口；公共 CA 证书、DNS-01 与自动续期 | 与 Reality 共用 TCP 443 |
| sing-box Shadowsocks 2022 | 多用户落地；独立高位 TCP/UDP 端口 | 可与入口协议同时运行 |

外部 Reality 目标会检查 TCP、TLS 1.3、h2、证书及连接耗时。自动门槛未通过时，默认要求更换，也支持明确确认并记录原因后继续。

AnyTLS 和 Reality 本机 HTTPS 目标的准备步骤，见[证书与域名配置手册](docs/CLOUDFLARE-CERTBOT.zh-CN.md)。

### 网络与真实连接验收

- 新部署在审计确认的干净 VPS 上应用最小 nftables；Shadowsocks 按可信入口地址限制访问。
- WinUI 网络调优：落地机仅启用 fq＋可用 BBR；入口机自动采集实际 TCP RTT、吞吐、延迟和资源，依据标称套餐与测试时段生成建议，应用后复测，未确认收益时恢复。无需手填 RTT。详见[网络调优流程与边界](docs/NETWORK-TUNING.zh-CN.md)。传统 CLI 的历史模式保持原流程。
- Reality / AnyTLS 使用稳定版 Mihomo 和 sing-box，按地址族测试真实握手、HTTPS、出口 IP 与 UDP；Shadowsocks 支持自测及可信入口链式探测。
- 项目携带 Windows amd64 测试核心及校验值，解压到 `.cache/client-cores/`，不读取 Clash Verge 安装、PATH 中的代理核心或注册表。
- 核心不可用时可按提示重试、手动选择或明确跳过。本机 IPv6 验收路径不可用时，可选择受支持的外部验收路径或明确跳过。跳过记为 `SkippedByUser`，不算通过；非交互模式不能自动跳过。

### 运维与恢复

运维中心提供健康审计和配置漂移检查、代理凭据轮换、SSH 与防火墙维护、组件更新、Komari 管理及分级退役。

关键维护操作建立本地和远端备份，并使用远端回滚保护。中断后先进入“处理未完成的维护操作”，核对服务器状态并同步本地记录；不能把本地失败直接当成远端未执行。

| 操作 | 重要边界 |
|---|---|
| 只恢复配置 | 保留当前版本、服务启停和防火墙；协议集合、端口或证书设置不兼容时拒绝恢复。涉及正在运行的 nginx 时，检查后重新加载 |
| 完整恢复协议相关文件和设置 | 不是系统重装，不恢复旧 SSH 身份；备份的 SSH 端口与当前不同会拒绝加载历史防火墙，恢复后重新验证管理入口 |
| 更新代理服务 | 重启目标服务并核对运行进程使用的二进制，再做连接验收；停用备用协议须先启用或切换后再更新 |
| 选择更新版本 | 通常使用 `config/versions.json` 的固定资产，不等于官方最新版；Xray 还可保持计划版本或解析官方最新稳定版，并记录实际版本 |
| 审计已有 SSH 策略 | 尊重纳管时明确保留的认证策略，但关闭公钥认证仍视为严重异常 |
| 退役 | 分级清理受管组件，保留 SSH 和基础系统，不删除服务商实例 |

### 配置设计

节点页支持批量分享链接预览导入（VLESS Reality + Vision、AnyTLS、Shadowsocks），连接页分别展示入口、落地和网站出口地址族，并可按具体路径执行可取消的轻量诊断。仍沿用生成、核心校验和审阅导出流程；详情见[第一轮配置设计扩展](docs/CLIENT-ROUTES-ROUND-1-2026-10-20.zh-CN.md)。

第二轮增加可预览的输出筛选、显示名处理与排序、分客户端能力报告，以及可取消的手动订阅获取和刷新。来源更新保留稳定节点身份并阻止本地冲突覆盖；详见[第二轮输出与来源扩展](docs/CLIENT-OUTPUT-ROUND-2-2026-10-20.zh-CN.md)。

第三轮在实例维护页增加服务器固定下一跳：先支持 AnyTLS 入站经 Shadowsocks / SS2022 落地出网，提供独立审阅、组件恢复点、配置漂移检查、实际出口与 UDP 验收，以及恢复原出口策略的移除操作。详见[第三轮服务器出站](docs/SERVER-OUTBOUND-ROUND-3-2026-10-21.zh-CN.md)。

第四轮将固定下一跳扩展到 Xray Reality，覆盖其主备端口和双栈监听；增加来源变化、缺失与受管凭据变化提示，并检查升级、轮换和恢复时保留链路及其他组件。详见[第四轮 Reality 与链路维护](docs/REALITY-OUTBOUND-ROUND-4-2026-10-21.zh-CN.md)。

第五轮增加有顺序的服务器 TCP 域名／CIDR 分流例外、直连／落地／阻断、匹配试算和组件草稿隔离；UDP 保持原固定落地。详见[第五轮目的地分流](docs/SERVER-DESTINATION-RULES-ROUND-5-2026-10-21.zh-CN.md)。

第六轮增加服务器 TCP 多落地：默认落地外可添加最多 7 个独立落地，规则明确选择去向，每个附加落地分别校验 TLS 和预期出口，并纳入升级、轮换和恢复；UDP 继续使用默认落地。详见[第六轮多落地分流](docs/SERVER-MULTI-HOP-ROUND-6-2026-10-21.zh-CN.md)。

从桌面 **配置设计 → 创建方案** 开始：点亮 sing-box 和/或 Clash，再添加节点、确认连接关系、生成、校验并审阅导出。两个目标独立开关，点亮两个就都生成；仅要求所选目标的来源和输出路径。命令行对应主菜单 **7**。

- 从受管实例提取节点，或手动录入未纳管节点。
- 独立编辑节点、入口与落地连接关系、地区分组、排序和业务默认出口。
- 草稿使用当前 Windows 用户加密，保存在 `private/client-schemes`；取消新建不保存空方案，编辑支持保存、退出和删除。不能直接跨账号解密，重开后需要重新校验。
- 生成不改正式配置；导出前校验所选核心、来源与目标指纹，并建立备份和恢复记录。
- 默认从通用模板生成；导入已有配置可保留高级 DNS、TUN 与规则，但不是任意字段的可视化编辑器。
- 正式配置必须是用户指定的独立权威文件，拒绝写入 Clash Verge AppData。双文件发布使用锁和阶段记录处理失败，不应视为跨文件的单次原子操作。

详见[方案工作台与事务恢复](docs/WORKBENCH-AND-RECOVERY.zh-CN.md)。

### 当前组件与配置兼容基线

截至 2026-10-01，版本目录固定 Komari Controller **1.5.1**、Agent **1.5.11**。通用和专用升级入口使用相同流程：停服务创建一致性备份、等待人工完成数据库迁移并复验。取消或保护窗口到期会恢复升级前二进制和完整数据，不把 HTTP 页面能打开当成迁移完成。

客户端通用 JSON 面向官方 **sing-box 1.14.2** 和 **May Route 1.14.2-mxh.7**，不需要拆成两套模板。它保留本机回环 mixed 入站、TUN、规则/全局/直连模式、策略选择缓存，以及同一组公共规则。官方版本首次加载远程规则仍需网络；May Route 可用自带的五个规则集离线初始化，之后按原地址与间隔更新。模板不携带应用缓存绝对路径，也不包含 May Route 专用字段。

Clash 模板同步补齐 DNS 分流、嗅探、国内直连、广告与 UDP 防护规则；TUN 默认关闭，交由用户选择。两套模板保留地区入口、入口/落地链路和业务分组结构。导入已有高级配置仍以保留原内容为原则，不会自动替换个人 DNS、端口、规则或系统代理设置。

Windows 客户端校验核心与 VPS 部署核心分别固定版本，当前 sing-box 均为 **1.14.2**，Mihomo 为 **1.19.32**；更新项目不会隐式升级服务器。核心 ZIP 与 GeoData、离线规则有固定 SHA-256，执行前同时复核缓存 EXE 和实际版本。旧 ZIP 不随当前版本打包。完整适配说明见[兼容基线](docs/COMPATIBILITY-2026-09-30.zh-CN.md)和[本轮审计修复与隔离升级验证](docs/AUDIT-FIXES-2026-10-01.zh-CN.md)。

## 私有数据与权限

源码、通用模板和 Git 仓库不应包含实例真实 IP、端口、UUID、私钥、密码、Token 或完整个人配置。请单独保管实例归档，不要上传到公开仓库。

```text
<实例归档根目录>\<服务商>\<实例>\May-VPS-Deploy\
├─ deployment-plan.json             部署计划
├─ deployment-state.json            执行状态
├─ deployment-secrets.private.json  私有凭据
├─ deployment.log                   操作日志
├─ ssh\                            管理密钥
├─ client-exports\                 客户端导出
├─ server-configs\                 服务端配置归档
├─ health-audits\                   健康审计
├─ migration-backups\               协议变更备份
├─ maintenance-backups\             维护备份
└─ SHA256SUMS-private.txt            归档校验值
```

桌面版实例统一保存在应用目录下的 `private/instances/<服务商>/<实例>/May-VPS-Deploy`，客户端方案、候选、发布记录和界面设置也保存在应用 `private` 下。原命令行的归档根目录仍依次取自 `-InstanceRoot`、环境变量 `MXH_VPS_INSTANCE_ROOT`、本地覆盖文件 `config/app-defaults.local.json`，最后使用项目通用默认值。旧版根目录计划仍可由命令行读取，桌面端切换前由维护者离线转换。

普通归档沿用用户目录权限，不做额外 ACL 收紧；**受管 SSH 私钥是例外**：为满足 Windows OpenSSH 最低运行要求，仅在其权限过宽时修复必要权限，不改服务商源私钥，也不因其他错误调整 ACL。

本地路径接受 `/` 或 `\`，但同一条路径不要混用。Cloudflare、Komari 等 Token 使用隐藏输入或私有文件，不应写入普通日志或提交到 Git。

## 命令行入口

保留终端交互和脚本自动化；已有计划也可直接进入指定功能：

```powershell
# 新部署；可用 -InstanceRoot 指定私有归档根目录
pwsh -File .\Start-VPSDeploy.ps1 -Mode New

# 预览新部署计划，不连接服务器
pwsh -File .\Start-VPSDeploy.ps1 -Mode New -DryRun

# 接入已有 VPS
pwsh -File .\Start-VPSDeploy.ps1 -Mode Import

# 继续计划
pwsh -File .\Start-VPSDeploy.ps1 -Mode Resume -PlanPath '<实例受管目录>\deployment-plan.json'

# 协议管理
pwsh -File .\Start-VPSDeploy.ps1 -Mode Migrate -PlanPath '<实例受管目录>\deployment-plan.json'

# 运维中心
pwsh -File .\Start-VPSDeploy.ps1 -Mode Maintain -PlanPath '<实例受管目录>\deployment-plan.json'

# 独立网络调优
pwsh -File .\Start-VPSDeploy.ps1 -Mode TuneNetwork -PlanPath '<实例受管目录>\deployment-plan.json'

# 客户端配置
pwsh -File .\Start-VPSDeploy.ps1 -Mode ClientConfig
```

`Migrate` 是为兼容旧命令保留的名称，实际对应协议管理。`-OnlyModule` 仅用于理解依赖关系的维护场景，不应绕过首次部署的 SSH、防火墙和最终验收顺序；局部模块完成不代表整套部署完成。

## 验证与开发

```powershell
# 完整本地测试入口
pwsh -NoProfile -File .\tests\Run-Tests.ps1 -ProjectRoot $PWD

# 查询上游版本，不修改配置
pwsh -File .\scripts\Check-UpstreamVersions.ps1
```

测试包含 PowerShell 逻辑、交互、工作台、SSH 私钥权限、桌面输入与取消、应用更新与回滚、菜单契约及具备依赖时的 Bash 隔离模拟。固定资产更新需要同步版本、文件名和 SHA-256，再进行项目测试与真实协议验收。

既有七项 CI 保留，另有 Windows/Linux/macOS 三档共享 C# 核心测试。Windows 安装器测试实际点击 WinUI 更新入口和确认按钮，经过下载摘要校验、旧窗口退出、原位安装与新版 EXE 自动重启，并验证导入字体、外观偏好、私人归档和本地配置保留及两种卸载。更新服务的隔离测试使用与 GitHub 相同的元数据和真实安装包；发行后另核对正式附件。隔离模拟不等于真实 systemd 调度、网络故障或 VPS 全流程验收。

## 文档导航

| 文档 | 内容 |
|---|---|
| [中文完整使用手册](docs/USER-GUIDE.zh-CN.md) | 环境准备、部署、维护与验收 |
| [方案工作台与事务恢复](docs/WORKBENCH-AND-RECOVERY.zh-CN.md) | 客户端草稿、发布与中断恢复 |
| [证书与域名配置](docs/CLOUDFLARE-CERTBOT.zh-CN.md) | Cloudflare、Certbot、AnyTLS 与 Reality 本机目标 |
| [安全模型](docs/SECURITY.md) | 凭据、权限与操作边界 |
| [模块开发](docs/MODULES.md) | 模块结构与开发约定 |
| [交互维护](docs/INTERACTION-MAINTENANCE.md) | 导航规范与回归约定 |
| [变更记录](CHANGELOG.md) | 功能调整与修复历史 |
| [审计修复与隔离验收](docs/AUDIT-FIXES-2026-10-01.zh-CN.md) | v0.5.2 修复、验证结果及未验收范围 |
| [最低 PowerShell 运行环境验证](docs/MINIMUM-POWERSHELL-2026-10-01.zh-CN.md) | v0.5.3 便携 7.4.20、初始化器回归与七项 CI |
