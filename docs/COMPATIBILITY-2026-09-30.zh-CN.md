# 组件与客户端兼容基线（2026-10-01 修订）

## 版本与范围

- [Komari Controller 1.5.1](https://github.com/komari-monitor/komari/releases/tag/1.5.1) 与 [Agent 1.5.11](https://github.com/komari-monitor/komari-agent/releases/tag/1.5.11)：采用当日最新正式版本，不采用 Snapshot、RC 或 1.6 预发布版。Linux amd64/arm64 的文件名和 SHA-256 固定在 `config/versions.json`；项目正式 VPS 支持范围仍为 Debian 12/13 amd64。
- [官方 sing-box 1.14.2](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2) Windows amd64 验证核心，匹配 [May Route 1.14.2-mxh.7](https://github.com/mxh110708/may-route-desktop/releases/tag/v1.14.2-mxh.7) 所用的官方核心版本。
- Linux VPS 的 sing-box 部署/升级资产经独立隔离验证更新到 1.14.2；Mihomo Windows/Linux 校验基线更新到 1.19.32。Windows 资产自身的 `version` 仍优先用于客户端验证，不能把客户端版本自动套用于远端。

本次适配只更新工具源码、通用模板、测试与公开验证资产，不执行现有服务器升级，不覆盖用户的 Clash/May Route 权威配置，不改变桌面客户端、系统代理或 TUN 状态。

## 同一份 JSON 适用于两种客户端

`templates/client/sing-box-general.template.json` 使用官方 1.14.2 字段：mixed/TUN、显式 route action、新版类型化 DNS、selector、缓存与 Clash 模式。没有 May Route 专用字段，因此保留一份模板；生成的 `sing-box-general.candidate.json` 可用于官方版本或 May Route。

mixed 默认只监听回环地址的 2080 端口。May Route 端口设置读取并修改配置的原生入站，不需要额外的应用全局端口字段。TUN 模板保留 `auto_route`、`strict_route` 和 `dns_mode: hijack`；应用在系统代理模式的临时运行副本中禁用 TUN 接管并配置本机 HTTP 代理，在 TUN 模式恢复原生路由。通用模板不会预置 `platform.http_proxy`，不会自行更改系统代理。

五个公共规则的 tag/type/format/URL 与 May Route 离线白名单完全一致：广告、私有域名、中国域名、中国 IP、非中国域名。导出保留远程地址、`download_detour` 和每日更新；官方版本首次加载仍需网络，May Route 可先使用自身资源初始化。只有本机验证的临时副本把已识别公共规则转成 SHA-256 校验过的本地 SRS；验证成功不代表规则联网更新或每个真实节点连接已经验收。

从现有配置导入时，构建器仅移除这五个已识别公共规则的 `initial_path`，让新客户端重新建立缓存；不同 URL、自定义规则及其 `initial_path` 不擅自更改。UTF-8 配置必须小于 4 MiB；失败不会写出超限候选。已有节点、端口、DNS、TUN 和高级规则不被通用模板强制覆盖。

Clash 模板保留同样的分组含义，新增 GeoSite/GeoIP、DNS 分流、嗅探及 UDP/广告防护；使用 Mihomo 1.19.32 与固定 GeoData 验证。Clash TUN 默认关闭，已有配置显式指定的栈不会被升级流程改写。请不要让两个客户端同时接管 Windows 系统代理或 TUN。

## Komari 1.5 升级与数据恢复

Controller 1.5 引入新的指标数据库结构；可能显示 `/admin/database-migration` 引导，需要管理员选择并执行迁移。备份须涵盖整个受支持的数据目录，包括 `komari.db`、`metrics.db`、主题、插件及插件数据，不能只替换或回滚二进制。

自动升级仅接受受支持的 `/opt/komari`、`/var/lib/komari` 工作/数据目录和 SQLite，按 systemd 实际注册的受支持可执行文件升级。预检发现数据库位于其他目录、目录指向外部的符号链接、数据库使用 URI/DSN、无法解析服务启动参数或使用其他数据库类型时，会在停服务或更换程序前拒绝升级；这类实例需自行确认完整备份与迁移方案。

工具创建完整备份与 Controller 专用事务快照时短暂停服务，随后恢复原运行状态。升级失败或用户取消时，先停服务，把升级后的数据移到受限备份目录，再恢复旧快照与二进制，以免新生成的数据库残留混入旧版本。失败数据保留用于排查，不自动删除。

升级后检查版本、实际运行程序、回环监听、HTTP 及迁移引导 API。正常 SPA 对未注册迁移接口可能返回 HTML，而非 404；必须再由正常版本 API 返回预期版本的 JSON 才确认迁移不再待处理。迁移仍待处理时不会提交，用户需在面板完成后返回复验；工具不代替用户点击迁移或删除历史数据。20 分钟远端保护窗口到期触发回滚，并拒绝后续写入命令与提交；回滚等待进行中的写入阶段释放锁，实际还原时间可能晚于截止时间。长时间大数据迁移应另行安排完整备份下的维护窗口。原先停用的 Controller 保持停用，只验证程序版本，并明确提示数据库迁移将延期到下次启动。

Agent 使用现有 Token 与配置，保持禁用自动更新和远程控制的安全默认值；安装/修复显式重启以加载新程序与配置。新安装不再写入已弃用的 `protocol_version` 字段。

Agent 1.5.11 未提供 `--version` 接口。升级预检不会运行下载的 Agent，而是用固定发布资产的 SHA-256 确认版本；安装后再次校验文件。原服务运行时才重启，并在最多 10 次核对中确认 MainPID 使用新程序及运行文件哈希一致；停用服务保持停用。任一检查失败均返回失败，由已有维护事务执行恢复，不将仅替换文件视为运行验收。

## 验证入口与边界

```powershell
pwsh -NoProfile -File .\Start-VPSDeploy.ps1 -Mode ValidateProject
pwsh -NoProfile -File .\tests\Test-ClientCompatibility.ps1 -ProjectRoot $PWD
```

可用 `Test-ClientCompatibility.ps1 -MayRouteCorePath '<隔离的 May Route CLI 验证核心>'` 加验同一份模板和生成配置。`Test-MayRouteRuntime.mts` 是可选跨项目集成测试：使用最新桌面源码的真实配置预处理函数，在空缓存且禁用网络时加载自带公开规则，再对系统代理/TUN 临时运行配置执行核心 `check`；不启动应用、服务或 TUN。

CI 验证官方 Windows 核心及生成配置，Debian 12/13 容器执行远端脚本语法与隔离 Komari/事务回归。真实 VPS 的数据量、systemd 调度、登录/TOTP、第三方主题及端到端网络连接仍需维护窗口中的实际验收，不能用这些离线检查代替。
