# v0.9.43 发行范围与验证

日期：2026-11-25。本版汇总主线第39至44轮，以及官方 sing-box 和配套 May Core 固定版本更新。源码推送与发行不代表已在用户电脑安装，也不代表生产 VPS 已执行升级。

## 本版行为

| 范围 | 结果与边界 |
| --- | --- |
| 第39轮 | 原 SSH 身份下的实例换址、完整依赖、双槽位和分阶段白名单、实际验收及范围恢复。原隔离 Debian 12／13 的换址及整机重启记录见[当轮证据](INSTANCE-ADDRESS-ROUND-39-2026-11-16.zh-CN.md)。 |
| 第40轮 | 受限私有协议健康、HTTPS／出口与加密 UDP、失败确认、稳定恢复及独立服务。原 Debian 双版本记录见[当轮证据](FORWARD-PROXY-HEALTH-ROUND-40-2026-11-16.zh-CN.md)。 |
| 第41轮 | 2–8 个固定身份目标、轮询／来源 IP 哈希、健康摘除、稳定恢复及 TCP／UDP 会话固定。见[当轮证据](FORWARD-MULTI-TARGET-ROUND-41-2026-11-24.zh-CN.md)。 |
| 第42轮 | 显式可信 TCP PROXY v1／v2 接收、客户端网段、原端点透传及局部恢复。原 Debian 重启和 Xray TLS 路径见[当轮证据](FORWARD-PROXY-RECEIVE-ROUND-42-2026-11-25.zh-CN.md)。 |
| 第43轮 | HTTPS 模板／规则 JSON、受限获取、加密缓存、不可变摘要／版本、差异和使用者影响；审阅后导入版本库，不自动修改使用者。见[说明](REMOTE-LIBRARY-ROUND-43-2026-11-25.zh-CN.md)。 |
| 第44轮 | 自动、严格 IPv4／IPv6、优先 IPv4／IPv6；区分直连网站和代理下一跳，TCP 建连回退、显式 IP、DNS 连接保护及 UDP 不重放。见[说明](OUTBOUND-ADDRESS-ROUND-44-2026-11-25.zh-CN.md)。 |

## 固定核心与来源

- 官方 sing-box：**1.14.4**，Windows amd64 校验 ZIP 及 Linux amd64／arm64 安装资产分别固定官方 SHA-256；Linux 运维正式验收范围仍为 Debian 12／13 amd64，arm64 清单存在不代表新增运维支持。
- May Core：**1.14.4-may.1**，固定发布提交 `5c4415cfd3ba448326c9564d9f934809cd74d4b3`，未改动已发布 ZIP；二进制、完整 CLI 源码 ZIP 和1609项源码文件摘要逐项核对。
- Route 兼容基线：**1.14.4-may.1**；其安装包不进入 Deploy 发行附件，也不自动安装。
- Mihomo 保持 **1.19.32**；Xray 保持 **26.3.27**。不借本轮无关升级其他核心。
- 内置模板修订升为 **2**，采用新的基线模板身份，避免与用户在旧身份下派生的修订2冲突。旧私人模板修订保持固定；核心变化后需要新建并审阅修订，不以同一修订覆盖不同依赖。迁移回归验证原参数和历史摘要保持不变。

原始来源：[官方 sing-box v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)、[May Core 发布和源码](https://github.com/mxh110708/may-route-core/releases/tag/v1.14.4-may.1)、[May Route](https://github.com/mxh110708/may-route-desktop/releases/tag/v1.14.4-may.1)。原公共 SRS 仍固定同一来源提交和字节，并未随 Route 版本号任意改动。

## 验证路径

项目主校验、双客户端完整候选和各16项实际分类检查、Windows 存储／ACL／更新元数据检查均执行于隔离目录。新远程来源专项覆盖20项缓存、版本、审阅、取消及恢复断言。地址族专项覆盖29项模型与出口观测断言；真实回环脚本覆盖两核心共26项场景，包括直连及 SS 下一跳、首选族失败、明确 IP、进程重启和无响应 UDP 不重放。

完整 .NET 回归分 foundation、clients、xhttp、chains、quic、udp、server-stream、operations 执行，覆盖旧协议与第39至44轮。测试使用固定验证资产，不拿解析成功代替业务路径。Linux 所有者／符号链接与 Debian 远端脚本契约由对应 CI 检查，Windows 本地权限不具备的用例明确保留跳过。最终提交的两组 CI 必须全部成功才发布，结果见[GitHub Actions](https://github.com/mxh110708/may-vps-deploy/actions)。

首次基线回归暴露旧测试把合成升级目标写死为1.14.3；更新正式基线后该版本不再更高。已改为从固定基线计算合成下一补丁版本，仅用于模拟升级／失败恢复，不下载或宣称这个合成版本是上游已发布版本。

首轮地址族验收发现 Xray 严格 IPv6 的全局目标限制会误挡解析器连接，修正为只约束业务入站。代理回环的受控 UDP DNS 另使用独立测试标签，不让解析未连接代理的过程依赖该代理；正式配置使用 OS-local 解析器。失败尝试不计入通过矩阵。

远端策略校验同步识别新的优先族及下一跳连接字段，探测请求将优先策略映射为实际观测而非严格出口。新增事务用例验证应用／恢复只作用于选中入站，保留旧未限定入站标签的固定快照。首轮 Windows CI 缺少第42轮 TLS 身份生成依赖，已在 `requirements-test.txt` 单独固定；不进入应用运行时。

## 发行与恢复

正式打包要求 main 干净、stable 元数据和完整对应内核源码附件。发行 ZIP 逐文件与清单比较，检查内置官方／May 核心和对应源代码的摘要，拒绝私人归档、本机设置、凭据、开发缓存、签名材料和 QA 安装器。原生启动核对 WinUI／.NET 内置运行时，不加载 WPF／PowerShell 驱动；后台启动不激活前台窗口。

安装器和文件清单沿用现有受管更新协议，更新只覆盖清单内文件，保留私人及未受管内容。安装器的隔离 install／update／uninstall 生命周期由 Windows CI 专项执行。发行附件大小、摘要、版本和公共最新版本信息须复核后才完成发布。

本轮没有修改 VPS、系统代理、TUN、Clash Verge 的 AppData 配置，未安装或重载本机代理应用。没有把本地进程重启写成新的 Debian 整机重启或公网线路验收。
