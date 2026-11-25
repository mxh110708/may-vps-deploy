# 第44轮：统一出站地址族策略

纳入 v0.9.43。支持自动、仅IPv4、仅IPv6、优先IPv4、优先IPv6。优先策略保留两族 DNS 结果，并在 TCP 建连期间尝试另一族；不是在 DNS 无记录时才切换，也不切换到其他代理或服务器直连。

## 选择入口与边界

- 新建 Reality／AnyTLS 组件：部署表单的“直连网站出口”定义该组件直接访问网站的策略。旧归档无新字段时继续解释原 `ForceIpv4Egress`。
- 通用独立入站的直连出站：“出口地址族”支持全部五种策略；默认及分类例外使用同一渲染模型。
- 通用独立入站的代理出站：“连接下一跳地址族”单独选择五种策略，仅控制代理端点连接。原“出口地址族”和预期出口 IP 用于目标流量限制及最终出口验收；不能用它替代理服务器决定最终网站的拨号优先级。
- SS2022 落地原有 IPv4／IPv6 双用户和绑定身份继续保留。现有线路和固定 IP 转发不被改成域名负载均衡。

已有服务修改通过通用入站的正常预览、配置摘要、实际验收和范围恢复执行；不会因软件更新自动写服务器。传统组件保留原维护事务，新建组件可在部署时选策略。旧配置不自动推断为新的优先模式。

## 核心映射

| 策略 | sing-box | 固定 Xray 26.3.27 |
| --- | --- | --- |
| 仅IPv4／仅IPv6 | `domain_resolver.strategy` 为 `ipv4_only`／`ipv6_only`，业务路由拒绝另一族显式目标 | Freedom 的 ForceIPv4／ForceIPv6；代理拨号使用对应 sockopt；业务路由拒绝另一族显式目标 |
| 优先IPv4／优先IPv6 | `prefer_ipv4`／`prefer_ipv6`，`fallback_delay: 300ms` | 业务目标保留域名到拨号阶段，sockopt ForceIP + Happy Eyeballs，首选族明确，300ms间隔，最多两个并行尝试 |
| 自动 | 保持既有解析默认与核心拨号默认 | 保持既有 Freedom／sockopt 默认 |

新 Xray 业务地址族限制绑定业务入站，避免把解析器自己的连接一起阻断。DNS 服务器和 TLS／Reality 身份仍独立配置；不更改系统 DNS、hosts 或路由。已有原生拨号策略与新显式策略冲突时拒绝覆盖，保留原参数供用户审阅。

域名代理端点由运行所在 VPS 解析；独立入站支持受验证的协议原生参数。明确 IPv4／IPv6 端点不能凭优先策略变成另一地址；与“仅某族”冲突会拒绝。最终网站若已经是明确 IP，优先策略保留该 IP，严格策略才限制对应族。

## UDP 与最终出口

TCP 优先／回退只发生在业务数据开始传输前的建连阶段。TCP 已连接后的鉴权、TLS 或业务失败不重放请求。UDP 选择目标后保持会话语义，不因无响应重发旧数据报到另一族；QUIC 握手及协议行为仍由固定核心实现决定，不承诺通用 UDP 跨族业务重放。

代理端点族、网站请求目标族及最终公网出口是不同观测。优先模式的导出节点不伪装成严格IPv4／IPv6出口，继续记录未知／实际观测及可选预期地址。更改策略会改变配置与客户端来源身份，旧候选需要重新生成和验收。恢复使用既有组件事务，只恢复本次范围。

## 验证与限制

专项模型入口 `--outbound-address-only`。实际脚本 `tests/outbound-address-runtime44.py` 使用固定官方 sing-box 1.14.4 和 Xray 26.3.27、进程内产出的产品出站配置、本地双栈 DNS 和受控 HTTP／SS 对端，验证双族、首选族连接失败、显式 IP、重启、代理端点与最终网站分离，以及无响应 UDP 只发送一次。全部测试使用回环与临时目录，不改系统网络或生产服务。

该证据不等于公网 IPv6 可用或一次新的 Debian 整机迁移／重启验收。公网服务应用仍执行原有协议、目标出口和必要 UDP 验收，失败按组件恢复。

实现参考固定版本：[sing-box 1.14.4 dialer](https://github.com/SagerNet/sing-box/tree/v1.14.4/common/dialer)、[Xray 26.3.27 拨号与 Happy Eyeballs](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/dialer.go)、[Xray 对应配置](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/transport_internet.go)。
