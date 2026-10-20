# Cloudflare、Certbot、AnyTLS 与 Reality 本机 target 配置手册

本文是 `May VPS Deploy` 的 Cloudflare 操作备忘录。适用于：

- 部署 AnyTLS + 可信 TLS + ECH；
- 给 Reality 使用自有域名的本机 HTTPS target；
- 两者同时安装、只启用其中一个 TCP 443 服务；
- 以后换 VPS、换 IP、续期、停用或退役时检查 Cloudflare 配置。

文中的 `example.com`、主机名和 IP 都是占位符，必须替换成自己的真实信息。不要把真实 Token、私钥或实例参数提交到 Git。

## 1. 先记住这张对应表

假设 Cloudflare 中的根域名是 `example.com`，VPS 位于洛杉矶，实例代号是 `a`：

| 用途 | 推荐示例 | 在脚本中填写的位置 | 是否需要与其他名称不同 |
|---|---|---|---|
| AnyTLS 真实证书名称和隐藏 SNI | `edge-lax-a.example.com` | AnyTLS 证书域名/内部 SNI | 是 |
| AnyTLS ECH 对外 public name | `www-lax-a.example.com` | ECH 对外 public name | 必须不同于 AnyTLS SNI |
| Reality 本机 HTTPS target | `portal-lax-a.example.com` | 本机 HTTPS target 域名 | 建议独立 |
| Cloudflare Zone | `example.com` | Cloudflare Zone 根域名 | 只填根域名 |

名称中的 `lax` 是实际地区代码，不要把所有节点都写成 `usw`。香港可用 `hkg`，法兰克福可用 `fra`，圣何塞可用 `sjc`。实例代号可以是 `a`、`b` 或更清楚的短名称。

最容易混淆的地方：

- `edge-lax-a.example.com` 是 AnyTLS 的真实证书/SNI 名称；
- `www-lax-a.example.com` 是 ECH 的 public name，不是另一个代理节点；
- `portal-lax-a.example.com` 是 Reality 回落到本机 nginx 时使用的证书域名；
- 三个名称可以指向同一台 VPS；
- AnyTLS 的 ECH 密钥和客户端 ECH config 由 sing-box 生成，不是在 Cloudflare 面板中生成；
- Cloudflare 在这里仅负责权威 DNS 和 DNS-01 API，不承载代理流量。

如果只部署 AnyTLS，只准备前两个名称。如果只部署 Reality 本机 target，只准备第三个名称。如果二者都保留，则三个名称都保留。

## 2. Cloudflare 在这个方案中做什么

Cloudflare 有两个职责：

1. 托管根域名的权威 DNS；
2. 允许 Certbot 使用受限 API Token 临时创建和删除 `_acme-challenge` TXT 记录，完成 DNS-01 验证。

Cloudflare 不负责：

- 代理 AnyTLS 或 Reality 流量；
- 生成 sing-box ECH 密钥；
- 代替 VPS 上的 Certbot；
- 提供本项目使用的 Origin CA 证书；
- 通过 Cloudflare Tunnel 转发代理入口。

因此，这些主机名必须使用“仅 DNS”灰云。橙云会让域名解析到 Cloudflare Anycast 地址，连接先进入 Cloudflare 的 HTTP 代理，不再直接到达 VPS，AnyTLS/Reality 握手会失去本项目设计的直连路径。

DNS-01 签发证书本身只依赖 `_acme-challenge` TXT 记录，不以 A/AAAA 为技术前提。项目仍建议为每个使用中的名称建立清晰的 A/AAAA 映射，便于客户端解析、迁移、排障和人工核对。

## 3. 配置前准备

先整理以下信息：

```text
Cloudflare Zone：example.com
VPS 公网 IPv4：<VPS IPv4>
VPS 公网 IPv6：<VPS IPv6，没有就留空>
AnyTLS SNI：edge-lax-a.example.com
AnyTLS ECH public name：www-lax-a.example.com
Reality 本机 target：portal-lax-a.example.com
Certbot 联系邮箱：<长期可用邮箱>
Token 私有文件：<实例私有目录>\cloudflare-certbot-token.private.txt
```

确认：

- Zone 在 Cloudflare 中显示为 Active；
- 域名注册商的 NS 已正确委托给当前 Cloudflare Zone；
- IPv6 只有在 VPS 确实配置并能正常入站时才填写；
- 不复用 `status`、邮件、Cloudflare Tunnel 或现有网站的主机名；
- 不使用根域名本身作为代理入口，给每台实例创建独立子域名。

## 4. 在 Cloudflare 创建 DNS 记录

### 4.1 进入记录页面

Cloudflare 控制台中依次进入：

```text
选择账户
→ 选择 example.com
→ DNS
→ 记录（Records）
→ 添加记录（Add record）
```

Cloudflare 的“名称”输入框通常只需要填写子域部分，例如填写 `edge-lax-a` 后，界面会显示完整名称 `edge-lax-a.example.com`。

### 4.2 AnyTLS 记录

为 AnyTLS SNI 创建：

| 字段 | IPv4 记录 | IPv6 记录 |
|---|---|---|
| 类型 | A | AAAA |
| 名称 | `edge-lax-a` | `edge-lax-a` |
| 内容 | `<VPS IPv4>` | `<VPS IPv6>` |
| 代理状态 | 仅 DNS（灰云） | 仅 DNS（灰云） |
| TTL | 自动 | 自动 |

为 ECH public name 再创建：

| 字段 | IPv4 记录 | IPv6 记录 |
|---|---|---|
| 类型 | A | AAAA |
| 名称 | `www-lax-a` | `www-lax-a` |
| 内容 | `<VPS IPv4>` | `<VPS IPv6>` |
| 代理状态 | 仅 DNS（灰云） | 仅 DNS（灰云） |
| TTL | 自动 | 自动 |

AnyTLS 的证书会同时覆盖 `edge-lax-a.example.com` 和 `www-lax-a.example.com`。两者不能填成同一个名称。

本项目会把 ECH config 直接写入客户端节点配置，因此不需要在 Cloudflare 额外手工创建 HTTPS/SVCB 记录，也不需要开启 Cloudflare 的 ECH 功能开关。

### 4.3 Reality 本机 target 记录

为本机 target 创建：

| 字段 | IPv4 记录 | IPv6 记录 |
|---|---|---|
| 类型 | A | AAAA |
| 名称 | `portal-lax-a` | `portal-lax-a` |
| 内容 | `<VPS IPv4>` | `<VPS IPv6>` |
| 代理状态 | 仅 DNS（灰云） | 仅 DNS（灰云） |
| TTL | 自动 | 自动 |

本机 target 不是一台外部网站。脚本会在 VPS 上部署 nginx，但 nginx 只监听类似 `127.0.0.1:8443` 和 `[::1]:8443` 的回环高位端口；公网 TCP 443 仍由 Xray Reality 监听。不要为 nginx 开放公网 80，也不要让 nginx 直接占用公网 443。

在浏览器里直接打开 `portal-lax-a.example.com` 不能替代脚本的本机 target 验收。应由脚本从回环地址验证证书、TLS 1.3、h2 和页面，再验证真实 Reality 连接。

### 4.4 DNS 记录最终应类似

只部署 AnyTLS：

```text
A     edge-lax-a     <VPS IPv4>    DNS only    Auto
AAAA  edge-lax-a     <VPS IPv6>    DNS only    Auto   # 有 IPv6 才创建
A     www-lax-a      <VPS IPv4>    DNS only    Auto
AAAA  www-lax-a      <VPS IPv6>    DNS only    Auto   # 有 IPv6 才创建
```

AnyTLS 和 Reality 本机 target 都保留：

```text
A     edge-lax-a     <VPS IPv4>    DNS only    Auto
AAAA  edge-lax-a     <VPS IPv6>    DNS only    Auto   # 可选
A     www-lax-a      <VPS IPv4>    DNS only    Auto
AAAA  www-lax-a      <VPS IPv6>    DNS only    Auto   # 可选
A     portal-lax-a   <VPS IPv4>    DNS only    Auto
AAAA  portal-lax-a   <VPS IPv6>    DNS only    Auto   # 可选
```

不要填写端口，DNS 记录只保存名称和地址。不要同时给同一个名称混用灰云与橙云记录；Cloudflare 可能把同名记录整体按代理状态处理。

## 5. 创建长期使用的 Certbot API Token

这不是一次性测试 Token。只要仍有 VPS 使用它自动续期，Token 就必须保持有效。

### 5.1 进入 Token 页面

在 Cloudflare 控制台右上角进入个人资料，然后：

```text
My Profile / 我的个人资料
→ API Tokens / API 令牌
→ Create Token / 创建令牌
→ Create Custom Token / 创建自定义令牌
```

推荐名称：

```text
MXH-CERTBOT-DNS-EXAMPLE-COM
```

名称里写 `CERTBOT` 是为了提醒“哪个客户端在使用它”。ACME 是 Certbot 所使用的证书自动化协议；以前写成 `ACME` 也不影响 Token 功能，不需要仅因名称重建。

### 5.2 权限填写

添加两行权限：

| 范围 | 权限 | 级别 |
|---|---|---|
| Zone | DNS | Edit |
| Zone | Zone | Read |

其中：

- `DNS / Edit` 允许 Certbot 创建和删除 DNS-01 TXT 记录；
- `Zone / Read` 允许脚本和插件找到目标 Zone；
- 不需要 Account 级别权限；
- 不需要 SSL and Certificates Edit；
- 不要使用 Global API Key；
- 不要使用 Origin CA Key。

### 5.3 Zone Resources 填写

填写：

```text
Include / 包括
Specific zone / 特定区域
example.com
```

不要选择 All zones。`example.com` 是根 Zone，不要把 `edge-lax-a.example.com` 填到 Zone Resources。

### 5.4 Client IP Address Filtering

这是可选项。

最省心的方案是留空，不限制 Token 的调用来源；Token 仍然只拥有一个 Zone 的 DNS 编辑权限。若 VPS IP 固定，也可以使用 `Is in` 白名单进一步收紧。

启用白名单时必须填写“实际运行 Certbot 的 VPS 公网出口地址”，不是当前 Windows 电脑的 IP。因此不要点击浏览器旁边的“Use my IP / 使用我的 IP”。

一个 Token 被多台 VPS 共用时，白名单应包含所有这些 VPS 可能调用 Cloudflare API 的地址：

```text
<VPS-A IPv4>/32
<VPS-A IPv6>/128
<VPS-B IPv4>/32
<VPS-B IPv6>/128
```

Cloudflare 界面也可能接受不写 `/32` 或 `/128` 的单个主机地址。没有 IPv6 就不要虚构。如果 VPS 对 Cloudflare API 的实际出口可能在 IPv4 和 IPv6 间变化，两种地址都要加入。

注意：一旦配置 `Is in`，不在列表中的来源将无法使用此 Token。VPS 换 IP、迁移或新增续期服务器时，要先更新 Token 白名单，再执行证书操作。

### 5.5 TTL

用于自动续期的 Token 不要设置结束日期。Cloudflare Token 默认长期有效；若设置 TTL，到期后现有证书不会立刻失效，但后续续期会失败。

### 5.6 创建前核对摘要

摘要应类似：

```text
example.com - DNS:Edit, Zone:Read
Client IP Address Filtering - <留空，或列出所有 Certbot VPS 公网出口>
TTL - <无结束日期>
```

确认后点击 `Create Token`。Token 值通常只完整显示一次。

## 6. 保存 Token 文件

在实例私有资料目录创建：

```text
cloudflare-certbot-token.private.txt
```

文件内容只能是一行原始 Token：

```text
<Cloudflare API Token>
```

不要写成：

```text
CF_DNS_API_TOKEN=<Token>
dns_cloudflare_api_token = <Token>
Bearer <Token>
"<Token>"
```

原因是本工具读取原始 Token 后，会在 VPS 上自行生成 Certbot 插件要求的：

```text
dns_cloudflare_api_token = <Token>
```

脚本只把本地 Token 文件路径写进计划，不把 Token 值写入计划、普通日志或 Git。远端文件保存为 `/etc/letsencrypt/cloudflare.ini`，所有者为 `root:root`，权限为 `0600`。

不要把 Token 复制到聊天、截图、README、GitHub Issue 或客户端配置。Cloudflare Token 泄漏后应立即撤销并创建新 Token。

## 7. 在 May VPS Deploy 向导中怎么填写

### 7.1 AnyTLS

```text
AnyTLS 证书域名/内部 SNI：edge-lax-a.example.com
ECH 对外 public name：www-lax-a.example.com
Cloudflare Zone 根域名：example.com
ACME/Let's Encrypt 联系邮箱：<长期可用邮箱>
Cloudflare Certbot Token 私有文件：<完整本地路径>
```

脚本会：

1. 用 Token 查询并确认唯一的 Cloudflare Zone；
2. 使用 Certbot DNS-01 为两个名称签发一张 ECDSA P-256 证书；
3. 生成 sing-box ECH 密钥对；
4. 把 ECH client config 写入私有客户端片段；
5. 安装专用自动续期 timer；
6. 完成 AnyTLS + 可信证书 + ECH 的真实客户端测试。

### 7.2 Reality 本机 target

```text
Reality target 模式：本机自有域名 HTTPS target
本机 HTTPS target 域名：portal-lax-a.example.com
Cloudflare Zone 根域名：example.com
ACME/Let's Encrypt 联系邮箱：<长期可用邮箱>
Cloudflare Certbot Token 私有文件：<完整本地路径>
回环 HTTPS 高位端口：<未占用的高位端口>
```

脚本会：

1. 为 `portal-lax-a.example.com` 签发可信证书；
2. 安装仅监听回环高位端口的 nginx；
3. 验证证书名称、TLS 1.3 和 h2；
4. 让 Xray Reality 使用该回环 HTTPS 服务作为 target；
5. 保持公网 TCP 443 归 Xray 所有。

AnyTLS 与 Reality 本机 target 可以同时安装并保留各自证书，但两者都需要公网 TCP 443，因此同一时刻只能启用一个入口服务。协议管理器会负责切换 enabled/active 状态。

## 8. 签发与续期机制

本项目使用 Certbot，而不是使用 sing-box 内置 ACME：

- Certbot 是 ACME 客户端；
- Let's Encrypt 是默认公共 CA；
- Cloudflare DNS API 完成 DNS-01 challenge；
- 不要求开放公网 80；
- 不要求临时停止 TCP 443 服务。

脚本会停用发行版默认的 `certbot.timer`，只启用：

```text
mxh-certbot-renew.timer
```

它每天检查两次。只有证书接近到期时 Certbot 才真正续期；每次成功续期后，部署 hook 会原子更新 `/etc/mxh-tls` 中的证书，并：

- AnyTLS 正在运行时，检查配置并重启 `sing-box-anytls.service`；
- Reality 本机 target 正在使用时，检查并 reload nginx。

首次部署还会执行一次 Certbot dry-run。单次签发成功但 dry-run 失败，不算完整验收通过。

## 9. 配置完成后的检查

### 9.1 Windows 检查 DNS

```powershell
Resolve-DnsName edge-lax-a.example.com -Type A
Resolve-DnsName edge-lax-a.example.com -Type AAAA
Resolve-DnsName www-lax-a.example.com -Type A
Resolve-DnsName portal-lax-a.example.com -Type A
```

只查询实际创建的记录。结果应为 VPS 的真实地址，而不是 Cloudflare Anycast 地址。若没有配置 IPv6，AAAA 查询返回无记录是正常的。

### 9.2 VPS 检查证书和 timer

```bash
sudo certbot certificates
sudo systemctl status mxh-certbot-renew.timer --no-pager
sudo systemctl list-timers mxh-certbot-renew.timer --no-pager
sudo systemctl is-enabled mxh-certbot-renew.timer
sudo stat -c '%U:%G %a %n' /etc/letsencrypt/cloudflare.ini
```

最后一条应显示 `root:root 600`。

需要人工再次模拟续期时：

```bash
sudo certbot renew --dry-run
```

不要频繁执行真实强制续期，以免触发 CA 速率限制。

### 9.3 协议验收

Cloudflare 和 Certbot 正常不等于代理协议正常。最终仍需检查：

- AnyTLS：可信证书、ECH、HTTP 204、出口 IP、UDP DNS；
- Reality 本机 target：回环 nginx 的 TLS 1.3/h2、真实 Reality 握手、HTTP 204、出口 IP；
- 客户端 `server_name` 与证书名称一致；
- 客户端 ECH config 与当前服务端 ECH key 成对。

优先使用本工具的最终验收和健康审计，不要只用浏览器访问域名判断。

## 10. 换 IP、迁移、共存和退役

### 10.1 VPS 换 IP

按以下顺序操作：

1. 若 Token 启用了 IP 白名单，先加入新 VPS 的实际出口 IPv4/IPv6；
2. 把相关 A/AAAA 更新到新 VPS；
3. 等待 DNS 生效并验证解析；
4. 在新 VPS 完成证书 dry-run 和协议真实验收；
5. 再从 Token 白名单移除旧 IP；
6. 最后删除不再使用的旧记录或旧实例。

不要先删旧 IP 白名单，否则旧机在迁移窗口内可能无法续期或重新签发。

### 10.2 Reality 与 AnyTLS 共存

如果同一台 VPS 同时保留 Reality 本机 target 和 AnyTLS：

- `edge-*`、`www-*`、`portal-*` 三类记录都保留；
- 两套证书都可以由 Certbot 续期；
- 只有 Reality 或 AnyTLS 其中一个入口服务占用公网 TCP 443；
- 切换协议不需要反复删除和重建 DNS 记录或 Token。

### 10.3 只卸载一个协议

本工具不会因为卸载一个协议就自动删除共享 Certbot 环境、Cloudflare Token 或 DNS 记录。确认其他协议和证书不再引用对应域名后，才在 Cloudflare 手工删除该域名的 A/AAAA。

### 10.4 退役旧 VPS

若 Token 被多台 VPS 共用：

- 不要撤销仍被其他 VPS 使用的 Token；
- 只从 IP 白名单移除旧 VPS 地址；
- 删除只属于旧 VPS 的 DNS 记录；
- 保留仍被其他实例使用的 Zone 和记录。

若 Token 只属于这台已退役 VPS，且确认没有任何证书需要续期，才撤销 Token，并删除本地 Token 文件的旧副本。

## 11. 常见错误对照

| 现象 | 常见原因 | 处理 |
|---|---|---|
| 找不到 Zone 或 Zone 查询不是唯一结果 | Zone 名填成了完整子域名；缺少 Zone Read | Zone 填根域名，补 `Zone / Zone / Read` |
| 403/权限不足 | Token 权限、Zone Resource 或 API 实际使用的 IPv4/IPv6 不在白名单 | 对照项目显示的请求源地址和第 5 节逐项检查 |
| Token 验证看似成功，但签发时失败 | Cloudflare 的 Token verify 接口不受 IP 白名单限制，而实际 Zone/DNS API 受限制 | 把 Certbot VPS 的真实出口加入白名单 |
| Token 文件格式错误 | 文件带前缀、引号、多行或空行 | 只保留一行原始 Token |
| 域名解析到 Cloudflare 地址 | 记录仍是橙云，或 CNAME 链中存在橙云 | 改为灰云并检查整个 CNAME 链 |
| IPv4 正常、IPv6 偶发超时 | 创建了 AAAA，但 VPS IPv6 入站或路由不完整 | 修复 IPv6；未准备好前删除 AAAA |
| AnyTLS TLS 正常但 ECH 失败 | SNI/public name 填反、两者相同，或客户端 ECH config 已过期 | 对照私有归档重新生成/导入当前客户端片段 |
| Reality 本机 target 浏览器打不开 | nginx 本来就只监听回环高位端口 | 用脚本本机检查和真实 Reality 验收 |
| 首次签发成功，数月后续期失败 | Token 设置了到期日、IP 变化或 Token 被撤销 | 检查 Token TTL、白名单和 timer 日志 |
| Certbot 提示凭据文件权限不安全 | `/etc/letsencrypt/cloudflare.ini` 权限过宽 | 改为 `root:root 0600`，再运行健康审计 |
| 证书只覆盖一个 AnyTLS 名称 | 签发时遗漏 SNI 或 ECH public name | AnyTLS 证书必须同时包含两个 SAN |

## 12. 最终检查清单

- [ ] Cloudflare Zone 是正确的根域名并处于 Active；
- [ ] AnyTLS SNI 与 ECH public name 是两个不同名称；
- [ ] Reality 本机 target 使用独立名称；
- [ ] 所有使用中的 A/AAAA 都指向当前 VPS；
- [ ] 没有 IPv6 时没有错误的 AAAA；
- [ ] 三类记录均为仅 DNS（灰云）；
- [ ] Token 只有 `Zone DNS Edit` 与 `Zone Read`；
- [ ] Zone Resource 只包含目标 Zone；
- [ ] IP 白名单留空，或包含每台 Certbot VPS 的实际 IPv4/IPv6；
- [ ] Token 没有结束日期；
- [ ] 本地 Token 文件只有一行原始 Token；
- [ ] `cloudflare.ini` 是 `root:root 0600`；
- [ ] `mxh-certbot-renew.timer` 已启用；
- [ ] Certbot dry-run 通过；
- [ ] AnyTLS 或 Reality 真实协议验收通过。

## 13. 官方参考

- [Cloudflare：管理 DNS 记录](https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/)
- [Cloudflare：代理状态与 DNS-only](https://developers.cloudflare.com/dns/proxy-status/)
- [Cloudflare：API Token 权限](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
- [Cloudflare：限制 Token 的客户端 IP 与 TTL](https://developers.cloudflare.com/fundamentals/api/how-to/restrict-tokens/)
- [Certbot DNS Cloudflare 插件](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)
- [sing-box：AnyTLS inbound](https://sing-box.sagernet.org/configuration/inbound/anytls/)
- [sing-box：TLS 与 ECH](https://sing-box.sagernet.org/configuration/shared/tls/)
