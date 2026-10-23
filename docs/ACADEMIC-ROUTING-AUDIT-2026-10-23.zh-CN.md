# 校园、学术数据库与业务分类审查

本轮修改公共策略、两套通用模板及已明确授权的本机权威配置。没有安装应用、切换节点、改变业务组选择、访问用户账户或重载现用核心。本文记录规则层面的行为，不代表已验证任意学校的全部订阅权限。

## 审查结果

1. **按厂商归组遮蔽了业务用途。** Google Scholar 被 Google Services 的 Google 域名规则覆盖；Colab 与 DeepMind 站点原在 AI Services，Kaggle 与 TensorFlow 等在通用 Google 分类。本轮将学术检索、数据集、研究网站和研究计算归入 Academic Research；OpenXLA、TensorFlow、PyTorch、Keras 开发文档归入 Developer Tools。Gemini、ChatGPT 和普通 Google 登录、文档、视频服务保留原业务类别。域名混合承载多种服务时无法只凭 URL 路径可靠区分，本轮不进行 HTTPS 解密或推测所有同厂商服务的用途。
2. **通用模板和实际长期配置覆盖范围不一致。** 实际配置已有大量学术域名，而公共模板只保留很少的初始条目。新增 `config/academic-services.policy.json` 作为两种格式的共享分类来源，涵盖常用出版商、检索库、文献身份与访问入口、独立全文 CDN、研究资料平台。已有其他自定义学术条目继续保留。
3. **直连标签不必然等于最终直连。** `Direct Route` 是可选出口组；如果被选为 Default Exit，所有引用它的“直连”规则仍可能被代理。校园及国内文献入口改用明确的 `DIRECT`，不依赖该组选择。规则模式覆盖 `edu.cn`、`ac.cn`、知网、万方、维普、读秀、超星等明确域名后缀；不把全部 `.edu` 或国外大学强制直连。
4. **路由和 DNS 必须同时覆盖。** 校园及国内文献域名使用系统 DNS，避免校内解析被公共或代理 DNS 替代；Clash 的相应域名排除 FakeIP。sing-box 复用已有 local/FakeIP 服务，学术域名的 A 查询保留域名信息，以便学术组选择 Direct Route 后仍按原始域名处理。保留原默认解析器及其他 DNS 服务、节点、监听和凭据。

用户举出的 `sysu.co.cnki.net` 是中山大学使用的知网毕业论文系统入口，[学校计算机学院的工作安排](https://cse.sysu.edu.cn/article/2471)列出了该地址。此次读取的原配置已将 `cnki.net` 归入 Direct Route，相关现用日志也明确记录了 `outbound/direct[DIRECT]`，没有证明该次请求被代理。本轮加强其直连及 DNS 保障，但不能据此声称已复现并修复了该站原本的具体访问失败。

## 检索、认证和下载保持同一选择

Academic Research 保留用户可选的代理／直连出口，不自动更改默认项或已选项。补齐的典型链路如下：

| 平台 | 覆盖示例 |
|---|---|
| Elsevier | ScienceDirect、Scopus、Engineering Village、Embase、Reaxys、ClinicalKey；`id.elsevier.com`、`sciencedirectassets.com`、`els-cdn.com` 等 |
| Springer Nature | `springer.com`、`springernature.com`、`nature.com`、BMC 及这些自有域名下的资源 |
| Wiley、Taylor & Francis | `wiley.com`、`tandfonline.com`、`taylorfrancis.com` 等 |
| 检索与文献库 | Web of Science（包含指定中国站入口）、IEEE、ACM、ACS、RSC、EBSCO（含 `ebsco.zone` 登录及 `ebsco-content.com` 内容域名）、ProQuest、JSTOR、OUP、Cambridge、SAGE 等 |
| 身份与解析 | DOI、Crossref、ORCID、OpenAthens、OCLC、Ex Libris 等明确域名 |
| 研究资料 | Scholar、PubMed、arXiv、Hugging Face（含 Hub、下载及 Spaces 明确域名）、Kaggle、Zenodo、Figshare 等 |

域名匹配包含后缀边界，不匹配 `cnki.net.example.invalid` 或 `scholar.google.com.evil.example`。不把所有 AWS、S3、CloudFront、Google Cloud 或共享 CDN 流量整体并入学术组；出版商自有下载域名可以归类，共享云上的任意文件不能据此推断用途。

官方参考：[中山大学图书馆数据库列表](https://library.sysu.edu.cn/basic/860)、[校外访问](https://library.sysu.edu.cn/vpn-visit)、[Elsevier 域名清单](https://www.elsevier.support/scopus/answer/how-can-i-allowlist-your-product-in-our-firewall)、[ScienceDirect 全文下载说明](https://www.elsevier.support/sciencedirect/answer/what-are-the-technical-requirements-for-sciencedirect)、[Scholar 服务说明](https://scholar.google.com/intl/en/scholar/about.html)。目录及订阅情况可能变化，策略采用已核对的明确域名，不承诺穷尽全球数据库。

## 验证

- Google／Hugging Face 策略与生成器 9 项、校园及学术分类 8 项、通用兼容性 8 项 Python 回归通过。包含旧模板修正、重复构建一致、ExistingAuthority 不被自动改写、后缀边界、DNS 复用以及用户自定义节点与出口组保留。
- `Test-ClientCompatibility.ps1` 使用固定 sing-box、Mihomo 核心校验公共模板及实际生成候选，并运行 `academic-routing-native.py`。后者仅启动回环 DNS、HTTP 和代理服务；每种真实核心执行 16 项实际请求，检查校园强制直连、学术直连／代理选择、认证／PDF 域名一致、开发工具分类及显式全局模式。测试复制公共域名规则，不连接现用应用或真实数据库。
- 本机三份候选中的 Clash 另通过已安装的两个 Mihomo 核心；两份 sing-box 候选也通过隔离 CLI 校验。自定义远程取件字段只在 CLI 测试副本中替换为相同缓存规则，原配置的远程取件设置保持不变。
- 写入前后校验 SHA-256，使用当前权威发布锁、原子替换并保留原文件备份；节点、凭据、监听及分组选择均作结构比较。

## 生效及权限边界

本机权威文件和 Route 已导入配置的磁盘规则已更新，**需用户手动重新加载当前配置后生效**。Clash Verge 的 AppData 副本未改；应通过正常导入流程使用权威文件。公共生成器继续仅在 GenericTemplate 模式应用策略，不隐式接管 ExistingAuthority。

选择学术直连可以保留本机当前网络出口，但不能凭空取得校园 IP、建立学校 VPN、扩大数据库订阅或绕过认证。学校官方提供统一门户、VPN 和 CARSI 等校外访问方式；当前网络是否具备授权、某篇全文是否在订阅内，需要在用户实际环境验证。本轮没有使用用户凭据验证受限论文下载。
