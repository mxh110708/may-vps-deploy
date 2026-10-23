# v0.9.35 校园与学术分流修复

本版在 v0.9.34 基础上修复通用客户端模板和生成器的业务分类，包含此前未发行的 Hugging Face 下载修复。独立 TCP / UDP 端口转发的第八、九轮开发代码未纳入本次发行。

## 行为变化

- 国内高校、科研院所及 CNKI、万方、维普等校园入口使用明确 DIRECT，并配合本地 DNS，避免可切换的 Direct Route 选择器改变校园出口。
- 学术数据库、出版商、身份认证和全文下载域名使用同一份公开策略目录，覆盖 149 条研究平台后缀、10 条校园／国内后缀及 4 条 ML 开发工具后缀。
- Hugging Face Hub、下载 CDN、Scholar、Colab、Kaggle 和研究机构入口归入 Academic Research；TensorFlow、PyTorch 等开发工具归入 Developer Tools，避免按厂商或 AI 主题粗分。精确业务规则优先于宽泛厂商、国内和广告回退规则。
- Academic Research 选择 Direct Route 时保留本机网络出口。全局模式仍遵循显式全局选择，不被校园规则反向覆盖。ExistingAuthority 不会被通用生成器隐式接管。

具体分类、DNS 边界及当前环境证据见[学术分类审查](ACADEMIC-ROUTING-AUDIT-2026-10-23.zh-CN.md)和[Hugging Face 修复](HUGGINGFACE-RESEARCH-ROUTING-2026-10-22.zh-CN.md)。原有 CNKI 日志已显示直连，本次没有将未复现的代理现象写成已复现故障。

## 验证与发行边界

Google／通用生成回归 9 项、学术策略回归 8 项、客户端兼容纯 Python 回归 8 项通过。固定 Mihomo 与 sing-box 除解析模板和实际生成配置外，各执行 16 次本地回环请求，覆盖校园直连、研究平台全文／认证链路、研究组切换代理、开发工具分类及显式全局模式。

正式包从单独的干净 main 副本构建，执行项目验证、公开材料检查和原生运行环境复核；提供安装 EXE、便携 ZIP、文件清单、SHA-256 清单及固定 Google BBR v3 对应源码。用户自行安装更新，本次不修改现用应用、系统代理或远端 VPS。

回环测试证明规则选择与 DNS 配合，不证明用户已取得校园 IP、学校 VPN 或数据库订阅权限。受限全文下载仍需用户在实际校园访问条件下验证。
