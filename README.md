# CTF系统

## 2026-10-30 双模块更新

- **解题能力**：传统 CTF 与破甲完整融合，按本题证据选择工具、POC、工具链和角色协作，破甲可以承担主力。保留全部既有接口及团队身份接口，运行环境与工具清单按本机现测。
- **WP 书写**：在关键且合适的线索、操作和结果页面保留真实截图，关联步骤并嵌入 Word；复用已有原图，一张图确实覆盖过程与结果时可用 `stage=process_and_result`，不为每次调用凑图。缺图或正文缺项仅导出明确标记的草稿。
- 修复能力查询空列表、过期 REA 路由、体检未知项误报正常，以及换行后的 flag 识别；补齐共享流程与角色工作流依赖。

已有 Git 安装直接更新代码后重连 MCP；保留本机配置、身份和 WP。说明与检查命令见 [本次更新](docs/upgrade-20261030.md)。注册数量、依赖就绪、工具成功与答案验证分别核对。

## 2026-10-23 最新团队规则与完整记录

所有队员均使用全题型系统，不按 A/B/D/G 限定主攻方向、资料或工具。不以未登记角色阻塞安装或解题；旧角色表和说明保留作历史参考。按当前题目读取对应方法，不要求一次加载所有题型资料。

队友接收资料时读取 docs/team-records.md，运行 tools/team_records.py verify 和 restore，获取完整共享记录。快照在 knowledge/records/20261023/，按用户要求不加密；其中已审阅处理的 WP、调用日志、附件和图片可随本次发布。新增私人任务和凭据仍不自动提交。历史成功、失败、自建验收和未完成状态分别保留。

一套由当前 AI 客户端使用的 CTF 工具、真实留证和共享经验系统。全员获取同一底座；AI 按本机身份恢复首接题型和首读资料。用户日常说“用 CTF系统 做这道题”，给出题面或附件即可。

## 已安装第一版的队友

本次为 2026-10-16 增量升级。先读取 [升级说明](docs/upgrade-20261016.md)。旧版升级器不识别新知识目录；请使用本版提供的 upgrade-to-20261016.ps1 迁移，不用旧脚本强行导入新清单。

执行 `./upgrade-to-20261016.ps1 -Target <已安装系统目录>`，默认在代码更新后、AI 接入前安装 Word/PDF 依赖；`-Plan` 只预览，不安装。离线可加 `-SkipWPDependencies` 保留 Markdown/HTML，跳过后不代表 Word/PDF 已就绪。首次 `setup.ps1` 也默认安装这些依赖。导出说明见 [WP 指南](docs/wp-guide.md)。

## 首次安装

1. 获取本仓库，长期保存在自己的目录。已有用户先备份并按升级说明处理。
2. 让能操作本机文件和终端的 AI 读取 AGENTS.md，按 setup.ps1 / 既有桥接说明定位本机 Python、VM 和依赖。不要复制队长的路径、账号或 SSH 身份。
3. 执行 connect-ai.ps1 或 tools/connect_ai.py，为实际客户端安装 ctf-system Skill/MCP。
4. 身份登记为可选；按当前全题型规则发现工具，完成本机调用和 WP 检查，并按 docs/team-records.md 恢复共享记录。没有验证的项目如实报缺。

## 队友怎么说

首次可说：“接管本仓库完整 CTF系统，按当前全题型规则安装或升级，并核验恢复 docs/team-records.md 中的共享记录。”已有身份登记可保留，不要求首次登记旧代号才能使用系统。

解题：“用 CTF系统做这道题。”继续：“用 CTF系统继续这道题。”
全员均可处理 Web、Pwn、Reverse、Crypto、Misc、Forensics，按当前题目读取方法。历史角色说明作为参考，不限定资料或工具。

## 有哪些内容

- tools/：统一工具、Kali 桥接适配、REA 路由、连续网页/GDB、CTFd、CTFCrackTools 和 WP。
- skills/ctf-system/：当前统一 AI 入口；旧 ctf-team-workflow 仅保留兼容。
- knowledge/methods/：可复用方法、SOP 与索引。
- knowledge/obsidian/：Obsidian 项目和上级目录的 CTF 方向笔记。
- knowledge/cases/：已有战例参考，独立解题默认不读取。
- knowledge/history/：历史部署与排错资料，不是当前机器事实。
- team/roles.json：公开代号与首读路径，个人身份登记在本机。

本版注册 103 个通用核心工具，统一 AI 入口为 9 个 MCP 方法，另含 73 篇经验正文。维护机的 109 工具中，3 个 Jev 入口按既有要求留本机，3 个历史题专用验证/探针不进入通用包。知识来源与摘要见 knowledge/catalog.json；完整范围见 bundle-manifest.json。第三方完整克隆、虚拟机、程序安装包、大附件与原始图像不随仓库复制。第三方工具入口有代码不等于对应依赖已装，需要本机安装与实调。

## 本次新增：流量题、调用效率与参考资料

- `forensics_pcap`：离线汇总、TCP/UDP 会话、TCP 流读取、HTTP 对象导出、DNS 与 USB 原始字段。复用已验证的 Kali 桥、系统 Python 和 TShark，无须启用整套可选运行扩展。数据附件自动进入同题私有 WP。
- `ctf_task_health`：查看同题新调用次数、工具耗时、连续失败及重复结果；调用结果自动附提示。提示只供复核，不强制换人或停止任务，模型费用未知。
- NoobCTF 参考检索：运行 `python tools/install_noobctf.py` 拉取固定版本文本并建立索引；使用 `source=noobctf allow_reference=true`。历史题解默认不注入独立解题，下载脚本不执行。完整第三方资料不直接进本仓库。

四人主队列保持不变；新增能力用于改善公共流量题认领、停滞复核和整题交接。详见 [四人分题方案](docs/saturday-four-allocation.md)、[本次升级与用法](docs/pcap-health-upgrade.md)。

## 真实验证与 WP

通过系统调用自动保存参数、返回、失败和证据。支持的网页动作附截图/Trace，终端/GDB 保存真实回放；ctf_finish 默认生成本机带图中文 WP 和私有 ZIP。记录完整不等于答案正确，候选必须有真实计算、原程序或平台依据。

公开仓库提供经用户授权审阅的历史解题记录快照，不含成员账号、SSH 私钥、管理员数据或私人机器配置。个人模型由当前客户端提供，本仓库不提供模型账号或额度。其他机器与复杂赛题效果不能用发布自检代替。

可选新依赖与可重建桥接见 [运行依赖](docs/optional-runtime.md)。

## 破甲红队（purge-fusion 1.0.0）

本版把 [dsh-purge](https://github.com/kingcharleslzy-ai/dsh-purge) 27919a32 的红队能力并入本系统，
与原有 `ctf_*` 工具**共用一套 MCP**：

- **56 个 `redteam_*` 工具**（各自 JSON Schema）：资产 / 漏洞 / POC / 隧道 / 会话 / 评分，一题一个 engagement
- **23 个红队技能**：`skills/redteam-*`（清单 `skills/redteam-index.json`，含依赖探针）
- **语义层**：`ctf_redteam_skills` / `_preset` / `_score_rules` / `_roles`
- 证据链：写操作带 `source_step`，`ctf_redteam_*` 自身的记录不能当执行证据

目录：`integrations/purge-redteam/`（上游 `lib/redteam` 全量 + `runtime` + playbook + schemas）、
`tools/ctf_redteam_fusion.py`、`tools/ctf_redteam_semantics.py`、
`config/purge-redteam-preset.md`、`docs/purge-redteam-scoring.md`。

装到**你自己的** CTF 系统（别人的机器）：下载 [Release](release/) 里的
`ctf-purge-fusion-1.0.1.zip`，解压后 `python install.py --root <CTF 根目录>`；
回滚 `python install.py --root <CTF 根目录> --uninstall`。

要求：Python ≥ 3.9；Node ≥ 22（runtime 用 `node:sqlite`，缺失时工具执行会报缺运行时）。
重启 MCP 后 `ctf_tools` 才会出现 `redteam_*`；`python tools/connect_ai.py` 可把 23 个技能分发到各客户端。

边界：技能可用性只到 probe 级；红队评分与 WP 评分两套量纲只并存不合并；未搬 DSH 面板 UI。
