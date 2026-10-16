# CTF系统

一套由当前 AI 客户端使用的 CTF 工具、真实留证和共享经验系统。全员获取同一底座；AI 按本机身份恢复首接题型和首读资料。用户日常说“用 CTF系统 做这道题”，给出题面或附件即可。

## 已安装第一版的队友

本次为 2026-10-16 增量升级。先读取 [升级说明](docs/upgrade-20261016.md)。旧版升级器不识别新知识目录；请使用本版提供的 upgrade-to-20261016.ps1 迁移，不用旧脚本强行导入新清单。

## 首次安装

1. 获取本仓库，长期保存在自己的目录。已有用户先备份并按升级说明处理。
2. 让能操作本机文件和终端的 AI 读取 AGENTS.md，按 setup.ps1 / 既有桥接说明定位本机 Python、VM 和依赖。不要复制队长的路径、账号或 SSH 身份。
3. 执行 connect-ai.ps1 或 tools/connect_ai.py，为实际客户端安装 ctf-system Skill/MCP。
4. 放置自己的队内角色卡 team-member.private.json，或通过 tools/ctf_roles.py 首次登记代号。实际发现角色与工具，完成本机调用和 WP 检查；没有验证的项目如实报缺。

## 队友怎么说

首次可说“我是 B，接管这个仓库里的 CTF系统，读取我负责的部分”。已有私有角色登记后，可直接说自己的姓名；AI 通过 ctf_team_role 恢复角色与真实首读路径。身份卡由队内单独提供，真实姓名不公开进仓库；仅凭未登记姓名无法可靠对应代号。

解题：“用 CTF系统 做这道题。”继续：“用 CTF系统 继续这道题。”

角色和队伍配置见 [TEAM_ROLES.md](TEAM_ROLES.md)。周六四人为 A Web、B Pwn、D Reverse、G Crypto；Misc/Forensics 为公共队列。月底七人配置单独登记。角色不限制共享工具，也不代替本机依赖验收。

## 有哪些内容

- tools/：统一工具、Kali 桥接适配、REA 路由、连续网页/GDB、CTFd、CTFCrackTools 和 WP。
- skills/ctf-system/：当前统一 AI 入口；旧 ctf-team-workflow 仅保留兼容。
- knowledge/methods/：可复用方法、SOP 与索引。
- knowledge/obsidian/：Obsidian 项目和上级目录的 CTF 方向笔记。
- knowledge/cases/：已有战例参考，独立解题默认不读取。
- knowledge/history/：历史部署与排错资料，不是当前机器事实。
- team/roles.json：公开代号与首读路径，个人身份登记在本机。

本版注册 100 个通用核心工具，统一 AI 入口为 9 个 MCP 方法，另含 73 篇经验正文。维护机的 106 工具中，3 个 Jev 入口按既有要求留本机，3 个历史题专用验证/探针不进入通用包。知识来源与摘要见 knowledge/catalog.json；完整范围见 bundle-manifest.json。第三方完整克隆、虚拟机、程序安装包、大附件与原始图像不随仓库复制。第三方工具入口有代码不等于对应依赖已装，需要本机安装与实调。

## 本次新增：流量题、调用效率与参考资料

- `forensics_pcap`：离线汇总、TCP/UDP 会话、TCP 流读取、HTTP 对象导出、DNS 与 USB 原始字段。复用已验证的 Kali 桥、系统 Python 和 TShark，无须启用整套可选运行扩展。数据附件自动进入同题私有 WP。
- `ctf_task_health`：查看同题新调用次数、工具耗时、连续失败及重复结果；调用结果自动附提示。提示只供复核，不强制换人或停止任务，模型费用未知。
- NoobCTF 参考检索：运行 `python tools/install_noobctf.py` 拉取固定版本文本并建立索引；使用 `source=noobctf allow_reference=true`。历史题解默认不注入独立解题，下载脚本不执行。完整第三方资料不直接进本仓库。

四人主队列保持不变；新增能力用于改善公共流量题认领、停滞复核和整题交接。详见 [四人分题方案](docs/saturday-four-allocation.md)、[本次升级与用法](docs/pcap-health-upgrade.md)。

## 真实验证与 WP

通过系统调用自动保存参数、返回、失败和证据。支持的网页动作附截图/Trace，终端/GDB 保存真实回放；ctf_finish 默认生成本机带图中文 WP 和私有 ZIP。记录完整不等于答案正确，候选必须有真实计算、原程序或平台依据。

公开仓库没有成员账号、SSH 私钥、管理员数据、原始任务或私有 WP 包。个人模型由当前客户端提供，本仓库不提供模型账号或额度。其他机器与复杂赛题效果不能用发布自检代替。

可选新依赖与可重建桥接见 [运行依赖](docs/optional-runtime.md)。
