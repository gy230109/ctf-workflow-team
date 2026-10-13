# 第一版已安装用户的增量升级

## 保留什么、更新什么

更新发布白名单中的代码、文档、技能和 `.example.json`。保留当前机器 `.venv`、实际 `config/*.json`、`bridge/config`、SSH 身份、账号、WP、日志与已下载题目。队长的 IP、账号和 VMX 从不作为升级默认值。没有必要重新安装 VMware 或重建 Kali。

Git 用户先在原仓库查看 `git status`。有本机代码修改先保存/备份，使用 `git pull --ff-only` 获取仓库更新；遇到分叉或冲突保留现场，不 reset --hard。ZIP 用户把新仓库包解压到旁边的新目录，不整目录覆盖旧安装。

对于 ZIP 安装用户，旧版还没有更新脚本，从新包运行：

```powershell
# <旧安装> 和 <新包> 使用该电脑实际绝对路径。
& '<旧安装>\.venv\Scripts\python.exe' -X utf8 '<新包>\tools\upgrade_install.py' --source '<新包>' --target '<旧安装>' --plan
& '<旧安装>\.venv\Scripts\python.exe' -X utf8 '<新包>\tools\upgrade_install.py' --source '<新包>' --target '<旧安装>'
```

发布包的 `upgrade_install.py` 提供显式 `--target`；用它核对新包摘要并备份更新旧目录。备份在旧目录 `.local/upgrade-backups/`，原机器配置不在发布白名单中。

Git 已获取新代码或完成 ZIP 增量应用后：

```powershell
.\update.ps1 -Plan
.\update.ps1 -InstallSpecialists
.\install-trae.ps1
.\.venv\Scripts\python.exe -X utf8 tools\ctf_team.py verify
```

下载慢时可仅本次选择已支持镜像：`update.ps1 -InstallSpecialists -PipIndex https://mirrors.aliyun.com/pypi/simple`，不修改全局 pip 配置或 TLS 校验。只补某类用 `-Category reverse` 等。安装过程中不要并发改同一个专项 venv。

## 专项依赖

六类工具计算在 Kali 的独立 `.venv-specialists`，路径根据本机桥的 guest_root 派生；原 `.venv` 保留。必须先真实导入再报告库可用。

| 类别 | Python 依赖 | 原生工具按需 |
|---|---|---|
| Web | requests、BeautifulSoup、Playwright | Chromium、sqlmap、ffuf |
| Pwn | Pwntools | GDB；Pwntools 环境中的 ROPgadget |
| Reverse | LIEF、Capstone、angr、bitstring | GDB；Ghidra/REA/调试器另配 |
| Crypto | SymPy、Z3、fpylll、cysignals、PyCryptodome | Sage 按题另配 |
| Misc | Pillow | file、7z、exiftool |
| Forensics | Scapy、Volatility3 | tshark；内存镜像所需符号 |

已观察 angr 10 与 bitstring 5 的导入不兼容，采用 `angr<10`、`bitstring<5` 的兼容范围，并记录每台机器实际版本。安装成功不代表模型解题成功；某一题的运行环境仍须现测。系统包和第三方大软件不随升级脚本无条件安装。

`logs/team-upgrade/latest.json` 和 `specialists.json` 保存实际升级与导入结果；`ctf_team.py verify` 只验核心。缺一个原生工具时按明示错误补缺项，先用可用替代路线，不把全题型目录当成全题型验收。

## 开机与服务恢复

沿用本机 `start.ps1`、已有登录启动任务和已配置 VM。更新只在当前调用完成后重载 CTF-OS 或重连本服务 MCP。不要强杀其他 Agent、未知端口进程或重启整台 VM。

启动后的就绪依据：正确的服务路径/工具目录、核心 bridge 验收、当前题需要的专项导入。冷启动时间与模型/反代就绪分别测；恢复核心不代表可选网关已登录。仓库的通用启动入口只管理本系统和明确配置的 Kali，不擅自启动队长的其他 VM。

## 回退

保留失败返回和更新备份。更新时单个文件写入失败，复制工具会恢复已替换文件；跨进程终止时先查看 receipt 和备份，核对配置与 WP 再回退代码。不要清空 `.local`、WP 或桥配置来“重装”。Skill 备份也保留在对应 skills 父目录，可在客户端空闲后恢复。
