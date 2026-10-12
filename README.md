# CTF Workflow Team

给六人 CTF 队伍使用的统一工具入口：AI 负责分析与调工具，Windows/Kali 负责真实执行，过程自动按题号留证，结束后生成中文 WP。

首版部署支持 **Windows 10/11 + VMware Workstation + 已有 Kali/Debian Linux VM**。不捆绑 VM 镜像、模型账号、私钥、比赛附件或历史答案。VirtualBox 只做发现提示，尚无自动桥接适配。

## 给队员的 AI

把下面这段交给具有终端能力的 AI：

> 拉取本仓库到你选定的本地目录，先读 AGENTS.md。运行 setup.ps1 -DiscoverOnly 检测 Python、VMware 和现有虚拟机；唯一的 Kali 自动复用，多台时让我选择。运行 setup.ps1 -StartVM -InstallGuest 安装缺失的基础依赖并验收。复用本机已信任的 SSH 身份；缺用户、SSH 登录或主机指纹时只补缺项，不猜密码、不忽略主机验证。最后报告已验证、未验证、未完成及证据路径。先部署，不派题、不调用收费模型。部署后每道题先 wp_init，全部 CTF-OS 调用加 wp_case，同步记录推理注释，关键时刻采集真实截图，结束调用 wp_build 生成中文 WP。

## 一次部署

从仓库目录执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1 -DiscoverOnly
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1 -StartVM -InstallGuest
```

Python 缺失时从 winget 的 Python 官方包安装。主机 Python 依赖安装到仓库 `.venv`；Linux 包只补基础执行工具，Python 模块装入客机独立 venv。没有无密码 sudo 时明确列出缺包，由本人在 VM 中安装后重试，不保存 sudo 密码。

如果 VMware 不在标准安装位置，可给 `-Vmrun`；多台 Kali 给 `-Vmx`。非默认 Linux 用户给 `-SshUser`；专用私钥给 `-IdentityFile`；已有别名公钥固定记录给 `-KnownHosts` 和 `-HostKeyAlias`。首次 SSH 需本人核对指纹并完成登录，脚本只复用已信任记录。VM 必须有 VMware Tools，才能从选定 VMX 得到当前 IP。

验收结果：`logs/team-setup/verification.json`。它检查核心接口、SSH、工具与 Python 模块，**不是整套工具或自动解题成功证明**。

## 每次开机

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\start.ps1
```

复用正在运行的 Kali 和兼容的本机 CTF-OS 服务。端口冲突会报错，不终止别人的进程。可选 `install-autostart.ps1` 注册当前用户登录 5 秒后启动的计划任务；这份通用入口只恢复核心，不自动拉起队长电脑上的 Muteki/反代 VM。

## Agent 接口

不依赖客户端 MCP 配置的入口：

```powershell
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once math_gcd --args values=48,60
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --stdio
```

MCP stdio：`command` 填本机 `.venv/Scripts/python.exe` 的绝对路径，`args` 填 `-X utf8 <本机仓库>/tools/ctf_os.py --stdio`。客户端各自配置，示例见 `docs/agent-integration.md`。HTTP 只监听 `127.0.0.1:8787`，接口 `/tools`、`/call`、`/mcp`；本机调用参数对象与 CLI 一致。

团队版注册 59 个入口。包含数论、编码、受限 Python、Kali、知识检索、Muteki、pwn.college、REA、x64dbg、三个 Jev 工具和五个 WP 工具。**可选适配器注册不等于已安装或已认证**；不分发三项依赖队长历史题目的专用校验/爆破脚本。详情见 `docs/components.md`。

## Jev 判断模型

已加入 `jev_status`、`jev_triage`、`jev_decide`，CLI/HTTP/MCP 共用入口；带 `wp_case` 的调用自动进入本题证据和中文 WP。复用本机 `OPENROUTER_API_KEY`，无需额外 SDK 或本地模型权重。配置和示例见 `docs/jev-integration.md`。

部署只检查配置，不调用收费模型；实际调用需 `confirm=true`。Jev 用于题型判断、给定候选评估，执行与 flag 验证仍使用现有工具。设置密钥后重启服务或重新连接 MCP。

## 自动 WP

```powershell
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_init --args case=demo title=自建验收 category=misc
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once math_gcd --args values=48,60 wp_case=demo
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_note --args case=demo status=observed source_step=2 text=真实返回最大公约数12
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_capture --args case=demo caption=Kali当前画面
.\.venv\Scripts\python.exe -X utf8 tools\ctf_os.py --once wp_build --args case=demo
```

`wp_case` 必须显式传给后续工具；已有桥接 `case` 若已 `wp_init` 也自动记录。没有全局活动题号，避免多 agent 把不同题混在一起。关键推理仍需 agent 以 `wp_note` 写入，记录器不会自动读取所有客户端聊天。经过同一入口的真实参数、返回、失败和时间会自动采集；绕过入口的调用不会自动出现。

输出在 `wp/cases/<case>/reports/<导出编号>/writeup.md`，带摘要清单和工具日志图。**日志图明确标为“非屏幕截图”**。`wp_capture` 的默认来源是 VMware 实际画面；网页/调试器 PNG 用 `mode=file file_path=... source=...` 导入，来源由调用者描述。默认 WP 不导出图片；检查图片像素后 `wp_build include_images=true` 才包含截图。图片没有自动遮盖功能。

WP 是可复现的中文证据稿，按已验证/未验证/未完成区分。AI 可依据它补写题解叙述，但须保留证据引用并核对；工具成功不会被写成“已拿到正确答案”。正文自动遮盖常见凭据与 flag 格式，原始证据仅保留本地，最终分享前仍需检查。

## 已验证

- 本机核心桥已经实测；WP 的隔离、失败保留、完整性与导出规则有自动测试。
- Jev 请求/返回校验、MCP stdio 和 WP 留证路径通过离线 fixture 测试；未调用真实模型。
- 发布包只用文件白名单构建；本机账号、配置、原始题目与 VM 镜像均不包含。

## 未验证

- 另外五台电脑的实际安装、全题型表现、完整比赛解题成功率。
- 首版可选组件在队友电脑上的安装与账号接入。
- Jev 真实账号、模型判断效果和 Windows/Kali 端到端联调。

## 未完成

- VirtualBox、Hyper-V 的自动桥接；自动部署整台 Muteki VM；跨客户端聊天自动采集。
- 团队权限由 GitHub 仓库管理员逐人配置，本仓库不自动邀请或分发账号。

更新后再跑 `setup.ps1` / `verify`；不覆盖已有桥配置。运行记录和配置均由 `.gitignore` 排除，上传代码应只提交白名单文件。
