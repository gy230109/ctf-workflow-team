> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 安装状态、端口和席位描述仅作历史记录，不是当前机器配置。

# Kali 当前状态与执行职责

复查：2026-10-11T18:03:52+08:00。Kali 已恢复，正常重启后统一桥仍可用。

- VM：`<本机路径>`，2 vCPU、4GB、80GiB，VMware NAT。
- 当前实测 IP：`<本机服务地址>/24`，网关 `<本机服务地址>`。入口每次仍查询指定 VMX，固定 SSH 主机公钥，未写死 IP。
- 根盘读写正常，可用 60,042,690,560 字节（约 55.9GiB）；2GiB 交换文件在重启后自动启用。
- LightDM / Xorg 正常，实际图形登录画面已采集；SSH 与 VMware Tools 在重启后自动运行。
- DNS 与 Kali 官方站点 HTTPS 200 验证通过；本次没有扫描题目外的网络。
- GDB 17.1、checksec、strace、ltrace 已安装并实测。现有 file、readelf、objdump、gcc、tshark、binwalk、exiftool、7z 等继续按题使用。
- 独立解题 Python：`/home/<用户>/ctf-workbench/.venv/bin/python3`；pwntools、Crypto、Z3、gmpy2、dnfile、sympy 可用。桥的 `python` 与 `run ... -- python3` 自动使用此环境。
- 修复前记录的 51 个工作目录文件全部 SHA256 一致；zsh 临时历史文件实际写入通过，未覆盖用户原历史文件。

验收使用自建 128 字节输入和小型 C 程序：上传 → GCC 编译 → GDB 断点运行 → checksec/strace/ltrace → AES 往返、Z3 求解、gmpy2/sympy 计算、pwntools ELF 解析 → 回收 JSON。全部退出码 0、输入和回收摘要验证通过。

证据：`<本机路径>`；完整本机修复证据：`<本机路径>`。冷备：`<本机路径>`，冷备摘要已经验证。

本次恢复的是 Kali 执行环境与 Windows 桥。WorkBuddy 已安装同一入口技能；它的模型自行调用，以及 Muteki Worker 直接调用 Kali，仍须各自取得真实执行证据。完整自动 CTF 解题、复核与 flag 提交流程尚未验收。

## 工作流职责

Windows 上的 WorkBuddy 接收题目与整理任务；Codex 维护与排障；Ubuntu VM 上的 Muteki / Coding2API 管理席位及模型接口；Kali 执行 Linux 工具并返回证据。Windows/.NET 专用分析仍在 Windows 按题使用。当前 GLM 主解、DeepSeek 串行复核，Step 禁用备用，Pi 不参与流程。

统一入口：`<本机路径>`。GUI 登录可由用户正常操作，后台工具桥不依赖桌面登录。

## 修复说明

此前根盘只读导致桌面和历史写入失败，挂载依赖修复已经经重启确认。校园桥接网络外网超时后改为 NAT。本轮发现 Kali 客机其实已启动，VMware 地址查询仍错误报告 Tools 未运行；重启 open-vm-tools 后恢复，随后正常重启再次验证自动恢复。

安装预检发现当前 rolling 最新整套包会切换系统 Python 并移除原组件，因此实际使用独立 venv 和与现有 libc/Python 匹配的 GDB 包。原生包安装合计新增 10 个包，升级 0、移除 0，系统 Python 与 libc 原版本保留。GDB 来自 [Kali 官方历史仓库](http<本机路径> `gdb_compat_install.json`。

Ghidra、Sage、jadx 已于 2026-10-12 补齐：jadx `1.5.6`（apt）、Ghidra `12.1.4+ds`（apt，依赖 openjdk-25）、SageMath `10.9`（micromamba/conda-forge，`/opt/sage`）。当前 2 vCPU/4GB 环境按题运行重计算工具，避免占满主机内存。详见 `环境/CTF-OS升级验收-20261011.md` §后续补齐。
