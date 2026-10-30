# AGENTS.md —— 给在本目录工作的 AI agent（Codex / Claude Code / 其他）

## 2026-10-16 WP 二期升级

- 当前核心工具 109 个。新增 `wp_intake` 追加受校验的题面与原附件、`wp_section` 追加有来源的五类正文、`wp_review` 检查稿件缺项。使用实际工具 schema，不要求用户手工初始化或交接路径。
- 接题自动保存题面、来源、原附件 SHA256 及副本；旧 Product 任务导出时可从已有任务档案补入，不回填虚构的历史操作。
- 原脚本与 JSON 请求在执行前快照，执行后漂移入缺项；截图失败写入时间线；不为补证据重跑工具。
- 正文 `writeup.md` 展示章节引用的主线与有界原文预览；完整失败和调用在 `technical.md` 及私有证据。`report.json` 为 Markdown/HTML/Word/PDF 的同源模型，格式错误分别报告。
- 统一完成入口默认导出四种格式；Word/PDF 需要可选依赖，升级脚本会安装。`include_images=false` 排除插图与视觉回放（包括日志渲染，原题附件仍保留）；`include_log_renders=false` 可在包含实际截图时排除冗余日志图。
- `wp_review` 只检查结构/证据引用，不能保证语义正确；题解文字不认证答案。默认文本仍遮盖常见凭据与 flag，私有包不是自动提交成稿。已验证/未验证/未完成须分开，提交和公开前审阅正文、原件及图片像素。
- 详细协议见 `docs/wp-guide.md` 与统一 Skill 的 `references/wp-guide.md`。自建样例验收不计比赛解题率。


## 2026-10-16 新增入口（已本机部署）

- 通过现有 CTF系统 `ctf_tools` 查询 `forensics_pcap`：离线 summary / streams / follow / http_objects / dns / usb。提供原附件 local_file；follow 带 TCP stream_id。实际导出的 TSV、TCP 文本及 HTTP 对象 ZIP 自动附入同题私有 WP。USB 当前提取原始数据和包号，不自动恢复键盘明文。
- 每题调用自动附 `task_health`：统计新调用次数、工具耗时、连续失败与相同参数/结果重复。提示不阻断任务、不调用模型、不计算未知费用。状态轮询、连续调试/浏览器动作默认不作循环；明确复查可加 wp_repeat_expected=true。通过 `ctf_task_health` 查询同题统计。
- `kb_search/kb_read source=noobctf allow_reference=true` 已可用，626 份文本、2399 个片段，固定提交出处与摘要。属于学习参考库，不向独立解题、holdout 或模型测评自动提供题解。Windows 无法创建的上游文件名从 Git 对象读取。
- 基线接口从 104 增至 106；工具成功与真实答案验证仍分别记录。本轮自建样例验收不计比赛解题率。详见 `协同/开源项目增益部署-20261016.md`。

本系统统一名称为 **CTF系统**。用户说“用CTF系统做这道题”时，优先使用 `ctf-system` MCP 的 ctf_start/tools/call/progress/note/finish；这些入口自动定位新版工具、建档和留证。没有加载 MCP 时用本机已安装的 `ctf-system` Skill 备用脚本，无需让用户再复制技术交接。当前用户安装登记为 `~/.ctf-system/location.json`。该接入体验不等于完整解题或所有客户端均已验收。

你现在在 `D:\强网杯大师\`（Windows 本机），这是 CTF 训练与作战目录。

## 一、你手边有 104 个 CTF 工具（CTF系统 / CLI / HTTP，含 CTFd、CTFCrackTools 与自动 WP 留证）

两种用法，**任选一种**：

**1) MCP**（如果你的客户端挂载了 `ctf-os`）→ 直接用工具

**2) 命令行**（一定能用，不依赖 MCP）：
```
python D:\强网杯大师\tools\ctf_os.py --once <工具名> --args <参数>
```
参数用**免引号的 key=value** 写法（JSON 的双引号会被 shell 吃掉，实测踩过）：
```
python D:\强网杯大师\tools\ctf_os.py --once math_gcd --args values=48,60
→ {"ok": true, "result": {"result": 12}, "tool": "math_gcd"}
```
- 多个参数空格分隔：`--args a=1 b=2`
- 布尔：`confirm=true`；十六进制：`0x1f` 能认
- 接口自检：`python D:\强网杯大师\tools\ctf_os.py --selftest`；只验证接口和自建算例
- 实际依赖体检：`python D:\强网杯大师\tools\ctf_os.py --doctor`；不调用模型、不派题
- 完整工具及参数清单通过 MCP `tools/list` 或 HTTP `/tools`（2026-10-15 自动 WP 留证接入后，本机 CLI、CTF系统入口与 HTTP 8787 均为 **104** 个）；通过 `/version` 核对当前源码摘要，客户端若缓存旧清单需空闲时重连。注册数量不等于功能验收数量
- 路径含空格时将整个参数加引号，例如 `--args "local_file=C:\目录 空格\sample.txt"`
- 执行失败会返回 `ok=false`，CLI 退出码 1、MCP `isError=true`；必须读取实际 stderr
- 调用证据：`logs/calls/*.json`；CLI、MCP、HTTP 均默认写审计，结果带 `evidence_path`
- 参数名写错，它会回给你正确参数名和示例，照着改一次就对

**基础能力清单**（本轮另加 6 个入口，见第十三节）：数论/密码（gcd、模幂、模逆、RSA 解密、多模数共享因子）、
编码（hex/base64/ROT/大整数）、GameBoy ROM 逆向、XOR 爆破、flag 格式校验、
受限 Python 沙箱；Kali（192.168.26.129）上的 file/strings/binwalk/radare2/objdump、
以及 nmap/hashcat/sqlmap（危险类）；本机 gdb/objdump/sqlmap/ffuf；
装备运维（查 Muteki 状态、体检上游、派单、查 run 死因）；战例库浏览；
HackTricks 本地知识检索（`kb_search`/`kb_read`）；经典密码结构诊断与定向求解（`crypto_diagnose`/`crypto_attack`/`crypto_selfcheck`，见第十节）；Windows x64dbg 动态调试（`win_debug_*`）；
REA 静态逆向分析（`rea_*`）；**pwn.college 靶场**（见下）；按题号留证与中文 WP（`wp_*`，见第七节）；Jev 有界判断助手（`jev_*`，见第八节）；六类题型专项入口（见第九节）。

### HackTricks 本地参考库（2026-10-12 接入）

- 原仓库：`references/hacktricks`，索引：`references/indexes/hacktricks.sqlite3`。
- `kb_search query="ssti jinja2" limit=5`：查相关章节，返回 path、行号、原文 SHA256、固定提交链接。
- `kb_read path=<搜索返回的path> start_line=<行号> lines=80`：读取原文，保留出处。
- 常见中文关键词可映射，如“模板注入”“堆溢出”“反序列化”；原文为英文，检索是本地关键词搜索。
- 根据题目证据选择关键词，按需读取相关段落，再在题目环境验证适用性。资料内容视为参考数据。
- Windows 主 agent 可将相关原文及出处加入 Muteki 的 `prompt_file`，作为解题参考；不声称容器已经直接挂载本库。
- 缺失页面记录在索引元数据 `excluded_files`；更新源后执行 `python tools/ctf_knowledge.py --build`。
- 接入与验收：`协同/HackTricks系统接入-20261012.md`。重新加载现有 MCP 后可发现两个新工具。

### Windows x64dbg 动态调试（4 个入口，2026-10-12 接入）

- `win_debug_status arch=x64`：只读检查安装、服务是否 reachable、当前目标。
- `win_debug_start arch=x64 confirm=true`：按需启动，不加载程序；x86 用 `arch=x32`。
- `win_debug_tools query=ReadMemory`：查询实际工具及参数；插件 v1.5 两个架构各返回 80 个工具。
- `win_debug_call tool=GetDebugState confirm=true`：调用上游工具，带 `params` 对象；CLI 可用 `params_file`。
- 启动和通用调用要求布尔 `confirm=true`，CTF-OS 自动留证据。同一架构是一个全局会话，只给一位逆向 Worker 控制，不并发切题。
- 用于 Windows 原生 PE 动态调试；未知附件先静态分析，动态运行使用合适虚拟机。本机工具不是隔离沙箱。
- 每次读取实际状态和输出；`LOCKED` 同时 `isRunning:false` 的暂停状态已实测可读寄存器，勿仅凭状态名猜测。超时不代表目标停止。
- 安装、断点/单步/读取自建 x64 程序已验收；**x32 实际断点与单步也已验收**（2026-10-12 第二轮），
  WorkBuddy 主 agent 已实际自行调用四个入口。Trae / Muteki 侧未验。见 `协同/x64dbg系统接入-20261012.md`。
- 🔴 `LoadBinary` 后**暂停位置常在 ntdll（系统断点）**，`currentAddress` **不是程序入口**。
  要拿入口：用 `ListModules` 取主模块基址 + PE 头的 `AddressOfEntryPoint` 自己算；
  **基址是 ASLR 后的值，不能用 PE 的 ImageBase**（实测 0xE00000 vs 头里 0x400000）。
- 🔴 **调试器进程随发起它的调用/脚本结束被回收**。多步调试要在同一次调用（或同一个脚本）里
  一口气做完；跨调用接着调之前先 `win_debug_status` 现测，不要假设会话还在。
- 本机 `gcc -m32` **编不出 32 位 PE**（winlibs 是 x86_64 单架构，缺 32 位库）。
  要 32 位自建目标用 `nasm -f win32` + `ld -m i386pe`；且 **nasm/ld 啃不动含中文的路径**，
  编译目录用 ASCII，编完再拷回。

### REA 静态逆向分析（3 个入口，2026-10-12 接入）

- `rea_status`：看分析引擎配置与绑定状态（Ghidra 是否 `available`）。只读。
- `rea_ops`：列 REA 可用/不可用 operation。只读。
- `rea_run command=<子命令> args=<字符串数组> timeout=<秒>`：调用 REA 逆向分析，默认输出 JSON。
- 引擎：`rea-agents@6.4.0` + 本机 Ghidra 12.1.4（`D:\Apps\ghidra_12.1.4_PUBLIC`）；配置在 `config/rea.json`。
- 原生 PE 用 `command=inspect`（**冷启动 Ghidra 可能数十秒**，timeout 上限 600）；`.NET` 用 `command=inspect-managed-members`（不需要引擎）。
- 只读子命令直接跑；改外部状态的（`setup`/`uninstall`/`update`/`install-adb-*`/`push-adb-file`/`start-adb-*`/`stop-adb-app`/`pull-adb-*`）必须布尔 `confirm=true`。
- 分工：REA 负责**静态**分析（结构/字符串/函数/交叉引用），x64dbg 负责 **Windows 动态**调试，两者配合。
- 上游 Windows Ghidra 属**实验性 P0**，只读、仅本机原生 x86/x64 PE。接入与验收见 `协同/REA系统接入-20261012.md`。
- **2026-10-12 实测已通**：`inspect` + `function` 对本机 x86 PE 成功（`exit_code:0`，38~42s），Ghidra 后端真实出伪码/汇编/调用者。
- 🔴 **REA 给的是文件地址，x64dbg 给的是运行时地址**：`运行地址 = ASLR基址 + RVA`，`RVA = 文件VA − ImageBase`。实测 REA 说 `start@0x40100d`，x64dbg 侧 `entry_va=0xE0100D`（基址 `0xE00000` + `0x100D`）——同一函数两侧可互证。
- `function` 的真实签名是 `rea function <path> [address]`，**藏在报错文本里**；别猜参数，先 `rea_ops`，或先跑一次 `--help` 读错误信息。

### 强网杯官方归档（2026-10-12 接入）

- `题目库/CTF-Archives/`：`org:CTF-Archives` 搜 `qwb` 的 6 个官方仓库快照 + **113 个 Release 附件**（约 1.95 GB）。含八强/七强/九强线上/九强线下/S6 青少年/2024 青少年专项。
- 每目录：`attachments/`（官方 handout）、`README.md`（索引与警示）、`UPSTREAM-README.md`（官方题面原文）；上级 `MANIFEST-files.txt` 逐文件 SHA256。
- 🔴 `2024-qwbs8/UPSTREAM-README.md` **内嵌 “Master of DFIR” 取证题答案**，解该题禁读；其余 README 为官方题面，可参考。
- 浏览：`case_list which=题目库`。分析：静态 `rea_run` / 动态 `win_debug_*` / Linux 密码走 Kali。
- 附件均为原始 handout，**不是答案**；不含 writeup/评分表。见 `题目库/CTF-Archives/README.md`。

## 二·补 pwn.college 靶场（6 个工具，2026-10-11 封装）

| 工具 | 干什么 | 危险 |
|---|---|---|
| `pc_find` | 列未完成的题（不传 dojo = 全站近万道） | 否 |
| `pc_pull` | 拉题：起容器 + 下载 `/challenge` 附件 + 交接 Kali | 否 |
| `pc_run` | 在容器里跑命令（**题目二进制在 `/challenge/`，不是 `./main`**） | 🔴 |
| `pc_submit` | 提交 flag | 🔴 |
| `pc_status` / `pc_stop` | 看当前活动挑战 / 终止容器 | 否 |

**一道题的完整链路**（已实测跑通并 solved）：
```
pc_find dojo=reversing-hell limit=50       # 拿题单（module + challenge）
pc_pull dojo=... module=... challenge=...  # 起容器、下载、交接 Kali
# 分析：本地 Python / objdump / strings 优先，必要时上 Kali
pc_run cmd=/challenge/main stdin=<key> confirm=true   # 喂输入拿 flag
pc_submit dojo=... module=... challenge=... flag=pwn.college{...} confirm=true
```
🔴 **这些题多为 crackme**：flag 不在二进制里，要逆向出 key 再运行才拿得到。
🔴 **只提交真实运行得到的 flag**，绝不猜——错提交会污染账号记录。
🔴 题目要求 `stdin` 输入时记得带 `stdin` 参数，不带就是空输入。

## 二·再补 Kali 上的逆向/密码重装备（2026-10-12 现测）

| 工具 | 版本 | 怎么调 |
|---|---|---|
| `kali_sage` | SageMath 10.9 | `--once kali_sage --args code="print(factor(2026))"` |
| `kali_ghidra` | Ghidra 12.1.4 | 无头 `analyzeHeadless`，**GUI 需要 X，别指望** |
| `kali_jadx` | jadx 1.5.6 | `--once kali_jadx --args local_file=<apk/dex/jar>` |

Kali 上的坑（踩过，别再踩）：

1. **apt 镜像有坏的**：`mirrors.qlu.edu.cn`（IPv4 超时）、`mirrors.neusoft.edu.cn`
   （只解析 IPv6，而这台 VM 没有 IPv6 路由 → 网络不可达）。
   装包用官方源 + 强制 IPv4；源已固化到 `kali.download`，`apt update` 干净。
2. **Sage 不在 apt 源里**（`候选：(无)`），它在 `/opt/sage`，直接 `sage` 调用。
   别再 `apt install sagemath`。
3. **Ghidra GUI 需要桌面**；无头分析只能走 `/usr/share/ghidra/support/analyzeHeadless`。
4. ~~`kali_run` 的 `cmd` 不能含逗号~~ —— **已修**（2026-10-12）。
   原因是我早先的 kv 解析器会把 `a,b` 拆成数组，带逗号的命令被拆碎 → 127，
   现象看着像"命令不存在"。现在只有 `values/numbers/args` 这类显式数组键才按逗号拆。
5. `kali_run` 的 `timeout` 上限 **600 秒**；更长的任务要 nohup 后台跑再轮询。

## 二、五条规矩（违反会被系统拒绝，或被视为越界）

1. **危险工具必须带 `confirm=true`**：
   `kali_nmap` `kali_hashcat` `kali_sqlmap` `local_sqlmap` `local_ffuf`
   `kali_run` `muteki_dispatch` `pc_run` `pc_submit` `win_debug_start` `win_debug_call` —— 不带系统直接拒绝，别反复试。
2. **Kali 是另一台机器**，它看不到本机文件。分析本机文件时用 `local_file`
   参数，系统经已验收的桥上传并校验 SHA256 后再跑。默认按文件摘要分配独立题号，
   也可提供 `case`；原附件不覆盖，执行保留客机日志。桥路径配置在 `config/ctf_os.json`。
3. **flag 必须由人本地亲手跑出来**。flag 相关工具只做格式校验，不产出答案。
   你可以给：方向、该调哪个工具、中间量、验证方法 —— **不要给最终 flag**。
4. **先算最便宜的那一步**，再决定上什么算力：
   能看源码别硬逆，本地 Python / z3 能算的别上 Kali，能静态分析别动态调试。
5. **报错按原样读，别脑补**。没看到的东西别假设，拿不准就说拿不准。

## 三、目录约定

| 目录 | 放什么 |
|---|---|
| `tools/` | 脚本（**不许硬编码绝对路径**，用 `BASE` / `sys.argv`） |
| `题目库/` | 题目与附件 |
| `战例库/` | 每道题的复盘（认知差 + 触发条件 + 可迁移性 + 边界） |
| `协同/` | 对外话术、接入卡 |
| `logs/` | 服务日志与调用审计 |

- 新写的 .md 要同步到 Obsidian：`python tools/sync_to_obsidian.py`（冲突以 D 盘为准）
- **落盘位置约定（2026-10-15 用户要求，长期有效）**：**一切新产生的文件都放 D 盘**（系统本体 `D:\强网杯大师`；临时/工作文件用 `D:\Temp\...`）。**C 盘上已有内容保持不动、不迁移**。不要在 `C:\Users\...\Documents\...` 下新建工作/交付目录；确有工具把产物写到 C（如 Kali 回传镜像），先报给用户再决定。
- 写报告**必须分区**：已验证 / 未验证 / 未完成，三栏不许混
- 协同文件里**不写** 密码 / Key / token / flag / 种子 / solver 正文

## 四、当前装备状态（2026-10-12）

- Muteki（比赛套）：`192.168.26.130:3001`，已修好，`step-5-preview` 可用，EasyRsa 5/5 通过
- Kali：`192.168.26.129`，可达。jadx / Ghidra / SageMath 已补齐（`--doctor` 的
  `missing_optional_kali_commands` 为空）；apt 源钉在 `kali.download` 并强制 IPv4
- Trae：`D:\trae-cn\`，MCP 配置已写（需重启 Trae）
- 火山方舟 API Key 还没提供，冗余上游未接

🔴 状态会变。**用之前现测**，别信本文件里写的状态：
`python D:\强网杯大师\tools\ctf_os.py --once status --args x=1`

## 五、2026-10-11 系统升级的使用约定

- `status` 的 Muteki 项仅证明配置 API 可访问；没有执行模型推理，不代表完成解题。
- `--doctor` 检查基础执行环境，同时列出缺失的可选工具。`doctor_passed` 不是全工具、全题型验收。
- `kali_run` 推荐提供 `argv` 字符串数组和 `case`；原 `cmd` 仍支持，需要布尔值 `confirm=true`。
- `muteki_dispatch` 必须有实际存在的 `prompt_file`；默认一个尝试，进程锁限制本机派发器并发。
  有未结束任务时拒绝重复派发；停止状态未确认时不重派。模型配置沿用当前设置。
- `flag_format_check` 只证明格式匹配，不证明答案正确。其他历史脚本需确认适用题目，不能当作通用答案判定器。
- 验收记录：`环境/CTF-OS升级验收-20261011.md`。当前 Codex 任务只做系统升级，不解题、不提交 flag。

## 六、登录后自动恢复（2026-10-12）

- Windows 登录触发器：`CTF-OS-常驻` 负责低权限运行统一接口；`CTF-Stack-Autostart` 在登录 5 秒后恢复网络、两台 VM 与 Muteki/Coding2API。三个 VMware 基础服务已设为自动。
- 入口：桌面 `CTF系统-启动`、根目录 `启动CTF系统.bat` 或 `启动CTF系统-无窗口.vbs`；这些入口请求同一计划任务，复用现有组件，不强杀端口进程。
- 看本次启动：`logs/startup/latest.json`，必须核对 `started_at`、`status` 和 `components`；旧的 `ready` 不能当作当前在线证据。当前在线仍用 CTF-OS `status` 现测。
- 配置：`config/startup.json`；日志与逐次记录：`logs/startup/`。Kali 路径继续从既有桥配置读取，不另造一条 SSH 通道。
- 新启动流程不派题、不调用模型、不改变席位；x64dbg、图形分析器按需启动。注册和温启动已验证；整机关机再开机的时间未测，见 `协同/开机自动恢复-20261012.md`。

## 七、中文 WP 与团队分发（2026-10-12）

用户已要求在解题过程中记录真实操作、截图和说明，并形成中文 WP。系统升级本身不启动题目任务。

1. 每题先调用 `wp_init case=<独立英文题号> title=<标题> category=<题型>`。
2. 后续 CTF-OS 工具调用显式加 `wp_case=<同题号>`，自动保存真实参数、返回、失败和时间。检查结果中的 `wp_record`；若有 `wp_record_error`，操作可能已经执行，不要直接重复执行。
3. 用 `wp_note case=... status=observed source_step=<实际步骤号> text=<说明>` 记录有证据的结论；假设用 `hypothesis`，待办用 `todo`。工具不会自动读取所有客户端聊天，绕过 CTF-OS 的调用也不会自动入稿。
4. 关键画面用 `wp_capture case=...` 采集 Kali 实际屏幕；网页/调试器图片可用 `mode=file file_path=... source=...` 导入并注明来源。自动生成的命令日志图明确标为“非屏幕截图”。
5. `ctf_finish` 现在默认生成带图的本机中文 WP 与私有证据 ZIP；底层 `wp_build` 直接调用仍默认不导出截图和原始证据。按用户要求，本机完整包可先包含未经对外审阅的图像；公开分享前检查正文、原始文件与图片像素，常见文本遮盖不是完整去密保证。
6. 原始证据仅留本机；WP 按已验证 / 未验证 / 未完成组织，不能把接口成功、工具成功或格式正确写成题目已解。详见第十七节，缺证据不重跑原动作。

本机 CLI、CTF系统入口与 HTTP 当前注册 **104** 个工具（2026-10-15 自动 WP 留证接入后）；团队版已发布为 **82** 个（2026-10-13，commit `6b164b4`），同样不含 Jev。若现有客户端仍列出此前清单，先用 CTF系统实时发现，空闲时重连。不得为加载工具强杀正在工作的其他 Agent。

团队公开仓库：https://github.com/gy230109/ctf-workflow-team （2026-10-12 按用户要求公开，GitHub 回读已确认）。任何人均可查看和克隆。队友先读仓库 AGENTS.md，再运行 `setup.ps1 -DiscoverOnly` 和 `setup.ps1 -StartVM -InstallGuest`；复用已有 VMware/Kali 和可信 SSH 登录，缺少的身份配置由该机器所有者补充。安装验收看 `logs/team-setup/verification.json`。

交付与验收：`协同/团队版与中文WP交付-20261012.md`。本机已验证核心部署与 WP；其他队友机器、全题型成功率和整机冷启动尚未验证。

## 八、Jev 本机判断助手（2026-10-13 文档收尾）

用户要求仅在本机接入；本次未修改 GitHub 仓库、团队模板、分发 checkout 或 ZIP。
本机代码和配置在 `tools/ctf_jev.py`、`config/ctf_jev.local.json`；复用已有 Node、jev-use 和本机环境变量凭据。没有新增常驻服务。
“本机接入”指适配代码与配置仅放在本机；Jev 模型判断仍调用在线 TypeSafe 服务。

| 入口 | 用法与边界 |
|---|---|
| `jev_status` | 只读检查配置、运行时和凭据是否存在；`last_live_check` 是历史记录，不等于当前模型可用 |
| `jev_judge` | 对已取得的事实批量选择候选项、评分或核对证据；MCP 可传 `state/questions`，CLI 推荐 `request_file=<本机JSON文件>` |
| `jev_ctf_triage` | 在一次请求中建议题型、从显式列出的实际可用工具中选下一步、检查当前结论的证据；`candidate_tools` 支持字符串数组或逗号分隔 |

适合有界语义判断时优先使用 Jev，同一状态的独立问题合并调用；查文件、精确计算、生成代码、复杂推理和实际执行由主 Agent 与既有工具完成。
Jev 仅返回建议，不自动执行所选工具，不认证最终答案，不给每次工具调用加审批钩子。
只提交判断所需的事实摘要；参考答案、私密 flag、密钥、种子与 solver 不进入判断输入。入口的文本遮盖是尽力处理，不能替代调用者选择最少输入。

**实际限制**：2026-10-12 接入验收及 2026-10-13 图片题试调用均返回 HTTP 451 `region_unavailable`（TypeSafe 在当前地区不可用）。
此时 `ok=false`、`model_success=false`、`requires_main_agent=true`、`fallback=main_agent`；主 Agent 自行继续，不循环重试，不把失败写成 Jev 已作出判断。
默认置信阈值 0.7 是暂定设置，尚未进行 CTF 领域校准；低置信、升级、超时或其他失败同样交回主 Agent。

调用加 `wp_case` 可将请求、真实返回或失败记入该题 WP。用 `jev_status` 只能确认入口，在线判断必须取得实际成功返回。
本机现有 MCP 若能发现三个 `jev_*` 即可直接调用，否则先走 CLI，空闲时重连；不强杀其他 Agent 的工作。
51 项回归测试通过（包含模拟 Jev 响应与既有系统回归），Kali 实际工具输出、Jev 451 与 WP 留证均已验证；**尚未取得有效的在线 Jev 判断**。
验收与接入说明：`协同/Jev本机接入-20261013.md`。

## 九、六类题型专项增强（2026-10-13 本机落实）

先调用 `ctf_profile category=web`，category 可为 `web/pwn/reverse/crypto/misc/forensics`，读取对应路线。
再 `ctf_specialist_status` 现测专项环境；`modules.<模块名>.import_usable` 是实际导入结果，文件存在或旧的安装日志不能替代它。

| 题型 | 本机专项入口 |
|---|---|
| Web | `web_http_inspect`、`web_html_parse`、`web_jwt_decode`、`web_browser_capture` |
| Pwn | `pwn_elf_info`、`pwn_cyclic`（generate/find）、`pwn_rop_search` |
| Reverse | `reverse_binary_info`、`reverse_disassemble`、`reverse_symbolic` |
| Crypto | `crypto_factor`、`crypto_crt`、`crypto_z3`（结构化或 SMT-LIB2）、`crypto_lll`、`crypto_aes_decrypt` |
| Misc | `misc_file_inspect`、`misc_archive_list`、`misc_image_inspect` |
| Forensics | `forensics_pcap_summary`、`forensics_volatility` |

1. 本机适配器在 `tools/ctf_specialists.py`，实际计算由 `tools/ctf_specialist_worker.py` 经原桥送到 Kali 的独立 `.venv-specialists` 执行。本机路径与 Python 位置从 `config/ctf_specialists.local.json` 和原桥配置读取，不另建 SSH 身份。原解题 venv 保留。
2. 附件用 `local_file=<本机路径>` 上传并校验 SHA256；已有同题客机文件用 `target=<同题相对路径>`。`case` 与 `wp_case` 必须一致。工具保留真实 stdout/stderr、退出码、超时和本机审计。
3. 每题仍先 `wp_init`。调用显式带同一 `wp_case`；复杂矩阵、约束、整数数组建议用 MCP/HTTP 对象或 `request_file=<本机JSON>`，将 `wp_case` 留在外层调用参数中。
4. HTTP 检查、网页截图与 `ctf_install_category` 必须布尔 `confirm=true`。网页截图仅加载题目同源与显式 `allow_origins`，用真实 Chromium、保留浏览器沙箱和 TLS 校验；PNG 经 SHA256 回收后自动导入 WP，导出前仍须检查像素。
5. `ctf_install_category category=reverse confirm=true` 只在专项 venv 补该类 Python 包；`all` 需显式指定。原生 GDB/sqlmap/ffuf/tshark/Chromium 等复用现有安装，不重复升级系统包。按缺项补，安装期间不同时修改同一个专项 venv。
6. 默认单次 60 秒、专项 Python 地址空间预算 1536 MiB；Chromium 因虚拟地址预留大，改用同任务 RSS 预算监测。Bridge 到时终止该调用进程组，不连带其他题。符号执行有步数/状态数限制，结果只作候选，须用真实目标回放。
7. 已固定兼容依赖 `angr<10`、`bitstring<5`，当前实际为 angr 9.3.4 / bitstring 4.4.0。原初装的 angr 10.0.3 依赖导入失败已保留证据。完整版本冻结见专项安装记录，不能把 pip 元数据检查当实际库可用。
8. 当前运行代码是依照上午功能清单与已收取源码核对的本机兼容实现，云端原始包另存 `logs/specialists/cloud-source-verified`，不会混入运行目录或团队分发。原始压缩包首次校验失败未执行，改用文本分块校验接收。以当前 `/tools` 的实际名称和参数为准。

新增 23 个入口。65 项本机回归通过，28 项真实工具检查通过，另有 HTTP 与实际网页截图/WP 往返验证；自建 ELF 的符号候选已实际回放。它们是系统验收，不是比赛题解成功率或模型排名。
Volatility3 安装/离线插件入口已验，真实内存镜像与匹配符号分析仍未验；复杂样本、题型覆盖率和整机冷启动仍需独立验证。
接入说明与真实证据：`协同/专项增强本机落地-20261013.md`。本轮没有发布 GitHub、切换模型席位或提交比赛答案。

## 十、经典密码结构诊断与定向求解（2026-10-13 本机落实）

`tools/ctf_crypto.py`。起因是「黄道十二官」一题（135 字符 / 25 符号 / 9×15 网格）未解出，
复盘确定短板不在线索而在方法论：逐个假设写一次性脚本盲试，且把弱求解器的阴性结果当成了排除证据。

| 工具 | 作用 |
|---|---|
| `crypto_diagnose` | 只读、秒级。输出重合指数 IC、列 IC 扫描（判多表周期）、符号数/密度/语义（键盘行、数字、标点）、长度分解，并按先验给出密码族排名 |
| `crypto_attack` | 按先验排名定向求解：单表替换 / 转置（读序枚举，含 Z340 式块交错）/ 多表 / 同音替换 / Bifid；返回候选明文、求解器自检状态、flag 正则命中 |
| `crypto_selfcheck` | 用已知明文测试向量验证各求解器真实能力 |

三条硬规矩：

1. `self_check_passed=false` 的结果只能记为「未测出」，**不得当作假设已被排除**。先跑 `crypto_selfcheck`，只采信自检通过的求解器给出的阴性结论。
2. 先 `crypto_diagnose` 定方向再求解；不要跳过诊断直接堆暴力。转置不改变单字母频率，因此 IC 未达 0.06 就能排除「单表 + 纯转置」。
3. 语料 n-gram 模型落盘缓存在 `logs/crypto_ngram.pkl`（可用 `CTF_CRYPTO_CACHE` 改路径，`CTF_CRYPTO_CORPUS` 换语料根）。首次调用会建表，之后秒级。

求解器仍是本机实现，能力由自检数据说话；对「黄道十二官」这类短样本高难度古典密码尚未证实可解，
不得据此宣称该类题目已有稳定成功率。

## 十一、练题/秒题（**见题就秒**）本机落实（2026-10-13）

**目标：让解题越来越快 —— 看到特征直接跳到"一招"，不再从头推。**

### 秒题（每题 0 成本起步）
1. 先跑 [速查卡.md](速查卡.md) 的 5 步分诊（体积/mod16/重复块/magic/可打印串）。
2. 再按 [秒题索引.md](秒题索引.md) 的「**识别特征 → 一招解法 → 现成命令**」对号入座。
3. 关键结论要能被**外部独立复算**（`p*q==n`、`pow(m,e,n)==c`、AES 重加密 == 密文）。

### 练题工作流（**不写 WP**）
见 [13-训练闭环.md](13-训练闭环.md) 的「练题模式 · 高效工作流」一节（六步：取题→读题读答案→真机复现→抽方法论→收尾三问→同步）。
练题阶段**不跑 `wp_build`**；WP 只在比赛时写。经验沉淀到 [06-密码SOP](06-密码SOP-连分数与素数幂RSA.md) / [战例库](战例库/) / Obsidian。

### 台账与进度
- `题目库/_queue.json`（113 题）：`python tools/qwb_queue.py` 看/改状态（`set <name> <solved|blocked|...>`）。
- 状态口径：`solved`=**真机跑出真实 flag 并外部验证**；`blocked`=动态附件/在线题等本地拿不到参数。

### 给本机 / 别的 agent 的分发包
- **只给 zip**：`分发/ctf-practice-kit-20261013.zip`（知识层：秒题索引+契约+回传规范+SOP+战例+台账）。
- 包内 `契约-给执行Agent.md` 定义流程与铁律；`回传规范.md` 定义回传格式（人读 `.md` + 机读 `experience.jsonl`）。
- **回传**：`.md` 写进 `战例库/<case>/README.md`；`.jsonl` 追加经验行；本机 agent 直接落盘，远程 agent 发回后由队长合并。

### 铁律（不变）
- **绝不臆造 flag**：flag 只能来自本机真机输出；跑不出记「未复现」。
- 用公开题解的**参数/手法**必须**标来源**，结论以本地复算为准。
- 新写的 .md 记得 `python tools/sync_to_obsidian.py` 进 Obsidian。

## 十二、2026-10-14 运行统一、REA 路由与本机题库（当前入口）

- `ctf_profile category=reverse local_file=<附件>` 返回基于文件头的 `reverse_routing`。Windows 原生 PE 明确先用 REA inspect/function；.NET 使用 managed members；ELF 走 Kali 并核对架构/解释器；Android 先 jadx；源码和未知格式分别处理。REA 的文件 VA 与调试器运行地址仍须换算。
- HTTP `/version` 返回运行源码摘要及磁盘摘要；两者相等且 `reload_required=false` 才是同版本。CLI、HTTP 与全新 MCP 连接已实测同 88 个工具、同源码摘要。〔2026-10-15 更新：本条描述的是当时（旧 8787 实例）的 88 个工具；新版 CTF系统 独立入口现为 **103** 个（CTFCrackTools 接入后），旧连接不得冒充新版。〕项目 Trae 和本机 Codex 的 CTF MCP 入口已改为 `tools/ctf_mcp_proxy.py`，转发到本机 8787；旧连接空闲时重连，不强杀其他 Agent。
- 本机 `questionbank/` 已接收去重 2485 条目录。第一批 66 题/86 个附件逐文件校验通过，66 题已有经核对的净化题面；其余目录不等于本机可解。231 道 holdout 仍默认保留。
- `tools/ctf_pipeline.py prepare <id> --case <新英文题号>` 取题；`run --task-dir <准备目录> --case <同题号> --judge-config <本机判题配置>` 派发单 Worker，默认 Codex、本机已有登录；Muteki 必须显式 `--backend muteki`。没有真实判题器不派发。具体操作看 `.trae/skills/ctf-system-local/SKILL.md`。
- Worker 验收要求实际工具调用、原程序正/负对照、独立回放和 WP 完整性；程序启动失败/架构不符/崩溃不能算负对照。真实比赛提交单独记录。自建样例不计入比赛题成功率。
- 已有一次独立 Codex Worker 的 REA inspect/function 与自建 PE 原程序正负验证成功，共 5 次工具调用；后续正式取题路径验收受到模型提供方风险拒绝，**最终完整流程尚未全部通过**。不能拿此前成功记录替代当前模型可用性。
- 2026-10-14 后续 Muteki 接入已修复为 `stepfun/step-5-preview-free`，只走 Kilo；调度端补齐 `/v1`。实际容器 CLI、普通随机文件 SHA256 工具往返及调度端测试通过，启用配置已回读；详见 `协同/Muteki模型接入修复-20261014.md`。这不等于完整 REA 解题已通过。此前 CodeBuddy 额度耗尽、Zen 来源限制及具体 Codex Worker 的 `provider_safety_rejection` 仍保留原始记录；不循环重派，不换措辞或通道规避拒绝。Trae 自己调用工具的完整模型验收仍未做。
- 本轮实际是系统升级与盲测验收，按用户要求留 WP；第十一节“读答案练习/不写 WP”是另一种学习模式，不用于此次独立 Worker 验收。
- 报告与证据：`协同/系统统一与端到端验收-20261014.md`、`logs/system-upgrade-20261014/`。本轮改动保存在本机；团队 checkout 未改，Jev 仍仅本机。


## 十三、2026-10-15 直接部署的运行增强

用户要求跳过测评，已新增 ctf_runtime_status / qemu_run / kali_debug_session / web_browser_session / crypto_library / misc_stego。CTF系统入口实时发现 94 个核心工具，原八个入口名称不变；工具加载/会话接入成功不等于解题成功。QEMU user 11.1.0、ARM64 运行库、GDB multiarch 17.2、Pwndbg 2026.09.15、crypto-attacks 固定提交与隐写工具已落地。连续会话按题隔离、闲置自动关闭；动态调用保持 confirm=true。先 ctf_tools 查实际参数，不要求用户交接路径。

2026-10-15 13:48 复查：旧 ctf-os HTTP 8787 已自动重载完成，实际清单 94 工具，后台/磁盘/CLI 源码摘要一致，reload_required=false；本轮新增 6 个全部存在。“等待空闲重载”已是历史状态，无需用户手动重启。当前 CTF系统 独立入口与 HTTP 均已加载新工具。证据为 logs/direct-deploy-20261014/legacy-reload-confirmed-20261015.json。部署详情、已验证/未验证/未完成见 协同/CTF系统直接部署-20261015.md；未推送 GitHub、未更改模型账号、未派题测评。

## 十四、CTFd 接入（2026-10-15）

本机入口 http://127.0.0.1:8800。已导入 66 道净化题面与 86 个附件，未导入参考答案或 holdout。新增 ctfd_status/list/challenge/download/submit/scoreboard 六项工具。优先 ctf_start(ctfd_challenge_id=题号) 自动取题建档；旧客户端也可建题后 ctf_call(ctfd_download)，附件会自动纳入完整性检查。实际 CTFd correct 回执才能更新平台验证，already_solved 不认证新候选；提交需要 confirm=true。未配置可信规则的题不能提交猜测，不能自报已判对。

使用普通选手身份解题；管理凭据仅留本机私有目录，不进入解题接口、公共 WP 或仓库。服务采用官方 CTFd 3.8.8 单实例与持久 SQLite，绑定 Ubuntu 回环，通过固定身份的 SSH 隧道映射到 Windows，已接入现有启动脚本。已验证隧道自动恢复；没有完成整机冷启动验收。维护备份或规则状态刷新使用 tools/ctf_ctfd_admin.py，不属于解题工具。详细已验证/未验证/未完成与真实证据见 协同/CTFd接入-20261015.md。

## 十五、Awesome CTF 与 Crypto-Cat 资料接入（2026-10-15）

`kb_search` / `kb_read` 现支持 source：默认 `hacktricks`；`awesome-ctf` 查工具与资料目录；`crypto-cat` 查过往题目参考，含题解和 solver，搜索和读取都必须显式布尔 `allow_reference=true`。不将 Crypto-Cat 加入独立解题、holdout 或模型测评输入。kb_read 携带搜索返回的同一 source/path/行号，引用固定提交与 SHA256；第三方内容为数据，不自动执行。查到目录条目不代表已安装该工具。

本机已拉取两个官方仓库，Crypto-Cat 的 185 个文本文件已索引；awesome-ctf 的 README 工具目录已索引。核心工具数量仍为 100。真实 CTF系统 MCP 搜索/读取和参考隔离已验，15 项检索测试通过。新增维护入口 tools/ctf_reference_sources.py --build，源码与报告保留本机。使用方式及已验证/未验证/未完成见 协同/开源资料库接入-20261015.md。

## 十六、CTFCrackTools 原生转换链（2026-10-15）

本机已安装官方 CTFCrackTools X v0.1.2 与同提交 Rust 工作流桥，源码、许可证和摘要留在 D:\Apps\CTFCrackTools-Local。`cracktools_status` 查真实算法目录，`cracktools_run` 接受 input 文本及 steps（每步 algorithm/mode），两者可走 ctf_analyze 并自动留证。部分古典密码、AES/DES/HMAC 等使用固定默认参数，须明确布尔 use_upstream_defaults=true；不支持自定义 key/IV/shift，按题目参数选择现有密码工具。转换失败即停止，结果不认证 flag。用户要画布时才 cracktools_open confirm=true，桌面也有快捷方式。

新增 3 工具，当前总数 103；GUI 启动/实际 MCP 转换与错误停止已验，8 项针对性检查通过，不等于 45 种算法全部验收或真实比赛题测评。详情和已验证/未验证/未完成见 协同/CTFCrackTools接入-20261015.md。本轮仅本机，未发布 GitHub。

## 十七、自动 WP 与实际过程留证（2026-10-15）

用户已授权部署。统一入口仍是“用 CTF系统 做这道题”，无需用户手动初始化记录。

1. `ctf_start` 建题；`ctf_call`/`ctf_analyze` 调用自动保存开始事件、真实参数/输出/失败、耗时和操作编号。关键动作带 `wp_purpose`、可选 `wp_expectation`；原工具不接收这两个说明字段。开始而未完成的操作列入缺项，禁止为补留证盲目重跑。
2. 连续 `web_browser_session` 自动收取真实 PNG 与每次动作 Playwright Trace，包括动作失败；`kali_debug_session` 保存实际 GDB MI 输入输出为 asciicast v2，明确它不是 GUI 屏幕录像。
3. 需要真实终端回放用新增 `kali_terminal_record argv=[...] confirm=true`；命令经原 Kali 桥执行，asciinema 2.4 捕获 PTY，退出码单独核对，超时/失败不能作成功。普通结构化算法保留 JSON 证据，无须伪造成终端画面。
4. Windows 调试器操作尝试采集已配置的目标程序窗口；其他具体窗口用 `wp_capture mode=windows_window process_id=...`。只收指定进程可见且未最小化窗口，无全桌面或前台窗口兜底，空白/不可用画面记错误。
5. 用实际返回的 `wp_record.step` 给 `ctf_note status=observed source_step=...` 写简明观察，假设用 hypothesis，待办用 todo。解题 Agent 负责行动目的和推理摘要，记录器不生成不存在的推理或截图。
6. `ctf_finish` 默认含图中文 WP、回放链接、脚本快照和可移交的本机私有 ZIP。manifest 保留来源、文件摘要、缺项与是否完整；真实提交回执单列。公开分享前审阅原始内容及图片；不自动上传到 GitHub。

本机当前 104 工具；自建真实验收在 `ctf-9f14d2187a3d8030`，5 张实际截图、10 份回放，未把自建样例记为比赛解题。详情、限制和证据见 `协同/WP自动留证部署-20261015.md`。系统外直接执行的命令/其他软件操作不保证收取；其他 AI 的 Skill 已同步，实际自主完成整题仍需分别验证。

## 十八、赛前环境体检 env_prep_check（2026-10-24 本机落实，纯只读）

来自 2026-10-24 羊城杯复盘（Defender 赛中查杀附件、Windows 更新抢带宽、无 VM 快照兜底、赛题二进制落在宿主机）。新增 `tools/ctf_envprep.py` + `tools/check_env.py`（落实 `环境/依赖清单.md` §四 TODO），配置在 `config/envprep.local.json`（比赛目录 / 平台 URL / 追加 VMX）。

1. **`env_prep_check`**：一次跑完 6 组只读检查——依赖自检（python/z3/dnfile/openssl/Obsidian 读写）、Defender（实时保护、比赛目录排除项、近期检出触及比赛目录）、Windows 更新（wuauserv、近 24h 下载安装事件、待重启、应用崩溃）、网络（比赛平台 DNS+HTTPS、系统代理、8787 服务在位）、VM（vmrun 在位、运行中 VM、配置 VMX 的快照数量）、宿主机卫生（盘余量、Downloads/Desktop 近 48h 新增 exe/dll/sys）。可选参数：`deep=false` 跳过依赖自检、`save_report=false` 不落盘、`platform_urls`/`vmx`/`downloads_hours` 覆盖默认。
2. **纯只读承诺**：不改防护、不停服务、不动快照；非 ok 项只给修复命令（需管理员的标注 `needs_admin`），命令由使用者自行执行。报告落 `环境/赛前体检-<ts>.md`，结论 JSON 同步返回并自动留证。
3. **使用时机**：每次比赛开赛前跑一次，按"修复命令清单"逐项处理；体检结果不代表解题能力，也不修改任何系统状态。

## 十九、天狐渗透工具箱全量接入 fox_status / fox_list / fox_open（2026-10-24 本机落实，本机专用不进分发）

工具箱完整版在 `D:\狐狸\天狐渗透工具箱-社区版V3.0`（12.9 GB，含 tools 工具库；桌面那份 697MB 拷贝缺工具库，勿用）。`tools/ctf_fox.py` 把 tools.json 的 **197 个菜单项**（131 本地 GUI + 66 网页入口）接成目录能力，编号 `fox-XXX` = tools.json 文件顺序，与 `环境/天狐工具职责清单-20261011.json` 一致；配置在 `config/fox.local.json`。

1. **`fox_status`**（只读）：根目录完整性（自带 Java 8/11、Python、tools 目录）、分类统计、路径存在性现算（基线：109 存在 / 22 缺失，与 10-11 清单一致）、缺失清单。
2. **`fox_list`**（只读）：query 模糊 / category 精确 / kind=local|web 检索，返回 id/name/exists/dangerous。
3. **`fox_open`**：按 name 或 id 拉起。网页入口直接开浏览器；本地按扩展名选启动方式（exe 直接启动、jar 用自带 Java 8（回退 11）、py 用自带 Python、bat/vbs 经 cmd start），缺失路径一律拒绝。
4. **红线**：(a) 工具箱许可禁止复制/分发/拆分——只引用原位路径，`build_team_bundle.py` 的显式白名单天然排除本模块，**永远不要把 ctf_fox.py 或工具箱文件加进分发**；(b) 敏感类别（后渗透/免杀/WebShell 管理/爆破/框架利用/漏扫利用，共 6 类）的 fox_open 必须 `confirm=true`，定位是**人工在 VM 内使用**，不编进 agent 自动化解题链路，拉起后 wp_capture 留证；(c) 工具箱捆绑软件来源复杂（其免责声明自述未逐一查验），**不要给工具箱目录加 Defender 排除项**，宿主机不执行其中不认识的二进制——这条同样进 env_prep_check 的纪律。
## 当前统一要求 两个模块 解题能力与 WP 书写（2026-10-30 用户确认）

上游：`kingcharleslzy-ai/dsh-purge` 1.6.60 @ 27919a32，融合契约见 `integrations/purge-redteam/FUSION-CONTRACT.md`。

**模块一：传统 CTF 与破甲能力完整融合，提高取得并验证 flag 的能力。模块二：解题时同步留证，完成规范、可复现的 WP。**

- 默认路线：`ctf_start → ctf_plan → ctf_analyze(tool=ctf_profile) → ctf_analyze/ctf_call → ctf_finish 出 WP`。
- 交付物是 **`ctf_finish` 导出的 WP**；不写渗透测试报告。`ctf_redteam_report` / `redteam_score_report` 只是可选附录。
- 两套能力均按题目需要充分调用，破甲可以承担主力；不设“只能辅助”“只准少量记录功能”或“仅内网题可用角色协作”的限制。
- 根据本题证据选择工具、POC、跨工具链、阶段流程及角色协作，以拿到并验证 flag 为目标。题型路线是建议，不是工具白名单；注册、依赖就绪、真实执行和答案验证分别核对。
- `redteam_*` 保留完整接口；工具/角色按实际需要选择，写入证据关联 `source_step`。具体执行继续走统一 CTF 入口，保留已有确认、范围及任务隔离要求。
- 在必要且合适的关键页面保留真实截图，例如关键线索、关键操作/调试画面、flag 结果及验证回执；不对每次状态查询或记账机械截图，不为凑图重复操作。
- 原图与来源、时间线步骤、SHA256 一起保存，正文按解题主线引用并嵌入 Word。复用已采原图，一张图确实覆盖过程与结果时可用 `stage=process_and_result` 共同引用；日志渲染与回放不冒充截图。
- WP 统一包含概述、分析、解法、验证和复现说明；截图或正文缺项明确标记草稿。截图/成稿完整与 flag 是否已验证分别记录。
- 23 篇红队 playbook 在 `skills/redteam-*/SKILL.md`；用法边界见 `skills/ctf-redteam-helper/SKILL.md`。
- `config/purge-redteam-preset.md` 保留原有流程，按题目需要选用。本节与运行时双模块规则取代旧文档中“辅助位/副武器/仅内网”的调用限制；原始上游资料保留不改写。
- 纪律不变：工具清单不等于依赖已装，记录不等于已解出，`source_step` 不能引用 `ctf_redteam_*` 自身当执行证据。
