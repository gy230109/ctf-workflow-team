> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 安装状态、端口和席位描述仅作历史记录，不是当前机器配置。

# 05 · 环境与 Kali 协同规划

## 一、当前本机环境（实测）

### 1.1 主机

| 项 | 值 |
|---|---|
| OS | Windows（用户 <本机用户>） |
| CPU | Intel i9-14900HX |
| 主 shell | Git Bash（**PATH 有问题，见 `04-踩坑` A1**） |

### 1.2 已具备的能力

| 类别 | 具体 | 备注 |
|---|---|---|
| Python | 托管 3.13.12 `<本机路径>` | **z3 5.1.0 已装在此解释器** |
| Python 缺什么 | 无 `pycryptodome`；默认 venv 里也没有 z3 | 用 `openssl` CLI 补密码学 |
| .NET | `<本机路径> Files\dotnet\` 在 PATH 中 | 但**没有** ILSpy/dnSpy，所以自写了 `dn.py`/`il.py` |
| Java | JDK 21（`/d/开发工具/jdk-21.0.4`、Eclipse Adoptium 21.0.11） | 可跑 jar 系工具 |
| 其它在 PATH 中可见 | `/d/metasploit-framework/bin`、`/d/虚拟机/bin` | 说明 D 盘已有 MSF 与虚拟机相关目录 |
| Obsidian | 库：`<本机路径> Vault`（`obsidian.json` 中 `open: true`） | 541 篇笔记，已有 `02_个人项目\强网杯备战\` |

### 1.3 缺失清单（要用时现装）

- [x] `z3`（裸环境）—— 已有，但只在一个解释器里，注意别用错
- [x] **`dnfile` + `pefile`** —— 已装进隔离 venv
      `<本机路径>`
      （**用它时必须用这个解释器**；它是第三方 CLR 解析器，用来交叉验证自研 `dn.py`，见 §3.6）
- [ ] `pycryptodome` / `gmpy2` / `sympy`（大数、数论）
- [ ] `capstone` / `lief`（ELF/PE 结构化解析；CLR 那部分已由 dnfile 覆盖）
- [ ] `pwntools`（pwn 方向）
- [ ] `angr`（符号执行，重；按需）
- [ ] `file` / `bc`（连这些都没有，说明 MSYS 基础包不全）

---

## 二、⭐ 固定规则：**每次写东西都要同步到 Obsidian**

> 由老板在 2026-10-09 明确要求，作为**常驻规则**执行，不限于本知识库。

**规则内容**：

1. 任何**新写的 / 修改的**笔记、报告、复盘、脚本说明，
   在落盘到工作目录（如 `<本机路径>`）之后，**必须同步一份到 Obsidian 库**。
2. 同步目标目录（按库的 `AGENTS.md` 约定，项目归 `02_个人项目\`）：
   ```
   <本机路径> Vault\02_个人项目\强网杯备战\强网杯大师\
   ```
3. 同步方式：**镜像 `*.md`**（纯 Markdown，Obsidian 直接可读）。
   工具：`tools\sync_to_obsidian.py`（自动从 `obsidian.json` 读库路径，不写死）。
4. 保留**双向可辨**：D 盘是"作者根"，Obsidian 是"阅读端"。
   如发生编辑冲突，以 **D 盘版本为准**（因为脚本都放那边）。
5. 同步后**回读校验**（脚本里做 `size` + 文件数比对），确认没有漏。

**为什么要写进规则**：本地模型每次产出都散落在不同工作目录里，
没有统一归档就**无法形成可检索的长期记忆**。Obsidian 就是这个"可检索层"。

---

## 三、Kali 接入规划（老板已准备）

目标：**Windows 主机（我）+ Kali（并肩作战）** 形成分工流水线。

### 3.1 分工原则

| 方向 | 主责环境 | 理由 |
|---|---|---|
| **.NET / PE / CLR 逆向** | **Windows** | 有 dotnet、自研 `dn.py`/`il.py` 已验证 |
| Windows 可执行体动态观察 | Windows（只读/沙箱） | 但按安全要求**默认不执行** |
| **ELF / pwn / 提权 / 内网** | **Kali** | pwntools、gdb+pwndbg、msf、nmap |
| **Crypto 重计算** | **Kali**（或 Windows + z3） | sage / gmpy2 / pari 在 Kali 上齐全 |
| Web | Kali | 已有既有 Web 方向备战计划（见库内 `02_个人项目\强网杯备战\`） |
| 取证 / Misc | 两边都行 | 看文件格式 |
| 归档 / 复盘 | Windows（本知识库）→ 同步 Obsidian | 统一出口 |

### 3.2 建议的 Kali 工具清单（按优先级）

**P0（必备）**
- `python3-pwntools`、`gdb` + `pwndbg`/`gef`、`binutils`（`objdump`/`readelf`/`nm`）
- `radare2` / `rizin`、`ghidra`（headless 模式可脚本化）
- `binwalk`、`foremost`、`exiftool`、`steghide`、`zsteg`
- `sagemath` 或 `python3-sympy` + `python3-gmpy2`、`z3`（`pipx install z3-solver`）
- `john` / `hashcat`、`hashid`
- `curl`/`httpie`、`jq`、`sqlmap`、`burpsuite`（Web）

**P1（加分）**
- `angr`、`triton`（符号执行）
- `frida`（动态插桩；**仅在授权的自有环境用**）
- `volatility3`（内存取证）
- `nmap` / `masscan` / `netcat`（内网；**仅授权范围**）
- `metasploit`（Kali 自带；D 盘已有 `metasploit-framework`）

**P2（按需）**
- `dnlib` 相关：`.NET` 需要 mono → `apt install mono-devel`，可跑 `monodis` 做 IL 反汇编，
  作为 `il.py` 的**交叉验证**工具（两边结果一致才敢下结论）

### 3.3 联通方式 —— ⭐ 已实测落地：**SSH 桥接**（2026-10-09 打通）

**结论：不要再自己写传输逻辑，统一用现成桥接。**

```
入口：<本机路径>
流程：同目录 CTF-WORKFLOW.md（按需读）
```

```powershell
# 必须用 PowerShell 工具跑（Bash 会被安全策略拦下）
powershell.exe -NoProfile -File "<本机路径>" status
powershell.exe -NoProfile -File "..." put    qwb2022_gamemaster <附件1> <附件2> <附件3>
powershell.exe -NoProfile -File "..." python qwb2022_gamemaster <本地脚本.py>
powershell.exe -NoProfile -File "..." fetch  qwb2022_gamemaster work/xxx.json
powershell.exe -NoProfile -File "..." run    qwb2022_gamemaster -- file ../input/x
```

**目录约定（桥接自动建）**

```
/home/<用户>/ctf-workbench/cases/<题号>/
├── input/      桥接上传并 SHA256 校验过的原始附件（只写一次，防覆盖）
├── work/       脚本工作目录，脚本用 CTF_WORK_DIR 定位
└── results/    每次执行的 .py + .json 证据（含 returncode / 耗时 / 截断标记）
```

Windows 侧同步留档：`ctf-workbench/cases/<题号>/logs/`（每条命令一份 JSON）
与 `.../downloads/<run_id>/`（fetch 回来的产物）。**两侧都留证据，才敢下结论。**

**环境变量给 Kali 脚本用**：`CTF_CASE_DIR` / `CTF_INPUT_DIR` / `CTF_WORK_DIR` / `CTF_RESULTS_DIR`。
超时上限 1–600 s（默认 60）。

| 项 | 实测值（2026-10-09） |
|---|---|
| guest IP | `<本机服务地址>`（NAT，必须在配置的 `<本机服务地址>/24` 内） |
| 主机别名 | `kali`，`StrictHostKeyChecking=yes` + **固定 known_hosts**（97 B） |
| 传输耗时 | status 0.55 s / put 0.47 s / run 0.66 s / fetch 0.48 s |
| 磁盘 | **19G 中仅剩 595 MiB（97 %）** → 不批量装 |
| 已有工具 | python3 gcc objdump readelf file strings burpsuite wireshark tshark binwalk exiftool 7z unzip，**sympy ✓** |
| 缺 | gdb / checksec / strace / ltrace / ghidra；python 模块 pwn / Crypto / z3 / dnfile |

> ⚠️ **`scp` / `sftp` 在本机是坏的**（见 `04-踩坑` **F1**），
> 桥接已改为**走 ssh 数据通道**传文件。**不要**再手写 scp 传输。

**Kali 侧脚本的写法约束**（因为上表"缺"那一行）：
只用 **Python 标准库 + openssl CLI**（+ sympy）。密码学一律 `subprocess` 调 `openssl`，
例如 `openssl enc -d -aes-128-ecb -K <hex> -nopad -in <file>`。
**不用 pycryptodome、不用 z3** —— 否则脚本到了 Kali 跑不起来。

**旧方案（保留备查，已不推荐）**：共享文件夹 `/share/ctf/` 手工交换 / `python -m http.server` /
剪贴板。当年是"任选其一"，现在已有桥接，手工方式只在桥接不通时兜底。

### 3.4 协同协议：**任务卡**（关键）

两边要能"接得上手"，就必须有统一的交接格式。约定 `handoff.md`：

```markdown
# HANDOFF
- 题目: QWB2022 GameMaster / Blackjack
- 当前状态: 已解出 / 进行中 / 卡住
- 已确证事实:
  - gamemessage = XOR 0x22 后 AES-128-ECB(key=Brainstorming!!!, Zeros)
  - 内嵌 embedded.dll, 算法在 T1Class.T1..ctor
- 已完成产物:
  - 10-work-win/gamemessage.decrypted.bin
  - 10-work-win/embedded.dll
- 下一步该谁做: Windows / Kali
- 需要对方提供: 无 / 用 sage 验算 X / 在 Kali 上跑 ELF Y
- 明确未验证的假设: a,b,c 是否等于游戏成就点数
```

**目录映射（旧规划 → 现在的桥接）**：`00-chal/` → `cases/<题号>/input/`，
`10-work-win/` → Windows 侧工作目录，`20-work-kali/` → `cases/<题号>/work/`，
`90-evidence/` → `cases/<题号>/results/` + `downloads/`。`handoff.md` 仍然有用，
但**优先把交接内容写进 kali 脚本的 docstring 和知识库战例**，任务卡只在真需要"人肉接力"时用。

**约定**：
- 交接时**只传最小必要产物**（别把整个目录塞过去）
- **结论必须带"证据文件路径"**，不能只写一句"我解出来了"
- **未验证的假设必须单列**，不许混进"已确证事实"

### 3.5 安全边界（不可协商）

- 只在**授权题目附件**与**自有虚拟机**范围内操作
- **不执行**来路不明的 exe/dll；**不反序列化**未知数据（本战例全程遵守）
- 不联网搜题解、不读其他目录的答案
- Kali 上的动态调试、内网工具**只在授权目标**上使用
- 所有"爆破/扫描"类操作**先估时、后执行**，并记录在案

---

## 四、近期落地 TODO

- [x] 建立 `<本机路径>` 知识库并写入首篇战例
- [x] 工具链搬运 + 路径解耦（13 个脚本）
- [x] 建立 Obsidian 同步规则与脚本
- [x] **⭐ Kali 桥接实测打通**：`status` / `put` / `python` / `fetch` 四动作全通（2026-10-09）
- [x] **⭐ 修掉 `scp.exe` 损坏问题**：传输改走 ssh 数据通道（`04-踩坑` F1/F2）
- [x] **⭐ Kali 侧独立复现 QWB2022 flag**：`战例库/QWB2022-GameMaster-Blackjack/kali_verify.py`
      9 步全 OK，从原始附件起算、只用 stdlib + openssl（报告存 `artifacts/kali_verify_report.json`）
- [x] **⭐ 元数据解析已交叉验证**：用第三方 `dnfile`/`pefile` 对自研 `dn.py`/`fld.py` 逐项比对，
      两张样本全绿（见下方 §3.6）。**不占 Kali 磁盘**，故 ~~装 mono-devel~~ 降级为可选项。
- [ ] （可选）在 Kali 上装 `mono-devel`（**实测落地约 219 MB**，下载约 64.5 MB），
      只为拿 `monodis` 交叉验证 `il.py` 的 **IL 反汇编**（元数据部分已由 §3.6 覆盖）。
      **前置**：先腾出空间（`/var/lib/apt/lists` 168 MB + journal 26 MB ≈ 194 MB），
      再装，装完剩约 570 MB。**优先级低** —— IL 的关键输出已被"taps 能复现 arr40"间接证明。
- [ ] 把"Kali 侧脚本模板"固化进 `模板\`：只用 stdlib + openssl + sympy，带 `$CTF_INPUT_DIR` 定位
- [ ] 把 `dn.py` + `il.py` 合成单一 CLI（`dump-info` / `dump-il` / `dump-fields`）
- [ ] 用第二道 .NET 题验证工具链的**普适性**（换一个样本，看能不能不写新代码就跑通分诊）
- [ ] 建立 `tools/brute_guard.py`：跑爆破前强制检查"分诊结论是否齐备"
- [ ] 每打完一题，把"新增的 SOP 条目"回填到 `03-逆向SOP`，形成飞轮

---

## 3.6 ⭐ 交叉验证：第三方 `dnfile` vs 自研 `dn.py`

**为什么必须做**：`dn.py` / `fld.py` 是手写的 CLR 元数据解析器。
**自己写的东西不能只自己验证** —— 表列顺序、coded index 宽度、RVA→文件偏移 的映射，
任一处错了，整套结论会一起错，而且**错得很像对的**。

**做法（零成本、零安装到 Kali）**：在 Windows 的隔离 venv 里装 PyPI 上的第三方实现
`dnfile`（底层 `pefile`），把同样的东西再解析一遍，逐项比对。

```bash
VENV=<本机路径>
"$VENV" -m pip install dnfile
"$VENV" <本机路径> <pe 文件> ...
```

**比什么**（只比可客观比较的，不比字符串格式）：

| # | 比对项 | 结果 |
|---|---|---|
| 1 | `FieldRVA` 表行数 | `embedded.dll` 2/2；`Blackjack.dll` 1/1 ✅ |
| 2 | `FieldRVA` 逐行 `(RVA, field#, 文件偏移)` | 全部一致 ✅ |
| 3 | Field 名表 | 2/2、58/58 ✅ |
| 4 | TypeDef 名表 | 5/5、17/17 ✅ |
| 5 | 同一 RVA 读出的前 64 字节 | 逐行一致 ✅ |
| 6 | **`arr19` / `arr40` 是否落在 FieldRVA 区** | **`arr19@0xfbc`、`arr40@0xfd4`** ✅ |
| 7 | `field#` 索引是否越界 | 无 ✅ |

**结论**：**FAIL 0 条**。自研解析器在"元数据表 + RVA 映射 + 常量定位"这条链路上被独立复现。
报告：`战例库\QWB2022-GameMaster-Blackjack\artifacts\crosscheck_dnfile_report.json`

**残留（未覆盖）**：`dnfile` **不做 IL 反汇编**，所以 `il.py` 的**操作码解码**没被它验证。
该风险由另一条证据兜住：从 IL 里读出的 LFSR 抽头能**精确复现 `arr40`**（Kali 上纯 Python 重算通过）——
抽头错一个 bit，`Check1` 就对不上。故此项**风险已很低**，mono 仅为"锦上添花"。
