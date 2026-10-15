> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# CTF · Reverse · ConsoleApplication4.exe（开关灯 Lights Out 环形 + 硬编码数组解密）

> 方向：Reverse（Windows 32 位 **原生 C++ 控制台**程序 · 交互式状态机 · GF(2) 线性方程 · 异或解密）
> 附件：`console.zip` → `ConsoleApplication4.exe`（932,864 B，PE32 i386，MSVC 编译，控制台子系统，无壳）
> sha256：`cd880995684180dd5b53bd3439f919e430334f66d82fa9f2e52abad8866aa602`（时间戳 2020-12-09 14:14:05）
> 答题日期：2026-10-14。状态：**双路径独立求解 + 真机通关复核，三者逐字符一致**
> 🔎 执行纪律「先盲解、后对照」：**全程未检索任何资料**（本轮无检索动作）。

## 1. 结论

> **Flag：** `<历史答案已移除>`（**56 字符**，直接提交即可）

题目是一个「开关灯（Lights Out）」控制台小游戏：8 盏灯，按 n 会翻转相邻灯，全亮后吐 flag。
**两条完全独立的路径都通**，且结果逐字符一致：

| 路径 | 做法 | 产出 |
|---|---|---|
| **A. 通关法** | 解 GF(2) 线性方程算出按键序列 → 真机按完 → 抓屏 | 屏幕输出 = flag ✔ |
| **B. 解密法** | 反汇编 flag 生成函数，还原 `flag[i]=(A[i]^B[i])^0x13` → 静态复算 | 静态字符串 = flag ✔ |

**通关序列（唯一解）：8 盏灯各按一次 ⇒ `1 2 3 4 5 6 7 8`**

**关键机关**：翻转是**环形**的 —— 按灯 1 翻 `{8,1,2}`，按灯 8 翻 `{7,8,1}`。
题面只写「(N-1) 和 (N+1) 也会变」，没说清边界，**必须自己反推**（见 §6 坑 3）。

## 2. 题面与判型

| 项 | 值 |
|---|---|
| 容器 | `console.zip` → `ConsoleApplication4.exe` |
| 体积 | 932,864 B |
| 位宽 / 架构 | PE32 i386（`machine=0x14c`，`magic=0x10b`） |
| 子系统 | **3 = console**（控制台程序） |
| CLR | **无**（CLR 目录 rva=0）⇒ **不是 .NET** |
| 节区 | 9 节：`.textbss`(raw=0，**增量链接 `/INCREMENTAL` 的特征**) / `.text` / `.rdata` / `.data` / `.idata` / `.gfids`(CFG 函数表) / `.00cfg` / `.rsrc` / `.reloc` |
| 编译器 | **MSVC**（`.rdata` 里有 `/RTC` 运行时检查串 `Run-Time Check Failure #%d`、`<本机路径>` 的 PDB 路径） |
| 导入 | **仅 `KERNEL32.dll`（95 个函数）**；C/C++ 运行时全部静态链接 |
| EP | RVA `0x57839`（VA `0x457839`），是 `/INCREMENTAL` 的 jmp 桩 |

**程序内可见的题面文本**（VA 与文件偏移对应关系见 §6 坑 1）：

```
Play a game
The n is the serial number of the lamp,and m is the state of the lamp
If m of the Nth lamp is 1,it's on ,if not it's off
At first all the lights were closed
Now you can input n to change its state
But you should pay attention to one thing,if you change the state of the Nth lamp,
the state of (N-1)th and (N+1)th will be changed too
When all lamps are on,flag will appear
Now,input n
input n,n(1-8)
sorry,n error,try again
1.△ 2.○ 3.◇ 4.□ 5.☆ 6.▽ 7.(￣▽￣)／ 8.(;°Д°) 0.restart      ← 8 盏灯的图标
done!!! the flag is                                        ← 成功后输出
```
签名 `by 0x61`（`0x61` = `'a'`）。

**安全体检**：全文件扫 `URLDownloadToFile / WinExec / ShellExecute / WS2_32 / wininet /
InternetOpen / http(s):// / socket / VirtualAlloc / CreateRemoteThread / SetWindowsHookEx /
CurrentVersion\Run / schtasks / .vbs` ⇒ **0 命中**。
- `CreateProcessA/W` 出现在 **`.idata`**（KERNEL32 导入）—— 供 CRT 的 `system("CLS")` 清屏用；
- `.bat` / `.cmd` 出现在 **`.rdata`**（CRT 的 PATHEXT 表，同上）；
- 注册表仅 `RegOpenKeyExW / RegQueryValueExW / RegCloseKey`（**只读**，且 **未导入 ADVAPI32**，仅作字符串残留）。
⇒ 无网络、无持久化、无文件破坏行为，**可安全运行**。

## 3. 解题链（怎么想出来的）

```
console.zip → ConsoleApplication4.exe
  │ ① PE 判型：PE32 i386 / 控制台子系统 / **CLR 目录为 0 ⇒ 原生 C++**（不是 .NET）
  │    9 节，含 .textbss（增量链接）+ .gfids（CFG）⇒ 现代 MSVC 编译，无壳
  │ ② 扫字符串 ⇒ 题面全暴露：8 盏灯、按 n 翻转 n±1、全亮出 flag
  │ ③ 找字符串引用点：以「小端 imm32 = VA」全文件搜
  │    ⚠️ 第一次全搜不到 —— 因为我把**文件偏移当成了 RVA**（.rdata raw=0xb3200 但 RVA=0x10a000）
  │    修正映射后：`done!!! the flag is` 被引用于 VA 0x45e969（在函数 0x45e940 内）
  │    `input n,n(1-8)` @0x45f509 / `sorry,n error` @0x45f552 / `CLS` @0x45f5b8 ⇒ 主循环在 0x45f4xx
  │ ④ 反汇编主循环（0x45f4fb~0x45f676）——**胜负判定与数据结构一目了然**：
  │      灯态数组 = byte[0x532e28 + i], i=0..7        （全局变量）
  │      n<0 或 n>8 → 打印 "sorry,n error" → **直接跳回循环头（跳过胜负判定）**
  │      n==0        → 8 个字节全清零（重开）
  │      n!=0        → call 0x4576d6(n-1)  翻转
  │      之后: system("CLS") → 重绘 → **检查 [0x532e28+0..7] 是否全 == 1**
  │            → 全 1 则 call 0x457ab4（打印 flag）→ 回到循环头
  │ ⑤ 0x4576d6 只是个 ILT 跳转桩（`jmp 0x45e640`，增量链接的产物）→ 跟进真函数
  │    0x45e640 是**逐 case 特判**的翻转函数，把 8 个 case 全抠出来：
  │      arg=0(按灯1) → 翻 index 0,1,7      arg=1(按2) → index 0,1,2
  │      arg=2(按3)   → index 1,2,3         arg=3(按4) → index 2,3,4
  │      arg=4(按5)   → index 3,4,5         arg=5(按6) → index 4,5,6
  │      arg=6(按7)   → index 5,6,7         arg=7(按8) → index 7,6,0
  │    ⇒ **按灯 n 翻转 {n-1, n, n+1} mod 8 —— 环形！**
  │ ⑥ 解 GF(2) 线性方程：对每盏灯 j，x_{j-1}+x_j+x_{j+1} = 1（下标模 8，x∈{0,1}）
  │    8 式两两相减 ⇒ 全部 x_i 相等 ⇒ 只能全 0（不满足）或**全 1**
  │    ⇒ **唯一解：8 盏灯各按一次**
  │ ⑦ 【路径 A 真机】新控制台 + 注入按键 1..8 + 高频抢帧抓屏
  │    同时 ReadProcessMemory 读灯态数组，逐键验证环形翻转：
  │      按1 → [1,1,0,0,0,0,0,1]   按2 → [0,0,1,0,0,0,0,1]   ...
  │      按8 → [1,1,1,1,1,1,1,1]  全部点亮 ✓
  │    ⇒ 屏幕抓到 <历史答案已移除>
  │ ⑧ 【路径 B 静态】跟进 0x45e940（打印 flag 的函数）：
  │      先在栈上构造两个 56 字节数组 A@[ebp-0x44]、B@[ebp-0x88]
  │      然后循环 i=0..0x37(56-1)：
  │           B[i] = (B[i] ^ A[i]) ^ 0x13
  │      最后 cout << DONE_FMT << B
  │    ⇒ 静态复算出同一字符串，长度 56 与循环次数**完全吻合**
  ▼
<历史答案已移除>
```

**主循环关键反汇编**（VA 0x45f545 起）：
```
45f545  cmp   dword [ebp-0x8], 0        ; n < 0 ?
45f549  jl    0x45f551                  ;   → 报错
45f54b  cmp   dword [ebp-0x8], 8
45f54f  jle   0x45f560                  ; 0 <= n <= 8 合法
45f551  push  "sorry,n error,try again" ; ★ 报错路径直接 jmp 回 0x45f4fb（跳过胜负判定）
45f560  cmp   dword [ebp-0x8], 0
45f564  jne   0x45f5a8
45f566  (n==0) 循环 8 次: mov byte [ecx+0x532e28], 0     ; 灯全清零
45f5a8  (n!=0) mov eax,[ebp-0x8]; sub eax,1; push eax; call 0x4576d6   ; 翻转(n-1)
45f5b7  push "CLS"; call 0x4581b7       ; system("CLS")
45f5c4  call  0x458054                  ; 重绘
45f5c9  ...                             ; 逐个检查 8 个字节 == 1
45f66c  call  0x457ab4                  ; ★ 全亮 → 打印 flag
45f671  jmp   0x45f4fb                  ; 回到循环头
```

**flag 生成函数关键反汇编**（VA 0x45e940 起，循环体在 0x45eb55）：
```
45e968  push 0x50b0f0; call 0x45a7be    ; cout << "done!!! the flag is "
45e975  mov byte [ebp-0x44], 0x12       ; ---- 数组 A：56 字节，逐字节 mov ----
   ...  (至 45ea55: mov byte [ebp-0x0c], 0x00  ← A 的结束/终止)
45ea59  mov byte [ebp-0x88], 0x7b       ; ---- 数组 B：56 字节 ----
   ...  (至 45eb51: mov byte [ebp-0x50], 0x00  ← B 的终止 0)
45eb55  mov dword [ebp-0x94], 0         ; i = 0
45eb70  cmp dword [ebp-0x94], 0x38      ; i < 56
45eb7f  movsx ecx, byte [ebp+eax-0x44]  ;   A[i]
45eb8a  movsx eax, byte [ebp+edx-0x88]  ;   B[i]
45eb92  xor   eax, ecx                  ;   A[i]^B[i]
45eb9a  mov   byte [ebp+ecx-0x88], al   ;   B[i] = A[i]^B[i]
45ebaf  xor   ecx, 0x13                 ;   ^ 0x13
45ebb8  mov   byte [ebp+edx-0x88], cl   ;   B[i] ^= 0x13
45ebc1  lea   eax,[ebp-0x88]; push eax  ; cout << "%s" << B
45ebc8  push  0x50b10c; call 0x45a7be
```

## 4. 工具调用记录（真实留证）

| # | 调用 | 结果 |
|---|---|---|
| 1 | 本地 python：解包 + PE 判型 | PE32 i386 / console / **CLR=0 非 .NET** / 9 节含 `.textbss`+`.gfids` ⇒ 原生 MSVC C++ |
| 2 | 本地 python：全段字符串扫描 | 题面全暴露（8 盏灯、`input n,n(1-8)`、`done!!! the flag is`） |
| 3 | 本地 python：按 VA 小端 imm32 找引用点 | ❌ **全 0 命中** —— 我把文件偏移当 RVA 了（见 §6 坑 1） |
| 4 | 修正 off↔RVA 映射后重搜 | ✅ `done!!! the flag is` → VA 0x45e969；`input n,n(1-8)` → 0x45f509 ⇒ 主循环定位 |
| 5 | mingw `objdump -D -b binary -m i386` | ⚠️ 首次 `--adjust-vma=0x400000` **地址全错**；改成 `0x456c00` 才对（见 §6 坑 1） |
| 6 | 反汇编主循环 0x45f4fb~0x45f676 | 拿到灯态数组 `byte[0x532e28]`、清零分支、`call 0x4576d6(n-1)`、胜负判定、`call 0x457ab4` |
| 7 | 反汇编 0x4576d6 | 只是 ILT 桩 `jmp 0x45e640`（增量链接）→ 跟进入真函数 |
| 8 | 反汇编 0x45e640，抽 8 个 case | ✅ 得到 **环形翻转 {n-1,n,n+1} mod 8**（按灯1翻{8,1,2}，按灯8翻{7,8,1}） |
| 9 | 本地 python：解 GF(2) 方程 | 唯一解 = **8 盏灯各按一次** |
| 10 | 本地 python：管道喂 `2,5,8` 跑程序 | ❌ 超时 + 只拿到 **3 字节**（输出在管道缓冲里，kill 时丢失） |
| 11 | 本地 python：`CREATE_NEW_CONSOLE` + `AttachConsole` + 抓屏 | ✅ 拿到完整**游戏画面**（8 盏灯图标 + `n=` 提示） |
| 12 | 送键（自造 `INPUT_RECORD`，24 字节） | ❌ `WriteConsoleInputW` **返回成功但按键全部无效**（见 §6 坑 4） |
| 13 | 修正 `INPUT_RECORD` 为 **20 字节** | ✅ 按键生效 |
| 14 | 送 `2,5,8` → 抓屏看灯态 | 屏显 `1:△(灭) 2~8:亮` ⇒ 反推「按 2,5,8 结果 = {2..8}」⇒ 印证环形模型 |
| 15 | 送 `1,4,7` → 抓屏看灯态 | 屏显灯 8 仍灭 ⇒ 与环形模型预测一致（灯 8 被翻 2 次） |
| 16 | `ReadProcessMemory` 读灯态数组（逐键采样） | ✅ 逐键验证环形翻转，最终 `[1,1,1,1,1,1,1,1]` |
| 17 | **高频抢帧**（10ms 轮询 `ReadConsoleOutputCharacterW`）送 `1..8` | ✅ 抓到 **`<历史答案已移除>`** |
| 18 | 本地 python：静态复算 `flag[i]=(A[i]^B[i])^0x13` | ✅ **完全一致**（且长度 56 == 循环次数 0x38） |
| 19 | 固化工具 + 三次回归测试 | `tools/win_console_probe.py`（新控制台/注入按键/抢帧抓屏/内存监视） |

## 5. 已验证事实

1. **flag 是 56 字符**：与 `for i in 0..0x37` 的循环次数**完全吻合**（56 字节，末字节为终止 0）。
2. **两条路径结果逐字符相同**：真机屏幕输出 == 静态复算，`<历史答案已移除>` 结构良好、leetspeak 语义通顺
   （`T9is_tOpic_1s_v5ry_int7resting_b6t_others_are_n0t` = "This topic is very interesting but others are not"）。
3. **翻转是环形的**：从 0x45e640 的 8 个 case 直接读出，并由内存实测逐键印证。
4. **通关序列唯一**：GF(2) 方程 `x_{j-1}+x_j+x_{j+1}=1`（模 8）只有全 1 解。
5. **报错路径会跳过胜负判定**：`sorry,n error` 分支 `jmp 0x45f4fb`（循环头），
   ⇒ 输入 9 或负数**不会**触发检查（这条对写自动化很关键）。
6. **谜题状态在全局变量**：`byte[0x532e28 + 0..7]`（RVA `0x132e28`），可直接读写。
7. **程序不会自己退出**：赢完打印 flag 后回到 `cin >> n` 继续等输入。
8. **程序性质**：纯本地小游戏。无网络 API、无自启动、无文件破坏；`CreateProcess` 仅由 `system("CLS")` 触发。

## 6. 这道题的坑

1. 🔴🔴 **PE 段 raw ≠ RVA 时，两个地址概念必须分清**（本题连踩两次）：
   - **找引用点**时：`done!!! the flag is` 在**文件偏移** 0xb42f0，但它的 **VA 是 0x50b0f0**
     （`.rdata` raw=0xb3200 / RVA=0x10a000，差 0x7e00）。用文件偏移当 VA 去搜 → **一条都搜不到**。
     **换算公式：`VA = ImageBase + SecRVA + (off − SecRaw)`**。
   - **反汇编**时：`objdump -b binary --adjust-vma=A` 打印的地址 = `off + A`，
     而 `off = VA − ImageBase − SecRVA + SecRaw`，所以
     **`A = ImageBase + SecRVA − SecRaw`**（本题 `.text`：`0x400000+0x57000−0x400 = 0x456c00`）。
     我第一次用 `--adjust-vma=0x400000`，**所有反汇编地址都是错的**，还照样"看起来很正常"。
     > 对比：VB6 那个 case 恰好 raw==RVA，所以 `--adjust-vma=0x400000` 是对的 —— **别把偶然当规律**。
2. 🔴 **增量链接（`/INCREMENTAL`）会插 ILT 跳转桩**：`.textbss` 段（raw=0）是它的标志；
   `call 0x4576d6` 进去只是一条 `jmp 0x45e640`。**必须跟进入真函数**，否则会以为"这个函数是空的"。
3. 🔴 **别信题面的文字描述，要反推边界行为**：题面只说"(N-1) 和 (N+1) 也会变"，
   实际是**环形**（按灯 1 会翻到灯 8）。这种边界必须从代码/实测里确认。
   本题我一开始按"线性不环绕"建模，算出 `{2,5,8}` 或 `{1,4,7}`，**两组都错**。
4. 🔴 **`INPUT_RECORD` 必须是 20 字节**（`KEY_EVENT_RECORD` 16 + `EventType` 2 + 对齐 2）。
   我在结构体里多写了一个 WORD 填充字 → **`WriteConsoleInputW` 返回成功、`written` 计数也对，
   但一个键都不生效**（现象：屏幕上 `n=` 后面永远空白）。这种"成功但无效"最难查。
5. 🔴 **控制台输出别用管道接**：目标被 kill 时，C 运行时**管道缓冲里的内容会直接丢失**
   （现象：忙活半天只拿到 3 个字节）。必须给目标**真实控制台**（`CREATE_NEW_CONSOLE` + `AttachConsole`）。
6. 🔴 **`system("CLS")` 会把 flag 刷掉**：程序每轮都清屏重绘，flag 一闪而过。
   ⇒ 必须**高频抢帧**（10~20ms 轮询 `ReadConsoleOutputCharacterW`）。
   > 加分项：把回滚缓冲调到 3000 行（`SetConsoleScreenBufferSize`），避免内容滚走。
7. 🔴 **别用肉眼看 ASCII 画面判断状态**：灯是 kaomoji 图标（`△→▲`、`○→●`、`(￣▽￣)／→(°Д°)`…），
   加上抓屏文本里挤满空格，**极易看错**（我就误判过一次"灯 8 还灭"）。
   **直接 `ReadProcessMemory` 读状态数组才可靠** —— 一读就是 `[1,1,1,1,1,1,1,1]`，没有任何歧义。
8. 🔴 **64 位 Python 看 32 位进程取模块基址**：`EnumProcessModulesEx(LIST_MODULES_32BIT)`
   在本机实测会返回 **64 位模块基址**（`0x7ffab4...`，明显不合理）。
   必须**优先用普通 `EnumProcessModules`**，并用「基址 < 4GB」做合理性断言。
9. **`cin >> n` 转换失败会保持原值**：输入非数字时读入失败，循环里反复触发报错分支 ——
   这也是「管道喂数据后进程不退出」的原因之一。

## 7. 未验证 / 未完成

- [ ] 未核对平台提交格式（本题 flag 自带 `zsctf{}` 外壳，程序直接输出完整 flag，**原样提交**即可）。
- [ ] 未在境外/新版系统上验证 `.gfids`/`.00cfg`（CFG 相关节区）的行为差异。
- [ ] 未追 `0x457ab4` 内部（只知道它触发 flag 打印），也未确认 0x45e940 与它的调用关系细节。
- [x] 两条路径已交叉验证，且真机通关成功。

## 8. 复现要点（方法）

**核心工具（本轮新增）**：`<本机路径>`
```bash
# 启动控制台程序 → 注入按键 1..8 → 高频抢帧抓 flag → 顺带监视灯态数组
python tools/win_console_probe.py "ConsoleApplication4.exe" \
       --keys 12345678 --delay 0.6 --wait 3 --watch 0x132e28,8

# 输出（实测）：
#   [+] 模块基址 = 0x00370000
#   [watch] 0x004a2e28 初始 = [0, 0, 0, 0, 0, 0, 0, 0]
#      按 '1' 后 watch = [1, 1, 0, 0, 0, 0, 0, 1]     ← 环形！灯1翻到了灯8
#      ...
#      按 '8' 后 watch = [1, 1, 1, 1, 1, 1, 1, 1]
#   FLAG = <历史答案已移除>
```

**静态复算**：
```python
A = [...56 字节...]      # 来自 VA 0x45e975~0x45ea55 的 mov byte [ebp-0x44+k], imm8
B = [...56 字节...]      # 来自 VA 0x45ea59~0x45eb51 的 mov byte [ebp-0x88+k], imm8
flag = bytes(((B[i] ^ A[i]) ^ 0x13) & 0xff for i in range(56)).decode()
assert flag == "<历史答案已移除>"
```

**GF(2) 求解（环形）**：
```python
# 按灯 n 翻转 {n-1, n, n+1} mod 8
import itertools
N = 8
def toggle(n):                      # n: 1..8
    return {((n-1-1) % N)+1, n, (n % N)+1}
sols = []
for x in itertools.product([0,1], repeat=N):
    cnt = [0]*N
    for n in range(1, N+1):
        if x[n-1]:
            for j in toggle(n): cnt[j-1] ^= 1
    if all(cnt): sols.append(x)
# => 唯一解 (1,1,1,1,1,1,1,1)  即 8 盏灯各按一次
```

**反汇编地址换算（重要）**：
```python
# VA = ImageBase + SecRVA + (file_off - SecRaw)
# objdump -b binary 的 --adjust-vma = ImageBase + SecRVA - SecRaw
# 本题 .text: 0x400000 + 0x57000 - 0x400 = 0x456c00
```

## 9. 复盘：可复用的判断

| 触发信号 | 含义 | 动作 |
|---|---|---|
| **CLR 目录 rva == 0** | **不是 .NET**，别去找反编译器 | 按原生 C/C++ 走；看 `.rdata` 里有没有 `/RTC`、PDB 路径来判编译器 |
| 有 `.textbss` 段（raw=0） | **`/INCREMENTAL` 增量链接** | `call` 目标可能是 ILT 桩（一条 `jmp`）⇒ **必须跟进入真函数** |
| 字符串引用点**一条都搜不到** | 🔴 很可能**把文件偏移当 RVA 了** | 先算 `VA = ImageBase + SecRVA + (off−SecRaw)` 再搜 |
| `objdump -b binary` 反汇编结果"看着正常但逻辑不通" | 🔴 `--adjust-vma` 算错了 | 用 `ImageBase + SecRVA − SecRaw`，不要想当然用 `ImageBase` |
| **管道**跑交互式程序只拿到几个字节 / 进程不退出 | 输出被 **C 运行时管道缓冲**吞了；`cin` 失败后死循环 | 改用 **`CREATE_NEW_CONSOLE` + `AttachConsole`** 抓屏 |
| 抓屏时内容总是空的 | 程序每轮 `system("CLS")` 清屏 | **高频抢帧**（10~20ms）+ 把回滚缓冲调大 |
| `WriteConsoleInput` 返回成功但按键无效 | 🔴 `INPUT_RECORD` **字节数写错了**（必须 20） | 打印 `ctypes.sizeof(INPUT_RECORD)` 断言 |
| 程序状态能用 ASCII 画面看出来 | ⚠️ 但极易看错（图标/空格干扰） | **优先 `ReadProcessMemory` 读状态变量**，画面只作辅助 |
| 64 位宿主取 32 位进程模块基址得到 `0x7ffa...` | `EnumProcessModulesEx` 返回了 64 位模块 | 改用普通 `EnumProcessModules` + 「基址 < 4GB」断言 |
| 题目要"按某盏灯会连带影响相邻灯" | 经典 **Lights Out / GF(2) 线性方程** | 先写出翻转集合矩阵，解方程；**特别注意边界是否环形** |
| 胜利条件写在某函数里，直接 `call` 打印函数 | 可以直接**改内存伪造胜利状态**绕过玩法 | 但更快的是先算好序列正常通关 |

## 10. 公开题解对照（来源标注）

- 🔎 **本轮未检索任何公开资料**（「先盲解、后对照」纪律；结论全部由本地静态分析 + 真机通关 + 静态复算得出）。
- 附件来源：用户提供的 `<本机路径>`（2026-10-14 21:37 下载）。
- 复核产物：`<本机路径>`（`triage.py` 判型+字符串、`toggle.asm` 翻转函数反汇编、
  `solve.py` 静态复算、`grab.py` 高频抢帧、`final.py` 终局验证）。
- 🧰 **本轮新增可复用工具：`<本机路径>`**
  —— Windows **控制台程序**交互探针（新控制台 + 注入按键 + 抢帧抓屏 + 内存监视）。
  已在本机上做三次回归测试，均稳定拿到本节 flag。

## 11. 收尾三问

1. **触发信号**：控制台交互程序（`subsystem=3`）+ 题面要求输入一串按键 + 输出一闪而过
   ⇒ **直接上 `win_console_probe.py`**（真控制台 + 注入按键 + 抢帧），别在管道上浪费时间。
   同时**找状态变量直接读内存**，比看 ASCII 画面可靠得多。
2. **可迁移性**：
   - 🔴 **「文件偏移 ≠ RVA」是 PE 逆向的第一号低级错误**，本次连踩两遍（搜引用点 + 反汇编）。
     记住两条公式：`VA = IB + SecRVA + (off − SecRaw)`、`--adjust-vma = IB + SecRVA − SecRaw`。
   - 🔴 **增量链接的 ILT 桩**：`.textbss` 段一出现，`call` 目标就要多跟一层。
   - 🔴 **`INPUT_RECORD` = 20 字节 / `KEY_EVENT_RECORD` = 16 字节**：写错会"静默无效"。
   - 🔴 **交互式控制台程序不要用管道抓输出**：缓冲丢失 + `CLS` 刷屏，两重坑叠加。
   - **GF(2) 线性方程是"开关灯 / 翻转类"谜题的通解**：先写翻转集合，再解方程；
     **边界（是否环形）必须从代码或实测确认**，不能照题面字面理解。
   - **通用套路**：找到打印 flag 的那个函数并静态还原它，往往能**绕过整个玩法**（双路径互证）。
3. **边界 / 失败分支**：
   - 若按键注入仍无效 ⇒ 换真实鼠标/键盘输入（`SendInput`）或 `SetForegroundWindow` 后 `keybd_event`；
   - 若状态数组在堆上而非全局 ⇒ 用「已知初值 + 变化/未变化」两轮扫描定位（见 `win_mem_probe.py`）；
   - 若胜负判定被反调试/校验和保护 ⇒ 改内存会被发现，需下断点改寄存器的改法；
   - 若抓屏仍抓不到（渲染过快）⇒ 直接把目标的 stdout 重定向到**由自己持有的控制台**，
     或用 `SetConsoleMode` 关掉快速编辑模式后再抢帧。
