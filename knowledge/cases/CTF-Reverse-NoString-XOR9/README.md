> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# CTF · Reverse · NoString.exe（字符串 XOR 0x09 隐藏 + 已知明文反推）

> 方向：Reverse（Windows 32 位 **原生 C++ 控制台**程序 · 字符串加密 · 已知明文反推 KPA）
> 附件：`NoString.zip` → `NoString.exe`（91,648 B，PE32 i386，MSVC，控制台子系统，无壳）
> sha256：`c817c0641ecd196c880eb143b394e5337f796a8b0e11dcb772da422748dfae58`（时间戳 2021-04-07 16:06:12）
> 答题日期：2026-10-14。状态：**静态反推 + 完整反汇编 + 真机输入三重验证一致**
> 🔎 执行纪律「先盲解、后对照」：**全程未检索任何资料**（本轮无检索动作）。

## 1. 结论

> **Flag：** `flage:{4564aOIJJNY}`（**19 字符**，注意 `flage` 是作者的拼写错误，`:` 后面还跟着 `{`）

程序是个「输入 flag → 判 right / error」的校验器。**它所有字符串都用 `XOR 0x09` 加密存在 `.data` 里**，
所以 `strings` 一条业务串都扫不到 —— 这就是题名 **NoString** 的含义。

**破法（本轮最核心的一招）**：程序会把提示打印到屏幕上，于是我们**已知明文**
（`please input u flage:`）—— 拿它当 crib，在全文件每个偏移上反推变换参数，
**一次定位到加密块并求出密钥 `0x09`**，然后把整块解出来（flag 就在里面）。

## 2. 题面与判型

| 项 | 值 |
|---|---|
| 容器 | `NoString.zip` → `NoString.exe`（另有 `__MACOSX\._NoString.exe` 资源叉，无用） |
| 体积 | 91,648 B |
| 位宽 / 架构 | PE32 i386（`machine=0x14c`，`magic=0x10b`） |
| 子系统 | **3 = console** |
| CLR | **无**（rva=0）⇒ 非 .NET |
| 节区 | 5 节：`.text`(熵 6.63) / `.rdata`(4.54) / `.data`(3.17) / `.rsrc` / `.reloc` |
| 编译器 | MSVC（`.rdata` 有 `R60xx` CRT 错误串、`mscoree.dll`、`Microsoft Visual C++ Runtime Library`） |
| 导入 | 仅 `KERNEL32.dll`（68 个）；CRT 静态链接 |
| EP | RVA `0x1533`（VA `0x401533`，`call 0x40534f; jmp 0x4013b8` = CRT 启动） |
| 反调试 | 导入 `IsDebuggerPresent` 且**被调用 3 次**，但三处**全在 MSVC CRT 内部**（见 §5-6），**main 里没有任何反调试** |
| 资源 | 只有一个 manifest（`dpiAware`），`htt<本机路径>` 命中即来自此处，非网络行为 |

**运行时输出**（真机抓屏）：
```
please input u flage:
flage:{4564aOIJJNY} right 请按任意键继续. . .
```

## 3. 解题链（怎么想出来的）

```
NoString.zip → NoString.exe
  │ ① PE 判型：PE32 i386 / 控制台 / CLR=0 ⇒ 原生 C++；5 节，无壳
  │ ② strings 全扫（ASCII + UTF-16）⇒ **一条业务字符串都没有**，只有 CRT/KERNEL32 加载器串
  │    ⇒ 题名坐实：字符串被藏了
  │ ③ 跑起来看输出 ⇒ 屏幕打印 `please input u flage:`   ★ 这就拿到了"已知明文"
  │ ④ 先试「栈上逐字节构造」假设：扫 `mov byte [mem], imm8` 连续序列 ⇒ **0 命中**
  │    ⇒ 字符串不是拼出来的，而是**加密存储、运行时解密**
  │ ⑤ ★★ **已知明文反推（KPA）**：把 `please input u flage:` 在**每一个文件偏移**上
  │    逐种变换试解（XOR k / ±k / XOR i / ±i / 倒序 / 位反转 …），密钥由首字节推出后**全文校验**
  │    ⇒ 命中！`off=0x014ff0`，变换 = **XOR 0x09**，位于 `.data`（VA 0x4161f0）
  │ ⑥ 用密钥 0x09 解整段 .data ⇒ 全部字符串现形：
  │      0x4161e0  right
  │      0x4161e8  error
  │      0x4161f0  please input u flage:
  │      0x416208  %19s
  │      0x416210  flage:{4564aOIJJNY}      ← ★ 比对目标（19 字节）
  │ ⑦ 反汇编引用点（VA 0x4010xx~0x4011xx，**整个 main 都在这**）——机制全部揭晓：
  │      · 逐字节 XOR 9 解密 prompt → 打印
  │      · 逐字节 XOR 9 解密 "%19s" → scanf 读入（最多 19 字符）到 [ebp-0x18]
  │      · ★ **把用户输入也逐字节 XOR 9**（循环 0x13 = 19 次）
  │      · ★ **strcmp(输入^9, 0x416210)** —— 注意比较目标**从未被解密**，始终是密文！
  │        两边都在"密文空间"比较 ⇒ 明文自然相等
  │      · 不等 → 解密 "error" 打印；相等 → 解密 "right" 打印
  │      · 收尾 `printf("\r\n")` + `system("pause")`
  │ ⑧ 真机验证：输入 `flage:{4564aOIJJNY}` → **right**；
  │    输入 `flag:{4564aOIJJNY}`（把作者的拼写错误改"对"）→ **error**
  │    ⇒ 证明 `flage` 的拼写错误是**故意且在比较串里**，必须照抄
  ▼
flage:{4564aOIJJNY}
```

**main 关键反汇编**（VA 0x401000 起，`--adjust-vma` 必须是 `0x400c00`）：
```
401010  mov  ecx, 0x4161f0            ; "please input u flage:"（密文）
401018  ...                            ; (内联 strlen)
401030  xor  BYTE PTR [eax+0x4161f0], 0x9        ; ★ 逐字节解密
401038  cmp  eax, ecx ; jl 0x401030
40103c  push 0x4161f0
401041  call 0x401174                  ; printf
401046  mov  ecx, 0x416208             ; "%19s"
401072  xor  BYTE PTR [eax+0x416208], 0x9        ; ★ 解密格式串
401082  push 0x416208 ; push [ebp-0x18]
401087  call 0x401223                  ; scanf
401091  xor  BYTE PTR [ebp+eax-0x18], 0x9        ; ★★ 把用户输入也 XOR 9（19 次）
40109a  cmp  eax, 0x13 ; jl 0x401091
40109c  mov  ecx, 0x416210             ; "flage:{4564aOIJJNY}"（密文，不解密！）
4010a4  (内联 strcmp，逐字节)
4010cb  je   0x4010f7                  ; 相等 → right
4010cd  mov  ecx, 0x4161e8             ; "error"
4010e4  xor  BYTE PTR [eax+0x4161e8], 0x9        ; 解密后打印
4010f7  mov  ecx, 0x4161e0             ; "right"
401110  xor  BYTE PTR [eax+0x4161e0], 0x9        ; 解密后打印
401129  push 0x413e3c                  ; "\r\n"
401133  push 0x413e40                  ; "pause"
401138  call 0x4012c3                  ; system("pause")
```

**设计上的小聪明**：比较目标字面量**从不被解密**，而用户输入**被就地加密** ——
两边都在密文域里比较。这样即使有人在内存里 dump 字符串，目标也还是密文
（除非他知道脚本会解密 prompt 而顺手把整块解了）。

## 4. 工具调用记录（真实留证）

| # | 调用 | 结果 |
|---|---|---|
| 1 | 本地 python：解包 + PE 判型 + 各节熵 | PE32 i386 / console / CLR=0 / 5 节无壳 / `.text` 熵 6.63 |
| 2 | 本地 python：ASCII+UTF-16 全段字符串扫描 | **无任何业务字符串** ⇒ NoString 含义确认 |
| 3 | `win_console_probe.py --list-only` 真机抓屏 | 拿到 `please input u flage:` ⇒ **获得已知明文** |
| 4 | 本地 python：扫 `mov byte [mem], imm8` 连续序列 | ❌ 0 命中 ⇒ 排除"栈上拼字符串" |
| 5 | ★ 本地 python：**已知明文反推**（全偏移 × 多变换） | ✅ `off=0x014ff0` **XOR 0x09** 命中 |
| 6 | 本地 python：用 0x09 解整段 `.data` | ✅ 5 条字符串全部现形（含 flag 与 `right`/`error`） |
| 7 | 本地 python：以正确 VA 找引用点 | 全部落在 VA 0x401000~0x401120 ⇒ main 定位 |
| 8 | mingw `objdump --adjust-vma=0x400c00` | ✅ 完整读出 main（解密/输入加密/strcmp/打印分支） |
| 9 | 本地 python：核对 `0x413e3c`/`0x413e40` | `"\r\n"` / `"pause"` ⇒ 解释"请按任意键继续" |
| 10 | 真机：输入 `flage:{4564aOIJJNY}` | ✅ **right** |
| 11 | 真机：输入 `flag:{4564aOIJJNY}` | **error** ⇒ 证明拼写错误必须照抄 |
| 12 | 固化工具 + 回归测试 | `tools/find_str_cipher.py`，三条明文全部命中并**直接反推出 flag** |

## 5. 已验证事实

1. **字符串全在 `.data`，用 `XOR 0x09` 加密**；共 5 条：
   `right` / `error` / `please input u flage:` / `%19s` / `flage:{4564aOIJJNY}`。
2. **flag 是 19 字节**：`flage:{4564aOIJJNY}`，与 `%19s` 的 19 和 XOR 循环的 `0x13=19` **三处互相印证**。
3. **比较在密文域**：程序把用户输入 XOR 9 后，与**保持密文**的目标串 strcmp。
   因为同一密钥，等价于明文直比 ⇒ 输入必须是 `flage:{4564aOIJJNY}`。
4. **真机双向验证**：正确串 → `right`；把 `flage` 改成 `flag` → `error`。
5. **程序流程**：打印 prompt → `scanf("%19s")` → 加密输入 → strcmp → 打印 right/error → `printf("\r\n")` → `system("pause")`。
6. **`IsDebuggerPresent` 只是 CRT 在用，不是本题的反调试**（**这条我一开始写错了，已核实纠正**）：
   导入表里有 `IsDebuggerPresent`，但全文件搜其 IAT 槽（VA `0x410004`）的引用，**只有 3 处 `call`**，
   且**全部位于 MSVC CRT 内部**：

   | 调用点 VA | 所属 | 做什么 |
   |---|---|---|
   | `0x401540` | `__report_gsfailure`（栈 cookie 校验失败处理器，由 `0x40166c` 调用） | `IsDebuggerPresent()` → 存全局 `0x41656c` → 调 debug hook → 若**无**调试器再调一次 → `__fastfail(0xC0000409)` |
   | `0x40175f` | CRT 启动路径（函数 `0x40157a` 内） | 结果存 `edi`，配合 `GetModuleFileName` 判环境 |
   | `0x408bab` | CRT 报告/中止路径 | `test eax,eax; je ...` 按是否被调试走不同分支 |

   并且存 `IsDebuggerPresent` 结果的全局 `0x41656c` **只在写它的同一个函数（`0x401549` 写、`0x40155c` 读）里被读**，
   main 完全不碰它。⇒ **main（`0x401000`~`0x40114f`）里没有任何反调试检查**。
   实测：本工具用 `ReadProcessMemory` / `AttachConsole` 抓屏观察时，程序行为无任何差异，正常输出并以 `system("pause")` 收尾。
   > 教训：**"导入了某个 API" ≠ "程序用了它"**。判断"有没有反调试"必须**去数 IAT 槽的引用点**，不能只看导入表。
7. **安全体检**：无网络 API（无 WS2_32/WININET/InternetOpen）；`htt<本机路径>` 仅出现在 manifest 里。
   `CreateProcessA` 由 CRT 的 `system("pause")` 使用。无持久化、无文件破坏。

## 6. 这道题的坑

1. 🔴🔴 **"没有字符串"不等于"程序里没信息"** —— 恰恰相反，这本身就是最强的提示：
   字符串一定被**加密/变换后存储**了。不要卡在 `strings` 上，直接换思路。
2. 🔴🔴 **最省力的破法是"已知明文反推"（KPA），而不是硬逆**：
   只要程序把任何一条串**打印到屏幕上**，你就有了 crib。
   拿明文在**全文件每个偏移**上、对**多种变换**逐一求参并全文校验，
   复杂度 O(文件大小 × 变换种类 × 明文长度)，本题不到一秒就命中，**直接拿密钥 + 定位 + 出 flag**。
   比逐个函数逆代码快一个数量级。
3. 🔴 **别急着试"栈上逐字节 mov 拼串"就当结论**：本题扫 `mov byte [mem], imm8` 是 0 命中，
   但那只说明"不是这种方式"，要继续换假设（加密存储 / push imm32 / 查表 / 运行时计算）。
4. 🔴 **`--adjust-vma` 又算错一次（第三次了）**：`.text` 的
   `--adjust-vma = ImageBase + SecRVA − SecRaw = 0x400000 + 0x1000 − 0x400 = **0x400c00**`，
   不是 `0x400000`。用错会让反汇编地址整体偏移，但"看起来依然像正常代码"。
   同一次里我还把 `.data` 里某串的 VA 数错（`0x14ff0` 的真 VA 是 `0x4161f0` 而非 `0x415ff0`），
   导致引用点搜索一度"无命中"。**每次算完 VA 都用 `off2va()` 反向验一遍**。
5. **注意作者的拼写错误必须照抄**：题面里 `flage`（应为 `flag`）、比较串里也是 `flage:{...}`
   （正常会写成 `<历史答案已移除>`）。**不要"好心"改成正确拼写** —— 实测改了就 error。
6. **`%19s` 的数字就是关键线索**：输入缓冲 19 字节、XOR 循环 `0x13=19`、目标串 19 字符 ——
   三处对齐，说明**目标串长度就是 19**。这类"数字互相印证"是很好的自检手段。
7. **`.rsrc` 里的 `htt<本机路径>` 是 manifest 的 `dpiAware` 命名空间**，不是网络行为 ——
   安全体检时要看**上下文**，别看到 `htt<本机路径>` 就报网络。
8. 🔴 **"导入了某个 API" ≠ "程序用了它"**：本题导入表里有 `IsDebuggerPresent`，
   很容易顺手写成"有反调试"。**正确做法是去数该 API 的 IAT 槽被 `call` 了几次、在哪**。
   本题数出来 3 次且全在 CRT 内部（`__report_gsfailure` / 启动 / 报告路径），main 一处没有。
   > 我第一版 README 就写了"反调试为虚设（未调用）"—— **事实是"被调用了，但不在 main 里"**，
   > 两者含义完全不同，已核实纠正。**这类断言必须用引用点计数来支撑，不能靠印象。**

## 7. 未验证 / 未完成

- [x] 静态反推 + 完整反汇编 + 真机输入，三重一致。
- [x] `IsDebuggerPresent` 的三处调用点已定位并确认**均在 CRT 内部**，main 无反调试。
- [ ] 未核对平台提交格式（程序输出 `right`，提交内容应为被接受的输入串 `flage:{4564aOIJJNY}`）。
- [ ] 未确认 `0x4156c9`/`0x4156e9` 那两张 26 字符字母表（`hkjmlona\`cbedgfyx{z}|~qps` 等）的用途
  —— 实测与本校验流程无关（XOR 9 解出的表，可能是某个未使用的辅助数据）。

## 8. 复现要点（方法）

**★ 核心：已知明文反推（一条命令定位 + 求密钥 + 出 flag）**
```bash
# 屏幕上看到的提示就是 crib
python tools/find_str_cipher.py "NoString.exe" "please input u flage:" "right"
# 输出：
#   === 明文 'please input u flage:' (21 字节) ===
#     off=0x014ff0  sec=.data  vs=0x004161f0  XOR k  key=0x09
#   === 明文 'right' (5 字节) ===
#     off=0x014fe0  sec=.data  vs=0x004161e0  XOR k  key=0x09
```

**拿到密钥后整段解密**
```python
d = open("NoString.exe", "rb").read()
seg = d[0x13e00:0x15200]                     # .data 节
dec = bytes(b ^ 0x09 for b in seg)
import re
for m in re.finditer(rb"[\x20-\x7e]{2,}", dec):
    print(hex(0x400000+0x15000+m.start()), m.group())   # 0x15000 = .data 的 RVA
# 0x4161e0 b'right'  0x4161e8 b'error'  0x4161f0 b'please input u flage:'
# 0x416208 b'%19s'   0x416210 b'flage:{4564aOIJJNY}'
```

**反汇编地址换算（第三次强调）**
```python
# .text: VA=0x1000, raw=0x400, ImageBase=0x400000
# --adjust-vma = 0x400000 + 0x1000 - 0x400 = 0x400c00
# objdump -D -b binary -m i386 -M intel --adjust-vma=0x400c00 ...
```

## 9. 复盘：可复用的判断

| 触发信号 | 含义 | 动作 |
|---|---|---|
| **`strings` 一条业务串都没有**（题名常带 NoString/Hidden） | 字符串**加密/变换后存储** | **不要硬逆**：先让程序跑起来拿到任意一条输出当 crib，做**已知明文反推** |
| 程序会把提示/结果打印到屏幕 | 你**免费获得明文** | 拿它做 KPA：全偏移 × 多变换 × 全文校验 ⇒ 拿到密钥 + 定位 |
| 扫 `mov byte [mem], imm8` 连续序列 0 命中 | 排除"栈上逐字节拼串" | 继续换假设：加密存储 / `push imm32` / 查表 / 运行时计算 |
| 比较目标在内存里**始终是密文**，而输入被就地加密 | **密文域比较**（同密钥等价明文比较） | 提交/输入用**明文**即可；别被"内存里是密文"迷惑 |
| 题面/串里有明显拼写错误（`flage`） | 作者手误，且**进了比较串** | **照抄**，不要"好心改对" |
| 缓冲大小 / 循环次数 / 目标串长度**三个数字一致** | 互相印证，可信度高 | 用它做长度自检 |
| 静态搜 `htt<本机路径>` 命中 | ⚠️ 需看上下文 | 若在 manifest/RCDATA 里则是配置，不是网络行为 |
| 导入表里有 `IsDebuggerPresent` 之类反调试 API | ⚠️ **导入 ≠ 调用** | **数它的 IAT 槽被 `call` 几次、落在哪**；再决定是否算反调试 |

## 10. 公开题解对照（来源标注）

- 🔎 **本轮未检索任何公开资料**（「先盲解、后对照」纪律；结论全部由本地静态反推 + 反汇编 + 真机输入得出）。
- 附件来源：用户提供的 `<本机路径>`（2026-10-14 下载）。
- 复核产物：`<本机路径>`（`triage.py` 判型+熵、`stackstr.py` 栈串检测、`kpa.py` 已知明文反推）。
- 🧰 **本轮新增可复用工具：`<本机路径>`**
  —— 「已知明文反推字符串编码」通用工具，支持 XOR/加减常数、位置相关、倒序、位反转、块级 XOR 等，
  自动报出**偏移 + 节区 + VA + 变换 + 密钥**。已用本题三条规定明文回归测试通过。

## 11. 收尾三问

1. **触发信号**：`strings` 空白 + 程序有屏幕输出 ⇒ **立刻做已知明文反推**，不要开始逆函数。
   一条命令就能同时拿到"密钥 + 加密块位置 + 明文内容"，性价比碾压手工分析。
2. **可迁移性**：
   - 🔴 **KPA 是"字符串隐藏类"题目的通杀招**：只要有一处输出是你能看见的，
     就能反推整块。**适用范围**：单字节 XOR/加减、位置相关、块级重复密钥、倒序、位变换。
   - 🔴 **"密文域比较"这个设计要认得**：输入被加密后再与密文目标比 —— 输入用明文即可，
     但如果你去 dump 目标串会看到乱码，别以为找错了。
   - 🔴 **`--adjust-vma = ImageBase + SecRVA − SecRaw`**（本轮第三次踩到同一类错误，
     已写入项目记忆，必须形成肌肉记忆；每次算完 VA 用 `off2va()` 反验）。
   - **长度互印证**：缓冲大小 / 循环次数 / 目标串长度三者一致 ⇒ 强自检。
3. **边界 / 失败分支**：
   - 若 KPA 无命中 ⇒ 明文取错了（屏幕文本可能被截断/含不可见字符），
     或变换不在支持列表里（如**多字节密钥**、**换表/Base64 变体**）⇒ 先扩大 crib（取更长的连续输出）；
   - 若密钥是**大于 1 字节**的循环密钥 ⇒ 用更长的 crib 先解出密钥周期，再复推；
   - 若是**流密码/查表替换** ⇒ 需要 dump 运行时已解密的内存（`ReadProcessMemory`）而不是离线解文件；
   - 若字符串根本**不落盘**（运行时算出来）⇒ 走栈串检测 / `push imm32` 搜索 / 动态内存 dump。
