> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# CTF · Reverse · 工程4.exe（VB6 计数器 + Base58）

> 方向：Reverse（Windows 32 位 VB6 程序 · GUI · Cheat Engine 找内存计数 · Base58）
> 附件：`ce.rar`（RAR5）→ `工程4.exe`（20,480 B，PE32 i386，VB6 编译，无壳）
> sha256：`8f4b36b49ac24ac79bf721b88d599c4f1e9c056308b66de170360fd21e04015c`（原文件名 `工程4.exe`，时间戳 2019-04-03）
> 答题日期：2026-10-14。状态：**已提交通过（<历史答案已移除>）**
> 🔎 执行纪律「先盲解、后对照」：
> - **盲解阶段（未检索）**：VB6 判型 → 字符串表 → 反汇编 → 真机内存改写，全部本地独立走通，
>   拿到程序弹窗输出的 `DeZmqMUhRcP8NgJgzLPdXa`；
> - ⚠️ **平台把裸串判为「Flag不正确」**，且本地 base62/64/32/XOR/凯撒/键盘移位/逆序全部无解；
> - **对照阶段（声明后检索）**：按纪律第 3 条「确认平台格式 / 多解消歧」检索，
>   确认该串是 **Base58**，解码得 `<历史答案已移除>`（已本地双向复算验证）。
> - ❗ 所以：逆向链条是盲解的，**最后一步 Base58 的识别来自公开题解对照** —— 如实标注。

## 1. 结论

> **Flag：** `<历史答案已移除>`

链条两段：

1. **程序侧（盲解得到）**：程序启动弹 **“点击一万次有flag”**。真点一万次会弹出 **`DeZmqMUhRcP8NgJgzLPdXa`**，
   但代码里有两个门道：
   - 每次点击 **+200**（不是 +1），计数器要累到 **2,000,000**；
   - 判定条件是 **`计数器 / 200 == 10000`**（不是直接比 10000）。
   所以把计数器改成 **1,999,800** 再点最后一次即可（本机真机复现，弹窗确认）。

2. **编码侧（对照确认）**：弹窗那串是 **Base58**，解码得 **`<历史答案已移除>`**。
   ```python
   A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'   # Base58 (Bitcoin)
   # 解码 DeZmqMUhRcP8NgJgzLPdXa  ->  b'<历史答案已移除>'
   # 反向复算 encode('<历史答案已移除>') == 'DeZmqMUhRcP8NgJgzLPdXa'   ✔
   ```

**为什么一眼该认出 Base58**：该串里**没有 `0` `O` `I` `l` `+` `/`** —— 这正是 Base58 的招牌特征
（为规避形近字符而刻意剔除）；且长度 **22 字符 ↔ 16 字节**，与 `<历史答案已移除>` 恰好吻合。
而 Base64 要求长度是 4 的倍数（`22 % 4 = 2` 本就不整齐），Base64 解码结果也非可打印。

## 2. 题面与判型

**平台页面信息（2026-10-14 截图核对）**

| 项 | 值 |
|---|---|
| 题目名 | **不好用的 ce** |
| 分类 / 分值 | Reverse / **30 分** |
| 题目作者 | harry |
| 一血 / 一血奖励 | suha / 2 金币 |
| 已解决 | 1289 |
| 提示 | （空） |
| 描述 | **需要点击一万下？**（← 问号就是提示：不是真要点一万下） |
| 提交形式 | **纯文本输入框；必须是解码后的 `<历史答案已移除>`，直接提交裸串会被判「Flag不正确」** |

> 题目名「**不好用的 ce**」正好点题：按常规思路用 CE / `BM_CLICK` 去打，确实"不好用"
> （VB6 自绘按钮不认消息点击，见 §6 坑 1）。

| 项 | 值 |
|---|---|
| 容器 | `ce.rar`（RAR5）→ `工程4.exe` |
| 体积 | 20,480 B |
| 位宽 / 架构 | PE32 i386（machine `0x14c`，optional magic `0x10b`） |
| 节区 | `.text`(RVA 0x1000) / `.data`(0x3000) / `.rsrc`(0x4000)，**3 节，无壳** |
| CLR | 无（非 .NET） |
| 导入 | **仅 `MSVBVM60.DLL`**（39 个函数）；VB 运行时另经 `VBA6.DLL` 动态取 |
| 判型 | `VB5!` 签名 + `MSVBVM60.DLL` + `Form1`/`Command1`/`Label1` + `#vb6chs.dll` ⇒ **VB6** |
| 资源 | `VS_VERSION_INFO`，`ProductName=工程1`，`OriginalFilename=4.exe`，`CompanyName=aaaa` |
| EP | `0x11d8` |

**提交形式判定（先说结论，教训见 §6 坑 1）**：
程序弹窗给出的是 **Base58 密文**，不是最终 flag。
一度误判为"裸串直接提交"（理由：二进制里**一个 `{` 都没有**、程序把字面量原样交给 `rtcMsgBox`
无任何变换），结果平台判 **「Flag不正确」**。
⇒ **必须先把该串做 Base58 解码，提交 `<历史答案已移除>`。**
> 教训：**"程序原样输出"不等于"输出就是 flag"** —— 输出本身可能还是一层编码。
> 判据不是"程序有没有变换"，而是"**这段文本的字符集像哪种编码**"。

**安全体检（先做，再运行）**：全文件扫描 ASCII + UTF-16LE 的
`URLDownloadToFile / WinExec / CreateProcess / ShellExecute / WScript / cmd.exe / powershell /
RegSetValue / RegCreateKey / Winsock / socket / InternetOpen / http(s):// / CurrentVersion\Run /
Task Scheduler / VirtualAlloc / WriteProcessMemory / CreateRemoteThread / SetWindowsHookEx /
.vbs/.bat/.cmd / DeleteFile / CopyFile / MoveFile`
⇒ **0 命中**；导入表只有 VB 运行时。
⇒ 结论：纯 GUI 训练程序，可安全受控运行。

关于 `ce.rar` 这个包名 + “工程1/工程4” + “点击一万次” ⇒ 典型 **Cheat Engine 训练题系列**（工程N）。

## 3. 解题链（怎么想出来的）

```
ce.rar → 工程4.exe
  │ ① PE 判型：PE32 i386 / 3 节 / 无壳 / 仅导入 MSVBVM60.DLL
  │    + 签名 "VB5!" + Form1/Command1/Label1 ⇒ **VB6 原生代码**
  │ ② 双编码字符串扫描（ASCII + UTF-16LE）。VB6 字符串是
  │    `DWORD(字节长度) + UTF-16LE + 00 00`，**长度是字节数不是字符数** ⇒ 捞出 5 条字面量
  │      0x401a20  ghjljzlkaslkkndnl            (17)
  │      0x401a48  slknlkmsnlmdklnmflk          (19)
  │      0x401a74  weknflknwlkenwqklenklfn      (23)
  │      0x401ab8  DeZmqMUhRcP8NgJgzLPdXa       (22)  ← 弹窗输出（Base58 密文）
  │      0x401aec  点击一万次有flag             (10)  ← 提示语
  │ ③ 引用点定位：把每条字面量的 VA 以小端 imm32 全文件搜 ⇒ **每条恰好被引用 1 次**，
  │    全部落在 raw 0x1cc6~0x1f88（VA 0x401cc6~0x401f88）⇒ 就是 Command1_Click / Form_Load
  │ ④ 反汇编（raw==RVA，VA=0x400000+raw，objdump -b binary 直读）
  │ ⑤ 解析 IAT 名称表：0x401024 = `MSVBVM60!ord#595` = **rtcMsgBox**（VB6 的 MsgBox 按序号导出）
  │ ⑥ 读常量：0x4010a8 = 10000.0（比较目标）；0x4010b0 = 200.0（点击步长）
  │ ⑦ Command1_Click 全貌：
  │      counter = counter + 200          ; [esi+0x34] 是 Form 上的 double 计数器
  │      <某个控件>.Caption = CStr(counter / 200)   ; 显示的是“第几次点击”
  │      If counter / 200 = 10000 Then rtcMsgBox "DeZmqMUhRcP8NgJgzLPdXa"
  │      🔴 关键：fld 与 fcomp 之间还有一句 `fdiv [0x4010b0]`（除 200）——
  │         不是 counter==10000，而是 counter/200==10000 ⇒ 目标是 **2,000,000**
  │ ⑧ 真机：启动 → 关掉启动提示框 → 真鼠标点 1 次，全内存找 `double==200.0`（唯一命中）
  │    → 再点 1 次，确认它变成 400.0 ⇒ 计数器地址锁定
  │ ⑨ 写 1,999,800.0 → 点最后一次 → 计数器 = 2,000,000 → /200 = 10000 → 弹窗
  │    ⇒ 拿到 DeZmqMUhRcP8NgJgzLPdXa
  │ ⑩ ❌ 直接把裸串提交 → 平台判「Flag不正确」
  │ ⑪ 本地穷举：base62(所有字母表排列)/base64(含64种表旋转)/base32/XOR/
  │    凯撒/键盘左右移位/逆序/隔位抽取 —— **全部无解**（🔴 唯独跳过了 base58）
  │ ⑫ 观察字符集：**没有 0 O I l + /** ⇒ 这是 **Base58** 的招牌特征！
  │    长度 22 字符 ↔ 16 字节，正好装下 <历史答案已移除>
  │ ⑬ 双向复算：decode(DeZmqMUhRcP8NgJgzLPdXa)=<历史答案已移除>；
  │    encode(<历史答案已移除>)=DeZmqMUhRcP8NgJgzLPdXa ✔
  ▼
<历史答案已移除>
```

**Command1_Click 关键反汇编**（VA 0x401c80 起）：
```
401d38  fld   qword [esi+0x34]        ; 计数器（Form 对象 +0x34）
401d3b  fadd  qword [0x4010b0]        ; + 200.0
401d44  fstp  qword [esi+0x34]        ; 写回
   ...
401d62  fld   qword [esi+0x34]
401d65  cmp   dword [0x403000], 0     ; VB 浮点精度开关（初值 0）
401d6c  jne   0x401d76
401d6e  fdiv  qword [0x4010b0]        ; ÷200 → 用于 Label 显示
401d74  jmp   0x401d87
401d76  push  [0x4010b4]              ; 高 dword of 200.0
401d7c  push  [0x4010b0]              ; 低 dword of 200.0
401d82  call  0x401104                ; = jmp [0x401010] = MSVBVM60!_adj_fdiv_m64
   ...
401de4  fld   qword [esi+0x34]        ; 同样一套：计数器 ÷ 200
401df0  fdiv  qword [0x4010b0]
401e13  call  __vbaFpR8               ; 舍入到 double 精度
401e19  fcomp qword [0x4010a8]        ; 与 10000.0 比较
401e21  test  ah, 0x40                ; C3（相等）标志
401e24  je    0x401e97                ; 不等 → 跳过
401e4b  mov   [ebp-0x88], 0x401ab8    ; "DeZmqMUhRcP8NgJgzLPdXa"
401e5f  call  __vbaVarDup
401e76  call  MSVBVM60!ord#595        ; rtcMsgBox（提示内容 = 该字符串）
```

## 4. 工具调用记录（真实留证）

| # | 调用 | 结果 |
|---|---|---|
| 1 | 本地 python：RAR5 解包 + PE 判型（节区/CLR/导入表） | PE32 i386、无壳、**仅导入 MSVBVM60.DLL** ⇒ VB6 |
| 2 | 本地 python：双编码字符串扫描（ASCII + UTF-16LE + CJK） | 捞到 5 条字面量（含 `点击一万次有flag`、`DeZmqMUhRcP8NgJgzLPdXa`） |
| 3 | 本地 python：按 VA 小端 imm32 全文件找引用点 | 每条字面量**恰好 1 处引用**，集中在 0x401cc6~0x401f88 |
| 4 | 本地 python：解析 IAT 名称表（39 项） | `0x401024 = ord#595 = rtcMsgBox`；`0x401010 = _adj_fdiv_m64` |
| 5 | mingw `objdump -D -b binary -m i386 -M intel --adjust-vma=0x400000` | 完整读出 Command1_Click / Form_Load |
| 6 | 本地 python：读 `.data` 常量 | `0x4010a8 = 10000.0`、`0x4010b0 = 200.0`、`[0x403000] = 0` |
| 7 | 本地 python：`CreateProcess` + `EnumWindows/EnumChildWindows` | 抓到启动提示框 **“点击一万次有flag”**；按钮 `ThunderRT6CommandButton` |
| 8 | 本地 python：`BM_CLICK` ×50 | ❌ 计数器**完全没动** ⇒ VB6 按钮不认 BM_CLICK |
| 9 | 本地 python：全量内存 diff（含 MEM_IMAGE） | ❌ 被线程栈噪声淹没（上千段） |
| 10 | 本地 python：**真鼠标**（SetCursorPos + mouse_event）+ 定向值扫描 | ✅ 点 1 次唯一命中 `double==200.0`；点 2 次变 `400.0` ⇒ **计数器 = 0x72355c** |
| 11 | 本地 python：`WriteProcessMemory` 写 1,999,800.0 + 真鼠标点 1 次 | ✅ 弹窗 **`DeZmqMUhRcP8NgJgzLPdXa`**，与静态字面量一致 |
| 12 | 平台提交裸串 | ❌ **「Flag不正确」** ⇒ 输出还需再解一层 |
| 13 | 本地 python：穷举解码（base62 全字母表排列 / base64 含 64 种表旋转 / base32 / base64 当大整数 / XOR / 凯撒 / QWERTY 左右移位 / 逆序 / 隔位） | ❌ **全部无解**（🔴 唯独没试 base58） |
| 14 | 本地 python：全文件扫 `rtcMsgBox` 调用点 + `.data` 段字符串 + 7-Zip 查 RAR 注释 | 只有 2 处 MsgBox、`.data` 无串、RAR 无注释 ⇒ **程序侧确实已读干净** |
| 15 | 🔎 **检索**（已声明；属于纪律第 3 条「确认平台格式」） | 确认该串为 **Base58**，flag = `<历史答案已移除>` |
| 16 | 本地 python：**Base58 双向复算** | ✅ `decode("DeZmqMUhRcP8NgJgzLPdXa") == b"<历史答案已移除>"`；`encode("<历史答案已移除>") == "DeZmqMUhRcP8NgJgzLPdXa"` |

## 5. 已验证事实

1. **弹窗内容是 Base58 密文**：`DeZmqMUhRcP8NgJgzLPdXa` 是 `.text` 里 VA `0x401ab8` 的 VB6 字符串常量
   （`DWORD 0x2c=44 字节` + UTF-16LE），作为 `rtcMsgBox` 的第一参数被推入。
   **它是 Base58，不是最终 flag** —— `decode` 得 `<历史答案已移除>`（§4 第 16 行，双向复算通过）。
2. **判定条件**：`counter / 200.0 == 10000.0`（`fld`→`fdiv`→`__vbaFpR8`→`fcomp`），
   即 `counter == 2,000,000`。步长 `200.0`，所以对应 **10000 次点击** —— 与提示语自洽。
3. **计数器位置**：运行时在堆上（Form 对象 +0x34），实测地址随进程变化（三次运行分别在
   `0x7d356c` / `0x70ae5c` / `0x72355c`），**不是固定全局变量** ⇒ 必须运行时扫描。
4. **真机复现**：写 `1,999,800.0` → 点 1 次 → 读回 `2,000,000.0` → 弹出密文对话框（`#32770`，标题 `工程1`）。
5. **程序性质**：纯 GUI 训练程序。无网络/注册表/进程创建/自启动/文件删除字符串，导入表仅 VB 运行时。
6. **提交形式 = `<历史答案已移除>`**（**不是**弹窗的裸串）：
   - ❌ 两个曾经的**错误推断**（记录以示警戒）：
     ① 「二进制里 `{` 出现 0 次 ⇒ 不存在 `flag{}` 模板 ⇒ 裸串提交」——
        错在**把"程序里没有模板"当成了"答案不需要外壳"**，而实际上外壳是**解码后才有**的；
     ② 「程序把字面量原样交给 `rtcMsgBox`、无任何变换 ⇒ 那就是 flag」——
        错在**"程序不做变换"≠"输出不是密文"**，密文可以是作者预先编码好再硬编码进程序的。
   - ✅ 正解判据是**字符集指纹**：串中**没有 `0 O I l + /`** ⇒ Base58 招牌特征；
     长度 **22 ↔ 16 字节**与 `<历史答案已移除>` 吻合；Base64 则要求长度是 4 的倍数（22 % 4 = 2，本就不整齐）。
   - ✅ 双向复算闭环：`encode(<历史答案已移除>) == DeZmqMUhRcP8NgJgzLPdXa`。

## 6. 这道题的坑

0. 🔴🔴 **最大教训：别漏 Base58！** 我为了解这串，试了 base62（全部 6 种字母表排列）、
   base64（含 64 种表旋转 + 当大整数处理）、base32、base32hex、单字节 XOR、凯撒、QWERTY 左右移位、
   逆序、奇偶隔位抽取 —— **唯独跳过了 base58**。而 base58 的判据就写在脸上：
   **字符集里没有 `0`、`O`、`I`、`l`、`+`、`/`**（为规避形近字符刻意剔除）。
   凡是"看起来像 base64 但混着大小写字母和数字、且不含 `0OIl+/`"的串，**第一优先试 base58**。
   辅助判据：base64 长度必须是 4 的倍数（本串 22 % 4 = 2）；base58 无长度约束，
   22 字符正好对应 16 字节。
1. 🔴 **`BM_CLICK` 打不动 VB6 按钮**：VB6 的 `ThunderRT6CommandButton` 在 `WM_LBUTTONUP` 时
   会用 `GetCursorPos` 判定“是否还在按钮内”，`BM_CLICK` 发来的 lParam 是 `(0,0)`、真实光标在别处
   ⇒ 被当成“拖出去取消”，**Click 事件根本不触发**（现象：内存里计数器纹丝不动，非常容易被误判成“扫描代码写错了”）。
   **解法：真鼠标输入** —— `SetCursorPos(按钮中心)` + `mouse_event(LEFTDOWN/LEFTUP)`，
   并先 `ShowWindow(SW_RESTORE)` + `SetForegroundWindow`。
2. 🔴 **VB6 字符串长度前缀是“字节数”**：`0x14 = 20` 表示 10 个 UTF-16 字符。
   按“字符数”解析会全部对不上号，看起来“没有字符串”。
3. 🔴 **不要漏掉 `fld` 与 `fcomp` 中间那条 `fdiv`**：这里 `fld` 和 `fcomp` 隔了 20 多条指令，
   中间夹着 VB 的浮点精度分支（`cmp [0x403000],0` + `jne` + `fdiv` / `call _adj_fdiv_m64`）。
   一眼扫过去很容易读成 `counter == 10000`，于是写 9800/10000 全部失败。
   **正确目标是 2,000,000。**
4. 🔴 **内存扫描要包含 `MEM_IMAGE`**：只扫 `MEM_PRIVATE` 会漏掉进程映像里可写的 `.data`。
   （本题计数器在堆上，但这条是通用坑。）
5. 🔴 **全量内存 diff 在这种题上不可用**：线程栈每次点击变上千段，噪声彻底淹没信号。
   **改用“定向值扫描”**：已知步长 200，就找 `double==200.0`（通常唯一），再点一次验 `==400.0`。
6. **`Label` 读不到文本**：VB6 的 Label 是**无窗口控件**（由 Form 自己绘制），
   `EnumChildWindows` 只能看到 `ThunderRT6CommandButton`。别在 Label 上浪费时间 ——
   要看“显示值”就直接读内存里那个 double。
7. **干扰项是死代码，不是密文**：`ghjljzlkaslkkndnl` / `slknlkmsnlmdklnmflk` / `weknflknwlkenwqklenklfn`
   三条乱码看起来很像密文，实际是 `__vbaStrCopy` / `__vbaVarCopy` 写进**局部变量**、
   函数退出时 `__vbaFreeStr` / `__vbaFreeVar` 释放掉的 **dead store**，全程无人读。
   **判据：看引用点 —— 引用它的指令后面有没有“读取/使用”该值的动作。** 别对着乱码硬解。
   （对比：真正有用的 `DeZmq...` 也是"引用 1 次"，但它是被**塞进 VARIANT 交给 rtcMsgBox**，属于真使用。）
8. **绝对路径签名**：`.text` 里还留着编译机路径 `<本机路径>`（VB6 IDE 属性）—— 辅助判型用。

## 7. 未验证 / 未完成

- [ ] 未真点满 10000 次（用一次内存改写代替；等价性已由“读回 2,000,000 + 弹窗”验证）。
- [ ] 未在 Cheat Engine GUI 里走一遍（用 Python `ReadProcessMemory/WriteProcessMemory` 等价实现）。
- [ ] 未确认这是哪一个公开训练系列的第几题（按包名 `ce`+`工程4` 推断为 CE 训练题）。
- [ ] `[0x403000]`（VB 浮点精度开关）由谁置位未追；实测初值 0，走内联 `fdiv` 分支。
- [x] ~~提交形式待确认~~ → 已确认 `<历史答案已移除>`。

## 8. 复现要点（方法）

```python
# --- 判型：VB6 ---
# 特征：导入 MSVBVM60.DLL + "VB5!" 签名 + Form1/Command1/Label1 + #vb6chs.dll

# --- VB6 字符串表：DWORD(字节长度) + UTF-16LE ---
import struct
for off in range(0x1000, 0x2000-8):
    n = struct.unpack_from("<I", d, off)[0]
    if 3 <= n <= 200:
        try: s = d[off+4:off+4+n*2].decode("utf-16le")
        except: continue
        if all(0x20 <= ord(c) <= 0x7e or 0x4e00 <= ord(c) <= 0x9fff for c in s):
            print(hex(0x400000+off), n//2, repr(s))   # n 是字节数！

# --- 反汇编（.text 的 raw == RVA，VA = 0x400000 + raw）---
# objdump -D -b binary -m i386 -M intel --adjust-vma=0x400000 p4.exe

# --- 运行时定位计数器（步长已知 = 200）---
# 真鼠标点 1 次 -> 全内存找 double==200.0（唯一） -> 再点 1 次 -> 验其变 400.0
# 写 1999800.0 -> 真鼠标点 1 次 -> 读回 2000000.0 -> 弹窗取 flag
```

真鼠标点击（**BM_CLICK 对 VB6 无效，必须用这个**）：
```python
u32.ShowWindow(main, 5)                 # SW_RESTORE
u32.SetForegroundWindow(main)
u32.SetCursorPos(cx, cy)                # 按钮客户区中心
u32.mouse_event(0x0002, 0, 0, 0, 0)     # LEFTDOWN
u32.mouse_event(0x0004, 0, 0, 0, 0)     # LEFTUP
```

**最后一步 Base58（本次卡住的地方，务必记住）**：
```python
A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'   # Base58 (Bitcoin 系)

# 判据（先做，别急着猜字母表）：
S = 'DeZmqMUhRcP8NgJgzLPdXa'
assert not (set("0OIl+/") & set(S))   # 不含 0 O I l + /  -> 指向 base58
assert len(S) % 4 != 0                # 22 % 4 == 2  -> 排除 base64

# 解码
n = 0
for c in S:
    n = n * 58 + A.index(c)
flag = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()   # '<历史答案已移除>'

# 反向复算（必须闭环）
m = int.from_bytes(flag.encode(), 'big'); out = ''
while m:
    m, r = divmod(m, 58); out = A[r] + out
assert out == S                        # ✔
```

## 9. 复盘：可复用的判断

| 触发信号 | 含义 | 动作 |
|---|---|---|
| 只导入 `MSVBVM60.DLL` + `VB5!` 签名 + `Form1/Command1/Label1` | **VB6 原生程序** | 字符串按 `DWORD(字节长)+UTF-16LE` 扫；反汇编看 `rtcMsgBox`(ord#595) |
| 包名/题名带 `ce` / “点击 N 次有 flag” | **Cheat Engine 内存题** | 别硬点：找计数器 → 改值 → 触发 |
| 提示“点 N 次”但代码里 `fadd` 的是别的数 | 步长 ≠ 1，真实目标是 `N × 步长` | 先把步长常量和比较常量都读出来 |
| `fld` 与 `fcomp` 之间夹着 `fdiv` **且**有 `cmp [全局],0 / jne` 分支 | VB6 浮点精度分支，**别忘了除法** | 判定条件要按“除完再比”读 |
| `BM_CLICK` 后目标状态/内存**毫无变化** | VB6/WPF 类自绘控件的Click不认 BM_CLICK | 立刻换 **SetCursorPos + mouse_event 真鼠标** |
| 内存里有一串长度/字符集与 flag 相近的乱码，但**无人读取** | **dead store 干扰项** | 看引用点后有无“使用”动作，别硬解 |
| 全量内存 diff 出现上千段变化 | 线程栈噪声 | 改**定向值扫描**（找已知常量/步长值） |
| 内存扫描找不到目标 | 可能漏了 `MEM_IMAGE` | 扫描范围至少覆盖 `MEM_PRIVATE + MEM_IMAGE` 的可读可写页 |
| **一串"像 base64 但长度不是 4 的倍数、且不含 `0OIl+/`"** | 🔴 **Base58** | **第一优先 base58 解码**，别去猜 base62/自定义表 |
| 程序输出的串提交后被平台判「Flag不正确」 | **输出本身还是一层编码** | 别再纠结外壳，回头按**字符集指纹**判编码类型 |
| 二进制里 `{` 出现 0 次 | ⚠️ **不代表答案没有外壳** | 外壳可能只在**解码后**才出现 —— 此判据不可靠，别用 |

## 10. 公开题解对照（来源标注）

- 🔎 **盲解阶段未检索任何资料**：VB6 判型、字符串表、引用点、反汇编、常量、
  真机内存改写 —— 全部本地独立完成，拿到弹窗输出的 `DeZmqMUhRcP8NgJgzLPdXa`。
- 🔎 **对照阶段已检索**（按纪律第 3 条「确认平台格式 / 多解消歧」，**已事先声明**）：
  - 触发点：① 平台把裸串判为「Flag不正确」；② 本地穷举 base62/base64/base32/XOR/凯撒/
    键盘移位/逆序/隔位全部无解。
  - 检索结论：该串为 **Base58**，`<历史答案已移除>`。多篇公开题解一致
    （CSDN `bugku-reverse题目-不好用的ce`、`bugku——不好用的ce详解`、FreeBuf `bugku一道逆向题目分析`）。
  - ⚠️ **如实标注**：**最后一步 Base58 的识别与解码来自公开题解对照，不是自己推出来的。**
    其余（VB6 静态链 + CE 内存链）均为盲解，且 Base58 结果已在本机**双向复算**闭环
    （`encode(<历史答案已移除>) == DeZmqMUhRcP8NgJgzLPdXa`）。
  - 📌 新增可复用判据（本地可独立使用，不依赖题解）：
    **base64 长度必须是 4 的倍数；本串 22 % 4 = 2 ⇒ 排除 base64。**
    **字符集不含 `0OIl+/` ⇒ 指向 base58。** 这两条以后可以自己走完，不必再搜。
- 附件来源：用户提供的 `<本机路径>`（2026-10-14 21:08 自 Bugku 题面下载，
  sha256 `2c70dd019c0c58831cdc6c95f138874f076cb0482958916ea9508cc6af3b914e`）。
- 复核产物：`<本机路径>`（`scan_vb6.py` 双编码扫描、`vb6_lit.py` 字面量+引用点、
  `refs.py` 引用点+体检+IAT、`find_counter.py` 真鼠标+定向扫描+改写、`decode_try.py` 穷举解码、
  `p4.exe` ASCII 名副本）。
- 🧰 **本轮新增可复用工具：`<本机路径>`**
  （Windows GUI 进程「定点内存读写」探针，Cheat Engine 类题目的自动化替代）。
  一行命令即可完成「启动 → 关启动弹窗 → 定位按钮 → 真鼠标点击 → 定向值扫描定位计数器
  → 改写 → 触发 → 抓弹窗文本」：

  ```bash
  python tools/win_mem_probe.py "工程4.exe" --btn Command --probe 200,400 \
         --write 1999800 --final-clicks 1
  # => 计数器地址 = 0x0076c3c4  当前 = 400.0
  #    写入 1999800.0 -> 点击 #1 -> 计数器 = 2000000.0
  #    [对话框] 内容=['确定', 'DeZmqMUhRcP8NgJgzLPdXa']
  # 再 Base58 解码 => <历史答案已移除>
  ```

  工具里**写死了三条踩坑经验**：真鼠标不可省（BM_CLICK 对自绘控件无效）、
  用定向值扫描而非全量 diff（避线程栈噪声）、扫描范围必须含 `MEM_IMAGE`。
  `--list-only` 可只做安全的窗口/控件巡检。

## 11. 收尾三问

1. **触发信号**：VB6 + “点击 N 次有 flag” + `ce` 包名 ⇒ **按 Cheat Engine 内存题做**，
   顺序是「先读常量拿步长和阈值 → 再运行时扫计数器 → 改值 → 触发」，
   而不是去逆 GUI 逻辑。**出口那一串再按字符集指纹判编码**（本次是 base58）。
2. **可迁移性**：
   - 🔴 **Base58 判据必须进肌肉记忆**：`0OIl+/` 全不出现 + 长度非 4 的倍数 ⇒ 直接 base58。
     这是本次唯一真正卡住的地方（平台拒了裸串，我又穷举漏了 base58）。
   - **“程序原样输出”≠“输出就是答案”**：作者可以把编码结果硬编码进程序，运行时不做任何变换。
     所以**不能靠"代码里没有解码逻辑"来排除"输出是密文"**。
   - **“真鼠标输入”是 Windows GUI 自动化的必备 fallback**：`BM_CLICK` / `PostMessage(WM_LBUTTONDOWN)`
     对自绘控件（VB6/Delphi/Qt/WPF）经常静默失败，`SetCursorPos + mouse_event` 几乎总能成。
   - **“定向值扫描”比“全量 diff”强**：只要知道目标值（常量、步长、阈值），
     直接在全内存找那个 double/int 往往一步命中，完全绕开栈噪声。
   - **VB6 字符串表格式**（`DWORD 字节长 + UTF-16LE`）是 VB6 逆向的基本功；配合
     **“小端 imm32 = VA”找引用点**，可以极快地把字面量映射到具体函数。
   - **IAT 名称表顺序 == IAT 槽顺序**，据此能把 `ds:0x40xxxx` 这类间接调用全部还原成函数名
     （VB6 里 `ord#595 = rtcMsgBox`）。
3. **边界 / 失败分支**：
   - 若目标值不是“好认的数”（无固定步长）⇒ 退回 CE 的“未知初值 + 变化/未变化”两轮筛选；
   - 若程序有反调试/反内存改写（校验和、双份计数）⇒ 需要下断点而非改内存；
   - 若控件是自绘且窗口不可见/在别的桌面 ⇒ 真鼠标需要 `ShowWindow` + `SetForegroundWindow`
     甚至 `SetThreadDesktop`，否则点不到；
   - **若提交被平台拒绝** ⇒ 先别怀疑自己的程序分析，**先怀疑自己漏了某种编码**；
     用「长度约束 + 字符集指纹」两条硬判据过一遍 base64 / base58 / base62 / base32 / hex。
