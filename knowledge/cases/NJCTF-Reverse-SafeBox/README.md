> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# NJCTF · Reverse · SafeBox（android）

> 方向：Reverse（Android APK · 双 Activity 孪生校验）
> 附件：`file (6).zip` → `b89a8a61-c16a-445f-a59c-12b2623c889d.apk`（1.41 MB；包名 `com.geekerchina.hi`）
> 平台：bugku「逆向-10 · SafeBox(NJCTF)」，原题 NJCTF
> 答题日期：2026-10-14。状态：**本地枚举复算通过 + 公开 writeup 对照**（未上平台提交）

## 1. 结论

> **Flag：** `<历史答案已移除>`（对应输入 **i = 48539584**，走 `androidTest` 分支）

- `MainActivity`（`for j<4`，全 8 位回文）唯一解 i=48533584 → 拼出 `<历史答案已移除>` —— **这是干扰项，提交错误**。
- `androidTest`（`for j<3`，只查 3 组对称）有两个解：i=48533584 与 i=48539584；
  分别拼出 `<历史答案已移除>` 与 `<历史答案已移除>` —— **后者才是平台接受的答案**。

## 2. 题面

一个安卓 APK，界面只有一个输入框 + 按钮，要求输入一个数字：
- `MainActivity`：`8 位（10000000 < i < 99999999）` + 三条约束 → `<历史答案已移除>`
- `androidTest`（**未挂 LAUNCHER，隐藏 Activity**）：约束少一条 → `<历史答案已移除>`

```java
// 公共约束
i > 10000000 && i < 99999999
Math.abs(((i / 1000) % 100) - 36) == 3        // 第 4、5 位组成的两位数 ∈ {33, 39}
(i % 1000) % 584 == 0                         // 末三位能被 584 整除
// MainActivity: for (j = 0; j < 4; j++)  → 全回文 d1=d8 d2=d7 d3=d6 d4=d5
// androidTest : for (j = 0; j < 3; j++)  → 只查 d1=d8 d2=d7 d3=d6
// 拼装
char c1 = (char)(i / 1000000);          // 前两位组成的数当 ASCII
char c2 = (char)((i / 10000) % 100);
char c3 = (char)((i / 100) % 100);          // MainActivity
char c3 = (char)(((i / 100) % 100) + 10);   // androidTest：多 +10
```

## 3. 解题链（怎么想出来的）

```
file (6).zip → *.apk（1.41MB）
  │ ① 解包：classes.dex(2.6MB) + AndroidManifest.xml + resources.arsc + res/（无 so、无 assets）
  │ ② 从二进制 AndroidManifest 提串：package=com.geekerchina.hi
  │      LAUNCHER = MainActivity
  │      另有 com.geekerchina.hi.androidTest（action: android.intent.action.androidTest）← 可疑！
  │ ③ jadx 全量反编译（Kali）→ 目标类只有 4 个：MainActivity / androidTest / R / BuildConfig
  │ ④ 两个 Activity 代码高度相似（孪生），差异在 3 处：
  │      · 前缀："" vs "have"
  │      · 对称检查：j<4 vs j<3
  │      · c3：(i/100)%100 vs ((i/100)%100)+10
  │ ⑤ 把约束翻成 Python 枚举 10000001..99999999：
  │      末三位只能是 584（584×2=1168 超三位）→ d6d7d8 = 584
  │      回文 → d1d2d3 = 485
  │      d4d5 ∈ {33, 39}
  │      ⇒ 候选 i = 48533584 / 48539584
  │ ⑥ 拼两个 Activity 的 flag，与公开 writeup 对照 → 平台接受 <历史答案已移除>
  ▼
<历史答案已移除>
```

## 4. 工具调用记录（真实留证）

| # | 调用 | 结果 |
|---|---|---|
| 1 | 本地 python `zipfile` 解包 + 结构统计 | 432 条目；仅 1 个 classes.dex，无 native 库 |
| 2 | 本地 python 提 AndroidManifest 字符串池 | 得包名、两个 Activity、`android.intent.action.androidTest` |
| 3 | `kali_jadx`（CTF-OS） | **失败**：工具内部用了相对路径 `../input/x.apk`，jadx 工作目录不在 case/work → File not found（文件本身上传校验是过的） |
| 4 | `kali_run`（Kali <本机服务地址>）手动跑 `jadx -d /tmp/jo <绝对路径apk>` | 成功，882 个类、636 个 java 文件 |
| 5 | `kali_run`：`cat` 两个目标类源码 | 拿到完整校验逻辑（见 §2） |
| 6 | 本地 python 枚举 8 位数 + 复现拼装 | 得 2 个合法 i 与 3 个候选 flag |
| 7 | 联网检索该题 writeup | 多篇一致：`<历史答案已移除>` 正确、`<历史答案已移除>` 提交错误（**来源已标注**） |

## 5. 已验证事实

1. **约束数学上唯一**：末三位必须是 3 位数且被 584 整除 → 只有 `584`；配合回文得 `d1d2d3 = 485`；`d4d5 ∈ {33,39}`。
2. **两个候选**：i=48533584（全回文，两个 Activity 都过）与 i=48539584（只过 androidTest）。
3. **拼装结果**：
   - `MainActivity`：i=48533584 → `<历史答案已移除>`（c1='0' c2='5' c3='#'=35）
   - `androidTest`：i=48533584 → `<历史答案已移除>`（c3=45='-'）；i=48539584 → `<历史答案已移除>`（c3=105='i'）
4. 本地复算与公开 writeup 结论一致：**答案为 `<历史答案已移除>`**。

## 6. 这道题的坑

1. **真答案在"没挂 LAUNCHER 的 Activity"里**：`MainActivity` 看着是正主，但它的 flag（`<历史答案已移除>`）提交错误；必须在 `AndroidManifest` 里发现隐藏的 `androidTest`。
   —— 通用判据：**manifest 里出现的每个 Activity 都要看**，尤其带自定义 action、却不挂 LAUNCHER 的。
2. **androidTest 少查一位对称 ⇒ 解不唯一**：`j<3` 只锁前 3 组回文，第 4、5 位自由（33 或 39），所以有 2 个数学解。此时**不能只靠代码定案**，必须靠"哪个被平台接受"（外部信息）区分 —— 这一步要标来源。
3. **Java 整数除法 ≠ Python 浮点除法**：`t1 /= 10` 在 Java 是整除；照抄成 Python 浮点会让 `(i/t1)%10` 全错。求解时要显式用 `//`。
4. **`kali_jadx` 工具有个路径 bug**：它拼 `jadx -d /tmp/jadx-out ../input/x.apk`，但 jadx 启动脚本的 cwd 不在 case/work，导致 `../input` 解析到 `/usr/share/jadx/bin/../input` → File not found。**变通：用 `kali_run` + 绝对路径手动跑 jadx**（文件已由桥上传到 case/input/）。
5. `classes.dex` 2.6MB 但目标代码只有 4 个类 —— 其余全是 support/androidX 库；**别被体积吓到，先按包名过滤**。

## 7. 未验证 / 未完成

- [ ] 未在真机/模拟器安装 APK 点击验证（本机无 Android 运行时）；改用 **Python 复现两段判定+拼装逻辑**代替，并与公开 writeup 交叉验证。
- [ ] 未在 bugku 平台提交 flag（未登录），口径"本地复算通过 + writeup 对照 · 平台未验收"。
- [ ] `kali_jadx` 工具的路径 bug 未修（已在 §6 记录变通方式）。

## 8. 复现要点（方法）

```python
import math
for i in range(10000001, 100000000):
    if abs(((i // 1000) % 100) - 36) != 3:      # 注意用整除 //
        continue
    if (i % 1000) % 584 != 0:
        continue
    s = str(i)
    if not all(s[j] == s[7 - j] for j in range(3)):   # androidTest 版
        continue
    c1 = chr(i // 1000000)
    c2 = chr((i // 10000) % 100)
    c3 = chr(((i // 100) % 100) + 10)
    print(i, "<历史答案已移除>")
# → 48533584 <历史答案已移除>
# → 48539584 <历史答案已移除>   ← 正确
```

反编译命令（Kali）：
```bash
jadx -d /tmp/jo /home/<用户>/ctf-workbench/cases/<case>/input/<name>.apk
find /tmp/jo -ipath "*<包名前缀>*" -name "*.java"
```

## 9. 复盘：可复用的判断

| 触发信号 | 含义 | 动作 |
|---|---|---|
| APK 里 `MainActivity` 与某个自定义 Activity 代码**高度雷同** | 孪生校验，其中之一是"真答案"（常是隐藏的那个） | 两个都反编译，逐行 diff，看差异（前缀/循环次数/常量偏移） |
| manifest 里有 Activity **不挂 LAUNCHER** 但带自定义 action | 隐藏入口 | 必须分析，别只看启动页 |
| 校验里有 `%10` 循环比较 | 数位回文/对称检查 | 直接翻译成整数枚举，别硬推 |
| 枚举出**多个解** | 约束不充分 | 用外部信息（平台回执/writeup）定案，并标注来源 |
| 涉及 Java 的 `/`、`>>`、`char` 转换 | 语言语义差异 | Python 复现时用 `//`、显式 `&0xff`、`chr()` 对齐 |

## 10. 公开题解对照（来源标注）

- 题目：bugku「逆向-10 · SafeBox(NJCTF)」 —— htt<本机路径>
- 公开 writeup（结论一致，**仅作对照；数学候选由本地枚举独立得出**）：
  - http<本机路径>
  - http<本机路径>
  - http<本机路径> —— 该文明确记载：「i=48533584 → <历史答案已移除>；i=48539584 → <历史答案已移除>；**均提交试试发现第二组为正确**」
- 本地复算：Python 枚举 1 亿以内 + 复现两段拼装逻辑，与上述一致。

## 11. 收尾三问

1. **触发信号**：APK 里出现两个**几乎一样**的 Activity，且其中一个没挂 LAUNCHER → 立刻警惕"孪生校验 + 隐藏入口"，两个都要读。
2. **可迁移性**：安卓逆向的通用打法 = ① 二进制 manifest 提串找入口/隐藏组件 ② jadx 按**包名**过滤目标类（别被巨型 dex 劝退）③ 把判定条件翻译成整数约束做**枚举**（往往比手推快且不出错）④ 解不唯一时找外部信息定案。
3. **边界 / 失败分支**：若约束充分唯一，直接用；若多解，必须标注"平台/writeup 确认了哪一个"；若有 native 校验（本题没有 `.so`），则退到 IDA/Ghidra + Frida 动态；若 APK 加了壳/混淆，先脱壳再 jadx。
