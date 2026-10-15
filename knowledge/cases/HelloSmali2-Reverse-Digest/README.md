> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# HelloSmali2 · Reverse · Digest（smali 自定义 Base64）

> 方向：Reverse（Android smali · 改表 Base64）
> 附件：`HelloSmali2.zip` → `challenge.smali`（6266 B，单文件；类 `Lcom/example/hellosmali/hellosmali/Digest;`）
> 答题日期：2026-10-14。状态：**本机双重复算通过**
> 🔎 **执行了新纪律「先盲解、后对照」**：盲解与两轮复算全部完成后，才检索确认出处（用途：确认来源，无题解可抄）。

## 1. 结论

> **答案为：** `eM_5m4Li_i4_Ea5y`（16 字节）

`Digest.check(String)` 是一段**改了表、改了 padding 的 Base64**：输入经编码后须等于常量
`xsZDluYYreJDyrpDpucZCo!?`。逆推即得 `eM_5m4Li_i4_Ea5y`（`5m4Li` = "Smali" 的 leet 写法，主题自洽）。

## 2. 题面

只有一个 `challenge.smali`，内容是 `com.example.hellosmali.hellosmali.Digest` 类的 smali 汇编，
含静态方法 `check(Ljava/lang/String;)Z`。

## 3. 解题链（怎么想出来的）

```
challenge.smali（单文件，6266B）
  │ ① 通读 check()：先取两个常量
  │      v6 = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"   ← 64 字符表
  │      v0 = 6（每组 6 bit）、v1 = 2（parseInt 用的基数）
  │ ② 三段处理逻辑（smali 逐条对应）：
  │      段1: for 每个字符 → Integer.toBinaryString → 左侧补 '0' 到 8 位 → 累积到 StringBuilder
  │      段2: while (len % 6 != 0) 末尾补 '0'
  │      段3: 每次取前 6 位 → parseInt(bin,2) → 查 v6 表得字符；循环到取完
  │      段4: if (input.length() % 3 == 1) 追加 "!?"；== 2 追加 "!"
  │      段5: key.equals("xsZDluYYreJDyrpDpucZCo!?") ⇒ true
  │ ③ 认出这是 **Base64 变体**（标准表 `A-Za-z0-9+/`，这里换成 `+/` 打头的自定义序）
  │      padding 也从 `=`/`==` 改成 `!?`/`!` —— 末尾 "!?" ⇒ input.length() % 3 == 1 ⇒ 明文 16 字节
  │ ④ 逆推：密文去掉 "!?" → 每字符查表得值 → 6bit 拼接 → 每 8bit 还原成字节（尾部 4 位补 0 丢弃）
  │ ⑤ 复算验证 A：把 smali 算法原样用 Python 实现，对逆推结果正向编码 ⇒ 与密文逐字符相等 ✔
  │ ⑥ 复算验证 B（换表法）：密文按「自定义表→标准表」translate → 标准 base64 解码 ⇒ 同一结果 ✔
  ▼
eM_5m4Li_i4_Ea5y
```

## 4. 工具调用记录（真实留证）

| # | 调用 | 结果 |
|---|---|---|
| 1 | Read `challenge.smali` | 通读 `check()`，提取字母表常量、6bit 分组、padding 规则、目标密文 |
| 2 | 本地 python：逆推（6bit 拼接 → 字节） | `b'eM_5m4Li_i4_Ea5y'`（22 字符 × 6bit = 132 bit = 16 字节 + 4 bit 补零） |
| 3 | 本地 python：**正向复算**（重实现 smali 算法） | 输出 == `xsZDluYYreJDyrpDpucZCo!?` ✔ |
| 4 | 本地 python：**换表法交叉验证** | `translate(T→STD)` 后 `base64.b64decode` == 同一结果；正向再换回 == 密文 ✔ |
| 5 | 事后检索（已声明） | 确认出处 = GitHub `DysaniazzZ/HelloSmali` 教学项目（无题解可比对） |

## 5. 已验证事实

1. **字母表**：题中表 `+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`，长度 64 ✓（与标准表字符集合相同，仅顺序不同）。
2. **padding**：`!?`（len%3==1）/ `!`（len%3==2）；密文尾 `!?` ⇒ 明文长度为 `4k−2 = 16` 字节。
3. **位布局**：132 bit = 16×8 + 4，尾部 4 bit 为补齐用的 `0`，还原时丢弃。
4. **正向复算**：完整重实现 smali 三段逻辑后，对 `eM_5m4Li_i4_Ea5y` 编码的结果与二进制内常量**逐字符一致**。
5. **换表法等价**：`ZU1fNW00TGlfaTRfRWE1eQ==`（标准表形式）经标准 base64 解码 = `eM_5m4Li_i4_Ea5y`。

## 6. 这道题的坑

1. **它不是"标准 Base64"，三处都被动过**：
   - ① 字符表顺序：`+/` 提到最前，再小写、再大写、再数字（标准是 `A-Z` `a-z` `0-9` `+/`）；
   - ② padding 字符：`!?` / `!` 取代 `=` / `==`；
   - ③ 位补齐方向：**先左补 0 到 8 位**，再**右补 0 到 6 的倍数**。
   ⇒ 直接拿标准 base64 解会得到乱码，必须**换表**（或自己按 smali 重写）。
2. **smali 里的 `goto_*` / `:cond_*` 是控制流标签**，`if-ge`、`rem-int/lit8`、`substring`、`parseInt(bin,2)` 要逐条对上——本次能秒解，是因为
   `toBinaryString` + `补0到8位` + `每6位查表` 这组"三件套"一眼就是 Base64。
3. **末尾 padding 是长度判据**：`!?` 直接告诉逆推者明文是 16 字节（`%3==1`），不必瞎猜长度。
4. **这是教学项目不是 CTF 题**：没有"平台标准 flag"，`check()` 返回 true 的输入即为答案。

## 7. 未验证 / 未完成

- [ ] 附件只有单个 `.smali`，**没有 APK**，无法 apktool 回编 + 真机安装验证 `check()` 返回 true；改用**正向复算 + 换表法双重复算**替代（两条独立路径结果一致）。
- [ ] 未做"改 smali 绕过校验 / 重打包"（本题目标是求输入，不是 patch）。

## 8. 复现要点（方法）

```python
T   = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
cipher = "xsZDluYYreJDyrpDpucZCo"        # 去掉自定义 padding '!?'

# 路线 A：按 smali 语义逆推
bits = "".join(format(T.index(c), "06b") for c in cipher)
data = bytes(int(bits[i:i+8], 2) for i in range(0, (len(bits)//8)*8, 8))
assert data == b"eM_5m4Li_i4_Ea5y"

# 路线 B：换表 + 标准 base64
import base64
assert base64.b64decode(cipher.translate(str.maketrans(T, STD)) + "==") == data

# 正向闭环：重实现 smali 的 check 编码
def enc(inp):
    b = "".join(format(ch, "08b") for ch in inp)     # 每字节 8 位（左补 0）
    while len(b) % 6: b += "0"                       # 右补 0 到 6 的倍数
    out = "".join(T[int(b[i:i+6], 2)] for i in range(0, len(b), 6))
    return out + ("!?" if len(inp) % 3 == 1 else "!" if len(inp) % 3 == 2 else "")
assert enc(data) == "xsZDluYYreJDyrpDpucZCo!?"
```

## 9. 复盘：可复用的判断

| 触发信号 | 含义 | 动作 |
|---|---|---|
| smali 里出现 `toBinaryString` + "补 0 到 8 位" + "每 6 位一组" | **Base64 的手写实现** | 找那个 64 字符常量当表，找 padding 规则 |
| 64 字符常量顺序与标准表不同 | **换表 Base64** | `cipher.translate(自定义→标准)` 后交给标准库解 |
| padding 不是 `=` 而是其它符号 | 长度对齐规则被改 | 先由 padding 反推明文长度（`!?`→`4k−2` 字节） |
| 只有 smali 没有 APK | 无法真机验证 | 用**正向复算 + 换表法**两条独立路径互证 |

## 10. 公开题解对照（来源标注）

- 🔎 **先盲解、后对照**（新纪律首次执行）：盲解 + 两轮复算全部完成后才检索。
- 检索用途：**仅确认出处** —— `HelloSmali` 是 GitHub 上的 Android 逆向教学项目
  （http<本机路径> ，"A tutorial to show how to reverse an app"），
  属于**教程练习**而非 CTF 题，因此不存在"标准 flag"可比对；本轮**未参考任何题解内容**。
- 附件来源：用户提供的 `HelloSmali2.zip`。
- 复核产物：`<本机路径>`。

## 11. 收尾三问

1. **触发信号**：smali 里 `toBinaryString` + `%6` 分组 + 一个 64 字符常量 → **立刻按"改表 Base64"处理**，别去逐位硬推。
2. **可迁移性**：
   - 任何"改表 Base64"都能用 **`translate(自定义表→标准表)` + 标准库** 两步秒解，不必自己实现；
   - smali 阅读的通用锚点：**常量（`const-string`）先看、控制流标签（`:goto_*`/`:cond_*`）后看**，
     认算法的特征是"位运算三件套"（截位 / 移位 / 查表）；
   - 凡是求"正确输入"的题，**正向复算必须闭环**（拿解出来的明文原样编码，比拼目标常量）。
3. **边界 / 失败分支**：若表长 ≠64 或有重复字符 ⇒ 不是简单换表（可能带字符替换/位移），需逐条跟 smali；
   若 padding 规则缺失 ⇒ 靠密文长度反推；若没有 APK 只有 smali ⇒ 双路径复算代替真机验证。
