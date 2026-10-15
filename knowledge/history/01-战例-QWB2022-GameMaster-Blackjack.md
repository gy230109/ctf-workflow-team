> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 安装状态、端口和席位描述仅作历史记录，不是当前机器配置。

# 01 · 战例：QWB2022 GameMaster / Blackjack

> 类型：**.NET 逆向 + 序列化利用 + 自定义流密码**
> 结果：✅ `<历史答案已移除>`
> 口径：首轮（8 次调用 / 120 s）**未解出**；解除限额后续查解出（z3 单步 129 s）

这是本库的**基准战例**（baseline）。它几乎踩全了本地模型的典型坑，因此值得逐段拆开。

---

## 1. 题目附件

```
Blackjack.dll         14,336 B    游戏逻辑 + 第一层 AES 解密
BlackjackConsole.exe 388,096 B    控制台主程序（含真正的密钥与反序列化点）
gamemessage           11,344 B    密文载荷
```

## 2. 一句话链路

```
gamemessage
  │ ① XOR 单字节 0x22
  │ ② AES-128-ECB, Key="Brainstorming!!!", Padding=Zeros
  ▼
BinaryFormatter (NRBF) 流
  │ ③ 流内嵌完整 .NET 程序集（MZ @ 偏移 5099）→ embedded.dll (5632 B)
  ▼
T1Class.T1..ctor 里的判题算法
  │ ④ 约束：Check1(a,b,c) == arr40(40B 常量)
  │ ⑤ z3 反解出 a,b,c
  ▼
key12 = ParseKey({a,b,c}) ; flag = arr19[i] ^ key12[i%12]
  ▼
<历史答案已移除>
```

---

## 3. 分诊阶段（第 1 步就该做对的事）

### 3.1 密文形态 —— 零成本判据

```python
gm = open('gamemessage','rb').read()
from collections import Counter
blocks = [gm[i:i+16] for i in range(0, len(gm)-15, 16)]
c = Counter(blocks)
print(len(gm), len(gm) % 16)                      # 11344 0
print([(i, c[b]) for i, b in enumerate(blocks) if c[b] > 1])
# -> [(0,2), (3,4), (4,4), (5,4), (12,2), (30,2), (31,2), (73,2), (74,2), (75,2)]
```

**判据推演（必须会自己推，不能背结论）**：
- 11344 = 709 × 16 → 分组长度 16 ⇒ AES / Rijndael-128（DES 是 8）
- **重复块存在** ⇒ 是 ECB。CBC/CFB/OFB/CTR 因为有 IV / 计数器，相同明文块在相同偏移也只有同等概率巧合；
  块 3/4/5 各出现 **4 次**，这种规律性只能是 ECB。
- 块 0 == 块 12 也是同一信号的佐证。

> 📌 **SOP 条目**：`重复密文块 + 长度整除分组 = ECB`。这一步**不需要任何解密尝试**，成本 0。

### 3.2 算法栈 —— 一次把字符串全拿到

- `Blackjack.dll`：`RijndaelManaged / CreateDecryptor / ICryptoTransform / TransformFinalBlock / set_Key / set_Mode / set_Padding / InitializeArray / __StaticArrayInitTypeSize=16 / genCode`
- `BlackjackConsole.exe`：`Main / memcmp / memcmp1 / goldFunc / verifyCode / Deserialize / get_Key / set_Key / Brainstorming!!!`

### 3.3 ⚠️ 第一个大坑：把 `SHA256(常量)` 当成密钥派生

两处"诡异的长 hex 字符串"：

```
Blackjack.dll   元数据 #Strings 里的标识符名：E64C31518ED1CE49AB83B7BA8DFC265482AECF35D157F174A496CC097B75AE07
BlackjackConsole.exe 字段名：                  166CCA32A8C9F83DD2B5BD9773C70B6FA93CB346D34305979714FADFDF65DF70
```

实测：

```python
import hashlib
hashlib.sha256(b'qwb2022BlackJack').hexdigest().upper()
# 'E64C31518ED1CE49AB83B7BA8DFC265482AECF35D157F174A496CC097B75AE07'  ← 完全一致
hashlib.sha256(b'Brainstorming!!!').hexdigest().upper()
# '166CCA32A8C9F83DD2B5BD9773C70B6FA93CB346D34305979714FADFDF65DF70'  ← 完全一致
```

**当时的错误推论**："代码里算过 `SHA256(常量)`，所以密钥是 SHA256 结果。"
于是花了 56 秒、一次调用，穷举 `~200 组密钥 × 5 种模式`（AES-128/192/256-ECB、CBC(IV=0)、CBC(IV=文件头)、3DES、CFB）
⇒ 全部乱码，最高可打印率 0.42（≈随机）。

**真相**：那串 hex 只是 **`__StaticArrayInitTypeSize` 那个 `<PrivateImplementationDetails>` 里
静态数组的字段名** —— C# 编译器对静态字节数组的**混淆命名习惯**（字段名 = 内容哈希）。
它**不是**密钥派生，连"线索"都算不上，只是编译器产物。

> 📌 **SOP 条目**：元数据里出现的 32/64 位 hex 标识符名，
> **优先怀疑是编译器为静态数组生成的哈希名**，而不是"密钥派生提示"。
> 正确做法是**直接去 `.text` 找那段静态数组的原始字节**（`FieldRVA` 表 + `InitializeArray` 的 `ldtoken`）。

### 3.4 正确的密钥定位方式

`RuntimeHelpers.InitializeArray(array, fieldHandle)` 的语义：把 `FieldRVA` 指向的原始字节灌进数组。
所以路径是：

```
IL: ldtoken tok0x4000003
      → FieldDef rid=3 → 名字 + 签名
      → FieldRVA 表查 rid=3 的 RVA
      → RVA → 文件偏移 → 读出原始字节
```

本次实测：
- `BlackjackConsole.exe`：`tok 0x4000003` → `.text` RVA `0x599c` / 文件偏移 **15260** → `"Brainstorming!!!"`（16 B）
- `Blackjack.dll`：`tok 0x4000031` → RVA `0x4fd0` → `"qwb2022BlackJack"`（16 B）

> ⚠️ **FieldRVA 表列顺序陷阱**：schema 是 `[RVA(u4), Field(ti)]` —— **RVA 在前**。
> 写反了会拿到 `None`，然后报 `TypeError: unsupported operand type(s) for +: 'NoneType' and 'int'`。
> 见 `tools/fld.py`。

---

## 4. 算法还原阶段

### 4.1 EXE `Main` 里的解密点

```
IL_0571–0596:  for (i) buf[i] ^= 0x22;                    ← 外层 XOR
IL_0A0B–0A5F:  byte[16] key ← InitializeArray(tok 0x4000003)
               aes.Mode    = 2   (ECB)
               aes.Padding = 3   (Zeros)
               FIELD#2 = aes.CreateDecryptor().TransformFinalBlock(FIELD#1, 0, len)
```

解密验证（可原样重跑）：

```bash
K=427261696e73746f726d696e67212121     # "Brainstorming!!!" hex
python -c "d=open('gamemessage','rb').read();open('_x22.bin','wb').write(bytes(b^0x22 for b in d))"
openssl enc -d -aes-128-ecb -K $K -nopad -in _x22.bin -out gamemessage.decrypted.bin
xxd gamemessage.decrypted.bin | head
# 00000000: 0001 0000 00ff ffff ff01 0000 0000 0000  ................
#           ↑ 合法 BinaryFormatter (NRBF) 魔数
```

`NRBF` 流里 `find(b'MZ')` 命中偏移 **5099**，抽出 5632 字节即 `embedded.dll`。

> 📌 **SOP 条目**：`Padding=Zeros` 时用 openssl 必须 `-nopad`，否则报 `bad decrypt`。
> 反过来，如果 `-nopad` 解出来的明文尾部有规律补零，也要想到 Zeros 填充。

### 4.2 内嵌程序集 `embedded.dll` 的方法

| 方法 | RVA | 作用 |
|---|---|---|
| `T1Class.T1.Check1` | `0x2050` | 320 bit 密钥流发生器（3 个 64 位 LFSR） |
| `T1Class.T1.ParseKey` | `0x2110` | `ulong[3]` → `byte[12]` |
| `T1Class.T1..ctor` | `0x215c` | **判题逻辑 + flag 生成** |

### 4.3 `Check1` 反汇编（关键片段，已逐字核对）

```
IL_000B: x = ((x>>29 ^ x>>28 ^ x>>25 ^ x>>23) & 1) | (x << 1)
IL_0027: y = ((y>>30 ^ y>>27) & 1) | (y << 1)
IL_0039: z = ((z>>31 ^ z>>30 ^ z>>29 ^ z>>28 ^ z>>26 ^ z>>24) & 1) | (z << 1)
IL_005F: if (i % 8 == 0) num++
IL_006F: ks[num] = (ks[num] << 1) | ((X1 & X2) ^ (~X1 & X3))
             where X1 = (z>>32)&1,  X2 = (x>>30)&1,  X3 = (y>>31)&1
IL_00A3: i++ ; if (i < 320) loop
```

**三个必须看准的细节**（任何一个看错，解出来的全是乱码）：

1. **状态更新在输出之前** —— 先 `x,y,z` 移位更新，再取 `X1/X2/X3`。
2. **输出位是三寄存器"复用选择器"**：`(X1 & X2) ^ (~X1 & X3)`，
   即 `X1` 为 1 时输出 `x` 的第 30 位，否则输出 `y` 的第 31 位 —— **非线性**（含 `and`），
   所以不能只用线代解，需要 z3。
3. **字节累积是 MSB-first**：`ks[num] = (ks[num] << 1) | bit`，
   且 `num` 只在 `i % 8 == 0` 时自增，数组初值为 0
   ⇒ 每组 8 个 bit 里，**最早产生的 bit 落在 bit7**。

### 4.4 `ParseKey` —— 决定未知量只有 96 bit

```
IL_0011: key[i*4+j] = (byte)((keys[i] >> (j*8)) & 0xFF)
```

⇒ `key12` = 三个 `ulong` 的**低 4 字节**按小端拼起来。

> 🔑 **这是本题的"降维"关键**：`a,b,c` 各是 64 位，但 flag 只依赖它们的**低 32 位**。
> 未知量从 192 bit 直接降到 **96 bit**。
> **通用启发**：看到"宽整数 → 窄字节数组"的转换，第一件事就是确认**取的是哪几位**。

### 4.5 判题逻辑（`T1..ctor` 反编译）

```csharp
string s1 = Environment.GetEnvironmentVariable("AchivePoint1");
string s2 = Environment.GetEnvironmentVariable("AchivePoint2");
string s3 = Environment.GetEnvironmentVariable("AchivePoint3");
if (s1 == null || s2 == null || s3 == null) return;   // 没达成成就就直接退出
ulong a = UInt64.Parse(s1), b = UInt64.Parse(s2), c = UInt64.Parse(s3);
ulong[] keys = { a, b, c };

byte[] ks40  = new byte[40];  T1.Check1(a, b, c, ks40);
byte[] arr40 = <40 字节常量, tok 0x4000002>;     // 目标密钥流
byte[] arr19 = <19 字节常量, tok 0x4000001>;     // 密文 flag
byte[] key12 = new byte[12];

if (arr40.SequenceEqual(ks40)) {                  // ← 唯一的约束条件
    T1.ParseKey(keys, key12);
    for (int i = 0; i < 19; i++) arr19[i] ^= key12[i % 12];
    MessageBox.Show("<历史答案已移除>", "Congratulations!");
}
```

**常量溯源（已验证）**：`arr19`(19B) 在 `embedded.dll` 文件偏移 **`0xfbc`**，
`arr40`(40B) 在 **`0xfd4`** —— 都以原始字节形式存在，可用 `re.finditer` 反查。

```
arr19 = 3c64245633fba76c74f5cfdf2867223e16fbe3
arr40 = 650550d5a31a3b261306adbdc6a68cb72af7df186a149125180716bf6eb3e3053e090d1141162505
```

---

## 5. 求解阶段（z3）

未知 96 bit（低 32 位充分），约束 320 bit ⇒ 约束数远大于未知数，
**但目标密钥流本来就是用某组真实 `a,b,c` 生成的**，所以必然有解。

```python
from z3 import *
arr40 = bytes.fromhex("650550d5a31a3b261306adbdc6a68cb72af7df186a149125180716bf6eb3e3053e090d1141162505")

def fb(x, taps):                      # 反馈位 = 若干抽头异或
    r = LShR(x, taps[0])
    for t in taps[1:]:
        r = r ^ LShR(x, t)
    return Extract(0, 0, r)

A, B, C = BitVecs('a b c', 64)
data = [BitVecVal(0, 8) for _ in range(40)]
idx = -1
for i in range(320):
    A = Concat(Extract(62, 0, A), fb(A, [29, 28, 25, 23]))          # (A<<1)|fb
    B = Concat(Extract(62, 0, B), fb(B, [30, 27]))
    C = Concat(Extract(62, 0, C), fb(C, [31, 30, 29, 28, 26, 24]))
    if i % 8 == 0: idx += 1
    X1 = Extract(0, 0, LShR(C, 32)); X2 = Extract(0, 0, LShR(A, 30)); X3 = Extract(0, 0, LShR(B, 31))
    data[idx] = Concat(Extract(6, 0, data[idx]), (X1 & X2) ^ (~X1 & X3))   # MSB-first

s = Solver()
for j in range(40): s.add(data[j] == arr40[j])
print(s.check())                       # sat，实测 129 s
m = s.model()
print([m.eval(v).as_long() for v in (A, B, C)])
```

**结果**（`tools/solve_z3b.py` 实测输出）：

```
result: sat
a = 156324965    b = 868387187    c = 3131229747
key12 = 655451097389c23333c6a2ba
```

枚举 8 个模型（`a,b,c` 高 32 位全不相同）后，**`key12` 的低 96 位完全一致**：

```
[0] [156324965,       868387187,          3131229747]        key12=655451097389c23333c6a2ba
[1] [8796249347173,   281475845097843,    4503602758600243]  key12=655451097389c23333c6a2ba
[2] [8933688300645,   4785075472468339,   4508000805111347]  key12=655451097389c23333c6a2ba
[3] [36037730707264613, 2306124485058791795, 292738376956823091] ...
```

---

## 6. 验证阶段（三重，全部通过）

**① 独立复算**：用纯 Python 整数（不依赖 z3）重跑 `Check1`，断言输出与二进制常量逐字节相等。

```python
a, b, c = 156324965, 868387187, 3131229747
M = 0xFFFFFFFFFFFFFFFF
x, y, z = a, b, c
ks = bytearray(40); num = -1
for i in range(320):
    x = (((x >> 29) ^ (x >> 28) ^ (x >> 25) ^ (x >> 23)) & 1) | ((x << 1) & M)
    y = (((y >> 30) ^ (y >> 27)) & 1) | ((y << 1) & M)
    z = (((z >> 31) ^ (z >> 30) ^ (z >> 29) ^ (z >> 28) ^ (z >> 26) ^ (z >> 24)) & 1) | ((z << 1) & M)
    if i % 8 == 0: num += 1
    X1, X2, X3 = (z >> 32) & 1, (x >> 30) & 1, (y >> 31) & 1
    ks[num] = ((ks[num] << 1) | ((X1 & X2) ^ ((1 - X1) & X3))) & 0xFF

assert bytes(ks) == arr40                    # ✅ True
key12 = b''.join((v & 0xFFFFFFFF).to_bytes(4, 'little') for v in (a, b, c))
pt = bytes(arr19[i] ^ key12[i % 12] for i in range(19))
print(pt.decode('gbk'))
```

**② 唯一性验证**：8 个模型交叉，需要的那 96 bit 完全一致。

**③ 来源可追溯**：`re.finditer` 在 `embedded.dll` 中反查 `arr40`/`arr19` 原始字节命中。

```
arr40(40B, tok0x4000002): found at file offsets ['0xfd4']
arr19(19B, tok0x4000001): found at file offsets ['0xfbc']
Check1(a,b,c) == arr40 ? True
key12 = 655451097389c23333c6a2ba
plaintext hex = 5930755f4072655f47336d654d337337657221
plaintext     = Y0u_@re_G3meM3s7er!
```

## 🏁 最终答案

```
<历史答案已移除>
```

---

## 7. 复盘：为什么首轮（8 次 / 120 s）没解出

| 环节 | 发生了什么 | 改进项 |
|---|---|---|
| 第 4–7 次调用 | 被 `SHA256(常量)` 误导，写了"200 组密钥 × 5 模式"的爆破，**一次烧掉 56 s** | 改成先看 IL 拿 `set_Mode/set_Padding` 实参，再决定要不要爆破 |
| 定位密钥 | 只在 `.text` 里"看到"了 `qwb2022BlackJack` 字符串，**没有走 FieldRVA 拿原始数组** | 把 `FieldRVA + InitializeArray` 固化成 SOP |
| 最大缺口 | 漏了外层 **XOR 0x22** 与 **`Padding=Zeros`** —— 只按"密钥直接解密"去试，永远解不出 | 见 `03-SOP`：**遇到 AES，先扫一遍明文前后的异或/字节级变换** |
| 工具 | 一开始没有 IL 反汇编器，靠 `grep` 猜；后来才自写 `dn.py` + `il.py` | 工具要**前置**准备（已在 `tools/` 里备好） |
| 预算 | z3 一步 129 s，本身就超 120 s | 预算模式下应先用"纯 Python 小范围试算 + 线性化推高位"缩小范围 |

**一句话**：这题不是"知识点不会"，而是**分诊顺序错 + 被编译器混淆产物带偏**。

---

## 8. 可复用产出清单

| 产出 | 位置 |
|---|---|
| CLR 元数据解析器 | `tools/dn.py` |
| IL 反汇编器 | `tools/il.py` |
| FieldRVA / 静态数组提取 | `tools/fld.py` |
| 孤立方法体扫描（绕过 MethodDef） | `tools/orphan.py` |
| 内嵌 PE 抽取 | `tools/extract.py` |
| 第一层解密（XOR 0x22 + AES） | `tools/solve.py` |
| LFSR + z3 求解（含多模型枚举 + 打分） | `tools/solve_z3b.py` |
| 取证与独立复算 | `tools/final_verify.py` |
| 解密产物留档 | `战例库\QWB2022-GameMaster-Blackjack\artifacts\` |
