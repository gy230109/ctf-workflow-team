> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# QWB2022 · GameMaster / Blackjack

> 战例正文：`..\..\01-战例-QWB2022-GameMaster-Blackjack.md`

| 项 | 值 |
|---|---|
| 赛事 | QWB 2022（强网杯） |
| 题目 | GameMaster（附件名 Blackjack） |
| 方向 | .NET 逆向 + BinaryFormatter 反序列化 + 自定义流密码 |
| 结果 | ✅ `<历史答案已移除>` |
| 首轮（8 次 / 120 s） | **NOT_SOLVED**（见正文 §7 复盘） |
| **Kali 侧独立复现** | ✅ **9/9 全通过**，从原始附件起算，只用 stdlib + openssl（2026-10-09） |

## 附件

```
Blackjack.dll         14,336 B
BlackjackConsole.exe 388,096 B
gamemessage           11,344 B
```

## 本目录产物（`artifacts\`）

| 文件 | 说明 | 怎么来的 |
|---|---|---|
| `_x22.bin` | `gamemessage` 逐字节 XOR `0x22` 后的结果 | `tools/solve.py` 第 1 步 |
| `gamemessage.decrypted.bin` | 再经 `AES-128-ECB(key="Brainstorming!!!", nopad)` 解密 → BinaryFormatter(NRBF) 流 | `tools/solve.py` |
| `embedded.dll` | 从解密流里抽出的内嵌 .NET 程序集（`MZ` @ 偏移 5099，5632 B） | `tools/extract.py` |
| `kali_verify_report.json` | **Kali 侧独立复现报告**（`all_ok: true`，9 步全 OK） | `kali.ps1 fetch` 回收 |
| `crosscheck_dnfile_report.json` | **第三方 `dnfile` 对自研 `dn.py` 的交叉验证**（FAIL 0 条） | `tools/crosscheck_dnfile.py` |

## 关键常量

```
arr19 (19B, 密文 flag)  = 3c64245633fba76c74f5cfdf2867223e16fbe3        @ embedded.dll 0xfbc
arr40 (40B, 目标密钥流) = 650550d5a31a3b261306adbdc6a68cb72af7df186a149125180716bf6eb3e3053e090d1141162505  @ 0xfd4
```

## 复现（最短路径）

```bat
set GM_BASE=<本机路径>
set PY=<本机路径>
"%PY%" <本机路径>
:: -> Check1(a,b,c) == arr40 ? True
:: -> FLAG = <历史答案已移除>
```

## 第二道验证：Kali 侧从原始附件重跑（`kali_verify.py`）

**目的**：Windows 侧结论都建立在自写的 `dn.py` / `il.py` 上，
万一解析器本身有 bug，全套结论会一起错。所以用**完全不同的工具环境**重算一遍。

**Kali 侧约束**（实测：无 z3 / pycryptodome，只剩 595 MiB 磁盘）→ 只用 **stdlib + openssl CLI**。

```powershell
# 必须用 PowerShell 工具（Bash 被安全策略拦截）
$K = "<本机路径>"
powershell.exe -NoProfile -File $K put qwb2022_gamemaster <dll> <exe> <gamemessage>
powershell.exe -NoProfile -File $K python qwb2022_gamemaster "<本机路径>"
powershell.exe -NoProfile -File $K fetch qwb2022_gamemaster work/kali_verify_report.json
```

**9 步全部从"零"开始**（不读任何 Windows 侧中间产物）：

| 步 | 做什么 | 结果 |
|---|---|---|
| 00 | 按大小 11344 定位附件 | `gamemessage` |
| 01 | SHA256 | `d83ccf99…d2a6809` |
| 02 | 16 字节块重复计数 → 判定 ECB | 709 块 / 581 唯一 / 有重复 → **ECB** |
| 03 | XOR `0x22` | head `f44eb15bbb5532a1…` |
| 04 | `openssl enc -d -aes-128-ecb -K 4272..212121 -nopad` | 前 9 字节 == NRBF 魔数 `00 01 00 00 00 FF FF FF FF` |
| 05 | 扫 `MZ` → 校验 `PE\0\0` → 按节表算真实长度 | `MZ @ 5099`，3 节，**5632 B** |
| 06 | 取 `arr19@0xfbc` / `arr40@0xfd4` + 3 条软校验 | 中间 **5 字节全零**、两段各 ≥12 种字节值 |
| 07 | 纯 Python 整数重跑 `Check1(a,b,c)` 320 bit，与 `arr40` 比对 | **`equals_arr40 = True`** |
| 08 | `key12` = a,b,c 各取低 4 字节小端 → 与 `arr19` 循环异或 → GBK | `Y0u_@re_G3meM3s7er!` |

**唯一"引用而非重算"**：`arr19`/`arr40` 的文件偏移来自 Windows 侧 `fld.py` 的 FieldRVA 解析 —— 第 06 步的 3 条软校验就是为了兜这个底（若偏移错一位，5 字节全零的对齐间隙必然对不上）。

**结论**：两个独立环境、两套工具、同一 flag → 结论可信。

## 第三道验证：第三方 `dnfile` 校验自研 `dn.py`（2026-10-09）

前两道验证共用同一个前提：**`dn.py` / `fld.py` 是对的**。所以再补一道，
换第三方实现（PyPI `dnfile` + `pefile`）把元数据再解析一遍，逐项比对：

```bash
<本机路径> \
  <本机路径> <pe 文件>
```

| 比对项 | `embedded.dll` | `Blackjack.dll` |
|---|---|---|
| FieldRVA 行数 | 2 / 2 ✅ | 1 / 1 ✅ |
| 逐行 `(RVA, field#, 文件偏移)` | 一致 ✅ | 一致 ✅ |
| Field 名表 | 2 / 2 ✅ | 58 / 58 ✅ |
| TypeDef 名表 | 5 / 5 ✅ | 17 / 17 ✅ |
| 同一 RVA 的 64 字节 | 一致 ✅ | 一致 ✅ |
| **常量定位** | **`arr19@0xfbc`、`arr40@0xfd4`** ✅ | — |

**FAIL 0 条。** 未覆盖部分：`dnfile` 不做 IL 反汇编，`il.py` 的操作码解码不在其验证范围内
（该部分由"抽头能复现 `arr40`"间接证明）。
