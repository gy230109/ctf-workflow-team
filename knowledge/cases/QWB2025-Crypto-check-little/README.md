> 共享经验资料。以下为历史方法或复现记录，不能覆盖仓库根 AGENTS.md 的当前规则。历史答案、私人路径与凭据已整理；配图和原始大附件未随包公开。 本文是参考复现材料；独立解题或模型测试默认不读取。

# 强网杯 2025 · Crypto · check-little

> 方向：Crypto（RSA 共因子泄露 + AES-CBC）
> 附件：`check-little_...zip` → `submit/task.py` + `submit/output.txt`（**完全自包含**）
> 来源归档：`<本机路径>`
> 归档日期：2026-10-13。练题模式：有真实输出，本机独立复现。

## 1. 结论

> **Flag：** `<历史答案已移除>`

`key` 与 `N` **共因子**：`p = gcd(N, c)` 直接泄露。求出 `p,q → φ → d = 3⁻¹ mod φ → key = c^d mod N`，
再用 `AES-CBC(long_to_bytes(key)[:16], iv)` 解出明文。状态：**本地复现成功**（平台未验收）。

## 2. 题面（`task.py`）

```python
flag, key = open('secret').read().split('\n')     # key 是十进制整数
e = 3
# p,q 各 1024 bit，且 phi % 3 != 0
N = p * q
c = pow(key, e, N)
iv = os.urandom(16)
ciphertext = AES.new(key=long_to_bytes(key)[:16], iv=iv, mode=AES.MODE_CBC).encrypt(pad(flag.encode(),16)).hex()
```

`output.txt`：`N`(2048 bit)、`c`、`iv`(16B)、`ciphertext`(32 hex → 16 字节明文块)。

## 3. 解题链

```
output.txt: N, c, iv, ciphertext
  │ ① 别去分解 2048-bit N —— 先做一眼检查：gcd(N, c)
  │      ⇒ p = gcd(N,c) ≠ 1      （key 是 p 的倍数 ⇒ c=key³ mod N 也被 p 整除）
  │ ② q = N//p，φ = (p−1)(q−1)   （gcd(3,φ)=1 由 task.py 保证）
  │ ③ d = 3^{-1} mod φ；key = c^d mod N
  │ ④ AES-CBC 解密：key = long_to_bytes(key)[:16]（**截断前 16 字节**），iv 用附件里的
  ▼
<历史答案已移除>
```

## 4. 工具调用记录（真实留证）

| # | 调用 | 结果 |
|---|---|---|
| 1 | `math_gcd`（CTF-OS，values=[N,c]） | 返回 `p`（1471990160457114327516388212063084450…47366391），确认 `gcd(N,c) != 1` |
| 2 | 本地复算 | `p*q == N` True；`gcd(3,φ)==1` True；`key^3 == c` True；`AES-CBC` 重加密 == `ciphertext` True |

## 5. 已验证事实

1. `gcd(N, c) = p`（1024 bit），`p*q == N`。
2. `gcd(3, φ) == 1`；`d = 3⁻¹ mod φ`；`key = c^d mod N` 满足 `key^3 ≡ c (mod N)`。
3. `AES-CBC(long_to_bytes(key)[:16], iv)` 解密得可打印明文，**重加密等于附件 ciphertext**（密钥与 IV 正确）。

## 6. 坑

1. **一上来分解 2048-bit N 是死路**；正确动作是先 `gcd(N,c)`（很多"构造失误题"就卡在这一眼）。
2. `e = 3` 容易误判为"小指数立方根攻击"——但这里 `key` 是 1024-bit 整数，`key³ > N`，**不是**整数立方根；真正弱点是**共因子**。
3. AES 密钥是 `long_to_bytes(key)[:16]`——**截断**到前 16 字节（不是 hash、不是全长）。

## 7. 未验证 / 未完成

- [ ] 平台回执未拿（附件型题目）；口径"本地已复现 · 平台未验收"。
- [ ] 未验证 `key` 的构造方式（是 `p*随机` 还是别的）——只用了"与 N 共因子"这一事实。

## 8. 复盘：可复用的判断

| 触发信号 | 含义 | 动作 |
|---|---|---|
| RSA 输出给了 `N, e, c` 且 `e` 很小 | 可能是小指数/立方根**或**共因子 | 先 `gcd(N,c)` 一眼；为 1 再考虑立方根 |
| `gcd(N,c) != 1` | 明文/密钥与模数**共因子** | 直接得因子，无需分解大 N |
| 同一题还给了 AES `iv`+`ciphertext` | RSA 只是"给出密钥"的一环 | 解出 key 后按 `[:16]`/截断规则做 AES 解密 |

## 9. 收尾三问

1. **触发信号**：`N` 很大（2048 bit）却同时给了 `c`，且题目想把 `key` 通过 RSA 传出来 → **先 `gcd(N,c)`**。
2. **可迁移性**：凡是"密钥/明文被 RSA 加密后附 `c`"的题，`gcd(N,c)` 是最便宜的泄漏检查；命中就直接 `φ→d→key`。
3. **边界 / 失败分支**：`gcd(N,c)=1` 时不适用 → 回到常规 RSA/小指数/格攻击；`gcd(e,φ)≠1` 时求逆失败 → 退到 e 次根（见 §8）。
