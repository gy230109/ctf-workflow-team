# -*- coding: utf-8 -*-
"""EasyRsa 独立复算验收（不依赖 Muteki 的任何输出）。

这是一次「独立复算」：
    - 只用题目原始附件 input/output.txt 与 input/task.py；
    - 不复用 Muteki 的 solve.py、不复用任何中间结果；
    - 从零重跑一遍漏洞利用，再正向加密回比，最后与参考答案逐字节比对。

判据（三条全过才算 verified）：
    1. 两两 GCD 命中同一个素因子 p，且 p 能整除全部 12 个模数；
    2. 从恢复出的 m_0 正向 pow(m, 65537, n_i) 连做 12 次，结果与题目给的 c 完全一致；
    3. m_0 解出的 ASCII 与参考答案逐字节相同。

⚠️ 关于「逆推能不能朴素连除」：本脚本走的是 DFS + 可打印剪枝（先按 limit 取全部 r+t*n_i，
   再筛可打印 ASCII）。实测本题**恰好**每层 m_i < n_i（中间态 1019~1022 bit，n 恒为 1023 bit），
   所以「直接取 pow(·,d,n) 的余数」也得同一个结果；这是撞对的，不是结构性保证。
   真正的判据是判据 2（正向加密回比），不是「脚本跑通了」。

用法：
    python verify_easyrsa.py
退出码 0 = 三条全过；非 0 = 有判据不过。
"""
import re
import sys
from math import gcd
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
INPUT = ROOT / "input"
REF_FILE = HERE / "reference_flag.txt"

E = 65537


def load_moduli() -> list[int]:
    return [int(x) for x in (INPUT / "output.txt").read_text().split() if x.strip()]


def load_expected_c() -> int:
    """题目 task.py 注释里给出的最终密文 c。"""
    text = (INPUT / "task.py").read_text(encoding="utf-8", errors="replace")
    m = re.search(r"c\s*=\s*(\d{20,})", text)
    if not m:
        raise SystemExit("[FAIL] 没能从 task.py 里取到题目给的 c")
    return int(m.group(1))


def step1_common_prime(ns: list[int]):
    """判据 1：两两 GCD。"""
    p = None
    hits = 0
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            g = gcd(ns[i], ns[j])
            if g > 1:
                hits += 1
                if p is None:
                    p = g
                elif g != p:
                    print("[WARN] 命中了不止一个公因子: %d 位" % g.bit_length())
    if p is None:
        print("[FAIL] 两两 GCD 没有任何命中")
        return None, 0
    divis = sum(1 for n in ns if n % p == 0)
    print("[1] 两两 GCD: %d/%d 对命中，公因子 %d bits；整除 %d/%d 个模数"
          % (hits, len(ns) * (len(ns) - 1) // 2, p.bit_length(), divis, len(ns)))
    if divis != len(ns):
        print("[FAIL] 判据1 不过：公因子没能整除全部模数")
        return p, hits
    print("[1] 判据1 通过")
    return p, hits


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def step2_chain_recover(ns: list[int], p: int, target_c: int):
    """从最内层往外逆推。m_0 = flag，m_{i+1} = m_i^e mod n_i，给出 m_12 = c。"""
    qs = [n // p for n in ns]
    ds = [pow(E, -1, (p - 1) * (q - 1)) for q in qs]

    # 逆推：已知 m_{i+1}，求 m_i。m_i 满足
    #   m_i^e ≡ m_{i+1} (mod n_i)  → m_i ≡ m_{i+1}^d_i (mod n_i)
    #   且 m_i < n_{i-1}（i>0 时它是上一层的结果；i=0 时它是 flag，直接要求可打印 ASCII）
    cands = [target_c]
    raw_inner = 0          # 最内层「未加可打印剪枝」的候选数，用来说明剪枝的必要性
    for i in range(len(ns) - 1, -1, -1):
        nxt = []
        limit = ns[i - 1] if i > 0 else None
        for m_next in cands:
            r = pow(m_next, ds[i], ns[i])
            # 候选 r + t*n_i
            t = 0
            while True:
                cand = r + t * ns[i]
                if limit is not None and cand >= limit:
                    break
                if i == 0:
                    raw_inner += 1
                    # 最内层：必须是可打印 ASCII
                    try:
                        raw = cand.to_bytes((cand.bit_length() + 7) // 8, "big")
                        if all(32 <= ch < 127 for ch in raw) and b"{" in raw:
                            nxt.append(cand)
                    except Exception:
                        pass
                else:
                    nxt.append(cand)
                t += 1
                if t > 4:      # 每层最多 ~4 个候选（12 个 n 位数相当）；实测最内层未剪枝 20 个
                    break
        cands = nxt
        if not cands:
            print("[FAIL] 逆推到第 %d 层时没有候选了" % i)
            return None
    # 去重
    uniq = sorted(set(cands))
    print("[2] 逆推完成: 最内层未剪枝候选 %d 个 → 加「可打印 ASCII 且含 {」剪枝后 %d 个"
          % (raw_inner, len(uniq)))
    if len(uniq) != 1:
        print("[WARN] 候选不唯一: %d 个" % len(uniq))
    return uniq


def step3_forward_check(m0: int, ns: list[int], expected_c: int) -> bool:
    """判据 2：从 m0 正向加密 12 次，必须与题目给的 c 完全一致。"""
    m = m0
    for n in ns:
        m = pow(m, E, n)
    ok = (m == expected_c)
    print("[2] 正推复算: %s（%d bits 结果 %s 题目 c）"
          % ("一致" if ok else "不一致", m.bit_length(),
             "==" if ok else "!="))
    if not ok:
        print("[FAIL] 判据2 不过")
    else:
        print("[2] 判据2 通过")
    return ok


def main() -> int:
    ns = load_moduli()
    expected_c = load_expected_c()
    ref = REF_FILE.read_text(encoding="utf-8").strip()
    print("模数个数 = %d，题目 c = %d bits" % (len(ns), expected_c.bit_length()))
    print("参考 flag = %r" % ref)

    p, _ = step1_common_prime(ns)
    if p is None:
        return 1

    uniq = step2_chain_recover(ns, p, expected_c)
    if not uniq:
        return 1

    ok_all = True
    for m0 in uniq:
        raw = m0.to_bytes((m0.bit_length() + 7) // 8, "big")
        text = raw.decode("utf-8", errors="replace")
        fwd = step3_forward_check(m0, ns, expected_c)
        # 判据 3
        eq = (text == ref)
        print("[3] 候选 %r 与参考答案 %s" % (text, "逐字节相同" if eq else "不同"))
        if not (fwd and eq):
            ok_all = False

    print()
    if ok_all and len(uniq) == 1:
        print("=== VERIFIED: 三条判据全过，flag = %s ===" % ref)
        return 0
    print("=== NOT VERIFIED: 见上面 [FAIL]/[WARN] ===")
    return 1


if __name__ == "__main__":
    sys.exit(main())
