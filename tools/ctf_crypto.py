# -*- coding: utf-8 -*-
"""Team CTF workflow component. See README.md for configuration and verified scope."""
from __future__ import annotations

import json
import math
import os
import pickle
import random
import re
import string
import time
from collections import Counter
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
GM_BASE = TOOLS_DIR.parent
CACHE_PATH = Path(os.environ.get("CTF_CRYPTO_CACHE", str(GM_BASE / "logs" / "crypto_ngram.pkl")))
DEFAULT_CORPUS = Path(os.environ.get(
    "CTF_CRYPTO_CORPUS", str(GM_BASE / "references" / "hacktricks" / "src")))
MAX_CORPUS_CHARS = 6_000_000
SQRT = math.sqrt

ALPHA = string.ascii_lowercase
BIFID_ALPHA = "abcdefghiklmnopqrstuvwxyz"  # 25 字母，无 j

# 英语字母频率（用于同音/多表的频率先验初始化）
ENGF = {'a': .082, 'b': .015, 'c': .028, 'd': .043, 'e': .127, 'f': .022, 'g': .020,
        'h': .061, 'i': .070, 'j': .0015, 'k': .008, 'l': .040, 'm': .024, 'n': .067,
        'o': .075, 'p': .019, 'q': .001, 'r': .060, 's': .063, 't': .091, 'u': .028,
        'v': .010, 'w': .024, 'x': .0015, 'y': .020, 'z': .0007}
LETTER_BY_FREQ = sorted(ALPHA, key=lambda c: -ENGF[c])

# ---------------------------------------------------------------- 语料与模型

def english_body(text: str) -> str:
    """去掉 Markdown 代码块/链接/数字，只留小写英文正文。"""
    out, in_code = [], False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        line = re.sub(r"`[^`]*`", " ", line)
        line = re.sub(r"\[[^\]]*\]\([^)]*\)", " ", line)
        line = re.sub(r"[0-9]+", " ", line)
        out.append(line)
    return re.sub(r"[^a-z]+", "", " ".join(out).lower())


def _build_model(root: Path, max_chars: int = MAX_CORPUS_CHARS) -> dict:
    chunks, total = [], 0
    for path in sorted(root.rglob("*.md")):
        try:
            body = english_body(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        chunks.append(body)
        total += len(body)
        if total > max_chars:
            break
    corpus = "".join(chunks)
    if len(corpus) < 100_000:
        raise RuntimeError("语料过小，无法构建语言模型：%s" % root)
    model = {"root": str(root), "chars": len(corpus), "L": {}, "floor": {}, "tot": {}}
    for n in (2, 3, 4):
        counter = Counter(corpus[i:i + n] for i in range(len(corpus) - n + 1))
        tot = sum(counter.values())
        model["L"][n] = {k: math.log(v / tot) for k, v in counter.items()}
        model["floor"][n] = math.log(0.1 / tot)
        model["tot"][n] = tot
    return model


_MODEL_CACHE: dict = {}


def load_model(root: Path | str | None = None, rebuild: bool = False) -> dict:
    """加载（或构建）n-gram 模型，落盘缓存，避免每次重建。"""
    root = Path(root or DEFAULT_CORPUS)
    key = str(root)
    if not rebuild and key in _MODEL_CACHE:
        return _MODEL_CACHE[key]
    if not rebuild and CACHE_PATH.exists():
        try:
            with CACHE_PATH.open("rb") as fh:
                blob = pickle.load(fh)
            if blob.get("root") == key and blob.get("chars"):
                _MODEL_CACHE[key] = blob
                return blob
        except (OSError, pickle.PickleError, AttributeError, EOFError):
            pass
    model = _build_model(root)
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CACHE_PATH.open("wb") as fh:
            pickle.dump(model, fh, protocol=4)
    except OSError:
        pass
    _MODEL_CACHE[key] = model
    return model


def score(s: str, model: dict, orders=(3, 4)) -> float:
    """n-gram 对数概率和（默认 trigram + quadgram），越大越像自然语言。"""
    tot = 0.0
    for n in orders:
        table, floor = model["L"][n], model["floor"][n]
        for i in range(len(s) - n + 1):
            tot += table.get(s[i:i + n], floor)
    return tot


def score_per_char(s: str, model: dict, orders=(2, 3, 4)) -> float:
    if not s:
        return -1e9
    return score(s, model, orders) / len(s)


# ---------------------------------------------------------------- 结构诊断

def ic(seq: str) -> float:
    n = len(seq)
    if n < 2:
        return 0.0
    counts = Counter(seq)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def avg_col_ic(seq: str, period: int) -> float:
    """按周期分列后的加权平均重合指数（维吉尼亚判周期用）。"""
    if period < 1 or period >= len(seq):
        return 0.0
    total = weight = 0.0
    for r in range(period):
        col = seq[r::period]
        total += ic(col) * len(col)
        weight += len(col)
    return total / weight if weight else 0.0


def col_ic_scan(seq: str, max_period: int = 24) -> list:
    out = []
    for p in range(1, min(max_period, len(seq) - 1) + 1):
        out.append((p, avg_col_ic(seq, p)))
    return out


def col_ic_significance(seq: str, max_period: int = 24, trials: int = 40,
                        min_col_len: int = 12, seed: int = 0) -> list:
    """列 IC 的显著性检验。

    短样本下大周期的列只有几个字符，列 IC 天然偏高（随机也能到 0.06+）。
    这里用打乱密文（保持符号频次）做零假设基线，给出 z 分数，避免把小样本噪声
    误判成「多表周期」。返回 [(period, observed_ic, z)]，按 z 降序。
    """
    rng = random.Random(seed)
    chars = list(seq)
    periods = [p for p in range(2, min(max_period, len(seq) - 1) + 1)
               if len(seq) // p >= min_col_len]
    if not periods:
        return []
    observed = {p: avg_col_ic(seq, p) for p in periods}
    samples = {p: [] for p in periods}
    for _ in range(trials):
        rng.shuffle(chars)
        shuffled = "".join(chars)
        for p in periods:
            samples[p].append(avg_col_ic(shuffled, p))
    out = []
    for p in periods:
        vals = samples[p]
        mean = sum(vals) / len(vals)
        var = sum((v - mean) ** 2 for v in vals) / max(1, len(vals) - 1)
        std = SQRT(var) if var > 0 else 0.0
        z = (observed[p] - mean) / std if std > 1e-9 else 0.0
        out.append((p, observed[p], z))
    out.sort(key=lambda x: -x[2])
    return out


def _symbol_semantics(syms: list) -> dict:
    digits = sum(c.isdigit() for c in syms)
    shift_row = sum(c in "!@#$%^&*()" for c in syms)
    punct = sum(c in ".,;:'\"-_=+[]{}\\|/?<>~`" for c in syms)
    letters = sum(c.isalpha() for c in syms)
    return {"digits": digits, "keyboard_shift_row": shift_row,
            "punctuation_like": punct, "letters": letters,
            "other": len(syms) - digits - shift_row - punct - letters}


def _factor_pairs(n: int) -> list:
    return [(r, n // r) for r in range(2, int(n ** 0.5) + 1) if n % r == 0]


def diagnose(text: str) -> dict:
    """只依赖密文本身的结构诊断，输出密码族先验排名。"""
    ct = re.sub(r"\s+", "", text)
    n = len(ct)
    syms = sorted(set(ct))
    k = len(syms)
    observed_ic = ic(ct)
    uniform_ic = 1.0 / k if k else 0.0
    scan = col_ic_scan(ct)
    sig = col_ic_significance(ct)
    # 只有 z 分数显著的周期才算证据；短样本下大周期的列 IC 天然偏高
    best_period, best_col_ic, best_z = 1, 0.0, 0.0
    if sig:
        best_period, best_col_ic, best_z = sig[0]
    period_evidence = best_z >= 3.0

    ranking = []
    lift = observed_ic / uniform_ic if uniform_ic else 0.0

    def add(family, prior, reason):
        ranking.append({"family": family, "prior": prior, "reason": reason})

    mono_like = observed_ic >= 0.055
    if k > 26:
        # 硬约束：26 字母表下的 1:1 替换最多产生 26 个符号；转置也不改变符号数
        add("mono_substitution", 0.05,
            "符号数 %d>26，26 字母表下 1:1 单表替换不可能产生" % k)
        add("transposition", 0.15, "转置不改变符号数，%d>26 同样不支持纯转置" % k)
    elif mono_like:
        add("mono_substitution", 0.85 if observed_ic >= 0.060 else 0.70,
            "IC=%.4f 接近英文单表 0.066，单字母频率未被拉平" % observed_ic)
        add("transposition", 0.55, "转置不改变单字母频率，需与单表联合排查")
    else:
        add("mono_substitution", 0.25 if observed_ic >= 0.045 else 0.08,
            "IC=%.4f 低于英文单表，纯单表可能性低" % observed_ic)
        add("transposition", 0.30,
            "若为纯转置，IC 应仍≈0.066，当前不足 -> 转置需配合替换")

    if period_evidence:
        add("polyalphabetic", 0.80,
            "周期 %d 的列 IC=%.4f 相对打乱基线 z=%.1f，显著抬升，疑似维吉尼亚类多表"
            % (best_period, best_col_ic, best_z))
    elif best_z >= 1.8 and observed_ic < 0.055:
        add("polyalphabetic", 0.50,
            "周期 %d 列 IC=%.4f 相对打乱基线 z=%.1f，弱抬升（样本短，可能漏检）"
            % (best_period, best_col_ic, best_z))
    elif observed_ic < 0.050:
        add("polyalphabetic", 0.55, "整体 IC 被拉平，多表/长密钥候选（列 IC 未达显著）")
    else:
        add("polyalphabetic", 0.15,
            "列 IC 未超过打乱基线（最佳 z=%.1f，样本长度 %d 不足以定周期）" % (best_z, n))

    if k > 26:
        add("homophonic", 0.75, "符号数 %d>26，超出单表字母表，典型同音替换特征" % k)
    elif lift >= 1.15 and observed_ic < 0.060:
        add("homophonic", 0.60,
            "符号数 %d 但 IC 仅 %.4f（均匀线 %.4f），频率被压平，疑似同音或多表" % (k, observed_ic, uniform_ic))
    else:
        add("homophonic", 0.25, "符号数/IC 未显同音特征")

    if k in (25, 26) or (5 <= k <= 9):
        add("polygraphic", 0.45, "符号数 %d 恰好构成 5x5 或小字母表，Bifid/Playfair 候选" % k)
    if _symbol_semantics(syms)["keyboard_shift_row"] >= 4:
        add("keyboard_encoding", 0.40, "符号大量落在键盘 Shift 数字行（!@#$%^&*()），疑似键盘/编码映射")

    ranking.sort(key=lambda d: -d["prior"])
    return {
        "length": n, "distinct_symbols": k, "symbols": "".join(syms),
        "ic": round(observed_ic, 5), "uniform_ic": round(uniform_ic, 5),
        "ic_lift_over_uniform": round(lift, 3),
        "factor_pairs": _factor_pairs(n),
        "symbol_semantics": _symbol_semantics(syms),
        "dominant_period": best_period, "dominant_period_ic": round(best_col_ic, 5),
        "dominant_period_z": round(best_z, 2), "period_evidence_significant": period_evidence,
        "col_ic_significance_top": [(p, round(v, 5), round(z, 2)) for p, v, z in sig[:5]],
        "col_ic_top": sorted(((p, round(v, 5)) for p, v in scan), key=lambda x: -x[1])[:5],
        "family_ranking": ranking,
        "note": "先验排名只用于排序尝试顺序，不构成任何结论。",
    }


# ---------------------------------------------------------------- 单表求解

def _apply(code: list, key: list) -> str:
    return "".join(map(key.__getitem__, code))


def solve_mono_seq(seq: str, model: dict, seconds: float = 20.0, seed: int = 0,
                   orders=(3, 4)) -> tuple:
    """对符号序列做单表替换求解：全对交换收敛 + 3-cycle 逃逸 + 预算内重启。"""
    syms = sorted(set(seq))
    n = len(syms)
    if n > 26 or n < 2:
        return -1e18, ""
    code = [syms.index(c) for c in seq]
    rng = random.Random(seed)
    t0 = time.time()
    best = (-1e18, "")
    while time.time() - t0 < seconds:
        key = rng.sample(ALPHA, n)
        plain = _apply(code, key)
        sc = score(plain, model, orders)
        improved = True
        while improved:
            improved = False
            for i in range(n):
                for j in range(i + 1, n):
                    key[i], key[j] = key[j], key[i]
                    candidate = _apply(code, key)
                    s2 = score(candidate, model, orders)
                    if s2 > sc:
                        sc, plain, improved = s2, candidate, True
                    else:
                        key[i], key[j] = key[j], key[i]
            if not improved:
                for _ in range(120):
                    a, b, c = rng.sample(range(n), 3)
                    key[a], key[b], key[c] = key[c], key[a], key[b]
                    candidate = _apply(code, key)
                    s2 = score(candidate, model, orders)
                    if s2 > sc:
                        sc, plain, improved = s2, candidate, True
                        break
                    key[a], key[b], key[c] = key[b], key[c], key[a]
        if sc > best[0]:
            best = (sc, plain)
    return best


# ---------------------------------------------------------------- 转置读序

def _spiral(rows: int, cols: int, corner: str, clockwise: bool) -> list:
    grid = [[r * cols + c for c in range(cols)] for r in range(rows)]
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    out = []
    while top <= bottom and left <= right:
        layer = []
        for c in range(left, right + 1):
            layer.append((top, c))
        for r in range(top + 1, bottom + 1):
            layer.append((r, right))
        if bottom > top:
            for c in range(right - 1, left - 1, -1):
                layer.append((bottom, c))
        if right > left:
            for r in range(bottom - 1, top, -1):
                layer.append((r, left))
        if not clockwise:
            layer = layer[::-1]
        out += [grid[r][c] for r, c in layer]
        top, bottom, left, right = top + 1, bottom - 1, left + 1, right - 1
    if corner in ("TR", "BR"):
        out = out[1:] + out[:1] if out else out
    return out


def _diag(rows: int, cols: int) -> list:
    out = []
    for s in range(rows + cols - 1):
        cells = [(r, s - r) for r in range(rows) if 0 <= s - r < cols]
        if s % 2:
            cells = cells[::-1]
        out += [r * cols + c for r, c in cells]
    return out


def read_orders(n: int) -> list:
    """返回 [(tag, idx)]；idx[k] 表示读出的第 k 个字符取自原文 idx[k] 位置。"""
    out: dict = {}

    def add(tag, idx):
        if len(idx) == n and sorted(idx) == list(range(n)) and tag not in out:
            out[tag] = list(idx)

    add("identity", range(n))
    add("reverse", range(n - 1, -1, -1))
    for L in range(2, min(n, 25) + 1):
        if n % L == 0:
            rows = n // L
            add("fence%d" % L, [r * L + c for c in range(L) for r in range(rows)])
            add("ifence%d" % L, [c * rows + r for r in range(rows) for c in range(L)])
    for r in range(2, n):
        if n % r:
            continue
        c = n // r
        if c < 2 or (r, c) == (n, 1):
            continue
        add("col%d" % r, [x * c + y for y in range(c) for x in range(r)])
        add("snakeR%d" % r, [(x * c + (y if x % 2 == 0 else c - 1 - y)) for x in range(r) for y in range(c)])
        add("snakeC%d" % r, [((x if y % 2 == 0 else r - 1 - x) * c + y) for y in range(c) for x in range(r)])
        add("diag%d" % r, _diag(r, c))
        for corner in ("TL", "TR", "BL", "BR"):
            for cw in (True, False):
                add("spiral%s%s%d" % (corner, "cw" if cw else "ccw", r), _spiral(r, c, corner, cw))
        for bh in (2, 3):
            if r % bh:
                continue
            idx = []
            for r0 in range(0, r, bh):
                for y in range(c):
                    for x in range(r0, r0 + bh):
                        idx.append(x * c + y)
            add("blockIL%d_%d" % (bh, r), idx)
    return sorted(out.items())


def solve_transposition(ct: str, model: dict, budget: float = 120.0, seed: int = 0,
                        min_each: float = 0.4) -> dict:
    """枚举读序 × 单表求解器。budget 是**总**时间预算，按读序数均分，避免总时长失控。"""
    orders = read_orders(len(ct))
    each = max(min_each, budget / max(1, len(orders)))
    # 宁可把每个读序的时间压薄、也要覆盖全部读序：截断读序列表会让真读序根本没被试到
    hard_stop = max(budget * 1.5, each * len(orders))
    t0 = time.time()
    results = []
    for i, (tag, idx) in enumerate(orders):
        if time.time() - t0 >= hard_stop:
            break
        seq = "".join(ct[p] for p in idx)
        sc, plain = solve_mono_seq(seq, model, each, seed + i)
        results.append((sc, tag, plain))
    if not results:
        return {"score": -1e18, "order": None, "plaintext": "", "top": [],
                "orders_tried": 0, "orders_total": len(orders)}
    results.sort(key=lambda x: -x[0])
    sc, tag, plain = results[0]
    return {"score": sc, "order": tag, "plaintext": plain,
            "orders_tried": len(results), "orders_total": len(orders),
            "elapsed_seconds": round(time.time() - t0, 1),
            "top": [{"order": t, "score": round(s, 1), "plaintext": p} for s, t, p in results[:5]]}


# ---------------------------------------------------------------- 多表求解

def solve_poly(ct: str, model: dict, period: int, seconds: float = 30.0, seed: int = 0) -> dict:
    """多表（维吉尼亚类，任意符号表）：每个列位置一个独立替换，联合爬山。"""
    n = len(ct)
    cols = [list(range(j, n, period)) for j in range(period)]
    syms_per_col = [sorted(set(ct[j::period])) for j in range(period)]
    if any(len(s) > 26 for s in syms_per_col):
        return {"score": -1e18, "plaintext": "", "error": "某列符号数 >26，超出字母表"}
    rng = random.Random(seed)
    t0 = time.time()
    best = (-1e18, "")

    def render(maps):
        buf = [""] * n
        for j, mapping in enumerate(maps):
            for p in cols[j]:
                buf[p] = mapping[ct[p]]
        return "".join(buf)

    while time.time() - t0 < seconds:
        maps = []
        for j in range(period):
            order = sorted(syms_per_col[j], key=lambda s: -ct[j::period].count(s))
            shift = rng.randrange(len(LETTER_BY_FREQ))
            pick = LETTER_BY_FREQ[shift:] + LETTER_BY_FREQ[:shift]
            maps.append({s: pick[i] for i, s in enumerate(order)})
        plain = render(maps)
        sc = score(plain, model)
        improved = True
        while improved and time.time() - t0 < seconds:
            improved = False
            for j in range(period):
                for s in syms_per_col[j]:
                    old = maps[j][s]
                    for cand in ALPHA:
                        if cand == old:
                            continue
                        maps[j][s] = cand
                        trial = render(maps)
                        s2 = score(trial, model)
                        if s2 > sc:
                            sc, plain, improved, old = s2, trial, True, cand
                        else:
                            maps[j][s] = old
        if sc > best[0]:
            best = (sc, plain)
    return {"score": best[0], "plaintext": best[1]}


# ---------------------------------------------------------------- 同音替换

def solve_homophonic(ct: str, model: dict, seconds: float = 60.0, seed: int = 0) -> dict:
    """同音替换：符号->字母 多对一，模拟退火 + 频率先验初始化 + 多次重启。"""
    syms = sorted(set(ct))
    freq = Counter(ct)
    order = [s for s, _ in freq.most_common()]
    rng = random.Random(seed)
    t0 = time.time()
    best = (-1e18, "")

    def render(mapping):
        return "".join(mapping[c] for c in ct)

    while time.time() - t0 < seconds:
        mapping = {}
        # 频率先验初始化：符号频率序 -> 高频字母池随机
        pool = LETTER_BY_FREQ[:14]
        for i, s in enumerate(order):
            mapping[s] = LETTER_BY_FREQ[i] if i < len(LETTER_BY_FREQ) and rng.random() < 0.5 \
                else rng.choice(pool)
        plain = render(mapping)
        sc = score_per_char(plain, model, (2, 3, 4))
        steps = 40000
        T0, T1 = 0.8, 0.02
        for it in range(steps):
            if time.time() - t0 >= seconds:
                break
            T = T0 * (T1 / T0) ** (it / steps)
            s = rng.choice(syms)
            old = mapping[s]
            new = rng.choice(pool)
            if new == old:
                continue
            mapping[s] = new
            trial = render(mapping)
            s2 = score_per_char(trial, model, (2, 3, 4))
            if s2 >= sc or rng.random() < math.exp(min(60.0, (s2 - sc) / T)):
                sc, plain = s2, trial
                if sc > best[0]:
                    best = (sc, plain)
            else:
                mapping[s] = old
    return {"score": best[0], "plaintext": best[1]}


# ---------------------------------------------------------------- Bifid

_POS = {ch: (i // 5, i % 5) for i, ch in enumerate(BIFID_ALPHA)}


def bifid_decrypt(letters: str, period: int) -> str:
    out = []
    for i in range(0, len(letters), period):
        blk = letters[i:i + period]
        flat = []
        for ch in blk:
            r, c = _POS[ch]
            flat.append(r)
            flat.append(c)
        half = len(blk)
        rows, cols = flat[:half], flat[half:]
        out += [BIFID_ALPHA[r * 5 + c] for r, c in zip(rows, cols)]
    return "".join(out)


def bifid_encrypt(letters: str, period: int) -> str:
    out = []
    for i in range(0, len(letters), period):
        blk = letters[i:i + period]
        rows, cols = [], []
        for ch in blk:
            r, c = _POS[ch]
            rows.append(r)
            cols.append(c)
        flat = rows + cols
        out += [BIFID_ALPHA[flat[k] * 5 + flat[k + 1]] for k in range(0, len(flat), 2)]
    return "".join(out)


def solve_bifid(ct: str, model: dict, seconds: float = 40.0, seed: int = 0,
                max_period: int = 16) -> dict:
    """Bifid：标准方阵下的周期枚举 × 符号->字母映射爬山。"""
    syms = sorted(set(ct))
    if len(syms) > 25:
        return {"score": -1e18, "plaintext": "", "error": "符号数 >25，无法映射到 5x5 方阵"}
    code = [syms.index(c) for c in ct]
    rng = random.Random(seed)
    t0 = time.time()
    best = {"score": -1e18, "plaintext": "", "period": None}
    budget_period = max(2.0, seconds / max(1, max_period - 1))
    for period in range(2, max_period + 1):
        pt0 = time.time()
        while time.time() - pt0 < budget_period and time.time() - t0 < seconds:
            key = rng.sample(BIFID_ALPHA, len(syms))
            plain = bifid_decrypt(_apply(code, key), period)
            sc = score(plain, model)
            improved = True
            while improved and time.time() - pt0 < budget_period:
                improved = False
                for i in range(len(syms)):
                    for j in range(i + 1, len(syms)):
                        key[i], key[j] = key[j], key[i]
                        plain2 = bifid_decrypt(_apply(code, key), period)
                        s2 = score(plain2, model)
                        if s2 > sc:
                            sc, plain, improved = s2, plain2, True
                        else:
                            key[i], key[j] = key[j], key[i]
            if sc > best["score"]:
                best = {"score": sc, "plaintext": plain, "period": period}
    return best


# ---------------------------------------------------------------- 自检

SELF_EN = ("the most important thing about a homophonic cipher is that the common letters "
           "are replaced by more than one symbol so that the simple frequency count cannot "
           "tell the difference between a natural language and a random string of symbols")
SELF_SYMS = list("!@#$%^&*()_+-=[]{};:,.<>/?~|`\\\"'")  # 25 个符号


def _selfcheck_mono(model, seconds=25.0):
    text = re.sub(r"[^a-z]", "", SELF_EN.lower())[:135]
    plain = text.replace("v", "")
    letters = sorted(set(plain))
    syms = SELF_SYMS[:len(letters)]
    rng = random.Random(11)
    pair = list(zip(letters, syms))
    rng.shuffle(pair)
    enc = "".join(dict(pair)[c] for c in plain)
    _, dec = solve_mono_seq(enc, model, seconds, 1)
    acc = sum(a == b for a, b in zip(dec, plain))
    detail = "还原 %d/%d" % (acc, len(plain))
    return {"passed": acc >= 0.85 * len(plain), "detail": detail}


def _selfcheck_transposition(model, seconds=25.0):
    text = re.sub(r"[^a-z]", "", SELF_EN.lower())[:135]
    order = dict(read_orders(len(text))).get("spiralTLcw9")
    if not order:
        order = list(range(len(text)))
    shuffled = "".join(text[i] for i in order)
    rng = random.Random(13)
    key = rng.sample(ALPHA, len(set(shuffled)))
    enc = "".join(key[idx] for idx in [sorted(set(shuffled)).index(c) for c in shuffled])
    r = solve_transposition(enc, model, max(30.0, seconds), 2)
    acc = sum(a == b for a, b in zip(r["plaintext"], text))
    return {"passed": acc >= 0.80 * len(text),
            "detail": "最佳读序 %s，还原 %d/%d" % (r["order"], acc, len(text))}


def _selfcheck_poly(model, seconds=25.0):
    text = re.sub(r"[^a-z]", "", SELF_EN.lower())[:135]
    period = 4
    rng = random.Random(17)
    maps = [{c: rng.choice(ALPHA) for c in ALPHA} for _ in range(period)]
    enc = "".join(maps[i % period][c] for i, c in enumerate(text))
    r = solve_poly(enc, model, period, seconds, 3)
    acc = sum(a == b for a, b in zip(r["plaintext"], text))
    return {"passed": acc >= 0.85 * len(text), "detail": "周期 4，还原 %d/%d" % (acc, len(text))}


def _selfcheck_homophonic(model, seconds=40.0):
    text = re.sub(r"[^a-z]", "", SELF_EN.lower())[:135]
    mapping = {}
    letters = sorted(set(text))
    pool = SELF_SYMS[:len(letters)]
    rng = random.Random(19)
    for i, c in enumerate(letters):
        mapping[c] = [pool[i]]
    extra = pool[len(letters):]
    for c in letters:
        if not extra:
            break
        mapping[c].append(extra.pop(0))
    enc = "".join(rng.choice(mapping[c]) for c in text)
    r = solve_homophonic(enc, model, seconds, 5)
    acc = sum(a == b for a, b in zip(r["plaintext"], text))
    return {"passed": acc >= 0.75 * len(text), "detail": "还原 %d/%d" % (acc, len(text))}


def _selfcheck_bifid(model, seconds=40.0):
    text = re.sub(r"[^a-z]", "", SELF_EN.lower()).replace("j", "i")[:135]
    text = "".join(c for c in text if c in BIFID_ALPHA)
    enc_letters = bifid_encrypt(text, 7)
    rng = random.Random(23)
    syms = SELF_SYMS[:25]
    pair = list(zip(BIFID_ALPHA, syms))
    rng.shuffle(pair)
    enc = "".join(dict(pair)[c] for c in enc_letters)
    r = solve_bifid(enc, model, seconds, 7, max_period=12)
    acc = sum(a == b for a, b in zip(r["plaintext"], text))
    return {"passed": acc >= 0.75 * len(text), "detail": "还原 %d/%d" % (acc, len(text))}


def _selfcheck_diagnosis(model=None, seconds=0.0):
    """用合成的已知密码样本验证诊断排名是否指向正确答案。"""
    text = re.sub(r"[^a-z]", "", SELF_EN.lower())[:135]
    rng = random.Random(31)
    cases = []

    # 1) 英文单表替换（25 符号）-> 期望 mono_substitution 排第一
    pair = list(zip(sorted(set(text)), SELF_SYMS[:len(set(text))]))
    rng.shuffle(pair)
    cases.append(("mono", "".join(dict(pair)[c] for c in text), "mono_substitution"))

    # 2) 周期 5 的多表（列内随机单表）-> 期望 polyalphabetic 排第一
    maps = [{c: rng.choice(ALPHA) for c in ALPHA} for _ in range(5)]
    cases.append(("poly5", "".join(maps[i % 5][c] for i, c in enumerate(text)), "polyalphabetic"))

    # 3) 同音替换：高频字母各配两个符号，交替使用以保证同音符号真的出现
    #    （若随机抽取，第二个符号常常一次都不出现，实际符号数仍是 25，那就真的退化成单表）
    letters = sorted(set(text))
    homo = {c: [SELF_SYMS[i]] for i, c in enumerate(letters)}
    hot = [c for c, _ in Counter(text).most_common(8)]
    for j, c in enumerate(hot):
        homo[c].append(SELF_SYMS[len(letters) + j])
    used = {c: 0 for c in hot}

    def _homo_pick(ch):
        if ch in used:
            used[ch] += 1
            return homo[ch][used[ch] % 2]
        return homo[ch][0]

    cases.append(("homophonic", "".join(_homo_pick(c) for c in text), "homophonic"))

    details, ok = [], True
    for name, cipher, expect in cases:
        ranking = diagnose(cipher)["family_ranking"]
        top = ranking[0]["family"] if ranking else None
        hit = top == expect
        ok = ok and hit
        details.append("%s->%s%s" % (name, top, "" if hit else "(期望 %s)" % expect))
    return {"passed": ok, "detail": "；".join(details)}


SELFCHECKS = {
    "diagnosis": _selfcheck_diagnosis,
    "mono_substitution": _selfcheck_mono,
    "transposition": _selfcheck_transposition,
    "polyalphabetic": _selfcheck_poly,
    "homophonic": _selfcheck_homophonic,
    "bifid": _selfcheck_bifid,
}


def run_selfchecks(root=None, seconds=25.0) -> dict:
    model = load_model(root)
    out = {}
    for name, fn in SELFCHECKS.items():
        t0 = time.time()
        try:
            r = fn(model, seconds)
        except Exception as exc:  # 自检失败也要如实汇报，不能崩
            r = {"passed": False, "detail": "自检异常：%s" % exc}
        r["seconds"] = round(time.time() - t0, 1)
        out[name] = r
    return out


# ---------------------------------------------------------------- 编排

def attack(text: str, root=None, budget: float = 150.0, flag_regex: str = r"flag\{[^}]{0,120}\}",
           families=None, checks=None) -> dict:
    """按诊断先验排名定向求解，结果显式带 self_check 状态。"""
    ct = re.sub(r"\s+", "", text)
    model = load_model(root)
    diag = diagnose(ct)
    checks = checks or {}
    plan = families or [d["family"] for d in diag["family_ranking"]]
    results = []

    def record(family, res, plaintext_key="plaintext"):
        plain = res.get(plaintext_key, "") if isinstance(res, dict) else str(res)
        check = checks.get(family, {})
        results.append({
            "family": family,
            "score": round(res.get("score", -1e18), 1) if isinstance(res, dict) else None,
            "plaintext": plain,
            "self_check_passed": check.get("passed"),
            "self_check_detail": check.get("detail"),
        })

    share = budget / max(1, len([p for p in plan if p in ("mono_substitution", "transposition",
                                                          "polyalphabetic", "homophonic", "bifid")]))
    for family in plan:
        if family == "mono_substitution":
            sc, plain = solve_mono_seq(ct, model, share, 1)
            record(family, {"score": sc, "plaintext": plain})
        elif family == "transposition":
            record(family, solve_transposition(ct, model, share, 2))
        elif family == "polyalphabetic":
            period = diag["dominant_period"] if diag["dominant_period"] >= 2 else 5
            record(family, solve_poly(ct, model, period, share, 3))
        elif family == "homophonic":
            record(family, solve_homophonic(ct, model, share, 4))
        elif family == "polygraphic":
            record(family, solve_bifid(ct, model, share, 5))

    matches = []
    for r in results:
        if r["plaintext"]:
            for m in re.findall(flag_regex, r["plaintext"]):
                matches.append({"family": r["family"], "flag": m})
    results.sort(key=lambda r: -(r["score"] or -1e18))
    return {
        "diagnosis": diag,
        "self_checks": checks,
        "results": results,
        "flag_matches": matches,
        "note": "self_check_passed=False 的结果只能记为「未测出」，不得作为排除证据。",
    }


# ---------------------------------------------------------------- 工具表

def _read_text(args: dict) -> str:
    if args.get("file"):
        return Path(args["file"]).read_text(encoding="utf-8", errors="ignore")
    return str(args.get("text") or "")


def tool_crypto_diagnose(args: dict) -> dict:
    text = _read_text(args)
    if not text.strip():
        return {"error": "需要 text 或 file 提供密文"}
    return diagnose(text)


def tool_crypto_attack(args: dict) -> dict:
    text = _read_text(args)
    if not text.strip():
        return {"error": "需要 text 或 file 提供密文"}
    budget = float(args.get("budget", 150))
    budget = max(10.0, min(900.0, budget))
    return attack(text, root=args.get("corpus"), budget=budget,
                  flag_regex=args.get("flag_regex") or r"flag\{[^}]{0,120}\}")


def tool_crypto_selfcheck(args: dict) -> dict:
    seconds = float(args.get("seconds", 25))
    return run_selfchecks(args.get("corpus"), max(5.0, min(120.0, seconds)))


TOOLS = {
    "crypto_diagnose": (tool_crypto_diagnose,
                        "经典密码结构诊断：重合指数、列重合指数、符号数/密度/语义、长度分解，输出密码族先验排名。只读、秒级。",
                        {"type": "object",
                         "properties": {"text": {"type": "string"},
                                        "file": {"type": "string"}},
                         "required": []}),
    "crypto_attack": (tool_crypto_attack,
                      "按诊断先验排名定向求解（单表/转置/多表/同音/Bifid），返回候选明文、求解器自检状态与 flag 命中。",
                      {"type": "object",
                       "properties": {"text": {"type": "string"},
                                      "file": {"type": "string"},
                                      "budget": {"type": "number", "default": 150},
                                      "corpus": {"type": "string"},
                                      "flag_regex": {"type": "string"}},
                       "required": []}),
    "crypto_selfcheck": (tool_crypto_selfcheck,
                         "用已知明文测试向量验证各求解器能力；自检不通过的求解器的阴性结果不得作为排除依据。",
                         {"type": "object",
                          "properties": {"seconds": {"type": "number", "default": 25},
                                         "corpus": {"type": "string"}},
                          "required": []}),
}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnose", metavar="FILE_OR_TEXT")
    parser.add_argument("--selfcheck", action="store_true")
    parser.add_argument("--attack", metavar="FILE_OR_TEXT")
    parser.add_argument("--budget", type=float, default=150.0)
    parser.add_argument("--seconds", type=float, default=25.0)
    parser.add_argument("--corpus")
    args = parser.parse_args()

    def payload(value):
        p = Path(value)
        return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else value

    if args.selfcheck:
        print(json.dumps(run_selfchecks(args.corpus, args.seconds), ensure_ascii=False, indent=2))
    elif args.diagnose:
        print(json.dumps(diagnose(payload(args.diagnose)), ensure_ascii=False, indent=2))
    elif args.attack:
        print(json.dumps(attack(payload(args.attack), args.corpus, args.budget),
                         ensure_ascii=False, indent=2)[:6000])


if __name__ == "__main__":
    main()