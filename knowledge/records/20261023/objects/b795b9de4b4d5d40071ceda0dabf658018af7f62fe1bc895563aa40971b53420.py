#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""两个 MP3 的结构与二进制差异比对（非解密，只做定位）。"""
import os, struct, hashlib

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INP = os.path.join(BASE, "input")

BITRATE = {1: {1: 32, 2: 48, 3: 56, 4: 64, 5: 80, 6: 96, 7: 112, 8: 128, 9: 160,
               10: 192, 11: 224, 12: 256, 13: 320}}
SRATE = {0: 44100, 1: 48000, 2: 32000}


def load(n):
    p = os.path.join(INP, n)
    d = open(p, "rb").read()
    return p, d


def id3(d):
    if d[:3] != b"ID3":
        return None
    ver = d[3:5]
    flags = d[5]
    size = (d[6] << 21) | (d[7] << 14) | (d[8] << 7) | d[9]   # syncsafe
    return ver, flags, size, 10 + size


def frames(d, off, limit=5):
    out = []
    i = off
    n = len(d)
    while i + 4 <= n and len(out) < limit:
        h = d[i:i + 4]
        if h[0] == 0xFF and (h[1] & 0xE0) == 0xE0:
            ver = (h[1] >> 3) & 3
            layer = (h[1] >> 1) & 3
            br_i = (h[2] >> 4) & 0xF
            sr_i = (h[2] >> 2) & 3
            pad = (h[2] >> 1) & 1
            if ver == 3 and layer == 1 and br_i in BITRATE[1] and sr_i in SRATE:
                br = BITRATE[1][br_i]
                sr = SRATE[sr_i]
                flen = (144 * br * 1000) // sr + pad
                out.append((i, br, sr, flen))
                i += flen
                continue
        i += 1
    return out


def tail_scan(d, n=4096):
    t = d[-n:]
    runs = []
    cur, cnt = t[0], 1
    for b in t[1:]:
        if b == cur:
            cnt += 1
        else:
            if cnt >= 16:
                runs.append((cur, cnt))
            cur, cnt = b, 1
    if cnt >= 16:
        runs.append((cur, cnt))
    return runs


for name in ("kun.mp3", "man.mp3"):
    p, d = load(name)
    print("=== %s  %d B  sha256=%s ===" % (name, len(d), hashlib.sha256(d).hexdigest()[:16]))
    print("  ID3:", id3(d))
    fr = frames(d, id3(d)[3], 6)
    print("  连续帧前6:", fr)
    if fr:
        print("  首帧偏移=%d 帧长=%d 推算总帧数≈%.1f" % (fr[0][0], fr[0][3],
              (len(d) - fr[0][0]) / fr[0][3]))
    print("  尾部 64B:", d[-64:].hex())
    print("  尾部≥16 连续同字节 runs:", tail_scan(d)[:10])
    print("  文件端点: 最后一个非0xAA字节偏移 =",
          max(i for i, b in enumerate(d) if b != 0xAA))
    print()

a = open(os.path.join(INP, "kun.mp3"), "rb").read()
b = open(os.path.join(INP, "man.mp3"), "rb").read()
n = min(len(a), len(b))
cp = 0
while cp < n and a[cp] == b[cp]:
    cp += 1
print("=== 两文件比对 ===")
print("  kun=%d man=%d  差=%d" % (len(a), len(b), len(b) - len(a)))
print("  最长公共前缀长度 =", cp)
print("  kun[cp-8:cp+40] =", a[max(0, cp - 8):cp + 40].hex(" "))
print("  man[cp-8:cp+40] =", b[max(0, cp - 8):cp + 40].hex(" "))
same = sum(1 for i in range(n) if a[i] == b[i])
print("  同长度部分相同字节比例 = %.2f%%" % (same / n * 100))
# 分块相同率
print("  分块相同率（每 64KB）:")
for s in range(0, n, 65536):
    e = min(s + 65536, n)
    r = sum(1 for i in range(s, e) if a[i] == b[i]) / (e - s) * 100
    print("    %08X-%08X %6.2f%%" % (s, e, r))
