#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把两首 mp3 解成单声道 8kHz PCM，做采样级统计（纯 stdlib，无 numpy）。"""
import os, subprocess, struct, math

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INP = os.path.join(BASE, "input")
FF = "ffmpeg"


def pcm(name, sr=8000):
    p = os.path.join(INP, name)
    out = subprocess.run([FF, "-v", "error", "-i", p, "-ac", "1", "-ar", str(sr),
                          "-f", "s16le", "-"], capture_output=True)
    d = out.stdout
    n = len(d) // 2
    return struct.unpack("<%dh" % n, d[:n * 2]), sr


for name in ("kun.mp3", "man.mp3"):
    s, sr = pcm(name)
    n = len(s)
    print("=== %s ===" % name)
    print("  采样数=%d  时长=%.1fs  @%dHz" % (n, n / sr, sr))
    # 全局
    mx = max(abs(v) for v in s)
    rms = math.sqrt(sum(v * v for v in s) / n)
    zc = sum(1 for i in range(1, n) if (s[i - 1] < 0) != (s[i] < 0))
    uniq = len(set(s))
    print("  峰值=%d (%.3f FS)  RMS=%d (%.3f FS)  过零率=%.1f%%  不同取值=%d"
          % (mx, mx / 32768, rms, rms / 32768, zc / n * 100, uniq))
    # 每秒 RMS
    per = []
    for t in range(0, n, sr):
        seg = s[t:t + sr]
        if seg:
            per.append(math.sqrt(sum(v * v for v in seg) / len(seg)))
    print("  每秒 RMS: min=%d max=%d 均值=%d 标准差=%.1f"
          % (min(per), max(per), sum(per) / len(per),
             math.sqrt(sum((x - sum(per) / len(per)) ** 2 for x in per) / len(per))))
    print("  每秒 RMS 前 30 秒:", [int(x) for x in per[:30]])
    print("  每秒 RMS 序号差分（找突变）:")
    jumps = [(i, int(per[i] - per[i - 1])) for i in range(1, len(per))
             if abs(per[i] - per[i - 1]) > 1000]
    print("    大幅突变点(%d 处):" % len(jumps), jumps[:20])
    # 自相关：找周期性（前 2000 个采样，允许 lag 到 1000）
    seg = s[sr * 30:sr * 30 + 4000]
    if len(seg) > 2000:
        best = []
        for lag in range(2, 1000):
            c = sum(seg[i] * seg[i + lag] for i in range(0, 2000 - lag))
            best.append((c, lag))
        best.sort(reverse=True)
        print("  自相关 top5 lag:", [(l, round(c / 1e9, 2)) for c, l in best[:5]])
    print()
