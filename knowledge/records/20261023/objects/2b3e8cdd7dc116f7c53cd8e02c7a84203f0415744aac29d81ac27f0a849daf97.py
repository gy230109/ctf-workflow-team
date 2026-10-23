#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分块渲染 game.gb 的 2bpp 图块 + 1bpp 视图，便于肉眼判别。"""
import os, zlib, struct, sys

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ROM = open(os.path.join(BASE, "input", "game.gb"), "rb").read()
OUT = os.path.join(BASE, "work", "img")
os.makedirs(OUT, exist_ok=True)


def png_gray(path, w, h, pix):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += pix[y * w:(y + 1) * w]
    def chunk(t, d):
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    blob = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)) \
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
    open(path, "wb").write(blob)


def tiles(data, path, per_row=16, scale=4, sh=(255, 200, 110, 0)):
    n = len(data) // 16
    rows = (n + per_row - 1) // per_row
    W, H = per_row * 8 * scale, rows * 8 * scale
    pix = bytearray(b"\xff" * (W * H))
    for t in range(n):
        ox, oy = (t % per_row) * 8 * scale, (t // per_row) * 8 * scale
        for r in range(8):
            lo, hi = data[t * 16 + r * 2], data[t * 16 + r * 2 + 1]
            for c in range(8):
                b = ((lo >> (7 - c)) & 1) | (((hi >> (7 - c)) & 1) << 1)
                for dy in range(scale):
                    s = (oy + r * scale + dy) * W + ox + c * scale
                    pix[s:s + scale] = bytes([sh[b]]) * scale
    png_gray(path, W, H, pix)


def bits1(data, path, width_bytes=32, scale=2):
    bpr = width_bytes
    h = (len(data) + bpr - 1) // bpr
    w = bpr * 8
    pix = bytearray(w * h)
    for i, b in enumerate(data):
        y, xb = divmod(i, bpr)
        for k in range(8):
            pix[y * w + xb * 8 + k] = 255 if (b >> (7 - k)) & 1 else 0
    if scale > 1:
        sw, sh_ = w * scale, h * scale
        sp = bytearray(sw * sh_)
        for y in range(h):
            big = bytearray()
            for v in pix[y * w:(y + 1) * w]:
                big += bytes([v]) * scale
            for s in range(scale):
                sp[(y * scale + s) * sw:(y * scale + s + 1) * sw] = big
        png_gray(path, sw, sh_, sp)
    else:
        png_gray(path, w, h, pix)


jobs_tile = [("t_0000_0400", 0x0000, 0x0400), ("t_0400_0800", 0x0400, 0x0800),
             ("t_0800_0C00", 0x0800, 0x0C00), ("t_0C00_1000", 0x0C00, 0x1000),
             ("t_1000_1400", 0x1000, 0x1400), ("t_1400_2000", 0x1400, 0x2000),
             ("t_2000_3000", 0x2000, 0x3000), ("t_3000_4000", 0x3000, 0x4000)]
for name, a, b in jobs_tile:
    tiles(ROM[a:b], os.path.join(OUT, name + ".png"), 16, 4)

jobs_bits = [("b_0000_1000", 0x0000, 0x1000, 32), ("b_1000_2000", 0x1000, 0x2000, 32),
             ("b_2000_3000", 0x2000, 0x3000, 32), ("b_3000_4000", 0x3000, 0x4000, 32),
             ("b_all_w64", 0x0000, 0x4000, 64)]
for name, a, b, wb in jobs_bits:
    bits1(ROM[a:b], os.path.join(OUT, name + ".png"), wb, 2)

for f in sorted(os.listdir(OUT)):
    print(f, os.path.getsize(os.path.join(OUT, f)))
