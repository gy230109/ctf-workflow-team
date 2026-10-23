#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Game Boy ROM 结构侦察：正确的头部解析 + 1bpp/2bpp 可视化。
只做结构层判断，不承担解题。"""
import sys, os, zlib, struct

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INP = os.path.join(BASE, "input")
OUT = os.path.join(BASE, "work", "img")
os.makedirs(OUT, exist_ok=True)

CART = {0x00: "ROM ONLY", 0x01: "MBC1", 0x02: "MBC1+RAM", 0x03: "MBC1+RAM+BATT",
        0x05: "MBC2", 0x06: "MBC2+BATT", 0x08: "ROM+RAM", 0x09: "ROM+RAM+BATT",
        0x0B: "MMM01", 0x0C: "MMM01+RAM", 0x0D: "MMM01+RAM+BATT",
        0x0F: "MBC3+TIMER+BATT", 0x10: "MBC3+TIMER+RAM+BATT", 0x11: "MBC3",
        0x12: "MBC3+RAM", 0x13: "MBC3+RAM+BATT", 0x19: "MBC5", 0x1A: "MBC5+RAM",
        0x1B: "MBC5+RAM+BATT", 0x1C: "MBC5+RUMBLE", 0x1D: "MBC5+RUMBLE+RAM",
        0x1E: "MBC5+RUMBLE+RAM+BATT", 0x20: "MBC6", 0x22: "MBC7+SENSOR+RUMBLE+RAM+BATT"}
ROMSZ = {0x00: "32KB(2 bank)", 0x01: "64KB(4)", 0x02: "128KB(8)", 0x03: "256KB(16)",
         0x04: "512KB(32)", 0x05: "1MB(64)", 0x06: "2MB(128)", 0x07: "4MB(256)",
         0x08: "8MB(512)", 0x52: "1.1MB(72)", 0x53: "1.2MB(80)", 0x54: "1.5MB(96)"}


def png_gray(path, w, h, pix):
    """pix: bytearray len w*h，0=黑 255=白"""
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += pix[y * w:(y + 1) * w]
    def chunk(t, d):
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
    blob = b"\x89PNG\r\n\x1a\n"
    blob += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
    blob += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    blob += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(blob)


def rom_as_1bpp(rom, path, width_bytes=16, scale=1):
    """整块 ROM 按 1bpp 排成图：每字节 8 像素。"""
    bpr = width_bytes
    h = (len(rom) + bpr - 1) // bpr
    w = bpr * 8
    pix = bytearray(w * h)
    for i in range(len(rom)):
        b = rom[i]
        y, xb = divmod(i, bpr)
        for k in range(8):
            v = 255 if (b >> (7 - k)) & 1 else 0
            pix[y * w + xb * 8 + k] = v
    if scale > 1:
        sw, sh = w * scale, h * scale
        sp = bytearray(sw * sh)
        for y in range(h):
            row = pix[y * w:(y + 1) * w]
            big = bytearray()
            for v in row:
                big += bytes([v]) * scale
            for s in range(scale):
                sp[(y * scale + s) * sw:(y * scale + s + 1) * sw] = big
        png_gray(path, sw, sh, sp)
    else:
        png_gray(path, w, h, pix)


def gb_tiles_2bpp(data, path, per_row=16, scale=3, shade=(255, 170, 85, 0)):
    """GB 2bpp tile：每 tile 16 字节，2 字节/行（低位面 + 高位面）。"""
    n = len(data) // 16
    rows = (n + per_row - 1) // per_row
    tw, th = 8 * scale, 8 * scale
    W, H = per_row * tw, rows * th
    pix = bytearray(b"\xff" * (W * H))
    for t in range(n):
        ox, oy = (t % per_row) * tw, (t // per_row) * th
        for r in range(8):
            lo = data[t * 16 + r * 2]
            hi = data[t * 16 + r * 2 + 1]
            for c in range(8):
                bit = ((lo >> (7 - c)) & 1) | (((hi >> (7 - c)) & 1) << 1)
                v = shade[bit]
                for dy in range(scale):
                    base = (oy + r * scale + dy) * W + ox + c * scale
                    pix[base:base + scale] = bytes([v]) * scale
    png_gray(path, W, H, pix)


def main():
    rom = open(os.path.join(INP, "game.gb"), "rb").read()
    print("=== game.gb %d B ===" % len(rom))
    print("-- 头部（正确偏移）--")
    print("  entry  @0100 =", rom[0x100:0x104].hex())
    print("  logo   @0104-0x0133 前16B =", rom[0x104:0x114].hex())
    logo_ok = rom[0x104:0x134] == bytes.fromhex(
        "CEED6666CC0D000B03730083000C000D0008111F8889000EDCCC6EE6DDDDD999"
        "BBBB666E6EDDDDCCCCDDDD88889999BBBB6666")
    print("  任天堂 logo 校验 =", "一致（正版头）" if logo_ok else "不一致")
    title = rom[0x134:0x144]
    print("  title  @0134 =", repr(title), "-> ASCII:", title.split(b"\x00")[0].decode("latin1"))
    print("  cgb    @0143 = %02X" % rom[0x143])
    print("  cart   @0147 = %02X -> %s" % (rom[0x147], CART.get(rom[0x147], "?")))
    print("  romsz  @0148 = %02X -> %s" % (rom[0x148], ROMSZ.get(rom[0x148], "?")))
    print("  ramsz  @0149 = %02X" % rom[0x149])
    print("  ver    @014C = %02X" % rom[0x14C])
    x = 0
    for b in rom[0x134:0x14D]:
        x = (x - b - 1) & 0xFF
    print("  hdr_csum @014D = %02X  复算 = %02X  %s" % (rom[0x14D], x, "一致" if x == rom[0x14D] else "不一致"))
    g = (sum(rom) - rom[0x14E] - rom[0x14F]) & 0xFFFF
    print("  glb_csum @014E = %02X%02X 复算 = %04X  %s"
          % (rom[0x14E], rom[0x14F], g, "一致" if g == (rom[0x14E] << 8 | rom[0x14F]) else "不一致"))

    print("\n-- 0x0100-0x0150 十六进制 --")
    for o in range(0x100, 0x150, 16):
        chunk = rom[o:o + 16]
        print("  %04X  %s  %s" % (o, chunk.hex(" "), "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))

    # bank 使用率
    print("\n-- bank 使用率 --")
    for i in range(len(rom) // 16384):
        blk = rom[i * 16384:(i + 1) * 16384]
        uniq = len(set(blk))
        z = blk.count(0) / len(blk) * 100
        f = blk.count(0xFF) / len(blk) * 100
        print("  bank%d 唯一字节 %3d  0x00 %5.1f%%  0xFF %5.1f%%" % (i, uniq, z, f))

    # 可视化
    rom_as_1bpp(rom, os.path.join(OUT, "rom_1bpp_w16.png"), 16, 2)
    rom_as_1bpp(rom, os.path.join(OUT, "rom_1bpp_w32.png"), 32, 1)
    gb_tiles_2bpp(rom[:0x4000], os.path.join(OUT, "rom_tiles_2bpp.png"), 16, 3)
    print("\n-- 图像已写出 --")
    for f in sorted(os.listdir(OUT)):
        print("  ", os.path.join("img", f), os.path.getsize(os.path.join(OUT, f)), "B")


if __name__ == "__main__":
    main()
