# -*- coding: utf-8 -*-
"""第 0 级侦察：Game Boy ROM 头 + 字符串 + MP3 结构。
纯本地、确定性、秒级。不猜结论，只输出事实。
"""
import os
import re
import sys
from pathlib import Path

BASE = Path(os.environ.get("GB_CASE",
                           r"[CTF_ROOT]\战例库\比赛-GameBoy")) / "input"

GB = BASE / "game.gb"
MPS = ["kun.mp3", "man.mp3"]

# GB 头域: (偏移, 长度, 名称)
GBHDR = [
    (0x0100, 4, "entry_point"),
    (0x0104, 16, "title"),
    (0x013F, 4, "manufacturer"),
    (0x0143, 1, "cgb_flag"),
    (0x0144, 2, "new_licensee"),
    (0x0146, 1, "sgb_flag"),
    (0x0147, 1, "cart_type"),
    (0x0148, 1, "rom_size"),
    (0x0149, 1, "ram_size"),
    (0x014A, 1, "dest_code"),
    (0x014B, 1, "old_licensee"),
    (0x014C, 1, "version"),
    (0x014D, 1, "header_csum"),
    (0x014E, 2, "global_csum"),
]
CART = {0x00: "ROM ONLY", 0x01: "MBC1", 0x02: "MBC1+RAM", 0x03: "MBC1+RAM+BAT",
        0x05: "MBC2", 0x06: "MBC2+BAT", 0x08: "ROM+RAM", 0x09: "ROM+RAM+BAT",
        0x0B: "MMM01", 0x0F: "MBC3+TIMER+BAT", 0x10: "MBC3+TIMER+RAM+BAT",
        0x11: "MBC3", 0x13: "MBC3+RAM+BAT", 0x19: "MBC5", 0x1B: "MBC5+RAM+BAT",
        0x1C: "MBC5+RUMBLE", 0x1E: "MBC5+RUMBLE+RAM+BAT"}
ROMSZ = {0x00: "32KB(2 bank)", 0x01: "64KB", 0x02: "128KB", 0x03: "256KB",
         0x04: "512KB", 0x05: "1MB", 0x06: "2MB", 0x07: "4MB", 0x08: "8MB"}


def recon_gb() -> None:
    d = GB.read_bytes()
    print("=== game.gb (%d B) ===" % len(d))
    print("  -- 头部 --")
    for off, ln, name in GBHDR:
        raw = d[off:off + ln]
        val = int.from_bytes(raw, "little")
        txt = raw.decode("ascii", "replace").replace("\x00", ".")
        extra = ""
        if name == "cart_type":
            extra = " -> " + CART.get(val, "?")
        if name == "rom_size":
            extra = " -> " + ROMSZ.get(val, "?")
        print("    %-14s @%04X = %-18r (int %d)%s" % (name, off, txt, val, extra))

    # 头校验和复算（0x014D）
    chk = 0
    for i in range(0x0134, 0x014D):
        chk = (chk - d[i] - 1) & 0xFF
    print("    头校验复算 = %02X（文件里是 %02X）%s"
          % (chk, d[0x014D], "一致" if chk == d[0x014D] else "**不一致**"))

    print("  -- ASCII 字符串（>=5）--")
    hits = [(m.start(), m.group().decode("ascii"))
            for m in re.finditer(rb"[\x20-\x7e]{5,}", d)]
    print("    共 %d 条" % len(hits))
    for off, s in hits[:80]:
        print("      @%04X  %r" % (off, s))

    # 可疑关键词
    print("  -- 关键词扫描 --")
    for kw in [b"flag", b"FLAG", b"{", b"}", b"CTF", b"ctf", b"key", b"KEY",
               b"pass", b"PASS", b"secret", b"answ", b"true", b"win"]:
        locs = [m.start() for m in re.finditer(re.escape(kw), d)]
        if locs:
            print("    %-8r x%-3d 首次 @%04X" % (kw, len(locs), locs[0]))

    # 32KB = 2 bank：看 bank 1 是否与 bank 0 相似（是否只是一遍空白）
    print("  -- 分 bank 统计（每 16KB）--")
    for b in range(len(d) // 0x4000):
        seg = d[b * 0x4000:(b + 1) * 0x4000]
        uniq = len(set(seg))
        zero = seg.count(0)
        ff = seg.count(0xFF)
        print("    bank %d: 唯一字节 %3d, 0x00 %5d(%.0f%%), 0xFF %5d(%.0f%%)"
              % (b, uniq, zero, 100 * zero / len(seg), ff, 100 * ff / len(seg)))


def recon_mp3(name: str) -> None:
    p = BASE / name
    d = p.read_bytes()
    print()
    print("=== %s (%d B) ===" % (name, len(d)))
    print("  头 16 字节: %s" % d[:16].hex(" "))
    id3 = d[:3] == b"ID3"
    print("  ID3v2: %s" % ("有" if id3 else "无"))
    if id3:
        ver, flags, size = d[3], d[4], int.from_bytes(d[6:10], "big")
        print("    版本 2.%d  flags %02X  声明大小 %d" % (ver, flags, size))
        total = 10 + size + (10 if flags & 0x10 else 0)
        print("    ID3 区结束 @%d" % total)
        tag = d[10:10 + size]
        print("  标签内 ASCII 片段:")
        for m in list(re.finditer(rb"[\x20-\x7e]{4,}", tag))[:25]:
            print("      %r" % m.group())

    # 找 MPEG 帧头（FFEx / FFFx）
    off = 0
    frames = []
    while off < len(d) - 4 and len(frames) < 3:
        if d[off] == 0xFF and (d[off + 1] & 0xE0) == 0xE0:
            frames.append(off)
            if len(frames) == 1:
                # 解析第一帧算出长度，据此跳
                h = int.from_bytes(d[off:off + 4], "big")
                ver = (h >> 19) & 0x3
                layer = (h >> 17) & 0x3
                brate = (h >> 12) & 0xF
                srate = (h >> 10) & 0x3
                pad = (h >> 9) & 0x1
                br = {1: {1: 32, 2: 32, 3: 32}, 2: {}, 3: {}, 0: {}}  # 简化
                print("  首个帧头 @%d: ver=%d layer=%d bitrate_idx=%d srate_idx=%d pad=%d"
                      % (off, ver, layer, brate, srate, pad))
                off += 4
                continue
        off += 1
    print("  前几个帧头偏移: %s" % frames)

    # 尾部：找 MP3 之后的附加数据（stego 常见手法）
    print("  尾部 64 字节: %s" % d[-64:].hex(" "))
    tail = d[-64:]
    print("  尾 ASCII: %r" % re.sub(rb"[^\x20-\x7e]", b".", tail))
    # 扫全文件的非音频可疑段：连续可打印长串
    print("  文件内 >=16 长可打印串（前 20 条）:")
    n = 0
    for m in re.finditer(rb"[\x20-\x7e]{16,}", d):
        print("     @%-9d %r" % (m.start(), m.group()[:70]))
        n += 1
        if n >= 20:
            break
    if n == 0:
        print("     （无）")


def main() -> int:
    if not GB.exists():
        print("找不到", GB)
        return 1
    recon_gb()
    for n in MPS:
        if (BASE / n).exists():
            recon_mp3(n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
