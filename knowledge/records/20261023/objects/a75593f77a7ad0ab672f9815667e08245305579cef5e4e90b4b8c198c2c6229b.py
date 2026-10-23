#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GB ROM 字体表提取 + 内联字符串解码（FlappyPig 这题踩坑后沉淀的通用工具）。

背景（重要，别再踩）：
  1. GB 的 tile 数据基址由 LCDC(0xFF40) bit4 决定：
       bit4 = 1 → 基址 0x8000，tile n 的 VRAM 地址 = 0x8000 + n*16
       bit4 = 0 → 基址 0x8800（有符号寻址），tile n 的地址：
            n <  128 → 0x9000 + n*16
            n >= 128 → 0x8800 + (n-128)*16
     🔴 用错地址会读到全 0 的空白 tile，从而误判"字体没加载"。
  2. **tile index ≠ ASCII**。很多游戏（尤其手写/精简字库）的字体表是自定义顺序。
     必须先把 VRAM 里每个 tile 渲染出来"看一眼"，才能建立 tile → 字符 的映射。
  3. ROM 里 `36 xx`（LD (HL),n）连成一串 = 编译器**内联展开的字符串初始化**。
     把 `36` 后面的立即数字节粗暴收集起来当字符串，得到的**不是数据**，
     而是"指令的立即数" —— 必须把这些值**当 tile index**、再用第 2 步的字体表解码。

用法：
    python gb_font.py glyphs  <rom> [start] [end]     # 渲染 tile 图案（ASCII art）
    python gb_font.py map     <rom>                   # 自动猜 tile→字符 映射
    python gb_font.py decode  <rom> <65,68,76,...>    # 按映射解码一个 tile 序列

依赖：pyboy（pip install --break-system-packages pyboy）
"""
import sys
from pathlib import Path

try:
    from pyboy import PyBoy
except ImportError:
    sys.exit("需要 pyboy： pip install --break-system-packages pyboy")

# 本机常用解释器（带 pyboy）：[USER_HOME]\.workbuddy\binaries\python\envs\default\Scripts\python.exe


def load(rom, frames=240):
    """跑到字体已加载到 VRAM 的稳定状态（标题画面足够）。"""
    pb = PyBoy(str(rom), window="null", sound_emulated=False)
    for _ in range(frames):
        pb.tick()
    return pb


def tiledata(pb, idx):
    lcdc = pb.memory[0xFF40]
    if lcdc & 0x10:
        off = 0x8000 + idx * 16
    else:
        off = (0x9000 + idx * 16) if idx < 128 else (0x8800 + (idx - 128) * 16)
    return bytes(pb.memory[off:off + 16])


def art(td):
    out = []
    for r in range(8):
        b0, b1 = td[r * 2], td[r * 2 + 1]
        out.append("".join(" .oO"[((b0 >> (7 - c)) & 1) | (((b1 >> (7 - c)) & 1) << 1)]
                           for c in range(8)))
    return out


def cmd_glyphs(rom, start=0x41, end=0x80):
    pb = load(rom)
    lcdc = pb.memory[0xFF40]
    print("LCDC=0x%02X  基址模式 = %s" % (lcdc, "0x8000" if lcdc & 0x10 else "0x8800(有符号)"))
    for i in range(start, end):
        d = tiledata(pb, i)
        if not any(d):
            print("tile %3d 0x%02X: (空)" % (i, i))
            continue
        print("tile %3d 0x%02X:" % (i, i))
        for r in art(d):
            print("    |" + r + "|")


def cmd_decode(rom, seq_str):
    """解码。映射表需要自己按 glyphs 的结果填（这里给的是 FlappyPig 实测表）。"""
    MAP = {65: 'P', 66: 'R', 67: 'E', 68: 'S', 69: 'T', 70: 'A',
           71: '.', 72: ':', 73: ';', 74: '#', 75: '#',
           76: '0', 77: '1', 78: '2', 79: '3', 80: '4',
           81: '5', 82: '6', 83: '7', 84: '8', 85: '9',
           86: 'U', 87: 'L', 88: 'B'}
    seq = [int(x, 0) for x in seq_str.replace(" ", "").split(",") if x]
    print("tile 序列   :", seq)
    print("按 ASCII 读 :", "".join(chr(v) if 32 <= v < 127 else '.' for v in seq))
    print("按字体表读  :", "".join(MAP.get(v, '?') for v in seq))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    cmd, rom = sys.argv[1], Path(sys.argv[2])
    if cmd == "glyphs":
        s = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x41
        e = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x80
        cmd_glyphs(rom, s, e)
    elif cmd == "decode":
        cmd_decode(rom, sys.argv[3])
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
