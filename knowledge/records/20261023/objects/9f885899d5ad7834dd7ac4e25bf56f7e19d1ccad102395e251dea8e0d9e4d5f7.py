#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 Game Boy 的 BG 图（0x9800）+ 窗口图（0x9C00）整块解码成文字。

踩坑记录（FlappyPig）：
  1. 用"猜 tile 序列"去子串匹配是脆的 —— 我一开始把 ASCII('P'=0x50) 当 tile 索引，
     结果永远匹配不上，得出"没有隐藏串"的**假阴性**。
     正确做法是整块解码，看实际内容。
  2. 字体表必须从**实际字形**建立，不能假设 tile index == ASCII。
  3. tile 数据基址由 LCDC bit4 决定（bit4=0 → 0x8800 有符号寻址）。

用法: python bgtext.py <rom> [frames] [press_start_at]
"""
import sys
from pyboy import PyBoy

FONT = {0x41: 'P', 0x42: 'R', 0x43: 'E', 0x44: 'S', 0x45: 'T', 0x46: 'A',
        0x47: '#', 0x48: '#', 0x49: '#', 0x4A: '#', 0x4B: '#',
        0x4C: '0', 0x4D: '1', 0x4E: '2', 0x4F: '3', 0x50: '4', 0x51: '5',
        0x52: '6', 0x53: '7', 0x54: '8', 0x55: '9',
        0x56: 'U', 0x57: 'L', 0x58: 'B'}


def decode_block(mem, base, w=32, h=18, rows=None):
    out = []
    for y in range(h):
        line = []
        for x in range(w):
            t = mem[base + y * w + x]
            line.append(FONT.get(t, ' ' if t == 0 or t not in FONT else '.'))
        out.append("".join(line))
    return out


def main():
    rom = sys.argv[1]
    N = int(sys.argv[2]) if len(sys.argv) > 2 else 6000
    START = int(sys.argv[3]) if len(sys.argv) > 3 else 120
    pb = PyBoy(rom, window="null", sound_emulated=False)
    pb.set_emulation_speed(0)
    seen = {}
    for f in range(N):
        pb.tick()
        if f == START:
            pb.button_press("start"); pb.tick(); pb.button_release("start")
        # 简易 bot：屏幕上半就停手，下半就拍翅膀
        if f > START and f % 8 == 0:
            # 从 OAM 取猪的 Y（sprite0=猪的左上角）
            y = pb.memory[0xFE00]
            if 30 <= y <= 110:
                pb.button_press("a"); pb.tick(); pb.button_release("a")
        if f % 30 == 0:
            bg = decode_block(pb.memory, 0x9800)
            win = decode_block(pb.memory, 0x9C00)
            txt = "\n".join(bg) + "\n---WIN---\n" + "\n".join(win)
            key = txt.replace(" ", "").replace("\n", "").replace("-WIN-", "")
            if key and key not in seen:
                seen[key] = f
                print("### f%d  PC=%04X" % (f, pb.register_file.PC))
                for l in bg:
                    if l.strip():
                        print("  BG |" + l + "|")
                for l in win:
                    if l.strip():
                        print("  WN |" + l + "|")
    print("\n共 %d 个不同画面" % len(seen))


if __name__ == "__main__":
    main()
