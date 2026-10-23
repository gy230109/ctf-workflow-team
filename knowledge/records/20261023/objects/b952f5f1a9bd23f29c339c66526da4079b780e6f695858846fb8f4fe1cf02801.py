# -*- coding: utf-8 -*-
"""跑到 GAME OVER / RESULT 画面，逐帧 ASCII 快照，找隐藏串。
用法: python run_to_over.py <rom> [frames] [outdir]
"""
import sys, os
from pyboy import PyBoy

rom = sys.argv[1]
N   = int(sys.argv[2]) if len(sys.argv) > 2 else 7000
OUT = sys.argv[3] if len(sys.argv) > 3 else "shots"

os.makedirs(OUT, exist_ok=True)
pb = PyBoy(rom, window="null", sound_emulated=False)
pb.set_emulation_speed(0)

CH = " .oO"
def screen_txt():
    a = pb.screen.ndarray
    h, w = a.shape[0], a.shape[1]
    # 每 8x8 取中心像素 -> 32x20 网格
    lines = []
    for ty in range(h // 8):
        row = []
        for tx in range(w // 8):
            px = a[ty*8+4, tx*8+4]
            if isinstance(px, (list, tuple)) or hasattr(px, "__len__"):
                v = int(px[0])
            else:
                v = int(px)
            row.append(CH[min(3, v // 64)])
        lines.append("".join(row))
    return lines

# BG map 原始 tile index（最可靠）
def bgmap():
    m = pb.memory[0x9800:0x9C00]
    return list(m)

HID = [0x50,0x44,0x30,0x33,0x52,0x34,0x39,0x55,0x45,0x35,0x37,0x36,0x52,0x34,0x32,0x31,0x52,0x45,0x38]
RES = [0x52,0x43,0x44,0x56,0x57,0x58]  # R E S U L T

hit_hidden = hit_result = None
for f in range(N):
    pb.tick()
    if f % 60 == 0:
        bg = bgmap()
        # 转成 "已加载的 tile 序列" 查是否存在连续子串
        def has(seq):
            L = len(seq)
            return any(bg[i:i+L] == seq for i in range(len(bg)-L))
        if HID and has(HID) and hit_hidden is None:
            hit_hidden = f
        if has(RES) and hit_result is None:
            hit_result = f
        if f % 600 == 0:
            print("frame %5d  PC=%04X  hidden=%s result=%s" % (f, pb.register_file.PC, hit_hidden, hit_result))
        if hit_hidden is not None:
            print("!! 第 %d 帧 BG 图上出现隐藏串 tile 序列" % f)
            break

tx = screen_txt()
print("\n=== frame %d  PC=%04X ===" % (pb.frame_count, pb.register_file.PC))
for l in tx:
    print("|" + l + "|")
print("\nhidden_first_frame =", hit_hidden, " result_first_frame =", hit_result)
pr = os.path.join(OUT, os.path.basename(rom).replace(".gb","") + "_final.png")
pb.screen.image.save(pr)
print("saved", pr)
