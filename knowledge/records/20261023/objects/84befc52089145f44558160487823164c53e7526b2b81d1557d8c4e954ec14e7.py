# -*- coding: utf-8 -*-
"""真正玩一遍：按 start 进游戏 -> 不操作让它撞死 -> 到结算画面，全程存档快照。
用法: python play.py <rom> <outdir> [maxframes]
"""
import sys, os, hashlib
from pyboy import PyBoy

rom, OUT = sys.argv[1], sys.argv[2]
NMAX = int(sys.argv[3]) if len(sys.argv) > 3 else 20000
os.makedirs(OUT, exist_ok=True)
tag = os.path.basename(rom).replace(".gb", "")

pb = PyBoy(rom, window="null", sound_emulated=False)
pb.set_emulation_speed(0)

def bgmap():
    return list(pb.memory[0x9800:0x9C00])

def has(seq, bg=None):
    bg = bg if bg is not None else bgmap()
    L = len(seq)
    return any(bg[i:i+L] == seq for i in range(len(bg)-L+1))

RES = [0x52,0x43,0x44,0x56,0x57,0x58]                                        # R E S U L T
HID = [0x50,0x44,0x30,0x33,0x52,0x34,0x39,0x55,0x45,0x35,0x37,0x36,0x52,0x34,0x32,0x31,0x52,0x45,0x38]

def snap(name):
    p = os.path.join(OUT, "%s_%s.png" % (tag, name))
    pb.screen.image.save(p)
    a = pb.screen.ndarray
    print("   snap %-14s -> %s   shape=%s max=%s" % (name, os.path.basename(p), a.shape, a.max()))
    return p

last = None
states = []
for f in range(NMAX):
    pb.tick()
    if f == 120:
        print("press START @f120  PC=%04X" % pb.register_file.PC)
        pb.button_press("start"); pb.tick(); pb.button_release("start")
    if f % 30 == 0:
        a = pb.screen.ndarray
        h = hashlib.md5(a.tobytes()).hexdigest()[:8]
        bg = bgmap()
        r, hid = has(RES, bg), has(HID, bg)
        if h != last or r or hid:
            pc = pb.register_file.PC
            print("f%-6d %s PC=%04X  RESULT=%s HIDDEN=%s" % (f, h, pc, r, hid))
            states.append((f, pc, r, hid))
            if r or hid:
                snap("f%05d_%s" % (f, "HID" if hid else "RES"))
            last = h

print("\n=== 状态轨迹 ===")
for s in states:
    print("  f%-6d PC=%04X RESULT=%-5s HIDDEN=%s" % s)
print("\nsaved snapshots in", OUT)
