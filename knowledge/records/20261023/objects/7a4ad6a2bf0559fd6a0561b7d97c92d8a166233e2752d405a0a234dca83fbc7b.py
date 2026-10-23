# -*- coding: utf-8 -*-
import sys, os
from pyboy import PyBoy
rom, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
AT = [int(x) for x in sys.argv[3].split(",")]
tag = os.path.basename(rom).replace(".gb","")
pb = PyBoy(rom, window="null", sound_emulated=False); pb.set_emulation_speed(0)
want = sorted(AT); i = 0
for f in range(max(AT)+1):
    pb.tick()
    if f == 120:
        pb.button_press("start"); pb.tick(); pb.button_release("start")
    if i < len(want) and f == want[i]:
        p = os.path.join(OUT, "%s_f%05d.png" % (tag, f))
        pb.screen.image.save(p)
        print("f%-6d PC=%04X -> %s" % (f, pb.register_file.PC, os.path.basename(p)))
        i += 1
