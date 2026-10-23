# -*- coding: utf-8 -*-
"""模拟玩家：按 start 后周期性按 A 拍翅膀，看能走到哪个画面。
用法: python play2.py <rom> <outdir> <tap_every>
"""
import sys, os, hashlib
from pyboy import PyBoy
rom, OUT = sys.argv[1], sys.argv[2]
TAP = int(sys.argv[3]) if len(sys.argv) > 3 else 0   # 0=不再按A，让它掉下去
os.makedirs(OUT, exist_ok=True)
tag = os.path.basename(rom).replace(".gb","")
pb = PyBoy(rom, window="null", sound_emulated=False); pb.set_emulation_speed(0)

def bgm(): return list(pb.memory[0x9800:0x9C00])
def has(seq, bg):
    L=len(seq); return any(bg[i:i+L]==seq for i in range(len(bg)-L+1))
RES=[0x52,0x43,0x44,0x56,0x57,0x58]
HID=[0x50,0x44,0x30,0x33,0x52,0x34,0x39,0x55,0x45,0x35,0x37,0x36,0x52,0x34,0x32,0x31,0x52,0x45,0x38]

seqs = {"RESULT":RES, "HIDDEN":HID}
last=None; found={}
for f in range(9000):
    pb.tick()
    if f==120:
        pb.button_press("start"); pb.tick(); pb.button_release("start")
    if f==200:
        pb.button_press("a"); pb.tick(); pb.button_release("a")
    if TAP and f>200 and f%TAP==0:
        pb.button_press("a"); pb.tick(); pb.button_release("a")
    if f%20==0:
        a=pb.screen.ndarray
        h=hashlib.md5(a.tobytes()).hexdigest()[:8]
        bg=bgm()
        for name,sq in seqs.items():
            if has(sq,bg) and name not in found:
                found[name]=f
                p=os.path.join(OUT,"%s_f%05d_%s.png"%(tag,f,name)); pb.screen.image.save(p)
                print("  ** %s 首次出现 @f%d  已存 %s"%(name,f,os.path.basename(p)))
        if h!=last:
            print("f%-6d %s PC=%04X"%(f,h,pb.register_file.PC))
            last=h
print("found:",found)
p=os.path.join(OUT,"%s_last.png"%tag); pb.screen.image.save(p); print("last ->",p)
