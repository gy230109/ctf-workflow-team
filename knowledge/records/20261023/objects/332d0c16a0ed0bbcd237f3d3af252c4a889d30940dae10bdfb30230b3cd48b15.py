#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地 pyboy 跑 game.gb：抓关键帧 + 读 tilemap/分数，用于独立验证。"""
import os, sys, json
from pathlib import Path
import numpy as np
from pyboy import PyBoy

BASE = Path(__file__).resolve().parent.parent
ROM = str(BASE / "input" / "game.gb")
OUT = BASE / "work" / "emu"
OUT.mkdir(parents=True, exist_ok=True)


def shot(pb, name, scale=3):
    a = pb.screen.ndarray[:, :, :3].astype(np.uint8)
    if scale > 1:
        a = np.repeat(np.repeat(a, scale, axis=0), scale, axis=1)
    try:
        from PIL import Image
        Image.fromarray(a).save(OUT / (name + ".png"))
    except Exception as e:
        np.save(OUT / (name + ".npy"), a)
        print("  (PIL 不可用，存 npy)", e)
    return a


def main():
    pb = PyBoy(ROM, window="null", sound_emulated=False, cgb=False)
    log = []
    # 先跑 600 帧（约 10 s）到标题
    for i in range(600):
        pb.tick()
    shot(pb, "01_title")
    log.append({"frame": 600, "note": "title"})

    # 按 START 进游戏
    pb.button_press("start")
    for i in range(30):
        pb.tick()
    pb.button_release("start")
    for i in range(120):
        pb.tick()
    shot(pb, "02_after_start")
    log.append({"frame": 750, "note": "after start"})

    # 读 BG tilemap（0x9800 / 0x9C00）与 OAM
    try:
        tm1 = pb.memory[0x9800:0x9C00]
        tm2 = pb.memory[0x9C00:0xA000]
        print("tilemap 0x9800 唯一值:", sorted(set(tm1))[:40])
        print("tilemap 0x9C00 唯一值:", sorted(set(tm2))[:40])
    except Exception as e:
        print("mem read err", e)

    # LCDC / SCY / SCX
    for addr, name in ((0xFF40, "LCDC"), (0xFF42, "SCY"), (0xFF43, "SCX"),
                       (0xFF44, "LY"), (0xFF47, "BGP")):
        try:
            print("%s = %02X" % (name, pb.memory[addr]))
        except Exception:
            pass

    # 连续 900 帧空转（不操作，看坠机/结束画面）
    for i in range(900):
        pb.tick()
    shot(pb, "03_idle_900")
    log.append({"frame": 1650, "note": "idle"})

    # 自动拍翅膀玩一段
    for i in range(1800):
        if i % 14 == 0:
            pb.button_press("a"); pb.tick(); pb.button_release("a")
        else:
            pb.tick()
    shot(pb, "04_autoplay")
    log.append({"frame": 3450, "note": "autoplay"})

    (OUT / "frames.json").write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")
    print("输出:", sorted(p.name for p in OUT.iterdir()))
    pb.stop(save=False)


if __name__ == "__main__":
    main()
