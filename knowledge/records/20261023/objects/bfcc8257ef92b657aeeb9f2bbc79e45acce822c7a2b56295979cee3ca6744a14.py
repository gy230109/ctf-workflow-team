#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sharp LR35902 (Game Boy) 反汇编器 —— 单文件、无依赖。

沉淀原因：这次 FlappyPig 题里我靠"扫 36 xx 立即数"猜字符串，反复猜错；
    正确做法是先拿到**指令边界**，再取 LD (HL),n 的立即数。
    另外 GB 汇编里大量出现 SDCC 的固定 idioms（2B 5E 23 56 = 从 (HL) 载入 16 位），
    靠肉眼看 hex 极易看错。

用法：
    python gbdis.py <rom> <start> [count]        # 从 start 反汇编 count 条
    python gbdis.py <rom> find <hexbytes>        # 搜索字节序列
    python gbdis.py <rom> xref <addr>            # 找所有 CALL/JP 到 addr 的位置
    python gbdis.py <rom> strs <cluster>         # 提取 "36 nn" 内联字符串簇并解码
"""
import sys

# 8 位立即数的助记符（opcode -> mnemonic）
R = {
    0x00: "NOP", 0x02: "LD (BC),A", 0x03: "INC BC", 0x04: "INC B", 0x05: "DEC B",
    0x06: "LD B,%n", 0x07: "RLCA", 0x08: "LD (%w),SP", 0x09: "ADD HL,BC", 0x0A: "LD A,(BC)",
    0x0B: "DEC BC", 0x0C: "INC C", 0x0D: "DEC C", 0x0E: "LD C,%n", 0x0F: "RRCA",
    0x10: "STOP", 0x11: "LD DE,%w", 0x12: "LD (DE),A", 0x13: "INC DE", 0x14: "INC D",
    0x15: "DEC D", 0x16: "LD D,%n", 0x17: "RLA", 0x18: "JR %r", 0x19: "ADD HL,DE",
    0x1A: "LD A,(DE)", 0x1B: "DEC DE", 0x1C: "INC E", 0x1D: "DEC E", 0x1E: "LD E,%n",
    0x1F: "RRA",
    0x20: "JR NZ,%r", 0x21: "LD HL,%w", 0x22: "LD (HL+),A", 0x23: "INC HL",
    0x24: "INC H", 0x25: "DEC H", 0x26: "LD H,%n", 0x27: "DAA", 0x28: "JR Z,%r",
    0x29: "ADD HL,HL", 0x2A: "LD A,(HL+)", 0x2B: "DEC HL", 0x2C: "INC L",
    0x2D: "DEC L", 0x2E: "LD L,%n", 0x2F: "CPL",
    0x30: "JR NC,%r", 0x31: "LD SP,%w", 0x32: "LD (HL-),A", 0x33: "INC SP",
    0x34: "INC (HL)", 0x35: "DEC (HL)", 0x36: "LD (HL),%n", 0x37: "SCF",
    0x38: "JR C,%r", 0x39: "ADD HL,SP", 0x3A: "LD A,(HL-)", 0x3B: "DEC SP",
    0x3C: "INC A", 0x3D: "DEC A", 0x3E: "LD A,%n", 0x3F: "CCF",
}
R.update({
    0x40: "LD B,B", 0x41: "LD B,C", 0x42: "LD B,D", 0x43: "LD B,E", 0x44: "LD B,H",
    0x45: "LD B,L", 0x46: "LD B,(HL)", 0x47: "LD B,A", 0x48: "LD C,B", 0x49: "LD C,C",
    0x4A: "LD C,D", 0x4B: "LD C,E", 0x4C: "LD C,H", 0x4D: "LD C,L", 0x4E: "LD C,(HL)",
    0x4F: "LD C,A",
    0x50: "LD D,B", 0x51: "LD D,C", 0x52: "LD D,D", 0x53: "LD D,E", 0x54: "LD D,H",
    0x55: "LD D,L", 0x56: "LD D,(HL)", 0x57: "LD D,A", 0x58: "LD E,B", 0x59: "LD E,C",
    0x5A: "LD E,D", 0x5B: "LD E,E", 0x5C: "LD E,H", 0x5D: "LD E,L", 0x5E: "LD E,(HL)",
    0x5F: "LD E,A",
    0x60: "LD H,B", 0x61: "LD H,C", 0x62: "LD H,D", 0x63: "LD H,E", 0x64: "LD H,H",
    0x65: "LD H,L", 0x66: "LD H,(HL)", 0x67: "LD H,A", 0x68: "LD L,B", 0x69: "LD L,C",
    0x6A: "LD L,D", 0x6B: "LD L,E", 0x6C: "LD L,H", 0x6D: "LD L,L", 0x6E: "LD L,(HL)",
    0x6F: "LD L,A",
    0x70: "LD (HL),B", 0x71: "LD (HL),C", 0x72: "LD (HL),D", 0x73: "LD (HL),E",
    0x74: "LD (HL),H", 0x75: "LD (HL),L", 0x76: "HALT", 0x77: "LD (HL),A",
    0x78: "LD A,B", 0x79: "LD A,C", 0x7A: "LD A,D", 0x7B: "LD A,E", 0x7C: "LD A,H",
    0x7D: "LD A,L", 0x7E: "LD A,(HL)", 0x7F: "LD A,A",
})
ALU = ["ADD A,", "ADC A,", "SUB ", "SBC A,", "AND ", "XOR ", "OR ", "CP "]
SRC = ["B", "C", "D", "E", "H", "L", "(HL)", "A"]
for i in range(8):
    for j in range(8):
        R[0x80 + i * 8 + j] = ALU[i] + SRC[j]
for cc, nm in enumerate(["NZ", "Z", "NC", "C"]):
    R[0xC0 + cc * 8] = "RET " + nm
    R[0xC2 + cc * 8] = "JP " + nm + ",%w"
    R[0xC4 + cc * 8] = "CALL " + nm + ",%w"
    R[0xC7 + cc * 8] = "RST %02Xh" % (cc * 8)
R.update({
    0xC1: "POP BC", 0xC3: "JP %w", 0xC5: "PUSH BC", 0xC6: "ADD A,%n",
    0xC8: "RET Z", 0xC9: "RET", 0xCA: "JP Z,%w", 0xCB: "PREFIX CB",
    0xCC: "CALL Z,%w", 0xCD: "CALL %w", 0xCE: "ADC A,%n", 0xCF: "RST 08h",
    0xD1: "POP DE", 0xD2: "JP NC,%w", 0xD5: "PUSH DE", 0xD6: "SUB %n",
    0xD9: "RETI", 0xDA: "JP C,%w", 0xDC: "CALL C,%w", 0xDE: "SBC A,%n",
    0xE0: "LDH (%n),A", 0xE1: "POP HL", 0xE2: "LD (C),A", 0xE5: "PUSH HL",
    0xE6: "AND %n", 0xE7: "RST 20h", 0xE8: "ADD SP,%n", 0xE9: "JP HL",
    0xEA: "LD (%w),A", 0xEE: "XOR %n", 0xEF: "RST 28h",
    0xF0: "LDH A,(%n)", 0xF1: "POP AF", 0xF2: "LD A,(C)", 0xF3: "DI",
    0xF5: "PUSH AF", 0xF6: "OR %n", 0xF7: "RST 30h", 0xF8: "LD HL,SP+%s",
    0xF9: "LD SP,HL", 0xFA: "LD A,(%w)", 0xFB: "EI", 0xFE: "CP %n", 0xFF: "RST 38h",
})
# 条件 RET 的正确编码：C0/C8/D0/D8 = RET NZ/Z/NC/C（已由上面的通用表覆盖）
# 下面这行曾写错成 R[0xD0+cc*8] / R[0xD8+cc*8]，把 E0-EF 段覆盖成 RET，导致 E8 被解成 1 字节指令。
for cc, nm in enumerate(["NZ", "Z", "NC", "C"]):
    R[0xC0 + cc * 8] = "RET " + nm
R[0xD9] = "RETI"
# CB 前缀
CB = ["CB %02Xh" % i for i in range(256)]
for i in range(8):
    CB[i * 8 + 0] = "RLC " + SRC[i]
    CB[i * 8 + 1] = "RRC " + SRC[i]
    CB[i * 8 + 2] = "RL " + SRC[i]
    CB[i * 8 + 3] = "RR " + SRC[i]
    CB[i * 8 + 4] = "SLA " + SRC[i]
    CB[i * 8 + 5] = "SRA " + SRC[i]
    CB[i * 8 + 6] = "SWAP " + SRC[i]
    CB[i * 8 + 7] = "SRL " + SRC[i]
for i in range(8):
    for j in range(8):
        CB[0x40 + i * 8 + j] = "BIT %d,%s" % (i, SRC[j])
        CB[0x80 + i * 8 + j] = "RES %d,%s" % (i, SRC[j])
        CB[0xC0 + i * 8 + j] = "SET %d,%s" % (i, SRC[j])


def fmt(rom, pc):
    """返回 (助记符, 字节长度, 目标地址或None)"""
    op = rom[pc]
    if op == 0xCB:
        return CB[rom[pc + 1]], 2, None
    m = R.get(op)
    if m is None:
        return "DB %02Xh" % op, 1, None
    if "%w" in m:
        v = rom[pc + 1] | (rom[pc + 2] << 8)
        return m.replace("%w", "%04Xh" % v), 3, v
    if "%n" in m:
        return m.replace("%n", "%02Xh" % rom[pc + 1]), 2, None
    if "%s" in m:
        e = rom[pc + 1]
        e = e - 256 if e > 127 else e
        return m.replace("%s", "%+d" % e), 2, None
    if "%r" in m:
        e = rom[pc + 1]
        e = e - 256 if e > 127 else e
        return m.replace("%r", "%04Xh" % ((pc + 2 + e) & 0xFFFF)), 2, (pc + 2 + e) & 0xFFFF
    return m, 1, None


def main():
    rom = open(sys.argv[1], "rb").read()
    if len(sys.argv) > 2 and sys.argv[2] == "find":
        pat = bytes.fromhex(sys.argv[3])
        i = rom.find(pat)
        while i >= 0:
            print("  %04X" % i)
            i = rom.find(pat, i + 1)
        return
    if len(sys.argv) > 2 and sys.argv[2] == "xref":
        tgt = int(sys.argv[3], 0)
        for i in range(len(rom) - 2):
            if rom[i] in (0xC3, 0xC2, 0xCA, 0xD2, 0xDA, 0xCD, 0xC4, 0xCC, 0xD4, 0xDC):
                if (rom[i + 1] | (rom[i + 2] << 8)) == tgt:
                    print("  %04X  %s" % (i, fmt(rom, i)[0]))
        return
    pc = int(sys.argv[2], 0)
    cnt = int(sys.argv[3]) if len(sys.argv) > 3 else 40
    for _ in range(cnt):
        txt, ln, _ = fmt(rom, pc)
        raw = " ".join("%02X" % b for b in rom[pc:pc + ln])
        print("%04X  %-12s %s" % (pc, raw, txt))
        pc += ln


if __name__ == "__main__":
    main()
