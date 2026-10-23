from PIL import Image
import numpy as np

d = open(r'd:\Temp\threebody\threebody.bmp', 'rb').read()
w, h = 580, 435; px = d[138:]
rgba = np.array(Image.frombytes('RGBA', (w, h), px, 'raw', 'BGRA').transpose(Image.FLIP_TOP_BOTTOM))
A = rgba[:, :, 3] & 1
grid = A[153:281, 226:354]  # 128x128

def d2xy(n, d):
    x = y = 0; t = d; s = 1
    while s < (1 << n):
        rx = 1 & (t >> 1)
        ry = 1 & (t ^ rx)
        if ry == 0:
            if rx == 1:
                x = s - 1 - x; y = s - 1 - y
            x, y = y, x
        x += s * rx; y += s * ry
        t >>= 2; s <<= 1
    return x, y

N = 7
path = [d2xy(N, i) for i in range(128 * 128)]

def to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits) // 8 * 8, 8):
        v = 0
        for k in range(8):
            v = (v << 1) | int(bits[i + k])
        out.append(v)
    return bytes(out)

def score(b):
    return sum(32 <= c < 127 for c in b) / len(b)

cands = []
for flipx in (0, 1):
    for flipy in (0, 1):
        for tr in (0, 1):
            g = grid.copy()
            if tr: g = g.T
            if flipx: g = g[:, ::-1]
            if flipy: g = g[::-1, :]
            for inv in (0, 1):
                bits = []
                for (x, y) in path:
                    v = g[127 - y][x]
                    if inv: v ^= 1
                    bits.append(v)
                b = to_bytes(bits)
                cands.append((score(b), (flipx, flipy, tr, inv), b))

cands.sort(reverse=True, key=lambda z: z[0])
for sc, meta, b in cands[:4]:
    print(round(sc, 3), meta, b[:80])

best = cands[0][2]
open(r'd:\Temp\threebody\output.bin', 'wb').write(best)
print('saved output.bin, len', len(best))
print(best[:400])
