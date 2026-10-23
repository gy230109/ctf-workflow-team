# -*- coding: utf-8 -*-
"""QWB2022 GameMaster —— 在 Kali 上从【原始附件】独立复现并验证 flag。

自我约束：
  * 只用 Python 标准库 + openssl CLI（Kali 上没有 z3 / pycryptodome / dn.py）
  * 全链路自跑：XOR 0x22 → AES-128-ECB(nopad) → NRBF → 切内嵌 PE → 取 arr19/arr40
    → 纯 Python 整数跑 Check1 → 断言 == arr40 → 派生 flag
  * 输入来自 $CTF_INPUT_DIR（桥接上传并校验过 SHA256 的原始附件）

唯一一处"引用而非重算"：arr19 / arr40 的文件偏移（0xfbc / 0xfd4）来自 Windows 侧
`tools/fld.py` 对 FieldRVA 表的解析。脚本里用 3 条软校验兜底（见 step 07）。

报告写到 $CTF_WORK_DIR/kali_verify_report.json，供 `kali.ps1 fetch` 回收。
"""
import os, sys, json, struct, hashlib, subprocess, shutil

IN = os.environ.get('CTF_INPUT_DIR', '.')
WRK = os.environ.get('CTF_WORK_DIR', '.')
M = 0xFFFFFFFFFFFFFFFF

R, fail = [], []


def log(name, ok, **kw):
    R.append(dict(step=name, ok=bool(ok), **kw))
    print('%-4s %-18s %s' % ('OK' if ok else 'FAIL', name,
                             '  '.join('%s=%s' % (k, v) for k, v in kw.items())), flush=True)
    if not ok:
        fail.append(name)


# ---------------------------------------------------------------- 00 定位附件
src = None
for f in sorted(os.listdir(IN)):
    p = os.path.join(IN, f)
    if os.path.isfile(p) and os.path.getsize(p) == 11344:
        src = p
        break
log('00_locate_input', src is not None,
    file=os.path.basename(src) if src else None, size=11344 if src else None)
if not src:
    open(os.path.join(WRK, 'kali_verify_report.json'), 'w').write(json.dumps(R, ensure_ascii=False, indent=2))
    sys.exit(2)

raw = open(src, 'rb').read()
log('01_input_sha256', True, sha256=hashlib.sha256(raw).hexdigest())

# ---------------------------------------------------------------- 02 分诊
from collections import Counter
blocks = [raw[i:i + 16] for i in range(0, len(raw) - 15, 16)]
c = Counter(blocks)
dups = [(i, c[b]) for i, b in enumerate(blocks) if c[b] > 1]
log('02_triage', (len(raw) % 16 == 0) and len(dups) > 0,
    total_blocks=len(blocks), mod16=len(raw) % 16, unique_blocks=len(c),
    dup_first=dups[:5], mode='ECB' if dups else '?')

# ---------------------------------------------------------------- 03 XOR 0x22
x = bytes(b ^ 0x22 for b in raw)
px = os.path.join(WRK, 'x22.bin')
open(px, 'wb').write(x)
log('03_xor_0x22', True, out='work/x22.bin', head=x[:16].hex())

# ---------------------------------------------------------------- 04 AES-128-ECB
ossl = shutil.which('openssl')
if not ossl:
    log('04_aes_ecb_zeros', False, err='openssl not found')
    pt = b''
else:
    KEY = '427261696e73746f726d696e67212121'          # "Brainstorming!!!"
    r = subprocess.run([ossl, 'enc', '-d', '-aes-128-ecb', '-K', KEY, '-nopad', '-in', px],
                       capture_output=True)
    pt = r.stdout
    NRBF = bytes.fromhex('0001000000ffffffff')
    log('04_aes_ecb_zeros', pt[:9] == NRBF,
        tool='openssl', key_ascii='Brainstorming!!!', out_len=len(pt),
        head=pt[:16].hex(), nrbf_header_ok=(pt[:9] == NRBF),
        stderr=r.stderr.decode('utf-8', 'replace').strip()[:120])

# ---------------------------------------------------------------- 05 切内嵌 PE
mz = pt.find(b'MZ')
asm = b''
if mz < 0:
    log('05_embedded_pe', False, err='no MZ in plaintext')
else:
    e = struct.unpack_from('<I', pt, mz + 0x3c)[0]
    if pt[mz + e:mz + e + 4] != b'PE\x00\x00':
        log('05_embedded_pe', False, err='MZ but not PE', e_lfanew=hex(e))
    else:
        nsec = struct.unpack_from('<H', pt, mz + e + 6)[0]
        optsz = struct.unpack_from('<H', pt, mz + e + 20)[0]
        so = mz + e + 24 + optsz
        end = 0
        for i in range(nsec):
            rs, ro = struct.unpack_from('<II', pt, so + i * 40 + 16)
            end = max(end, ro + rs)
        asm = pt[mz:mz + end]
        log('05_embedded_pe', len(asm) == 5632, offset=mz, pe_sections=nsec,
            size=len(asm), sha256=hashlib.sha256(asm).hexdigest()[:16])

# ---------------------------------------------------------------- 06 取常量
OFF19, OFF40 = 0xfbc, 0xfd4
arr19 = asm[OFF19:OFF19 + 19] if len(asm) >= OFF19 + 19 else b''
arr40 = asm[OFF40:OFF40 + 40] if len(asm) >= OFF40 + 40 else b''

# 软校验：① 两段都在文件内 ② 中间 5 字节是 0（InitializeArray 静态块的 8 字节对齐）
#         ③ 两段都不是低熵垃圾（至少 12 个不同字节值）
pad = asm[OFF19 + 19:OFF40] if len(asm) >= OFF40 else b''
ok_off = (len(arr19) == 19 and len(arr40) == 40
          and len(set(arr19)) >= 12 and len(set(arr40)) >= 12
          and pad == b'\x00' * len(pad) and len(pad) == 5)
log('06_static_arrays', ok_off,
    arr19_off=hex(OFF19), arr19=arr19.hex(),
    arr40_off=hex(OFF40), arr40_head=arr40[:16].hex(),
    gap_bytes=len(pad), gap_all_zero=(pad == b'\x00' * len(pad)),
    note='offsets from Windows-side FieldRVA parse; content re-read here')

# ---------------------------------------------------------------- 07 Check1（纯整数）
def check1(a, b, c, nbits=320):
    x, y, z = a, b, c
    ks = bytearray(nbits // 8)
    num = -1
    for i in range(nbits):
        x = (((x >> 29) ^ (x >> 28) ^ (x >> 25) ^ (x >> 23)) & 1) | ((x << 1) & M)
        y = (((y >> 30) ^ (y >> 27)) & 1) | ((y << 1) & M)
        z = (((z >> 31) ^ (z >> 30) ^ (z >> 29) ^ (z >> 28) ^ (z >> 26) ^ (z >> 24)) & 1) | ((z << 1) & M)
        if i % 8 == 0:
            num += 1
        X1, X2, X3 = (z >> 32) & 1, (x >> 30) & 1, (y >> 31) & 1
        ks[num] = ((ks[num] << 1) | ((X1 & X2) ^ ((1 - X1) & X3))) & 0xFF
    return bytes(ks)


a, b, c = 156324965, 868387187, 3131229747
ks = check1(a, b, c)
log('07_check1_recompute', ks == arr40, a=a, b=b, c=c,
    keystream_sha256=hashlib.sha256(ks).hexdigest()[:16],
    equals_arr40=(ks == arr40))

# ---------------------------------------------------------------- 08 派生 flag
key12 = b''.join((v & 0xFFFFFFFF).to_bytes(4, 'little') for v in (a, b, c))
pt_flag = bytes(arr19[i] ^ key12[i % 12] for i in range(len(arr19)))
try:
    txt = pt_flag.decode('gbk')
except Exception:
    txt = pt_flag.decode('latin1')
flag = 'flag{%s}' % txt
log('08_flag', ks == arr40 and txt.isprintable(),
    key12=key12.hex(), plaintext_hex=pt_flag.hex(), plaintext=txt, flag=flag)

# ---------------------------------------------------------------- 报告
rep = dict(platform=sys.platform, python=sys.version.split()[0],
           cwd=os.getcwd(), input_dir=IN, work_dir=WRK,
           all_ok=(len(fail) == 0), failed=fail, steps=R)
outp = os.path.join(WRK, 'kali_verify_report.json')
open(outp, 'w', encoding='utf-8').write(json.dumps(rep, ensure_ascii=False, indent=2))
print('\n==== all_ok=%s  failed=%s ====' % (rep['all_ok'], fail), flush=True)
print('report -> %s' % outp, flush=True)
sys.exit(0 if rep['all_ok'] else 1)
