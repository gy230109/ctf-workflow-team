from math import gcd
from Crypto.Util.number import long_to_bytes, inverse

e = 65537
ns = [int(l) for l in open('output.txt')]
import re
c = int(re.findall(r'c = (\d+)', open('task.py').read())[0])

m = c
for n in reversed(ns):
    p = gcd(ns[0], ns[1])
    q = n // p
    d = inverse(e, (p-1)*(q-1))
    m = pow(m, d, n)

print(long_to_bytes(m))
