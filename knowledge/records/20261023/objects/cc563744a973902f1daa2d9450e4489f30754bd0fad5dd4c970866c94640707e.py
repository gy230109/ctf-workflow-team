from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import os

flag, key = open('secret').read().split('\n')

e = 3

while 1:
    p = getPrime(1024)
    q = getPrime(1024)
    phi = (p - 1) * (q - 1)
    if phi % e != 0:
        break
N = p * q
c = pow(key, e, N)

iv = os.urandom(16)
ciphertext = AES.new(key = long_to_bytes(key)[:16], iv = iv, mode = AES.MODE_CBC).encrypt(pad(flag.encode(),16)).hex()

f = open('output.txt', 'w')
f.write(f'N = {N}\n')
f.write(f'c = {c}\n')
f.write(f'iv = {iv}\n')
f.write(f'ciphertext = {ciphertext}\n')
