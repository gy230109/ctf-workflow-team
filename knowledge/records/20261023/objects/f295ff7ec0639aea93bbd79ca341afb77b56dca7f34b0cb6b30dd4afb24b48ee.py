"""Factor CTF: continued fractions for close primes and p**7*q RSA."""
from pathlib import Path
import hashlib
import json
import math
import os
import re
import zipfile

def convergents(a,b):
    h0,h1,k0,k1=0,1,1,0
    while b:
        q,a,b=a//b,b,a%b
        h=q*h1+h0; k=q*k1+k0
        yield h,k
        h0,h1,k0,k1=h1,h,k1,k

def iroot(n,r):
    x=1<<((n.bit_length()+r-1)//r)
    while True:
        y=((r-1)*x+n//x**(r-1))//r
        if y>=x:
            while x**r>n:x-=1
            while (x+1)**r<=n:x+=1
            return x
        x=y

def phi(p,q,r):
    return p**(r-1)*(p-1)*(q-1)

def close_pair(n1,n2):
    for index,(q1,q2) in enumerate(convergents(n1,n2)):
        if q1<=1 or q2<=1 or n1%q1 or n2%q2:continue
        p1=math.isqrt(n1//q1);p2=math.isqrt(n2//q2)
        if p1*p1*q1==n1 and p2*p2*q2==n2:
            assert abs(p1-p2)<p1//(4*q1*q2)
            print('Stage 1: exact factors recovered at convergent',index,flush=True)
            return p1,q1,p2,q2
    raise RuntimeError('No close-prime factors found')

def prime_power_factors(n,e,r=7):
    # inv(e,n) = small private exponent + t*p**(r-1).
    # Continued fractions recover t/(p*q), because the error is very small.
    inverse=pow(e,-1,n)
    for index,(u,v) in enumerate(convergents(inverse,n)):
        if v<=1 or n%v:continue
        power=n//v
        p=iroot(power,r-1)
        if p>1 and p**(r-1)==power and n%(p**r)==0:
            q=n//p**r
            if q>1:
                print('Prime-power factorization: convergent',index,'p bits',p.bit_length(),flush=True)
                return p,q
    raise RuntimeError('No prime-power factors found')

if 'CTF_INPUT_DIR' in os.environ:
    archive=Path(os.environ['CTF_INPUT_DIR'])/'Factor.zip'
    output=Path(os.environ['CTF_WORK_DIR'])
else:
    archive=Path('[USER_HOME]/Downloads/Factor.zip')
    output=Path(__file__).resolve().parent/'solution'
output.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(archive) as z:
    source=z.read('task.py').decode('utf-8').replace('\r','')
values={k:int(v) for k,v in re.findall(r'^([a-z]\w*)=(\d+)$',source,re.M)}
n11,n12=values['n11'],values['n12']
p11,q11,p12,q12=close_pair(n11,n12)
ph11,ph12=phi(p11,q11,2),phi(p12,q12,2)
m1=pow(values['c11'],pow(values['e11'],-1,ph11),n11)
m2=pow(values['c12'],pow(values['e12'],-1,ph12),n12)
assert pow(m1,values['e11'],n11)==values['c11']
assert pow(m2,values['e12'],n12)==values['c12']
print('Recovered m1/m2, bits:',m1.bit_length(),m2.bit_length(),flush=True)
n2=values['n2'];p2,q2=prime_power_factors(n2,m1)
ph2=phi(p2,q2,7)
d1,d2=pow(m1,-1,ph2),pow(m2,-1,ph2)
assert d1.bit_length()==672 and d2.bit_length()==672
b=pow(values['c2'],pow(values['e2'],-1,ph2),n2)
assert b.bit_length()==672 and pow(b,values['e2'],n2)==values['c2']
print('Stage 2: b recovered, bits:',b.bit_length(),flush=True)
assert values['e3']%b==0
e3base=values['e3']//b
n3=values['n3'];p3,q3=prime_power_factors(n3,e3base)
ph3=phi(p3,q3,7)
a=pow(e3base,-1,ph3)
assert a.bit_length()==672
common=math.gcd(values['e3'],ph3)
print('Stage 3: factors recovered; gcd(e3,phi3)=',common,flush=True)
if common!=1:
    raise RuntimeError(f'Noninvertible final exponent; need root extraction, gcd={common}')
m=pow(values['c3'],pow(values['e3'],-1,ph3),n3)
assert pow(m,values['e3'],n3)==values['c3']
plaintext=m.to_bytes((m.bit_length()+7)//8,'big')
flag=plaintext.decode('utf-8')
print('FLAG:',flag,flush=True)
result={'flag':flag,'verified_reencryption':True,'zip_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
        'method':'continued fractions; close-prime ratio and prime-power modular inverses',
        'factors':{k:str(v) for k,v in {'p11':p11,'q11':q11,'p12':p12,'q12':q12,
                                     'p2':p2,'q2':q2,'p3':p3,'q3':q3}.items()},
        'intermediates':{k:str(v) for k,v in {'m1':m1,'m2':m2,'d1':d1,'d2':d2,'b':b,'a':a}.items()}}
(output/'solution.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
(output/'flag.txt').write_text(flag+'\n',encoding='utf-8')
