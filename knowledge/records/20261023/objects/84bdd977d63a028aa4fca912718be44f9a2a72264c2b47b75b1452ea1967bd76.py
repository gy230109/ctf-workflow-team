from pathlib import Path
import sys,time,json
sys.stdout.reconfigure(encoding='utf-8')
D=Path(__file__).resolve().parent
P=(D/'stage2-dec.elf').read_bytes()
N=25; ALL=(1<<N)-1
clues=lambda off:[list(P[off+N*i+1:off+N*i+1+P[off+N*i]]) for i in range(N)]
rows=clues(0x32a0);cols=clues(0x3020)
def patterns(a):
 out=[]
 def rec(k,start,m):
  if k==len(a):out.append(m);return
  space=sum(a[k:])+len(a)-k-1
  for s in range(start,N-space+1):rec(k+1,s+a[k]+1,m|(((1<<a[k])-1)<<s))
 rec(0,0,0)
 return out
R=[patterns(a) for a in rows];C=[patterns(a) for a in cols]
print('Candidate counts',list(map(len,R)),list(map(len,C)),flush=True)
nodes=0;solutions=[]
def solve(R,C):
 global nodes
 nodes+=1
 while True:
  change=False
  for axis in range(2):
   A,B=(R,C) if axis==0 else(C,R)
   for i,opts in enumerate(A):
    if not opts:return
    any1=0;all1=ALL
    for x in opts:any1|=x;all1&=x
    for j in range(N):
     bit=1<<j
     if all1&bit:v=1
     elif not(any1&bit):v=0
     else:continue
     new=[x for x in B[j] if ((x>>i)&1)==v]
     if not new:return
     if len(new)<len(B[j]):B[j]=new;change=True
  if not change:break
 if all(len(x)==1 for x in R):
  solutions.append([x[0] for x in R]);return
 _,axis,i=min((len(x),axis,i) for axis,A in enumerate((R,C)) for i,x in enumerate(A) if len(x)>1)
 A=(R,C)[axis]
 for x in A[i]:
  r=R.copy();c=C.copy();(r,c)[axis][i]=[x]
  solve(r,c)
  if len(solutions)>=10000:return
solve(R,C)
print('solutions',len(solutions),'nodes',nodes,flush=True)
import numpy as np
from PIL import Image,ImageOps
S=np.array([[[(x>>j)&1 for j in range(N)] for x in sol] for sol in solutions],dtype=np.uint8)
np.save(D/'solutions.npy',S)
lo=S.min(axis=0);hi=S.max(axis=0)
a=np.where(lo==hi,(1-lo)*255,128).astype(np.uint8)
ImageOps.expand(Image.fromarray(a).resize((750,750),Image.Resampling.NEAREST),30,255).save(D/'ambiguous.png')
print('ambiguous',np.sum(lo!=hi))
