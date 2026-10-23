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
  if len(solutions)>=2:return
solve(R,C)
print('solutions',len(solutions),'nodes',nodes)
for k,sol in enumerate(solutions):
 grid=[[((x>>j)&1) for j in range(N)] for x in sol]
 print('\n'.join(''.join('##' if v else '  ' for v in r) for r in grid))
 (D/f'grid{k}.txt').write_text('\n'.join(''.join(map(str,r)) for r in grid)+'\n')
 import numpy as np,cv2
 a=np.array(grid,dtype=np.uint8)
 for invert in range(2):
  arr=np.pad((a if invert else 1-a)*255,4,constant_values=255)
  arr=cv2.resize(arr,None,fx=12,fy=12,interpolation=cv2.INTER_NEAREST)
  cv2.imwrite(str(D/f'grid{k}-inv{invert}.png'),arr)
  for rot in range(4):
   b=np.rot90(arr,rot).copy()
   result,pts,_=cv2.QRCodeDetector().detectAndDecode(b)
   if result:print('DECODE',invert,rot,repr(result))
