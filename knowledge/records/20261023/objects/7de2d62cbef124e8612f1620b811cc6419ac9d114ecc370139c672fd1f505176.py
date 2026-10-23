from pathlib import Path
import sys,numpy as np,time,itertools
r=Path(__file__).parent;sys.path.insert(0,str(r/'python-libs'))
import dnfile
pe=dnfile.dnPE(str(r/'embedded-reward.dll'))
fields={f.Field.row_index:pe.get_data(f.Rva,19 if f.Field.row_index==1 else 40) for f in pe.net.mdtables.FieldRva}
z=np.unpackbits(np.frombuffer(fields[2],dtype=np.uint8)).astype(np.int8)
N=len(z)
checks=set()
for k in range(4):
 for i in range(N-(31<<k)):checks.add(tuple([i,i+(3<<k),i+(31<<k)]))
base=list(checks)
adj=[[] for _ in range(N)]
for c in base:
 for i in c:adj[i].append(c)
for cs in adj:
 for x,y in itertools.combinations(cs,2):
  t=tuple(sorted(set(x)^set(y)))
  if len(t)==4:checks.add(t)
cs=list(checks);groups={n:np.array([x for x in cs if len(x)==n]) for n in [3,4]}
print('bits',N,'checks',{k:len(v) for k,v in groups.items()},flush=True)
def rowseq(width,taps):
 rows=[1<<(width-1-i) for i in range(width)]
 for i in range(width,N):rows.append(sum([]) if False else __import__('functools').reduce(int.__xor__,(rows[i-width+t] for t in taps)))
 return rows
ar=rowseq(30,[0,1,4,6]);cr=rowseq(32,[0,1,2,3,5,7])
def gauss(equations,width):
 basis={}
 for x,b in equations:
  while x:
   p=x.bit_length()-1
   if p in basis:x^=basis[p][0];b^=basis[p][1]
   else:basis[p]=(x,b);break
  else:
   if b:return None
 if len(basis)<width:return None
 v=0
 for p in sorted(basis):
  x,b=basis[p]
  if (x&v).bit_count()%2!=b:v|=1<<p
 return v

def examine(bs):
 inds=np.flatnonzero(z!=bs)
 a=gauss([(ar[int(i)],int(z[i])) for i in inds],30)
 c=gauss([(cr[int(i)],1) for i in inds],32)
 if a is None or c is None:return False
 b=int(''.join(str(int(x)) for x in bs[:31]),2)
 out=np.array([((a&ar[i]).bit_count()%2) if ((c&cr[i]).bit_count()%2) else int(bs[i]) for i in range(N)])
 if not np.array_equal(out,z):return False
 print('SOLVED states',a,b,c,flush=True)
 results=[]
 for ah in range(4):
  for bh in range(2):
   vals=[a+(ah<<30),b+(bh<<31),c]
   key=b''.join(x.to_bytes(4,'little') for x in vals)
   flag=bytes(v^key[i%12] for i,v in enumerate(fields[1]))
   if all(32<=x<127 for x in flag):print('FLAG CANDIDATE',vals,repr(flag),flush=True);results.append((vals,flag.decode()))
 (r/'solved-states.txt').write_text(repr(results),encoding='utf-8')
 return True
rng=np.random.default_rng(12);start=time.time()
for trial in range(36):
 prior=(1-2*z.astype(float))*np.log(3)
 if trial:prior*=rng.uniform(.25,1.75,N)
 msgs={k:np.zeros(v.shape) for k,v in groups.items()}
 total=prior.copy()
 for step in range(120):
  newmsgs={}
  for k,idx in groups.items():
   q=np.tanh(np.clip((total[idx]-msgs[k])/2,-12,12))
   prod=np.ones_like(q)
   for j in range(k):prod[:,j]=np.prod(q[:,[u for u in range(k) if u!=j]],axis=1)
   val=2*np.arctanh(np.clip(prod,-.9999999,.9999999))
   newmsgs[k]=.55*val+.45*msgs[k]
  msgs=newmsgs;total=prior.copy()
  for k,idx in groups.items():total+=np.bincount(idx.ravel(),weights=msgs[k].ravel(),minlength=N)
  bs=(total<0).astype(np.int8)
  if step%5==0 and examine(bs):sys.exit(0)
 if trial%4==0:print('correlation pass',trial,'seconds',round(time.time()-start,1),flush=True)
print('Correlation decoding did not recover state',flush=True)
