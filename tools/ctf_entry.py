"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--stdio',action='store_true')
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);a=parser.parse_args()
    for stream in (sys.stdin,sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8')
    for line in sys.stdin:
        if not line.strip():continue
        try:request=json.loads(line)
        except ValueError:
            print(json.dumps({'jsonrpc':'2.0','id':None,'error':{'code':-32700,'message':'Invalid JSON'}}),flush=True);continue
        if isinstance(request,dict) and 'id' not in request:continue
        try:
            p=subprocess.run([sys.executable,'-X','utf8',str(a.root/'tools/ctf_product.py'),'--root',str(a.root)],
                input=line,capture_output=True,text=True,encoding='utf-8',timeout=700)
            if p.returncode:raise RuntimeError('CTF system component failed to load; check the local installation.')
            response=json.loads(p.stdout)
        except Exception as e:
            response={'jsonrpc':'2.0','id':request.get('id') if isinstance(request,dict) else None,'error':{'code':-32000,'message':str(e)}}
        print(json.dumps(response,ensure_ascii=False),flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
