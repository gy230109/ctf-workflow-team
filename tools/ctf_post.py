"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import json
import os
from pathlib import Path
import urllib.request

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('tool');p.add_argument('request')
    p.add_argument('--timeout',type=int,default=600);p.add_argument('--wp-case')
    a=p.parse_args()
    try:
        path=Path(a.request)
        if path.stat().st_size>65536:raise ValueError('Request exceeds 64 KiB')
        data=json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(data,dict):raise ValueError('Request must be a JSON object')
        if a.wp_case:data['wp_case']=a.wp_case
        url=os.environ.get('CTF_OS_URL','http://127.0.0.1:8787/call')
        body=json.dumps({'tool':a.tool,'args':data}).encode('utf-8')
        request=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request,timeout=a.timeout) as response:result=json.load(response)
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result.get('ok') else 1
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 1
if __name__=='__main__':raise SystemExit(main())
