"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse,json,sys,urllib.error,urllib.request
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('tool');p.add_argument('args',nargs='?',default='{}');p.add_argument('--config',default='ctf_worker.json');p.add_argument('--out');a=p.parse_args()
    cfg=json.loads(Path(a.config).read_text(encoding='utf-8'))
    request=urllib.request.Request(cfg['url']+'/call',data=json.dumps({'tool':a.tool,'args':json.loads(a.args)}).encode(),headers={'Content-Type':'application/json','X-CTF-Case-Token':cfg['token']})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=340) as response:result=json.load(response)
    except urllib.error.HTTPError as e:result={'ok':False,'error':'gateway HTTP '+str(e.code)}
    raw=json.dumps(result,ensure_ascii=True,indent=2)
    if a.out:Path(a.out).write_text(raw,encoding='utf-8')
    print(raw);return 0 if result.get('ok') else 1
if __name__=='__main__':sys.exit(main())
