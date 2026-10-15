"""Resolve the shared installation; forward to the live CTF系统 entry."""
import argparse,json,subprocess,sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('tool',nargs='?',default='ctf_system_status')
    p.add_argument('--json',type=Path);p.add_argument('--list-tools',action='store_true');a=p.parse_args()
    registry=Path.home()/'.ctf-system/location.json'
    if not registry.is_file():
        print(json.dumps({'ok':False,'error':'CTF系统尚未在本机登记，请运行安装包中的 connect-ai.ps1 一次。'},ensure_ascii=False));return 1
    cfg=json.loads(registry.read_text(encoding='utf-8'));root=Path(cfg['root'])
    if not (root/'tools/ctf_product.py').is_file():
        print(json.dumps({'ok':False,'error':'安装目录已经移动或缺失；在新目录运行 connect-ai.ps1 更新登记。'},ensure_ascii=False));return 1
    request={'jsonrpc':'2.0','id':1,'method':'tools/list' if a.list_tools else 'tools/call'}
    if not a.list_tools:request['params']={'name':a.tool,'arguments':json.loads(a.json.read_text(encoding='utf-8-sig')) if a.json else {}}
    run=subprocess.run([cfg['python'],'-X','utf8',str(root/'tools/ctf_product.py'),'--root',str(root)],input=json.dumps(request),capture_output=True,text=True,encoding='utf-8',timeout=700)
    if run.returncode:
        print(json.dumps({'ok':False,'error':run.stderr[-1600:]},ensure_ascii=False));return 1
    value=json.loads(run.stdout);print(json.dumps(value,ensure_ascii=False,indent=2))
    return 1 if value.get('error') or value.get('result',{}).get('isError') else 0

if __name__=='__main__':raise SystemExit(main())
