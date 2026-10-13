"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import uuid

BASE=Path(__file__).resolve().parent.parent
TOP={'tools','tests','docs','skills','bridge','config','ctf-questionbank','.trae','.traecli'}
ROOT_FILES={'README.md','AGENTS.md','.gitignore','requirements.txt','setup.ps1','start.ps1',
            'update.ps1','install-autostart.ps1','install-trae.ps1','bundle-manifest.json'}

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def managed_path(name):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or not p.parts:
        raise ValueError('Invalid release path: '+name)
    if len(p.parts)==1 and name not in ROOT_FILES or len(p.parts)>1 and p.parts[0] not in TOP:
        raise ValueError('Path is outside release allowlist: '+name)
    if p.parts[0]=='config' and not name.endswith('.example.json'):
        raise ValueError('Machine configuration cannot be distributed')
    if p.parts[0]=='bridge' and len(p.parts)>1 and p.parts[1] in {'config','cases'}:
        raise ValueError('Machine bridge data cannot be distributed')
    if any(x in {'__pycache__','.git','.local','credentials','answers','solutions','downloads','attachments'} for x in p.parts):
        raise ValueError('Runtime/private data cannot be distributed: '+name)
    return p

def release(source):
    source=Path(source).resolve(strict=True)
    manifest=json.loads((source/'bundle-manifest.json').read_text(encoding='utf-8-sig'))
    rows={}; total=0
    for item in manifest['files']:
        name=item['path']; relative=managed_path(name)
        if name in rows:raise ValueError('Duplicate release path')
        path=source.joinpath(*relative.parts)
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(source):
            raise ValueError('Release contains escaped path')
        raw=path.read_bytes(); total+=len(raw)
        if total>100*1024*1024:raise ValueError('Release exceeds 100 MiB; use per-challenge downloads')
        if digest(raw)!=item['sha256']:
            normalized=raw.replace(b'\r\n',b'\n') if path.suffix not in {'.sqlite','.db'} else raw
            if manifest.get('text_line_endings')!='LF' or digest(normalized)!=item['sha256']:
                raise ValueError('Release hash mismatch: '+name)
            raw=normalized
        rows[name]=raw
    if not {'tools/ctf_os.py','README.md','AGENTS.md'}<=set(rows):raise ValueError('Incomplete release')
    rows['bundle-manifest.json']=(source/'bundle-manifest.json').read_bytes()
    return manifest,rows

def apply(source,target=BASE,plan=False):
    target=Path(target).resolve(strict=True)
    manifest,rows=release(source)
    changed=[]
    for name,raw in rows.items():
        path=target.joinpath(*PurePosixPath(name).parts)
        if path.is_symlink() or not path.resolve().is_relative_to(target):raise ValueError('Target path escaped')
        if path.exists() and not path.is_file():raise ValueError('Target path is not a file')
        if not path.exists() or digest(path.read_bytes())!=digest(raw):changed.append(name)
    result={'ok':True,'plan':plan,'version':manifest.get('version'),'changed_files':changed,
            'preserved':['.venv','.local machine settings','config/*.json','bridge/config','wp/cases','logs','downloaded attachments']}
    if plan or Path(source).resolve()==target or not changed:return result
    backup=target/'.local/upgrade-backups'/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    backup.mkdir(parents=True,exist_ok=False); created=[]; replaced=[]
    try:
        for name in changed:
            dst=target/name
            if dst.exists():
                saved=backup/name; saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(dst,saved);replaced.append(name)
            else:created.append(name)
            dst.parent.mkdir(parents=True,exist_ok=True)
            dst.write_bytes(rows[name])
            if digest(dst.read_bytes())!=digest(rows[name]):raise RuntimeError('Copy verification failed')
    except BaseException:
        for name in replaced:shutil.copy2(backup/name,target/name)
        for name in created:
            dst=(target/name).resolve()
            if not dst.is_relative_to(target):raise RuntimeError('Rollback path escaped')
            dst.unlink(missing_ok=True)
        raise
    (backup/'upgrade-receipt.json').write_text(json.dumps({'replaced':replaced,'created':created},ensure_ascii=False,indent=2),encoding='utf-8')
    result['backup']=str(backup)
    return result

def install_specialists(index=None,category='all'):
    sys.path.insert(0,str(BASE/'tools'))
    import ctf_os_runtime as runtime
    import ctf_specialists as specialists
    from ctf_team import save
    cfg_path=BASE/'bridge/config/kali.json'
    bridge=json.loads(cfg_path.read_text(encoding='utf-8-sig'))
    guest_root=PurePosixPath(bridge['guest_root'])
    environment=str(guest_root.parent/'.venv-specialists')
    path=BASE/'config/ctf_specialists.local.json'
    cfg=json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
    cfg.setdefault('python',environment+'/bin/python3')
    if not cfg['python']:cfg['python']=environment+'/bin/python3'
    envdir=str(PurePosixPath(cfg['python']).parent.parent)
    registry=index or cfg.get('pip_index','https://pypi.org/simple')
    if registry not in ('https://pypi.org/simple','https://mirrors.aliyun.com/pypi/simple'):
        raise ValueError('Use a supported PyPI index')
    code='import fcntl,pathlib,sys,venv; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); l=(p.parent/(p.name+".bootstrap.lock")).open("a"); fcntl.flock(l,fcntl.LOCK_EX|fcntl.LOCK_NB); (p/"bin/python3").is_file() or venv.EnvBuilder(with_pip=True,symlinks=True).create(p)'
    made=runtime.kali_execute({'case':'team_specialists_install','timeout':90},['/usr/bin/python3','-c',code,envdir])
    if runtime.failed(made):return {'ok':False,'stage':'create specialist venv','detail':made}
    cfg.update(enabled=True,pip_index=registry)
    cfg.setdefault('timeout_seconds',60)
    cfg.setdefault('source_status','portable team release; installation verified on this computer')
    save(path,cfg)
    result=specialists.install({'category':category,'confirm':True,'timeout':600,'case':'team_specialists_install'})
    if result.get('ok'):
        result['actual_status']=specialists.execute('status',{'case':'team_specialists_install','timeout':60})
        data=result['actual_status'].get('data',{})
        required={n for p in specialists.PROFILES.values() for n in p['modules']} if category=='all' else set(specialists.PROFILES[category]['modules'])
        result['ok']=result['actual_status'].get('ok') is True and all(data.get('modules',{}).get(n,{}).get('import_usable') is True for n in required)
    save(BASE/'logs/team-upgrade/specialists.json',result)
    return result

def verify():
    sys.path.insert(0,str(BASE/'tools'))
    import ctf_os
    core=subprocess.run([sys.executable,'-X','utf8',str(BASE/'tools/ctf_os.py'),'--selftest'],capture_output=True,text=True,timeout=60)
    return {'ok':core.returncode==0,'registered_tools':len(ctf_os.ALL_TOOLS),
            'interface_exit':core.returncode,'scope':'interface only; use ctf_team.py verify and specialist status for live dependencies'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source');parser.add_argument('--plan',action='store_true')
    parser.add_argument('--install-specialists',action='store_true')
    parser.add_argument('--category',default='all',choices=['all','web','pwn','reverse','crypto','misc','forensics'])
    parser.add_argument('--pip-index',choices=['https://pypi.org/simple','https://mirrors.aliyun.com/pypi/simple'])
    args=parser.parse_args()
    try:
        result=apply(args.source or BASE,plan=args.plan)
        if not args.plan:
            result['interface']=verify();result['ok']&=result['interface']['ok']
            if args.install_specialists:
                result['specialists']=install_specialists(args.pip_index,args.category)
                result['ok']&=result['specialists'].get('ok') is True
        if not args.plan:
            from ctf_team import save
            save(BASE/'logs/team-upgrade/latest.json',result)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0 if result['ok'] else 1
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 1

if __name__=='__main__':raise SystemExit(main())
