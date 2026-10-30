"""Baseline-locked install/rollback; no service restart and no external setup."""
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import secrets
import shutil
import subprocess
from datetime import datetime, timezone

HERE=Path(__file__).resolve().parent
PROJECT_FILES=frozenset({'AGENTS.md','tests/test_ctf_wp.py','tests/test_ctf_wp_review.py'})
def sha(data):return hashlib.sha256(data).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8'))
def safe(root,relative):
    if not isinstance(relative,str) or '\\' in relative or ':' in relative or PurePosixPath(relative).is_absolute() or any(part in {'.','..'} for part in relative.split('/')):
        raise ValueError('Invalid upgrade path')
    path=(root/relative).resolve()
    if not path.is_relative_to(root.resolve()) or not (relative.startswith(('tools/','integrations/purge-redteam/')) or relative in PROJECT_FILES):
        raise ValueError('Upgrade path is outside the permitted CTF integration')
    cursor=root/relative
    while cursor!=root:
        if cursor.is_symlink():raise ValueError('Linked upgrade target')
        cursor=cursor.parent
    return path
def atomic(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp')
    try:
        with tmp.open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
    finally:tmp.unlink(missing_ok=True)

def install(root,apply=False,rollback=None):
    root=Path(root).resolve(strict=True)
    if root.is_symlink() or not (root/'tools/ctf_entry.py').is_file():raise ValueError('Choose the existing CTF installation')
    if any((root/'.local/ctf-system/tasks').glob('*/operation.lock')):raise ValueError('A CTF task is running; wait for its operation to finish. No process was stopped.')
    if any(read(file).get('status') in {'queued','running'} for file in (root/'.local/ctf-suite/jobs').glob('*.json')):raise ValueError('Role jobs are queued/running; wait or cancel them before changing source. No process was stopped.')
    if rollback:
        if not rollback.replace('-','').isalnum():raise ValueError('Invalid rollback id')
        backup=root/'.local/purge-fusion-installs'/rollback
        receipt=read(backup/'receipt.json');rows=receipt['files']
        for row in rows:
            target=safe(root,row['path'])
            if not target.is_file() or sha(target.read_bytes())!=row['after_sha256']:raise ValueError('Later source changes detected; rollback refused')
            if row['before_sha256'] and sha((backup/row['path']).read_bytes())!=row['before_sha256']:raise ValueError('Backup integrity error')
        if not apply:return {'ready':True,'rollback':rollback,'apply_required':True}
        for row in sorted(rows,key=lambda item:0 if item['before_sha256'] else 1):
            target=safe(root,row['path'])
            if row['before_sha256']:atomic(target,(backup/row['path']).read_bytes())
            else:target.unlink()
        return {'rolled_back':True,'backup_id':rollback,'task_data_preserved':True}
    manifest=read(HERE/'upgrade.json');rows=manifest['files'];identical=True
    for row in rows:
        target=safe(root,row['path']);source=safe(HERE/'payload',row['path'])
        data=source.read_bytes()
        if sha(data)!=row['after_sha256']:raise ValueError('Package checksum mismatch: '+row['path'])
        if row['path'].endswith('.py'):compile(data,row['path'],'exec')
        current=sha(target.read_bytes()) if target.is_file() else None
        if current!=row['after_sha256']:identical=False
        if current not in (row['before_sha256'],row['after_sha256'],*row.get('compatible_before_sha256',[])):raise ValueError('CTF source baseline changed: '+row['path'])
    if identical:return {'installed':True,'changed':False,'source_verified':True}
    node=shutil.which('node')
    if not node:raise ValueError('Node with node:sqlite is required; nothing installed')
    probe=subprocess.run([node,'--input-type=module','-e',"import {DatabaseSync} from 'node:sqlite';const d=new DatabaseSync(':memory:');d.close();"],capture_output=True,text=True)
    if probe.returncode:raise ValueError('Node SQLite runtime unavailable; nothing installed')
    if not apply:return {'ready':True,'files':len(rows),'added_tools':manifest.get('added_tools',17),'apply_required':True,'service_restart':False}
    backup_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4)
    backup=root/'.local/purge-fusion-installs'/backup_id;backup.mkdir(parents=True)
    original={}
    for row in rows:
        target=safe(root,row['path']);data=target.read_bytes() if target.is_file() else None
        original[row['path']]=data
        if data is not None:
            copy=backup/row['path'];copy.parent.mkdir(parents=True,exist_ok=True);copy.write_bytes(data)
            if sha(copy.read_bytes())!=sha(data):raise ValueError('Backup verification failed')
    receipt={'files':[dict(row,before_sha256=sha(original[row['path']]) if original[row['path']] is not None else None) for row in rows]}
    (backup/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    # Publish all new dependencies first, then registry/product hooks, fingerprint last.
    rows=sorted(rows,key=lambda row:0 if row['before_sha256'] is None else 2 if row['path'].endswith('ctf_version.py') else 1)
    applied=[]
    try:
        for row in rows:
            target=safe(root,row['path']);previous=original[row['path']]
            current=target.read_bytes() if target.is_file() else None
            if current!=previous:raise ValueError('Concurrent source edit detected')
            atomic(target,safe(HERE/'payload',row['path']).read_bytes());applied.append(row)
        for row in rows:
            if sha(safe(root,row['path']).read_bytes())!=row['after_sha256']:raise ValueError('Installed source checksum mismatch')
    except Exception:
        for row in reversed(applied):
            target=safe(root,row['path'])
            if sha(target.read_bytes())!=row['after_sha256']:raise RuntimeError('Concurrent source change; automatic recovery stopped. Keep backup '+backup_id)
            previous=original[row['path']]
            if previous is None:target.unlink()
            else:atomic(target,previous)
        raise
    return {'installed':True,'changed':True,'added_tools':manifest.get('added_tools',17),'backup_id':backup_id,'service_restart':False,
            'next':'Use existing ctf-system: ctf_tools(query=ctf_redteam), then run the self-created acceptance task. No live solve rate is claimed.'}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',default=r'D:\强网杯大师');parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback')
    args=parser.parse_args()
    try:print(json.dumps(install(args.root,args.apply,args.rollback),ensure_ascii=False,indent=2));return 0
    except Exception as error:print(json.dumps({'ok':False,'error':str(error)},ensure_ascii=False));return 1
if __name__=='__main__':raise SystemExit(main())
