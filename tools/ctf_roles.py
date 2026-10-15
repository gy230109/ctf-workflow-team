"""Shared role definitions with private, per-installation identity registration."""
import argparse
import json
import os
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def member_id(value):
    text=str(value).strip().upper().removeprefix('成员')
    if not re.fullmatch('[A-G]',text):raise ValueError('member must be A-G')
    return text

def definitions(root):
    return read(Path(root)/'team/roles.json')

def identity(root):
    root=Path(root)
    for path in [root/'.local/team-member.json',root/'team-member.private.json']:
        if path.is_file():return read(path)
    return {}

def lookup(root=ROOT,member=None,profile=None,name=None):
    root=Path(root).resolve();data=definitions(root);saved=identity(root)
    if name is not None:
        if not saved.get('display_name') or str(name).strip()!=saved['display_name']:
            return {'ok':False,'needs_identity':True,'next':'姓名没有本机对应记录。读取队内角色卡，或让用户首次确认代号；不从公开资料猜测真实身份。'}
    selected=member or saved.get('member')
    if not selected:
        return {'ok':True,'needs_identity':True,'members':list(data['profiles'][profile or data['default_profile']]['members']),
                'next':'首次以队内代号登记，或放置自己的 team-member.private.json；之后自动恢复本机角色。'}
    selected=member_id(selected);profile=profile or saved.get('profile') or data['default_profile']
    if profile not in data['profiles']:raise ValueError('Unknown team profile')
    event=data['profiles'][profile];role=event['members'].get(selected)
    if role is None:return {'ok':False,'member':selected,'profile':profile,'active':False,'next':'该成员不在这个队伍配置中；按实际参赛安排选用 full-seven。'}
    reading=[]
    for rel in data['common_reading']+role['reading']:
        path=(root/rel).resolve()
        if not path.is_relative_to(root) or not path.is_file():raise ValueError('Role reading missing or outside installation: '+rel)
        reading.append({'path':rel,'local_path':str(path),'reference_only':False})
    return {'ok':True,'member':selected,'profile':profile,'active':True,**role,'reading':reading,
            'common_pool':event['common_pool'],'identity_source':'local' if saved else 'explicit member',
            'reference_cases':'knowledge/cases: learning/reference only; not default independent-solving inputs',
            'tool_readiness':'not inferred from role assignment','next':'Read the listed common and role material as context, discover current tools, then solve the supplied challenge and retain real evidence.'}

def register(root=ROOT,member=None,profile=None,display_name=None,identity_file=None):
    root=Path(root).resolve();card=read(Path(identity_file)) if identity_file else {}
    selected=member_id(member or card.get('member',''));data=definitions(root)
    selected_profile=profile or card.get('profile') or data['default_profile']
    result=lookup(root,member=selected,profile=selected_profile)
    if not result.get('ok'):raise ValueError('Member is not active in selected profile')
    record={'member':selected,'profile':selected_profile}
    if display_name or card.get('display_name'):record['display_name']=display_name or card['display_name']
    path=root/'.local/team-member.json';path.parent.mkdir(parents=True,exist_ok=True)
    if path.is_symlink():raise ValueError('Refusing linked identity file')
    temporary=path.with_name(path.name+'.new');temporary.write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(temporary,path)
    return lookup(root)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['show','register','list'])
    p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--member');p.add_argument('--profile');p.add_argument('--name');p.add_argument('--identity-file',type=Path)
    a=p.parse_args()
    try:
        result=definitions(a.root) if a.action=='list' else register(a.root,a.member,a.profile,a.name,a.identity_file) if a.action=='register' else lookup(a.root,a.member,a.profile,a.name)
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result.get('ok',True) else 1
    except (OSError,ValueError,KeyError) as exc:print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 1

if __name__=='__main__':raise SystemExit(main())
