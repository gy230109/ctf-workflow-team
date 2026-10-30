"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse,hashlib,json,os,re,shutil,sys,tomllib
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parents[1]
FILES=('SKILL.md','agents/openai.yaml','scripts/system.py',
    'references/roles/a-web.md','references/roles/b-pwn.md',
    'references/roles/d-reverse.md','references/roles/g-crypto.md',
    'references/wp-guide.md')

def atomic(path,text):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.ctf-new')
    temp.write_text(text,encoding='utf-8');os.replace(temp,path)

def json_text(data):return json.dumps(data,ensure_ascii=False,indent=2)+'\n'

def merge_json(text,entry):
    data=json.loads(text or '{}');servers=data.setdefault('mcpServers',{})
    if not isinstance(servers,dict):raise ValueError('mcpServers is not an object')
    if 'ctf-system' in servers and servers['ctf-system']!=entry:
        previous=servers['ctf-system']
        if not any(str(a).endswith('ctf_entry.py') for a in previous.get('args',[])):
            raise ValueError('ctf-system already belongs to another service')
    servers['ctf-system']=entry
    return json_text(data)

def merge_toml(text,entry):
    parsed=tomllib.loads(text);existing=parsed.get('mcp_servers',{}).get('ctf-system')
    if existing and not any(str(a).endswith('ctf_entry.py') for a in existing.get('args',[])):
        raise ValueError('ctf-system already belongs to another service')
    # Replace only our own top-level table; retain all unrelated TOML and comments.
    pattern=r'(?ms)^\[mcp_servers\.ctf-system\][^\n]*\n.*?(?=^\[|\Z)'
    approved=('ctf_system_status','ctf_tools','ctf_start','ctf_analyze','ctf_note','ctf_progress','ctf_finish','ctf_team_role')
    policy=', '.join(name+' = { approval_mode = "approve" }' for name in approved)
    block='[mcp_servers.ctf-system]\ncommand = '+json.dumps(entry['command'])+'\nargs = '+json.dumps(entry['args'])+'\nstartup_timeout_sec = 30\ntool_timeout_sec = 700\ndefault_tools_approval_mode = "prompt"\ntools = { '+policy+' }\n'
    updated=re.sub(pattern,lambda _:block,text) if re.search(pattern,text) else text.rstrip()+'\n\n'+block
    check=tomllib.loads(updated)
    assert check['mcp_servers']['ctf-system']['command']==entry['command']
    return updated

def install(root=ROOT,home=None,python=None,project=None):
    root=Path(root).resolve();home=Path(home or Path.home()).resolve();python=str(Path(python or sys.executable).resolve())
    for file in ('tools/ctf_entry.py','tools/ctf_product.py','tools/ctf_os.py'):
        if not (root/file).is_file():raise ValueError('System entry missing: '+file)
    source=root/'skills/ctf-system'
    for name in FILES:
        if not (source/name).is_file():raise ValueError('Skill entry missing: '+name)
    control=home/'.ctf-system';control.mkdir(parents=True,exist_ok=True)
    registry_path=control/'installed-files.json';owned=json.loads(registry_path.read_text(encoding='utf-8')) if registry_path.exists() else {}
    planned=[];clients=[]
    roots=[('codex','.codex'),('trae-cn','.trae-cn'),('trae','.trae'),('workbuddy','.workbuddy'),('claude','.claude'),('cursor','.cursor')]
    entry={'command':python,'args':['-X','utf8',str(root/'tools/ctf_entry.py'),'--stdio','--root',str(root)]}
    for client,base in roots:
        folder=home/base
        if not folder.exists():continue
        clients.append(client)
        # Skills enable the exact Chinese name even in clients using CLI rather than MCP.
        if client!='cursor':
            for name in FILES:
                target=folder/'skills/ctf-system'/name;data=(source/name).read_text(encoding='utf-8')
                if target.is_symlink():raise ValueError('Refusing to replace linked skill: '+str(target))
                if target.exists():
                    digest=hashlib.sha256(target.read_bytes()).hexdigest()
                    if digest!=owned.get(str(target)) and target.read_text(encoding='utf-8')!=data:
                        raise ValueError('Skill modified outside this installer: '+str(target))
                planned.append((target,data))
            for red in sorted((root/'skills').glob('redteam-*/SKILL.md')):
                data=red.read_text(encoding='utf-8')
                target=folder/'skills'/red.parent.name/'SKILL.md'
                if target.is_symlink():raise ValueError('Refusing to replace linked skill: '+str(target))
                if target.exists():
                    digest=hashlib.sha256(target.read_bytes()).hexdigest()
                    if digest!=owned.get(str(target)) and target.read_text(encoding='utf-8')!=data:
                        raise ValueError('Skill modified outside this installer: '+str(target))
                planned.append((target,data))
        config=folder/('config.toml' if client=='codex' else 'mcp.json')
        if client=='claude':config=home/'.claude.json'
        # Trae CN config location varies. Use detected config or the skill fallback.
        if client=='trae-cn' and not config.exists():continue
        original=config.read_text(encoding='utf-8-sig') if config.exists() else ''
        planned.append((config,merge_toml(original,entry) if client=='codex' else merge_json(original,entry)))
    if project:
        config=Path(project).resolve()/'.trae/mcp.json'
        planned.append((config,merge_json(config.read_text(encoding='utf-8-sig') if config.exists() else '',entry)))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f');backup=control/'backups'/stamp
    records=[]
    for index,(path,text) in enumerate(planned):
        if path.is_symlink():raise ValueError('Refusing linked config: '+str(path))
        if path.exists() and path.read_text(encoding='utf-8-sig')==text:continue
        previous=None
        if path.exists():
            backup.mkdir(parents=True,exist_ok=True);previous=backup/(str(index)+'-'+path.name);shutil.copy2(path,previous)
        atomic(path,text);owned[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
        records.append({'file':str(path),'backup':str(previous) if previous else None})
    atomic(control/'location.json',json_text({'name':'CTF系统','root':str(root),'python':python,'entry':'tools/ctf_entry.py'}))
    atomic(registry_path,json_text(owned))
    result={'ok':True,'name':'CTF系统','clients_detected':clients,'changed_files':records,
        'entry':entry,'model_accounts_modified':False,'client_sessions_verified':False,
        'next':'New client sessions discover CTF系统 automatically. Existing sessions may need to reconnect the new MCP once.'}
    atomic(control/'last-install.json',json_text(result));return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--project',type=Path);a=p.parse_args()
    print(json_text(install(a.root,project=a.project)))

if __name__=='__main__':main()
