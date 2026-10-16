"""Team CTF workflow component. See README.md for configuration and verified scope."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import uuid
import ctf_os_runtime as runtime
import ctf_specialists as specialists
import ctf_wp as wp

BASE=Path(__file__).resolve().parents[1]
WORKER=Path(__file__).with_name('ctf_extension_worker.py')
CONFIG=BASE/'config/ctf_extensions.local.json'

def execute(operation,args,worker=None,require_config=True,python=None):
    worker=Path(worker or WORKER)
    a=specialists.arguments(args)
    case=specialists.checked_case(a)
    cfg=json.loads(CONFIG.read_text(encoding='utf-8-sig')) if CONFIG.exists() else {}
    if require_config and cfg.get('enabled') is not True:return {'ok':False,'error':'Runtime additions not deployed on this machine','error_code':'not_deployed'}
    timeout=a.get('timeout',60)
    if isinstance(timeout,bool) or not isinstance(timeout,int) or not 1<=timeout<=600:raise ValueError('timeout must be 1..600')
    folder=BASE/'logs/extensions/requests'/uuid.uuid4().hex
    folder.mkdir(parents=True)
    staged=folder/('extension-worker-'+hashlib.sha256(worker.read_bytes()).hexdigest()[:16]+'.py')
    shutil.copyfile(worker,staged)
    payload=dict(a);payload['_config']=cfg;payload['_budget_seconds']=timeout
    files=[str(staged)]
    for key,target_key in [('local_file','target'),('wordlist_file','wordlist')]:
        if a.get(key):
            if a.get(target_key):raise ValueError('Provide either a local file or same-case guest path')
            p=Path(a[key]).resolve(strict=True)
            if not p.is_file():raise ValueError('Expected a regular input file')
            files.append(str(p));payload[target_key]='../input/'+p.name;payload.pop(key,None)
    req=folder/('request-'+uuid.uuid4().hex+'.json')
    raw=json.dumps({'operation':operation,'args':payload},ensure_ascii=False)
    if len(raw.encode())>65536:raise ValueError('Request exceeds 64 KiB')
    req.write_text(raw,encoding='utf-8');files.append(str(req))
    uploaded=runtime.bridge_call(['put',case,*files],timeout=180)
    if runtime.failed(uploaded) or uploaded.get('verified') is not True:return {'ok':False,'error':'Input upload/hash failed','detail':uploaded}
    python=python or specialists.settings()['python']
    result=runtime.kali_execute({'case':case,'timeout':timeout},[python,'../input/'+staged.name,'../input/'+req.name])
    try:data=json.loads(result.get('stdout',''))
    except ValueError:return {'ok':False,'error':'Runtime worker did not return JSON','execution':result}
    out={'ok':not runtime.failed(result) and not runtime.failed(data),'data':data,'execution':result,'case':case,'upload_verified':True}
    if not out['ok']:out.update(error=data.get('error') or 'Operation failed',error_code=data.get('error_code','operation_failed'))
    if data.get('artifact') and not data.get('evidence_artifacts'):
        path=PurePosixPath(data['artifact'])
        if path.is_absolute() or '..' in path.parts or path.parts[0]!='work':raise ValueError('Artifact escaped case')
        fetched=runtime.bridge_call(['fetch',case,str(path)],timeout=90)
        out['artifact_fetch']=fetched
        if runtime.failed(fetched) or fetched.get('verified') is not True or fetched.get('sha256')!=data.get('sha256'):
            out.update(ok=False,error='Artifact download/hash failed')
        else:
            out['artifact_path']=fetched['local_path']
            if operation=='browser' and a.get('action')=='screenshot' and a.get('wp_case'):
                out['screenshot_record']=wp.capture({'case':a['wp_case'],'mode':'file','file_path':fetched['local_path'],
                    'source':'Actual Kali Chromium persistent-session screenshot; verified bridge SHA256','caption':'连续浏览器会话实际画面'})
    out['evidence_artifacts']=[]
    out['capture_errors']=list(data.get('capture_errors') or [])
    for asset in (data.get('evidence_artifacts') or [])[:8]:
        try:
            path=PurePosixPath(asset['artifact'])
            if path.is_absolute() or '..' in path.parts or len(path.parts)<2 or path.parts[0]!='work':raise ValueError('Artifact escaped case')
            fetched=runtime.bridge_call(['fetch',case,str(path)],timeout=90)
            if runtime.failed(fetched) or fetched.get('verified') is not True or fetched.get('sha256')!=asset['sha256']:raise ValueError('Artifact SHA256 fetch failed')
            out['evidence_artifacts'].append({'path':fetched['local_path'],'sha256':asset['sha256'],'kind':asset['kind'],'source':asset['source']})
        except Exception as exc:
            out['capture_errors'].append({'kind':asset.get('kind'),'error':str(exc),'action_replayed':False})
            if operation=='pcap':out.update(ok=False,error='Required PCAP data export download/hash failed',error_code='artifact_fetch_failed')
    if operation=='browser' and a.get('wp_case') and data.get('recording_enabled') is not True:
        out['capture_errors'].append({'kind':'browser_recording','error':'Existing session has not loaded recording support; close it when idle before a new start','action_replayed':False})
    if operation=='pcap' and out['ok'] and not out['evidence_artifacts']:
        out.update(ok=False,error='Required PCAP data export is missing',error_code='artifact_fetch_failed')
    return out

S={'type':'string'};B={'type':'boolean'};I={'type':'integer'};A={'type':'array','items':S}
COMMON={'case':S,'local_file':S,'target':S,'timeout':I,'request_file':S}
SPECS={
 'ctf_runtime_status':('status','现测新增 QEMU/Pwndbg/隐写/密码方法库/连续浏览器依赖；不派题、不调用模型',{}),
 'qemu_run':('qemu','QEMU user 在 Kali 执行本题 ELF；需 confirm=true，架构须匹配，动态程序需要 sysroot',{'arch':dict(S,enum=['aarch64','arm','mips','mipsel','riscv64','ppc','ppc64','i386','x86_64']),'argv':A,'stdin':S,'sysroot':S,'confirm':B}),
 'kali_debug_session':('debug','本题连续 GDB/Pwndbg 会话：start/command/status/close；跨调用保留断点与状态，闲置自动退出。须 confirm=true',{'action':dict(S,enum=['start','command','status','close']),'command':S,'argv':A,'confirm':B}),
 'web_browser_session':('browser','本题连续 Playwright 会话：start/navigate/snapshot/click/fill/screenshot/status/close；独立 profile、同源约束。须 confirm=true',{'action':dict(S,enum=['start','navigate','snapshot','click','fill','screenshot','status','close']),'url':S,'allow_origins':A,'selector':S,'text':S,'confirm':B}),
 'crypto_library':('crypto','固定版本 crypto-attacks 方法目录、源码和 Sage 模块导入；算法条件由 Agent 判断，未调用题解',{'action':dict(S,enum=['list','read','import']),'query':S,'method':S,'start_line':I,'lines':I}),
 'misc_stego':('stego','本题 PNG/BMP/JPEG/WAV 隐写入口：zsteg/steghide/stegseek；提取文件留摘要。须 confirm=true',{'action':dict(S,enum=['zsteg','info','extract','seek']),'passphrase':S,'wordlist':S,'wordlist_file':S,'confirm':B}),
 'kali_terminal_record':('terminal','Kali 本题 PTY 命令自动由 asciinema 录制为 .cast；适合需要终端回放的命令，stdin 关闭，需 confirm=true。普通 JSON 工具保留原入口。',{'argv':A,'confirm':B}),
}
TOOLS={}
for name,(op,description,props) in SPECS.items():
    TOOLS[name]=(lambda a,operation=op:execute(operation,a),description,{'type':'object','properties':dict(COMMON,**props),'required':[]})
DANGEROUS={'qemu_run','kali_debug_session','web_browser_session','misc_stego','kali_terminal_record'}
