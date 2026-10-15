"""Team CTF workflow component. See README.md for configuration and verified scope."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

CASE=Path(os.environ['CTF_CASE_DIR']).resolve()
WORK=CASE/'work'

def case_file(value):
    if not isinstance(value,str) or not value:raise ValueError('Provide local_file or same-case target')
    p=(WORK/value).resolve()
    if not p.is_relative_to(CASE) or not p.is_file():raise ValueError('Input must be a regular file inside this case')
    return p

def bounded_argv(values):
    if not isinstance(values,list) or len(values)>40 or any(not isinstance(v,str) or len(v)>4096 or '\x00' in v for v in values):raise ValueError('argv must contain at most 40 bounded strings')
    return values

def run(argv,timeout=30,stdin=None,env=None):
    # Spool outputs to keep verbose tools from exhausting the small VM's memory.
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(8*1048576,8*1048576))
        resource.setrlimit(resource.RLIMIT_CPU,(max(1,int(timeout)+1),max(2,int(timeout)+2)))
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        p=subprocess.Popen(argv,cwd=WORK,stdin=subprocess.PIPE,stdout=out,stderr=err,env=env,start_new_session=True,preexec_fn=limits)
        expired=False
        try:p.communicate(stdin,timeout=timeout)
        except subprocess.TimeoutExpired:
            expired=True;os.killpg(p.pid,signal.SIGKILL);p.communicate()
        out.seek(0);err.seek(0);o=out.read(1048577);e=err.read(1048577)
    return {'ok':p.returncode==0 and not expired,'returncode':p.returncode,'timed_out':expired,
        'stdout':o[:1048576].decode('utf-8','replace'),'stderr':e[:1048576].decode('utf-8','replace'),
        'output_truncated':len(o)>1048576 or len(e)>1048576}

def artifact(path):
    return {'artifact':str(path.relative_to(CASE)),'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest(),'bytes':path.stat().st_size}

def qemu(a):
    arch=a['arch'];target=case_file(a.get('target'))
    with target.open('rb') as stream:header=stream.read(20)
    if header[:4]!=b'\x7fELF' or len(header)<20:raise ValueError('QEMU input must be an ELF')
    machine=int.from_bytes(header[18:20],'little' if header[5]==1 else 'big')
    machines={'aarch64':183,'arm':40,'mips':8,'mipsel':8,'riscv64':243,'ppc':20,'ppc64':21,'i386':3,'x86_64':62}
    if arch not in machines or machines[arch]!=machine:raise ValueError('Requested architecture does not match the actual ELF machine')
    if arch in ('mips','mipsel') and (header[5]==1)!=(arch=='mipsel'):raise ValueError('MIPS byte order mismatch')
    args=['qemu-'+arch]
    prefix=a.get('sysroot') or a['_config'].get('sysroots',{}).get(arch)
    if prefix:
        p=Path(prefix).resolve()
        if not p.is_dir() or not (p.is_relative_to(CASE) or str(p) in a['_config'].get('sysroots',{}).values()):raise ValueError('sysroot must be a configured runtime or inside this case')
        args+=['-L',str(p)]
    args+=[str(target),*bounded_argv(a.get('argv',[]))]
    return dict(run(args,min(a['_budget_seconds']-1,120),str(a.get('stdin','')).encode()),arch=arch,sysroot=prefix,command=args,
        scope='User-mode emulation; not a sandbox and not a complete firmware/OS environment')

def crypto(a):
    root=Path(a['_config']['crypto_library'])
    action=a.get('action','list')
    if action=='list':
        rows=[str(p.relative_to(root)).removesuffix('.py').replace('/','.') for p in (root/'attacks').rglob('*.py') if p.name!='__init__.py']
        query=str(a.get('query','')).lower()
        found=[p for p in sorted(rows) if all(w in p.lower() for w in query.split())]
        return {'ok':True,'methods':found[:200],'count':len(found),'commit':a['_config']['crypto_commit'],'sage_usage':'kali_sage code may insert this library root into sys.path before importing a chosen method','library_root':str(root)}
    method=a.get('method','')
    if not re.fullmatch(r'(?:attacks|shared)\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*',method):raise ValueError('Use a module returned by list, e.g. attacks.rsa.wiener_attack')
    p=(root/(method.replace('.','/')+'.py')).resolve()
    if not p.is_relative_to(root.resolve()) or not p.is_file():raise ValueError('No such library module')
    if action=='read':
        start=int(a.get('start_line',1));count=int(a.get('lines',100))
        if start<1 or not 1<=count<=200:raise ValueError('Read up to 200 source lines')
        return {'ok':True,'method':method,'start_line':start,'source':'\n'.join(p.read_text().splitlines()[start-1:start-1+count]),'sha256':hashlib.file_digest(p.open('rb'),'sha256').hexdigest(),'commit':a['_config']['crypto_commit']}
    if action!='import':raise ValueError('Unknown library action')
    code='import sys,importlib,json;sys.path.insert(0,'+json.dumps(str(root))+');m=importlib.import_module('+json.dumps(method)+');print(json.dumps({"module":m.__name__,"file":m.__file__,"import_usable":True}))'
    return run(['sage','-c',code],min(45,a['_budget_seconds']-1))

def stego(a):
    target=case_file(a.get('target'));action=a['action'];name=secrets.token_hex(6)
    dest=WORK/('stego-'+name+'.bin')
    if action=='zsteg':argv=[a['_config']['zsteg_binary'],'-a',str(target)]
    elif action=='info':argv=['steghide','info',str(target),'-p',str(a.get('passphrase',''))]
    elif action=='extract':argv=['steghide','extract','-sf',str(target),'-xf',str(dest),'-p',str(a.get('passphrase',''))]
    elif action=='seek':
        wordlist=case_file(a.get('wordlist'))
        if wordlist.stat().st_size>64*1048576:raise ValueError('Wordlist budget: 64 MiB')
        argv=['stegseek','--crack',str(target),str(wordlist),str(dest)]
    else:raise ValueError('Unknown stego action')
    result=run(argv,min(120,a['_budget_seconds']-1),stdin=b'no\n')
    if result['ok'] and dest.exists():result.update(artifact(dest))
    return result

def origin(url):
    u=urlsplit(url)
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password:raise ValueError('Use an explicit HTTP(S) challenge URL without embedded credentials')
    return u.scheme+'://'+u.hostname.lower()+(':'+str(u.port) if u.port and u.port!=(443 if u.scheme=='https' else 80) else '')

def session_paths(kind):
    root=Path('/tmp')/('ctf-sessions-'+str(os.getuid()))
    root.mkdir(mode=0o700,exist_ok=True)
    if root.is_symlink() or root.stat().st_uid!=os.getuid():raise ValueError('Session directory ownership mismatch')
    root.chmod(0o700)
    name=hashlib.sha256(str(CASE).encode()).hexdigest()[:20]+'-'+kind
    return root/(name+'.sock'),WORK/('.ctf-'+kind+'.json'),root/(kind+'.lock')

def rpc(sock,token,args):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(25);s.connect(str(sock));s.sendall(json.dumps({'token':token,'args':args}).encode()+b'\n')
        stream=s.makefile('rb');raw=stream.readline(1048577)
        if not raw or len(raw)>1048576:raise ValueError('Invalid session response')
        return json.loads(raw)

def session(kind,a):
    sock,meta,_=session_paths(kind);action=a.get('action','status')
    if meta.exists():
        record=json.loads(meta.read_text())
        try:
            if action=='start':
                # Starting twice must not silently reuse another target/origin set.
                live=rpc(sock,record['token'],{'action':'status'})
                if kind=='debug' and a.get('target') and live.get('target')!=str(case_file(a['target'])):raise ValueError('Close the current debugger before selecting another target')
                if kind=='browser' and a.get('url') and origin(a['url']) not in live.get('origins',[]):raise ValueError('Close/start with the new explicit challenge origins')
                return dict(live,reused=True)
            return rpc(sock,record['token'],a)
        except (FileNotFoundError,ConnectionRefusedError):
            # Stale metadata is not proof a debugger process should be killed.
            pass
    if action in ('status','close'):return {'ok':True,'running':False,'kind':kind,'reason':'no_live_session'}
    if action!='start':raise ValueError('No live session; call start for this case')
    if kind=='debug' and a.get('target'):case_file(a['target'])
    if kind=='browser':
        if a.get('url'):origin(a['url'])
        if len(a.get('allow_origins',[]))>10:raise ValueError('At most 10 challenge origins')
    token=secrets.token_hex(32)
    launch=WORK/('.ctf-'+kind+'-launch.json')
    launch.write_text(json.dumps({'kind':kind,'args':a,'token':token}));launch.chmod(0o600)
    log=WORK/('.ctf-'+kind+'-daemon.log')
    with log.open('ab') as stream:
        p=subprocess.Popen([sys.executable,__file__,'--daemon',str(launch)],stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,cwd=WORK,start_new_session=True)
    for _ in range(160):
        if p.poll() is not None:raise RuntimeError('Session failed to start: '+log.read_text(errors='replace')[-1500:])
        try:return rpc(sock,token,{'action':'status'})
        except (FileNotFoundError,ConnectionRefusedError):time.sleep(0.1)
    raise TimeoutError('Session startup timed out; inspect daemon log before retrying')

class Debugger:
    def __init__(self,a):
        self.target=str(case_file(a['target'])) if a.get('target') else None
        executable=a['_config'].get('pwndbg_binary') or 'gdb-multiarch'
        argv=[executable,'-q','-nx','-nh','--interpreter=mi2','-iex','set auto-load off','-iex','set debuginfod enabled off']
        if self.target:argv+=['--args',self.target,*bounded_argv(a.get('argv',[]))]
        self.p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,cwd=WORK)
        self.record_started=time.monotonic()
        self.record_path=WORK/('gdb-live-'+secrets.token_hex(8)+'.cast') if a.get('wp_case') else None
        if self.record_path:
            self.record_path.write_text(json.dumps({'version':2,'width':120,'height':40,'timestamp':int(time.time()),'title':'Actual GDB MI process stream'})+'\n')
            self.record_path.chmod(0o600)
        os.set_blocking(self.p.stdout.fileno(),False);self.buffer=b'';self.seq=0
        self.read(10,prompt=True)
        self.command_mi('-gdb-set pagination off')
        self.command_mi('-gdb-set mi-async on')
    def read(self,timeout,token=None,prompt=False):
        result=[];end=time.monotonic()+timeout
        with selectors.DefaultSelector() as sel:
            sel.register(self.p.stdout,selectors.EVENT_READ)
            while time.monotonic()<end:
                while b'\n' in self.buffer:
                    line,self.buffer=self.buffer.split(b'\n',1);line=line.decode('utf-8','replace');result.append(line)
                    if token and line.startswith(str(token)+'^'):return result
                    if prompt and line.startswith('(gdb)'):return result
                if sum(map(len,result))>200000:raise RuntimeError('Debugger output budget exceeded')
                if self.p.poll() is not None:return result
                if sel.select(min(0.1,max(0,end-time.monotonic()))):
                    chunk=os.read(self.p.stdout.fileno(),65536)
                    if chunk:
                        self.buffer+=chunk
                        self.record('o',chunk.decode('utf-8','replace'))
        return result
    def record(self,kind,text):
        if self.record_path:
            with self.record_path.open('a') as stream:stream.write(json.dumps([round(time.monotonic()-self.record_started,6),kind,text])+'\n')
    def command_mi(self,cmd):
        self.seq+=1;token=self.seq
        sent=str(token)+cmd+'\n';self.record('i',sent)
        self.p.stdin.write(sent.encode());self.p.stdin.flush()
        rows=self.read(10,token=token)
        response=next((x for x in rows if x.startswith(str(token)+'^')),None)
        return {'ok':bool(response) and not response.startswith(str(token)+'^error'),'mi_records':rows,'result_record':response,'running':self.p.poll() is None,
            **({'error':'GDB reported an error or did not acknowledge the command','error_code':'gdb_command_failed'} if not response or '^error' in response else {})}
    def handle(self,a):
        result=self.perform(a)
        result['recording_enabled']=bool(self.record_path)
        if self.record_path:
            snapshot=WORK/('gdb-step-'+secrets.token_hex(8)+'.cast')
            shutil.copyfile(self.record_path,snapshot)
            result['evidence_artifacts']=[dict(artifact(snapshot),kind='terminal_recording',source='Live GDB MI input/output stream in asciicast v2 format; this is not a desktop screenshot')]
        return result
    def perform(self,a):
        action=a.get('action')
        if action in ('start','status'):return {'ok':True,'running':self.p.poll() is None,'target':self.target,'pid':self.p.pid,'kind':'debug','transport':'local_unix_socket','new_target_requires_close':True}
        if action=='close':return {'ok':True,'closed':True}
        if action!='command':raise ValueError('Unknown debugger action')
        cmd=a.get('command','')
        if not isinstance(cmd,str) or not cmd or len(cmd)>2048 or any(c in cmd for c in '\r\n\x00'):raise ValueError('One bounded debugger command required')
        if cmd=='interrupt':return self.command_mi('-exec-interrupt --all')
        verbs={'help','info','x','disassemble','print','p','bt','backtrace','where','break','b','tbreak','delete','disable','enable','continue','c','next','n','step','s','nexti','ni','stepi','si','finish','context','regs','vmmap','telescope','heap','bins','checksec','version','pwndbg'}
        verb=cmd.split()[0].split('/')[0]
        if verb=='run' and cmd=='run':pass
        elif verb not in verbs:raise ValueError('Supported debugger inspection/breakpoint/step commands only; file/source/shell/python/attach are excluded')
        return self.command_mi('-interpreter-exec console '+json.dumps(cmd))
    def close(self):
        if self.p.poll() is None:
            try:os.killpg(self.p.pid,signal.SIGTERM);self.p.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(self.p.pid,signal.SIGKILL);self.p.wait()

class Browser:
    def __init__(self,a):
        from playwright.sync_api import sync_playwright
        self.origins={origin(v) for v in a.get('allow_origins',[])}
        if a.get('url'):self.origins.add(origin(a['url']))
        self.pw=sync_playwright().start()
        self.context=self.pw.chromium.launch_persistent_context(str(WORK/'.ctf-browser-profile'),executable_path=shutil.which('chromium'),headless=True,chromium_sandbox=True,accept_downloads=False,ignore_https_errors=False,service_workers='block',viewport={'width':1280,'height':800})
        self.context.set_default_timeout(8000)
        self.recording = bool(a.get('wp_case'))
        self.chunk_open = False
        self.initial_error = None
        if self.recording:
            self.context.tracing.start(screenshots=True, snapshots=True, sources=False)
            self.context.tracing.start_chunk(title='Start challenge browser')
            self.chunk_open = True
        self.context.route('**/*',self.route)
        if hasattr(self.context,'route_web_socket'):self.context.route_web_socket('**/*',lambda ws:ws.close())
        self.page=self.context.pages[0] if self.context.pages else self.context.new_page()
        if a.get('url'):
            try:self.page.goto(a['url'],wait_until='domcontentloaded')
            except Exception as exc:self.initial_error=str(exc)
    def route(self,route):
        try:allowed=origin(route.request.url) in self.origins
        except ValueError:allowed=route.request.url.startswith(('data:','blob:','about:'))
        if allowed:route.continue_()
        else:route.abort('blockedbyclient')
    def handle(self,a):
        action=a.get('action')
        capture=self.recording and (self.chunk_open or action in ('navigate','click','fill','screenshot','close'))
        if capture and not self.chunk_open:
            self.context.tracing.start_chunk(title=str(action));self.chunk_open=True
        try:
            if self.initial_error:
                error=self.initial_error;self.initial_error=None
                reply={'ok':False,'error':error,'error_code':'browser_navigation_failed'}
            else:reply=self.perform(a)
        except Exception as exc:
            reply={'ok':False,'error':str(exc),'error_code':'browser_action_failed'}
        reply['recording_enabled']=self.recording
        if capture:
            assets=[];errors=[]
            try:
                path=WORK/('browser-step-'+secrets.token_hex(8)+'.png')
                self.page.screenshot(path=str(path),timeout=8000)
                assets.append(dict(artifact(path),kind='browser_screenshot',source='Actual Kali Chromium page after '+str(action)+'; URL '+self.page.url))
            except Exception as exc:errors.append({'kind':'browser_screenshot','error':str(exc)})
            try:
                path=WORK/('browser-trace-'+secrets.token_hex(8)+'.zip')
                self.context.tracing.stop_chunk(path=str(path));self.chunk_open=False
                if path.stat().st_size>33554432:raise ValueError('Trace chunk exceeds 32 MiB')
                assets.append(dict(artifact(path),kind='browser_trace',source='Playwright trace chunk for this tool action, including failure'))
            except Exception as exc:errors.append({'kind':'browser_trace','error':str(exc)})
            reply['evidence_artifacts']=assets;reply['capture_errors']=errors
        return reply
    def perform(self,a):
        action=a.get('action')
        if action=='close':return {'ok':True,'closed':True}
        if action=='navigate':
            if origin(a['url']) not in self.origins:raise ValueError('URL origin not in this session; close/start with explicit allow_origins')
            self.page.goto(a['url'],wait_until='domcontentloaded')
        elif action=='click':self.page.locator(a['selector']).click()
        elif action=='fill':
            if len(a.get('text',''))>16000:raise ValueError('Form input exceeds 16 KiB')
            self.page.locator(a['selector']).fill(a['text'])
        elif action=='screenshot':
            path=WORK/('browser-'+secrets.token_hex(6)+'.png');self.page.screenshot(path=str(path))
            return dict(self.snapshot(),**artifact(path))
        elif action not in ('start','status','snapshot'):raise ValueError('Unknown browser action')
        return self.snapshot()
    def snapshot(self):
        info=self.page.evaluate('''() => ({text:document.body?.innerText?.slice(0,16000)||'',forms:[...document.querySelectorAll('input,button,textarea,select,a')].slice(0,100).map(e=>({tag:e.tagName,id:e.id,name:e.name,type:e.type,text:e.innerText?.slice(0,120),href:e.getAttribute('href')}))})''')
        return {'ok':True,'kind':'browser','running':True,'url':self.page.url,'title':self.page.title(),'origins':sorted(self.origins),'snapshot':info,'cookies_preserved':True}
    def close(self):
        if self.recording:
            try:self.context.tracing.stop()
            except Exception:pass
        self.context.close();self.pw.stop()


def terminal_record(a):
    import shlex
    if a.get('confirm') is not True:raise ValueError('confirm=true required')
    executable=shutil.which('asciinema')
    if not executable:raise ValueError('asciinema is not installed')
    argv=bounded_argv(a.get('argv'))
    if not argv:raise ValueError('argv is required')
    path=WORK/('terminal-'+secrets.token_hex(8)+'.cast')
    # This is explicitly a PTY command; machine-readable JSON tools keep their
    # existing non-interactive transport unchanged.
    timeout=int(a.get('timeout',60))
    if not 1<=timeout<=180:raise ValueError('Terminal recording timeout must be 1..180')
    bounded_command=['timeout','--signal=TERM','--kill-after=2s',str(timeout),*argv]
    exit_path=WORK/('terminal-exit-'+secrets.token_hex(8)+'.txt')
    shell_command=shlex.join(bounded_command)+'; result_code=$?; printf "%s" "$result_code" > '+shlex.quote(str(exit_path))+'; exit "$result_code"'
    command=[executable,'rec','--quiet','--command',shell_command,str(path)]
    env=dict(os.environ,TERM='xterm-256color',SHELL='/bin/bash')
    started=time.monotonic()
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(16777216,16777216))
        resource.setrlimit(resource.RLIMIT_CPU,(timeout+3,timeout+4))
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=err,cwd=WORK,env=env,preexec_fn=limits)
        timed_out=False
        try:proc.wait(timeout=timeout+5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
            timed_out=True
        out.seek(0);err.seek(0);stdout=out.read(32769);stderr=err.read(8193)
    child_exit=int(exit_path.read_text()) if exit_path.is_file() else None
    result={'ok':proc.returncode==0 and child_exit==0 and not timed_out,'argv':argv,'returncode':child_exit,'recorder_returncode':proc.returncode,'timed_out':timed_out,
        'stdout':stdout[:32768].decode('utf-8','replace'),'stderr':stderr[:8192].decode('utf-8','replace'),
        'output_truncated':len(stdout)>32768 or len(stderr)>8192,'duration_seconds':round(time.monotonic()-started,3),
        'capture_errors':[],'evidence_artifacts':[],'transport':'asciinema PTY; stdin is closed'}
    if path.is_file() and path.stat().st_size<=16777216:
        terminal_text=''.join(str(event[2]) for line in path.read_text().splitlines()[1:] if (event:=json.loads(line))[1]=='o')
        result['terminal_output']=terminal_text[:32768]
        result['terminal_output_truncated']=len(terminal_text)>32768
        result['evidence_artifacts'].append(dict(artifact(path),kind='terminal_recording',source='Actual asciinema PTY output recording for this command; no public upload'))
    else:result['capture_errors'].append({'kind':'terminal_recording','error':'Recording missing or exceeds 16 MiB'})
    if not result['ok']:result.update(error='Recorded command failed or timed out',error_code='terminal_command_failed')
    return result

def descendant_rss(pid):
    total=0;todo=[pid];seen=set()
    while todo:
        p=todo.pop()
        if p in seen:continue
        seen.add(p)
        try:
            # PSS avoids counting Chromium's shared libraries once per process.
            rollup=Path('/proc/'+str(p)+'/smaps_rollup').read_text()
            total+=int(re.search(r'^Pss:\s+(\d+)',rollup,re.M).group(1))*1024
            todo.extend(map(int,Path('/proc/'+str(p)+'/task/'+str(p)+'/children').read_text().split()))
        except (OSError,ValueError):pass
    return total

def daemon(launch):
    init=json.loads(Path(launch).read_text());a=init['args'];kind=init['kind'];token=init['token']
    sock,meta,guard=session_paths(kind);owner=guard.open('a')
    fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)  # One heavy browser/debugger per VM.
    handler=None;server=None;reason='closed_or_error';measured=0
    def stop(*_):raise SystemExit()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        handler=Browser(a) if kind=='browser' else Debugger(a)
        sock.unlink(missing_ok=True)
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(sock));sock.chmod(0o600);server.listen(2);server.settimeout(1)
        meta.write_text(json.dumps({'token':token,'pid':os.getpid(),'kind':kind,'started_at':time.time()}));meta.chmod(0o600)
        last=time.monotonic();start=last
        while time.monotonic()-last<300 and time.monotonic()-start<1800:
            measured=descendant_rss(os.getpid())
            if measured>int(a['_config'].get('session_memory_mb',768))*1048576:
                reason='session_memory_budget';break
            try:client,_=server.accept()
            except socket.timeout:continue
            with client:
                client.settimeout(10)
                try:
                    raw=client.makefile('rb').readline(65537)
                    if len(raw)>65536:raise ValueError('Request budget exceeded')
                    req=json.loads(raw)
                    if not isinstance(req.get('token'),str) or not secrets.compare_digest(req.get('token',''),token):raise ValueError('Session authentication failed')
                    request=req['args'];last=time.monotonic();reply=handler.handle(request)
                except Exception as e:reply={'ok':False,'error':str(e),'error_code':'session_operation_failed'};request={}
                client.sendall(json.dumps(reply,ensure_ascii=False).encode()+b'\n')
                if request.get('action')=='close':reason='explicit_close';break
        else:reason='idle_or_total_lifetime_budget'
    finally:
        if handler:handler.close()
        if server:server.close()
        sock.unlink(missing_ok=True);meta.unlink(missing_ok=True)
        Path(launch).unlink(missing_ok=True);owner.close()
        (WORK/('.ctf-'+kind+'-last.json')).write_text(json.dumps({'end_reason':reason,'memory_pss_mb':round(measured/1048576,1),'ended_at':time.time()}))

def status(a):
    cfg=a['_config'];commands=['qemu-aarch64','qemu-arm','qemu-mips','qemu-riscv64','gdb-multiarch','steghide','stegseek','zsteg','chromium','sage']
    actual={c:shutil.which(c) for c in commands}
    actual['zsteg']=str(Path(cfg['zsteg_binary'])) if Path(cfg['zsteg_binary']).is_file() else None
    probes={}
    for name,argv in [('qemu',['qemu-aarch64','--version']),('zsteg',['ruby','-rzsteg','-e','puts Gem.loaded_specs["zsteg"].version']),('pwndbg',[cfg['pwndbg_binary'],'-nx','-nh','--batch','-ex','version'])]:
        probes[name]=run(argv,15)
    library=Path(cfg['crypto_library']);count=len(list((library/'attacks').rglob('*.py')))
    return {'ok':all(actual.values()) and all(p['ok'] for p in probes.values()) and count>0,'commands':actual,'version_probes':probes,
        'crypto_library':{'root':str(library),'method_files':count,'commit':cfg['crypto_commit']},'sysroots':{k:Path(v).is_dir() for k,v in cfg.get('sysroots',{}).items()},
        'sessions':{k:session(k,{'action':'status'}) for k in ('debug','browser')},'scope':'Installation, command loading and session connection checks; no challenge/model evaluation'}

if __name__=='__main__':
    if sys.argv[1]=='--daemon':daemon(sys.argv[2])
    else:
        try:
            req=json.loads(Path(sys.argv[1]).read_text());op=req['operation'];a=req['args']
            fn={'status':status,'qemu':qemu,'crypto':crypto,'stego':stego,'terminal':terminal_record,'debug':lambda a:session('debug',a),'browser':lambda a:session('browser',a)}[op]
            result=fn(a)
        except Exception as e:result={'ok':False,'error':str(e),'error_code':'runtime_operation_failed'}
        print(json.dumps(result,ensure_ascii=False));sys.exit(0 if result.get('ok') else 1)
