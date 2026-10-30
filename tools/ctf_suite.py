"""CTF management and role-worker service. No host patching or permission overrides."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
import importlib.util
import stat

BASE=Path(__file__).resolve().parents[1]
VERSION='0.2.0'
LOADED_SOURCE=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
ROLES={'plan':'指挥与整合','recon':'信息收集','assess':'资产梳理','vuln-scan':'漏洞发现','exploit':'验证与解题','internal':'内网实验'}
ID=re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')

def digest(value):return hashlib.sha256(value if isinstance(value,bytes) else json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
def read(file,default=None):return json.loads(file.read_text(encoding='utf-8')) if file.is_file() else default
def save(file,value):
    file.parent.mkdir(parents=True,exist_ok=True)
    temp=file.with_name(file.name+'.'+secrets.token_hex(6)+'.tmp')
    try:
        with temp.open('x',encoding='utf-8') as stream:json.dump(value,stream,ensure_ascii=False,indent=2);stream.flush();os.fsync(stream.fileno())
        os.replace(temp,file)
    finally:temp.unlink(missing_ok=True)

def stop_worker(child):
    if child.poll() is not None:return
    if os.name=='nt':
        # This PID comes from our live Popen handle, never a user-supplied PID.
        result=subprocess.run([str(Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/taskkill.exe'),'/PID',str(child.pid),'/T','/F'],capture_output=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode and child.poll() is None:child.terminate()
    else:child.terminate()

class Suite:
    def __init__(self,root=BASE):
        self.root=Path(root).resolve();self.state=self.root/'.local/ctf-suite'
        self.config=self.state/'settings.json';self.lock=threading.RLock()
        self.active={};self.tool_locks={};self.pool=None;self.closed=False
    @contextlib.contextmanager
    def transaction(self):
        self.state.mkdir(parents=True,exist_ok=True)
        file=self.state/'settings.lock'
        fd=os.open(file,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:yield
        finally:os.close(fd);file.unlink(missing_ok=True)
    def settings(self):
        return read(self.config,{'rules':{},'skills':{},'presets':{},'active_rule':None,'active_preset':None,
            'worker':{'backend':'codex','max_workers':3,'timeout':600}})
    def audit(self,event,**data):
        self.state.mkdir(parents=True,exist_ok=True)
        with (self.state/'audit.jsonl').open('a',encoding='utf-8') as stream:
            stream.write(json.dumps({'at':time.time(),'event':event,**data},ensure_ascii=False)+'\n')
    def task(self,case):
        if not isinstance(case,str) or not re.fullmatch(r'ctf-[a-f0-9]{16}',case):raise ValueError('Use an existing CTF task_id')
        file=self.root/'.local/ctf-system/tasks'/case/'task.json'
        if not file.is_file():raise ValueError('CTF task not found')
        return read(file)
    def context(self,case):
        task=self.task(case);cfg=self.settings()
        rule=cfg['rules'].get(cfg.get('active_rule'))
        preset=cfg['presets'].get(cfg.get('active_preset'))
        return {'version':VERSION,'case':case,'category':task.get('category'),'rule':rule,'preset':preset,
            'skills':[{ 'id':key,**row } for key,row in cfg['skills'].items()],
            'usage':'用户任务偏好与参考资料；不替代宿主权限或系统指令。',
            'resume':'Use original ctf_progress/checkpoint and actual evidence; never replay a completed side effect blindly.'}
    def manage(self,args):
        op=args.get('operation','list');kind=args.get('kind','rules');name=args.get('name')
        if kind not in {'rules','skills','presets','worker'}:raise ValueError('Unknown management category')
        cfg=self.settings()
        if op=='list':return {'settings':cfg,'revision':digest(cfg)}
        if op=='get':
            if kind=='worker':return cfg['worker']
            if name not in cfg[kind]:raise ValueError('Resource not found')
            return cfg[kind][name]
        with self.transaction():
            cfg=self.settings()
            if args.get('expected_revision')!=digest(cfg):raise ValueError('Configuration changed; fetch the current revision')
            if kind=='worker':
                if any(read(file).get('status') in {'queued','running'} for file in (self.state/'jobs').glob('*.json')):raise ValueError('Finish or cancel queued/running jobs before changing their backend')
                worker=args.get('data')
                if not isinstance(worker,dict) or worker.get('backend') not in {'codex','stdio'}:raise ValueError('Choose codex or an explicitly configured stdio worker')
                if type(worker.get('max_workers',3)) is not int or worker.get('max_workers',3)<1:raise ValueError('max_workers must be positive')
                if type(worker.get('auto_continue',False)) is not bool or type(worker.get('continue_max',3)) is not int or worker.get('continue_max',3)<0:raise ValueError('Use boolean auto_continue and nonnegative continue_max')
                if worker['backend']=='stdio' and (not isinstance(worker.get('command'),list) or not worker['command'] or any(not isinstance(v,str) for v in worker['command'])):raise ValueError('A stdio worker requires an argv array, not a shell command')
                cfg['worker']=worker
            else:
                if not isinstance(name,str) or not ID.fullmatch(name):raise ValueError('Invalid resource id')
                if op=='put':
                    data=args.get('data')
                    if not isinstance(data,dict) or not isinstance(data.get('content'),str):raise ValueError('Provide content and optional description')
                    cfg[kind][name]=data
                elif op=='delete':
                    if name not in cfg[kind]:raise ValueError('Resource not found')
                    del cfg[kind][name]
                    if kind in {'rules','presets'} and cfg.get('active_'+kind[:-1])==name:cfg['active_'+kind[:-1]]=None
                elif op=='select' and kind in {'rules','presets'}:
                    if name not in cfg[kind]:raise ValueError('Resource not found')
                    cfg['active_'+kind[:-1]]=name
                else:raise ValueError('Unknown management operation')
            snapshot=self.snapshot()
            save(self.config,cfg);self.audit('configuration',operation=op,kind=kind,name=name)
            return {'saved':True,'revision':digest(cfg),'undo_snapshot':snapshot['id']}
    def snapshot(self):
        cfg=self.settings();identifier=secrets.token_hex(12)
        save(self.state/'snapshots'/(identifier+'.json'),{'schema':1,'settings':cfg,'sha256':digest(cfg),'at':time.time()})
        return {'id':identifier,'scope':'suite settings and pending preferences; no external actions undone'}
    def snapshots(self):return {'snapshots':[p.stem for p in sorted((self.state/'snapshots').glob('*.json'))]}
    def restore(self,identifier,expected_revision):
        if not isinstance(identifier,str) or not re.fullmatch(r'[a-f0-9]{24}',identifier):raise ValueError('Invalid snapshot id')
        row=read(self.state/'snapshots'/(identifier+'.json'))
        if not row or row.get('sha256')!=digest(row['settings']):raise ValueError('Snapshot is missing or corrupted')
        with self.transaction():
            if digest(self.settings())!=expected_revision:raise ValueError('Configuration changed; restore refused')
            if any(read(file).get('status') in {'queued','running'} for file in (self.state/'jobs').glob('*.json')):raise ValueError('Finish or cancel role jobs before restoring their configuration')
            undo=self.snapshot();save(self.config,row['settings']);self.audit('restore',snapshot=identifier)
            return {'restored':True,'undo_snapshot':undo['id'],'scope':'suite configuration only; task evidence and model history are retained'}
    def job_file(self,job):
        if not isinstance(job,str) or not re.fullmatch(r'[a-f0-9]{24}',job):raise ValueError('Invalid job id')
        return self.state/'jobs'/(job+'.json')
    def enqueue(self,case,jobs,extra=None):
        self.task(case)
        if not isinstance(jobs,list) or not jobs:raise ValueError('Provide role tasks')
        created=[]
        for job in jobs:
            if not isinstance(job,dict) or job.get('role') not in ROLES or not isinstance(job.get('objective'),str) or not job['objective'].strip():raise ValueError('Each role task requires a role and objective')
        for job in jobs:
            identifier=secrets.token_hex(12)
            save(self.job_file(identifier),{'id':identifier,'case':case,'role':job['role'],'objective':job['objective'],'created_at':time.time(),**(extra or {}),'status':'queued'})
            created.append(identifier)
        self.audit('enqueue',case=case,jobs=created)
        return {'jobs':created,'state':'queued','requires_running_service':True}
    def jobs(self,case):
        self.task(case)
        return {'jobs':[read(file) for file in sorted((self.state/'jobs').glob('*.json')) if read(file).get('case')==case]}
    def cancel(self,identifier):
        with self.lock:
            file=self.job_file(identifier);job=read(file)
            if not job:raise ValueError('Job not found')
            if job['status'] not in {'queued','running'}:return {'cancelled':False,'status':job['status']}
            job['cancel_requested']=True;save(file,job)
            child=self.active.get(identifier)
            if child:stop_worker(child)
            return {'cancel_requested':True,'job_id':identifier}
    def session(self,identifier,operation,objective):
        old=read(self.job_file(identifier))
        if not old or old.get('backend')!='codex' or not old.get('session_id'):raise ValueError('This job has no recorded native Codex session; no synthetic session was created')
        if self.settings()['worker'].get('backend')!=old['backend']:raise ValueError('Select the original worker backend before continuing its session')
        if operation not in {'resume','fork'} or not isinstance(objective,str) or not objective.strip():raise ValueError('Choose resume/fork and provide the next objective')
        if not isinstance(old['session_id'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,159}',old['session_id']):raise ValueError('Invalid recorded session id')
        created=self.enqueue(old['case'],[{'role':old['role'],'objective':objective}],{'session_operation':operation,'resume_id':old['session_id'],'parent_job':identifier})
        return dict(created,operation=operation,external_actions_undone=False)
    def note_result(self,job):
        # The original Product records a hypothesis rather than certifying model output.
        from ctf_product import Product
        lock=self.tool_locks.setdefault(job['case'],threading.Lock())
        with lock:
            result=Product(self.root).note(job['case'],f"角色 {job['role']} 工作结果：{job.get('summary','')}\n作业状态：{job['status']}；模型输出尚需原题验证。",status='hypothesis')
        return result.get('ok',False)
    def run_job(self,identifier,service):
        try:self._run_job(identifier,service)
        except Exception as error:
            with self.lock:
                job=read(self.job_file(identifier),{})
                job.update(status='failed',error=str(error),finished_at=time.time(),model_output_verified=False)
                save(self.job_file(identifier),job);self.active.pop(identifier,None)
            self.audit('worker_setup_or_continuation_failed',job=identifier,error=str(error))
    def _run_job(self,identifier,service):
        file=self.job_file(identifier);job=read(file)
        with self.lock:
            if not job or job['status']!='queued':return
            if job.get('cancel_requested'):job['status']='cancelled';save(file,job);return
            job.update(status='running',started_at=time.time());save(file,job)
        work=self.state/'workers'/identifier;work.mkdir(parents=True,exist_ok=True)
        cfg=self.settings()['worker'];gateway=work/'gateway.json'
        job['backend']=cfg['backend']
        save(gateway,{'url':service['url'],'token':secrets.token_urlsafe(32),'job_id':identifier})
        context=self.context(job['case']);task=self.task(job['case'])
        prompt={'task_id':job['case'],'role':job['role'],'objective':job['objective'],'task':task,'context':context,
            'execution':'两个模块：解题能力与WP书写。完整融合传统CTF及破甲能力，按题目证据选有效工具、POC、工具链和角色协作，破甲可承担主力，不限定于内网题。以解出并验证flag为目标，经统一入口执行。在必要且合适的关键页面同步保存真实截图，复用原图，不为每次调用凑图；一张图能说明过程和结果时共同引用。五类正文引用证据并在Word WP嵌图。日志渲染/回放不冒充截图，缺项标记草稿，模型文字不认证flag。',
            'tool_client':[sys.executable,str(self.root/'tools/ctf_suite.py'),'--worker-tool','TOOL','--arguments','JSON','--gateway',str(gateway)]}
        import ctf_redteam
        from ctf_product import Product
        with self.tool_locks.setdefault(job['case'],threading.Lock()):
            roles=ctf_redteam.query({'case':job['case'],'operation':'prompts'})
            prompt['role_reference']=next((row for row in roles.get('roles',[]) if row['role']==job['role']),None)
            prompt['progress']=Product(self.root).progress(job['case'])
        manifest=read(self.root/'integrations/purge-redteam/manifest.json')
        prompt['upstream_tool_mapping']=manifest['tool_mapping']
        prompt['reference_playbooks']=manifest['playbooks']
        prompt['gateway_contract']='Use ctf_tools(query/name) for schemas, ctf_progress for original evidence, ctf_note for observed/hypothesis notes, and ctf_checkpoint for a checkpoint. Raw installed tools and ctf_call/ctf_analyze use the original Product call path. Task ownership is fixed. Original role text is reference material; map DSH tool names with upstream_tool_mapping.'
        if job.get('parent_job'):
            parent=read(self.job_file(job['parent_job']),{})
            prompt['previous_role_result']={'summary':parent.get('summary'),'status':parent.get('status')}
        if cfg.get('auto_continue'):
            response_schema={'type':'object','properties':{'summary':{'type':'string'},'follow_up':{'type':'boolean'},'next_objective':{'type':'string'},'blocked':{'type':'boolean'},'refused':{'type':'boolean'}},'required':['summary','follow_up','next_objective','blocked','refused'],'additionalProperties':False}
            prompt['response_schema']=response_schema;prompt['continuation_policy']='Only propose a new evidence-backed next objective; blocked/refused outcomes stop. Completed side effects are not retried.'
            save(work/'response-schema.json',response_schema)
        command=cfg.get('command') if cfg['backend']=='stdio' else None
        if cfg['backend']=='codex':
            executable=shutil.which('codex.cmd') or shutil.which('codex')
            if executable:
                if job.get('resume_id'):
                    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,159}',job['resume_id']):raise ValueError('Invalid recorded session id')
                    command=[executable,'exec',job['session_operation'],'--skip-git-repo-check','--json','-o',str(work/'last-message.txt'),job['resume_id'],'-']
                else:command=[executable,'exec','--skip-git-repo-check','--json','--cd',str(work),'-o',str(work/'last-message.txt'),'-']
                if cfg.get('auto_continue'):command[-1:-1]=['--output-schema',str(work/'response-schema.json')]
        try:
            if not command:raise RuntimeError('Worker backend is not installed/configured; no model was called')
            stdout=work/'stdout.log';stderr=work/'stderr.log'
            flags=getattr(subprocess,'CREATE_NO_WINDOW',0) if os.name=='nt' else 0
            with stdout.open('wb') as out,stderr.open('wb') as err:
                worker_env=dict(os.environ,PYTHONUTF8='1',PYTHONIOENCODING='utf-8')
                child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=out,stderr=err,cwd=work,creationflags=flags,env=worker_env)
                with self.lock:self.active[identifier]=child
                payload=json.dumps(prompt,ensure_ascii=True).encode('ascii');deadline=time.monotonic()+float(cfg.get('timeout',600))
                while True:
                    try:child.communicate(payload,timeout=.2);break
                    except subprocess.TimeoutExpired:
                        payload=None
                        cancelled=read(file).get('cancel_requested')
                        if cancelled or time.monotonic()>=deadline:
                            stop_worker(child)
                            try:child.wait(timeout=5)
                            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
                            if cancelled:break
                            raise RuntimeError('Worker budget expired; inspect its tool receipts before retrying')
            latest=read(file);job['status']='cancelled' if latest.get('cancel_requested') else 'completed' if child.returncode==0 else 'failed'
            output=(work/'last-message.txt').read_text(encoding='utf-8') if (work/'last-message.txt').is_file() else stdout.read_text(encoding='utf-8',errors='replace')
            job.update(summary=output,exit_code=child.returncode,output_file=str(stdout),model_output_verified=False)
            if cfg['backend']=='codex':
                for line in stdout.read_text(encoding='utf-8',errors='replace').splitlines():
                    try:event=json.loads(line)
                    except ValueError:continue
                    session_id=event.get('thread_id') or event.get('session_id')
                    if isinstance(session_id,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,159}',session_id):job['session_id']=session_id
            if child.returncode and job['status']!='cancelled':job.update(error='Worker process exited with code '+str(child.returncode),stderr_file=str(stderr))
        except Exception as error:job.update(status='failed',error=str(error),model_output_verified=False)
        finally:
            with self.lock:self.active.pop(identifier,None)
        job['finished_at']=time.time();save(file,job)
        try:job['ctf_note_recorded']=self.note_result(job)
        except Exception as error:job['note_error']=str(error)
        save(file,job);self.audit('worker_finished',job=identifier,case=job['case'],status=job['status'])
        if cfg.get('auto_continue') is True and job['status']=='completed' and job.get('continuation_depth',0)<cfg.get('continue_max',3):
            try:answer=json.loads(job.get('summary',''))
            except (ValueError,TypeError):answer={}
            if not isinstance(answer,dict):answer={}
            if answer.get('follow_up') is True and not answer.get('blocked') and not answer.get('refused') and isinstance(answer.get('next_objective'),str) and answer['next_objective'].strip():
                if digest(cfg)==digest(self.settings()['worker']):
                    extra={'parent_job':identifier,'continuation_depth':job.get('continuation_depth',0)+1}
                    if cfg['backend']=='codex' and job.get('session_id'):extra.update(resume_id=job['session_id'],session_operation='resume')
                    next_job=self.enqueue(job['case'],[{'role':job['role'],'objective':answer['next_objective']}],extra)
                    job['continuation_job']=next_job['jobs'][0];save(file,job)
    def poll(self,service):
        wanted=self.settings()['worker'].get('max_workers',3)
        if self.pool is not None and self.pool._max_workers!=wanted and not self.active:
            self.pool.shutdown(wait=False);self.pool=None
        if self.pool is None:self.pool=ThreadPoolExecutor(max_workers=wanted)
        with self.lock:
            if not hasattr(self,'scheduled'):self.scheduled=set()
            for file in sorted((self.state/'jobs').glob('*.json')):
                job=read(file)
                if job['status']=='queued' and job['id'] not in self.scheduled:
                    if (self.root/'.local/ctf-system/tasks'/job['case']/'operation.lock').exists():continue
                    self.scheduled.add(job['id']);self.pool.submit(self.run_job,job['id'],service)
    def tool(self,job_id,tool,args,request_id=None):
        job=read(self.job_file(job_id))
        if not job or job.get('status')!='running':raise ValueError('Only a running role job can use its gateway')
        if tool in {'ctf_suite_dispatch','ctf_suite_session','ctf_suite_upgrade','ctf_suite_manage','ctf_suite_snapshot','ctf_suite_jobs'}:raise ValueError('This is a leaf worker; management stays with the owning session')
        if not isinstance(args,dict):raise ValueError('Tool arguments must be an object')
        if any(args.get(key) not in (None,job['case']) for key in ('case','wp_case','task_id')):raise ValueError('A worker cannot switch the owning CTF task')
        args={key:value for key,value in args.items() if key not in {'case','wp_case','task_id'}}
        if tool=='ctf_call':
            if args.get('tool') in {'ctf_call','ctf_analyze'}:raise ValueError('Recursive gateway wrapper')
            return self.tool(job_id,args.get('tool'),args.get('arguments',{}),request_id=args.get('request_id'))
        from ctf_product import Product
        with self.tool_locks.setdefault(job['case'],threading.Lock()):
            product=Product(self.root)
            if tool=='ctf_tools':return product.tools(**args)
            if tool=='ctf_progress':return product.progress(job['case'])
            if tool=='ctf_note':return product.note(job['case'],**args)
            if tool=='ctf_checkpoint':return product.checkpoint(job['case'],**args)
            if tool=='ctf_analyze':return product.analyze(job['case'],**args)
            return product.call(job['case'],tool,args,request_id=request_id)
    def worker_authorized(self,job_id,token):
        try:
            self.job_file(job_id)
            cfg=read(self.state/'workers'/job_id/'gateway.json',{})
            return bool(cfg.get('token')) and hmac.compare_digest(cfg['token'],token)
        except (ValueError,TypeError):return False
    def maintenance(self,operation):
        if operation=='selfcheck':
            info=read(self.root/'integrations/purge-redteam/manifest.json')
            bad=[]
            for name,expected in info['unmodified_upstream_sha256'].items():
                file=self.root/'integrations/purge-redteam/upstream'/name
                if not file.is_file() or digest(file.read_bytes())!=expected:bad.append(name)
            return {'ok':not bad,'version':VERSION,'upstream_source_mismatches':bad,'codex_cli_present':bool(shutil.which('codex.cmd') or shutil.which('codex')),
                'model_inference_verified':False,'host_policy_modified':False,'suite_source_sha256':LOADED_SOURCE,
                'panel_restart_required':LOADED_SOURCE!=digest(Path(__file__).read_bytes())}
        if operation=='upstream_check':
            request=urllib.request.Request('https://api.github.com/repos/kingcharleslzy-ai/dsh-purge/releases/latest',headers={'User-Agent':'ctf-purge-fusion','Accept':'application/vnd.github+json'})
            with urllib.request.urlopen(request,timeout=20) as response:release=json.load(response)
            return {'latest':release.get('tag_name'),'installed_source':read(self.root/'integrations/purge-redteam/manifest.json')['upstream'],
                'automatic_application':False,'next':'Prepare a reviewed baseline-locked upgrade; no remote code was executed.'}
        raise ValueError('Unknown maintenance operation')
    def prepare_upgrade(self,archive,expected_sha256):
        source=Path(archive).resolve(strict=True)
        if not re.fullmatch(r'[a-fA-F0-9]{64}',expected_sha256 or '') or digest(source.read_bytes())!=expected_sha256.lower():raise ValueError('Upgrade archive SHA256 mismatch')
        identifier=secrets.token_hex(12);destination=self.state/'updates'/identifier
        with zipfile.ZipFile(source) as package:
            members=package.infolist()
            if len(members)>10000 or sum(m.file_size for m in members)>1024*1024*1024:raise ValueError('Upgrade archive exceeds package resource budget')
            for member in members:
                name=member.filename;target=(destination/name).resolve()
                if '\\' in name or ':' in name or name.startswith('/') or '..' in name.split('/') or not target.is_relative_to(destination.resolve()) or stat.S_ISLNK(member.external_attr>>16):raise ValueError('Invalid archive member')
            for member in members:
                target=destination/member.filename
                if member.is_dir():target.mkdir(parents=True,exist_ok=True)
                else:
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with package.open(member) as incoming,target.open('xb') as out:shutil.copyfileobj(incoming,out)
        loader=importlib.util.spec_from_file_location('ctf_owned_upgrade_installer',self.root/'integrations/purge-redteam/upgrade-installer.py')
        module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module);module.HERE=destination
        preview=module.install(self.root,apply=False)
        save(destination/'prepared.json',{'archive_sha256':expected_sha256.lower(),'prepared_at':time.time(),'manifest_sha256':digest((destination/'upgrade.json').read_bytes())})
        self.audit('upgrade_prepared',identifier=identifier)
        manifest=read(destination/'upgrade.json')
        return {'prepared_id':identifier,'preview':preview,'version':manifest['version'],'changes':manifest['files'],'code_executed_from_archive':False}
    def apply_upgrade(self,identifier):
        if not isinstance(identifier,str) or not re.fullmatch(r'[a-f0-9]{24}',identifier):raise ValueError('Invalid prepared upgrade id')
        if any(read(file).get('status') in {'queued','running'} for file in (self.state/'jobs').glob('*.json')):raise ValueError('Finish or cancel role jobs before applying an upgrade')
        directory=self.state/'updates'/identifier;prepared=read(directory/'prepared.json')
        if not prepared or digest((directory/'upgrade.json').read_bytes())!=prepared['manifest_sha256']:raise ValueError('Prepared manifest changed')
        loader=importlib.util.spec_from_file_location('ctf_owned_upgrade_installer',self.root/'integrations/purge-redteam/upgrade-installer.py')
        module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module);module.HERE=directory
        result=module.install(self.root,apply=True)
        self.audit('upgrade_applied',identifier=identifier,result=result)
        return dict(result,panel_restart_required=bool(result.get('changed')))

def get_suite():return Suite(BASE)
def manage(args):return get_suite().manage(args)
def context(args):return get_suite().context(args.get('case') or args.get('wp_case'))
def dispatch(args):
    if args.get('confirm') is not True:raise ValueError('Dispatch may use a model account; confirm=true is required')
    return get_suite().enqueue(args.get('case') or args.get('wp_case'),args.get('jobs'))
def jobs(args):
    suite=get_suite()
    if args.get('operation','list')=='cancel':return suite.cancel(args.get('job_id'))
    return suite.jobs(args.get('case') or args.get('wp_case'))
def session(args):
    if args.get('confirm') is not True:raise ValueError('Continuing a model session requires confirm=true')
    return get_suite().session(args.get('job_id'),args.get('operation'),args.get('objective'))
def snapshot(args):
    suite=get_suite();op=args.get('operation','list')
    if op=='create':return suite.snapshot()
    if op=='restore':return suite.restore(args.get('id'),args.get('expected_revision'))
    return suite.snapshots()
def maintenance(args):return get_suite().maintenance(args.get('operation','selfcheck'))
def upgrade(args):
    if args.get('confirm') is not True:raise ValueError('Code upgrade operations retain confirm=true')
    suite=get_suite()
    if args.get('operation')=='prepare':return suite.prepare_upgrade(args.get('archive'),args.get('sha256'))
    if args.get('operation')=='apply':return suite.apply_upgrade(args.get('id'))
    raise ValueError('Choose prepare or apply')
def panel(args):
    info=read(get_suite().state/'service.json',{})
    return {'running_state':'not_checked','url':info.get('url'),'launcher':str(BASE/'integrations/purge-redteam/OPEN_PANEL.ps1'),
        'note':'Run OPEN_PANEL.cmd locally. The browser receives its token from a URL fragment; do not publish service.json.'}
def schema(props=None,required=()):
    fields={'case':{'type':'string'}};fields.update(props or {})
    return {'type':'object','properties':fields,'required':list(required),'additionalProperties':False}
TOOLS={
 'ctf_suite_manage':(manage,'管理 CTF 兼容规则、技能、预设和 Worker 配置；写入需当前 revision。',schema({'operation':{'type':'string'},'kind':{'type':'string'},'name':{'type':'string'},'data':{'type':'object'},'expected_revision':{'type':'string'}})),
 'ctf_suite_context':(context,'返回当前题目的已选规则/预设及技能索引，作为任务偏好与参考。',schema()),
 'ctf_suite_dispatch':(dispatch,'将角色任务交给本地常驻服务并行执行，结果回写原 CTF；需 confirm=true。',schema({'jobs':{'type':'array','items':{'type':'object'}},'confirm':{'type':'boolean'}},('jobs','confirm'))),
 'ctf_suite_jobs':(jobs,'读取角色作业真实排队/运行/完成状态，或取消指定自有作业。',schema({'operation':{'type':'string'},'job_id':{'type':'string'}})),
 'ctf_suite_snapshot':(snapshot,'保存和恢复兼容层配置；不伪装撤销外部工具动作或模型历史。',schema({'operation':{'type':'string'},'id':{'type':'string'},'expected_revision':{'type':'string'}})),
 'ctf_suite_maintenance':(maintenance,'核对源文件摘要或检查上游版本；不下载执行远程代码。',schema({'operation':{'type':'string','enum':['selfcheck','upstream_check']}})),
 'ctf_suite_panel':(panel,'定位图谱、作业、规则与技能管理界面；状态由真实本地服务确认。',schema())
 ,'ctf_suite_session':(session,'对已记录的 Codex Worker 会话原生续接或创建分支，不伪装撤销既有工具动作。',schema({'job_id':{'type':'string'},'operation':{'type':'string','enum':['resume','fork']},'objective':{'type':'string'},'confirm':{'type':'boolean'}},('job_id','operation','objective','confirm')))
 ,'ctf_suite_upgrade':(upgrade,'校验并预检指定本地升级包；apply 使用已安装的可信安装器并保留基线、备份和任务锁检查。',schema({'operation':{'type':'string','enum':['prepare','apply']},'archive':{'type':'string'},'sha256':{'type':'string'},'id':{'type':'string'},'confirm':{'type':'boolean'}},('operation','confirm')))
}
DANGEROUS={'ctf_suite_dispatch','ctf_suite_session','ctf_suite_upgrade'}

def serve(root,port=0,instance_id=None):
    suite=Suite(root);token=secrets.token_urlsafe(32)
    suite.state.mkdir(parents=True,exist_ok=True)
    instance=(suite.state/'service.lock').open('a+b')
    if instance.seek(0,2)==0:instance.write(b'0');instance.flush()
    instance.seek(0)
    try:
        if os.name=='nt':
            import msvcrt
            msvcrt.locking(instance.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(instance.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except OSError:
        instance.close();raise RuntimeError('A suite service already owns this installation')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def reply(self,status,value,content_type='application/json'):
            body=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=False).encode()
            self.send_response(status);self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(body)
        def authorized(self):
            origin=self.headers.get('Origin')
            return (not origin or origin==service['url']) and hmac.compare_digest(self.headers.get('X-CTF-Suite-Token',''),token)
        def do_GET(self):
            if self.path=='/':return self.reply(200,(suite.root/'integrations/purge-redteam/suite-ui.html').read_bytes(),'text/html; charset=utf-8')
            if not self.authorized():return self.reply(403,{'ok':False,'error':'Local service authorization required'})
            if self.path=='/api/health':return self.reply(200,{'ok':True,'version':VERSION})
            return self.reply(404,{'ok':False})
        def do_POST(self):
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=8*1024*1024:raise ValueError('Invalid request body')
                data=json.loads(self.rfile.read(length));action=data.get('action')
                if self.path=='/api/tool':
                    origin=self.headers.get('Origin')
                    if (origin and origin!=service['url']) or not suite.worker_authorized(data.get('job_id'),self.headers.get('X-CTF-Suite-Token','')):
                        return self.reply(403,{'ok':False,'error':'Worker authorization required'})
                    result=suite.tool(data['job_id'],data['tool'],data.get('arguments',{}))
                elif not self.authorized():return self.reply(403,{'ok':False,'error':'Local service authorization required'})
                elif action=='overview':
                    tasks=[read(file) for file in (suite.root/'.local/ctf-system/tasks').glob('*/task.json')]
                    result={'tasks':[{k:v for k,v in row.items() if k in {'task_id','title','category','state','answer_verified'}} for row in tasks], 'roles':ROLES,'settings':suite.manage({}), 'jobs':suite.jobs(data['case']) if data.get('case') else {'jobs':[]}}
                elif action=='manage':result=suite.manage(data.get('arguments',{}))
                elif action=='dispatch':result=suite.enqueue(data['case'],data['jobs'])
                elif action=='cancel':result=suite.cancel(data['job_id'])
                elif action=='session':result=suite.session(data['job_id'],data['operation'],data['objective'])
                elif action=='snapshot':result=suite.snapshot()
                elif action=='snapshots':result=suite.snapshots()
                elif action=='restore':result=suite.restore(data['id'],data['expected_revision'])
                elif action=='selfcheck':result=suite.maintenance('selfcheck')
                elif action=='upstream_check':result=suite.maintenance('upstream_check')
                elif action=='prepare_upgrade':result=suite.prepare_upgrade(data['archive'],data['sha256'])
                elif action=='apply_upgrade':result=suite.apply_upgrade(data['id'])
                elif action=='shutdown':
                    if any(read(file).get('status') in {'queued','running'} for file in (suite.state/'jobs').glob('*.json')):raise ValueError('Role workers are queued/running; cancel or finish them first')
                    result={'stopping':True};threading.Thread(target=server.shutdown,daemon=True).start()
                elif action=='redteam':
                    import ctf_redteam
                    result=ctf_redteam.query({'case':data['case'],'operation':data.get('operation','graph'),'data':data.get('data',{})})
                else:raise ValueError('Unknown panel action')
                self.reply(200,{'ok':True,'result':result})
            except Exception as error:self.reply(400,{'ok':False,'error':str(error)})
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    service={'url':'http://127.0.0.1:'+str(server.server_address[1]),'token':token,'pid':os.getpid(),'instance_id':instance_id or secrets.token_hex(12)}
    save(suite.state/'service.json',service)
    def poller():
        while not suite.closed:
            try:suite.poll(service)
            except Exception as error:suite.audit('scheduler_error',error=str(error))
            time.sleep(.2)
    thread=threading.Thread(target=poller,daemon=True);thread.start()
    try:server.serve_forever()
    finally:
        suite.closed=True;server.server_close()
        if suite.pool:suite.pool.shutdown(wait=False,cancel_futures=True)
        if read(suite.state/'service.json',{}).get('pid')==os.getpid():(suite.state/'service.json').unlink(missing_ok=True)
        instance.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--service',action='store_true');parser.add_argument('--root',type=Path,default=BASE);parser.add_argument('--instance-id');parser.add_argument('--worker-tool');parser.add_argument('--arguments',default='{}');parser.add_argument('--gateway',type=Path)
    args=parser.parse_args()
    if args.service:serve(args.root,instance_id=args.instance_id);return 0
    if args.worker_tool:
        cfg=read(args.gateway);payload={'job_id':cfg['job_id'],'tool':args.worker_tool,'arguments':json.loads(args.arguments)}
        request=urllib.request.Request(cfg['url']+'/api/tool',data=json.dumps(payload).encode(),headers={'X-CTF-Suite-Token':cfg['token'],'Content-Type':'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=650) as response:result=json.load(response)
        print(json.dumps(result,ensure_ascii=False));return 0 if result.get('ok') else 1
    parser.error('Use --service or --worker-tool')
if __name__=='__main__':raise SystemExit(main())
