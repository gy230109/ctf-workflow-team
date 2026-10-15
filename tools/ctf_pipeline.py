"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse,hashlib,json,secrets,shutil,sys,time
from pathlib import Path
import ctf_os,ctf_os_runtime as runtime,ctf_version
import muteki_client as mc,muteki_autopilot as auto
from ctf_worker_gateway import CaseGateway
from ctf_worker_tunnel import WorkerTunnel
BASE=Path(__file__).resolve().parents[1]

def worker_failure(path):
    """Classify the CLI terminal event without copying raw prompts or output."""
    reason=None
    for line in Path(path).read_text(encoding='utf-8',errors='replace').splitlines():
        try:event=json.loads(line)
        except ValueError:continue
        if event.get('type') not in {'error','turn.failed'}:continue
        value=event.get('error',event)
        message=str(value.get('message','') if isinstance(value,dict) else value).lower()
        if 'flagged for possible cybersecurity risk' in message:return 'provider_safety_rejection'
        reason='worker_turn_failed'
    return reason

def acceptance_passed(evidence,require_rea=False):
    return (all(evidence.get(k) is True for k in ('worker_tools_verified','challenge_verified','negative_control_verified','independent_replay_verified'))
            and (not require_rea or evidence.get('rea_worker_verified') is True)
            and not evidence.get('failure_code')
            and evidence.get('outcome',{}).get('outcome')=='terminal'
            and evidence.get('worker_process_exit',0)==0)

def write(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')

def prepare(identifier,case):
    sys.path.insert(0,str(BASE/'questionbank'));import bank
    if not __import__('re').fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',case):raise ValueError('invalid case')
    task=bank.require_task(bank.load_rows(),identifier)
    out=BASE/'workflows'/case/'task'
    result=bank.prepare_task(task,out)
    write(out.parent/'state.json',{'case':case,'task_id':identifier,'status':'prepared','source':task['source_url'],'prepared':result,'verified':False})
    return result

def run_task(task_dir,case,verifier=None,budget=600,require_rea=False,backend='codex'):
    if not __import__('re').fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',case):raise ValueError('invalid case')
    if not 30<=budget<=1800:raise ValueError('budget must be 30..1800 seconds')
    if backend not in {'muteki','codex'}:raise ValueError('unsupported Worker backend')
    if not callable(verifier):raise ValueError('configure a real challenge verifier before dispatch')
    task_dir=Path(task_dir).resolve(strict=True);task=json.loads((task_dir/'task.json').read_text(encoding='utf-8'))
    artifacts={p.name:p for p in (task_dir/'attachments').iterdir() if p.is_file()}
    if not artifacts:raise ValueError('no prepared artifacts')
    declared=[h['name'] for h in task.get('handouts',[])]
    if len(declared)!=len(set(declared)) or set(declared)!=set(artifacts):raise ValueError('attachments differ from the declared task manifest')
    # Rehash every input before the Worker sees it; reference material is never uploaded.
    for h in task.get('handouts',[]):
        p=artifacts[h['name']]
        if hashlib.sha256(p.read_bytes()).hexdigest()!=h['sha256']:raise ValueError('prepared attachment hash mismatch')
    init=ctf_os.call_tool('wp_init',{'case':case,'title':task['name'],'category':task['category']})
    if not init.get('ok'):raise RuntimeError('WP initialization failed')
    work=task_dir.parent;upload=work/'worker-input';upload.mkdir(exist_ok=False)
    for p in artifacts.values():shutil.copyfile(p,upload/p.name)
    shutil.copyfile(Path(__file__).with_name('ctf_worker_call.py'),upload/'ctf_worker_call.py')
    (upload/'task.json').write_text((task_dir/'task.json').read_text(encoding='utf-8'),encoding='utf-8')
    manifest=[{'name':k,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for k,p in artifacts.items()]
    evidence={'case':case,'task_id':task['id'],'artifacts':manifest,'runtime':ctf_version.info(len(ctf_os.ALL_TOOLS)),
        'worker_tools_verified':False,'challenge_verified':False,'status':'prepared','reference_inputs_distributed':False}
    ledger=work/'result.json';write(ledger,evidence)
    with runtime.dispatch_lock():
        session=mc.login() if backend=='muteki' else None
        if session and auto.active_runs(session):raise RuntimeError('another Muteki run is active; no dispatch performed')
        gateway=CaseGateway(case,artifacts,verifier=verifier,lifetime=budget+60).start()
        tunnel=None;rid=None
        try:
            if backend=='muteki':tunnel=WorkerTunnel(gateway.port).start()
            url=tunnel.url if tunnel else f'http://127.0.0.1:{gateway.port}'
            write(upload/'ctf_worker.json',{'url':url,'token':gateway.token,'case':case})
            tools=['ctf_profile','rea_status','rea_ops','rea_run','verify_candidate']
            tools+=['kali_file','kali_strings','kali_objdump','reverse_binary_info']
            (upload/'WORKER-TOOLS.md').write_text(
                '# Case tools\n\nUse python3 ctf_worker_call.py TOOL JSON --out result.json.\n'
                'Configuration is in ctf_worker.json; never print its token.\n'
                'ctf_profile: {"category":"reverse","artifact":"NAME"}.\n'
                'rea_status / rea_ops: {}.\n'
                'rea_run: {"command":"inspect","artifact":"NAME","timeout":180}, then '
                '{"command":"function","artifact":"NAME","address":"0xFILE_VA","timeout":180}.\n'
                'verify_candidate: {"candidate":"YOUR_RECOVERED_INPUT"}.\n'
                'All these calls execute real host tools and record receipts in the same WP.\n',encoding='utf-8')
            with (upload/'WORKER-TOOLS.md').open('a',encoding='utf-8') as guide:
                guide.write('Linux static tools kali_file/kali_strings/kali_objdump/reverse_binary_info: {"artifact":"NAME"}; kali_objdump may add "opts":"-d -M intel".\n')
            prompt=('系统流程验收，独立解题，允许 AI。只读本次 task.json、附件和 WORKER-TOOLS.md。题面：'+task['description']+
                '\n必须先调用实际 case tools 的 ctf_profile 判定格式。'+
                ('本题必须用 rea_run inspect 再对校验函数用 rea_run function；不要只用 strings 猜测。' if require_rea else '')+
                '\n从程序恢复输入，通过 verify_candidate 喂给真实题目程序。先给一个明确错误输入记录拒绝，再验证你恢复的输入。'
                '\n使用 python3 ctf_worker_call.py 的请求对象，不要猜 Windows 绝对路径。artifact 就是附件文件名。'
                '\n工具失败读错误并记录，禁止读取他人答案或搜索题解。令牌不要输出到聊天或黑板。'+
                ('\n说明真实验证记录，然后按本次黑板 Skill 提交结果。' if backend=='muteki' else '\n本次是本地 CLI Worker，没有 Muteki 黑板。完成真实验证后给出简洁最终结果即结束，不要寻找黑板接口。')+
                '预算 '+str(budget)+' 秒，单 Worker。')
            prompt_path=work/'prompt.txt';prompt_path.write_text(prompt,encoding='utf-8')
            if backend=='muteki':
                rid=mc.submit_run(session,dir_path=upload,name='Workflow-'+case,prompt=prompt,category=task['category'],flag_format=task.get('flag_format','flag{...}'),quiet=True)
                if not rid:raise RuntimeError('Muteki submission failed')
            else:rid='codex-'+secrets.token_hex(6)
            evidence.update(run_id=rid,status='running',gateway_tools=tools);write(ledger,evidence)
            print(json.dumps({'case':case,'run_id':rid,'status':'running','budget_seconds':budget}),flush=True)
            if backend=='muteki':
                tracker=auto.probe.Tracker(warn=180,dead=420,grace=300,tool_timeout=360)
                outcome=auto.watch_once(session,rid,budget_s=budget,interval=2,tr=tracker,quiet=True)
            else:
                import subprocess
                command=shutil.which('codex.cmd') or shutil.which('codex')
                if not command:raise RuntimeError('Codex CLI is not installed')
                # The existing ChatGPT login is reused; task overrides do not alter user config.
                argv=[command,'exec','--ignore-user-config','--skip-git-repo-check','--ephemeral',
                    '--sandbox','danger-full-access','-c','approval_policy="never"','-c','features.multi_agent=false',
                    '--disable','apps','--disable','plugins','--disable','browser_use','--disable','computer_use',
                    '--json','-C',str(upload),'-o',str(work/'private-worker-final.txt'),'-']
                prompt+='\n你是 Windows 本机独立 Worker，先查 Get-Command python；客户端只用 Python 标准库。只读取当前工作目录，不读取父目录、其他题目或参考资料。本次使用 case tools，无需任何其他 MCP。不用创建新 Agent。'
                with (work/'private-worker-events.jsonl').open('wb') as stdout,(work/'private-worker-stderr.txt').open('wb') as stderr:
                    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=stdout,stderr=stderr,cwd=upload)
                    process.stdin.write(prompt.encode('utf-8'));process.stdin.close()
                    try:code=process.wait(timeout=budget);outcome={'outcome':'terminal','reason':'codex_cli_exit','exit_code':code,'solved':False}
                    except subprocess.TimeoutExpired:
                        subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,timeout=15)
                        process.wait(timeout=10);outcome={'outcome':'timeout','reason':'codex_cli_budget','solved':False}
                evidence['worker_backend']='codex-local';evidence['worker_process_exit']=outcome.get('exit_code')
                evidence['failure_code']=worker_failure(work/'private-worker-events.jsonl')
            if backend=='muteki' and outcome['outcome']!='terminal':
                stopped,note=mc.stop_run(session,rid)
                for _ in range(10):
                    current=mc.get_run(session,rid)
                    if current and current.get('status') in auto.FINAL_STATUS:break
                    time.sleep(1)
                else:stopped=False
                evidence['stop_confirmed']=stopped
                if not stopped:raise RuntimeError('run stop not confirmed; no retries')
            evidence['outcome']={k:v for k,v in outcome.items() if k!='flag'}
            calls=gateway.calls
            successes=[c for c in calls if c.get('ok')]
            rea=[c for c in successes if c['tool']=='rea_run' and c['args'].get('command') in {'inspect','function'}]
            accepted=[c for c in successes if c['tool']=='verify_candidate' and c['response'].get('accepted') is True]
            rejected=[c for c in successes if c['tool']=='verify_candidate' and c['response'].get('accepted') is False and c['response'].get('program_executed') is True]
            evidence.update(worker_tools_verified=bool(successes),rea_worker_verified=(len({c['args']['command'] for c in rea})==2),
                challenge_verified=bool(accepted),negative_control_verified=bool(rejected),tool_calls=len(calls),
                tool_receipts=[{'tool':c['tool'],'ok':c.get('ok'),'command':c['args'].get('command'),'evidence_path':c.get('evidence_path')} for c in calls])
            # Independently replay the candidate after the Worker has finished.
            if accepted:
                replay=verifier(accepted[-1]['args']['candidate'])
                write(work/'private-verification-replay.json',replay)
                evidence['independent_replay_verified']=replay.get('accepted') is True
            else:evidence['independent_replay_verified']=False
            full_pass=acceptance_passed(evidence,require_rea)
            evidence['status']='verified' if full_pass else 'unverified'
            write(work/'private-worker-calls.json',calls)
            wp=ctf_os.call_tool('wp_build',{'case':case});evidence['wp']=wp
            evidence['records_verified']=wp.get('ok') is True and wp.get('result',{}).get('integrity_verified') is True
            if full_pass and not evidence['records_verified']:
                evidence.update(status='unverified',failure_code='wp_recording_failed');full_pass=False
            if (BASE/'questionbank/data/challenges.jsonl').is_file():
                sys.path.insert(0,str(BASE/'questionbank'));import bank
                if task['id'] in {r['id'] for r in bank.load_rows()}:
                    with (BASE/'questionbank/verified-results.jsonl').open('a',encoding='utf-8') as stream:
                        stream.write(json.dumps({'task_id':task['id'],'case':case,'status':evidence['status'],'evidence_path':str(ledger),
                            'program_verified':full_pass,'platform_submission_verified':False,'at':time.time()})+'\n')
            write(ledger,evidence)
            print(json.dumps({k:evidence[k] for k in ['case','run_id','status','tool_calls','rea_worker_verified','challenge_verified','negative_control_verified','independent_replay_verified']}),flush=True)
            return evidence
        except Exception as e:
            evidence.update(status='failed',error=str(e),tool_calls=len(gateway.calls));write(ledger,evidence)
            if session and rid and (mc.get_run(session,rid) or {}).get('status') not in auto.FINAL_STATUS:
                mc.stop_run(session,rid)
            raise
        finally:
            if tunnel:tunnel.close()
            gateway.close()
            # Revoke the task capability even when the Worker or operator interrupted the run.
            (upload/'ctf_worker.json').unlink(missing_ok=True)

def main():
    ap=argparse.ArgumentParser();sub=ap.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare');p.add_argument('id');p.add_argument('--case',required=True)
    p=sub.add_parser('run');p.add_argument('--task-dir',required=True);p.add_argument('--case',required=True);p.add_argument('--budget',type=int,default=600);p.add_argument('--backend',choices=['muteki','codex'],default='codex');p.add_argument('--judge-config')
    a=ap.parse_args()
    if a.command=='prepare':print(json.dumps(prepare(a.id,a.case),ensure_ascii=False));return 0
    verifier=None
    if a.judge_config:
        cfg=json.loads(Path(a.judge_config).read_text(encoding='utf-8'))
        from ctf_worker_gateway import kali_program_verifier
        if cfg['kind']!='kali-program' or Path(cfg['artifact']).name!=cfg['artifact']:raise ValueError('invalid judge configuration')
        verifier=kali_program_verifier(a.case,Path(a.task_dir)/'attachments'/cfg['artifact'],cfg['success_stdout_regex'],cfg.get('expected_exit',0))
    result=run_task(a.task_dir,a.case,budget=a.budget,backend=a.backend,verifier=verifier)
    return 0 if result['status']=='verified' else 1
if __name__=='__main__':sys.exit(main())
