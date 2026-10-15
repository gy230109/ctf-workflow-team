"""Team CTF workflow component. See README.md for configuration and verified scope."""
import hashlib,hmac,json,secrets,subprocess,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import ctf_os

class CaseGateway:
    def __init__(self,case,artifacts,verifier=None,max_calls=20,lifetime=900):
        self.case=case;self.artifacts={k:Path(v).resolve(strict=True) for k,v in artifacts.items()}
        self.verifier=verifier;self.token=secrets.token_urlsafe(32);self.deadline=time.monotonic()+lifetime
        self.max_calls=max_calls;self.calls=[];self.lock=threading.Lock()
        self.hashes={k:hashlib.sha256(p.read_bytes()).hexdigest() for k,p in self.artifacts.items()}
        state=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def do_POST(self):
                if not hmac.compare_digest(self.headers.get('X-CTF-Case-Token',''),state.token):
                    return self.send(401,{'ok':False,'error':'case credential required'})
                if self.path!='/call':return self.send(404,{'ok':False})
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    if not 0<length<=65536:raise ValueError('request size outside bound')
                    request=json.loads(self.rfile.read(length));result=state.call(request)
                    self.send(200,result)
                except (ValueError,KeyError,TypeError) as e:self.send(400,{'ok':False,'error':str(e)})
            def send(self,status,obj):
                body=json.dumps(obj,ensure_ascii=False).encode();self.send_response(status)
                self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
                self.end_headers();self.wfile.write(body)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)

    @property
    def port(self):return self.server.server_address[1]
    def start(self):self.thread.start();return self
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(timeout=3)
    def artifact(self,name):
        p=self.artifacts[name]
        if hashlib.sha256(p.read_bytes()).hexdigest()!=self.hashes[name]:raise ValueError('artifact changed since preparation')
        return p
    def call(self,request):
        if not isinstance(request,dict):raise ValueError('request must be an object')
        if time.monotonic()>self.deadline:raise ValueError('case gateway expired')
        with self.lock:
            if len(self.calls)>=self.max_calls:raise ValueError('case tool budget exhausted')
            name=request.get('tool');args=request.get('args',{})
            if not isinstance(args,dict):raise ValueError('args must be an object')
            started=time.time()
            record={'tool':name,'args':args,'started_at':started}
            self.calls.append(record)
            try:
                if name=='ctf_profile':
                    if set(args)-{'artifact','category'}:raise ValueError('unsupported profile parameters')
                    call={'category':args.get('category','reverse'),'wp_case':self.case}
                    if args.get('artifact'):call['local_file']=str(self.artifact(args['artifact']))
                    result=ctf_os.call_tool(name,call)
                elif name in {'rea_status','rea_ops'}:
                    if args:raise ValueError('status/ops take no Worker arguments')
                    result=ctf_os.call_tool(name,{'wp_case':self.case})
                elif name=='rea_run':
                    if set(args)-{'command','artifact','address','timeout'}:raise ValueError('unsupported REA parameters')
                    command=args.get('command')
                    if command not in {'inspect','function','inspect-managed-members'}:raise ValueError('REA operation outside this case capability')
                    argv=[str(self.artifact(args['artifact']))]
                    if command=='function':
                        address=str(args.get('address',''))
                        import re
                        if not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{1,16}',address):raise ValueError('function requires a file VA')
                        argv.append(address)
                    result=ctf_os.call_tool(name,{'command':command,'args':argv,'timeout':min(300,max(5,int(args.get('timeout',180)))),'wp_case':self.case})
                elif name in {'kali_file','kali_strings','kali_objdump','reverse_binary_info'}:
                    if set(args)-{'artifact','opts','timeout'}:raise ValueError('unsupported artifact parameters')
                    call={'local_file':str(self.artifact(args['artifact'])),'case':self.case,'wp_case':self.case,'timeout':min(120,max(5,int(args.get('timeout',60))))}
                    if args.get('opts'):
                        if name!='kali_objdump' or args['opts'] not in {'-d','-d -M intel','-s','-t','-h'}:raise ValueError('unsupported objdump option')
                        call['opts']=args['opts']
                    result=ctf_os.call_tool(name,call)
                elif name=='verify_candidate':
                    if not self.verifier:raise ValueError('real verifier not configured for this challenge')
                    if set(args)!={'candidate'}:raise ValueError('candidate is the only verifier parameter')
                    value=args['candidate']
                    if not isinstance(value,str) or not 1<=len(value)<=256 or '\x00' in value:raise ValueError('invalid candidate')
                    for artifact_name in self.artifacts:self.artifact(artifact_name)
                    result=self.verifier(value)
                    # This receipt is local and private. It records actual process output.
                    evidence=ctf_os.GM_BASE/'logs/calls'/('worker-verify-'+secrets.token_hex(8)+'.json')
                    result.update(tool=name,evidence_path=str(evidence))
                    evidence.parent.mkdir(parents=True,exist_ok=True)
                    evidence.write_text(json.dumps({'args':args,'response':result},ensure_ascii=False,indent=2),encoding='utf-8')
                    if ctf_os.writeup.exists(self.case):result['wp_record']=ctf_os.writeup.record_call(self.case,args,result)
                else:raise ValueError('tool outside this case capability')
                record.update(ok=result.get('ok',False),evidence_path=result.get('evidence_path'),response=result)
                return result
            except Exception as e:
                result={'ok':False,'error':str(e),'tool':name};record.update(ok=False,response=result);return result
            finally:record['duration_seconds']=round(time.time()-started,3)

def pe_verifier(path,expected_flag_sha256):
    """Only for a maintainer-built or explicitly trusted local executable."""
    p=Path(path).resolve(strict=True);digest=hashlib.sha256(p.read_bytes()).hexdigest()
    def verify(candidate):
        if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError('verifier executable changed')
        process=subprocess.run([str(p)],input=(candidate+'\n').encode(),capture_output=True,timeout=8,cwd=p.parent)
        stdout=process.stdout.decode('utf-8','replace');stderr=process.stderr.decode('utf-8','replace')
        output=stdout.strip()
        accepted=process.returncode==0 and hashlib.sha256(output.encode()).hexdigest()==expected_flag_sha256
        executed=process.returncode in (0,1)
        return {'ok':executed,'program_executed':True,'accepted':accepted if executed else None,'returncode':process.returncode,'stdout':stdout,'stderr':stderr,
            'verification':'actual_challenge_process_and_independent_output_hash','artifact_sha256':digest}
    return verify


def kali_program_verifier(case,path,success_stdout_regex,expected_exit=0):
    """Replay only the selected original program inside the existing Kali VM."""
    import ctf_os_runtime as runtime,re
    p=Path(path).resolve(strict=True);digest=hashlib.sha256(p.read_bytes()).hexdigest()
    success=re.compile(success_stdout_regex)
    # A structured envelope distinguishes launch failure from a real negative control.
    code='''import json,os,pathlib,platform,subprocess,sys
p=pathlib.Path(sys.argv[1]); data=p.read_bytes()[:20]; result={"program_executed":False}
try:
    if data[:4]==b"\\x7fELF":
        machine=int.from_bytes(data[18:20],"little" if data[5]==1 else "big")
        required={3:"i386",62:"x86_64",40:"arm",183:"aarch64"}.get(machine)
        if required!=platform.machine():raise RuntimeError("architecture mismatch: "+str(required)+" vs "+platform.machine())
    os.chmod(p,0o700)
    r=subprocess.run([str(p.resolve())],input=(sys.argv[2]+"\\n").encode(),capture_output=True,timeout=8)
    result.update(program_executed=True,returncode=r.returncode,stdout=r.stdout.decode("utf-8","replace"),stderr=r.stderr.decode("utf-8","replace"))
except (OSError,RuntimeError,subprocess.TimeoutExpired) as error:
    result.update(error_code="program_environment_failed",error=str(error))
print(json.dumps(result))
'''
    def verify(candidate):
        if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError('original verifier artifact changed')
        run=runtime.kali_execute({'case':case,'timeout':15},['python3','-c',code,'../input/'+p.name,candidate],local=str(p))
        try:program=json.loads(run.get('stdout','')) if not runtime.failed(run) else {}
        except (ValueError,TypeError):program={}
        if not isinstance(program,dict):program={}
        executed=isinstance(program,dict) and program.get('program_executed') is True
        valid=executed and program.get('returncode') in {expected_exit,1}
        accepted=(program.get('returncode')==expected_exit and bool(success.search(program.get('stdout','')))) if valid else None
        return {'ok':valid,'program_executed':executed,'accepted':accepted,
            'error_code':None if valid else program.get('error_code','verification_execution_failed'),
            'error':None if valid else program.get('error','Program did not finish with a configured accept/reject exit code'),
            'returncode':program.get('returncode'),'stdout':program.get('stdout',''),'stderr':program.get('stderr',''),
            'artifact_sha256':digest,'verification':'original_program_in_kali','execution':run}
    return verify
