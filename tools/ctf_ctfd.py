"""Team CTF workflow component. See README.md for configuration and verified scope."""
import hashlib,json,os,re,secrets
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin,urlsplit,unquote
import requests

BASE=Path(__file__).resolve().parents[1]
CONFIG=BASE/'config/ctfd.local.json'

def settings():
    if not CONFIG.is_file():raise ValueError('CTFd is not configured on this machine')
    cfg=json.loads(CONFIG.read_text(encoding='utf-8-sig'))
    if cfg.get('enabled') is not True:raise ValueError('CTFd connector is disabled')
    return cfg

def number(value):
    if isinstance(value,bool) or not re.fullmatch(r'[1-9][0-9]{0,9}',str(value)):raise ValueError('A positive CTFd challenge_id is required')
    return int(value)

def catalog():
    path=BASE/'config/ctfd_catalog.local.json'
    return json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}

def binding_folder(case):
    if not isinstance(case,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',case):raise ValueError('A case/task identifier is required')
    product=BASE/'.local/ctf-system/tasks'/case
    return product if (product/'task.json').is_file() else BASE/'.local/ctfd/cases'/case

def save(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+secrets.token_hex(5)+'.tmp')
    temp.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(temp,path)

class Client:
    def __init__(self):
        self.cfg=settings();self.url=self.cfg['base_url'].rstrip('/')
        parsed=urlsplit(self.url)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:raise ValueError('Invalid configured CTFd URL')
        credential=json.loads(Path(self.cfg['player_credential_file']).read_text(encoding='utf-8-sig'))
        if credential.get('role')!='user' or credential.get('origin')!=self.url:raise ValueError('The connector only accepts a player credential for this CTFd origin')
        self.s=requests.Session();self.s.trust_env=False
        # CTFd 3.8.x dispatches token authentication for JSON requests, including
        # GET. Explicit content type is needed before any session cookie exists.
        self.s.headers.update({'Authorization':'Token '+credential['token'],'Content-Type':'application/json','User-Agent':'CTF-System-CTFd/1'})
        me=self.request('GET','/api/v1/users/me')
        # CTFd 3.8.8 deliberately omits type from /users/me. Prove the account
        # lacks management access without reading any configuration response.
        probe=self.s.get(self.url+'/api/v1/configs?key=ctf_name',timeout=(4,10),allow_redirects=False,stream=True)
        try:restricted=probe.status_code==403
        finally:probe.close()
        if me.get('id')!=credential['user_id'] or not restricted:raise ValueError('Live account role mismatch: a non-admin player is required')
        self.me=me
    def request(self,method,path,**kwargs):
        if not path.startswith('/api/v1/') or path.startswith('/api/v1/flags') or path.startswith('/api/v1/solutions'):
            raise ValueError('Endpoint outside the player connector')
        r=self.s.request(method,self.url+path,timeout=(4,15),allow_redirects=False,**kwargs)
        if r.status_code in (301,302,303,307,308):raise ValueError('Unexpected CTFd redirect; no credentials forwarded')
        r.raise_for_status();value=r.json()
        if value.get('success') is not True:raise ValueError('CTFd rejected the request')
        return value.get('data')
    def challenge(self,identifier):
        cid=number(identifier);data=self.request('GET','/api/v1/challenges/'+str(cid))
        # Never expose solution IDs/rendered admin views or arbitrary plugin fields.
        result={k:data.get(k) for k in ('id','name','category','description','value','files','tags','hints','max_attempts','attempts','solved_by_me')}
        result.update(source='CTFd',grading_configured=catalog().get(str(cid),{}).get('grading_configured'),challenge_url=self.url+'/challenges#'+str(cid))
        return result
    def close(self):self.s.close()

def with_client(fn):
    @wraps(fn)
    def wrapped(args):
        client=Client()
        try:return fn(client,args)
        except requests.RequestException as e:
            # Requests exceptions may include Authorization-independent URLs; do
            # not serialize the session, token file or response bodies here.
            return {'ok':False,'error':'CTFd network/API request failed: '+type(e).__name__,'error_code':'ctfd_request_failed'}
        finally:client.close()
    return wrapped

@with_client
def status(client,a):
    return {'ok':True,'url':client.url,'player':{'id':client.me['id'],'name':client.me.get('name'),'role':'user'},'reference_answers_exposed':False,
        'practice_challenges':sum(not x.get('test_fixture',False) for x in catalog().values()),'verification_scope':'Player API authentication only; not a solved challenge'}

@with_client
def listing(client,a):
    limit=a.get('limit',30)
    if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=200:raise ValueError('limit must be 1..200')
    rows=client.request('GET','/api/v1/challenges')
    query=str(a.get('query','')).casefold();category=a.get('category')
    filtered=[r for r in rows if query in (str(r.get('name',''))+' '+str(r.get('category',''))).casefold() and (not category or r.get('category')==category)]
    result=[]
    for row in filtered[:limit]:
        item={k:row.get(k) for k in ('id','name','category','value','solved_by_me','solves')}
        item['grading_configured']=catalog().get(str(row['id']),{}).get('grading_configured');result.append(item)
    return {'ok':True,'challenges':result,'matched':len(filtered),'returned':len(result)}

@with_client
def challenge(client,a):return {'ok':True,'challenge':client.challenge(a['challenge_id'])}

def intake(client,identifier,destination):
    data=client.challenge(identifier);folder=Path(destination);folder.mkdir(parents=True,exist_ok=False);files=[];names=set();total=0
    links=data.get('files') or []
    if len(links)>20:raise ValueError('At most 20 handouts per intake')
    for link in links:
        absolute=urljoin(client.url+'/',link)
        u=urlsplit(absolute);base=urlsplit(client.url)
        if (u.scheme,u.netloc)!=(base.scheme,base.netloc) or not u.path.startswith('/files/') or u.username or u.password:raise ValueError('Handout URL outside configured CTFd files origin')
        name=unquote(u.path.rsplit('/',1)[-1])
        if not name or name in ('.','..') or any(c in name for c in '/\\:\x00') or len(name)>180:raise ValueError('Unsafe handout filename')
        if name.casefold() in names:raise ValueError('Duplicate handout filename')
        names.add(name.casefold());path=folder/name;tmp=path.with_suffix(path.suffix+'.download')
        r=client.s.get(absolute,timeout=(4,30),stream=True,allow_redirects=False)
        try:
            if r.status_code!=200:raise ValueError('Handout was not returned directly by CTFd')
            h=hashlib.sha256();size=0
            with tmp.open('xb') as f:
                for chunk in r.iter_content(1048576):
                    size+=len(chunk);total+=len(chunk)
                    if size>256*1048576 or total>512*1048576:raise ValueError('Handout byte budget exceeded')
                    f.write(chunk);h.update(chunk)
            tmp.replace(path);files.append({'name':name,'path':str(path),'sha256':h.hexdigest(),'bytes':size})
        finally:r.close();tmp.unlink(missing_ok=True)
    data['attachments']=files
    return data

def download_for_start(identifier):
    client=Client()
    try:return intake(client,identifier,BASE/'.local/ctfd/intake'/secrets.token_hex(12))
    finally:client.close()

def bind(case,data):
    value={'challenge_id':data['id'],'name':data['name'],'origin':settings()['base_url'].rstrip('/'),'grading_configured':data.get('grading_configured'),'handouts':data.get('attachments',[])}
    save(binding_folder(case)/'ctfd-source.json',value)
    return value

@with_client
def download(client,a):
    case=a.get('wp_case') or a.get('case');folder=binding_folder(case)
    source=folder/'ctfd-source.json'
    if source.exists():
        old=json.loads(source.read_text(encoding='utf-8'))
        if old['challenge_id']!=number(a['challenge_id']):raise ValueError('This case is already bound to another CTFd challenge')
    data=intake(client,a['challenge_id'],BASE/'.local/ctfd/intake'/secrets.token_hex(12));bind(case,data)
    return {'ok':True,'challenge':data,'next':'Prefer ctf_start with ctfd_challenge_id to create a task with these original handouts automatically.'}

@with_client
def submit(client,a):
    if a.get('confirm') is not True:raise ValueError('confirm=true required')
    cid=number(a['challenge_id']);case=a.get('wp_case') or a.get('case');folder=binding_folder(case)
    source=folder/'ctfd-source.json'
    if not source.is_file():raise ValueError('Use ctf_start with ctfd_challenge_id before submitting')
    bound=json.loads(source.read_text(encoding='utf-8'))
    if bound['challenge_id']!=cid or bound['origin']!=client.url:raise ValueError('Submission differs from the case binding')
    if catalog().get(str(cid),{}).get('grading_configured') is False:return {'ok':False,'error':'This imported challenge has no verified grading rule; submission was not sent','error_code':'judge_not_configured'}
    value=a.get('submission_flag')
    if not isinstance(value,str) or not 1<=len(value)<=4096 or '\x00' in value:raise ValueError('submission_flag must be a bounded string')
    key=hashlib.sha256((str(cid)+'\0'+value).encode()).hexdigest();receipt=folder/'ctfd-submissions'/(key+'.json')
    if receipt.exists():return dict(json.loads(receipt.read_text(encoding='utf-8')),replayed_receipt=True)
    # Reserve before POST. A network failure must not cause an automatic repeat.
    receipt.parent.mkdir(parents=True,exist_ok=True)
    try:
        claim=os.open(receipt.with_suffix('.claimed'),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(claim)
    except FileExistsError:return {'ok':False,'error_code':'submission_outcome_unknown','challenge_id':cid,'candidate_verified':False}
    save(receipt,{'ok':False,'error_code':'submission_outcome_unknown','challenge_id':cid,'candidate_verified':False})
    try:data=client.request('POST','/api/v1/challenges/attempt',json={'challenge_id':cid,'submission':value})
    except requests.RequestException:return {'ok':False,'error':'Submission outcome unknown; inspect CTFd attempts before retrying','error_code':'submission_outcome_unknown'}
    state=data.get('status');result={'ok':state in ('correct','incorrect','already_solved'),'challenge_id':cid,'judge_status':state,
        'candidate_verified':state=='correct','platform_previously_solved':state=='already_solved','judge':'CTFd player submission API','submission_sha256':key}
    if not result['ok']:result.update(error='CTFd did not judge this submission',error_code='ctfd_'+str(state))
    save(receipt,result);return result

@with_client
def scoreboard(client,a):
    rows=client.request('GET','/api/v1/scoreboard')
    return {'ok':True,'standings':[{k:r.get(k) for k in ('pos','account_id','name','score')} for r in rows[:100]]}

S={'type':'string'};I={'type':'integer'};B={'type':'boolean'}
SPECS={
 'ctfd_status':(status,'CTFd 普通选手 API 和本机题库接入状态，不读取管理员答案',{}),
 'ctfd_list':(listing,'浏览 CTFd 题单；显式区分已配置判题与仅导入题面',{'query':S,'category':S,'limit':I}),
 'ctfd_challenge':(challenge,'读取 CTFd 选手可见题面和附件链接，不读取题解或 flag 配置',{'challenge_id':I}),
 'ctfd_download':(download,'下载同源题目附件并校验摘要；一般优先 ctf_start(ctfd_challenge_id=...) 自动建档',{'challenge_id':I,'case':S}),
 'ctfd_submit':(submit,'提交本题候选给 CTFd 实际判题；需 confirm=true，只采信服务端 correct 回执',{'challenge_id':I,'case':S,'submission_flag':S,'confirm':B}),
 'ctfd_scoreboard':(scoreboard,'读取 CTFd 积分榜；不据此评价模型能力',{})}
TOOLS={name:(fn,desc,{'type':'object','properties':props,'required':['challenge_id'] if 'challenge_id' in props else []}) for name,(fn,desc,props) in SPECS.items()}
DANGEROUS={'ctfd_submit'}
