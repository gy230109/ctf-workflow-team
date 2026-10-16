"""Team CTF workflow component. See README.md for configuration and verified scope."""
import hashlib
import contextlib
import json
from pathlib import Path
import re
import sqlite3
import time

BASE = Path(__file__).resolve().parents[1]
DB = BASE / '.local/ctf-system/task-health.sqlite3'


@contextlib.contextmanager
def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute('CREATE TABLE IF NOT EXISTS calls(id INTEGER PRIMARY KEY,case_id TEXT,at REAL,tool TEXT,signature TEXT,outcome TEXT,ok INTEGER,ms REAL,expected INTEGER)')
    c.execute('CREATE INDEX IF NOT EXISTS case_calls ON calls(case_id,id)')
    try:
        with c:yield c
    finally:c.close()


def case_id(a):
    value = a.get('wp_case') or a.get('case')
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,99}', value):
        raise ValueError('Provide this task case/wp_case')
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def outcome(result):
    value=result.get('result')
    if isinstance(value,dict) and isinstance(value.get('data'),dict):value=value['data']
    volatile={'evidence_artifacts','artifact','artifact_path','artifact_fetch','execution','run_id','guest_log',
              'started_at_utc','duration_seconds','transport_seconds','duration_ms','evidence_path','wp_record','wp_operation'}
    def stable(x):
        if isinstance(x,dict):return {k:stable(v) for k,v in x.items() if k not in volatile}
        if isinstance(x,list):return [stable(v) for v in x]
        return x
    return digest([result.get('ok'),stable(value),result.get('error_code')])


def observe(case, tool, args, result):
    a = {k:v for k,v in args.items() if k not in {'case','wp_case','wp_purpose','wp_expectation','wp_repeat_expected'}}
    for k in ('local_file','wordlist_file'):
        if isinstance(a.get(k), str):
            p = Path(a[k])
            if p.is_file():
                with p.open('rb') as f:
                    a[k] = {'sha256':hashlib.file_digest(f, 'sha256').hexdigest()}
    expected = (args.get('wp_repeat_expected') is True or tool.endswith(('_status','_progress','_scoreboard'))
                or tool == 'ctf_task_health' or args.get('action') == 'status'
                or tool in {'kali_debug_session','win_debug_call','web_browser_session'})
    # Persist hashes and totals, never raw arguments, output, credentials or candidates.
    with connect() as c:
        c.execute('INSERT INTO calls(case_id,at,tool,signature,outcome,ok,ms,expected) VALUES(?,?,?,?,?,?,?,?)',
                  (case,time.time(),tool,digest([tool,a]),outcome(result),
                   bool(result.get('ok')),float(result.get('duration_ms') or 0),expected))
    return status({'case':case})


def status(a):
    case = case_id(a)
    with connect() as c:
        total = c.execute('SELECT count(*) n,coalesce(sum(ms),0) ms,sum(CASE WHEN ok=0 THEN 1 ELSE 0 END) failures FROM calls WHERE case_id=?',(case,)).fetchone()
        rows = c.execute('SELECT * FROM calls WHERE case_id=? ORDER BY id DESC LIMIT 12',(case,)).fetchall()
    warnings=[]
    if rows and not rows[0]['expected']:
        same=sum(r['signature']==rows[0]['signature'] and r['outcome']==rows[0]['outcome'] and not r['expected'] for r in rows)
        if same>=3:
            warnings.append({'code':'repeated_same_result','count':same,'tool':rows[0]['tool'],
                             'action':'相同参数与结果已重复；检查已有证据，换假设或交接。正常复查可注明 wp_repeat_expected=true。'})
    streak=0
    for r in rows:
        if r['expected']:continue
        if r['ok']:break
        streak+=1
    if streak>=3:warnings.append({'code':'consecutive_failures','count':streak,'action':'读取实际错误并修复依赖、参数或假设，再继续调用。'})
    if total['n']>=80:warnings.append({'code':'call_budget_notice','action':'本题已超过 80 次调用，整理进展并决定是否交接。'})
    if total['ms']>=1800000:warnings.append({'code':'time_budget_notice','action':'本题累计工具执行超过 30 分钟，检查收益与下一步。'})
    return {'ok':True,'case':case,'calls':total['n'],'failed_calls':total['failures'] or 0,
            'active_tool_seconds':round(total['ms']/1000,3),'recent_failure_streak':streak,'warnings':warnings,
            'policy':'advisory_only','execution_blocked':False,'model_tokens':None,'model_cost':None,
            'scope':'仅统计经过本系统的新调用；不含模型推理时间或费用，不证明答案正确。'}


TOOLS={'ctf_task_health':(status,'读取本题调用次数、工具耗时、连续失败和重复结果提示；不阻断任务，模型费用未知。',
       {'type':'object','properties':{'case':{'type':'string'}},'required':[]})}
