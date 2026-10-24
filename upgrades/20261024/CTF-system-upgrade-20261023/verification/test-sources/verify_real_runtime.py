"""A real stdio/core/WP round trip across provider envelopes, without model calls."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from ctf_client_adapter import CTFClient, StdioTransport

client=CTFClient(StdioTransport(ROOT))
checks=[]
def check(name,condition):
    checks.append({'name':name,'passed':bool(condition)})
    if not condition:raise AssertionError(name)

def call(name,args=None,using=client):
    return using.call(name,args)['structuredContent']

oa=client.tools('deepseek');other=CTFClient(StdioTransport(ROOT));ant=other.tools('anthropic')
check('same_provider_neutral_schemas',[t['function']['parameters'] for t in oa]==[t['input_schema'] for t in ant])
status=call('ctf_system_status')
check('real_109_tool_catalog',status['registered_tools']==109)
started=call('ctf_start',{'title':'Portable protocol self-test','description':'Offline arithmetic and provider-envelope handoff; no challenge service or model inference.','category':'crypto'})
task=started['task']['task_id']
check('server_requires_triage',call('ctf_analyze',{'task_id':task,'tool':'math_gcd','arguments':{'values':[48,60]}}).get('error_code')=='triage_required')
check('real_profile',call('ctf_analyze',{'task_id':task,'tool':'ctf_profile','arguments':{'category':'crypto'}})['workflow']['phase']=='analysis')
calc=call('ctf_analyze',{'task_id':task,'tool':'math_gcd','arguments':{'values':[48,60],'wp_purpose':'Verify the shared runtime.'},'request_id':'real-gcd'})
check('actual_gcd_output',calc['execution']['result']['result']==12)
check('actual_wp_evidence',Path(calc['execution']['wp_record']['path']).is_file())
again=call('ctf_analyze',{'task_id':task,'tool':'math_gcd','arguments':{'values':[48,60],'wp_purpose':'Verify the shared runtime.'},'request_id':'real-gcd'})
check('same_request_returns_same_evidence',again['replayed'] and again['execution']['wp_record']==calc['execution']['wp_record'])
failure=call('ctf_analyze',{'task_id':task,'tool':'math_modinv','arguments':{'a':2,'mod':4,'wp_purpose':'Verify real failure handling.'}})
check('actual_noninvertible_error',failure['ok'] is False and failure['workflow']['phase']=='needs_recovery')
resume=other.anthropic_call({'type':'tool_use','id':'real-resume','name':'ctf_progress','input':{'task_id':task}})
resumed=json.loads(resume['content'])['structuredContent']
check('other_provider_sees_same_failure',resumed['workflow']['pending_error']==failure['workflow']['pending_error'])
blocked=call('ctf_analyze',{'task_id':task,'tool':'math_gcd','arguments':{'values':[4,6]}})
check('failure_blocks_further_execution',blocked.get('error_code')=='recovery_required')
step=failure['workflow']['pending_error']['source_step']
recovery={'task_id':task,'text':'2 has no inverse modulo 4; retain the failed evidence and continue with valid arithmetic.','status':'todo','resolve_error':True}
if step is not None:recovery['source_step']=step
check('real_recovery_note',call('ctf_note',recovery)['workflow']['phase']=='analysis')
check('analysis_after_recovery',call('ctf_analyze',{'task_id':task,'tool':'math_gcd','arguments':{'values':[4,6]}})['ok'])
finished=call('ctf_finish',{'task_id':task,'state':'analysis_complete','include_images':False,'summary':'Self-built interface verification; no model inference or competition answer.'})
check('report_does_not_claim_verified_answer',finished['ok'] and not finished['answer_verified'])
report={'passed':all(c['passed'] for c in checks),'checks':checks,'task_id':task,
        'source_root':str(ROOT),'contract':status['contract'],
        'scope':'Real stdio entry, core tools, shared task state and WP receipts; provider envelopes only, no live AI/model calls.'}
(ROOT/'real-runtime-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print(json.dumps(report,ensure_ascii=False))
