"""Behavior checks at the shared protocol, task store and provider adapters."""
import copy
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
from ctf_product import Product, TOOLS, handle, read, save
from ctf_client_adapter import CTFClient, AdapterError
import ctf_protocol as protocol


class FixtureProduct(Product):
    """Deterministic runtime fixture; actual core is checked separately."""
    def __init__(self, root):
        super().__init__(root)
        self.calls=[]
        self.fail_next=False
        self.timeout_next=False

    def catalog(self):
        names=['ctf_profile','math_gcd','kali_run','flag_format_check','ctfd_submit','ctf_runtime_status']
        return {'tools':[{'name':n,'description':n,'inputSchema':{'properties':{'case':{}}}} for n in names], 'version':{'release':'fixture'}}

    def core(self, tool, args):
        self.calls.append((tool, copy.deepcopy(args)))
        step=len(self.calls)
        receipt=self.root/'logs/calls'/f'{step}.json'
        if self.timeout_next and not tool.startswith('wp_'):
            self.timeout_next=False
            raise TimeoutError('No final runtime receipt')
        if self.fail_next and not tool.startswith('wp_'):
            self.fail_next=False
            result={'ok':False,'error':'actual dependency failure','error_code':'dependency_missing'}
        elif tool=='kali_run' and args.get('confirm') is not True:
            result={'ok':False,'error':'confirm=true required','error_code':'confirmation_required'}
        elif tool=='ctf_profile':result={'ok':True,'result':{'category':args['category']}}
        elif tool=='math_gcd':result={'ok':True,'result':{'result':math.gcd(*args['values'])}}
        elif tool=='ctfd_submit':result={'ok':True,'result':{'candidate_verified':True,'judge_status':'correct','challenge_id':7}}
        else:result={'ok':True,'result':{}}
        result.update(wp_record={'step':step}, evidence_path=str(receipt))
        save(receipt,result)
        return result


class PortableProtocol(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.product=FixtureProduct(Path(self.temp.name))
        self.transport_calls=[]
        def transport(request):
            self.transport_calls.append(copy.deepcopy(request))
            return handle(request,self.product)
        self.transport=transport
        self.client=CTFClient(transport)

    def tearDown(self):self.temp.cleanup()

    def call(self,name,arguments=None,client=None):
        result=(client or self.client).call(name,arguments)
        return result['structuredContent']

    def start(self):
        return self.call('ctf_start',{'title':'Self-built protocol fixture','description':'Compute gcd(48,60).','category':'crypto'})['task']['task_id']

    def triage(self,task):
        return self.call('ctf_analyze',{'task_id':task,'tool':'ctf_profile','arguments':{'category':'crypto'}})

    def calculate(self,task,request_id=None):
        args={'task_id':task,'tool':'math_gcd','arguments':{'values':[48,60]}}
        if request_id is not None:args['request_id']=request_id
        return self.call('ctf_analyze',args)

    def test_public_surface_is_same_for_each_provider(self):
        plain=self.client.tools()
        oa=self.client.tools('openai')
        ds=self.client.tools('deepseek')
        ant=self.client.tools('anthropic')
        self.assertEqual(len(plain),8)
        self.assertEqual(oa,ds)
        self.assertEqual([t['name'] for t in plain],[t['function']['name'] for t in oa])
        self.assertEqual([t['inputSchema'] for t in plain],[t['input_schema'] for t in ant])

    def test_contract_does_not_depend_on_model_name(self):
        a=self.call('ctf_system_status')['contract']
        b=self.call('ctf_system_status',client=CTFClient(self.transport))['contract']
        self.assertEqual(a,b)
        self.assertEqual(a['version'],protocol.VERSION)

    def test_early_solving_call_is_rejected_before_execution(self):
        task=self.start();count=len(self.product.calls)
        result=self.calculate(task)
        self.assertEqual(result['error_code'],'triage_required')
        self.assertEqual(len(self.product.calls),count)

    def test_real_profile_result_advances_workflow(self):
        task=self.start()
        self.assertEqual(self.triage(task)['workflow']['phase'],'analysis')
        result=self.calculate(task)
        self.assertEqual(result['execution']['result']['result'],12)
        self.assertEqual(result['workflow']['analysis_calls'],1)

    def test_another_provider_continues_same_task_and_evidence(self):
        task=self.start();self.triage(task);self.calculate(task)
        other=CTFClient(self.transport)
        block={'type':'tool_use','id':'claude-resume','name':'ctf_progress','input':{'task_id':task}}
        reply=other.anthropic_call(block)
        data=json.loads(reply['content'])['structuredContent']
        self.assertEqual(data['task']['task_id'],task)
        self.assertEqual(data['workflow']['analysis_calls'],1)
        self.assertEqual(len(data['task']['events']),2)
        self.assertFalse(reply['is_error'])

    def test_failure_blocks_next_execution_until_explicit_recovery(self):
        task=self.start();self.triage(task);self.product.fail_next=True
        failure=self.calculate(task)
        self.assertEqual(failure['workflow']['phase'],'needs_recovery')
        step=failure['workflow']['pending_error']['source_step']
        self.assertEqual(self.calculate(task)['error_code'],'recovery_required')
        self.call('ctf_note',{'task_id':task,'text':'A normal note','status':'todo'})
        self.assertEqual(self.calculate(task)['error_code'],'recovery_required')
        resolved=self.call('ctf_note',{'task_id':task,'text':'Dependency inspected; retry the operation once.','status':'todo','source_step':step,'resolve_error':True})
        self.assertEqual(resolved['workflow']['phase'],'analysis')
        self.assertTrue(self.calculate(task)['ok'])

    def test_wrong_failure_reference_cannot_unlock_workflow(self):
        task=self.start();self.triage(task);self.product.fail_next=True;self.calculate(task)
        result=self.call('ctf_note',{'task_id':task,'text':'wrong reference','source_step':999,'resolve_error':True})
        self.assertEqual(result['error_code'],'wrong_failure_step')
        self.assertEqual(self.calculate(task)['error_code'],'recovery_required')

    def test_diagnostic_success_does_not_erase_failure(self):
        task=self.start();self.triage(task);self.product.fail_next=True;self.calculate(task)
        result=self.call('ctf_call',{'task_id':task,'tool':'ctf_runtime_status'})
        self.assertTrue(result['ok'])
        self.assertEqual(result['workflow']['phase'],'needs_recovery')

    def test_request_retry_uses_receipt_without_reexecution(self):
        task=self.start();self.triage(task)
        first=self.calculate(task,'same-action');count=len(self.product.calls)
        second=self.calculate(task,'same-action')
        self.assertTrue(second['replayed'])
        self.assertEqual(len(self.product.calls),count)
        self.assertEqual(first['execution'],second['execution'])

    def test_request_id_conflict_cannot_execute_other_arguments(self):
        task=self.start();self.triage(task);self.calculate(task,'same-action')
        result=self.call('ctf_analyze',{'task_id':task,'tool':'math_gcd','arguments':{'values':[3,5]},'request_id':'same-action'})
        self.assertEqual(result['error_code'],'request_id_conflict')

    def test_failed_request_is_also_replayed_without_execution(self):
        task=self.start();self.triage(task);self.product.fail_next=True
        self.calculate(task,'failed-action');count=len(self.product.calls)
        again=self.calculate(task,'failed-action')
        self.assertFalse(again['ok']);self.assertTrue(again['replayed'])
        self.assertEqual(len(self.product.calls),count)

    def test_indeterminate_request_is_never_automatically_reexecuted(self):
        task=self.start();self.triage(task);self.product.timeout_next=True
        result=self.calculate(task,'interrupted-action')
        self.assertFalse(result['ok'])
        count=len(self.product.calls)
        again=self.calculate(task,'interrupted-action')
        self.assertEqual(again['error_code'],'request_indeterminate')
        self.assertEqual(len(self.product.calls),count)
        self.assertEqual(self.call('ctf_progress',{'task_id':task})['workflow']['phase'],'needs_recovery')

    def test_permission_confirmation_is_not_injected_by_adapter(self):
        task=self.start();self.triage(task)
        result=self.call('ctf_call',{'task_id':task,'tool':'kali_run','arguments':{'confirm':False}})
        self.assertFalse(result['ok'])
        self.assertEqual(result['execution']['error_code'],'confirmation_required')
        self.assertIs(self.product.calls[-1][1]['confirm'],False)

    def test_cross_task_arguments_are_rejected(self):
        task=self.start();self.triage(task)
        result=self.call('ctf_analyze',{'task_id':task,'tool':'math_gcd','arguments':{'case':'another','values':[1,2]}})
        self.assertFalse(result['ok'])
        self.assertIn('different task',result['error'])

    def test_no_execution_cannot_be_finished_as_completed_analysis(self):
        task=self.start()
        self.assertEqual(self.call('ctf_finish',{'task_id':task})['error_code'],'analysis_required')
        self.assertTrue(self.call('ctf_finish',{'task_id':task,'state':'blocked'})['ok'])

    def test_failure_cannot_be_finished_as_completed_analysis(self):
        task=self.start();self.triage(task);self.product.fail_next=True;self.calculate(task)
        self.assertEqual(self.call('ctf_finish',{'task_id':task})['error_code'],'recovery_required')

    def test_report_export_does_not_verify_answer(self):
        task=self.start();self.triage(task);self.calculate(task)
        result=self.call('ctf_finish',{'task_id':task})
        self.assertTrue(result['ok']);self.assertFalse(result['answer_verified'])
        self.assertEqual(result['workflow']['phase'],'analysis_complete_unverified')

    def test_platform_receipt_can_verify_answer(self):
        task=self.start();self.triage(task)
        result=self.call('ctf_call',{'task_id':task,'tool':'ctfd_submit','arguments':{'confirm':True}})
        self.assertTrue(result['answer_verified'])
        self.assertEqual(result['workflow']['phase'],'verified')

    def test_legacy_task_migration_does_not_fabricate_events(self):
        task=self.start();self.triage(task);self.calculate(task)
        path=self.product.folder(task)/'task.json';before=read(path)
        del before['workflow'];save(path,before)
        progress=self.call('ctf_progress',{'task_id':task})
        self.assertEqual(progress['workflow']['analysis_calls'],1)
        self.assertEqual(progress['task']['events'],before['events'])
        self.assertNotIn('workflow',read(path))

    def test_legacy_failures_remain_visible_without_inventing_recovery(self):
        task=self.start();self.triage(task);self.product.fail_next=True;self.calculate(task)
        path=self.product.folder(task)/'task.json';before=read(path)
        del before['workflow'];save(path,before)
        progress=self.call('ctf_progress',{'task_id':task})
        self.assertEqual(progress['workflow']['phase'],'needs_recovery')
        self.assertEqual(progress['workflow']['pending_error']['error'],'actual dependency failure')
        self.assertEqual(progress['task']['events'],before['events'])
        self.assertEqual(self.calculate(task)['error_code'],'recovery_required')

    def test_malformed_public_arguments_fail_before_runtime(self):
        count=len(self.product.calls)
        result=self.call('ctf_system_status',{'deep':'false'})
        self.assertFalse(result['ok'])
        self.assertEqual(len(self.product.calls),count)

    def test_native_tool_names_cannot_be_dispatched_by_ctf_adapter(self):
        self.client.tools();count=len(self.transport_calls)
        with self.assertRaises(AdapterError):self.client.call('pwsh',{'command':'anything'})
        self.assertEqual(len(self.transport_calls),count)

    def test_malformed_provider_json_is_rejected_without_dispatch(self):
        with self.assertRaises(AdapterError):
            self.client.openai_call({'id':'x','function':{'name':'ctf_start','arguments':'{broken'}})
        self.assertEqual(self.transport_calls,[])

    def test_tool_name_prefixes_resolve_to_same_canonical_operation(self):
        a=self.call('mcp__ctf_system__ctf_system_status')['contract']
        b=self.call('mcp__ctf-system__ctf_system_status')['contract']
        self.assertEqual(a,b)

    def test_provider_error_reply_keeps_structured_failure(self):
        task=self.start()
        call={'id':'early','function':{'name':'ctf_analyze','arguments':json.dumps({'task_id':task,'tool':'math_gcd','arguments':{'values':[1,2]}})}}
        reply=self.client.openai_call(call)
        result=json.loads(reply['content'])
        self.assertTrue(result['isError'])
        self.assertEqual(result['structuredContent']['error_code'],'triage_required')

    def test_provider_call_id_becomes_reusable_execution_id(self):
        task=self.start();self.triage(task)
        call={'id':'provider-stable-id','function':{'name':'ctf_analyze','arguments':json.dumps({'task_id':task,'tool':'math_gcd','arguments':{'values':[48,60]}})}}
        self.client.openai_call(call);count=len(self.product.calls)
        again=json.loads(self.client.openai_call(call)['content'])['structuredContent']
        self.assertTrue(again['replayed'])
        self.assertEqual(len(self.product.calls),count)


if __name__=='__main__':unittest.main()
