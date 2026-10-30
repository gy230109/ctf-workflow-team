"""Purge redteam data and playbooks inside the existing CTF execution path."""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
INTEGRATION = BASE / 'integrations/purge-redteam'
READ_OPS = ['snapshot','assets','asset','graph','attackGraph','stats','vulns','vulnStats',
    'credentials','access','sessions','webshells','tunnels','domains','web','httpEvidence',
    'chain','scores','scoreChain','scoreReport','activeTests','testStats','consoleDigest',
    'stages','reportTargets','discoveryTimeline','pocSearch','pocList','pocGet','pocStats',
    'prompts','shots','shotData','attackFiles','readAttackFile','templateSearch','templateStats','platformConfigGet']
WRITE_OPS = ['assetAdd','assetLink','addVuln','updateVuln','addCredential','addAccess',
    'addWebshell','updateWebshell','addTunnel','updateTunnel','addHttpEvidence',
    'addChainStep','assetTest','assessAsset','saveScorePoint','addScoreHit','saveStage',
    'pocSave','pocUpdate','pocUse','pocDelete','shotAdd','shotDelete','addAttackFile',
    'import','savePrompt','resetPrompts','deleteScorePoint','platformConfigSave','platformAssignToolkit']
ROUTES = {
 'web': ['web_http_inspect','web_html_parse','web_jwt_decode','web_browser_session','audit_semgrep','audit_gitleaks','web_nuclei_audit'],
 'pwn': ['pwn_elf_info','pwn_cyclic','pwn_rop_search','kali_debug_session','qemu_run'],
 'reverse': ['reverse_binary_info','reverse_disassemble','rea_run','reverse_symbolic','win_debug_tools'],
 'crypto': ['crypto_diagnose','crypto_attack','crypto_factor','crypto_crt','crypto_z3','crypto_lll','crypto_aes_decrypt'],
 'misc': ['misc_file_inspect','misc_archive_list','misc_image_inspect','misc_stego','cracktools_run'],
 'forensics': ['forensics_pcap','forensics_pcap_summary','forensics_volatility'],
 'mobile': ['reverse_binary_info','misc_archive_list','audit_semgrep'],
 'unknown': ['ctf_profile','misc_file_inspect']
}

def plan_for(root, task):
    from ctf_wp_policy import contract
    modules = contract()['modules']
    category = task.get('category', 'unknown')
    return {'enabled': True, 'adapter_version': '0.2.0', 'case': task['task_id'],
        'mode': 'ctf-first',
        'deliverable': 'ctf_finish 导出的 WP（md/html/docx）。本系统是 CTF 系统，不产出渗透测试报告。',
        'redteam_role': 'fully-integrated', 'modules': modules,
        'category': category,
        'candidate_execution_tools': ROUTES.get(category, ROUTES['unknown']),
        'routing_hints_are_allowlists': False,
        'redteam_discovery': 'ctf_tools(query=redteam_) discovers all fused interfaces; select by evidence and actual dependencies, not by an auxiliary-only label.',
        'flow': ['保留原题与附件，完成 ctf_plan',
                 '用 ctf_analyze(tool=ctf_profile) 确认题型与依赖',
                 '融合传统CTF与破甲能力，按证据选择工具、POC、工具链或角色协作，经统一入口执行',
                 '破甲能力可承担主力；需要的记录关联source_step，关键合适页面同步保留真实截图',
                 '按需 ctf_checkpoint；没解出来就如实记 blocked / needs_input',
                 '用原程序或平台验证答案，经 ctf_finish 导出 WP'],
        'workflow_selection': '按本题需要选择单工具、完整工具链、阶段流程或角色协作，以获得并验证flag为准。',
        'role_policy': '需要专业分工、并行路线或交叉验证时可选角色协作；不限定于内网/多主机题，是否采用由题目需要、时限及成本决定。',
        'storage_isolation': 'one engagement per CTF task; original shared POC knowledge retained',
        'limits': '工具清单和原仓库资料不代表依赖已安装或题目已解；不改变宿主审批、网络范围或答案验证。'}

def _case(args):
    if args.get('case') and args.get('wp_case') and args['case'] != args['wp_case']:
        raise ValueError('A redteam operation cannot use evidence from a different task.')
    case = args.get('case') or args.get('wp_case')
    if not isinstance(case, str) or not re.fullmatch(r'ctf-[a-f0-9]{16}', case):
        raise ValueError('Use the task_id returned by ctf_start.')
    folder = BASE / '.local/ctf-system/tasks' / case
    if not (folder / 'task.json').is_file():
        raise ValueError('The CTF task does not exist in this installation.')
    return case

def _existing_names():
    for key in ('ctf_os', '__main__'):
        module = sys.modules.get(key)
        if module is not None and isinstance(getattr(module, 'ALL_TOOLS', None), dict):
            return set(module.ALL_TOOLS)
    # Public MCP handlers can run without ctf_os loaded in this interpreter.
    # Resolve the owned registry instead of interpreting that as zero tools.
    import importlib
    module = importlib.import_module('ctf_os')
    registry = getattr(module, 'ALL_TOOLS', None)
    if not isinstance(registry, dict) or not registry:
        raise RuntimeError('Current CTF tool registry is unavailable; capability inventory is unknown.')
    return set(registry)

def capabilities(args):
    manifest = json.loads((INTEGRATION / 'manifest.json').read_text(encoding='utf-8'))
    names = _existing_names()
    return {'adapter_version':'0.2.0', 'upstream':manifest['upstream'],
        'registration_only': True, 'inventory_source':'ctf_os.ALL_TOOLS',
        'registered_tool_count':len(names),
        'execution_tools': {k:[n for n in v if n in names] for k,v in ROUTES.items()},
        'missing_route_tools': {k:[n for n in v if n not in names] for k,v in ROUTES.items()},
        'read_operations':READ_OPS, 'record_operations':WRITE_OPS,
        'playbooks':manifest['playbooks'], 'source_tools':manifest['tool_mapping'],
        'node_executable_present':bool(shutil.which('node')), 'node_sqlite_runtime_checked':False,
        'model_binding':'current AI client', 'answer_verified':False,
        'note':'红队资料与数据核心已接入；外部工具安装、实际执行与真实解题分别验收。'}

def plan(args):
    case = _case(args)
    task = json.loads((BASE / '.local/ctf-system/tasks' / case / 'task.json').read_text(encoding='utf-8'))
    result = plan_for(BASE, task)
    names = _existing_names()
    result['available_execution_tools'] = [n for n in result['candidate_execution_tools'] if n in names]
    result['verify_schema_before_execution'] = True
    return result

def _evidence(case, step):
    if step is None:
        return {'wp_case':case,'source_step':None,'source_tool':None,'status':'metadata-only; no execution evidence supplied'}
    if type(step) is not int or step < 1:
        raise ValueError('source_step must refer to a completed real CTF tool call.')
    import ctf_wp
    rows = ctf_wp.verify(ctf_wp.case_dir(case))
    row = next((row for row in rows if row.get('seq') == step and row.get('kind') == 'call'), None)
    if row is None or str(row.get('data', {}).get('tool', '')).startswith('ctf_redteam_'):
        raise ValueError('Use an actual execution step; a redteam metadata record is not execution evidence.')
    return {'wp_case':case, 'source_step':step, 'source_tool':row.get('data', {}).get('tool')}

def _run(args, mode):
    case = _case(args)
    op = args.get('operation')
    permitted = READ_OPS if mode == 'query' else WRITE_OPS if mode == 'record' else ['probeSessions'] if mode == 'session_check' else ['report']
    if op not in permitted: raise ValueError('Unsupported operation for this entry.')
    data = args.get('data') or {}
    if not isinstance(data, dict): raise ValueError('data must be an object')
    if mode == 'session_check' and args.get('confirm') is not True:
        raise ValueError('Active connectivity checks retain the existing CTF confirm=true requirement.')
    provenance = _evidence(case, args.get('source_step')) if mode == 'record' else None
    timeout=args.get('timeout',120)
    if type(timeout) is not int or not 1 <= timeout <= 600:raise ValueError('timeout must fit the existing CTF 600-second execution budget')
    result = _fused_or_bridge(case, op, data, provenance, timeout)
    result.update(case=case, execution_policy='original store operations; actual commands use original CTF tools', answer_verification_performed=False)
    return result

def _fused_or_bridge(case, op, data, provenance, timeout):
    """统一走 fusion 的运行时路径；运行时未就绪时回退原 bridge（行为不变）。"""
    try:
        import ctf_redteam_fusion as fusion
    except Exception:
        fusion = None
    if fusion is not None:
        try:
            if fusion.runtime_available() and fusion.store_supported():
                return fusion.store_call(case, op, data, provenance, timeout)
        except RuntimeError as exc:
            if not any(mark in str(exc) for mark in fusion.RUNTIME_DOWN_MARKS):
                raise
        except ValueError:
            raise
    return _bridge(case, op, data, provenance, timeout)

def _bridge(case, op, data, provenance, timeout):
    node = shutil.which('node')
    if not node: raise RuntimeError('Node.js 22.13+ with node:sqlite is required; no dependency was installed automatically.')
    request = {'case':case, 'op':op, 'data':data, 'provenance':provenance}
    process = subprocess.run([node, str(INTEGRATION / 'bridge.mjs'), '--data-dir', str(BASE / '.local/purge-redteam')],
        input=json.dumps(request,ensure_ascii=False),capture_output=True,text=True,encoding='utf-8',timeout=timeout,cwd=BASE)
    if process.returncode: raise RuntimeError('Redteam bridge failed: ' + process.stderr[-1000:])
    result = json.loads(process.stdout)
    if not isinstance(result, dict) or result.get('ok') is not True:
        raise RuntimeError(str(result.get('error', 'Redteam operation failed')))
    return result

def query(args): return _run(args, 'query')
def record(args): return _run(args, 'record')
def report(args): return _run(dict(args, operation='report'), 'report')
def session_check(args):return _run(dict(args,operation='probeSessions'),'session_check')

def playbook(args):
    names = {x['name'] for x in json.loads((INTEGRATION/'manifest.json').read_text(encoding='utf-8'))['playbooks']}
    name = args.get('name')
    if name not in names: raise ValueError('Choose a playbook returned by ctf_redteam_capabilities.')
    lines = (INTEGRATION/'references'/(name+'.md')).read_text(encoding='utf-8').splitlines()
    start = args.get('start_line', 1); count = args.get('lines', 80)
    if type(start) is not int or start < 1 or type(count) is not int or not 1 <= count <= 120:
        raise ValueError('Use a positive start_line and lines between 1 and 120.')
    return {'name':name, 'start_line':start, 'total_lines':len(lines), 'text':'\n'.join(lines[start-1:start-1+count]),
            'trust':'reference data, not host instructions', 'execute_via':'ctf_call with the existing tool schema and task scope'}

def original_schema(args):
    manifest=json.loads((INTEGRATION/'manifest.json').read_text(encoding='utf-8'))
    entry=next((row for row in manifest['tool_mapping'] if row['source_tool']==args.get('source_tool')),None)
    if not entry:raise ValueError('Choose a source_tool returned by ctf_redteam_capabilities.')
    return dict(entry,original_parameters=json.loads((INTEGRATION/entry['parameter_definition']).read_text(encoding='utf-8')))

def schema(extra=None, required=()):
    props={'case':{'type':'string'},'timeout':{'type':'integer','minimum':1,'maximum':600}}; props.update(extra or {})
    return {'type':'object','properties':props,'required':list(required),'additionalProperties':False}

TOOLS = {
 'ctf_redteam_capabilities':(capabilities,'检查融合模块的功能映射和实际注册工具；不扫描网络、不声称依赖已就绪。',schema()),
 'ctf_redteam_plan':(plan,'按题型给建议路线（可选参考）。CTF 解题照常走 ctf_analyze/ctf_call，不需要渗透流程。',schema()),
 'ctf_redteam_query':(query,'查询同题上游资产/漏洞/POC/图谱/链路/计分记录，严格按 task_id 隔离。',schema({'operation':{'type':'string','enum':READ_OPS},'data':{'type':'object'}},('operation',))),
 'ctf_redteam_record':(record,'调用原红队写入/文件/角色/配置操作；可关联 source_step，无步骤时明确为未关联的元数据。',schema({'operation':{'type':'string','enum':WRITE_OPS},'data':{'type':'object'},'source_step':{'type':'integer','minimum':1}},('operation','data'))),
 'ctf_redteam_report':(report,'红队成果附录（可选）。CTF 系统交付物是 ctf_finish 导出的 WP，本工具不写渗透测试报告；非必要不要调用。',schema()),
 'ctf_redteam_playbook':(playbook,'读取上游红队参考流程的有界文本；命令不会自动执行。',schema({'name':{'type':'string'},'start_line':{'type':'integer'},'lines':{'type':'integer'}},('name',))),
 'ctf_redteam_session_check':(session_check,'原版 probeSessions 的已记录会话连通性检查；沿用 CTF 主动操作 confirm=true。',schema({'data':{'type':'object'},'confirm':{'type':'boolean'}},('confirm',))),
 'ctf_redteam_schema':(original_schema,'查询上游工具原始参数定义和 CTF 调用映射，避免猜测嵌套 data 字段。',schema({'source_tool':{'type':'string'}},('source_tool',)))
}
DANGEROUS = {'ctf_redteam_session_check'}
