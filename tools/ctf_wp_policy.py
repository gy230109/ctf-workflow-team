"""CTF-first screenshot requirements, evaluated over saved evidence only."""
import json
import re

VERSION = 'ctf-two-modules/20261030.1'
IMAGE_KINDS = frozenset({'vm_screenshot', 'imported_image', 'windows_screenshot', 'browser_screenshot'})
FLAG = re.compile(r'(?i)\b(?:flag|ctf|gwht|qwb|pwn\.college)\{[^}\n]*\}')


def contract():
    return {'version': VERSION, 'primary_goal': '解出并验证本题 flag',
            'redteam_role': 'fully-integrated',
            'modules': {
                'solving': {'goal': '融合传统CTF与破甲能力，提高解出并验证flag的能力',
                            'capability_policy': 'fully-integrated',
                            'selection': '按本题证据选择有效工具、POC、工具链或角色协作；破甲能力可以承担主力，不设辅助位或仅内网可用限制。',
                            'routing_hints_are_allowlists': False},
                'writeup': {'goal': '同步留证，写出规范、可复现的WP',
                            'capture_policy': 'at_key_milestones',
                            'capture_when': ['题面或关键线索页面', '支撑关键判断的操作或调试画面', 'flag结果或验证回执'],
                            'selection': '选择必要、合适、可读的真实截图；复用已采原图，一张图覆盖过程与结果时可共同引用，不为凑数量重复截图。'}},
            'writeup_sections': [
                'overview', 'analysis', 'solution', 'validation', 'reproduction'],
            'screenshots': '关键解题过程同步保存真实截图；取得 flag 后保存关联结果步骤的真实截图；正文嵌入并注明来源与步骤。',
            'capture_tool': 'wp_capture(mode=kali_vm|windows_window|file, source_step=实际调用步骤, stage=process|result|process_and_result)',
            'automatic_capture': '浏览器/已支持的调试器沿用实际自动采集；无可见界面的命令需主动选择真实终端/窗口采集。',
            'failure_policy': '截图失败如实留缺项，继续保存解题结果；不重放有副作用的动作，不把日志渲染或回放冒充截图。',
            'completion_policy': '截图或正文缺项只能导出明确标记的草稿；平台验证与稿件完整性分别记录。'}


def flags_in(value):
    # Match actual strings, not JSON-escaped text: "\\nflag{...}" would lose
    # the word boundary when regex is run over a serialized JSON envelope.
    pending, found = [value], []
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            for flag in FLAG.findall(item):
                if flag not in found:
                    found.append(flag)
        elif isinstance(item, dict):
            pending.extend(reversed(list(item.values())))
        elif isinstance(item, (list, tuple)):
            pending.extend(reversed(item))
    return found


def has_flag(response):
    return bool(flags_in(response))


def inspect(folder, rows, platform_verified=False):
    flag_steps = set()
    for event in rows:
        if event['kind'] != 'call':
            continue
        raw_file = next((x for x in event.get('files', []) if x.get('kind') == 'tool_output'), None)
        if raw_file:
            raw = json.loads((folder / raw_file['path']).read_text(encoding='utf-8'))
            if has_flag(raw.get('response', {})):
                flag_steps.add(event['seq'])
    images = []
    for event in rows:
        if event['kind'] not in {'call', 'capture'}:
            continue
        data = event['data']
        source_step = data.get('source_step') or event['seq']
        for item in event.get('files', []):
            if item.get('kind') not in IMAGE_KINDS:
                continue
            stage = data.get('stage') or ('result' if source_step in flag_steps else 'process')
            images.append({'step': event['seq'], 'source_step': source_step,
                           'stage': stage, 'kind': item['kind'], 'path': item['path'],
                           'caption': data.get('caption') or item.get('source') or '实际采集画面'})
    process = [x for x in images if x['stage'] in {'process', 'process_and_result'}]
    result = [x for x in images if x['stage'] in {'result', 'process_and_result'}]
    issues = []
    if not process:
        issues.append({'code': 'missing_process_screenshot', 'severity': 'needs_attention',
                       'message': '缺少关键解题过程真实截图；终端回放和日志渲染不替代截图。', 'steps': []})
    result_required = bool(flag_steps or platform_verified)
    if result_required and not result:
        issues.append({'code': 'missing_result_screenshot', 'severity': 'needs_attention',
                       'message': '已取得 flag 或正确回执，但缺少关联结果步骤的真实截图；用 wp_capture(stage=result, source_step=...) 保存当前结果画面。',
                       'steps': sorted(flag_steps)})
    return {'version': VERSION, 'images': images, 'process_count': len(process),
            'result_count': len(result), 'result_required': result_required,
            'flag_steps': sorted(flag_steps), 'complete': not issues, 'issues': issues,
            'pixel_content_verified': False}


def guidance(tool, response):
    step = (response.get('wp_record') or {}).get('step')
    result = has_flag(response.get('result', {}))
    visual = tool in {'web_browser_session', 'web_browser_capture', 'win_debug_call',
                      'kali_debug_session', 'kali_terminal_record'}
    return {'primary_goal': '解出并验证本题 flag', 'source_step': step,
            'capture_policy': 'at_key_milestones', 'capture_recommended': result or visual,
            'stage': 'result' if result else 'process',
            'next': ('这是结果或可见操作节点，选择支撑解题主线的必要画面及时截图并关联source_step；复用已有自动原图。一张图确实覆盖过程及结果时可用stage=process_and_result。'
                     if result or visual else
                     '保留本次原始输出；只在出现关键、合适的可见页面时截图，不为状态查询、记账或后台计算凑图。')}
